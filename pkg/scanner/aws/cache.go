package aws

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type cachedResponse struct {
	statusCode int
	header     http.Header
	body       []byte
	expiresAt  time.Time
}

// AWSCache manages an in-memory cache of AWS API responses across accounts and regions.
type AWSCache struct {
	mu      sync.RWMutex
	entries map[string]*cachedResponse
	sfGroup singleflight.Group
}

var (
	sharedAWSCacheInstance *AWSCache
	sharedAWSCacheOnce     sync.Once
)

// GetSharedAWSCache returns the singleton instance of the AWS API cache.
func GetSharedAWSCache() *AWSCache {
	sharedAWSCacheOnce.Do(func() {
		sharedAWSCacheInstance = &AWSCache{
			entries: make(map[string]*cachedResponse),
		}
	})
	return sharedAWSCacheInstance
}

// Clear removes all cached entries.
func (c *AWSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cachedResponse)
}

// InvalidateAccount removes all cached entries for a specific account.
func (c *AWSCache) InvalidateAccount(accountID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := "possum:aws:" + accountID + ":"
	for k := range c.entries {
		if strings.HasPrefix(k, prefix) {
			delete(c.entries, k)
		}
	}
}

// ForAccount returns an http.RoundTripper configured with caching for the specified account.
func (c *AWSCache) ForAccount(accountID string, base ...http.RoundTripper) *AWSCacheTransport {
	var b http.RoundTripper
	if len(base) > 0 && base[0] != nil {
		b = base[0]
	} else {
		b = http.DefaultTransport
	}
	return &AWSCacheTransport{
		cache:      c,
		base:       b,
		accountID:  accountID,
		defaultTTL: 5 * time.Minute,
	}
}

// AWSCacheTransport provides transparent, concurrency-safe, read-only caching for AWS SDK v2 calls.
type AWSCacheTransport struct {
	cache      *AWSCache
	base       http.RoundTripper
	accountID  string
	defaultTTL time.Duration
}

// NewAWSCacheTransport creates a new AWSCacheTransport for the given account.
func NewAWSCacheTransport(base http.RoundTripper, accountID string) *AWSCacheTransport {
	return GetSharedAWSCache().ForAccount(accountID, base)
}

func (t *AWSCacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only cache read-only requests (GET/HEAD or POST with describe/list/get actions)
	if !t.isCacheableRequest(req) {
		return t.base.RoundTrip(req)
	}

	key, ttl := t.generateCacheKey(req)
	if key == "" {
		return t.base.RoundTrip(req)
	}

	// 1. Check Cache Hit
	t.cache.mu.RLock()
	if cached, ok := t.cache.entries[key]; ok {
		if time.Now().Before(cached.expiresAt) {
			t.cache.mu.RUnlock()
			return t.createResponse(cached, req), nil
		}
	}
	t.cache.mu.RUnlock()

	// 2. Cache Miss: Coalesce concurrent requests using Singleflight
	resAny, err, _ := t.cache.sfGroup.Do(key, func() (interface{}, error) {
		// Re-check cache inside singleflight barrier
		t.cache.mu.RLock()
		if cached, ok := t.cache.entries[key]; ok {
			if time.Now().Before(cached.expiresAt) {
				t.cache.mu.RUnlock()
				return cached, nil
			}
		}
		t.cache.mu.RUnlock()

		// Execute actual HTTP request
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		cached := &cachedResponse{
			statusCode: resp.StatusCode,
			header:     resp.Header.Clone(),
			body:       bodyBytes,
		}

		// Only cache successful 200 OK responses with defined TTL
		if resp.StatusCode == http.StatusOK && ttl > 0 {
			cached.expiresAt = time.Now().Add(ttl)
			t.cache.mu.Lock()
			t.cache.entries[key] = cached
			t.cache.mu.Unlock()
		} else {
			cached.expiresAt = time.Time{}
		}

		return cached, nil
	})

	if err != nil {
		return nil, err
	}

	cached := resAny.(*cachedResponse)
	return t.createResponse(cached, req), nil
}

func (t *AWSCacheTransport) isCacheableRequest(req *http.Request) bool {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return true
	}
	if req.Method == http.MethodPost {
		target := req.Header.Get("X-Amz-Target")
		if target != "" {
			dotIdx := strings.LastIndex(target, ".")
			action := target
			if dotIdx >= 0 {
				action = target[dotIdx+1:]
			}
			return strings.HasPrefix(action, "Describe") ||
				strings.HasPrefix(action, "List") ||
				strings.HasPrefix(action, "Get")
		}

		// Inspect form body for Action=Describe*/List*/Get*
		if req.Body != nil {
			bodyBytes, err := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if err == nil {
				str := string(bodyBytes)
				return strings.Contains(str, "Action=Describe") ||
					strings.Contains(str, "Action=List") ||
					strings.Contains(str, "Action=Get")
			}
		}
	}
	return false
}

func (t *AWSCacheTransport) generateCacheKey(req *http.Request) (string, time.Duration) {
	ttl := t.defaultTTL
	host := req.URL.Host

	// Multi-tier TTL policy
	service := "generic"
	if strings.Contains(host, "costexplorer") {
		service = "costexplorer"
		ttl = 12 * time.Hour
	} else if strings.Contains(host, "monitoring") {
		service = "cloudwatch"
		ttl = 15 * time.Minute
	} else if strings.Contains(host, "iam") || strings.Contains(host, "cognito") || strings.Contains(host, "acm") || strings.Contains(host, "route53") {
		service = "identity"
		ttl = 20 * time.Minute
	} else {
		// Regional inventory & configuration (EC2, S3, RDS, Lambda, DynamoDB, ELB, CloudFormation, etc.)
		service = "regional"
		ttl = 5 * time.Minute
	}

	// Canonicalize Request Body
	var bodyHash string
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			h := sha256.Sum256(bodyBytes)
			bodyHash = hex.EncodeToString(h[:])
		}
	}

	// Canonicalize Query
	q := req.URL.Query()
	var sortedKeys []string
	for k := range q {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	var canonicalQuery strings.Builder
	for _, k := range sortedKeys {
		canonicalQuery.WriteString(k + "=" + url.QueryEscape(q.Get(k)) + "&")
	}

	rawKey := host + "|" + service + "|" + req.URL.Path + "|" + canonicalQuery.String() + "|" + bodyHash
	h := sha256.Sum256([]byte(rawKey))
	return "possum:aws:" + t.accountID + ":" + hex.EncodeToString(h[:]), ttl
}

func (t *AWSCacheTransport) createResponse(cached *cachedResponse, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode:    cached.statusCode,
		Status:        http.StatusText(cached.statusCode),
		Header:        cached.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(cached.body)),
		ContentLength: int64(len(cached.body)),
		Request:       req,
	}
}
