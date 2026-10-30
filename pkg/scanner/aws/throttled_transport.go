package aws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// APICallEvent represents telemetry recorded for an individual AWS API HTTP call.
type APICallEvent struct {
	AccountID  string    `json:"account_id"`
	Service    string    `json:"service"`
	Action     string    `json:"action"`
	Region     string    `json:"region"`
	Method     string    `json:"method"`
	Endpoint   string    `json:"endpoint"`
	StatusCode int       `json:"status_code"`
	DurationMs int64     `json:"duration_ms"`
	Throttled  bool      `json:"throttled"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// APICallTelemetryRecorder tracks, logs, and exposes metrics on all outbound AWS API calls.
type APICallTelemetryRecorder interface {
	Record(event APICallEvent)
	GetStats() map[string]interface{}
	GetRecentCalls(limit int) []APICallEvent
}

// MemoryTelemetryRecorder stores in-memory metrics and a ring buffer of recent AWS API calls.
type MemoryTelemetryRecorder struct {
	mu             sync.RWMutex
	recent         []APICallEvent
	maxHistory     int
	totalCalls     atomic.Int64
	throttledCalls atomic.Int64
	serviceCounts  map[string]*atomic.Int64
}

var (
	sharedTelemetryInstance *MemoryTelemetryRecorder
	sharedTelemetryOnce     sync.Once
)

// GetSharedAPITelemetry returns the global shared instance of the API call telemetry recorder.
func GetSharedAPITelemetry() *MemoryTelemetryRecorder {
	sharedTelemetryOnce.Do(func() {
		sharedTelemetryInstance = NewMemoryTelemetryRecorder(1000)
	})
	return sharedTelemetryInstance
}

// NewMemoryTelemetryRecorder creates a new thread-safe in-memory API telemetry recorder.
func NewMemoryTelemetryRecorder(maxHistory int) *MemoryTelemetryRecorder {
	if maxHistory <= 0 {
		maxHistory = 1000
	}
	return &MemoryTelemetryRecorder{
		recent:        make([]APICallEvent, 0, maxHistory),
		maxHistory:    maxHistory,
		serviceCounts: make(map[string]*atomic.Int64),
	}
}

func (r *MemoryTelemetryRecorder) Record(event APICallEvent) {
	r.totalCalls.Add(1)
	if event.Throttled {
		r.throttledCalls.Add(1)
	}

	r.mu.Lock()
	counter, ok := r.serviceCounts[event.Service]
	if !ok {
		counter = &atomic.Int64{}
		r.serviceCounts[event.Service] = counter
	}
	counter.Add(1)

	if len(r.recent) >= r.maxHistory {
		r.recent = r.recent[1:]
	}
	r.recent = append(r.recent, event)
	r.mu.Unlock()
}

func (r *MemoryTelemetryRecorder) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	svcMap := make(map[string]int64, len(r.serviceCounts))
	for svc, cnt := range r.serviceCounts {
		svcMap[svc] = cnt.Load()
	}

	total := r.totalCalls.Load()
	throttled := r.throttledCalls.Load()
	throttledPct := 0.0
	if total > 0 {
		throttledPct = (float64(throttled) / float64(total)) * 100
	}

	return map[string]interface{}{
		"total_calls":           total,
		"throttled_calls":       throttled,
		"throttled_percentage":  throttledPct,
		"calls_by_service":      svcMap,
		"recent_recorded_count": len(r.recent),
	}
}

func (r *MemoryTelemetryRecorder) GetRecentCalls(limit int) []APICallEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 || limit > len(r.recent) {
		limit = len(r.recent)
	}

	out := make([]APICallEvent, limit)
	start := len(r.recent) - limit
	copy(out, r.recent[start:])
	return out
}

// ServiceRateConfig defines rate and burst limits for a service.
type ServiceRateConfig struct {
	RateLimit rate.Limit
	Burst     int
}

// DefaultServiceRates provides AWS API rate limits per second.
var DefaultServiceRates = map[string]ServiceRateConfig{
	"iam":        {RateLimit: rate.Limit(5), Burst: 10},  // IAM is strictly throttled globally per account
	"sts":        {RateLimit: rate.Limit(10), Burst: 20}, // STS AssumeRole / Identity
	"ec2":        {RateLimit: rate.Limit(20), Burst: 35}, // EC2 describe / list
	"s3":         {RateLimit: rate.Limit(30), Burst: 50}, // S3 object & bucket listings
	"rds":        {RateLimit: rate.Limit(15), Burst: 25},
	"cloudwatch": {RateLimit: rate.Limit(12), Burst: 20},
	"cloudtrail": {RateLimit: rate.Limit(10), Burst: 20},
	"lambda":     {RateLimit: rate.Limit(15), Burst: 25},
	"kms":        {RateLimit: rate.Limit(15), Burst: 25},
	"default":    {RateLimit: rate.Limit(15), Burst: 25},
}

// ThrottledTransport intercepts HTTP requests to provide per-service rate limiting and telemetry tracking.
type ThrottledTransport struct {
	base       http.RoundTripper
	accountID  string
	recorder   APICallTelemetryRecorder
	mu         sync.RWMutex
	limiters   map[string]*rate.Limiter
	MaxRetries int
	BaseDelay  time.Duration
}

// NewThrottledTransport wraps an existing RoundTripper with rate-limiting queues and telemetry.
func NewThrottledTransport(base http.RoundTripper, accountID string, recorder ...APICallTelemetryRecorder) *ThrottledTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	var rec APICallTelemetryRecorder
	if len(recorder) > 0 && recorder[0] != nil {
		rec = recorder[0]
	} else {
		rec = GetSharedAPITelemetry()
	}

	return &ThrottledTransport{
		base:       base,
		accountID:  accountID,
		recorder:   rec,
		limiters:   make(map[string]*rate.Limiter),
		MaxRetries: 3,
		BaseDelay:  50 * time.Millisecond,
	}
}

// AccountID returns the account identifier associated with this throttled transport.
func (t *ThrottledTransport) AccountID() string {
	return t.accountID
}

// Base returns the underlying RoundTripper wrapped by this throttled transport.
func (t *ThrottledTransport) Base() http.RoundTripper {
	return t.base
}

func (t *ThrottledTransport) limiterKey(service string) string {
	if t.accountID == "" {
		return service
	}
	return t.accountID + ":" + service
}

func (t *ThrottledTransport) getLimiter(service string) *rate.Limiter {
	key := t.limiterKey(service)

	t.mu.RLock()
	l, ok := t.limiters[key]
	if !ok {
		l, ok = t.limiters[service]
	}
	t.mu.RUnlock()
	if ok {
		return l
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// Re-check under write lock
	if l, ok = t.limiters[key]; ok {
		return l
	}
	if l, ok = t.limiters[service]; ok {
		return l
	}

	cfg, ok := DefaultServiceRates[service]
	if !ok {
		cfg = DefaultServiceRates["default"]
	}
	l = rate.NewLimiter(cfg.RateLimit, cfg.Burst)
	t.limiters[key] = l
	return l
}

var awsThrottleErrorCodes = []string{
	"Throttling",
	"ThrottlingException",
	"ThrottledException",
	"RequestLimitExceeded",
	"TooManyRequestsException",
	"ProvisionedThroughputExceededException",
	"RequestThrottled",
	"SlowDown",
}

func isThrottledResponse(resp *http.Response, err error) bool {
	if err != nil {
		lowerErr := strings.ToLower(err.Error())
		if strings.Contains(lowerErr, "throttling") ||
			strings.Contains(lowerErr, "throttled") ||
			strings.Contains(lowerErr, "requestlimitexceeded") ||
			strings.Contains(lowerErr, "toomanyrequests") ||
			strings.Contains(lowerErr, "slowdown") {
			return true
		}
	}
	if resp != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			return true
		}
		if resp.StatusCode == http.StatusBadRequest && resp.Body != nil {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if readErr == nil && len(bodyBytes) > 0 {
				bodyStr := string(bodyBytes)
				for _, code := range awsThrottleErrorCodes {
					if strings.Contains(bodyStr, code) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (t *ThrottledTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	service := ExtractAWSService(req)
	action := ExtractAWSAction(req)
	region := ExtractAWSRegion(req)

	limiter := t.getLimiter(service)

	// Check if context already has less than 200ms remaining; fail fast rather than wasting tokens
	if deadline, ok := req.Context().Deadline(); ok {
		if time.Until(deadline) < 200*time.Millisecond {
			return nil, fmt.Errorf("insufficient remaining deadline (%v) to queue AWS API call: %w", time.Until(deadline), context.DeadlineExceeded)
		}
	}

	// 1. Queue wait: blocks until token is ready or context is canceled
	if err := limiter.Wait(req.Context()); err != nil {
		t.recorder.Record(APICallEvent{
			AccountID:  t.accountID,
			Service:    service,
			Action:     action,
			Region:     region,
			Method:     req.Method,
			Endpoint:   req.URL.Host,
			StatusCode: 0,
			DurationMs: 0,
			Throttled:  true,
			Error:      fmt.Sprintf("rate-limiter queue canceled: %v", err),
			Timestamp:  time.Now().UTC(),
		})
		return nil, fmt.Errorf("AWS API queue wait canceled: %w", err)
	}

	// Preserve request body so throttled POST/PUT requests can be replayed safely
	var reqBodyBytes []byte
	hasBody := req.Body != nil
	bodyReplayable := true
	if hasBody {
		var readErr error
		reqBodyBytes, readErr = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if readErr != nil {
			bodyReplayable = false
		} else {
			req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
		}
	}

	maxRetries := t.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	baseDelay := t.BaseDelay
	if baseDelay <= 0 {
		baseDelay = 50 * time.Millisecond
	}

	// 2. Execute underlying HTTP call with exponential backoff on throttling
	start := time.Now()
	var resp *http.Response
	var err error
	isThrottled := false

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			delay := baseDelay * time.Duration(1<<(attempt-1))
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				err = req.Context().Err()
				resp = nil
			case <-timer.C:
			}
			if req.Context().Err() != nil {
				break
			}
			if hasBody {
				req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
			}
		}

		resp, err = t.base.RoundTrip(req)
		if isThrottledResponse(resp, err) {
			isThrottled = true
			if attempt < maxRetries && bodyReplayable {
				continue
			}
		}
		break
	}
	duration := time.Since(start)

	// 3. Extract status code and error message
	statusCode := 0
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	if resp != nil {
		statusCode = resp.StatusCode
	}

	// 4. Record Telemetry Event
	t.recorder.Record(APICallEvent{
		AccountID:  t.accountID,
		Service:    service,
		Action:     action,
		Region:     region,
		Method:     req.Method,
		Endpoint:   req.URL.Host,
		StatusCode: statusCode,
		DurationMs: duration.Milliseconds(),
		Throttled:  isThrottled,
		Error:      errMsg,
		Timestamp:  time.Now().UTC(),
	})

	return resp, err
}

// ExtractAWSService extracts the AWS service name from Host or Authorization header.
func ExtractAWSService(req *http.Request) string {
	// 1. Check Authorization header: Credential=AKIA.../20261008/us-east-1/service/aws4_request
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, "/")
		if len(parts) >= 4 {
			return strings.ToLower(strings.TrimSpace(parts[len(parts)-2]))
		}
	}

	// 2. Check Hostname: e.g. "ec2.us-east-1.amazonaws.com" -> "ec2"
	host := req.URL.Host
	if host != "" {
		host = strings.Split(host, ":")[0]
		dotParts := strings.Split(host, ".")
		if len(dotParts) > 0 && dotParts[0] != "" {
			return strings.ToLower(dotParts[0])
		}
	}

	return "unknown"
}

// ExtractAWSAction extracts the AWS action name from headers, query parameters, or body.
func ExtractAWSAction(req *http.Request) string {
	// 1. Check X-Amz-Target header: e.g. "DynamoDB_20120810.DescribeTable"
	target := req.Header.Get("X-Amz-Target")
	if target != "" {
		parts := strings.Split(target, ".")
		if len(parts) > 1 {
			return parts[len(parts)-1]
		}
		return target
	}

	// 2. Check URL Query Action
	if qAction := req.URL.Query().Get("Action"); qAction != "" {
		return qAction
	}

	// 3. Check Form encoded body Action for POST requests
	if req.Body != nil && (req.Method == "POST" || req.Method == "PUT") {
		// Attempt peek if non-destructive or read body
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			vals, parseErr := url.ParseQuery(string(bodyBytes))
			if parseErr == nil && vals.Get("Action") != "" {
				return vals.Get("Action")
			}
		}
	}

	return req.Method
}

// ExtractAWSRegion extracts the AWS region from Authorization header or Host.
func ExtractAWSRegion(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, "/")
		if len(parts) >= 5 {
			return strings.TrimSpace(parts[len(parts)-3])
		}
	}

	host := req.URL.Host
	if host != "" {
		parts := strings.Split(host, ".")
		if len(parts) >= 3 && parts[len(parts)-1] == "com" && parts[len(parts)-2] == "amazonaws" {
			if len(parts) == 4 {
				return parts[1]
			}
		}
	}

	return "global"
}
