package aws

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockRoundTripper struct {
	callCount atomic.Int32
	handler   func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.callCount.Add(1)
	if m.handler != nil {
		return m.handler(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
	}, nil
}

func TestAWSCacheTransport_HitAndMiss(t *testing.T) {
	GetSharedAWSCache().Clear()
	mockRT := &mockRoundTripper{}
	transport := NewAWSCacheTransport(mockRT, "acc-123")

	reqURL, _ := url.Parse("https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances")
	req := &http.Request{
		Method: http.MethodGet,
		URL:    reqURL,
		Header: http.Header{},
	}

	// First call: Miss
	resp1, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if string(body1) != `{"status":"ok"}` {
		t.Errorf("expected body `{\"status\":\"ok\"}`, got %s", string(body1))
	}
	if count := mockRT.callCount.Load(); count != 1 {
		t.Fatalf("expected 1 backend call, got %d", count)
	}

	// Second call: Hit
	resp2, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if string(body2) != `{"status":"ok"}` {
		t.Errorf("expected cached body `{\"status\":\"ok\"}`, got %s", string(body2))
	}
	if count := mockRT.callCount.Load(); count != 1 {
		t.Errorf("expected still 1 backend call after cache hit, got %d", count)
	}
}

func TestAWSCacheTransport_SingleflightConcurrentDeduplication(t *testing.T) {
	GetSharedAWSCache().Clear()
	mockRT := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			// Simulate 50ms AWS API latency
			time.Sleep(50 * time.Millisecond)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/xml"}},
				Body:       io.NopCloser(bytes.NewBufferString(`<ListBucketsResponse><Buckets><Bucket><Name>test</Name></Bucket></Buckets></ListBucketsResponse>`)),
			}, nil
		},
	}

	cache := &AWSCache{entries: make(map[string]*cachedResponse)}
	transport := cache.ForAccount("acc-test-sf", mockRT)

	reqURL, _ := url.Parse("https://s3.us-east-1.amazonaws.com/?Action=ListBuckets")

	var wg sync.WaitGroup
	const numGoroutines = 20

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &http.Request{
				Method: http.MethodGet,
				URL:    reqURL,
				Header: http.Header{},
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Errorf("concurrent request error: %v", err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !bytes.Contains(body, []byte("test")) {
				t.Errorf("unexpected response body: %s", string(body))
			}
		}()
	}

	wg.Wait()

	// All 20 concurrent goroutines should have coalesced into 1 backend call
	if count := mockRT.callCount.Load(); count != 1 {
		t.Errorf("expected singleflight to coalesce into 1 backend call, got %d", count)
	}
}

func TestAWSCacheTransport_AccountIsolation(t *testing.T) {
	GetSharedAWSCache().Clear()
	mockRT := &mockRoundTripper{}
	cache := &AWSCache{entries: make(map[string]*cachedResponse)}

	transport1 := cache.ForAccount("account-A", mockRT)
	transport2 := cache.ForAccount("account-B", mockRT)

	reqURL, _ := url.Parse("https://iam.amazonaws.com/?Action=ListUsers")
	req := &http.Request{
		Method: http.MethodGet,
		URL:    reqURL,
		Header: http.Header{},
	}

	// Call from account A
	_, _ = transport1.RoundTrip(req)
	if count := mockRT.callCount.Load(); count != 1 {
		t.Fatalf("expected 1 call, got %d", count)
	}

	// Call from account B for the same URL must NOT hit account A's cache
	_, _ = transport2.RoundTrip(req)
	if count := mockRT.callCount.Load(); count != 2 {
		t.Errorf("expected 2 calls due to different account IDs, got %d", count)
	}
}

func TestAWSCacheTransport_InvalidateAccount(t *testing.T) {
	GetSharedAWSCache().Clear()
	mockRT := &mockRoundTripper{}
	cache := &AWSCache{entries: make(map[string]*cachedResponse)}
	transport := cache.ForAccount("acc-to-invalidate", mockRT)

	reqURL, _ := url.Parse("https://rds.us-east-1.amazonaws.com/?Action=DescribeDBInstances")
	req := &http.Request{
		Method: http.MethodGet,
		URL:    reqURL,
		Header: http.Header{},
	}

	_, _ = transport.RoundTrip(req)
	if count := mockRT.callCount.Load(); count != 1 {
		t.Fatalf("expected 1 call, got %d", count)
	}

	// Invalidate account
	cache.InvalidateAccount("acc-to-invalidate")

	// Call again should miss and fetch again
	_, _ = transport.RoundTrip(req)
	if count := mockRT.callCount.Load(); count != 2 {
		t.Errorf("expected 2 calls after account invalidation, got %d", count)
	}
}

func TestAWSCacheTransport_XAmzTargetIsolation(t *testing.T) {
	GetSharedAWSCache().Clear()
	mockRT := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			target := req.Header.Get("X-Amz-Target")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"target":"` + target + `"}`)),
			}, nil
		},
	}

	cache := &AWSCache{entries: make(map[string]*cachedResponse)}
	transport := cache.ForAccount("acc-json-target", mockRT)

	reqURL, _ := url.Parse("https://kms.us-east-1.amazonaws.com/")

	req1 := &http.Request{
		Method: http.MethodPost,
		URL:    reqURL,
		Header: http.Header{"X-Amz-Target": []string{"TrentService.ListKeys"}},
		Body:   io.NopCloser(bytes.NewBufferString(`{}`)),
	}
	resp1, err := transport.RoundTrip(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if string(body1) != `{"target":"TrentService.ListKeys"}` {
		t.Fatalf("unexpected body1: %s", string(body1))
	}

	// Second request to same URL and body `{}` with different X-Amz-Target must NOT hit cache
	req2 := &http.Request{
		Method: http.MethodPost,
		URL:    reqURL,
		Header: http.Header{"X-Amz-Target": []string{"TrentService.ListAliases"}},
		Body:   io.NopCloser(bytes.NewBufferString(`{}`)),
	}
	resp2, err := transport.RoundTrip(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body2) != `{"target":"TrentService.ListAliases"}` {
		t.Fatalf("expected different response for different X-Amz-Target, got %s", string(body2))
	}
	if count := mockRT.callCount.Load(); count != 2 {
		t.Errorf("expected 2 backend calls for different X-Amz-Target headers, got %d", count)
	}
}

func TestAWSCacheTransport_DoesNotCacheSecretsOrS3Objects(t *testing.T) {
	GetSharedAWSCache().Clear()
	mockRT := &mockRoundTripper{}
	cache := &AWSCache{entries: make(map[string]*cachedResponse)}
	transport := cache.ForAccount("acc-sensitive", mockRT)

	// 1. SecretsManager GetSecretValue must not be cached
	smURL, _ := url.Parse("https://secretsmanager.us-east-1.amazonaws.com/")
	for i := 0; i < 2; i++ {
		req := &http.Request{
			Method: http.MethodPost,
			URL:    smURL,
			Header: http.Header{"X-Amz-Target": []string{"secretsmanager.GetSecretValue"}},
			Body:   io.NopCloser(bytes.NewBufferString(`{"SecretId":"my-secret"}`)),
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("secretsmanager call failed: %v", err)
		}
		resp.Body.Close()
	}
	if count := mockRT.callCount.Load(); count != 2 {
		t.Errorf("expected GetSecretValue not to be cached (2 calls), got %d", count)
	}

	// 2. S3 GetObject must not be cached
	s3ObjURL, _ := url.Parse("https://my-bucket.s3.us-east-1.amazonaws.com/private/key.json?x-id=GetObject")
	for i := 0; i < 2; i++ {
		req := &http.Request{
			Method: http.MethodGet,
			URL:    s3ObjURL,
			Header: http.Header{},
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("s3 GetObject call failed: %v", err)
		}
		resp.Body.Close()
	}
	if count := mockRT.callCount.Load(); count != 4 {
		t.Errorf("expected S3 GetObject not to be cached (4 total calls), got %d", count)
	}
}

func TestAWSCacheTransport_EvictExpired(t *testing.T) {
	GetSharedAWSCache().Clear()
	cache := &AWSCache{entries: make(map[string]*cachedResponse)}
	cache.entries["expired-key"] = &cachedResponse{
		statusCode: http.StatusOK,
		body:       []byte(`{}`),
		expiresAt:  time.Now().Add(-1 * time.Minute),
	}
	cache.entries["active-key"] = &cachedResponse{
		statusCode: http.StatusOK,
		body:       []byte(`{}`),
		expiresAt:  time.Now().Add(5 * time.Minute),
	}

	cache.EvictExpired()

	cache.mu.RLock()
	_, expiredExists := cache.entries["expired-key"]
	_, activeExists := cache.entries["active-key"]
	cache.mu.RUnlock()

	if expiredExists {
		t.Errorf("expected expired-key to be evicted")
	}
	if !activeExists {
		t.Errorf("expected active-key to remain")
	}
}

func TestAWSCacheTransport_SingleflightCallerCancellationIsolation(t *testing.T) {
	GetSharedAWSCache().Clear()
	started := make(chan struct{})
	proceed := make(chan struct{})

	mockRT := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			close(started)
			<-proceed
			if err := req.Context().Err(); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			}, nil
		},
	}

	cache := &AWSCache{entries: make(map[string]*cachedResponse)}
	transport := cache.ForAccount("acc-cancel", mockRT)
	reqURL, _ := url.Parse("https://ec2.us-east-1.amazonaws.com/?Action=DescribeSubnets")

	ctx1, cancel1 := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	var err2 error
	go func() {
		defer wg.Done()
		req1 := (&http.Request{Method: http.MethodGet, URL: reqURL, Header: http.Header{}}).WithContext(ctx1)
		_, _ = transport.RoundTrip(req1)
	}()

	<-started

	go func() {
		defer wg.Done()
		req2 := (&http.Request{Method: http.MethodGet, URL: reqURL, Header: http.Header{}}).WithContext(context.Background())
		resp2, err := transport.RoundTrip(req2)
		err2 = err
		if resp2 != nil {
			resp2.Body.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)
	cancel1()
	close(proceed)
	wg.Wait()

	if err2 != nil {
		t.Fatalf("expected second caller to succeed despite first caller cancelling context, got: %v", err2)
	}
}

