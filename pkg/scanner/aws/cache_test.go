package aws

import (
	"bytes"
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
