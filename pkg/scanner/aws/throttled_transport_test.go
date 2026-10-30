package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestExtractAWSMetadata(t *testing.T) {
	// Test from Authorization header
	req1, _ := http.NewRequest("POST", "https://iam.amazonaws.com/", nil)
	req1.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261008/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=...")
	req1.Header.Set("X-Amz-Target", "IAM.ListUsers")

	assert.Equal(t, "iam", ExtractAWSService(req1))
	assert.Equal(t, "us-east-1", ExtractAWSRegion(req1))
	assert.Equal(t, "ListUsers", ExtractAWSAction(req1))

	// Test from Hostname and Query
	req2, _ := http.NewRequest("GET", "https://ec2.eu-west-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15", nil)
	assert.Equal(t, "ec2", ExtractAWSService(req2))
	assert.Equal(t, "eu-west-1", ExtractAWSRegion(req2))
	assert.Equal(t, "DescribeInstances", ExtractAWSAction(req2))
}

func TestThrottledTransport_RecordsTelemetry(t *testing.T) {
	rec := NewMemoryTelemetryRecorder(100)

	mock := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			res := httptest.NewRecorder()
			if strings.Contains(req.URL.String(), "throttled") {
				res.WriteHeader(http.StatusTooManyRequests)
				_, _ = res.WriteString(`{"__type":"ThrottlingException"}`)
			} else {
				res.WriteHeader(http.StatusOK)
				_, _ = res.WriteString(`{"status":"ok"}`)
			}
			return res.Result(), nil
		},
	}

	transport := NewThrottledTransport(mock, "acc-123", rec)

	// Normal call
	req1, _ := http.NewRequestWithContext(context.Background(), "GET", "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances", nil)
	resp1, err1 := transport.RoundTrip(req1)
	require.NoError(t, err1)
	assert.Equal(t, 200, resp1.StatusCode)

	// Throttled call
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", "https://iam.amazonaws.com/?Action=ListRoles&throttled=1", nil)
	resp2, err2 := transport.RoundTrip(req2)
	require.NoError(t, err2)
	assert.Equal(t, 429, resp2.StatusCode)

	stats := rec.GetStats()
	assert.Equal(t, int64(2), stats["total_calls"])
	assert.Equal(t, int64(1), stats["throttled_calls"])
	assert.Equal(t, 50.0, stats["throttled_percentage"])

	recent := rec.GetRecentCalls(10)
	require.Len(t, recent, 2)
	assert.Equal(t, "ec2", recent[0].Service)
	assert.False(t, recent[0].Throttled)
	assert.Equal(t, "iam", recent[1].Service)
	assert.True(t, recent[1].Throttled)
}

func TestThrottledTransport_RateLimitingQueue(t *testing.T) {
	rec := NewMemoryTelemetryRecorder(100)

	mock := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			res := httptest.NewRecorder()
			res.WriteHeader(http.StatusOK)
			return res.Result(), nil
		},
	}

	transport := NewThrottledTransport(mock, "acc-test", rec)
	// Inject a strict limiter: 2 req/sec with burst 2
	transport.limiters["iam"] = rate.NewLimiter(rate.Limit(2), 2)

	start := time.Now()
	var wg sync.WaitGroup

	// Dispatch 4 requests concurrently
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://iam.amazonaws.com/", nil)
			req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/20261008/us-east-1/iam/aws4_request")
			resp, err := transport.RoundTrip(req)
			assert.NoError(t, err)
			assert.Equal(t, 200, resp.StatusCode)
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	// 4 requests at 2 req/sec with burst 2 requires at least ~500ms to replenish tokens
	assert.True(t, duration >= 400*time.Millisecond, "Expected rate limiter to queue and throttle requests, took %v", duration)
	assert.Equal(t, int64(4), rec.totalCalls.Load())
}

func TestThrottledTransport_ContextCanceled(t *testing.T) {
	rec := NewMemoryTelemetryRecorder(100)
	mock := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			return httptest.NewRecorder().Result(), nil
		},
	}

	transport := NewThrottledTransport(mock, "acc-timeout", rec)
	// Exhaust limiter completely
	l := rate.NewLimiter(rate.Limit(1), 1)
	require.True(t, l.Allow()) // take 1 token
	transport.limiters["ec2"] = l

	// Call with already expired / very short context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances", nil)
	resp, err := transport.RoundTrip(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "context")
}

func TestThrottledTransport_PerAccountLimiterKey(t *testing.T) {
	rec := NewMemoryTelemetryRecorder(100)
	mock := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			res := httptest.NewRecorder()
			res.WriteHeader(http.StatusOK)
			return res.Result(), nil
		},
	}

	transport := NewThrottledTransport(mock, "111122223333", rec)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances", nil)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	transport.mu.RLock()
	_, exists := transport.limiters["111122223333:ec2"]
	transport.mu.RUnlock()
	assert.True(t, exists, "expected limiter to be keyed by accountID:service")
}

func TestThrottledTransport_HTTP400ThrottlingExceptionAndBackoffRetry(t *testing.T) {
	rec := NewMemoryTelemetryRecorder(100)
	var attempts int
	var bodiesSeen []string

	mock := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			attempts++
			if req.Body != nil {
				b := make([]byte, 1024)
				n, _ := req.Body.Read(b)
				bodiesSeen = append(bodiesSeen, string(b[:n]))
			}
			res := httptest.NewRecorder()
			if attempts < 3 {
				res.WriteHeader(http.StatusBadRequest)
				_, _ = res.WriteString(`{"__type":"ThrottlingException","message":"Rate exceeded"}`)
				return res.Result(), nil
			}
			res.WriteHeader(http.StatusOK)
			_, _ = res.WriteString(`{"Functions":[]}`)
			return res.Result(), nil
		},
	}

	transport := NewThrottledTransport(mock, "acc-backoff", rec)
	transport.BaseDelay = 5 * time.Millisecond
	transport.MaxRetries = 3

	req, err := http.NewRequestWithContext(context.Background(), "POST", "https://lambda.us-east-1.amazonaws.com/", strings.NewReader("Action=ListFunctions"))
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 3, attempts, "expected 2 throttled attempts followed by 1 successful retry")
	assert.Equal(t, []string{"Action=ListFunctions", "Action=ListFunctions", "Action=ListFunctions"}, bodiesSeen)

	stats := rec.GetStats()
	assert.Equal(t, int64(1), stats["total_calls"])
	assert.Equal(t, int64(1), stats["throttled_calls"])

	recent := rec.GetRecentCalls(10)
	require.Len(t, recent, 1)
	assert.True(t, recent[0].Throttled, "expected HTTP 400 ThrottlingException to record Throttled=true")
	assert.Equal(t, http.StatusOK, recent[0].StatusCode)
}

