package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientIPIgnoresUntrustedForwardedHeaders(t *testing.T) {
	r := newClientIPResolver([]string{"10.0.0.0/8"})
	req := httptest.NewRequest("GET", "http://example.test", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := r.resolve(req); got != "198.51.100.10" {
		t.Fatalf("unexpected client IP %q", got)
	}
}

func TestClientIPUsesTrustedProxyChain(t *testing.T) {
	r := newClientIPResolver([]string{"10.0.0.0/8", "192.0.2.0/24"})
	req := httptest.NewRequest("GET", "http://example.test", nil)
	req.RemoteAddr = "10.0.0.9:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 192.0.2.4")
	if got := r.resolve(req); got != "203.0.113.7" {
		t.Fatalf("unexpected client IP %q", got)
	}
}

func TestAuthFailureLimiterEscalatesAndResets(t *testing.T) {
	l := newAuthFailureLimiter(2, time.Minute, 5*time.Second, 20*time.Second)
	now := time.Unix(1000, 0)
	if delay := l.recordFailure("client", now); delay != 0 {
		t.Fatalf("first failure delay=%s", delay)
	}
	if delay := l.recordFailure("client", now); delay != 5*time.Second {
		t.Fatalf("threshold delay=%s", delay)
	}
	if delay := l.retryAfter("client", now.Add(time.Second)); delay != 4*time.Second {
		t.Fatalf("retry delay=%s", delay)
	}
	if delay := l.recordFailure("client", now.Add(5*time.Second)); delay != 10*time.Second {
		t.Fatalf("escalated delay=%s", delay)
	}
	l.reset("client")
	if delay := l.retryAfter("client", now.Add(6*time.Second)); delay != 0 {
		t.Fatalf("reset delay=%s", delay)
	}
}

func TestAuthFailureMiddlewareBlocksRepeatedBearerFailures(t *testing.T) {
	l := newAuthFailureLimiter(2, time.Minute, time.Minute, time.Minute)
	h := authFailureRateLimit(l, newClientIPResolver(nil), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
	}))
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "198.51.100.9:1234"
		req.Header.Set("Authorization", "Bearer invalid")
		result := httptest.NewRecorder()
		h.ServeHTTP(result, req)
		if i < 2 && result.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status=%d", i, result.Code)
		}
		if i == 2 {
			if result.Code != http.StatusTooManyRequests {
				t.Fatalf("blocked status=%d body=%s", result.Code, result.Body.String())
			}
			if result.Header().Get("Retry-After") == "" {
				t.Fatal("missing Retry-After")
			}
		}
	}
}
