package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestAuthFailureLimiterEscalatesAndExpires(t *testing.T) {
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
	if delay := l.retryAfter("client", now.Add(6*time.Second)); delay != 9*time.Second {
		t.Fatalf("active block delay=%s", delay)
	}
	if delay := l.retryAfter("client", now.Add(time.Minute+time.Second)); delay != 0 {
		t.Fatalf("expired window delay=%s", delay)
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

type fakeDistributedLimiter struct {
	mu           sync.Mutex
	requestCount int
	lastKey      string
	lastScope    string
	lastLimit    int
	lastWindow   time.Duration
	authFailures int
	blockedUntil time.Time
}

func (f *fakeDistributedLimiter) TakeRateLimit(_ context.Context, scope, key string, limit int, window time.Duration, _ time.Time) (bool, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requestCount++
	f.lastKey = key
	f.lastScope = scope
	f.lastLimit = limit
	f.lastWindow = window
	if f.requestCount > limit {
		return false, time.Minute, nil
	}
	return true, 0, nil
}

func (f *fakeDistributedLimiter) AuthFailureRetryAfter(_ context.Context, key string, now time.Time) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastKey = key
	if f.blockedUntil.After(now) {
		return f.blockedUntil.Sub(now), nil
	}
	return 0, nil
}

func (f *fakeDistributedLimiter) RecordAuthFailure(_ context.Context, key string, threshold int, _ time.Duration, baseDelay, _ time.Duration, now time.Time) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastKey = key
	f.authFailures++
	if f.authFailures >= threshold {
		f.blockedUntil = now.Add(baseDelay)
		return baseDelay, nil
	}
	return 0, nil
}

func TestSharedRateLimiterAggregatesAcrossServerInstances(t *testing.T) {
	shared := &fakeDistributedLimiter{}
	resolver := newClientIPResolver(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	first := rateLimitWithShared(newRateLimiter(1, time.Minute), shared, "cluster-secret", resolver, nil, next)
	second := rateLimitWithShared(newRateLimiter(1, time.Minute), shared, "cluster-secret", resolver, nil, next)

	request := func(handler http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "198.51.100.44:1234"
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		return result
	}
	if result := request(first); result.Code != http.StatusNoContent {
		t.Fatalf("first status=%d", result.Code)
	}
	if result := request(second); result.Code != http.StatusTooManyRequests {
		t.Fatalf("second status=%d body=%s", result.Code, result.Body.String())
	}
	shared.mu.Lock()
	storedKey := shared.lastKey
	shared.mu.Unlock()
	if storedKey == "" || strings.Contains(storedKey, "198.51.100.44") || len(storedKey) != 64 {
		t.Fatalf("shared key was not protected: %q", storedKey)
	}
}

func TestSharedAuthFailureLimiterAggregatesAcrossServerInstances(t *testing.T) {
	shared := &fakeDistributedLimiter{}
	resolver := newClientIPResolver(nil)
	unauthorized := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
	first := authFailureRateLimitWithShared(newAuthFailureLimiter(2, time.Minute, time.Minute, time.Minute), shared, "cluster-secret", resolver, nil, unauthorized)
	second := authFailureRateLimitWithShared(newAuthFailureLimiter(2, time.Minute, time.Minute, time.Minute), shared, "cluster-secret", resolver, nil, unauthorized)

	request := func(handler http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "203.0.113.20:4321"
		req.Header.Set("Authorization", "Bearer invalid")
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		return result
	}
	if result := request(first); result.Code != http.StatusUnauthorized {
		t.Fatalf("first status=%d", result.Code)
	}
	if result := request(second); result.Code != http.StatusUnauthorized {
		t.Fatalf("second status=%d", result.Code)
	}
	if result := request(first); result.Code != http.StatusTooManyRequests {
		t.Fatalf("third status=%d body=%s", result.Code, result.Body.String())
	}
}

type failingDistributedLimiter struct{}

func (failingDistributedLimiter) TakeRateLimit(context.Context, string, string, int, time.Duration, time.Time) (bool, time.Duration, error) {
	return false, 0, errors.New("database unavailable")
}
func (failingDistributedLimiter) AuthFailureRetryAfter(context.Context, string, time.Time) (time.Duration, error) {
	return 0, errors.New("database unavailable")
}
func (failingDistributedLimiter) RecordAuthFailure(context.Context, string, int, time.Duration, time.Duration, time.Duration, time.Time) (time.Duration, error) {
	return 0, errors.New("database unavailable")
}
func TestDistributedRateLimiterFailsClosed(t *testing.T) {
	resolver := newClientIPResolver(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := rateLimitWithShared(newRateLimiter(100, time.Minute), failingDistributedLimiter{}, "secret", resolver, nil, next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	if result.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestDistributedAuthLimiterFailsClosed(t *testing.T) {
	resolver := newClientIPResolver(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := authFailureRateLimitWithShared(newAuthFailureLimiter(10, time.Minute, time.Second, time.Minute), failingDistributedLimiter{}, "secret", resolver, nil, next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("Authorization", "Bearer token")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	if result.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestSuccessfulAuthenticationDoesNotEraseIPFailureHistory(t *testing.T) {
	shared := &fakeDistributedLimiter{}
	resolver := newClientIPResolver(nil)
	local := newAuthFailureLimiter(2, time.Minute, time.Minute, time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer valid" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
	handler := authFailureRateLimitWithShared(local, shared, "cluster-secret", resolver, nil, next)
	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "203.0.113.81:4321"
		req.Header.Set("Authorization", "Bearer "+token)
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		return result
	}
	if result := request("bad-one"); result.Code != http.StatusUnauthorized {
		t.Fatalf("first failure status=%d", result.Code)
	}
	if result := request("valid"); result.Code != http.StatusNoContent {
		t.Fatalf("successful request status=%d", result.Code)
	}
	if result := request("bad-two"); result.Code != http.StatusUnauthorized {
		t.Fatalf("second failure status=%d", result.Code)
	}
	if result := request("valid"); result.Code != http.StatusTooManyRequests {
		t.Fatalf("expected preserved failure history to block request, status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestOAuthRoutesUseTighterRateLimitScopes(t *testing.T) {
	for _, test := range []struct {
		path       string
		wantScope  string
		wantLimit  int
		wantWindow time.Duration
	}{
		{path: "/oauth/register", wantScope: "oauth_register", wantLimit: 30, wantWindow: 10 * time.Minute},
		{path: "/oauth/token", wantScope: "oauth_token", wantLimit: 120, wantWindow: time.Minute},
	} {
		t.Run(test.wantScope, func(t *testing.T) {
			shared := &fakeDistributedLimiter{}
			h := rateLimitWithShared(newRateLimiter(600, time.Minute), shared, "secret", newClientIPResolver(nil), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodPost, test.path, nil)
			req.RemoteAddr = "198.51.100.90:1234"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			shared.mu.Lock()
			defer shared.mu.Unlock()
			if shared.lastScope != test.wantScope || shared.lastLimit != test.wantLimit || shared.lastWindow != test.wantWindow {
				t.Fatalf("scope=%q limit=%d window=%s", shared.lastScope, shared.lastLimit, shared.lastWindow)
			}
		})
	}
}
