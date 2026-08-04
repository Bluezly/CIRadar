package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateEntry struct {
	window time.Time
	count  int
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{entries: map[string]rateEntry{}, limit: limit, window: window}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e.window.IsZero() || now.Sub(e.window) >= l.window {
		e = rateEntry{window: now}
	}
	e.count++
	l.entries[key] = e
	if len(l.entries) > 10000 {
		for k, v := range l.entries {
			if now.Sub(v.window) >= 2*l.window {
				delete(l.entries, k)
			}
		}
	}
	return e.count <= l.limit
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.Trim(host, "[]")
}

func rateLimit(l *rateLimiter, next http.Handler) http.Handler {
	webhookLimit := l.limit * 10
	if webhookLimit < 2000 {
		webhookLimit = 2000
	}
	webhooks := newRateLimiter(webhookLimit, l.window)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := l
		if r.URL.Path == "/webhooks/github" {

			limiter = webhooks
		}
		if !limiter.allow(clientIP(r), time.Now().UTC()) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
