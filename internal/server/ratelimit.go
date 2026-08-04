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

type clientIPResolver struct {
	trusted []*net.IPNet
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{entries: map[string]rateEntry{}, limit: limit, window: window}
}

func newClientIPResolver(cidrs []string) *clientIPResolver {
	r := &clientIPResolver{}
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil {
			r.trusted = append(r.trusted, network)
		}
	}
	return r
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
	for len(l.entries) > 20000 {
		oldestKey := ""
		oldest := now
		for key, value := range l.entries {
			if oldestKey == "" || value.window.Before(oldest) {
				oldestKey = key
				oldest = value.window
			}
		}
		if oldestKey == "" {
			break
		}
		delete(l.entries, oldestKey)
	}
	return e.count <= l.limit
}

func remoteIP(remote string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err != nil {
		host = strings.TrimSpace(remote)
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func (r *clientIPResolver) trustedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range r.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseForwardedChain(raw string) []net.IP {
	parts := strings.Split(raw, ",")
	out := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		ip := net.ParseIP(strings.Trim(strings.TrimSpace(part), "[]"))
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func (r *clientIPResolver) resolve(req *http.Request) string {
	peer := remoteIP(req.RemoteAddr)
	if peer == nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	if !r.trustedIP(peer) {
		return peer.String()
	}
	chain := parseForwardedChain(req.Header.Get("X-Forwarded-For"))
	if len(chain) == 0 {
		if candidate := net.ParseIP(strings.Trim(strings.TrimSpace(req.Header.Get("X-Real-IP")), "[]")); candidate != nil {
			return candidate.String()
		}
		return peer.String()
	}
	chain = append(chain, peer)
	for i := len(chain) - 1; i >= 0; i-- {
		if !r.trustedIP(chain[i]) {
			return chain[i].String()
		}
	}
	return chain[0].String()
}

func rateLimit(l *rateLimiter, resolver *clientIPResolver, next http.Handler) http.Handler {
	webhookLimit := l.limit * 10
	if webhookLimit < 2000 {
		webhookLimit = 2000
	}
	webhooks := newRateLimiter(webhookLimit, l.window)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := l
		if strings.HasPrefix(r.URL.Path, "/webhooks/") || strings.HasPrefix(r.URL.Path, "/chatops/") {
			limiter = webhooks
		}
		if !limiter.allow(resolver.resolve(r), time.Now().UTC()) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
