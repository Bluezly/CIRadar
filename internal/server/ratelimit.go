package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ciradar/internal/db"
)

const (
	defaultAuthFailureThreshold = 10
	defaultAuthFailureWindow    = 5 * time.Minute
	defaultAuthFailureBaseDelay = 5 * time.Second
	defaultAuthFailureMaxDelay  = 15 * time.Minute
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

func (l *rateLimiter) take(key string, now time.Time) (bool, time.Duration) {
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
		for entryKey, value := range l.entries {
			if oldestKey == "" || value.window.Before(oldest) {
				oldestKey = entryKey
				oldest = value.window
			}
		}
		if oldestKey == "" {
			break
		}
		delete(l.entries, oldestKey)
	}
	if e.count <= l.limit {
		return true, 0
	}
	retry := e.window.Add(l.window).Sub(now)
	if retry < time.Second {
		retry = time.Second
	}
	return false, retry
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
	return rateLimitWithShared(l, nil, "", resolver, nil, next)
}

type rateLimitWarning struct {
	mu   sync.Mutex
	last time.Time
}

func (w *rateLimitWarning) log(logger *slog.Logger, message string, err error) {
	if logger == nil || err == nil {
		return
	}
	now := time.Now().UTC()
	w.mu.Lock()
	if !w.last.IsZero() && now.Sub(w.last) < time.Minute {
		w.mu.Unlock()
		return
	}
	w.last = now
	w.mu.Unlock()
	logger.Warn(message, "error", err)
}

func rateLimitKey(secret, key string) string {
	if strings.TrimSpace(secret) == "" {
		sum := sha256.Sum256([]byte(key))
		return hex.EncodeToString(sum[:])
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

func rateLimitWithShared(l *rateLimiter, shared db.DistributedRateLimiter, secret string, resolver *clientIPResolver, logger *slog.Logger, next http.Handler) http.Handler {
	webhookLimit := l.limit * 10
	if webhookLimit < 2000 {
		webhookLimit = 2000
	}
	webhooks := newRateLimiter(webhookLimit, l.window)
	oauthRegister := newRateLimiter(30, 10*time.Minute)
	oauthToken := newRateLimiter(120, time.Minute)
	warning := &rateLimitWarning{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := l
		scope := "http"
		switch {
		case r.URL.Path == "/oauth/register":
			limiter = oauthRegister
			scope = "oauth_register"
		case r.URL.Path == "/oauth/token":
			limiter = oauthToken
			scope = "oauth_token"
		case strings.HasPrefix(r.URL.Path, "/webhooks/") || strings.HasPrefix(r.URL.Path, "/chatops/"):
			limiter = webhooks
			scope = "webhook"
		}
		key := resolver.resolve(r)
		now := time.Now().UTC()
		allowed, retry := limiter.take(key, now)
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retry)))
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		if shared != nil {
			allowed, retry, err := shared.TakeRateLimit(r.Context(), scope, rateLimitKey(secret, key), limiter.limit, limiter.window, now)
			if err != nil {
				warning.log(logger, "shared rate limiter unavailable; rejecting request", err)
				writeError(w, http.StatusServiceUnavailable, "distributed rate limiter unavailable")
				return
			} else if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retry)))
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type authFailureEntry struct {
	windowStart  time.Time
	failures     int
	blockedUntil time.Time
	lastSeen     time.Time
}

type authFailureLimiter struct {
	mu        sync.Mutex
	entries   map[string]authFailureEntry
	threshold int
	window    time.Duration
	baseDelay time.Duration
	maxDelay  time.Duration
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

type statusCaptureFlusher struct {
	*statusCapture
	flusher http.Flusher
}

func newAuthFailureLimiter(threshold int, window, baseDelay, maxDelay time.Duration) *authFailureLimiter {
	if threshold < 1 {
		threshold = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if baseDelay <= 0 {
		baseDelay = time.Second
	}
	if maxDelay < baseDelay {
		maxDelay = baseDelay
	}
	return &authFailureLimiter{
		entries:   map[string]authFailureEntry{},
		threshold: threshold,
		window:    window,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
	}
}

func (l *authFailureLimiter) retryAfter(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return 0
	}
	if now.Sub(e.windowStart) >= l.window && !now.Before(e.blockedUntil) {
		delete(l.entries, key)
		return 0
	}
	if now.Before(e.blockedUntil) {
		return e.blockedUntil.Sub(now)
	}
	return 0
}

func (l *authFailureLimiter) recordFailure(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e.windowStart.IsZero() || now.Sub(e.windowStart) >= l.window {
		e = authFailureEntry{windowStart: now}
	}
	e.failures++
	e.lastSeen = now
	var delay time.Duration
	if e.failures >= l.threshold {
		delay = l.baseDelay
		for i := l.threshold; i < e.failures && delay < l.maxDelay; i++ {
			if delay > l.maxDelay/2 {
				delay = l.maxDelay
				break
			}
			delay *= 2
		}
		if delay > l.maxDelay {
			delay = l.maxDelay
		}
		e.blockedUntil = now.Add(delay)
	}
	l.entries[key] = e
	l.pruneLocked(now)
	return delay
}

func (l *authFailureLimiter) pruneLocked(now time.Time) {
	if len(l.entries) <= 10000 {
		return
	}
	for key, entry := range l.entries {
		if now.Sub(entry.lastSeen) >= 2*l.window && !now.Before(entry.blockedUntil) {
			delete(l.entries, key)
		}
	}
	for len(l.entries) > 20000 {
		oldestKey := ""
		oldest := now
		for key, entry := range l.entries {
			if oldestKey == "" || entry.lastSeen.Before(oldest) {
				oldestKey = key
				oldest = entry.lastSeen
			}
		}
		if oldestKey == "" {
			break
		}
		delete(l.entries, oldestKey)
	}
}

func (w *statusCapture) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusCapture) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusCaptureFlusher) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.flusher.Flush()
}

func captureStatus(w http.ResponseWriter) (http.ResponseWriter, *statusCapture) {
	capture := &statusCapture{ResponseWriter: w}
	if flusher, ok := w.(http.Flusher); ok {
		return &statusCaptureFlusher{statusCapture: capture, flusher: flusher}, capture
	}
	return capture, capture
}

func hasBearerCredential(r *http.Request) bool {
	parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
	return len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && strings.TrimSpace(parts[1]) != ""
}

func isAuthenticationAttempt(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/auth/token" || hasBearerCredential(r)
}

func retryAfterSeconds(delay time.Duration) int {
	seconds := int((delay + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func authFailureRateLimit(l *authFailureLimiter, resolver *clientIPResolver, next http.Handler) http.Handler {
	return authFailureRateLimitWithShared(l, nil, "", resolver, nil, next)
}

func authFailureRateLimitWithShared(l *authFailureLimiter, shared db.DistributedRateLimiter, secret string, resolver *clientIPResolver, logger *slog.Logger, next http.Handler) http.Handler {
	warning := &rateLimitWarning{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticationAttempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		key := resolver.resolve(r)
		keyHash := rateLimitKey(secret, key)
		now := time.Now().UTC()
		if delay := l.retryAfter(key, now); delay > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(delay)))
			writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		if shared != nil {
			delay, err := shared.AuthFailureRetryAfter(r.Context(), keyHash, now)
			if err != nil {
				warning.log(logger, "shared authentication limiter unavailable; rejecting authentication attempt", err)
				writeError(w, http.StatusServiceUnavailable, "distributed authentication limiter unavailable")
				return
			} else if delay > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(delay)))
				writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
				return
			}
		}
		wrapped, capture := captureStatus(w)
		next.ServeHTTP(wrapped, r)
		if capture.status == http.StatusUnauthorized {
			failureTime := time.Now().UTC()
			l.recordFailure(key, failureTime)
			if shared != nil {
				_, err := shared.RecordAuthFailure(r.Context(), keyHash, l.threshold, l.window, l.baseDelay, l.maxDelay, failureTime)
				warning.log(logger, "failed to update shared authentication limiter", err)
			}
			return
		}
	})
}
