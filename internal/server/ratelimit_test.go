package server

import (
	"net/http/httptest"
	"testing"
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
