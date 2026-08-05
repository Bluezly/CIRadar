// Package httpguard provides outbound network clients that reject SSRF targets
// such as loopback, link-local, private, and metadata-service addresses.
package httpguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var blockedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// ValidateURL performs syntax and literal-address checks before a request is
// attempted. DNS answers are validated again by the guarded dialer.
func ValidateURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse outbound URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("outbound URL scheme %q is not allowed", u.Scheme)
	}
	if u.Hostname() == "" {
		return errors.New("outbound URL requires a host")
	}
	if u.User != nil {
		return errors.New("outbound URL must not contain user credentials")
	}
	if allowPrivate {
		return nil
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("outbound URL host %q is not public", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil && blockedIP(ip) {
		return fmt.Errorf("outbound URL address %s is not public", ip)
	}
	return nil
}

// NewClient returns an HTTP client that resolves and dials only validated
// addresses. Environment proxies are deliberately disabled because a proxy can
// resolve a seemingly public hostname to an internal target outside this
// process's validation boundary.
func NewClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return NewClientWithOptions(timeout, ClientOptions{AllowPrivateNetwork: allowPrivate})
}

type ClientOptions struct {
	AllowPrivateNetwork       bool
	AllowCrossOriginRedirects bool
}

// NewClientWithOptions permits narrowly scoped redirect behavior for read-only
// APIs that hand out signed download URLs. Cross-origin redirects never carry
// caller-provided headers.
func NewClientWithOptions(timeout time.Duration, options ClientOptions) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialTLSContext = nil
	transport.DialContext = GuardedDialContext(&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}, options.AllowPrivateNetwork)
	return &http.Client{
		Timeout:   timeout,
		Transport: guardedTransport{base: transport, allowPrivate: options.AllowPrivateNetwork},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if err := ValidateURL(req.URL.String(), options.AllowPrivateNetwork); err != nil {
				return err
			}
			if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
				if !options.AllowCrossOriginRedirects {
					return errors.New("cross-origin outbound redirect is not allowed")
				}
				if via[0].Method != http.MethodGet && via[0].Method != http.MethodHead {
					return errors.New("cross-origin outbound redirect is allowed only for GET or HEAD")
				}
				clearRedirectHeaders(req.Header)
			}
			return nil
		},
	}
}

type guardedTransport struct {
	base         http.RoundTripper
	allowPrivate bool
}

func (t guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := ValidateURL(req.URL.String(), t.allowPrivate); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// GuardedDialContext wraps a net.Dialer and pins the connection to an address
// returned by the validated DNS lookup, preventing a second DNS resolution at
// dial time.
func GuardedDialContext(dialer *net.Dialer, allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if allowPrivate {
			return dialer.DialContext(ctx, network, address)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse outbound address %q: %w", address, err)
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		lowerHost := strings.TrimSuffix(strings.ToLower(host), ".")
		if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") {
			return nil, fmt.Errorf("outbound host %q is not public", host)
		}

		var addresses []netip.Addr
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			addresses = []netip.Addr{ip.Unmap()}
		} else {
			resolved, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if lookupErr != nil {
				return nil, fmt.Errorf("resolve outbound host %q: %w", host, lookupErr)
			}
			addresses = make([]netip.Addr, 0, len(resolved))
			for _, ip := range resolved {
				addresses = append(addresses, ip.Unmap())
			}
		}

		var dialErr error
		allowed := 0
		for _, ip := range addresses {
			if blockedIP(ip) {
				continue
			}
			allowed++
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			dialErr = errors.Join(dialErr, err)
		}
		if allowed == 0 {
			return nil, fmt.Errorf("outbound host %q resolved only to non-public addresses", host)
		}
		return nil, fmt.Errorf("dial outbound host %q: %w", host, dialErr)
	}
}

func blockedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, prefix := range blockedRanges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(strings.TrimSuffix(a.Hostname(), "."), strings.TrimSuffix(b.Hostname(), ".")) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
}

func clearRedirectHeaders(header http.Header) {
	for name := range header {
		switch http.CanonicalHeaderKey(name) {
		case "Accept", "Accept-Encoding", "Range", "User-Agent":
			continue
		default:
			header.Del(name)
		}
	}
}
