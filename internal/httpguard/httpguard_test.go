package httpguard

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateURLRejectsSSRFAddresses(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/hook",
		"http://[::1]/hook",
		"http://169.254.169.254/latest/meta-data",
		"http://10.0.0.1/hook",
		"http://100.64.0.1/hook",
		"http://192.0.2.1/hook",
		"http://198.51.100.1/hook",
		"http://203.0.113.1/hook",
		"http://[2001:db8::1]/hook",
		"file:///etc/passwd",
		"http://user:pass@example.com/hook",
		"http://localhost/hook",
	}
	for _, raw := range blocked {
		if err := ValidateURL(raw, false); err == nil {
			t.Errorf("accepted blocked URL %q", raw)
		}
	}
	if err := ValidateURL("https://example.com/hook", false); err != nil {
		t.Fatalf("public URL rejected: %v", err)
	}
}

func TestClientBlocksPrivateNetworkUnlessExplicitlyAllowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(time.Second, false).Do(req)
	if err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("private target was not blocked: %v", err)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewClient(time.Second, true).Do(req)
	if err != nil {
		t.Fatalf("explicit private-network opt-in failed: %v", err)
	}
	resp.Body.Close()
}

func TestClientRejectsCrossOriginRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Webhook-Secret"); got != "" {
			t.Errorf("secret header leaked across redirect: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodPost, source.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Webhook-Secret", "do-not-forward")
	resp, err := NewClient(time.Second, true).Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("cross-origin redirect was accepted: %v", err)
	}
}

func TestClientAllowsSameOriginRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	resp, err := NewClient(time.Second, true).Get(server.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestGuardedDialRejectsPrivateLiteral(t *testing.T) {
	dial := GuardedDialContext(&net.Dialer{Timeout: 100 * time.Millisecond}, false)
	_, err := dial(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("metadata address was not blocked")
	}
}

func TestClientAllowsSanitizedCrossOriginDownloadRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"Authorization", "Private-Token", "X-Webhook-Secret", "Cookie"} {
			if got := r.Header.Get(name); got != "" {
				t.Errorf("%s leaked across redirect: %q", name, got)
			}
		}
		if got := r.Header.Get("Accept"); got != "application/octet-stream" {
			t.Errorf("Accept header=%q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Private-Token", "secret")
	req.Header.Set("X-Webhook-Secret", "secret")
	req.Header.Set("Cookie", "secret=1")
	req.Header.Set("Accept", "application/octet-stream")
	client := NewClientWithOptions(time.Second, ClientOptions{AllowPrivateNetwork: true, AllowCrossOriginRedirects: true})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestClientDoesNotAllowCrossOriginPostRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("cross-origin POST redirect reached target")
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	req, err := http.NewRequest(http.MethodPost, source.URL, strings.NewReader("secret-body"))
	if err != nil {
		t.Fatal(err)
	}
	client := NewClientWithOptions(time.Second, ClientOptions{AllowPrivateNetwork: true, AllowCrossOriginRedirects: true})
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "GET or HEAD") {
		t.Fatalf("cross-origin POST redirect was accepted: %v", err)
	}
}
