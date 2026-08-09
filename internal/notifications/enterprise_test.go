package notifications

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/config"
)

func TestEnterpriseHTTPChannels(t *testing.T) {
	var mu sync.Mutex
	got := map[string]map[string]any{}
	headers := map[string]http.Header{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		got[r.URL.Path] = payload
		headers[r.URL.Path] = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{
		{Name: "teams", Type: "teams", Enabled: true, URL: ts.URL + "/teams", AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 2},
		{Name: "pager", Type: "pagerduty", Enabled: true, URL: ts.URL + "/pager", AllowPrivateNetwork: true, RoutingKey: "route-secret", Timeout: time.Second, MaxAttempts: 2},
		{Name: "ops", Type: "opsgenie", Enabled: true, URL: ts.URL, AllowPrivateNetwork: true, APIKey: "ops-secret", Timeout: time.Second, MaxAttempts: 2},
	}}
	ev := TestEvent()
	ev.DedupeKey = "incident:abc"
	ev.Severity = "critical"
	if err := New(cfg, testStore(t), testLog()).Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got["/teams"]["type"] != "message" {
		t.Fatalf("teams payload=%#v", got["/teams"])
	}
	if got["/pager"]["routing_key"] != "route-secret" || got["/pager"]["dedup_key"] != "incident:abc" {
		t.Fatalf("pager payload=%#v", got["/pager"])
	}
	if got["/v2/alerts"]["alias"] != "incident:abc" {
		t.Fatalf("ops payload=%#v", got["/v2/alerts"])
	}
	if headers["/v2/alerts"].Get("Authorization") != "GenieKey ops-secret" {
		t.Fatal("missing opsgenie auth")
	}
}

func TestPagerDutyAndOpsgenieResolve(t *testing.T) {
	ev := TestEvent()
	ev.Type = "incident_resolved"
	ev.DedupeKey = "fp:one"
	body, _, _, err := buildRequest(config.NotificationChannel{Type: "pagerduty", RoutingKey: "rk", URL: "https://events.example/v2"}, ev)
	if err != nil {
		t.Fatal(err)
	}
	var pd map[string]any
	_ = json.Unmarshal(body, &pd)
	if pd["event_action"] != "resolve" || pd["dedup_key"] != "fp:one" {
		t.Fatalf("pager resolve=%#v", pd)
	}
	body, endpoint, _, err := buildRequest(config.NotificationChannel{Type: "opsgenie", APIKey: "key", URL: "https://ops.example"}, ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(endpoint, "/close?identifierType=alias") {
		t.Fatalf("endpoint=%s", endpoint)
	}
	var og map[string]any
	_ = json.Unmarshal(body, &og)
	if og["source"] != "CI Radar" {
		t.Fatalf("ops resolve=%#v", og)
	}
}

func TestEmailSMTPPlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	messages := make(chan string, 1)
	go serveFakeSMTP(ln, messages)
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	ch := config.NotificationChannel{Name: "email", Type: "email", Enabled: true, SMTPHost: host, AllowPrivateNetwork: true, SMTPPort: port, SMTPMode: "plain", EmailFrom: "ci@example.com", EmailTo: []string{"ops@example.com"}, Timeout: 2 * time.Second, MaxAttempts: 2}
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{ch}}
	if err := New(cfg, testStore(t), testLog()).Dispatch(context.Background(), TestEvent()); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-messages:
		if !strings.Contains(msg, "Subject: [CI Radar]") || !strings.Contains(msg, "ops@example.com") || !strings.Contains(msg, "CI Radar notification test") {
			t.Fatalf("message=%s", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no SMTP message")
	}
}

func serveFakeSMTP(ln net.Listener, messages chan<- string) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	write := func(s string) { _, _ = rw.WriteString(s + "\r\n"); _ = rw.Flush() }
	write("220 fake-smtp")
	var data strings.Builder
	inData := false
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		clean := strings.TrimRight(line, "\r\n")
		if inData {
			if clean == "." {
				inData = false
				messages <- data.String()
				write("250 queued")
				continue
			}
			data.WriteString(clean)
			data.WriteString("\n")
			continue
		}
		upper := strings.ToUpper(clean)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			write("250 fake-smtp")
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"):
			write("250 ok")
		case upper == "DATA":
			inData = true
			write("354 end with dot")
		case upper == "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

func TestEmailSubjectCannotInjectHeaders(t *testing.T) {
	from, err := parseEmailAddress("CI Radar <ci@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := parseEmailAddress("Ops <ops@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	ev := TestEvent()
	ev.Title = "build failed\r\nBcc: attacker@example.com"
	message := string(buildEmailMessage(from, []*mail.Address{recipient}, ev))
	header, _, ok := strings.Cut(message, "\r\n\r\n")
	if !ok {
		t.Fatalf("message has no header/body boundary: %q", message)
	}
	if strings.Contains(header, "\r\nBcc:") || strings.Contains(header, "\nBcc:") {
		t.Fatalf("injected header found in message: %q", message)
	}
	if !strings.Contains(header, "Subject: [CI Radar] build failed Bcc: attacker@example.com") {
		t.Fatalf("subject was not safely flattened: %q", message)
	}
}
