package providers

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/httpguard"
)

func TestProviderPollerBlocksPrivateTargets(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("private provider endpoint was reached")
	}))
	defer target.Close()

	poller := &Poller{
		http: httpguard.NewClient(time.Second, false),
		log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	_, err := poller.fetch(context.Background(), Endpoint{Name: "test", URL: target.URL})
	if err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("private provider endpoint was not blocked: %v", err)
	}
}

func TestProviderPollerRejectsOversizedResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", (1<<20)+1))
	}))
	defer target.Close()
	poller := &Poller{http: target.Client(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err := poller.fetch(context.Background(), Endpoint{Name: "test", URL: target.URL})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}

func TestProviderPollerSuppressesRepeatedWarningsAndLogsRecovery(t *testing.T) {
	var output bytes.Buffer
	poller := &Poller{log: slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	poller.reportPollFailures([]string{"npm"}, []string{"npm: unavailable"})
	if first := output.String(); !strings.Contains(first, "provider status polling incomplete") {
		t.Fatalf("first warning missing: %s", first)
	}
	output.Reset()
	poller.reportPollFailures([]string{"npm"}, []string{"npm: unavailable"})
	if repeated := output.String(); strings.Contains(repeated, "provider status polling incomplete") || !strings.Contains(repeated, "provider status poll detail") {
		t.Fatalf("repeated logging=%s", repeated)
	}
	output.Reset()
	poller.reportPollFailures(nil, nil)
	if recovered := output.String(); !strings.Contains(recovered, "provider status polling recovered") {
		t.Fatalf("recovery log missing: %s", recovered)
	}
}

func TestProviderPollerDoesNotExposeUpstreamErrorBody(t *testing.T) {
	const secret = "upstream-secret-value"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, secret)
	}))
	defer target.Close()
	poller := &Poller{http: target.Client(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err := poller.fetch(context.Background(), Endpoint{Name: "test", URL: target.URL})
	if err == nil || !strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), secret) {
		t.Fatalf("error=%v", err)
	}
}
