package providers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ciradar/internal/httpguard"
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
