package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

func testStore(t *testing.T) *db.Store {
	t.Helper()
	s, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestDispatchAllChannelTypesAndSignature(t *testing.T) {
	var mu sync.Mutex
	requests := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests[r.URL.Path] = b
		mu.Unlock()
		if r.URL.Path == "/generic" {
			mac := hmac.New(sha256.New, []byte("secret"))
			_, _ = mac.Write(b)
			want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if r.Header.Get("X-CI-Radar-Signature-256") != want {
				t.Errorf("bad signature")
			}
			if r.Header.Get("X-CI-Radar-Event") != "test" {
				t.Errorf("missing event header")
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{
		{Name: "slack", Type: "slack", Enabled: true, URL: server.URL + "/slack", Timeout: time.Second, MaxAttempts: 3},
		{Name: "discord", Type: "discord", Enabled: true, URL: server.URL + "/discord", Timeout: time.Second, MaxAttempts: 3},
		{Name: "telegram", Type: "telegram", Enabled: true, URL: server.URL + "/telegram", BotToken: "x", ChatID: "123", Timeout: time.Second, MaxAttempts: 3},
		{Name: "generic", Type: "webhook", Enabled: true, URL: server.URL + "/generic", HMACSecret: "secret", Headers: map[string]string{"X-Custom": "ok"}, Timeout: time.Second, MaxAttempts: 3},
	}}
	d := New(cfg, testStore(t), testLog())
	if err := d.Dispatch(context.Background(), TestEvent()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/slack", "/discord", "/telegram", "/generic"} {
		if len(requests[p]) == 0 {
			t.Errorf("no request for %s", p)
		}
	}
	var tg map[string]any
	if err := json.Unmarshal(requests["/telegram"], &tg); err != nil {
		t.Fatal(err)
	}
	if tg["chat_id"] != "123" {
		t.Fatalf("telegram chat id: %#v", tg)
	}
}

func TestCooldownSuppressesDuplicate(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count++; w.WriteHeader(204) }))
	defer ts.Close()
	store := testStore(t)
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: ts.URL, Cooldown: time.Hour, Timeout: time.Second, MaxAttempts: 3, Events: []string{"analysis"}}}}
	d := New(cfg, store, testLog())
	ev := model.NotificationEvent{ID: "one", Type: "analysis", DedupeKey: "same", OccurredAt: time.Now(), Title: "x", Summary: "x", Category: model.CategoryNetworkFailure, Score: 80}
	if err := d.Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	ev.ID = "two"
	if err := d.Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("requests=%d", count)
	}
	x, _ := store.GetNotificationDelivery(context.Background(), "two", "ops")
	if x == nil || x.Status != "suppressed" {
		t.Fatalf("delivery=%#v", x)
	}
}

func TestRetryDoesNotRepeatSuccessfulChannel(t *testing.T) {
	goodCount, badCount := 0, 0
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { goodCount++; w.WriteHeader(204) }))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badCount++
		if badCount == 1 {
			http.Error(w, "temporary", 500)
			return
		}
		w.WriteHeader(204)
	}))
	defer bad.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{
		{Name: "good", Type: "webhook", Enabled: true, URL: good.URL, Timeout: time.Second, MaxAttempts: 3},
		{Name: "bad", Type: "webhook", Enabled: true, URL: bad.URL, Timeout: time.Second, MaxAttempts: 3},
	}}
	d := New(cfg, testStore(t), testLog())
	ev := TestEvent()
	if err := d.Dispatch(context.Background(), ev); err == nil {
		t.Fatal("expected retryable error")
	}
	if err := d.Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if goodCount != 1 || badCount != 2 {
		t.Fatalf("good=%d bad=%d", goodCount, badCount)
	}
}

func TestFiltering(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count++; w.WriteHeader(204) }))
	defer ts.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "filtered", Type: "webhook", Enabled: true, URL: ts.URL, Timeout: time.Second, MaxAttempts: 3, Events: []string{"analysis"}, Categories: []string{"NETWORK_FAILURE"}, MinimumScore: 70, ExternalOnly: true, IncludeRepositories: []string{"acme/*"}}}}
	d := New(cfg, testStore(t), testLog())
	ev := model.NotificationEvent{ID: "1", Type: "analysis", DedupeKey: "1", Title: "x", Summary: "x", Repository: "other/repo", Category: model.CategoryNetworkFailure, Confidence: model.ConfidenceModerate, Score: 90}
	_ = d.Dispatch(context.Background(), ev)
	ev.ID = "2"
	ev.Repository = "acme/api"
	ev.Score = 60
	_ = d.Dispatch(context.Background(), ev)
	ev.ID = "3"
	ev.Score = 90
	ev.Category = model.CategoryCodeFailure
	ev.Confidence = model.ConfidenceLikelyCode
	_ = d.Dispatch(context.Background(), ev)
	ev.ID = "4"
	ev.Category = model.CategoryNetworkFailure
	ev.Confidence = model.ConfidenceModerate
	_ = d.Dispatch(context.Background(), ev)
	if count != 1 {
		t.Fatalf("count=%d", count)
	}
}

func TestPayloadDoesNotContainLogOrSecrets(t *testing.T) {
	var body string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(204)
	}))
	defer ts.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "g", Type: "webhook", Enabled: true, URL: ts.URL, Timeout: time.Second, MaxAttempts: 2}}}
	ev := TestEvent()
	ev.Summary = "safe summary"
	if err := New(cfg, testStore(t), testLog()).Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "raw_log") || strings.Contains(body, "AWS_SECRET") {
		t.Fatalf("unsafe payload %s", body)
	}
}

func TestTransportErrorRedactsWebhookSecrets(t *testing.T) {
	store := testStore(t)
	secretURL := "http://127.0.0.1:1/hooks/SUPER_SECRET_VALUE"
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "secret", Type: "webhook", Enabled: true, URL: secretURL, Timeout: 100 * time.Millisecond, MaxAttempts: 1}}}
	ev := TestEvent()
	_ = New(cfg, store, testLog()).Dispatch(context.Background(), ev)
	d, _ := store.GetNotificationDelivery(context.Background(), ev.ID, "secret")
	if d == nil {
		t.Fatal("missing delivery")
	}
	if strings.Contains(d.LastError, "SUPER_SECRET_VALUE") || strings.Contains(d.LastError, secretURL) {
		t.Fatalf("secret leaked: %s", d.LastError)
	}
}

func TestConcurrentDuplicateFingerprintSendsOnce(t *testing.T) {
	var mu sync.Mutex
	count := 0
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(204)
	}))
	defer ts.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: ts.URL, Timeout: 2 * time.Second, MaxAttempts: 3, Cooldown: time.Hour, Events: []string{"analysis"}}}}
	d := New(cfg, testStore(t), testLog())
	ev1 := model.NotificationEvent{ID: "concurrent-1", Type: "analysis", DedupeKey: "same-fingerprint", Title: "x", Summary: "x", Category: model.CategoryNetworkFailure, Confidence: model.ConfidenceModerate, Score: 90}
	ev2 := ev1
	ev2.ID = "concurrent-2"
	done := make(chan error, 1)
	go func() { done <- d.Dispatch(context.Background(), ev1) }()
	<-started
	if err := d.Dispatch(context.Background(), ev2); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatalf("count=%d", count)
	}
}
