package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
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
		{Name: "slack", Type: "slack", Enabled: true, URL: server.URL + "/slack", AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 3},
		{Name: "discord", Type: "discord", Enabled: true, URL: server.URL + "/discord", AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 3},
		{Name: "telegram", Type: "telegram", Enabled: true, URL: server.URL + "/telegram", AllowPrivateNetwork: true, BotToken: "x", ChatID: "123", Timeout: time.Second, MaxAttempts: 3},
		{Name: "generic", Type: "webhook", Enabled: true, URL: server.URL + "/generic", AllowPrivateNetwork: true, HMACSecret: "secret", Headers: map[string]string{"X-Custom": "ok"}, Timeout: time.Second, MaxAttempts: 3},
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
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: ts.URL, AllowPrivateNetwork: true, Cooldown: time.Hour, Timeout: time.Second, MaxAttempts: 3, Events: []string{"analysis"}}}}
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
		{Name: "good", Type: "webhook", Enabled: true, URL: good.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 3},
		{Name: "bad", Type: "webhook", Enabled: true, URL: bad.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 3},
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
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "filtered", Type: "webhook", Enabled: true, URL: ts.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 3, Events: []string{"analysis"}, Categories: []string{"NETWORK_FAILURE"}, MinimumScore: 70, ExternalOnly: true, IncludeRepositories: []string{"acme/*"}}}}
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
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "g", Type: "webhook", Enabled: true, URL: ts.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 2}}}
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
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "secret", Type: "webhook", Enabled: true, URL: secretURL, AllowPrivateNetwork: true, Timeout: 100 * time.Millisecond, MaxAttempts: 1}}}
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
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: ts.URL, AllowPrivateNetwork: true, Timeout: 2 * time.Second, MaxAttempts: 3, Cooldown: time.Hour, Events: []string{"analysis"}}}}
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

func TestRepositoryProfileRoutesChannel(t *testing.T) {
	var a, b int
	sa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { a++; w.WriteHeader(204) }))
	defer sa.Close()
	sb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b++; w.WriteHeader(204) }))
	defer sb.Close()
	store := testStore(t)
	_, err := store.UpsertRepositoryProfile(context.Background(), model.RepositoryProfile{TenantID: "default", Repository: "acme/api", NotificationChannels: []string{"team-a"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{
		{Name: "team-a", Type: "webhook", Enabled: true, URL: sa.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 2},
		{Name: "team-b", Type: "webhook", Enabled: true, URL: sb.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 2},
	}}
	d := New(cfg, store, testLog())
	ev := TestEvent()
	ev.Repository = "acme/api"
	if err := d.Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if a != 1 || b != 0 {
		t.Fatalf("team-a=%d team-b=%d", a, b)
	}
}

func TestQuietHoursSuppressUnlessCritical(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count++; w.WriteHeader(204) }))
	defer ts.Close()
	now := time.Now().UTC()
	start := now.Add(-time.Minute).Format("15:04")
	end := now.Add(time.Minute).Format("15:04")
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: ts.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 2, QuietHoursStart: start, QuietHoursEnd: end, Timezone: "UTC", QuietHoursBypassSeverity: "critical"}}}
	store := testStore(t)
	d := New(cfg, store, testLog())
	ev := TestEvent()
	ev.ID = "quiet"
	ev.Incident = &model.Incident{Severity: "major"}
	if err := d.Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("quiet notification sent")
	}
	ev.ID = "critical"
	ev.DedupeKey = "critical"
	ev.Severity = "critical"
	ev.Incident = &model.Incident{Severity: "critical"}
	if err := d.Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("critical bypass count=%d", count)
	}
}

func TestRepositoryCriticalityElevatesSeverity(t *testing.T) {
	if got := elevateSeverityForCriticality("minor", "high"); got != "major" {
		t.Fatalf("high criticality severity=%s", got)
	}
	if got := elevateSeverityForCriticality("minor", "critical"); got != "critical" {
		t.Fatalf("critical repository severity=%s", got)
	}
	if got := elevateSeverityForCriticality("critical", "normal"); got != "critical" {
		t.Fatalf("severity downgraded=%s", got)
	}
}

func TestNegativeCodeScorePassesEvidenceFilter(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count++; w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "code", Type: "webhook", Enabled: true, URL: ts.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 1, Events: []string{"analysis"}, MinimumScore: 60}}}
	ev := model.NotificationEvent{ID: "code-negative", Type: "analysis", DedupeKey: "code-negative", Title: "test failed", Summary: "expected 4, got 5", Category: model.CategoryCodeFailure, Attribution: model.AttributionCode, Confidence: model.ConfidenceLikelyCode, Score: -62, ExternalityScore: -62, EvidenceStrength: 62, CodeEvidenceScore: 62}
	if err := New(cfg, testStore(t), testLog()).Dispatch(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count=%d", count)
	}
}

func TestAutomaticQuarantineEventIsDedicatedAndHasNoQuarantineButton(t *testing.T) {
	now := time.Now().UTC()
	st := model.TestCaseStats{TenantID: "alpha", TestKey: "test-key", Repository: "acme/api", Framework: "junit", Name: "Calc.adds", FlakeScore: 72.5, TotalRuns: 12}
	q := model.TestQuarantine{TenantID: "alpha", TestKey: st.TestKey, Owner: "platform", Reason: "Automatic quarantine: repeated pass/fail transitions", CreatedBy: "system", CreatedAt: now, ExpiresAt: now.Add(48 * time.Hour), Active: true}
	ev := TestQuarantinedEvent(st, q, "https://ciradar.example")
	if ev.Type != "test_quarantined" || ev.TenantID != "alpha" || ev.Fingerprint != st.TestKey || ev.Operation != "test-quarantine" {
		t.Fatalf("event=%#v", ev)
	}
	payload := slackPayload(config.NotificationChannel{}, ev)
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "automatically quarantined") || !strings.Contains(text, "platform") {
		t.Fatalf("Slack quarantine payload missing context: %s", text)
	}
	if strings.Contains(text, "Quarantine 7 days") || strings.Contains(text, "ciradar_quarantine") {
		t.Fatalf("already-quarantined event exposed quarantine action: %s", text)
	}
}

func TestRepairPRCreatedEventRoutesToSlackAndLinksDraft(t *testing.T) {
	analysis := model.AnalysisResult{ID: "analysis-1", TenantID: "alpha", Category: model.CategoryCodeFailure, Attribution: model.AttributionCode, Confidence: model.ConfidenceLikelyCode, Score: -88, EvidenceStrength: 88, CodeEvidenceScore: 88, Fingerprint: "fp-1"}
	source := model.RepairSource{TenantID: "alpha", Provider: "github", Repository: "acme/api", CommitSHA: "abc123"}
	result := model.RepairResult{TenantID: "alpha", AnalysisID: "analysis-1", Provider: "github", PullRequestNumber: 42, PullRequestURL: "https://github.com/acme/api/pull/42", Status: "draft_pr_created", UpdatedAt: time.Now().UTC()}
	ev := RepairPRCreatedEvent(analysis, source, result)
	if ev.Type != "repair_pr_created" || ev.Repository != "acme/api" || ev.DetailsURL != result.PullRequestURL {
		t.Fatalf("event=%#v", ev)
	}
	payload := slackPayload(config.NotificationChannel{}, ev)
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "Review draft PR") || !strings.Contains(text, result.PullRequestURL) {
		t.Fatalf("Slack repair payload missing draft PR action: %s", text)
	}
}

func TestNotificationTruncateKeepsUTF8Valid(t *testing.T) {
	out := truncate("تنبيه عربي طويل", 7)
	if !utf8.ValidString(out) {
		t.Fatalf("invalid UTF-8: %q", out)
	}
}

func TestWebhookBlocksPrivateNetworkByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "blocked", Type: "webhook", Enabled: true, URL: ts.URL, Timeout: 250 * time.Millisecond, MaxAttempts: 2, Events: []string{"test"}}}}
	err := New(cfg, testStore(t), testLog()).Dispatch(context.Background(), TestEvent())
	if err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("private webhook was not blocked: %v", err)
	}
}

type failingNotificationMetadataStore struct {
	db.Backend
	lookupErr error
	recordErr error
}

func (s failingNotificationMetadataStore) GetNotificationDeliveryForTenant(context.Context, string, string, string) (*model.NotificationDelivery, error) {
	return nil, s.lookupErr
}

func (s failingNotificationMetadataStore) RecordNotificationDelivery(context.Context, model.NotificationDelivery) error {
	return s.recordErr
}

func TestRecordFailurePropagatesNotificationMetadataErrors(t *testing.T) {
	base := testStore(t)
	channel := config.NotificationChannel{Name: "ops", Type: "webhook", MaxAttempts: 3}
	event := TestEvent()
	original := errors.New("delivery failed")

	lookupErr := errors.New("lookup unavailable")
	dispatcher := New(config.NotificationConfig{}, failingNotificationMetadataStore{Backend: base, lookupErr: lookupErr}, testLog())
	err := dispatcher.recordFailure(context.Background(), channel, event, 1, 500, original, false)
	if !errors.Is(err, original) || !errors.Is(err, lookupErr) {
		t.Fatalf("lookup failure error=%v", err)
	}

	recordErr := errors.New("record unavailable")
	dispatcher = New(config.NotificationConfig{}, failingNotificationMetadataStore{Backend: base, recordErr: recordErr}, testLog())
	err = dispatcher.recordFailure(context.Background(), channel, event, 1, 500, original, false)
	if !errors.Is(err, original) || !errors.Is(err, recordErr) {
		t.Fatalf("record failure error=%v", err)
	}
}

type failingRepositoryProfileStore struct {
	db.Backend
	err error
}

func (s failingRepositoryProfileStore) GetRepositoryProfile(context.Context, string, string) (*model.RepositoryProfile, error) {
	return nil, s.err
}

func TestDispatchFailsClosedWhenRepositoryRoutingCannotBeLoaded(t *testing.T) {
	var requests int
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer endpoint.Close()

	sentinel := errors.New("repository profile storage unavailable")
	store := failingRepositoryProfileStore{Backend: testStore(t), err: sentinel}
	cfg := config.NotificationConfig{Enabled: true, Channels: []config.NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: endpoint.URL, AllowPrivateNetwork: true, Timeout: time.Second, MaxAttempts: 1}}}
	event := TestEvent()
	event.Repository = "acme/api"
	err := New(cfg, store, testLog()).Dispatch(context.Background(), event)
	if !errors.Is(err, sentinel) {
		t.Fatalf("dispatch error=%v", err)
	}
	if requests != 0 {
		t.Fatalf("notification was sent without repository routing metadata: requests=%d", requests)
	}
}

type failingResponseReader struct {
	err error
}

func (r failingResponseReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadResponseSnippetPropagatesReadFailure(t *testing.T) {
	sentinel := errors.New("response stream failed")
	if _, err := readResponseSnippet(failingResponseReader{err: sentinel}, 1024); !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}
