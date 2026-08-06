package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestIssueLifecycleUsesCurrentGitHubFields(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.CreateTemp(t.TempDir(), "key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatal(err)
	}

	created := false
	updated := false
	locked := false
	unlocked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/7/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "installation-token", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/api/issues":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["title"] != "CI failure" || payload["type"] != "Bug" {
				t.Fatalf("create payload=%#v", payload)
			}
			fields, ok := payload["issue_field_values"].([]any)
			if !ok || len(fields) != 1 {
				t.Fatalf("issue fields=%#v", payload["issue_field_values"])
			}
			created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":91,"number":12,"html_url":"https://github.example/acme/api/issues/12","state":"open","title":"CI failure","created_at":"2026-08-06T12:00:00Z","updated_at":"2026-08-06T12:00:00Z"}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/api/issues/12":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if value, exists := payload["milestone"]; !exists || value != nil {
				t.Fatalf("milestone clear missing: %#v", payload)
			}
			if payload["state_reason"] != "duplicate" || payload["duplicate_issue_id"] != float64(55) {
				t.Fatalf("duplicate payload=%#v", payload)
			}
			updated = true
			_, _ = w.Write([]byte(`{"id":91,"number":12,"html_url":"https://github.example/acme/api/issues/12","state":"closed","state_reason":"duplicate","title":"CI failure","created_at":"2026-08-06T12:00:00Z","updated_at":"2026-08-06T12:01:00Z"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/repos/acme/api/issues/12/lock":
			locked = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/repos/acme/api/issues/12/lock":
			unlocked = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(123, keyFile.Name(), server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	issueType := "Bug"
	issue, err := client.CreateIssue(context.Background(), 7, "acme", "api", CreateIssueRequest{
		Title: "CI failure", Type: &issueType,
		IssueFieldValues: []IssueFieldValue{{FieldID: 10, Value: "Urgent"}},
	})
	if err != nil || issue.Number != 12 || !created {
		t.Fatalf("issue=%#v created=%v err=%v", issue, created, err)
	}
	state, reason := "closed", "duplicate"
	canonical := int64(55)
	issue, err = client.UpdateIssue(context.Background(), 7, "acme", "api", 12, UpdateIssueRequest{State: &state, StateReason: &reason, DuplicateIssueID: &canonical, MilestoneSet: true})
	if err != nil || issue.StateReason != "duplicate" || !updated {
		t.Fatalf("issue=%#v updated=%v err=%v", issue, updated, err)
	}
	if err := client.LockIssue(context.Background(), 7, "acme", "api", 12, "resolved"); err != nil {
		t.Fatal(err)
	}
	if err := client.UnlockIssue(context.Background(), 7, "acme", "api", 12); err != nil {
		t.Fatal(err)
	}
	if !locked || !unlocked {
		t.Fatalf("locked=%v unlocked=%v", locked, unlocked)
	}
}

func TestDuplicateIssueRequiresCanonicalID(t *testing.T) {
	reason := "duplicate"
	client := &Client{}
	if _, err := client.UpdateIssue(context.Background(), 1, "acme", "api", 2, UpdateIssueRequest{StateReason: &reason}); err == nil {
		t.Fatal("duplicate state reason without duplicate_issue_id was accepted")
	}
}
