package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/model"
)

func TestWebhookSignatures(t *testing.T) {
	body := []byte(`{"x":1}`)
	now := time.Now().UTC()
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	circle := "v1=" + hex.EncodeToString(mac.Sum(nil))
	h := http.Header{"Circleci-Signature": []string{circle}}
	if !VerifyWebhook("circleci", "secret", h, body, now) {
		t.Fatal("circle signature")
	}
	ts := now.Unix()
	mac = hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(strings.Join([]string{formatInt(ts), string(body)}, ".")))
	bk := "timestamp=" + formatInt(ts) + ",signature=" + hex.EncodeToString(mac.Sum(nil))
	h = http.Header{"X-Buildkite-Signature": []string{bk}}
	if !VerifyWebhook("buildkite", "secret", h, body, now) {
		t.Fatal("buildkite signature")
	}
	h = http.Header{"X-Gitlab-Token": []string{"secret"}}
	if !VerifyWebhook("gitlab", "secret", h, body, now) {
		t.Fatal("gitlab token")
	}
}
func TestParseProviderPayloads(t *testing.T) {
	gl := []byte(`{"object_kind":"build","build_id":42,"build_name":"test","build_status":"failed","pipeline_id":9,"project":{"id":7,"path_with_namespace":"acme/api","web_url":"https://gitlab/acme/api"},"commit":{"sha":"abc"}}`)
	ev, err := ParseWebhook("gitlab", "t", "d", gl)
	if err != nil || ev.Repository != "acme/api" || ev.JobID != "42" || ev.Conclusion != "failure" {
		t.Fatalf("gitlab %#v %v", ev, err)
	}
	bk := []byte(`{"event":"job.finished","organization":{"slug":"acme"},"pipeline":{"slug":"api","name":"API"},"build":{"id":"b1","number":3,"state":"failed","commit":"abc"},"job":{"id":"j1","name":"tests","state":"failed"}}`)
	ev, err = ParseWebhook("buildkite", "t", "d", bk)
	if err != nil || ev.Repository != "acme/api" || ev.Metadata["job_uuid"] != "j1" {
		t.Fatalf("buildkite %#v %v", ev, err)
	}
	cc := []byte(`{"id":"w1","type":"job-completed","project":{"slug":"gh/acme/api"},"organization":{"name":"acme"},"workflow":{"id":"wf","name":"build"},"pipeline":{"number":8,"vcs":{"revision":"abc","branch":"main"}},"job":{"id":"job","name":"test","status":"failed","number":12}}`)
	ev, err = ParseWebhook("circleci", "t", "d", cc)
	if err != nil || ev.Metadata["job_number"] != "12" || ev.Conclusion != "failure" {
		t.Fatalf("circle %#v %v", ev, err)
	}
	j := []byte(`{"name":"api","repository":"acme/api","build":{"number":5,"phase":"FINALIZED","status":"FAILURE","full_url":"https://jenkins/job/api/5/"}}`)
	ev, err = ParseWebhook("jenkins", "t", "d", j)
	if err != nil || ev.Repository != "acme/api" || ev.Conclusion != "failure" {
		t.Fatalf("jenkins %#v %v", ev, err)
	}
}
func TestFetchLogs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/trace"):
			if r.Header.Get("PRIVATE-TOKEN") != "tok" {
				t.Error("gitlab auth")
			}
			_, _ = w.Write([]byte("npm ERR! ECONNRESET"))
		case strings.HasSuffix(r.URL.Path, "/log"):
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Error("buildkite auth")
			}
			_, _ = w.Write([]byte(`{"content":"runner lost communication"}`))
		case strings.HasSuffix(r.URL.Path, "/steps"):
			_, _ = w.Write([]byte(`{"items":[{"actions":[{"output_url":"` + tsURL(r) + `/output"}]}]}`))
		case r.URL.Path == "/output":
			_, _ = w.Write([]byte(`[{"message":"test failed"}]`))
		case strings.HasSuffix(r.URL.Path, "/consoleText"):
			_, _ = w.Write([]byte("No space left on device"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	cases := []struct {
		co   config.CIConnector
		ev   model.CIEvent
		want string
	}{
		{config.CIConnector{Provider: "gitlab", BaseURL: ts.URL, Token: "tok"}, model.CIEvent{ProjectID: "7", JobID: "42"}, "ECONNRESET"},
		{config.CIConnector{Provider: "buildkite", BaseURL: ts.URL, Token: "tok"}, model.CIEvent{Metadata: map[string]string{"organization": "acme", "pipeline_slug": "api", "build_number": "3", "job_uuid": "j1"}}, "lost communication"},
		{config.CIConnector{Provider: "circleci", BaseURL: ts.URL, Token: "tok"}, model.CIEvent{Metadata: map[string]string{"project_slug": "gh/acme/api", "job_number": "12"}}, "test failed"},
		{config.CIConnector{Provider: "jenkins", BaseURL: ts.URL}, model.CIEvent{Metadata: map[string]string{"build_url": ts.URL + "/job/api/5/"}}, "No space"},
	}
	for _, tc := range cases {
		got, err := FetchLog(context.Background(), tc.co, tc.ev, 1<<20)
		if err != nil || !strings.Contains(got, tc.want) {
			t.Fatalf("%s got=%q err=%v", tc.co.Provider, got, err)
		}
	}
}
func formatInt(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	b := make([]byte, 0, 20)
	for v > 0 {
		b = append(b, digits[v%10])
		v /= 10
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
func tsURL(r *http.Request) string { return "http://" + r.Host }

func TestUpsertGitLabMRCommentCreatesThenUpdates(t *testing.T) {
	var created, updated int
	var noteBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "token" {
			t.Fatalf("token=%q", r.Header.Get("PRIVATE-TOKEN"))
		}
		switch {
		case r.Method == http.MethodGet:
			if created == 0 {
				_, _ = w.Write([]byte(`[]`))
			} else {
				_, _ = w.Write([]byte(`[{"id":7,"body":"<!-- ci-radar-diagnosis --> old"}]`))
			}
		case r.Method == http.MethodPost:
			created++
			_ = r.ParseForm()
			noteBody = r.Form.Get("body")
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut:
			updated++
			_ = r.ParseForm()
			noteBody = r.Form.Get("body")
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("method=%s", r.Method)
		}
	}))
	defer srv.Close()
	co := config.CIConnector{Provider: "gitlab", BaseURL: srv.URL, Token: "token"}
	ev := model.CIEvent{Provider: "gitlab", ProjectID: "12", MergeRequestIID: 3}
	if err := UpsertGitLabMRComment(context.Background(), co, ev, "<!-- ci-radar-diagnosis -->", "new", true); err != nil {
		t.Fatal(err)
	}
	if err := UpsertGitLabMRComment(context.Background(), co, ev, "<!-- ci-radar-diagnosis -->", "updated", true); err != nil {
		t.Fatal(err)
	}
	if created != 1 || updated != 1 || !strings.Contains(noteBody, "updated") {
		t.Fatalf("created=%d updated=%d body=%q", created, updated, noteBody)
	}
}
