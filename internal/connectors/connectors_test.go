package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
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

func TestGitLabStandardWebhookRejectsReplay(t *testing.T) {
	body := []byte(`{"object_kind":"build"}`)
	now := time.Now().UTC().Truncate(time.Second)
	key := []byte("a sufficiently random webhook key")
	secret := "whsec_" + base64.StdEncoding.EncodeToString(key)

	signedHeaders := func(id string, timestamp time.Time) http.Header {
		ts := formatInt(timestamp.Unix())
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(id + "." + ts + "." + string(body)))
		return http.Header{
			"Webhook-Id":        []string{id},
			"Webhook-Timestamp": []string{ts},
			"Webhook-Signature": []string{"v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))},
		}
	}

	if !VerifyWebhook("gitlab", secret, signedHeaders("delivery-1", now), body, now) {
		t.Fatal("current signed webhook should be accepted")
	}
	if VerifyWebhook("gitlab", secret, signedHeaders("delivery-2", now.Add(-10*time.Minute)), body, now) {
		t.Fatal("stale signed webhook should be rejected")
	}
	if VerifyWebhook("gitlab", secret, signedHeaders("delivery-3", now.Add(10*time.Minute)), body, now) {
		t.Fatal("far-future signed webhook should be rejected")
	}
	if VerifyWebhook("gitlab", secret, signedHeaders("delivery-extreme", time.Unix(1<<62, 0)), body, now) {
		t.Fatal("extreme future timestamp should be rejected")
	}

	missingID := signedHeaders("delivery-4", now)
	missingID.Del("Webhook-Id")
	if VerifyWebhook("gitlab", secret, missingID, body, now) {
		t.Fatal("signed webhook without delivery ID should be rejected")
	}

	malformedTimestamp := signedHeaders("delivery-5", now)
	malformedTimestamp.Set("Webhook-Timestamp", "not-a-timestamp")
	if VerifyWebhook("gitlab", secret, malformedTimestamp, body, now) {
		t.Fatal("signed webhook with malformed timestamp should be rejected")
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

func TestParseAdditionalProviderPayloads(t *testing.T) {
	cases := []struct {
		provider string
		body     string
		repo     string
		status   string
	}{
		{"bitbucket", `{"repository":{"full_name":"acme/api","workspace":{"slug":"acme"}},"pipeline":{"uuid":"{p1}","build_number":7,"state":{"result":{"name":"FAILED"}},"target":{"ref_name":"main","commit":{"hash":"abc"}}},"step":{"uuid":"{s1}","name":"test","state":{"result":{"name":"FAILED"}}}}`, "acme/api", "failure"},
		{"drone", `{"repository":{"slug":"acme/api"},"build":{"id":9,"number":3,"status":"failure","after":"abc","source":"main"},"stage":{"number":1,"name":"default"},"step":{"number":2,"name":"test","status":"failure"}}`, "acme/api", "failure"},
		{"semaphore", `{"organization_name":"acme","project_name":"api","pipeline_id":"p1","result":"failed","commit_sha":"abc"}`, "acme/api", "failure"},
		{"appveyor", `{"eventData":{"accountName":"acme","projectName":"api","buildId":5,"status":"failed","commitId":"abc","jobs":[{"jobId":"j1","name":"test","status":"failed"}]}}`, "acme/api", "failure"},
		{"cloudbuild", `{"id":"b1","projectId":"acme","status":"FAILURE","substitutions":{"REPO_NAME":"api","COMMIT_SHA":"abc"},"steps":[{"name":"test","status":"FAILURE"}]}`, "api", "failure"},
	}
	for _, tc := range cases {
		ev, err := ParseWebhook(tc.provider, "t", "d", []byte(tc.body))
		if err != nil || ev.Repository != tc.repo || ev.Conclusion != tc.status {
			t.Fatalf("%s ev=%#v err=%v", tc.provider, ev, err)
		}
	}
}

func TestBitbucketWebhookSignature(t *testing.T) {
	body := []byte(`{"pipeline":{"uuid":"p"}}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	h := http.Header{"X-Hub-Signature": []string{"sha256=" + hex.EncodeToString(mac.Sum(nil))}}
	if !VerifyWebhook("bitbucket", "secret", h, body, time.Now().UTC()) {
		t.Fatal("bitbucket signature")
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
		{config.CIConnector{Provider: "gitlab", BaseURL: ts.URL, AllowPrivateNetwork: true, Token: "tok"}, model.CIEvent{ProjectID: "7", JobID: "42"}, "ECONNRESET"},
		{config.CIConnector{Provider: "buildkite", BaseURL: ts.URL, AllowPrivateNetwork: true, Token: "tok"}, model.CIEvent{Metadata: map[string]string{"organization": "acme", "pipeline_slug": "api", "build_number": "3", "job_uuid": "j1"}}, "lost communication"},
		{config.CIConnector{Provider: "circleci", BaseURL: ts.URL, AllowPrivateNetwork: true, Token: "tok"}, model.CIEvent{Metadata: map[string]string{"project_slug": "gh/acme/api", "job_number": "12"}}, "test failed"},
		{config.CIConnector{Provider: "jenkins", BaseURL: ts.URL, AllowPrivateNetwork: true}, model.CIEvent{Metadata: map[string]string{"build_url": ts.URL + "/job/api/5/"}}, "No space"},
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
	co := config.CIConnector{Provider: "gitlab", BaseURL: srv.URL, AllowPrivateNetwork: true, Token: "token"}
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

func TestRetryKnownProviders(t *testing.T) {
	tests := []struct {
		provider string
		ev       model.CIEvent
		co       config.CIConnector
		method   string
		path     string
		query    string
		auth     string
		body     string
	}{
		{"gitlab", model.CIEvent{ProjectID: "7", JobID: "42"}, config.CIConnector{}, http.MethodPost, "/api/v4/projects/7/jobs/42/retry", "", "gitlab", `{}`},
		{"circleci", model.CIEvent{Metadata: map[string]string{"workflow_id": "wf1"}}, config.CIConnector{}, http.MethodPost, "/api/v2/workflow/wf1/rerun", "", "circle", `{"from_failed":true}`},
		{"buildkite", model.CIEvent{Metadata: map[string]string{"organization": "acme", "pipeline_slug": "api", "build_number": "9"}}, config.CIConnector{}, http.MethodPost, "/v2/organizations/acme/pipelines/api/builds/9/rebuild", "", "bearer", `{}`},
		{"travis", model.CIEvent{Metadata: map[string]string{"build_id": "11"}}, config.CIConnector{}, http.MethodPost, "/build/11/restart", "", "travis", `{}`},
		{"cloudbuild", model.CIEvent{Metadata: map[string]string{"build_name": "projects/acme/locations/us/builds/b1"}}, config.CIConnector{}, http.MethodPost, "/v1/projects/acme/locations/us/builds/b1:retry", "", "bearer", `{}`},
		{"azuredevops", model.CIEvent{Metadata: map[string]string{"project_id": "p1", "build_id": "88"}}, config.CIConnector{Organization: "acme"}, http.MethodPatch, "/acme/p1/_apis/build/builds/88", "retry=true&api-version=7.1", "azure", `{}`},
		{"bitbucket", model.CIEvent{Repository: "acme/api", Branch: "main", Metadata: map[string]string{"workspace": "acme", "repo_slug": "api"}}, config.CIConnector{}, http.MethodPost, "/2.0/repositories/acme/api/pipelines/", "", "bearer", `{"target":{"ref_name":"main","ref_type":"branch","type":"pipeline_ref_target"}}`},
		{"drone", model.CIEvent{Repository: "acme/api", RunID: 14, Metadata: map[string]string{"build_number": "14"}}, config.CIConnector{}, http.MethodPost, "/api/repos/acme/api/builds/14", "", "bearer", `{}`},
		{"semaphore", model.CIEvent{Metadata: map[string]string{"workflow_id": "wf-2"}}, config.CIConnector{}, http.MethodPost, "/api/v1alpha/plumber-workflows/wf-2/reschedule", "request_token=", "semaphore", `{}`},
		{"appveyor", model.CIEvent{RunID: 17}, config.CIConnector{}, http.MethodPut, "/api/builds", "", "bearer", `{"buildId":17,"reRunIncomplete":true}`},
		{"bitrise", model.CIEvent{Metadata: map[string]string{"app_slug": "app", "pipeline_id": "pipe"}}, config.CIConnector{}, http.MethodPost, "/v0.1/apps/app/pipelines/pipe/rebuild", "", "bitrise", `{}`},
		{"teamcity", model.CIEvent{PipelineID: "Build_Config", Branch: "main"}, config.CIConnector{}, http.MethodPost, "/app/rest/buildQueue", "", "bearer", `{"branchName":"main","buildType":{"id":"Build_Config"},"comment":{"text":"Safe rerun requested by CI Radar"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
				}
				if tc.query != "" {
					if tc.provider == "semaphore" {
						if !strings.HasPrefix(r.URL.RawQuery, tc.query) || len(r.URL.Query().Get("request_token")) < 16 {
							t.Fatalf("query=%s", r.URL.RawQuery)
						}
					} else if r.URL.RawQuery != tc.query {
						t.Fatalf("query=%s", r.URL.RawQuery)
					}
				}
				switch tc.auth {
				case "gitlab":
					if r.Header.Get("PRIVATE-TOKEN") != "tok" {
						t.Fatal("missing GitLab token")
					}
				case "circle":
					if r.Header.Get("Circle-Token") != "tok" {
						t.Fatal("missing CircleCI token")
					}
				case "travis":
					if r.Header.Get("Authorization") != "token tok" {
						t.Fatal("missing Travis token")
					}
				case "azure":
					if r.Header.Get("Authorization") != "Basic OnRvaw==" {
						t.Fatalf("azure auth=%q", r.Header.Get("Authorization"))
					}
				case "semaphore":
					if r.Header.Get("Authorization") != "Token tok" {
						t.Fatal("missing Semaphore token")
					}
				case "bitrise":
					if r.Header.Get("Authorization") != "tok" {
						t.Fatal("missing Bitrise token")
					}
				default:
					if r.Header.Get("Authorization") != "Bearer tok" {
						t.Fatal("missing bearer token")
					}
				}
				b, _ := io.ReadAll(r.Body)
				if string(b) != tc.body {
					t.Fatalf("body=%q", string(b))
				}
				w.Header().Set("X-Request-Id", "r1")
				w.WriteHeader(http.StatusAccepted)
			}))
			defer srv.Close()
			co := tc.co
			co.Provider = tc.provider
			co.BaseURL = srv.URL
			co.AllowPrivateNetwork = true
			co.Token = "tok"
			result, err := Retry(context.Background(), co, tc.ev)
			if err != nil || result.HTTPStatus != http.StatusAccepted || result.RequestID != "r1" {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestRetryCustomEndpointStaysOnConfiguredBase(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	co := config.CIConnector{Provider: "jenkins", BaseURL: srv.URL, AllowPrivateNetwork: true, Token: "tok", Username: "ci", RetryURL: srv.URL + "/job/${job_id}/rebuild", RetryBody: `{"run":"${run_id}"}`}
	_, err := Retry(context.Background(), co, model.CIEvent{JobID: "22", RunID: 9})
	if err != nil || got != "/job/22/rebuild" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	co.RetryURL = "https://attacker.invalid/retry"
	if _, err := Retry(context.Background(), co, model.CIEvent{}); err == nil {
		t.Fatal("expected off-base retry endpoint rejection")
	}
}

func TestFetchLogBlocksPrivateNetworkByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secret internal log"))
	}))
	defer srv.Close()
	co := config.CIConnector{Provider: "gitlab", BaseURL: srv.URL, Token: "tok"}
	_, err := FetchLog(context.Background(), co, model.CIEvent{ProjectID: "7", JobID: "42"}, 1024)
	if err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("private connector endpoint was not blocked: %v", err)
	}
}

func TestSameBaseRequiresPathBoundary(t *testing.T) {
	if sameBase("https://ci.example/gitlab", "https://ci.example/gitlab-evil/jobs/1") {
		t.Fatal("prefix-confusable path was accepted")
	}
	if !sameBase("https://ci.example/gitlab", "https://ci.example/gitlab/jobs/1") {
		t.Fatal("child path was rejected")
	}
	if !sameBase("https://ci.example/gitlab", "https://ci.example:443/gitlab/jobs/1") {
		t.Fatal("equivalent default HTTPS port was rejected")
	}
	for _, endpoint := range []string{
		"https://user@ci.example/gitlab/jobs/1",
		"http://ci.example/gitlab/jobs/1",
		"https://ci.example:444/gitlab/jobs/1",
		"https://ci.example/gitlab/%2e%2e/admin",
		"https://ci.example/gitlab/%2E%2E/admin",
		"https://ci.example/gitlab/%252e%252e/admin",
		"https://ci.example/gitlab/%25252e%25252e/admin",
		"https://ci.example/gitlab\\..\\admin",
	} {
		if sameBase("https://ci.example/gitlab", endpoint) {
			t.Fatalf("encoded path traversal was accepted: %s", endpoint)
		}
	}
}

func TestPostFormRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", (1<<20)+1))
	}))
	defer srv.Close()
	if err := postForm(context.Background(), srv.Client(), http.MethodPost, srv.URL, nil, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}

func TestRetryReportsUnreadableResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "x")
	}))
	defer srv.Close()
	co := config.CIConnector{Provider: "jenkins", BaseURL: srv.URL, AllowPrivateNetwork: true, RetryURL: srv.URL + "/retry"}
	result, err := Retry(context.Background(), co, model.CIEvent{})
	if err == nil || !strings.Contains(err.Error(), "read retry response") {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if result.HTTPStatus != http.StatusAccepted {
		t.Fatalf("result=%#v", result)
	}
}
