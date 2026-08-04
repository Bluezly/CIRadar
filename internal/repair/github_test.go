package repair

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gh "ciradar/internal/github"
	"ciradar/internal/model"
)

func TestCreateGitHubDraftRepairPR(t *testing.T) {
	var branchCreated, fileUpdated, pullCreated bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/contents/src/app.js":
			_ = json.NewEncoder(w).Encode(map[string]any{"path": "src/app.js", "sha": "file-sha", "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("const retries = 1;\n"))})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/api/git/refs":
			branchCreated = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && r.URL.Path == "/repos/acme/api/contents/src/app.js":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			decoded, _ := base64.StdEncoding.DecodeString(body["content"].(string))
			if string(decoded) != "const retries = 2;\n" || body["sha"] != "file-sha" {
				t.Fatalf("update body=%#v content=%q", body, string(decoded))
			}
			fileUpdated = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/api/pulls":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["draft"] != true || body["base"] != "feature" || !strings.HasPrefix(body["head"].(string), "ciradar/repair-") {
				t.Fatalf("pull body=%#v", body)
			}
			pullCreated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 12, "html_url": "https://github.example/pr/12"})
		default:
			http.Error(w, "not found "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	file, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	client, err := gh.New(1, keyPath, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisResult{ID: "analysis-1234567890", TenantID: "alpha", Attribution: model.AttributionCode, Confidence: model.ConfidenceLikelyCode, Score: -90, ExternalityScore: -90, EvidenceStrength: 90, CodeEvidenceScore: 90, Summary: "retry count is too low"}
	source := model.RepairSource{TenantID: "alpha", Provider: "github", Repository: "acme/api", InstallationID: 77, CommitSHA: "abc", BaseBranch: "feature", RunURL: "https://github.example/run/1"}
	patch := "--- a/src/app.js\n+++ b/src/app.js\n@@ -1 +1 @@\n-const retries = 1;\n+const retries = 2;\n"
	result, err := CreateGitHubDraftPR(context.Background(), client, source, analysis, patch, "ciradar/repair-", 10, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !branchCreated || !fileUpdated || !pullCreated || result.PullRequestNumber != 12 || result.Status != "draft_pr_created" {
		t.Fatalf("flags=%v/%v/%v result=%#v", branchCreated, fileUpdated, pullCreated, result)
	}
}
