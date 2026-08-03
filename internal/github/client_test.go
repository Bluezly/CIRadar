package github

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAppJWTSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	c, err := New(12345, f.Name(), "https://api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	token, err := c.AppJWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("parts=%d", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWebhook(t *testing.T) {
	body := []byte(`{"action":"completed"}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifyWebhook("secret", body, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyWebhook("wrong", body, sig) {
		t.Fatal("invalid signature accepted")
	}
}

func TestGitHubClientFlowAgainstMockAPI(t *testing.T) {
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
	_ = keyFile.Close()

	var checkReceived bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/1/access_tokens":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Fatalf("missing app JWT")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "installation-token", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/actions/runs/22/jobs":
			if r.Header.Get("Authorization") != "Bearer installation-token" {
				t.Fatalf("wrong installation auth")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 1, "jobs": []map[string]any{{"id": 33, "name": "test", "status": "completed", "conclusion": "failure"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/actions/jobs/33/logs":
			_, _ = w.Write([]byte("npm ERR! code ECONNRESET"))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/actions/runs":
			if r.URL.Query().Get("head_sha") != "abc" || r.URL.Query().Get("status") != "success" {
				t.Fatalf("unexpected run query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 1, "workflow_runs": []map[string]any{{"id": 21, "head_sha": "abc", "status": "completed", "conclusion": "success"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/check-runs":
			var request CheckRunRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.HeadSHA != "abc" || request.Name == "" {
				t.Fatalf("bad check request: %+v", request)
			}
			checkReceived = true
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := New(12345, keyFile.Name(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	jobs, err := client.ListJobs(ctx, 1, "o", "r", 22)
	if err != nil || len(jobs) != 1 || jobs[0].ID != 33 {
		t.Fatalf("jobs=%+v err=%v", jobs, err)
	}
	logText, err := client.DownloadJobLog(ctx, 1, "o", "r", 33, 1024)
	if err != nil || !strings.Contains(logText, "ECONNRESET") {
		t.Fatalf("log=%q err=%v", logText, err)
	}
	previous, err := client.HasPreviousSuccessfulRun(ctx, 1, "o", "r", "abc", 22)
	if err != nil || !previous {
		t.Fatalf("previous=%v err=%v", previous, err)
	}
	if err := client.CreateCheckRun(ctx, 1, "o", "r", CheckRunRequest{Name: "CI Radar / test", HeadSHA: "abc", Status: "completed", Conclusion: "neutral", Output: CheckOutput{Title: "Diagnosis", Summary: "Summary"}}); err != nil {
		t.Fatal(err)
	}
	if !checkReceived {
		t.Fatal("check run was not received")
	}
}
