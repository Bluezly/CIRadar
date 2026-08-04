package connectors

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestParseAdditionalProviders(t *testing.T) {
	cases := []struct {
		name       string
		payload    any
		provider   string
		conclusion string
	}{
		{"azure", map[string]any{"eventType": "build.complete", "resource": map[string]any{"id": 42, "status": "completed", "result": "failed", "sourceVersion": "abc", "sourceBranch": "refs/heads/main", "definition": map[string]any{"id": 2, "name": "CI"}, "project": map[string]any{"id": "p1", "name": "Acme"}, "repository": map[string]any{"id": "r1", "name": "api"}, "_links": map[string]any{"web": map[string]any{"href": "https://dev.azure.com/run"}}}}, "azuredevops", "failure"},
		{"bitrise", map[string]any{"build_slug": "b1", "app_slug": "a1", "build_status": -1, "build_number": 7, "commit_hash": "abc", "branch": "main", "workflow_id": "primary"}, "bitrise", "failure"},
		{"teamcity", map[string]any{"build": map[string]any{"id": 12, "status": "FAILURE", "state": "finished", "branchName": "main"}, "buildType": map[string]any{"id": "BT", "name": "Build", "projectName": "Acme"}}, "teamcity", "failure"},
		{"travis", map[string]any{"id": 9, "state": "failed", "commit": map[string]any{"sha": "abc"}, "repository": map[string]any{"slug": "acme/api"}, "job": map[string]any{"id": 10, "state": "failed", "name": "test"}}, "travis", "failure"},
		{"codebuild", map[string]any{"id": "evt", "detail-type": "CodeBuild Build State Change", "time": "2026-08-04T10:00:00Z", "region": "us-east-1", "account": "1", "detail": map[string]any{"build-status": "FAILED", "project-name": "api", "build-id": "arn:build", "current-phase": "BUILD", "additional-information": map[string]any{"source": map[string]any{"location": "acme/api"}, "phases": []any{map[string]any{"phase-type": "BUILD", "phase-status": "FAILED", "phase-context": []string{"command failed"}}}}}}, "codebuild", "failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.payload)
			ev, err := ParseWebhook(tc.provider, "tenant", "delivery", b)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Provider != tc.provider || ev.Conclusion != tc.conclusion {
				t.Fatalf("got %s %s", ev.Provider, ev.Conclusion)
			}
			if ev.TenantID != "tenant" {
				t.Fatal("tenant missing")
			}
		})
	}
}

func TestGenericWebhookVerification(t *testing.T) {
	h := http.Header{}
	h.Set("X-CI-Radar-Token", "secret")
	if !VerifyWebhook("azuredevops", "secret", h, []byte("{}"), time.Now()) {
		t.Fatal("token verification failed")
	}
	if VerifyWebhook("azuredevops", "wrong", h, []byte("{}"), time.Now()) {
		t.Fatal("accepted wrong token")
	}
}
