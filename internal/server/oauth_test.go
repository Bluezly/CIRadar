package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ciradar/internal/model"
)

func TestMCPOAuthAuthorizationCodePKCE(t *testing.T) {
	s, _, _ := testServer(t)
	login := httptest.NewRequest(http.MethodPost, "http://ciradar.test/auth/token", bytes.NewBufferString(`{"token":"root-secret","tenant":"default"}`))
	login.Header.Set("Content-Type", "application/json")
	login.RemoteAddr = "203.0.113.10:1234"
	loginResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(loginResult, login)
	if loginResult.Code != http.StatusOK || len(loginResult.Result().Cookies()) == 0 {
		t.Fatalf("login status=%d body=%s", loginResult.Code, loginResult.Body.String())
	}
	sessionCookie := loginResult.Result().Cookies()[0]
	registrationBody := `{"redirect_uris":["http://127.0.0.1:9876/callback"],"client_name":"MCP test","grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
	registration := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/register", strings.NewReader(registrationBody))
	registration.Header.Set("Content-Type", "application/json")
	registration.RemoteAddr = "203.0.113.10:1234"
	registrationResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(registrationResult, registration)
	if registrationResult.Code != http.StatusCreated {
		t.Fatalf("registration status=%d body=%s", registrationResult.Code, registrationResult.Body.String())
	}
	var registered map[string]any
	if err := json.Unmarshal(registrationResult.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	clientID, _ := registered["client_id"].(string)
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	authorizeURL := "http://ciradar.test/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://127.0.0.1:9876/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"ciradar.read ciradar.write"},
		"resource":              {"http://ciradar.test/mcp"},
		"state":                 {"state-1"},
	}.Encode()
	authorize := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	authorize.AddCookie(sessionCookie)
	authorize.RemoteAddr = "203.0.113.10:1234"
	authorizeResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(authorizeResult, authorize)
	if authorizeResult.Code != http.StatusOK || !strings.Contains(authorizeResult.Body.String(), "Authorize MCP test") {
		t.Fatalf("authorize status=%d body=%s", authorizeResult.Code, authorizeResult.Body.String())
	}
	if location := authorizeResult.Header().Get("Location"); location != "" {
		t.Fatalf("GET authorization unexpectedly redirected to %q", location)
	}
	authorizeForm := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://127.0.0.1:9876/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"ciradar.read ciradar.write"},
		"resource":              {"http://ciradar.test/mcp"},
		"state":                 {"state-1"},
		"decision":              {"approve"},
	}
	authorize = httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/authorize", strings.NewReader(authorizeForm.Encode()))
	authorize.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authorize.Header.Set("Origin", "http://ciradar.test")
	authorize.AddCookie(sessionCookie)
	authorize.RemoteAddr = "203.0.113.10:1234"
	authorizeResult = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(authorizeResult, authorize)
	if authorizeResult.Code != http.StatusFound {
		t.Fatalf("authorize approval status=%d body=%s", authorizeResult.Code, authorizeResult.Body.String())
	}
	location, err := url.Parse(authorizeResult.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" || location.Query().Get("state") != "state-1" {
		t.Fatalf("location=%s", location.String())
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {"http://127.0.0.1:9876/callback"}, "code": {code}, "code_verifier": {verifier}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.RemoteAddr = "203.0.113.10:1234"
	tokenResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(tokenResult, tokenRequest)
	if tokenResult.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokenResult.Code, tokenResult.Body.String())
	}
	var issued map[string]any
	if err := json.Unmarshal(tokenResult.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := issued["access_token"].(string)
	if !strings.HasPrefix(accessToken, "cir_oauth_") {
		t.Fatalf("access token=%q", accessToken)
	}
	status := doReq(t, s, http.MethodGet, "/api/v1/status", accessToken, "", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("OAuth status=%d body=%s", status.Code, status.Body.String())
	}
	replay := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/token", strings.NewReader(tokenForm.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay.RemoteAddr = "203.0.113.10:1234"
	replayResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(replayResult, replay)
	if replayResult.Code != http.StatusBadRequest || !strings.Contains(replayResult.Body.String(), "already used") {
		t.Fatalf("replay status=%d body=%s", replayResult.Code, replayResult.Body.String())
	}
	revoke := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/revoke", strings.NewReader(url.Values{"token": {accessToken}}.Encode()))
	revoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revoke.RemoteAddr = "203.0.113.10:1234"
	revokeResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(revokeResult, revoke)
	if revokeResult.Code != http.StatusOK {
		t.Fatalf("revoke status=%d", revokeResult.Code)
	}
	status = doReq(t, s, http.MethodGet, "/api/v1/status", accessToken, "", nil)
	if status.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status=%d", status.Code)
	}
}

func TestOAuthAuthorizationRequiresExplicitSameOriginConsent(t *testing.T) {
	s, _, _ := testServer(t)
	login := httptest.NewRequest(http.MethodPost, "http://ciradar.test/auth/token", bytes.NewBufferString(`{"token":"root-secret","tenant":"default"}`))
	login.Header.Set("Content-Type", "application/json")
	login.RemoteAddr = "203.0.113.10:1234"
	loginResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(loginResult, login)
	if loginResult.Code != http.StatusOK || len(loginResult.Result().Cookies()) == 0 {
		t.Fatalf("login status=%d body=%s", loginResult.Code, loginResult.Body.String())
	}
	sessionCookie := loginResult.Result().Cookies()[0]

	registration := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/register", strings.NewReader(`{"redirect_uris":["https://client.example/callback"],"client_name":"External client"}`))
	registration.Header.Set("Content-Type", "application/json")
	registration.RemoteAddr = "203.0.113.10:1234"
	registrationResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(registrationResult, registration)
	if registrationResult.Code != http.StatusCreated {
		t.Fatalf("registration status=%d body=%s", registrationResult.Code, registrationResult.Body.String())
	}
	var registered map[string]any
	if err := json.Unmarshal(registrationResult.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	clientID, _ := registered["client_id"].(string)
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://client.example/callback"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
		"scope":                 {"ciradar.read"},
		"resource":              {"http://ciradar.test/mcp"},
		"state":                 {"state-2"},
		"decision":              {"approve"},
	}

	get := httptest.NewRequest(http.MethodGet, "http://ciradar.test/oauth/authorize?"+form.Encode(), nil)
	get.AddCookie(sessionCookie)
	get.RemoteAddr = "203.0.113.10:1234"
	getResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(getResult, get)
	if getResult.Code != http.StatusOK || !strings.Contains(getResult.Body.String(), "External client") {
		t.Fatalf("consent status=%d body=%s", getResult.Code, getResult.Body.String())
	}
	if strings.Contains(getResult.Body.String(), "cir_oauth_") || getResult.Header().Get("Location") != "" {
		t.Fatal("GET authorization issued a code without consent")
	}

	crossSite := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/authorize", strings.NewReader(form.Encode()))
	crossSite.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossSite.Header.Set("Origin", "https://attacker.example")
	crossSite.AddCookie(sessionCookie)
	crossSite.RemoteAddr = "203.0.113.10:1234"
	crossSiteResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(crossSiteResult, crossSite)
	if crossSiteResult.Code != http.StatusForbidden {
		t.Fatalf("cross-site approval status=%d body=%s", crossSiteResult.Code, crossSiteResult.Body.String())
	}

	form.Set("decision", "deny")
	deny := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/authorize", strings.NewReader(form.Encode()))
	deny.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deny.Header.Set("Origin", "http://ciradar.test")
	deny.AddCookie(sessionCookie)
	deny.RemoteAddr = "203.0.113.10:1234"
	denyResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(denyResult, deny)
	if denyResult.Code != http.StatusFound {
		t.Fatalf("deny status=%d body=%s", denyResult.Code, denyResult.Body.String())
	}
	destination, err := url.Parse(denyResult.Header().Get("Location"))
	if err != nil || destination.Query().Get("error") != "access_denied" || destination.Query().Get("state") != "state-2" {
		t.Fatalf("deny redirect=%q err=%v", denyResult.Header().Get("Location"), err)
	}
}

func TestOAuthMetadataAndRedirectValidation(t *testing.T) {
	s, _, _ := testServer(t)
	metadata := doReq(t, s, http.MethodGet, "/.well-known/oauth-authorization-server", "", "", nil)
	if metadata.Code != http.StatusOK || !strings.Contains(metadata.Body.String(), "code_challenge_methods_supported") {
		t.Fatalf("metadata status=%d body=%s", metadata.Code, metadata.Body.String())
	}
	bad := httptest.NewRequest(http.MethodPost, "http://ciradar.test/oauth/register", strings.NewReader(`{"redirect_uris":["https://good.example/cb","http://evil.example/cb"]}`))
	bad.Header.Set("Content-Type", "application/json")
	bad.RemoteAddr = "203.0.113.10:1234"
	result := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(result, bad)
	if result.Code != http.StatusBadRequest {
		t.Fatalf("bad redirect status=%d", result.Code)
	}
}

func TestOAuthRejectsAmbiguousRedirectsAndResources(t *testing.T) {
	for _, raw := range []string{
		"https://user@example.com/callback",
		"https://example.com/callback#fragment",
	} {
		if validOAuthRedirect(raw) {
			t.Fatalf("redirect %q was accepted", raw)
		}
	}

	s, _, _ := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "http://ciradar.test/oauth/authorize", nil)
	for _, raw := range []string{
		"http://user@ciradar.test/mcp",
		"http://ciradar.test/mcp?tenant=other",
		"http://ciradar.test/mcp#fragment",
		"http://ciradar.test/%6dcp",
	} {
		if s.validOAuthResource(r, raw) {
			t.Fatalf("resource %q was accepted", raw)
		}
	}
	if !s.validOAuthResource(r, "http://ciradar.test/mcp") {
		t.Fatal("canonical MCP resource was rejected")
	}
}

func TestOAuthReadScopeCannotWrite(t *testing.T) {
	s, _, _ := testServer(t)
	now := time.Now().UTC()
	raw, err := sealOAuthValue(s.dashboardSecret(), "access", oauthAccessToken{
		ID:       "read-only-token",
		Resource: "http://ciradar.test/mcp",
		Scope:    "ciradar.read",
		Principal: model.Principal{
			TenantID: model.DefaultTenantID,
			Name:     "oauth-reader",
			Role:     model.RoleOperator,
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	read := doReq(t, s, http.MethodGet, "/api/v1/status", raw, "", nil)
	if read.Code != http.StatusOK {
		t.Fatalf("read status=%d body=%s", read.Code, read.Body.String())
	}
	write := doReq(t, s, http.MethodPost, "/api/v1/analyze", raw, "", strings.NewReader(`{"log":"npm ERR! ECONNRESET"}`))
	if write.Code != http.StatusForbidden || !strings.Contains(write.Body.String(), "ciradar.write") {
		t.Fatalf("write status=%d body=%s", write.Code, write.Body.String())
	}
	listBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	listRequest := httptest.NewRequest(http.MethodPost, "http://ciradar.test/mcp", strings.NewReader(listBody))
	listRequest.Header.Set("Authorization", "Bearer "+raw)
	listRequest.Header.Set("Content-Type", "application/json")
	listRequest.RemoteAddr = "203.0.113.10:1234"
	list := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(list, listRequest)
	if list.Code != http.StatusOK {
		t.Fatalf("MCP list status=%d body=%s", list.Code, list.Body.String())
	}
	if strings.Contains(list.Body.String(), "prepare_action") {
		t.Fatalf("read-only OAuth token exposed write tools: %s", list.Body.String())
	}
	writeBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"acknowledge_incident","arguments":{"target":"fp","confirmation_token":"x"}}}`
	writeRequest := httptest.NewRequest(http.MethodPost, "http://ciradar.test/mcp", strings.NewReader(writeBody))
	writeRequest.Header.Set("Authorization", "Bearer "+raw)
	writeRequest.Header.Set("Content-Type", "application/json")
	writeRequest.RemoteAddr = "203.0.113.10:1234"
	mcpWrite := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(mcpWrite, writeRequest)
	if mcpWrite.Code != http.StatusForbidden || !strings.Contains(mcpWrite.Body.String(), "ciradar.write") {
		t.Fatalf("MCP write status=%d body=%s", mcpWrite.Code, mcpWrite.Body.String())
	}
}

func TestOAuthRejectsUnsignedPlaintextToken(t *testing.T) {
	s, _, _ := testServer(t)
	now := time.Now().UTC()
	forged, err := json.Marshal(oauthAccessToken{
		ID:       "forged-token",
		Resource: "http://ciradar.test/mcp",
		Scope:    "ciradar.read ciradar.write",
		Principal: model.Principal{
			TenantID: model.DefaultTenantID,
			Name:     "attacker",
			Role:     model.RoleAdmin,
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	token := "cir_oauth_" + base64.RawURLEncoding.EncodeToString(forged)
	response := doReq(t, s, http.MethodGet, "/api/v1/status", token, "", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned OAuth token status=%d body=%s", response.Code, response.Body.String())
	}
}
