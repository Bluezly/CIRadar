package sso

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/model"
)

func TestProxyPrincipal(t *testing.T) {
	m, e := New(config.SSOConfig{Enabled: true, Mode: "saml_proxy", TrustedProxyCIDRs: []string{"127.0.0.0/8"}, ProxySecretHeader: "X-Secret", ProxySecret: "secret", ProxySubjectHeader: "X-User", ProxyEmailHeader: "X-Email", ProxyNameHeader: "X-Name", ProxyTenantHeader: "X-Tenant", ProxyRoleHeader: "X-Role", DefaultTenant: "default", DefaultRole: "viewer", SessionSecret: "01234567890123456789012345678901", AllowPrivateNetwork: true, CookieName: "session"})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "http://example/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Secret", "secret")
	r.Header.Set("X-User", "alice")
	r.Header.Set("X-Email", "alice@example.com")
	r.Header.Set("X-Tenant", "acme")
	r.Header.Set("X-Role", "operator")
	p, ok := m.Authenticate(r)
	if !ok || p.TenantID != "acme" || p.Role != model.RoleOperator {
		t.Fatalf("%#v %v", p, ok)
	}
}
func TestIdentityClaims(t *testing.T) {
	m, e := New(config.SSOConfig{Enabled: true, Mode: "oidc", AllowedDomains: []string{"example.com"}, TenantClaim: "tenant", RoleClaim: "role", GroupsClaim: "groups", AdminGroups: []string{"admins"}, DefaultTenant: "default", DefaultRole: "viewer"})
	if e != nil {
		t.Fatal(e)
	}
	id, e := m.identityFromClaims(map[string]any{"sub": "1", "email": "a@example.com", "email_verified": true, "tenant": "acme", "role": "viewer", "groups": []any{"admins"}})
	if e != nil {
		t.Fatal(e)
	}
	if id.TenantID != "acme" || id.Role != model.RoleAdmin {
		t.Fatalf("%#v", id)
	}
}

func TestOIDCAuthorizationCodePKCEFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer *httptest.Server
	var expectedNonce string
	var sawVerifier bool
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/jwks"})
		case "/jwks":
			n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "test", "alg": "RS256", "n": n, "e": e}}})
		case "/token":
			_ = r.ParseForm()
			sawVerifier = r.Form.Get("code_verifier") != ""
			header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
			claims, _ := json.Marshal(map[string]any{"iss": issuer.URL, "aud": "ciradar", "sub": "alice", "email": "alice@example.com", "email_verified": true, "tenant_id": "acme", "role": "operator", "nonce": expectedNonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
			h := base64.RawURLEncoding.EncodeToString(header)
			c := base64.RawURLEncoding.EncodeToString(claims)
			digest := sha256.Sum256([]byte(h + "." + c))
			sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": h + "." + c + "." + base64.RawURLEncoding.EncodeToString(sig)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	m, err := New(config.SSOConfig{Enabled: true, Mode: "oidc", IssuerURL: issuer.URL, ClientID: "ciradar", RedirectURL: "http://ciradar.example/auth/callback", Scopes: []string{"openid", "email"}, AllowedDomains: []string{"example.com"}, TenantClaim: "tenant_id", RoleClaim: "role", GroupsClaim: "groups", DefaultTenant: "default", DefaultRole: "viewer", SessionSecret: "01234567890123456789012345678901", AllowPrivateNetwork: true, CookieName: "ciradar_session"})
	if err != nil {
		t.Fatal(err)
	}
	loginRequest := httptest.NewRequest(http.MethodGet, "http://ciradar.example/auth/login?return_to=/dashboard", nil)
	loginResponse := httptest.NewRecorder()
	m.Login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login status %d", loginResponse.Code)
	}
	location, _ := url.Parse(loginResponse.Header().Get("Location"))
	state := location.Query().Get("state")
	if state == "" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("bad authorize URL %s", location.String())
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing flow cookie")
	}
	if !strings.HasPrefix(cookies[0].Value, "v1.") || strings.Contains(cookies[0].Value, state) {
		t.Fatalf("OIDC flow cookie is not encrypted: %q", cookies[0].Value)
	}
	flowRequest := httptest.NewRequest(http.MethodGet, "http://ciradar.example/auth/callback", nil)
	flowRequest.AddCookie(cookies[0])
	flow, err := m.readFlow(flowRequest)
	if err != nil {
		t.Fatal(err)
	}
	expectedNonce = flow.Nonce
	callbackManager, err := New(m.cfg)
	if err != nil {
		t.Fatal(err)
	}
	callbackRequest := httptest.NewRequest(http.MethodGet, "http://ciradar.example/auth/callback?state="+url.QueryEscape(state)+"&code=ok", nil)
	callbackRequest.AddCookie(cookies[0])
	callbackResponse := httptest.NewRecorder()
	callbackManager.Callback(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound || callbackResponse.Header().Get("Location") != "/dashboard" || !sawVerifier {
		t.Fatalf("callback status=%d location=%q verifier=%v", callbackResponse.Code, callbackResponse.Header().Get("Location"), sawVerifier)
	}
	var session *http.Cookie
	for _, cookie := range callbackResponse.Result().Cookies() {
		if cookie.Name == "ciradar_session" && cookie.Value != "" {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("missing session cookie")
	}
	if !strings.HasPrefix(session.Value, "v1.") || strings.Contains(session.Value, "alice@example.com") || strings.Contains(session.Value, "acme") {
		t.Fatalf("SSO session cookie is not encrypted: %q", session.Value)
	}
	authRequest := httptest.NewRequest(http.MethodGet, "http://ciradar.example/", nil)
	authRequest.AddCookie(session)
	principal, ok := callbackManager.Authenticate(authRequest)
	if !ok || principal.TenantID != "acme" || principal.Role != model.RoleOperator {
		t.Fatalf("principal=%#v ok=%v", principal, ok)
	}
}

func TestNativeSAMLFlow(t *testing.T) {
	xmlsec := filepath.Join(t.TempDir(), "xmlsec1")
	if err := os.WriteFile(xmlsec, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.SSOConfig{Enabled: true, Mode: "saml", SessionSecret: "01234567890123456789012345678901", AllowPrivateNetwork: true, CookieName: "ciradar_session", SAMLEntityID: "https://ciradar.example/saml", SAMLIdPSSOURL: "https://idp.example/sso", SAMLIdPEntityID: "https://idp.example/metadata", SAMLIdPCertificate: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----", SAMLACSURL: "https://ciradar.example/auth/callback", SAMLXMLSecPath: xmlsec, SAMLEmailAttribute: "email", SAMLNameAttribute: "name", SAMLClockSkew: 2 * time.Minute, TenantClaim: "tenant_id", RoleClaim: "role", GroupsClaim: "groups", DefaultTenant: "default", DefaultRole: "viewer"}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodGet, "https://ciradar.example/auth/login?return_to=/dashboard", nil)
	loginResult := httptest.NewRecorder()
	manager.Login(loginResult, login)
	if loginResult.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", loginResult.Code, loginResult.Body.String())
	}
	location, err := url.Parse(loginResult.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	relay := location.Query().Get("RelayState")
	cookies := loginResult.Result().Cookies()
	if relay == "" || len(cookies) == 0 {
		t.Fatalf("location=%s cookies=%d", location.String(), len(cookies))
	}
	flowRequest := httptest.NewRequest(http.MethodGet, "https://ciradar.example/", nil)
	flowRequest.AddCookie(cookies[0])
	flow, err := manager.readFlow(flowRequest)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	response := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" InResponseTo="%s" Destination="%s"><saml:Issuer>%s</saml:Issuer><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_response"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ignored</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>ignored</ds:SignatureValue></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assertion"><saml:Issuer>%s</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="%s" Recipient="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue>Alice</saml:AttributeValue></saml:Attribute><saml:Attribute Name="tenant_id"><saml:AttributeValue>acme</saml:AttributeValue></saml:Attribute><saml:Attribute Name="role"><saml:AttributeValue>operator</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`, flow.RequestID, cfg.SAMLACSURL, cfg.SAMLIdPEntityID, cfg.SAMLIdPEntityID, flow.RequestID, cfg.SAMLACSURL, now.Add(5*time.Minute).Format(time.RFC3339Nano), now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(5*time.Minute).Format(time.RFC3339Nano), cfg.SAMLEntityID)
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(response))}, "RelayState": {relay}}
	callback := httptest.NewRequest(http.MethodPost, "https://ciradar.example/auth/callback", strings.NewReader(form.Encode()))
	callback.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	callback.AddCookie(cookies[0])
	callbackResult := httptest.NewRecorder()
	manager.Callback(callbackResult, callback)
	if callbackResult.Code != http.StatusFound || callbackResult.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback status=%d location=%q body=%s", callbackResult.Code, callbackResult.Header().Get("Location"), callbackResult.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range callbackResult.Result().Cookies() {
		if cookie.Name == cfg.CookieName && cookie.Value != "" {
			session = cookie
		}
	}
	if session == nil || strings.Contains(session.Value, "alice") || strings.Contains(session.Value, "acme") {
		t.Fatalf("session=%#v", session)
	}
	authRequest := httptest.NewRequest(http.MethodGet, "https://ciradar.example/", nil)
	authRequest.AddCookie(session)
	principal, ok := manager.Authenticate(authRequest)
	if !ok || principal.TenantID != "acme" || principal.Role != model.RoleOperator || principal.Name != "Alice" {
		t.Fatalf("principal=%#v ok=%v", principal, ok)
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "https://ciradar.example/auth/callback", strings.NewReader(form.Encode()))
	replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRequest.AddCookie(cookies[0])
	replayResult := httptest.NewRecorder()
	manager.Callback(replayResult, replayRequest)
	if replayResult.Code != http.StatusUnauthorized || !strings.Contains(replayResult.Body.String(), "already been used") {
		t.Fatalf("replay status=%d body=%s", replayResult.Code, replayResult.Body.String())
	}
}

func TestSAMLShapeRejectsWrappingAndNamespaces(t *testing.T) {
	valid := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#r"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference></ds:SignedInfo></ds:Signature><samlp:Status/><saml:Assertion ID="a"><saml:Subject/><saml:Conditions/></saml:Assertion></samlp:Response>`
	if err := validateSAMLShape([]byte(valid), "request"); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`<!DOCTYPE x><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
		`<Response xmlns="urn:wrong" ID="r"><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a"/><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><Reference URI="#a"/></SignedInfo></Signature></Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:Reference URI="#other"/></ds:SignedInfo></ds:Signature><saml:Assertion ID="a"/></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="same"><ds:Signature><ds:SignedInfo><ds:Reference URI="#same"/></ds:SignedInfo></ds:Signature><saml:Assertion ID="same"/></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:evil="urn:evil" evil:ID="r"><saml:Assertion ID="a"><ds:Signature><ds:SignedInfo><ds:Reference URI="#a"/></ds:SignedInfo></ds:Signature></saml:Assertion></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><wrapper><saml:Assertion ID="a"><ds:Signature><ds:SignedInfo><ds:Reference URI="#a"/></ds:SignedInfo></ds:Signature></saml:Assertion></wrapper></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:Reference URI="#a"/></ds:SignedInfo></ds:Signature><saml:Assertion ID="a"/></samlp:Response>`,
	}

	for _, sample := range cases {
		if err := validateSAMLShape([]byte(sample), "request"); err == nil {
			t.Fatalf("expected rejection for %s", sample)
		}
	}
}

func TestSAMLMetadata(t *testing.T) {
	m, err := New(config.SSOConfig{Enabled: true, Mode: "saml", SessionSecret: "01234567890123456789012345678901", SAMLEntityID: "https://ciradar.example/saml", SAMLACSURL: "https://ciradar.example/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/saml/metadata", nil)
	rr := httptest.NewRecorder()
	m.SAMLMetadata(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `entityID="https://ciradar.example/saml"`) || !strings.Contains(rr.Body.String(), `WantAssertionsSigned="true"`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestOIDCBlocksPrivateIssuerByDefault(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://issuer.example",
			"authorization_endpoint": "https://issuer.example/authorize",
			"token_endpoint":         "https://issuer.example/token",
			"jwks_uri":               "https://issuer.example/jwks",
		})
	}))
	defer issuer.Close()
	m, err := New(config.SSOConfig{Enabled: true, Mode: "oidc", IssuerURL: issuer.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.getDiscovery(context.Background()); err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("private issuer was not blocked: %v", err)
	}
}

func TestOIDCDiscoveryIssuerMustMatchConfiguration(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://attacker.example",
			"authorization_endpoint": "https://attacker.example/authorize",
			"token_endpoint":         "https://attacker.example/token",
			"jwks_uri":               "https://attacker.example/jwks",
		})
	}))
	defer issuer.Close()
	m, err := New(config.SSOConfig{Enabled: true, Mode: "oidc", IssuerURL: issuer.URL, AllowPrivateNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.getDiscovery(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched issuer was accepted: %v", err)
	}
}

func TestSafeReturnToRejectsExternalAndEncodedRedirects(t *testing.T) {
	for _, value := range []string{
		"https://evil.example/",
		"//evil.example/path",
		"/\\evil.example/path",
		"/%2f%2fevil.example/path",
		"/%252f%252fevil.example/path",
		"/ok\r\nLocation: https://evil.example/",
	} {
		if got := safeReturnTo(value); got != "/" {
			t.Errorf("safeReturnTo(%q)=%q, want /", value, got)
		}
	}
	for _, value := range []string{"/", "/dashboard", "/incidents?id=123"} {
		if got := safeReturnTo(value); got != value {
			t.Errorf("safeReturnTo(%q)=%q", value, got)
		}
	}
}

func TestIdentityClaimsRequireStableSubjectAndVerifiedEmail(t *testing.T) {
	m, err := New(config.SSOConfig{Enabled: true, Mode: "oidc", AllowedDomains: []string{"example.com"}, DefaultTenant: "default", DefaultRole: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.identityFromClaims(map[string]any{"email": "a@example.com"}); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("identity without sub accepted: %v", err)
	}
	if _, err := m.identityFromClaims(map[string]any{"sub": "alice", "email": "a@example.com", "email_verified": false}); err == nil || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("unverified email accepted: %v", err)
	}
	if _, err := m.identityFromClaims(map[string]any{"sub": "alice", "email": "a@example.com", "email_verified": "false"}); err == nil || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("malformed email verification claim accepted: %v", err)
	}
	if _, err := m.identityFromClaims(map[string]any{"sub": "alice", "email": "a@example.com"}); err == nil || !strings.Contains(err.Error(), "verified email") {
		t.Fatalf("unverified domain-gated email accepted: %v", err)
	}
	if _, err := m.identityFromClaims(map[string]any{"sub": "alice", "preferred_username": "a@example.com", "email_verified": true}); err == nil || !strings.Contains(err.Error(), "verified email") {
		t.Fatalf("preferred_username bypassed allowed_domains: %v", err)
	}
	if _, err := m.identityFromClaims(map[string]any{"sub": "alice", "email": "a@example.com", "email_verified": true}); err != nil {
		t.Fatalf("verified identity rejected: %v", err)
	}
}

func TestOIDCMultipleAudiencesRequireAuthorizedParty(t *testing.T) {
	audiences := []any{"ciradar", "another-client"}
	if validAudienceClaims(audiences, "", "ciradar") {
		t.Fatal("multiple audiences accepted without azp")
	}
	if validAudienceClaims(audiences, "another-client", "ciradar") {
		t.Fatal("multiple audiences accepted with mismatched azp")
	}
	if !validAudienceClaims(audiences, "ciradar", "ciradar") {
		t.Fatal("matching azp was rejected")
	}
	if !validAudienceClaims("ciradar", "", "ciradar") {
		t.Fatal("single matching audience was rejected")
	}
	if validAudienceClaims("ciradar", "another-client", "ciradar") {
		t.Fatal("single audience accepted with mismatched azp")
	}
	if validAudienceClaims([]any{"ciradar", 7}, "ciradar", "ciradar") {
		t.Fatal("malformed audience array was accepted")
	}
}

func TestParseJWKRejectsWeakAndInvalidKeys(t *testing.T) {
	weakRSA := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(big.NewInt(17).Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{3}),
	}
	if _, err := parseJWK(weakRSA); err == nil {
		t.Fatal("weak RSA JWK accepted")
	}
	invalidEC := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"y":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	if _, err := parseJWK(invalidEC); err == nil {
		t.Fatal("off-curve EC JWK accepted")
	}
}

func TestReadLimitedResponseBodyRejectsOversizedBody(t *testing.T) {
	if _, err := readLimitedResponseBody(strings.NewReader("12345"), 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
	body, err := readLimitedResponseBody(strings.NewReader("1234"), 4)
	if err != nil || string(body) != "1234" {
		t.Fatalf("body=%q err=%v", string(body), err)
	}
}

func TestSAMLSecurityProfiles(t *testing.T) {
	secure := samlShape{CanonicalizationAlg: "http://www.w3.org/2001/10/xml-exc-c14n#", SignatureAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", DigestAlg: "http://www.w3.org/2001/04/xmlenc#sha256", Transforms: []string{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"}}
	responseSigned := secure
	responseSigned.ResponseID, responseSigned.AssertionID, responseSigned.SignedID = "r", "a", "r"
	assertionSigned := secure
	assertionSigned.ResponseID, assertionSigned.AssertionID, assertionSigned.SignedID = "r", "a", "a"
	if err := validateSAMLSecurityProfile(responseSigned, "strict"); err != nil {
		t.Fatal(err)
	}
	if err := validateSAMLSecurityProfile(assertionSigned, "strict"); err == nil {
		t.Fatal("strict profile accepted assertion-only signature")
	}
	if err := validateSAMLSecurityProfile(assertionSigned, "compatibility"); err != nil {
		t.Fatal(err)
	}
}

func TestSAMLSecurityProfileRejectsWeakAlgorithms(t *testing.T) {
	base := samlShape{
		ResponseID:          "r",
		AssertionID:         "a",
		SignedID:            "r",
		CanonicalizationAlg: "http://www.w3.org/2001/10/xml-exc-c14n#",
		SignatureAlg:        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		DigestAlg:           "http://www.w3.org/2001/04/xmlenc#sha256",
		Transforms:          []string{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
	}
	weakSignature := base
	weakSignature.SignatureAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	if err := validateSAMLSecurityProfile(weakSignature, "strict"); err == nil {
		t.Fatal("SHA-1 SAML signature was accepted")
	}
	weakDigest := base
	weakDigest.DigestAlg = "http://www.w3.org/2000/09/xmldsig#sha1"
	if err := validateSAMLSecurityProfile(weakDigest, "strict"); err == nil {
		t.Fatal("SHA-1 SAML digest was accepted")
	}
	unsafeTransform := base
	unsafeTransform.Transforms = []string{"http://www.w3.org/TR/1999/REC-xslt-19991116", "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}
	if err := validateSAMLSecurityProfile(unsafeTransform, "strict"); err == nil {
		t.Fatal("XSLT SAML transform was accepted")
	}
	noEnvelope := base
	noEnvelope.Transforms = []string{"http://www.w3.org/2001/10/xml-exc-c14n#"}
	if err := validateSAMLSecurityProfile(noEnvelope, "strict"); err == nil {
		t.Fatal("signature without enveloped transform was accepted")
	}
}

func TestSAMLShapeRejectsDuplicateSecurityElements(t *testing.T) {
	samples := []string{
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:Reference URI="#r"/></ds:SignedInfo></ds:Signature><samlp:Status/><samlp:Status/><saml:Assertion ID="a"><saml:Subject/><saml:Conditions/></saml:Assertion></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:Reference URI="#r"/></ds:SignedInfo></ds:Signature><samlp:Status/><saml:Assertion ID="a"><saml:Subject/><saml:Subject/><saml:Conditions/></saml:Assertion></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:Reference URI="#r"/></ds:SignedInfo></ds:Signature><samlp:Status/><saml:Assertion ID="a"><saml:Subject/><saml:Conditions/><saml:Conditions/></saml:Assertion></samlp:Response>`,
	}
	for _, sample := range samples {
		if err := validateSAMLShape([]byte(sample), "request"); err == nil {
			t.Fatalf("duplicate security element was accepted: %s", sample)
		}
	}
}

func TestSAMLAudienceRestrictionsRequireEveryRestriction(t *testing.T) {
	const entityID = "https://ciradar.example/saml"
	tests := []struct {
		name         string
		restrictions []samlAudienceRestriction
		want         bool
	}{
		{name: "missing", want: false},
		{name: "single matching", restrictions: []samlAudienceRestriction{{Audiences: []string{entityID}}}, want: true},
		{name: "one of multiple audiences matches", restrictions: []samlAudienceRestriction{{Audiences: []string{"https://other.example", entityID}}}, want: true},
		{name: "single mismatch", restrictions: []samlAudienceRestriction{{Audiences: []string{"https://other.example"}}}, want: false},
		{name: "all restrictions match", restrictions: []samlAudienceRestriction{{Audiences: []string{entityID}}, {Audiences: []string{"https://other.example", entityID}}}, want: true},
		{name: "one restriction rejects", restrictions: []samlAudienceRestriction{{Audiences: []string{entityID}}, {Audiences: []string{"https://other.example"}}}, want: false},
		{name: "empty restriction rejects", restrictions: []samlAudienceRestriction{{Audiences: []string{entityID}}, {}}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := samlAudienceRestrictionsAllow(tt.restrictions, entityID); got != tt.want {
				t.Fatalf("samlAudienceRestrictionsAllow()=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestSAMLXMLVerificationHonorsParentCancellation(t *testing.T) {
	dir := t.TempDir()
	xmlsec := filepath.Join(dir, "xmlsec1")
	if err := os.WriteFile(xmlsec, []byte("#!/bin/sh\nsleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := verifySAMLXML(ctx, xmlsec, "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----", []byte("<Response/>"))
	if err == nil {
		t.Fatal("cancelled SAML verification unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled SAML verification took too long: %s", elapsed)
	}
}

func FuzzInspectSAMLShape(f *testing.F) {
	for _, seed := range []string{
		`<Response/>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"/></samlp:Response>`,
		`<!DOCTYPE x [<!ENTITY y "z">]><x>&y;</x>`,
		strings.Repeat("<x>", 70) + strings.Repeat("</x>", 70),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = inspectSAMLShape([]byte(raw), "_request")
	})
}

func TestOIDCDiscoveryIssuerRequiresExactMatch(t *testing.T) {
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer.URL,
			"authorization_endpoint": issuer.URL + "/authorize",
			"token_endpoint":         issuer.URL + "/token",
			"jwks_uri":               issuer.URL + "/jwks",
		})
	}))
	defer issuer.Close()
	m, err := New(config.SSOConfig{Enabled: true, Mode: "oidc", IssuerURL: issuer.URL + "/", AllowPrivateNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.getDiscovery(context.Background()); err == nil || !strings.Contains(err.Error(), "exactly") {
		t.Fatalf("issuer differing by trailing slash was accepted: %v", err)
	}
}

func TestValidateJWKUsageRejectsNonSigningMetadata(t *testing.T) {
	for _, key := range []map[string]any{
		{"use": "enc"},
		{"alg": "RS512"},
		{"key_ops": []any{"encrypt"}},
		{"key_ops": []any{"verify", 7}},
	} {
		if err := validateJWKUsage(key, "RS256"); err == nil {
			t.Fatalf("unsafe JWK metadata accepted: %#v", key)
		}
	}
	if err := validateJWKUsage(map[string]any{"use": "sig", "alg": "RS256", "key_ops": []any{"verify"}}, "RS256"); err != nil {
		t.Fatalf("valid JWK metadata rejected: %v", err)
	}
}
