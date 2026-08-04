package sso

import (
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
	m, e := New(config.SSOConfig{Enabled: true, Mode: "saml_proxy", TrustedProxyCIDRs: []string{"127.0.0.0/8"}, ProxySecretHeader: "X-Secret", ProxySecret: "secret", ProxySubjectHeader: "X-User", ProxyEmailHeader: "X-Email", ProxyNameHeader: "X-Name", ProxyTenantHeader: "X-Tenant", ProxyRoleHeader: "X-Role", DefaultTenant: "default", DefaultRole: "viewer", SessionSecret: "01234567890123456789012345678901", CookieName: "session"})
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
	id, e := m.identityFromClaims(map[string]any{"sub": "1", "email": "a@example.com", "tenant": "acme", "role": "viewer", "groups": []any{"admins"}})
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
			claims, _ := json.Marshal(map[string]any{"iss": issuer.URL, "aud": "ciradar", "sub": "alice", "email": "alice@example.com", "tenant_id": "acme", "role": "operator", "nonce": expectedNonce, "exp": time.Now().Add(time.Hour).Unix()})
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
	m, err := New(config.SSOConfig{Enabled: true, Mode: "oidc", IssuerURL: issuer.URL, ClientID: "ciradar", RedirectURL: "http://ciradar.example/auth/callback", Scopes: []string{"openid", "email"}, AllowedDomains: []string{"example.com"}, TenantClaim: "tenant_id", RoleClaim: "role", GroupsClaim: "groups", DefaultTenant: "default", DefaultRole: "viewer", SessionSecret: "01234567890123456789012345678901", CookieName: "ciradar_session"})
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
	cfg := config.SSOConfig{Enabled: true, Mode: "saml", SessionSecret: "01234567890123456789012345678901", CookieName: "ciradar_session", SAMLEntityID: "https://ciradar.example/saml", SAMLIdPSSOURL: "https://idp.example/sso", SAMLIdPEntityID: "https://idp.example/metadata", SAMLIdPCertificate: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----", SAMLACSURL: "https://ciradar.example/auth/callback", SAMLXMLSecPath: xmlsec, SAMLEmailAttribute: "email", SAMLNameAttribute: "name", SAMLClockSkew: 2 * time.Minute, TenantClaim: "tenant_id", RoleClaim: "role", GroupsClaim: "groups", DefaultTenant: "default", DefaultRole: "viewer"}
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
	response := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" InResponseTo="%s" Destination="%s"><saml:Issuer>%s</saml:Issuer><ds:Signature><ds:SignedInfo><ds:Reference URI="#_assertion"/></ds:SignedInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assertion"><saml:Issuer>%s</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="%s" Recipient="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue>Alice</saml:AttributeValue></saml:Attribute><saml:Attribute Name="tenant_id"><saml:AttributeValue>acme</saml:AttributeValue></saml:Attribute><saml:Attribute Name="role"><saml:AttributeValue>operator</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`, flow.RequestID, cfg.SAMLACSURL, cfg.SAMLIdPEntityID, cfg.SAMLIdPEntityID, flow.RequestID, cfg.SAMLACSURL, now.Add(5*time.Minute).Format(time.RFC3339Nano), now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(5*time.Minute).Format(time.RFC3339Nano), cfg.SAMLEntityID)
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
}

func TestSAMLShapeRejectsWrappingAndNamespaces(t *testing.T) {
	valid := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:Reference URI="#a"/></ds:SignedInfo></ds:Signature><saml:Assertion ID="a"/></samlp:Response>`
	if err := validateSAMLShape([]byte(valid), "request"); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`<!DOCTYPE x><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
		`<Response xmlns="urn:wrong" ID="r"><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a"/><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><Reference URI="#a"/></SignedInfo></Signature></Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r"><ds:Signature><ds:SignedInfo><ds:Reference URI="#other"/></ds:SignedInfo></ds:Signature><saml:Assertion ID="a"/></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="same"><ds:Signature><ds:SignedInfo><ds:Reference URI="#same"/></ds:SignedInfo></ds:Signature><saml:Assertion ID="same"/></samlp:Response>`,
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
