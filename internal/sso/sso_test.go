package sso

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	authRequest := httptest.NewRequest(http.MethodGet, "http://ciradar.example/", nil)
	authRequest.AddCookie(session)
	principal, ok := callbackManager.Authenticate(authRequest)
	if !ok || principal.TenantID != "acme" || principal.Role != model.RoleOperator {
		t.Fatalf("principal=%#v ok=%v", principal, ok)
	}
}
