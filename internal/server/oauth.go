package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Bluezly/CIRadar/internal/logsafe"
	"github.com/Bluezly/CIRadar/internal/model"
	"github.com/Bluezly/CIRadar/internal/secrets"
)

const (
	oauthClientNameMaxBytes    = 128
	oauthClientURIMaxBytes     = 2048
	oauthSoftwareFieldMaxBytes = 128
	oauthRedirectURIMaxBytes   = 2048
	oauthDynamicClientLimit    = 1000
	oauthPKCEVerifierMinBytes  = 43
	oauthPKCEVerifierMaxBytes  = 128
)

type oauthClient struct {
	ID              string    `json:"client_id"`
	Name            string    `json:"client_name,omitempty"`
	RedirectURIs    []string  `json:"redirect_uris"`
	CreatedAt       time.Time `json:"created_at"`
	ClientURI       string    `json:"client_uri,omitempty"`
	SoftwareID      string    `json:"software_id,omitempty"`
	SoftwareVersion string    `json:"software_version,omitempty"`
}

type oauthCode struct {
	ID            string          `json:"id"`
	ClientID      string          `json:"client_id"`
	RedirectURI   string          `json:"redirect_uri"`
	CodeChallenge string          `json:"code_challenge"`
	Resource      string          `json:"resource"`
	Scope         string          `json:"scope"`
	Principal     model.Principal `json:"principal"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

type oauthAccessToken struct {
	ID        string          `json:"id"`
	ClientID  string          `json:"client_id,omitempty"`
	Resource  string          `json:"resource"`
	Scope     string          `json:"scope"`
	Principal model.Principal `json:"principal"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

var oauthConsentTemplate = template.Must(template.New("oauth-consent").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize {{.ClientName}}</title>
  <link rel="stylesheet" href="/assets/dashboard.css">
</head>
<body>
<main>
  <section class="panel">
    <h1>Authorize {{.ClientName}}</h1>
    <p>This application is requesting access to CI Radar.</p>
    <dl>
      <dt>Redirect destination</dt><dd><code>{{.RedirectURI}}</code></dd>
      <dt>Tenant</dt><dd><code>{{.TenantID}}</code></dd>
      <dt>Permissions</dt><dd><code>{{.Scope}}</code></dd>
    </dl>
    <form method="post" action="/oauth/authorize">
      {{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}
      <button type="submit" name="decision" value="approve">Authorize</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </section>
</main>
</body>
</html>`))

type oauthConsentField struct {
	Name  string
	Value string
}

type oauthConsentPage struct {
	ClientName  string
	RedirectURI string
	TenantID    string
	Scope       string
	Fields      []oauthConsentField
}

func (s *Server) oauthAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	base := s.requestBaseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"registration_endpoint":                 base + "/oauth/register",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"ciradar.read", "ciradar.write"},
	})
}

func (s *Server) oauthRegister(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RedirectURIs    []string `json:"redirect_uris"`
		ClientName      string   `json:"client_name"`
		ClientURI       string   `json:"client_uri"`
		SoftwareID      string   `json:"software_id"`
		SoftwareVersion string   `json:"software_version"`
		GrantTypes      []string `json:"grant_types"`
		ResponseTypes   []string `json:"response_types"`
		TokenAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := decodeJSONBody(w, r, 128<<10, &input, false); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid registration request")
		return
	}
	input.ClientName = strings.TrimSpace(input.ClientName)
	input.ClientURI = strings.TrimSpace(input.ClientURI)
	input.SoftwareID = strings.TrimSpace(input.SoftwareID)
	input.SoftwareVersion = strings.TrimSpace(input.SoftwareVersion)
	if len(input.ClientName) > oauthClientNameMaxBytes || len(input.SoftwareID) > oauthSoftwareFieldMaxBytes || len(input.SoftwareVersion) > oauthSoftwareFieldMaxBytes {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client metadata exceeds the supported length")
		return
	}
	if input.ClientURI != "" && !validOAuthClientURI(input.ClientURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_uri must use HTTPS or loopback HTTP")
		return
	}
	if len(input.RedirectURIs) == 0 || len(input.RedirectURIs) > 20 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between one and 20 redirect URIs are required")
		return
	}
	for _, raw := range input.RedirectURIs {
		if !validOAuthRedirect(raw) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URI must use HTTPS or loopback HTTP and fit within the supported length")
			return
		}
	}
	if len(input.GrantTypes) > 0 && !onlyContains(input.GrantTypes, "authorization_code") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only authorization_code is supported")
		return
	}
	if len(input.ResponseTypes) > 0 && !onlyContains(input.ResponseTypes, "code") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only code response type is supported")
		return
	}
	if input.TokenAuthMethod != "" && input.TokenAuthMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public clients are supported")
		return
	}
	clientID, err := randomOpaque(24)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate client ID")
		return
	}
	client := oauthClient{ID: "mcp_" + clientID, Name: input.ClientName, RedirectURIs: uniqueStrings(input.RedirectURIs), CreatedAt: time.Now().UTC(), ClientURI: input.ClientURI, SoftwareID: input.SoftwareID, SoftwareVersion: input.SoftwareVersion}
	created, err := s.store.PutObjectIfKindBelowLimit(r.Context(), model.DefaultTenantID, "oauth_client", client.ID, client, oauthDynamicClientLimit)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not register client")
		return
	}
	if !created {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "dynamic client registration capacity has been reached")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"client_id": client.ID, "client_id_issued_at": client.CreatedAt.Unix(), "client_name": client.Name, "redirect_uris": client.RedirectURIs, "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
}

func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid authorization request")
			return
		}
	}
	query := r.URL.Query()
	if r.Method == http.MethodPost {
		query = r.Form
	}
	clientID := strings.TrimSpace(query.Get("client_id"))
	redirectURI := strings.TrimSpace(query.Get("redirect_uri"))
	state := query.Get("state")
	if query.Get("response_type") != "code" || clientID == "" || redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "response_type, client_id, and redirect_uri are required")
		return
	}
	client, ok := s.oauthClient(r.Context(), clientID)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client or redirect URI")
		return
	}
	redirectURI, ok = registeredOAuthRedirect(client.RedirectURIs, redirectURI)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client or redirect URI")
		return
	}
	challenge := strings.TrimSpace(query.Get("code_challenge"))
	if query.Get("code_challenge_method") != "S256" || !validPKCEChallenge(challenge) {
		s.redirectOAuthError(w, r, redirectURI, state, "invalid_request", "a valid PKCE S256 challenge is required")
		return
	}
	p, authenticated := s.authenticate(r)
	if !authenticated {
		if s.sso != nil && r.Method == http.MethodGet {
			returnTo := r.URL.RequestURI()
			http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
			return
		}
		writeOAuthError(w, http.StatusUnauthorized, "login_required", "authenticate in the dashboard first")
		return
	}
	resource := strings.TrimSpace(query.Get("resource"))
	if resource == "" {
		resource = s.requestBaseURL(r) + "/mcp"
	}
	if !s.validOAuthResource(r, resource) {
		s.redirectOAuthError(w, r, redirectURI, state, "invalid_target", "unsupported resource")
		return
	}
	scope := normalizeOAuthScope(query.Get("scope"), p.Role)
	if scope == "" {
		s.redirectOAuthError(w, r, redirectURI, state, "invalid_scope", "requested scope is not allowed")
		return
	}
	if r.Method == http.MethodGet {
		clientName := strings.TrimSpace(client.Name)
		if clientName == "" {
			clientName = client.ID
		}
		fields := make([]oauthConsentField, 0, 8)
		for _, name := range []string{"response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "scope", "resource", "state"} {
			if value := query.Get(name); value != "" {
				fields = append(fields, oauthConsentField{Name: name, Value: value})
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := oauthConsentTemplate.Execute(w, oauthConsentPage{ClientName: clientName, RedirectURI: redirectURI, TenantID: p.TenantID, Scope: scope, Fields: fields}); err != nil {
			s.log.Error("render OAuth consent page", "error_kind", logsafe.Kind(err))
		}
		return
	}
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "unsupported authorization method")
		return
	}
	switch query.Get("decision") {
	case "deny":
		s.redirectOAuthError(w, r, redirectURI, state, "access_denied", "the resource owner denied the request")
		return
	case "approve":
	default:
		s.redirectOAuthError(w, r, redirectURI, state, "invalid_request", "an explicit authorization decision is required")
		return
	}
	p.Root = false
	codeID, err := randomOpaque(24)
	if err != nil {
		s.redirectOAuthError(w, r, redirectURI, state, "server_error", "could not generate authorization code")
		return
	}
	code := oauthCode{ID: codeID, ClientID: clientID, RedirectURI: redirectURI, CodeChallenge: challenge, Resource: resource, Scope: scope, Principal: p, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	sealed, err := sealOAuthValue(s.dashboardSecret(), "code", code)
	if err != nil {
		s.redirectOAuthError(w, r, redirectURI, state, "server_error", "could not create authorization code")
		return
	}
	destination, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URI is invalid")
		return
	}
	values := destination.Query()
	values.Set("code", sealed)
	if state != "" {
		values.Set("state", state)
	}
	destination.RawQuery = values.Encode()
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	var code oauthCode
	if err := openOAuthValue(s.dashboardSecret(), "code", r.Form.Get("code"), &code); err != nil || time.Now().UTC().After(code.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	if !constantString(code.ClientID, strings.TrimSpace(r.Form.Get("client_id"))) || !constantString(code.RedirectURI, strings.TrimSpace(r.Form.Get("redirect_uri"))) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code binding mismatch")
		return
	}
	verifier := r.Form.Get("code_verifier")
	if !validPKCEVerifier(verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	if !constantString(code.CodeChallenge, base64.RawURLEncoding.EncodeToString(digest[:])) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if _, ok := s.oauthClient(r.Context(), code.ClientID); !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "OAuth client is no longer registered")
		return
	}
	now := time.Now().UTC()
	accessID, err := randomOpaque(24)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate access token")
		return
	}
	access := oauthAccessToken{ID: accessID, ClientID: code.ClientID, Resource: code.Resource, Scope: code.Scope, Principal: code.Principal, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	access.Principal.Root = false
	token, err := sealOAuthValue(s.dashboardSecret(), "access", access)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	fresh, err := s.store.RecordDelivery(r.Context(), "oauth-code-"+code.ID, "oauth.authorization_code")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not redeem authorization code")
		return
	}
	if !fresh {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code was already used")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": access.Scope, "resource": access.Resource})
}

func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	var token oauthAccessToken
	if openOAuthValue(s.dashboardSecret(), "access", r.Form.Get("token"), &token) == nil && token.ID != "" {
		if err := s.store.PutObject(r.Context(), token.Principal.TenantID, "oauth_revocation", token.ID, map[string]any{"revoked_at": time.Now().UTC(), "expires_at": token.ExpiresAt}); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not revoke access token")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authenticateOAuthToken(ctx context.Context, raw string) (model.Principal, bool) {
	var token oauthAccessToken
	if openOAuthValue(s.dashboardSecret(), "access", raw, &token) != nil || token.ID == "" || time.Now().UTC().After(token.ExpiresAt) {
		return model.Principal{}, false
	}
	if ok, err := s.store.GetObject(ctx, token.Principal.TenantID, "oauth_revocation", token.ID, nil); err != nil || ok {
		return model.Principal{}, false
	}
	if token.ClientID != "" {
		if _, ok := s.oauthClient(ctx, token.ClientID); !ok {
			return model.Principal{}, false
		}
	}
	tenant, err := s.store.GetTenant(ctx, token.Principal.TenantID)
	if err != nil || tenant == nil || !tenant.Enabled {
		return model.Principal{}, false
	}
	token.Principal.Root = false
	token.Principal.Scopes = strings.Fields(token.Scope)
	return token.Principal, true
}

func (s *Server) oauthClient(ctx context.Context, id string) (oauthClient, bool) {
	var client oauthClient
	ok, err := s.store.GetObject(ctx, model.DefaultTenantID, "oauth_client", id, &client)
	return client, err == nil && ok
}

func (s *Server) requestBaseURL(r *http.Request) string {
	if strings.TrimSpace(s.cfg.PublicBaseURL) != "" {
		return strings.TrimRight(s.cfg.PublicBaseURL, "/")
	}
	scheme := "http"
	if requestIsHTTPS(r, s.cfg.PublicBaseURL, s.ipResolver) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) validOAuthResource(r *http.Request, raw string) bool {
	resource, err := url.Parse(raw)
	if err != nil || resource.User != nil || resource.RawQuery != "" || resource.Fragment != "" || resource.Opaque != "" {
		return false
	}
	mcp, err := url.Parse(s.requestBaseURL(r) + "/mcp")
	if err != nil {
		return false
	}
	return strings.EqualFold(resource.Scheme, mcp.Scheme) && strings.EqualFold(resource.Host, mcp.Host) && strings.TrimRight(resource.EscapedPath(), "/") == strings.TrimRight(mcp.EscapedPath(), "/")
}

func sealOAuthValue(secret, purpose string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	ciphertext, err := secrets.EncryptDerived(secret+"|oauth|"+purpose, string(encoded))
	if err != nil {
		return "", err
	}
	return "cir_oauth_" + base64.RawURLEncoding.EncodeToString([]byte(ciphertext)), nil
}

func openOAuthValue(secret, purpose, value string, out any) error {
	if !strings.HasPrefix(value, "cir_oauth_") {
		return errors.New("invalid OAuth token")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "cir_oauth_"))
	if err != nil {
		return err
	}
	plain, err := secrets.DecryptDerived(secret+"|oauth|"+purpose, string(encoded))
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(plain), out)
}

func registeredOAuthRedirect(allowed []string, requested string) (string, bool) {
	requested = strings.TrimSpace(requested)
	for _, candidate := range allowed {
		candidate = strings.TrimSpace(candidate)
		if candidate == requested && validOAuthRedirect(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func validOAuthRedirect(raw string) bool {
	if len(raw) == 0 || len(raw) > oauthRedirectURIMaxBytes {
		return false
	}
	return validOAuthHTTPSOrLoopbackURL(raw, true)
}

func validOAuthClientURI(raw string) bool {
	if len(raw) == 0 || len(raw) > oauthClientURIMaxBytes {
		return false
	}
	return validOAuthHTTPSOrLoopbackURL(raw, false)
}

func validOAuthHTTPSOrLoopbackURL(raw string, rejectFragment bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || (rejectFragment && parsed.Fragment != "") {
		return false
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	return strings.EqualFold(parsed.Scheme, "http") && (host == "127.0.0.1" || host == "localhost" || host == "::1")
}

func validPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < oauthPKCEVerifierMinBytes || len(verifier) > oauthPKCEVerifierMaxBytes {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return false
	}
	return true
}

func normalizeOAuthScope(raw string, role model.Role) string {
	requested := strings.Fields(raw)
	if len(requested) == 0 {
		requested = []string{"ciradar.read"}
	}
	allowed := map[string]bool{"ciradar.read": true}
	if roleRank(role) >= roleRank(model.RoleOperator) {
		allowed["ciradar.write"] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, scope := range requested {
		if !allowed[scope] {
			return ""
		}
		if !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	return strings.Join(out, " ")
}

func onlyContains(values []string, expected string) bool {
	for _, value := range values {
		if value != expected {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func constantString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for index := range a {
		difference |= a[index] ^ b[index]
	}
	return difference == 0
}

func randomOpaque(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": description})
}

func (s *Server) redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	destination, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, code, description)
		return
	}
	values := destination.Query()
	values.Set("error", code)
	values.Set("error_description", description)
	if state != "" {
		values.Set("state", state)
	}
	destination.RawQuery = values.Encode()
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (s *Server) oauthClients(w http.ResponseWriter, r *http.Request) {
	objects, err := s.store.ListObjects(r.Context(), model.DefaultTenantID, "oauth_client", oauthDynamicClientLimit+1)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	clients := make([]oauthClient, 0, len(objects))
	for _, object := range objects {
		var client oauthClient
		if err := json.Unmarshal(object.Value, &client); err != nil || client.ID == "" {
			continue
		}
		clients = append(clients, client)
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients, "limit": oauthDynamicClientLimit})
}

func (s *Server) deleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || len(id) > 256 {
		writeError(w, http.StatusBadRequest, "client id is required")
		return
	}
	if _, ok := s.oauthClient(r.Context(), id); !ok {
		writeError(w, http.StatusNotFound, "OAuth client not found")
		return
	}
	if err := s.store.DeleteObject(r.Context(), model.DefaultTenantID, "oauth_client", id); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "oauth.client_delete", "oauth_client", id, nil)
	w.WriteHeader(http.StatusNoContent)
}
