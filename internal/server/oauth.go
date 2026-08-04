package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ciradar/internal/model"
	"ciradar/internal/secrets"
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
	Resource  string          `json:"resource"`
	Scope     string          `json:"scope"`
	Principal model.Principal `json:"principal"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&input); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid registration request")
		return
	}
	if len(input.RedirectURIs) == 0 || len(input.RedirectURIs) > 20 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect URI is required")
		return
	}
	for _, raw := range input.RedirectURIs {
		if !validOAuthRedirect(raw) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URI must use HTTPS or loopback HTTP")
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
	client := oauthClient{ID: "mcp_" + randomOpaque(24), Name: strings.TrimSpace(input.ClientName), RedirectURIs: uniqueStrings(input.RedirectURIs), CreatedAt: time.Now().UTC(), ClientURI: strings.TrimSpace(input.ClientURI), SoftwareID: strings.TrimSpace(input.SoftwareID), SoftwareVersion: strings.TrimSpace(input.SoftwareVersion)}
	if err := s.store.PutObject(r.Context(), model.DefaultTenantID, "oauth_client", client.ID, client); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not register client")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"client_id": client.ID, "client_id_issued_at": client.CreatedAt.Unix(), "client_name": client.Name, "redirect_uris": client.RedirectURIs, "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
}

func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := strings.TrimSpace(query.Get("client_id"))
	redirectURI := strings.TrimSpace(query.Get("redirect_uri"))
	state := query.Get("state")
	if query.Get("response_type") != "code" || clientID == "" || redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "response_type, client_id, and redirect_uri are required")
		return
	}
	client, ok := s.oauthClient(r.Context(), clientID)
	if !ok || !containsString(client.RedirectURIs, redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client or redirect URI")
		return
	}
	challenge := strings.TrimSpace(query.Get("code_challenge"))
	if query.Get("code_challenge_method") != "S256" || challenge == "" {
		s.redirectOAuthError(w, r, redirectURI, state, "invalid_request", "PKCE S256 is required")
		return
	}
	p, authenticated := s.authenticate(r)
	if !authenticated {
		if s.sso != nil {
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
	p.Root = false
	code := oauthCode{ID: randomOpaque(24), ClientID: clientID, RedirectURI: redirectURI, CodeChallenge: challenge, Resource: resource, Scope: scope, Principal: p, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	sealed, err := sealOAuthValue(s.dashboardSecret(), "code", code)
	if err != nil {
		s.redirectOAuthError(w, r, redirectURI, state, "server_error", "could not create authorization code")
		return
	}
	destination, _ := url.Parse(redirectURI)
	values := destination.Query()
	values.Set("code", sealed)
	if state != "" {
		values.Set("state", state)
	}
	destination.RawQuery = values.Encode()
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
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
	digest := sha256.Sum256([]byte(verifier))
	if verifier == "" || !constantString(code.CodeChallenge, base64.RawURLEncoding.EncodeToString(digest[:])) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
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
	now := time.Now().UTC()
	access := oauthAccessToken{ID: randomOpaque(24), Resource: code.Resource, Scope: code.Scope, Principal: code.Principal, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	access.Principal.Root = false
	token, err := sealOAuthValue(s.dashboardSecret(), "access", access)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": access.Scope, "resource": access.Resource})
}

func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	var token oauthAccessToken
	if openOAuthValue(s.dashboardSecret(), "access", r.Form.Get("token"), &token) == nil && token.ID != "" {
		_ = s.store.PutObject(r.Context(), token.Principal.TenantID, "oauth_revocation", token.ID, map[string]any{"revoked_at": time.Now().UTC()})
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authenticateOAuthToken(ctx context.Context, raw string) (model.Principal, bool) {
	var token oauthAccessToken
	if openOAuthValue(s.dashboardSecret(), "access", raw, &token) != nil || token.ID == "" || time.Now().UTC().After(token.ExpiresAt) {
		return model.Principal{}, false
	}
	if ok, _ := s.store.GetObject(ctx, token.Principal.TenantID, "oauth_revocation", token.ID, nil); ok {
		return model.Principal{}, false
	}
	tenant, _ := s.store.GetTenant(ctx, token.Principal.TenantID)
	if tenant == nil || !tenant.Enabled {
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
	if err != nil {
		return false
	}
	mcp, _ := url.Parse(s.requestBaseURL(r) + "/mcp")
	return strings.EqualFold(resource.Scheme, mcp.Scheme) && strings.EqualFold(resource.Host, mcp.Host) && strings.TrimRight(resource.Path, "/") == strings.TrimRight(mcp.Path, "/")
}

func sealOAuthValue(secret, purpose string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	ciphertext, err := secrets.Encrypt(secret+"|oauth|"+purpose, string(encoded))
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
	plain, err := secrets.Decrypt(secret+"|oauth|"+purpose, string(encoded))
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(plain), out)
}

func validOAuthRedirect(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Fragment != "" || parsed.Host == "" {
		return false
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	return strings.EqualFold(parsed.Scheme, "http") && (host == "127.0.0.1" || host == "localhost" || host == "::1")
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

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if constantString(value, expected) {
			return true
		}
	}
	return false
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

func randomOpaque(size int) string {
	value := make([]byte, size)
	_, _ = rand.Read(value)
	return base64.RawURLEncoding.EncodeToString(value)
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
