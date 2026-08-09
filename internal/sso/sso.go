package sso

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/httpguard"
	"github.com/Bluezly/CIRadar/internal/model"
)

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type flowState struct {
	State     string    `json:"state"`
	RequestID string    `json:"request_id,omitempty"`
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
	ReturnTo  string    `json:"return_to"`
	Expires   time.Time `json:"expires"`
}

type ReplayGuard interface {
	ClaimSSOReplay(context.Context, string, time.Time) (bool, error)
}

type localReplayGuard struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func (g *localReplayGuard) ClaimSSOReplay(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	key = strings.TrimSpace(key)
	expiresAt = expiresAt.UTC()
	if key == "" || len(key) > 128 || !expiresAt.After(now) || expiresAt.Sub(now) > 24*time.Hour {
		return false, errors.New("invalid SSO replay claim")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for candidate, expiry := range g.entries {
		if !expiry.After(now) {
			delete(g.entries, candidate)
		}
	}
	if expiry, exists := g.entries[key]; exists && expiry.After(now) {
		return false, nil
	}
	g.entries[key] = expiresAt.UTC()
	return true, nil
}

type Manager struct {
	cfg       config.SSOConfig
	http      *http.Client
	mu        sync.Mutex
	discovery discovery
	discAt    time.Time
	jwks      map[string]crypto.PublicKey
	jwksAt    time.Time
	proxies   []*net.IPNet
	replay    ReplayGuard
}

func New(cfg config.SSOConfig, replayGuards ...ReplayGuard) (*Manager, error) {
	cfg.SAMLSecurityProfile = strings.ToLower(strings.TrimSpace(cfg.SAMLSecurityProfile))
	if cfg.Mode == "saml" {
		if cfg.SAMLSecurityProfile == "" {
			cfg.SAMLSecurityProfile = "strict"
		}
		if cfg.SAMLSecurityProfile != "strict" && cfg.SAMLSecurityProfile != "compatibility" {
			return nil, fmt.Errorf("unsupported SAML security profile %q", cfg.SAMLSecurityProfile)
		}
	}
	var replay ReplayGuard = &localReplayGuard{entries: map[string]time.Time{}}
	if len(replayGuards) > 0 && replayGuards[0] != nil {
		replay = replayGuards[0]
	}
	m := &Manager{cfg: cfg, http: httpguard.NewClient(20*time.Second, cfg.AllowPrivateNetwork), jwks: map[string]crypto.PublicKey{}, replay: replay}
	for _, raw := range cfg.TrustedProxyCIDRs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		m.proxies = append(m.proxies, n)
	}
	return m, nil
}

func (m *Manager) Enabled() bool {
	return m != nil && m.cfg.Enabled
}

func (m *Manager) Login(w http.ResponseWriter, r *http.Request) {
	if !m.Enabled() {
		http.NotFound(w, r)
		return
	}
	if m.cfg.Mode == "saml" {
		m.samlLogin(w, r)
		return
	}
	if m.cfg.Mode != "oidc" {
		http.Error(w, "OIDC is not enabled", http.StatusNotFound)
		return
	}
	d, err := m.getDiscovery(r.Context())
	if err != nil {
		http.Error(w, "OIDC discovery failed", http.StatusBadGateway)
		return
	}
	state, err := randomText(32)
	if err != nil {
		http.Error(w, "OIDC state creation failed", http.StatusInternalServerError)
		return
	}
	nonce, err := randomText(32)
	if err != nil {
		http.Error(w, "OIDC nonce creation failed", http.StatusInternalServerError)
		return
	}
	verifier, err := randomText(48)
	if err != nil {
		http.Error(w, "OIDC verifier creation failed", http.StatusInternalServerError)
		return
	}
	challengeRaw := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeRaw[:])
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	flow := flowState{State: state, Nonce: nonce, Verifier: verifier, ReturnTo: returnTo, Expires: time.Now().Add(10 * time.Minute)}
	if err := m.writeFlow(w, flow); err != nil {
		http.Error(w, "OIDC state creation failed", http.StatusInternalServerError)
		return
	}
	q := url.Values{}
	q.Set("client_id", m.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", m.cfg.RedirectURL)
	q.Set("scope", strings.Join(m.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, d.AuthorizationEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (m *Manager) Callback(w http.ResponseWriter, r *http.Request) {
	if !m.Enabled() {
		http.NotFound(w, r)
		return
	}
	if m.cfg.Mode == "saml" {
		m.samlCallback(w, r)
		return
	}
	if m.cfg.Mode != "oidc" {
		http.Error(w, "OIDC is not enabled", http.StatusNotFound)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}
	flow, err := m.readFlow(r)
	m.clearFlow(w)
	if err != nil || flow.State != state || time.Now().After(flow.Expires) {
		http.Error(w, "expired SSO state", http.StatusBadRequest)
		return
	}
	d, err := m.getDiscovery(r.Context())
	if err != nil {
		http.Error(w, "OIDC discovery failed", http.StatusBadGateway)
		return
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", m.cfg.RedirectURL)
	form.Set("client_id", m.cfg.ClientID)
	form.Set("code_verifier", flow.Verifier)
	if m.cfg.ClientSecret != "" {
		form.Set("client_secret", m.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "OIDC token endpoint is invalid", http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.http.Do(req)
	if err != nil {
		http.Error(w, "OIDC token exchange failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := readLimitedResponseBody(resp.Body, 2<<20)
	if err != nil {
		http.Error(w, "OIDC token response could not be read", http.StatusBadGateway)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, "OIDC token exchange rejected", http.StatusUnauthorized)
		return
	}
	var token struct {
		IDToken string `json:"id_token"`
	}
	if json.Unmarshal(body, &token) != nil || token.IDToken == "" {
		http.Error(w, "OIDC response has no id_token", http.StatusUnauthorized)
		return
	}
	claims, err := m.verifyIDToken(r.Context(), token.IDToken, d, flow.Nonce)
	if err != nil {
		http.Error(w, "OIDC token validation failed", http.StatusUnauthorized)
		return
	}
	identity, err := m.identityFromClaims(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := m.writeSession(w, identity, 8*time.Hour); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, safeReturnTo(flow.ReturnTo), http.StatusFound)
}

func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: m.cfg.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	if m.cfg.Mode == "oidc" {
		if d, err := m.getDiscovery(r.Context()); err == nil && d.EndSessionEndpoint != "" {
			destination := d.EndSessionEndpoint
			if postLogout := oidcPostLogoutRedirect(m.cfg.RedirectURL); postLogout != "" {
				q := url.Values{"post_logout_redirect_uri": []string{postLogout}}
				destination += "?" + q.Encode()
			}
			http.Redirect(w, r, destination, http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func oidcPostLogoutRedirect(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
		return ""
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "http") {
		return ""
	}
	parsed.Path = "/"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func (m *Manager) Authenticate(r *http.Request) (*model.Principal, bool) {
	if !m.Enabled() {
		return nil, false
	}
	if m.cfg.Mode == "proxy" || m.cfg.Mode == "saml_proxy" {
		if p, ok := m.proxyPrincipal(r); ok {
			return p, true
		}
	}
	cookie, err := r.Cookie(m.cfg.CookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	identity, err := m.readSession(cookie.Value)
	if err != nil {
		return nil, false
	}
	return &model.Principal{TenantID: identity.TenantID, Name: firstNonEmpty(identity.Name, identity.Email, identity.Subject), Role: identity.Role}, true
}

func (m *Manager) proxyPrincipal(r *http.Request) (*model.Principal, bool) {
	ipText := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(ipText); err == nil {
		ipText = host
	}
	ip := net.ParseIP(strings.Trim(ipText, "[]"))
	trusted := false
	for _, n := range m.proxies {
		if n.Contains(ip) {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, false
	}
	provided := r.Header.Get(m.cfg.ProxySecretHeader)
	if subtle.ConstantTimeCompare([]byte(provided), []byte(m.cfg.ProxySecret)) != 1 {
		return nil, false
	}
	subject := strings.TrimSpace(r.Header.Get(m.cfg.ProxySubjectHeader))
	email := strings.TrimSpace(r.Header.Get(m.cfg.ProxyEmailHeader))
	if subject == "" && email == "" {
		return nil, false
	}
	role := parseRole(r.Header.Get(m.cfg.ProxyRoleHeader), m.cfg.DefaultRole)
	tenant := cleanTenant(firstNonEmpty(r.Header.Get(m.cfg.ProxyTenantHeader), m.cfg.DefaultTenant))
	return &model.Principal{TenantID: tenant, Name: firstNonEmpty(r.Header.Get(m.cfg.ProxyNameHeader), email, subject), Role: role}, true
}

func (m *Manager) writeFlow(w http.ResponseWriter, flow flowState) error {
	b, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	sealed, err := sealCookie(m.cfg.SessionSecret, "oidc-flow", b)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: m.cfg.CookieName + "_oidc", Value: sealed, Path: "/auth", MaxAge: 600, HttpOnly: true, Secure: m.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	return nil
}

func (m *Manager) readFlow(r *http.Request) (flowState, error) {
	cookie, err := r.Cookie(m.cfg.CookieName + "_oidc")
	if err != nil {
		return flowState{}, err
	}
	b, err := openCookie(m.cfg.SessionSecret, "oidc-flow", cookie.Value)
	if err != nil {
		return flowState{}, errors.New("invalid OIDC state")
	}
	var flow flowState
	if json.Unmarshal(b, &flow) != nil || flow.State == "" || time.Now().After(flow.Expires) {
		return flowState{}, errors.New("invalid SSO state")
	}
	if m.cfg.Mode == "saml" {
		if flow.RequestID == "" {
			return flowState{}, errors.New("invalid SAML state")
		}
	} else if flow.Verifier == "" || flow.Nonce == "" {
		return flowState{}, errors.New("invalid OIDC state")
	}
	return flow, nil
}

func (m *Manager) clearFlow(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: m.cfg.CookieName + "_oidc", Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: m.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
}

func readLimitedResponseBody(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("response body limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response body exceeds %d bytes", max)
	}
	return body, nil
}

func (m *Manager) getDiscovery(ctx context.Context) (discovery, error) {
	m.mu.Lock()
	if m.discovery.Issuer != "" && time.Since(m.discAt) < time.Hour {
		d := m.discovery
		m.mu.Unlock()
		return d, nil
	}
	m.mu.Unlock()
	endpoint := strings.TrimRight(m.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return discovery{}, err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return discovery{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discovery{}, fmt.Errorf("OIDC discovery HTTP %d", resp.StatusCode)
	}
	body, err := readLimitedResponseBody(resp.Body, 1<<20)
	if err != nil {
		return discovery{}, err
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return discovery{}, err
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return discovery{}, errors.New("incomplete OIDC discovery document")
	}
	if d.Issuer != m.cfg.IssuerURL {
		return discovery{}, errors.New("OIDC discovery issuer does not match configured issuer_url exactly")
	}
	for _, raw := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if err := httpguard.ValidateURL(raw, m.cfg.AllowPrivateNetwork); err != nil {
			return discovery{}, fmt.Errorf("invalid OIDC discovery endpoint: %w", err)
		}
	}
	m.mu.Lock()
	m.discovery = d
	m.discAt = time.Now()
	m.mu.Unlock()
	return d, nil
}

func (m *Manager) getJWKS(ctx context.Context, uri string, force bool) (map[string]crypto.PublicKey, error) {
	m.mu.Lock()
	if !force && len(m.jwks) > 0 && time.Since(m.jwksAt) < time.Hour {
		keys := m.jwks
		m.mu.Unlock()
		return keys, nil
	}
	m.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS HTTP %d", resp.StatusCode)
	}
	body, err := readLimitedResponseBody(resp.Body, 2<<20)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	seenKids := map[string]struct{}{}
	for _, j := range raw.Keys {
		kid, _ := j["kid"].(string)
		kid = strings.TrimSpace(kid)
		if kid == "" || len(kid) > 256 || strings.IndexFunc(kid, unicode.IsControl) >= 0 {
			continue
		}
		if _, exists := seenKids[kid]; exists {
			return nil, fmt.Errorf("JWKS contains duplicate key id %q", kid)
		}
		seenKids[kid] = struct{}{}
		key, err := parseJWK(j)
		if err == nil {
			keys[kid] = key
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no supported keys")
	}
	m.mu.Lock()
	m.jwks = keys
	m.jwksAt = time.Now()
	m.mu.Unlock()
	return keys, nil
}

func (m *Manager) verifyIDToken(ctx context.Context, raw string, d discovery, nonce string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	var claims map[string]any
	if json.Unmarshal(headerBytes, &header) != nil || json.Unmarshal(claimsBytes, &claims) != nil {
		return nil, errors.New("invalid JWT JSON")
	}
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	if alg != "RS256" && alg != "ES256" {
		return nil, fmt.Errorf("unsupported JWT algorithm %q", alg)
	}
	keys, err := m.getJWKS(ctx, d.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	key, ok := keys[kid]
	if !ok {
		keys, err = m.getJWKS(ctx, d.JWKSURI, true)
		if err != nil {
			return nil, err
		}
		key, ok = keys[kid]
	}
	if !ok {
		return nil, errors.New("JWT signing key not found")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], sig) != nil {
			return nil, errors.New("JWT signature invalid")
		}
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 || !ecdsa.Verify(k, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("JWT signature invalid")
		}
	default:
		return nil, errors.New("unsupported JWT key")
	}
	now := time.Now().Unix()
	if exp := numberClaim(claims["exp"]); exp == 0 || now >= exp {
		return nil, errors.New("JWT expired")
	}
	if issuedAt := numberClaim(claims["iat"]); issuedAt <= 0 || issuedAt > now+60 {
		return nil, errors.New("JWT issued-at claim is missing or invalid")
	}
	if nbf := numberClaim(claims["nbf"]); nbf > 0 && now+60 < nbf {
		return nil, errors.New("JWT not active")
	}
	issuer, _ := claims["iss"].(string)
	if issuer != d.Issuer {
		return nil, errors.New("JWT issuer mismatch")
	}
	if !validAudienceClaims(claims["aud"], stringClaim(claims, "azp"), m.cfg.ClientID) {
		return nil, errors.New("JWT audience or authorized party mismatch")
	}
	claimNonce, _ := claims["nonce"].(string)
	if nonce != "" && subtle.ConstantTimeCompare([]byte(claimNonce), []byte(nonce)) != 1 {
		return nil, errors.New("JWT nonce mismatch")
	}
	return claims, nil
}

func (m *Manager) identityFromClaims(claims map[string]any) (model.SSOIdentity, error) {
	subject := stringClaim(claims, "sub")
	if subject == "" {
		return model.SSOIdentity{}, errors.New("identity subject is missing")
	}
	emailClaim := stringClaim(claims, "email")
	verifiedEmail := false
	if rawVerified, present := claims["email_verified"]; present {
		verified, ok := rawVerified.(bool)
		if !ok || !verified {
			return model.SSOIdentity{}, errors.New("email address is not verified")
		}
		verifiedEmail = true
	}
	if len(m.cfg.AllowedDomains) > 0 {
		if emailClaim == "" || !verifiedEmail {
			return model.SSOIdentity{}, errors.New("a verified email claim is required for allowed_domains")
		}
		parts := strings.Split(strings.ToLower(emailClaim), "@")
		if len(parts) != 2 || !containsFold(m.cfg.AllowedDomains, parts[1]) {
			return model.SSOIdentity{}, errors.New("email domain is not allowed")
		}
	}
	email := emailClaim
	if email == "" {
		email = stringClaim(claims, "preferred_username")
	}
	groups := stringSliceClaim(claims[m.cfg.GroupsClaim])
	role := parseRole(stringClaim(claims, m.cfg.RoleClaim), m.cfg.DefaultRole)
	if anyGroup(groups, m.cfg.AdminGroups) {
		role = model.RoleAdmin
	} else if anyGroup(groups, m.cfg.OperatorGroups) {
		role = model.RoleOperator
	} else if anyGroup(groups, m.cfg.ViewerGroups) {
		role = model.RoleViewer
	}
	tenant := cleanTenant(firstNonEmpty(stringClaim(claims, m.cfg.TenantClaim), m.cfg.DefaultTenant))
	return model.SSOIdentity{Subject: subject, Email: email, Name: firstNonEmpty(stringClaim(claims, "name"), email, subject), TenantID: tenant, Role: role, Groups: groups, Issuer: stringClaim(claims, "iss")}, nil
}

func (m *Manager) writeSession(w http.ResponseWriter, identity model.SSOIdentity, duration time.Duration) error {
	payload := struct {
		Identity model.SSOIdentity `json:"identity"`
		Expires  int64             `json:"expires"`
	}{Identity: identity, Expires: time.Now().Add(duration).Unix()}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	sealed, err := sealCookie(m.cfg.SessionSecret, "sso-session", b)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: m.cfg.CookieName, Value: sealed, Path: "/", MaxAge: int(duration.Seconds()), HttpOnly: true, Secure: m.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
	return nil
}

func (m *Manager) readSession(raw string) (model.SSOIdentity, error) {
	b, err := openCookie(m.cfg.SessionSecret, "sso-session", raw)
	if err != nil {
		return model.SSOIdentity{}, errors.New("invalid session")
	}
	var payload struct {
		Identity model.SSOIdentity `json:"identity"`
		Expires  int64             `json:"expires"`
	}
	if json.Unmarshal(b, &payload) != nil || time.Now().Unix() >= payload.Expires {
		return model.SSOIdentity{}, errors.New("expired session")
	}
	return payload.Identity, nil
}

func validateJWKUsage(j map[string]any, expectedAlgorithm string) error {
	if use, present := j["use"]; present {
		value, ok := use.(string)
		if !ok || value != "sig" {
			return errors.New("JWK is not designated for signatures")
		}
	}
	if algorithm, present := j["alg"]; present {
		value, ok := algorithm.(string)
		if !ok || value != expectedAlgorithm {
			return fmt.Errorf("JWK algorithm does not match %s", expectedAlgorithm)
		}
	}
	if operations, present := j["key_ops"]; present {
		verify := false
		switch values := operations.(type) {
		case []any:
			for _, raw := range values {
				value, ok := raw.(string)
				if !ok {
					return errors.New("JWK key_ops is malformed")
				}
				if value == "verify" {
					verify = true
				}
			}
		case []string:
			for _, value := range values {
				if value == "verify" {
					verify = true
				}
			}
		default:
			return errors.New("JWK key_ops is malformed")
		}
		if !verify {
			return errors.New("JWK is not permitted for verification")
		}
	}
	return nil
}

func parseJWK(j map[string]any) (crypto.PublicKey, error) {
	kty, _ := j["kty"].(string)
	switch kty {
	case "RSA":
		if err := validateJWKUsage(j, "RS256"); err != nil {
			return nil, err
		}
		nRaw, _ := j["n"].(string)
		eRaw, _ := j["e"].(string)
		nBytes, err := base64.RawURLEncoding.DecodeString(nRaw)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eRaw)
		if err != nil {
			return nil, err
		}
		if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 4 {
			return nil, errors.New("invalid RSA JWK")
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		n := new(big.Int).SetBytes(nBytes)
		if n.BitLen() < 2048 || e < 3 || e%2 == 0 {
			return nil, errors.New("invalid RSA JWK")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		if err := validateJWKUsage(j, "ES256"); err != nil {
			return nil, err
		}
		if crv, _ := j["crv"].(string); crv != "P-256" {
			return nil, errors.New("unsupported EC curve")
		}
		xRaw, _ := j["x"].(string)
		yRaw, _ := j["y"].(string)
		xBytes, err := base64.RawURLEncoding.DecodeString(xRaw)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(yRaw)
		if err != nil {
			return nil, err
		}
		if len(xBytes) != 32 || len(yBytes) != 32 {
			return nil, errors.New("invalid EC JWK coordinates")
		}
		point := make([]byte, 65)
		point[0] = 4
		copy(point[1:33], xBytes)
		copy(point[33:], yBytes)
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return nil, errors.New("invalid EC JWK point")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
	default:
		return nil, errors.New("unsupported JWK type")
	}
}

func sealCookie(secret, purpose string, plain []byte) (string, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := g.Seal(nil, nonce, plain, []byte("ci-radar:"+purpose))
	return "v1." + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func openCookie(secret, purpose, value string) ([]byte, error) {
	if !strings.HasPrefix(value, "v1.") {
		return nil, errors.New("unsupported cookie format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "v1."))
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < g.NonceSize() {
		return nil, errors.New("truncated cookie")
	}
	return g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("ci-radar:"+purpose))
}

func randomText(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func safeReturnTo(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, "\\\r\n") {
		return "/"
	}
	decoded := v
	for range 4 {
		next, err := url.PathUnescape(decoded)
		if err != nil || strings.ContainsAny(next, "\\\r\n") {
			return "/"
		}
		if next == decoded {
			break
		}
		decoded = next
	}
	parsed, err := url.Parse(decoded)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return "/"
	}
	return v
}

func numberClaim(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	default:
		return 0
	}
}

func validAudienceClaims(audience any, authorizedParty, clientID string) bool {
	count, valid := audienceCount(audience)
	if !valid || !audienceContains(audience, clientID) {
		return false
	}
	if authorizedParty != "" && authorizedParty != clientID {
		return false
	}
	return count <= 1 || authorizedParty == clientID
}

func audienceCount(v any) (int, bool) {
	switch a := v.(type) {
	case string:
		return 1, a != ""
	case []any:
		if len(a) == 0 {
			return 0, false
		}
		seen := make(map[string]struct{}, len(a))
		for _, value := range a {
			s, ok := value.(string)
			if !ok || s == "" {
				return 0, false
			}
			seen[s] = struct{}{}
		}
		return len(seen), true
	default:
		return 0, false
	}
}

func audienceContains(v any, target string) bool {
	switch a := v.(type) {
	case string:
		return a == target
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}

func stringClaim(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	v, _ := claims[name].(string)
	return strings.TrimSpace(v)
}

func stringSliceClaim(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case string:
		for _, p := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			if p != "" {
				out = append(out, p)
			}
		}
	case []any:
		for _, raw := range x {
			if s, ok := raw.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseRole(raw, fallback string) model.Role {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "admin", "administrator":
		return model.RoleAdmin
	case "operator", "write", "editor":
		return model.RoleOperator
	case "viewer", "read", "reader":
		return model.RoleViewer
	default:
		return parseRole(fallback, "viewer")
	}
}

func cleanTenant(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	for _, r := range v {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return model.DefaultTenantID
	}
	return b.String()
}

func anyGroup(groups, allowed []string) bool {
	for _, g := range groups {
		if containsFold(allowed, g) {
			return true
		}
	}
	return false
}

func containsFold(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
