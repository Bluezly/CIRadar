package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Bluezly/CIRadar/internal/marketplace"
	"github.com/Bluezly/CIRadar/internal/model"
)

const marketplaceSetupStateTTL = 10 * time.Minute

type marketplaceSetupState struct {
	InstallationID int64     `json:"installation_id"`
	IssuedAt       time.Time `json:"issued_at"`
}

type githubOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

type githubUserInstallation struct {
	ID      int64 `json:"id"`
	Account struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
}

func (s *Server) marketplaceSetup(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.GitHubMarketplace
	if !cfg.Enabled || strings.TrimSpace(cfg.OAuthClientID) == "" || strings.TrimSpace(cfg.OAuthClientSecret) == "" {
		http.NotFound(w, r)
		return
	}
	installationID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("installation_id")), 10, 64)
	if err != nil || installationID < 1 {
		writeError(w, http.StatusBadRequest, "installation_id is required")
		return
	}
	state, err := sealMarketplaceSetupState(s.dashboardSecret(), marketplaceSetupState{InstallationID: installationID, IssuedAt: time.Now().UTC()})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	callback := strings.TrimRight(s.cfg.PublicBaseURL, "/") + "/github/marketplace/callback"
	q := url.Values{}
	q.Set("client_id", cfg.OAuthClientID)
	q.Set("redirect_uri", callback)
	q.Set("state", state)
	// read:user is sufficient to identify the buyer; installation membership is
	// verified separately through /user/installations with this user token.
	q.Set("scope", "read:user")
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

func (s *Server) marketplaceCallback(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.GitHubMarketplace
	if !cfg.Enabled || strings.TrimSpace(cfg.OAuthClientID) == "" || strings.TrimSpace(cfg.OAuthClientSecret) == "" {
		http.NotFound(w, r)
		return
	}
	if strings.TrimSpace(r.URL.Query().Get("error")) != "" {
		writeError(w, http.StatusBadRequest, "GitHub authorization was not completed")
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	stateRaw := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || stateRaw == "" {
		writeError(w, http.StatusBadRequest, "missing OAuth code or state")
		return
	}
	state, err := openMarketplaceSetupState(s.dashboardSecret(), stateRaw)
	if err != nil || time.Since(state.IssuedAt) < 0 || time.Since(state.IssuedAt) > marketplaceSetupStateTTL {
		writeError(w, http.StatusBadRequest, "invalid or expired Marketplace setup state")
		return
	}
	callback := strings.TrimRight(s.cfg.PublicBaseURL, "/") + "/github/marketplace/callback"
	token, err := s.exchangeGitHubOAuthCode(r, code, callback)
	if err != nil {
		writeError(w, http.StatusBadGateway, "GitHub OAuth exchange failed")
		return
	}
	installation, err := s.findUserInstallation(r, token, state.InstallationID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not verify GitHub installation")
		return
	}
	if installation == nil {
		writeError(w, http.StatusForbidden, "the authorized GitHub user cannot access this installation")
		return
	}

	var sub marketplace.Subscription
	found, err := s.store.GetObject(r.Context(), model.DefaultTenantID, "marketplace_account_index", strconv.FormatInt(installation.Account.ID, 10), &sub)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found || strings.TrimSpace(sub.TenantID) == "" {
		writeError(w, http.StatusConflict, "Marketplace purchase is not provisioned yet; retry setup after GitHub delivers the purchase event")
		return
	}
	if err := s.store.BindInstallation(r.Context(), sub.TenantID, state.InstallationID); err != nil {
		s.internalError(w, r, err)
		return
	}
	if sub.InstallationID != state.InstallationID {
		sub.InstallationID = state.InstallationID
		sub.UpdatedAt = time.Now().UTC()
		id := strconv.FormatInt(sub.AccountID, 10)
		if err := s.store.PutObject(r.Context(), sub.TenantID, "marketplace_subscription", id, sub); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := s.store.PutObject(r.Context(), model.DefaultTenantID, "marketplace_account_index", id, sub); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	_ = s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: sub.TenantID, Actor: installation.Account.Login, Role: model.RoleAdmin, Action: "marketplace.setup", Resource: "github_installation", ResourceID: strconv.FormatInt(state.InstallationID, 10), Metadata: map[string]string{"account": installation.Account.Login}})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<!doctype html><html><head><meta charset=utf-8><title>CIRadar setup complete</title><link rel=stylesheet href=/assets/dashboard.css></head><body><main><section class=panel><h1>CIRadar setup complete</h1><p>GitHub installation <code>"+strconv.FormatInt(state.InstallationID, 10)+"</code> is linked to tenant <code>"+htmlEscape(sub.TenantID)+"</code>.</p><p><a href=\"/\">Open CIRadar</a></p></section></main></body></html>")
}

func (s *Server) exchangeGitHubOAuthCode(r *http.Request, code, callback string) (string, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.GitHubMarketplace.OAuthClientID)
	form.Set("client_secret", s.cfg.GitHubMarketplace.OAuthClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", callback)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("github token endpoint returned %s", resp.Status)
	}
	var out githubOAuthTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != "" || strings.TrimSpace(out.AccessToken) == "" {
		return "", fmt.Errorf("github oauth error: %s", out.Error)
	}
	return out.AccessToken, nil
}

func (s *Server) findUserInstallation(r *http.Request, token string, installationID int64) (*githubUserInstallation, error) {
	endpoint := strings.TrimRight(s.cfg.GitHubAPIURL, "/") + "/user/installations?per_page=100"
	for page := 0; page < 10 && endpoint != ""; page++ {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		var body struct {
			Installations []githubUserInstallation `json:"installations"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("github installations endpoint returned %s", resp.Status)
		}
		if decodeErr != nil {
			return nil, decodeErr
		}
		for i := range body.Installations {
			if body.Installations[i].ID == installationID {
				return &body.Installations[i], nil
			}
		}
		endpoint = nextGitHubLink(resp.Header.Get("Link"))
	}
	return nil, nil
}

func sealMarketplaceSetupState(secret string, value marketplaceSetupState) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmacSHA256([]byte(secret), payload)
	buf := append(payload, mac...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func openMarketplaceSetupState(secret, sealed string) (marketplaceSetupState, error) {
	var out marketplaceSetupState
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < 32 {
		return out, fmt.Errorf("invalid state")
	}
	payload, sig := raw[:len(raw)-32], raw[len(raw)-32:]
	expected := hmacSHA256([]byte(secret), payload)
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return out, fmt.Errorf("invalid state signature")
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return out, err
	}
	if out.InstallationID < 1 || out.IssuedAt.IsZero() {
		return out, fmt.Errorf("invalid state payload")
	}
	return out, nil
}

func hmacSHA256(key, payload []byte) []byte {
	// Local small helper avoids coupling Marketplace setup state to MCP OAuth internals.
	blockSize := 64
	if len(key) > blockSize {
		h := sha256Sum(key)
		key = h
	}
	k := make([]byte, blockSize)
	copy(k, key)
	oPad := make([]byte, blockSize)
	iPad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		oPad[i] = k[i] ^ 0x5c
		iPad[i] = k[i] ^ 0x36
	}
	inner := append(iPad, payload...)
	innerHash := sha256Sum(inner)
	outer := append(oPad, innerHash...)
	return sha256Sum(outer)
}

func sha256Sum(data []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func nextGitHubLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		segments := strings.Split(part, ";")
		if len(segments) < 2 || !strings.Contains(segments[1], `rel="next"`) {
			continue
		}
		value := strings.TrimSpace(segments[0])
		if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
			return strings.TrimSuffix(strings.TrimPrefix(value, "<"), ">")
		}
	}
	return ""
}

func htmlEscape(v string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return replacer.Replace(v)
}

// keep crypto/rand linked in this file's security-focused tests when build tags
// trim unrelated server helpers.
var _ = rand.Reader
