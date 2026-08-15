package server

import (
	"crypto/hmac"
	"crypto/sha256"
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

var marketplaceGitHubHTTPClient = &http.Client{Timeout: 15 * time.Second}

type marketplaceSetupState struct {
	InstallationID int64     `json:"installation_id"`
	IssuedAt       time.Time `json:"issued_at"`
}

type githubOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
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
	now := time.Now().UTC()
	if err != nil || state.IssuedAt.After(now.Add(time.Minute)) || now.Sub(state.IssuedAt) > marketplaceSetupStateTTL {
		writeError(w, http.StatusBadRequest, "invalid or expired Marketplace setup state")
		return
	}
	callback := strings.TrimRight(s.cfg.PublicBaseURL, "/") + "/github/marketplace/callback"
	token, err := s.exchangeGitHubOAuthCode(r, code, callback)
	if err != nil {
		s.log.Warn("GitHub Marketplace OAuth exchange failed", "error", err)
		writeError(w, http.StatusBadGateway, "GitHub OAuth exchange failed")
		return
	}
	installation, err := s.findUserInstallation(r, token, state.InstallationID)
	if err != nil {
		s.log.Warn("GitHub Marketplace installation verification failed", "error", err)
		writeError(w, http.StatusBadGateway, "could not verify GitHub installation")
		return
	}
	if installation == nil {
		writeError(w, http.StatusForbidden, "the authorized GitHub user cannot access this installation")
		return
	}

	var sub marketplace.Subscription
	accountID := strconv.FormatInt(installation.Account.ID, 10)
	found, err := s.store.GetObject(r.Context(), model.DefaultTenantID, "marketplace_account_index", accountID, &sub)
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
		sub.UpdatedAt = now
		if err := s.store.PutObject(r.Context(), sub.TenantID, "marketplace_subscription", accountID, sub); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := s.store.PutObject(r.Context(), model.DefaultTenantID, "marketplace_account_index", accountID, sub); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if err := s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: sub.TenantID, Actor: installation.Account.Login, Role: model.RoleAdmin, Action: "marketplace.setup", Resource: "github_installation", ResourceID: strconv.FormatInt(state.InstallationID, 10), Metadata: map[string]string{"account": installation.Account.Login}}); err != nil {
		s.log.Warn("record Marketplace setup audit failed", "error", err)
	}

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
	resp, err := marketplaceGitHubHTTPClient.Do(req)
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
		return "", fmt.Errorf("github oauth error: %s", firstNonEmpty(out.Error, "missing access token"))
	}
	return out.AccessToken, nil
}

func (s *Server) findUserInstallation(r *http.Request, token string, installationID int64) (*githubUserInstallation, error) {
	endpoint := "https://api.github.com/user/installations?per_page=100"
	for page := 0; page < 10 && endpoint != ""; page++ {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := marketplaceGitHubHTTPClient.Do(req)
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
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	buf := append(payload, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func openMarketplaceSetupState(secret, sealed string) (marketplaceSetupState, error) {
	var out marketplaceSetupState
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < sha256.Size {
		return out, fmt.Errorf("invalid state")
	}
	payload, sig := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
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

func nextGitHubLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		segments := strings.Split(part, ";")
		if len(segments) < 2 || !strings.Contains(segments[1], `rel="next"`) {
			continue
		}
		value := strings.TrimSpace(segments[0])
		if !strings.HasPrefix(value, "<") || !strings.HasSuffix(value, ">") {
			continue
		}
		candidate := strings.TrimSuffix(strings.TrimPrefix(value, "<"), ">")
		parsed, err := url.Parse(candidate)
		if err == nil && parsed.Scheme == "https" && strings.EqualFold(parsed.Hostname(), "api.github.com") {
			return candidate
		}
	}
	return ""
}

func htmlEscape(v string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return replacer.Replace(v)
}
