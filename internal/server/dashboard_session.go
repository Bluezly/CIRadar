package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"ciradar/internal/model"
)

const dashboardSessionCookie = "ciradar_dashboard_session"

type dashboardSession struct {
	Principal model.Principal `json:"principal"`
	Expires   int64           `json:"expires"`
}

func (s *Server) dashboardSecret() string {
	return strings.TrimSpace(s.cfg.DashboardSessionSecret)
}

func sealDashboardSession(secret string, session dashboardSession) (string, error) {
	if len(strings.TrimSpace(secret)) < 32 {
		return "", errors.New("dashboard session secret is not configured")
	}
	plain, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
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
	sealed := g.Seal(nil, nonce, plain, []byte("ci-radar-dashboard-session-v1"))
	return "v1." + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func openDashboardSession(secret, value string) (dashboardSession, error) {
	if len(strings.TrimSpace(secret)) < 32 {
		return dashboardSession{}, errors.New("dashboard session secret is not configured")
	}
	if !strings.HasPrefix(value, "v1.") {
		return dashboardSession{}, errors.New("unsupported session")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "v1."))
	if err != nil {
		return dashboardSession{}, err
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return dashboardSession{}, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return dashboardSession{}, err
	}
	if len(raw) < g.NonceSize() {
		return dashboardSession{}, errors.New("truncated session")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("ci-radar-dashboard-session-v1"))
	if err != nil {
		return dashboardSession{}, err
	}
	var session dashboardSession
	if json.Unmarshal(plain, &session) != nil || session.Expires <= time.Now().Unix() {
		return dashboardSession{}, errors.New("expired session")
	}
	return session, nil
}

func (s *Server) authToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token  string `json:"token"`
		Tenant string `json:"tenant"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	principal, ok := s.authenticateToken(r.Context(), strings.TrimSpace(body.Token), strings.TrimSpace(body.Tenant))
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	value, err := sealDashboardSession(s.dashboardSecret(), dashboardSession{Principal: principal, Expires: time.Now().Add(8 * time.Hour).Unix()})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: dashboardSessionCookie, Value: value, Path: "/", MaxAge: int((8 * time.Hour).Seconds()), HttpOnly: true, Secure: s.cfg.DashboardCookieSecure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]any{"status": "authenticated", "tenant_id": principal.TenantID, "role": principal.Role, "root": principal.Root})
}

func (s *Server) authenticateDashboardSession(r *http.Request) (model.Principal, bool) {
	cookie, err := r.Cookie(dashboardSessionCookie)
	if err != nil {
		return model.Principal{}, false
	}
	session, err := openDashboardSession(s.dashboardSecret(), cookie.Value)
	if err != nil {
		return model.Principal{}, false
	}
	tenant, err := s.store.GetTenant(r.Context(), session.Principal.TenantID)
	if err != nil {
		s.log.Error("dashboard session tenant lookup failed", "tenant_id", session.Principal.TenantID, "error", err)
		return model.Principal{}, false
	}
	if tenant == nil || !tenant.Enabled {
		return model.Principal{}, false
	}
	return session.Principal, true
}

func (s *Server) authenticateToken(ctx context.Context, token, tenant string) (model.Principal, bool) {
	if strings.HasPrefix(token, "cir_oauth_") {
		return s.authenticateOAuthToken(ctx, token)
	}
	if tenant == "" {
		tenant = s.cfg.DefaultTenantID
	}
	if s.cfg.AdminToken != "" && secureEqual(token, s.cfg.AdminToken) {
		t, err := s.store.GetTenant(ctx, tenant)
		if err != nil {
			s.log.Error("admin token tenant lookup failed", "tenant_id", tenant, "error", err)
			return model.Principal{}, false
		}
		if t == nil || !t.Enabled {
			return model.Principal{}, false
		}
		return model.Principal{TenantID: t.ID, Name: "root", Role: model.RoleAdmin, Root: true}, true
	}
	p, err := s.store.AuthenticateAPIKey(ctx, token)
	if err != nil {
		s.log.Error("API key authentication lookup failed", "error", err)
		return model.Principal{}, false
	}
	if p != nil {
		return *p, true
	}
	return model.Principal{}, false
}

func clearDashboardSession(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: dashboardSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
