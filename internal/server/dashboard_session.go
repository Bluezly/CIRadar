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

	"github.com/Bluezly/CIRadar/internal/model"
)

const dashboardSessionCookie = "ciradar_dashboard_session"

type dashboardSession struct {
	Principal     model.Principal `json:"principal"`
	Expires       int64           `json:"expires"`
	CredentialTag string          `json:"credential_tag,omitempty"`
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
	if err := decodeJSONBody(w, r, 64<<10, &body, false); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	if strings.HasPrefix(body.Token, "cir_oauth_") {
		writeError(w, http.StatusBadRequest, "OAuth access tokens cannot create dashboard sessions")
		return
	}
	principal, ok := s.authenticateToken(r.Context(), body.Token, strings.TrimSpace(body.Tenant))
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	session := dashboardSession{Principal: principal, Expires: time.Now().Add(8 * time.Hour).Unix()}
	if principal.Root {
		session.CredentialTag = dashboardCredentialTag(body.Token)
	}
	value, err := sealDashboardSession(s.dashboardSecret(), session)
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
	if session.Principal.Root {
		expected := dashboardCredentialTag(strings.TrimSpace(s.cfg.AdminToken))
		if session.CredentialTag == "" || !secureEqual(session.CredentialTag, expected) {
			return model.Principal{}, false
		}
	}
	if session.Principal.APIKeyID != "" {
		key, err := s.store.GetAPIKey(r.Context(), session.Principal.TenantID, session.Principal.APIKeyID)
		if err != nil {
			s.log.Error("dashboard session API key lookup failed", "tenant_id", session.Principal.TenantID, "api_key_id", session.Principal.APIKeyID, "error", err)
			return model.Principal{}, false
		}
		if key == nil || !key.RevokedAt.IsZero() {
			return model.Principal{}, false
		}
		session.Principal.Name = key.Name
		session.Principal.Role = key.Role
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

func dashboardCredentialTag(token string) string {
	sum := sha256.Sum256([]byte("ci-radar-dashboard-credential-v1|" + strings.TrimSpace(token)))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func clearDashboardSession(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: dashboardSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
