package server

import (
	"ciradar/internal/model"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ciradar/internal/config"
)

func TestDashboardSecretDoesNotFallBackToOtherCredentials(t *testing.T) {
	s := &Server{cfg: config.Config{
		AdminToken:         "admin-token-that-should-not-seal-sessions",
		MasterKey:          "master-key-that-should-not-seal-sessions",
		FingerprintHMACKey: "fingerprint-key-that-should-not-seal-sessions",
	}}
	if got := s.dashboardSecret(); got != "" {
		t.Fatalf("dashboard secret fell back to another credential: %q", got)
	}
}

func TestDashboardSessionRejectsMissingSecret(t *testing.T) {
	validSecret := "0123456789abcdef0123456789abcdef"
	value, err := sealDashboardSession(validSecret, dashboardSession{Expires: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openDashboardSession("", value); err == nil {
		t.Fatal("dashboard session accepted an empty secret")
	}
}

func TestRevokedAPIKeyInvalidatesDashboardSession(t *testing.T) {
	s, store, _ := testServer(t)
	_, token, err := store.CreateAPIKey(context.Background(), "default", "dashboard", model.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodPost, "http://ciradar.test/auth/token", strings.NewReader(`{"token":"`+token+`","tenant":"default"}`))
	login.Header.Set("Content-Type", "application/json")
	login.RemoteAddr = "203.0.113.21:1234"
	loggedIn := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(loggedIn, login)
	if loggedIn.Code != http.StatusOK || len(loggedIn.Result().Cookies()) == 0 {
		t.Fatalf("login status=%d body=%s", loggedIn.Code, loggedIn.Body.String())
	}
	cookie := loggedIn.Result().Cookies()[0]
	keys, err := store.ListAPIKeys(context.Background(), "default")
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%d err=%v", len(keys), err)
	}
	if err := store.RevokeAPIKey(context.Background(), "default", keys[0].ID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://ciradar.test/api/v1/status", nil)
	request.RemoteAddr = "203.0.113.21:1234"
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked API key session status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestOAuthTokenCannotCreateLongLivedDashboardSession(t *testing.T) {
	s, _, _ := testServer(t)
	login := httptest.NewRequest(http.MethodPost, "http://ciradar.test/auth/token", strings.NewReader(`{"token":"cir_oauth_not-a-real-token"}`))
	login.Header.Set("Content-Type", "application/json")
	login.RemoteAddr = "203.0.113.22:1234"
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, login)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "cannot create dashboard sessions") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRootTokenRotationInvalidatesDashboardSession(t *testing.T) {
	s, _, cfg := testServer(t)
	login := httptest.NewRequest(http.MethodPost, "http://ciradar.test/auth/token", strings.NewReader(`{"token":"`+cfg.AdminToken+`","tenant":"default"}`))
	login.Header.Set("Content-Type", "application/json")
	login.RemoteAddr = "203.0.113.23:1234"
	loggedIn := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(loggedIn, login)
	if loggedIn.Code != http.StatusOK || len(loggedIn.Result().Cookies()) == 0 {
		t.Fatalf("login status=%d body=%s", loggedIn.Code, loggedIn.Body.String())
	}
	cookie := loggedIn.Result().Cookies()[0]
	s.cfg.AdminToken = "rotated-root-secret"
	request := httptest.NewRequest(http.MethodGet, "http://ciradar.test/api/v1/status", nil)
	request.RemoteAddr = "203.0.113.23:1234"
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("rotated root session status=%d body=%s", response.Code, response.Body.String())
	}
}
