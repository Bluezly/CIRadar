package server

import (
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
