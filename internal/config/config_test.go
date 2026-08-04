package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsPrivateAndChannelsUnique(t *testing.T) {
	cfg := Default()
	if cfg.CrossTenantCorrelation || cfg.StoreRawLogs {
		t.Fatalf("unsafe sharing/storage defaults: %+v", cfg)
	}
	seen := map[string]bool{}
	for _, ch := range cfg.Notifications.Channels {
		if seen[ch.Name] {
			t.Fatalf("duplicate channel %q", ch.Name)
		}
		seen[ch.Name] = true
	}
}

func TestCrossTenantCorrelationRequiresHMACKey(t *testing.T) {
	cfg := Default()
	cfg.CrossTenantCorrelation = true
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "fingerprint_hmac_key") {
		t.Fatalf("error=%v", err)
	}
}

func TestNotificationValidation(t *testing.T) {
	cfg := Default()
	cfg.Notifications.Channels[0].Events = []string{"made_up"}
	if err := cfg.normalize(); err == nil {
		t.Fatal("unsupported notification event accepted")
	}
	cfg = Default()
	cfg.Notifications.Channels[0].MinimumSeverity = "disaster"
	if err := cfg.normalize(); err == nil {
		t.Fatal("invalid severity accepted")
	}
}

func TestSaveDefaultGeneratesRootTokenWithRestrictedPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ciradar.json")
	if err := SaveDefault(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.AdminToken, "cir_root_") || len(cfg.AdminToken) < 40 {
		t.Fatalf("bad admin token: %q", cfg.AdminToken)
	}
	if len(cfg.FingerprintHMACKey) < 40 {
		t.Fatalf("fingerprint HMAC key was not generated")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("permissions=%v err=%v", info.Mode().Perm(), err)
	}
}
