package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig() Config {
	cfg := Default()
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	return cfg
}

func TestDefaultIsPrivateAndChannelsUnique(t *testing.T) {
	cfg := testConfig()
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
	cfg := testConfig()
	cfg.CrossTenantCorrelation = true
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "fingerprint_hmac_key") {
		t.Fatalf("error=%v", err)
	}
}

func TestNotificationValidation(t *testing.T) {
	cfg := testConfig()
	cfg.Notifications.Channels[0].Events = []string{"made_up"}
	if err := cfg.normalize(); err == nil {
		t.Fatal("unsupported notification event accepted")
	}
	cfg = testConfig()
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
	if len(cfg.DashboardSessionSecret) < 40 {
		t.Fatalf("dashboard session secret was not generated")
	}
	if cfg.DashboardSessionSecret == cfg.AdminToken || cfg.DashboardSessionSecret == cfg.FingerprintHMACKey {
		t.Fatal("dashboard session secret reused another generated credential")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("permissions=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestHardeningConfigurationValidation(t *testing.T) {
	cfg := testConfig()
	cfg.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "trusted_proxy_cidrs") {
		t.Fatalf("invalid trusted proxy accepted: %v", err)
	}
	cfg = testConfig()
	cfg.DashboardSessionSecret = "short"
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "dashboard_session_secret") {
		t.Fatalf("short session secret accepted: %v", err)
	}
	cfg = testConfig()
	cfg.RedactionPatterns = []string{"["}
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "redaction pattern") {
		t.Fatalf("invalid redaction pattern accepted: %v", err)
	}
}

func TestPublicBaseURLMustBeAnOriginAndEnablesSecureCookie(t *testing.T) {
	for _, raw := range []string{
		"javascript:alert(1)",
		"/relative",
		"https://user@example.com",
		"https://example.com/ciradar",
		"https://example.com?tenant=other",
		"https://example.com?",
		"https://example.com/%2f",
		"https://example.com/#fragment",
	} {
		cfg := testConfig()
		cfg.PublicBaseURL = raw
		if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "public_base_url") {
			t.Fatalf("invalid public base URL %q accepted: %v", raw, err)
		}
	}

	cfg := testConfig()
	cfg.PublicBaseURL = "HTTPS://ciradar.example/"
	cfg.DashboardCookieSecure = false
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.PublicBaseURL != "https://ciradar.example" || !cfg.DashboardCookieSecure {
		t.Fatalf("normalized URL=%q secure=%v", cfg.PublicBaseURL, cfg.DashboardCookieSecure)
	}
}

func TestMarketplaceIsMetadataOnlyAndRequiresWebhookSecret(t *testing.T) {
	cfg := testConfig()
	cfg.GitHubMarketplace.Enabled = true
	cfg.GitHubWebhookSecret = ""
	cfg.GitHubMarketplace.WebhookSecret = ""
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "marketplace") {
		t.Fatalf("marketplace without secret accepted: %v", err)
	}
	cfg.GitHubMarketplace.WebhookSecret = "secret"
	if err := cfg.normalize(); err != nil {
		t.Fatalf("valid marketplace config rejected: %v", err)
	}
}

func TestIncidentThresholdsHaveMinimumOfTwo(t *testing.T) {
	cfg := testConfig()
	cfg.IncidentRepoThreshold = 0
	cfg.IncidentOrgThreshold = 1
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.IncidentRepoThreshold != 2 || cfg.IncidentOrgThreshold != 2 {
		t.Fatalf("thresholds=%d/%d, want 2/2", cfg.IncidentRepoThreshold, cfg.IncidentOrgThreshold)
	}
}

func TestDashboardSessionSecretIsRequired(t *testing.T) {
	cfg := testConfig()
	cfg.DashboardSessionSecret = ""
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "dashboard_session_secret is required") {
		t.Fatalf("missing dashboard session secret accepted: %v", err)
	}
}

func TestWeakMasterKeyIsRejected(t *testing.T) {
	cfg := testConfig()
	cfg.MasterKey = "human-passphrase"
	if err := cfg.resolveSecrets(); err == nil || !strings.Contains(err.Error(), "32-byte base64url") {
		t.Fatalf("weak master key accepted: %v", err)
	}
}

func TestDashboardSessionSecretCannotReuseAnotherCredential(t *testing.T) {
	for name, apply := range map[string]func(*Config){
		"admin token": func(cfg *Config) {
			cfg.AdminToken = "0123456789abcdef0123456789abcdef"
			cfg.DashboardSessionSecret = cfg.AdminToken
		},
		"fingerprint key": func(cfg *Config) {
			cfg.FingerprintHMACKey = "0123456789abcdef0123456789abcdef"
			cfg.DashboardSessionSecret = cfg.FingerprintHMACKey
		},
		"SSO session secret": func(cfg *Config) {
			cfg.SSO.SessionSecret = "0123456789abcdef0123456789abcdef"
			cfg.DashboardSessionSecret = cfg.SSO.SessionSecret
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			apply(&cfg)
			if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "must not reuse") {
				t.Fatalf("credential reuse accepted: %v", err)
			}
		})
	}
}

func TestEmailNotificationRejectsHeaderInjection(t *testing.T) {
	cfg := testConfig()
	ch := &cfg.Notifications.Channels[len(cfg.Notifications.Channels)-1]
	ch.Enabled = true
	ch.SMTPHost = "smtp.example.com"
	ch.EmailFrom = "ci@example.com\r\nBcc: attacker@example.com"
	ch.EmailTo = []string{"ops@example.com"}
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "invalid email_from") {
		t.Fatalf("email header injection accepted: %v", err)
	}

	cfg = testConfig()
	ch = &cfg.Notifications.Channels[len(cfg.Notifications.Channels)-1]
	ch.Enabled = true
	ch.SMTPHost = "smtp.example.com"
	ch.EmailFrom = "ci@example.com"
	ch.EmailTo = []string{"ops@example.com\nCc: attacker@example.com"}
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "invalid email_to") {
		t.Fatalf("recipient header injection accepted: %v", err)
	}
}

func TestDisabledIntegrationSecretsAreNotResolved(t *testing.T) {
	cfg := testConfig()
	cfg.GitHubMarketplace.Enabled = false
	cfg.GitHubMarketplace.WebhookSecret = "env:CI_RADAR_MISSING_MARKETPLACE_SECRET"
	cfg.Notifications.Enabled = false
	cfg.Notifications.Channels[0].Enabled = true
	cfg.Notifications.Channels[0].URL = "env:CI_RADAR_MISSING_WEBHOOK"
	cfg.Connectors[0].Enabled = false
	cfg.Connectors[0].Token = "env:CI_RADAR_MISSING_CONNECTOR_TOKEN"
	cfg.SSO.Enabled = false
	cfg.SSO.ClientSecret = "env:CI_RADAR_MISSING_SSO_SECRET"
	cfg.LLM.Enabled = false
	cfg.LLM.APIKey = "env:CI_RADAR_MISSING_LLM_KEY"
	cfg.ChatOps.Enabled = false
	cfg.ChatOps.SlackSigningSecret = "env:CI_RADAR_MISSING_CHATOPS_SECRET"
	if err := cfg.resolveSecrets(); err != nil {
		t.Fatalf("disabled integration secret blocked configuration: %v", err)
	}
}

func TestEnabledIntegrationSecretsMustResolve(t *testing.T) {
	cfg := testConfig()
	cfg.Notifications.Enabled = true
	cfg.Notifications.Channels[0].Enabled = true
	cfg.Notifications.Channels[0].URL = "env:CI_RADAR_MISSING_ENABLED_WEBHOOK"
	if err := cfg.resolveSecrets(); err == nil || !strings.Contains(err.Error(), "CI_RADAR_MISSING_ENABLED_WEBHOOK") {
		t.Fatalf("missing enabled integration secret was accepted: %v", err)
	}
}

func TestSemanticLocalAPIKeyIsResolved(t *testing.T) {
	t.Setenv("CI_RADAR_LOCAL_EMBEDDING_KEY", "local-secret")
	cfg := testConfig()
	cfg.Semantic.Enabled = true
	cfg.Semantic.Mode = "ollama"
	cfg.Semantic.LocalAPIKey = "env:CI_RADAR_LOCAL_EMBEDDING_KEY"
	if err := cfg.resolveSecrets(); err != nil {
		t.Fatal(err)
	}
	if cfg.Semantic.LocalAPIKey != "local-secret" {
		t.Fatalf("local API key=%q", cfg.Semantic.LocalAPIKey)
	}
}
