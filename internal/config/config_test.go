package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := Default()
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	return cfg
}

func testSAMLPrerequisites(t *testing.T, cfg *Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SSO.SAMLIdPCertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	xmlsecPath := filepath.Join(t.TempDir(), "xmlsec1")
	if err := os.WriteFile(xmlsecPath, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.SSO.SAMLXMLSecPath = xmlsecPath
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
			cfg.SSO.SessionSecret = "abcdef0123456789abcdef0123456789"
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

func TestChatOpsRequiresExplicitAllowlists(t *testing.T) {
	cfg := testConfig()
	cfg.ChatOps.Enabled = true
	cfg.ChatOps.SlackSigningSecret = "slack-secret"
	cfg.ChatOps.TeamsSigningSecret = ""
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "slack_allowed") {
		t.Fatalf("Slack ChatOps without an allowlist was accepted: %v", err)
	}

	cfg = testConfig()
	cfg.ChatOps.Enabled = true
	cfg.ChatOps.SlackSigningSecret = ""
	cfg.ChatOps.TeamsSigningSecret = "teams-secret"
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "teams_allowed_users") {
		t.Fatalf("Teams ChatOps without an allowlist was accepted: %v", err)
	}

	cfg = testConfig()
	cfg.ChatOps.Enabled = true
	cfg.ChatOps.SlackSigningSecret = "slack-secret"
	cfg.ChatOps.SlackAllowedTeams = []string{"T123"}
	cfg.ChatOps.TeamsSigningSecret = "teams-secret"
	cfg.ChatOps.TeamsAllowedUsers = []string{"29:user"}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("ChatOps with explicit allowlists was rejected: %v", err)
	}
}

func TestNotificationRepositoryPatternsAreValidated(t *testing.T) {
	cfg := testConfig()
	cfg.Notifications.Enabled = true
	cfg.Notifications.Channels = []NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: "https://hooks.example.test/notify", IncludeRepositories: []string{"[broken"}}}
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "invalid repository pattern") {
		t.Fatalf("err=%v", err)
	}

	cfg = testConfig()
	cfg.Notifications.Enabled = true
	cfg.Notifications.Channels = []NotificationChannel{{Name: "ops", Type: "webhook", Enabled: true, URL: "https://hooks.example.test/notify", ExcludeRepositories: []string{"acme/*"}}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("valid repository pattern rejected: %v", err)
	}
}

func TestLLMRejectsAnthropicCompatibilityConfiguration(t *testing.T) {
	cfg := testConfig()
	cfg.LLM.Enabled = true
	cfg.LLM.Provider = "openai-compatible"
	cfg.LLM.Endpoint = "https://api.anthropic.com/v1/chat/completions"
	cfg.LLM.DataPolicy = "metadata_only"
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "provider anthropic") {
		t.Fatalf("expected Anthropic compatibility configuration to fail, got %v", err)
	}
}

func TestLLMAcceptsNativeAnthropicProvider(t *testing.T) {
	cfg := testConfig()
	cfg.LLM.Enabled = true
	cfg.LLM.Provider = "Anthropic"
	cfg.LLM.Endpoint = "https://api.anthropic.com"
	cfg.LLM.DataPolicy = "metadata_only"
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.Provider != "anthropic" {
		t.Fatalf("provider=%q", cfg.LLM.Provider)
	}
}

func TestSAMLDefaultsToStrictSecurityProfile(t *testing.T) {
	cfg := testConfig()
	cfg.SSO.Enabled = true
	cfg.SSO.Mode = "saml"
	cfg.SSO.SessionSecret = "abcdef0123456789abcdef0123456789"
	cfg.SSO.SAMLEntityID = "https://ciradar.example/saml"
	cfg.SSO.SAMLIdPSSOURL = "https://idp.example/sso"
	cfg.SSO.SAMLIdPEntityID = "https://idp.example/metadata"
	cfg.SSO.SAMLACSURL = "https://ciradar.example/auth/callback"
	testSAMLPrerequisites(t, &cfg)
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.SSO.SAMLSecurityProfile != "strict" {
		t.Fatalf("profile=%q", cfg.SSO.SAMLSecurityProfile)
	}
}

func TestSAMLRejectsRelativeXMLSecPath(t *testing.T) {
	cfg := testConfig()
	cfg.SSO.Enabled = true
	cfg.SSO.Mode = "saml"
	cfg.SSO.SessionSecret = "abcdef0123456789abcdef0123456789"
	cfg.SSO.SAMLEntityID = "https://ciradar.example/saml"
	cfg.SSO.SAMLIdPSSOURL = "https://idp.example/sso"
	cfg.SSO.SAMLIdPEntityID = "https://idp.example/metadata"
	cfg.SSO.SAMLIdPCertificate = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
	cfg.SSO.SAMLACSURL = "https://ciradar.example/auth/callback"
	cfg.SSO.SAMLXMLSecPath = "xmlsec1"
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "absolute saml_xmlsec_path") {
		t.Fatalf("expected relative xmlsec path rejection, got %v", err)
	}
}

func TestRemoteSourceCodeRequiresExplicitAcknowledgement(t *testing.T) {
	cfg := testConfig()
	cfg.LLM.Enabled = true
	cfg.LLM.Provider = "openai-compatible"
	cfg.LLM.Endpoint = "https://llm.example/v1/chat/completions"
	cfg.LLM.DataPolicy = "redacted_remote"
	cfg.LLM.SendSourceCode = true
	cfg.LLM.AllowRemoteSourceCode = false
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "allow_remote_source_code") {
		t.Fatalf("expected explicit remote-source acknowledgement requirement, got %v", err)
	}
	cfg.LLM.AllowRemoteSourceCode = true
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteLLMRequiresHTTPS(t *testing.T) {
	cfg := testConfig()
	cfg.LLM.Enabled = true
	cfg.LLM.Endpoint = "http://llm.example/v1/chat/completions"
	cfg.LLM.DataPolicy = "metadata_only"
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS rejection, got %v", err)
	}
}

func TestMetadataOnlyDisablesPayloadContent(t *testing.T) {
	cfg := testConfig()
	cfg.LLM.Enabled = true
	cfg.LLM.Endpoint = "https://llm.example/v1/chat/completions"
	cfg.LLM.DataPolicy = "metadata_only"
	cfg.LLM.SendRedactedExcerpt = true
	cfg.LLM.SendChangedFiles = true
	cfg.LLM.SendSourceCode = true
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.SendRedactedExcerpt || cfg.LLM.SendChangedFiles || cfg.LLM.SendSourceCode {
		t.Fatalf("metadata-only policy retained content flags: %#v", cfg.LLM)
	}
}

func TestRedactedRemoteLLMRequiresResidualSecretBlocking(t *testing.T) {
	cfg := testConfig()
	cfg.LLM.Enabled = true
	cfg.LLM.Provider = "openai-compatible"
	cfg.LLM.Endpoint = "https://llm.example/v1/chat/completions"
	cfg.LLM.DataPolicy = "redacted_remote"
	cfg.LLM.SendSourceCode = false
	cfg.LLM.BlockOnResidualSecret = false
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "block_on_residual_secret") {
		t.Fatalf("expected residual-secret blocking requirement, got %v", err)
	}
	cfg.LLM.BlockOnResidualSecret = true
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicBaseURLRequiredForNonLoopbackListen(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8787", ":8787", "192.0.2.10:8787", "ciradar.internal:8787"} {
		if !listenAddressIsPublic(address) {
			t.Fatalf("address=%q was treated as loopback", address)
		}
	}
	for _, address := range []string{"127.0.0.1:8787", "[::1]:8787", "localhost:8787"} {
		if listenAddressIsPublic(address) {
			t.Fatalf("loopback address=%q was treated as public", address)
		}
	}

	cfg := Default()
	cfg.ListenAddress = "0.0.0.0:8787"
	cfg.PublicBaseURL = ""
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "public_base_url") {
		t.Fatalf("error=%v", err)
	}
}
