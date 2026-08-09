package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/Bluezly/CIRadar/internal/secrets"
)

const MaxLogBytesLimit int64 = 256 << 20

type NotificationChannel struct {
	Name                     string            `json:"name"`
	Type                     string            `json:"type"`
	Enabled                  bool              `json:"enabled"`
	URL                      string            `json:"url,omitempty"`
	BotToken                 string            `json:"bot_token,omitempty"`
	ChatID                   string            `json:"chat_id,omitempty"`
	MessageThreadID          int64             `json:"message_thread_id,omitempty"`
	Username                 string            `json:"username,omitempty"`
	Mention                  string            `json:"mention,omitempty"`
	Events                   []string          `json:"events,omitempty"`
	Categories               []string          `json:"categories,omitempty"`
	MinimumScore             int               `json:"minimum_score,omitempty"`
	MinimumSeverity          string            `json:"minimum_severity,omitempty"`
	ExternalOnly             bool              `json:"external_only,omitempty"`
	IncludeRepositories      []string          `json:"include_repositories,omitempty"`
	ExcludeRepositories      []string          `json:"exclude_repositories,omitempty"`
	CooldownText             string            `json:"cooldown,omitempty"`
	Cooldown                 time.Duration     `json:"-"`
	TimeoutText              string            `json:"timeout,omitempty"`
	Timeout                  time.Duration     `json:"-"`
	MaxAttempts              int               `json:"max_attempts,omitempty"`
	Headers                  map[string]string `json:"headers,omitempty"`
	HMACSecret               string            `json:"hmac_secret,omitempty"`
	APIKey                   string            `json:"api_key,omitempty"`
	RoutingKey               string            `json:"routing_key,omitempty"`
	SMTPHost                 string            `json:"smtp_host,omitempty"`
	SMTPPort                 int               `json:"smtp_port,omitempty"`
	SMTPUsername             string            `json:"smtp_username,omitempty"`
	SMTPPassword             string            `json:"smtp_password,omitempty"`
	SMTPMode                 string            `json:"smtp_mode,omitempty"`
	EmailFrom                string            `json:"email_from,omitempty"`
	EmailTo                  []string          `json:"email_to,omitempty"`
	QuietHoursStart          string            `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd            string            `json:"quiet_hours_end,omitempty"`
	Timezone                 string            `json:"timezone,omitempty"`
	QuietHoursBypassSeverity string            `json:"quiet_hours_bypass_severity,omitempty"`
	AllowPrivateNetwork      bool              `json:"allow_private_network,omitempty"`
}

type CIConnector struct {
	Name                string            `json:"name"`
	Provider            string            `json:"provider"`
	Enabled             bool              `json:"enabled"`
	TenantID            string            `json:"tenant_id"`
	BaseURL             string            `json:"base_url,omitempty"`
	Token               string            `json:"token,omitempty"`
	WebhookSecret       string            `json:"webhook_secret,omitempty"`
	Username            string            `json:"username,omitempty"`
	Organization        string            `json:"organization,omitempty"`
	Project             string            `json:"project,omitempty"`
	Region              string            `json:"region,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	RetryURL            string            `json:"retry_url,omitempty"`
	RetryMethod         string            `json:"retry_method,omitempty"`
	RetryBody           string            `json:"retry_body,omitempty"`
	CostPerMinute       float64           `json:"cost_per_minute,omitempty"`
	Currency            string            `json:"currency,omitempty"`
	AllowPrivateNetwork bool              `json:"allow_private_network,omitempty"`
}

type TestIntelligenceConfig struct {
	Enabled                    bool          `json:"enabled"`
	AutoQuarantine             bool          `json:"auto_quarantine"`
	AutoQuarantineMinRuns      int           `json:"auto_quarantine_min_runs"`
	AutoQuarantineMinScore     float64       `json:"auto_quarantine_min_score"`
	AutoQuarantineDurationText string        `json:"auto_quarantine_duration"`
	AutoQuarantineDuration     time.Duration `json:"-"`
}

type PRCommentConfig struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	MinimumScore   int    `json:"minimum_score"`
	UpdateExisting bool   `json:"update_existing"`
}

type NotificationConfig struct {
	Enabled  bool                  `json:"enabled"`
	Channels []NotificationChannel `json:"channels,omitempty"`
}

type Config struct {
	ListenAddress                 string                 `json:"listen_address"`
	DatabaseDriver                string                 `json:"database_driver"`
	DatabaseURL                   string                 `json:"database_url,omitempty"`
	DatabasePath                  string                 `json:"database_path"`
	DataDirectory                 string                 `json:"data_directory"`
	RulesDirectory                string                 `json:"rules_directory"`
	LogLevel                      string                 `json:"log_level"`
	RetentionDays                 int                    `json:"retention_days"`
	StoreRedactedExcerpts         bool                   `json:"store_redacted_excerpts"`
	StoreRawLogs                  bool                   `json:"store_raw_logs"`
	CrossTenantCorrelation        bool                   `json:"cross_tenant_correlation"`
	IncidentWindow                time.Duration          `json:"-"`
	IncidentWindowText            string                 `json:"incident_window"`
	IncidentRepoThreshold         int                    `json:"incident_repo_threshold"`
	IncidentOrgThreshold          int                    `json:"incident_org_threshold"`
	WorkerCount                   int                    `json:"worker_count"`
	MaxLogBytes                   int64                  `json:"max_log_bytes"`
	ProviderPolling               bool                   `json:"provider_polling"`
	ProviderPollInterval          time.Duration          `json:"-"`
	ProviderPollIntervalText      string                 `json:"provider_poll_interval"`
	AutomaticRetryEnabled         bool                   `json:"automatic_retry_enabled"`
	AutomaticRetryMinScore        int                    `json:"automatic_retry_min_score"`
	GitHubAppID                   int64                  `json:"github_app_id"`
	GitHubPrivateKeyPath          string                 `json:"github_private_key_path"`
	GitHubWebhookSecret           string                 `json:"github_webhook_secret"`
	GitHubAPIURL                  string                 `json:"github_api_url"`
	GitHubAllowPrivateNetwork     bool                   `json:"github_allow_private_network,omitempty"`
	RequireInstallationBinding    bool                   `json:"require_github_installation_binding"`
	PublicBaseURL                 string                 `json:"public_base_url"`
	SourceURL                     string                 `json:"source_url,omitempty"`
	FingerprintHMACKey            string                 `json:"fingerprint_hmac_key"`
	AdminToken                    string                 `json:"admin_token"`
	DefaultTenantID               string                 `json:"default_tenant_id"`
	AllowUnauthenticatedLocalhost bool                   `json:"allow_unauthenticated_localhost"`
	TrustedProxyCIDRs             []string               `json:"trusted_proxy_cidrs,omitempty"`
	DashboardEnabled              bool                   `json:"dashboard_enabled"`
	DashboardSessionSecret        string                 `json:"dashboard_session_secret,omitempty"`
	DashboardCookieSecure         bool                   `json:"dashboard_cookie_secure"`
	RedactionPatterns             []string               `json:"redaction_patterns,omitempty"`
	RedactionEntropyDetection     bool                   `json:"redaction_entropy_detection"`
	GitHubMarketplace             MarketplaceConfig      `json:"github_marketplace"`
	IncidentResolveAfterText      string                 `json:"incident_resolve_after"`
	IncidentResolveAfter          time.Duration          `json:"-"`
	Notifications                 NotificationConfig     `json:"notifications"`
	PRComments                    PRCommentConfig        `json:"pr_comments"`
	Connectors                    []CIConnector          `json:"connectors,omitempty"`
	TestIntelligence              TestIntelligenceConfig `json:"test_intelligence"`
	SSO                           SSOConfig              `json:"sso"`
	LLM                           LLMConfig              `json:"llm"`
	Repair                        RepairConfig           `json:"repair"`
	ChatOps                       ChatOpsConfig          `json:"chatops"`
	Costs                         CostConfig             `json:"costs"`
	Semantic                      SemanticConfig         `json:"semantic_similarity"`
	PredictiveTests               PredictiveTestConfig   `json:"predictive_tests"`
	MasterKey                     string                 `json:"-"`
}

func Default() Config {
	dataDir := ".ciradar"
	return Config{
		ListenAddress:                 "127.0.0.1:8787",
		DatabaseDriver:                "embedded",
		DatabasePath:                  filepath.Join(dataDir, "ciradar-state.json"),
		DataDirectory:                 dataDir,
		RulesDirectory:                "rules",
		LogLevel:                      "info",
		RetentionDays:                 30,
		StoreRedactedExcerpts:         true,
		StoreRawLogs:                  false,
		CrossTenantCorrelation:        false,
		IncidentWindowText:            "15m",
		IncidentWindow:                15 * time.Minute,
		IncidentRepoThreshold:         3,
		IncidentOrgThreshold:          2,
		WorkerCount:                   2,
		MaxLogBytes:                   32 << 20,
		ProviderPolling:               true,
		ProviderPollIntervalText:      "2m",
		ProviderPollInterval:          2 * time.Minute,
		AutomaticRetryEnabled:         false,
		AutomaticRetryMinScore:        85,
		GitHubAPIURL:                  "https://api.github.com",
		RequireInstallationBinding:    true,
		DefaultTenantID:               "default",
		AllowUnauthenticatedLocalhost: false,
		TrustedProxyCIDRs:             []string{},
		DashboardEnabled:              true,
		DashboardCookieSecure:         false,
		RedactionEntropyDetection:     true,
		GitHubMarketplace:             MarketplaceConfig{Enabled: false, AutoCreateTenant: true, CancellationPolicy: "retain_free", FreePlanName: "free"},
		IncidentResolveAfterText:      "30m",
		IncidentResolveAfter:          30 * time.Minute,
		PRComments:                    PRCommentConfig{Enabled: true, Mode: "external_or_strong", MinimumScore: 60, UpdateExisting: true},
		TestIntelligence:              TestIntelligenceConfig{Enabled: true, AutoQuarantine: false, AutoQuarantineMinRuns: 5, AutoQuarantineMinScore: 65, AutoQuarantineDurationText: "7d"},
		SSO:                           SSOConfig{Enabled: false, Mode: "oidc", DefaultTenant: "default", DefaultRole: "viewer", CookieName: "ciradar_session", CookieSecure: true},
		LLM:                           LLMConfig{Enabled: false, Provider: "openai-compatible", Model: "gpt-5-mini", MinimumScore: 60, MaxInputCharacters: 24000, MaxOutputTokens: 1200, TimeoutText: "45s", SendRedactedExcerpt: true, SendChangedFiles: true, SendSourceCode: true, MaxSourceFiles: 8, MaxSourceFileCharacters: 32000, DataPolicy: "local_only", BlockOnResidualSecret: true},
		Repair:                        RepairConfig{Enabled: false, AutoDraftPR: false, MinimumScore: 60, BranchPrefix: "github.com/Bluezly/CIRadar/repair-", MaximumFiles: 10, MaximumLines: 1000},
		ChatOps:                       ChatOpsConfig{Enabled: false, DefaultTenant: "default", AllowAcknowledge: true, AllowResolve: true, AllowQuarantine: true, QuarantineDuration: "7d"},
		Costs:                         CostConfig{Enabled: true, Currency: "USD", DefaultRates: map[string]float64{}, RunnerRates: map[string]float64{}, BillingRounds: map[string]int{}},
		Semantic:                      SemanticConfig{Enabled: true, RemoteEmbeddings: false, VectorDimensions: 128, CandidateLimit: 500},
		PredictiveTests:               PredictiveTestConfig{Enabled: true, DefaultLimit: 100, MinimumScore: 20, AlwaysRunFlaky: true, AlwaysRunFailed: true},
		Notifications: NotificationConfig{Enabled: false, Channels: []NotificationChannel{
			{Name: "slack-ops", Type: "slack", Enabled: false, Events: []string{"analysis", "environment_changed", "incident_opened", "incident_updated", "incident_resolved", "test_flaky", "test_quarantined", "repair_pr_created"}, MinimumScore: 60, CooldownText: "15m", TimeoutText: "10s", MaxAttempts: 5},
			{Name: "discord-ops", Type: "discord", Enabled: false, Events: []string{"analysis", "environment_changed", "incident_opened", "incident_updated", "incident_resolved", "test_flaky", "test_quarantined", "repair_pr_created"}, MinimumScore: 60, CooldownText: "15m", TimeoutText: "10s", MaxAttempts: 5},
			{Name: "telegram-ops", Type: "telegram", Enabled: false, Events: []string{"analysis", "environment_changed", "incident_opened", "incident_updated", "incident_resolved", "test_flaky", "test_quarantined", "repair_pr_created"}, MinimumScore: 60, CooldownText: "15m", TimeoutText: "10s", MaxAttempts: 5},
			{Name: "custom-webhook", Type: "webhook", Enabled: false, Events: []string{"analysis", "environment_changed", "incident_opened", "incident_updated", "incident_resolved", "test_flaky", "test_quarantined", "repair_pr_created"}, MinimumScore: 60, CooldownText: "15m", TimeoutText: "10s", MaxAttempts: 5},
			{Name: "teams-ops", Type: "teams", Enabled: false, Events: []string{"incident_opened", "incident_updated", "incident_resolved", "test_quarantined"}, MinimumScore: 70, CooldownText: "15m", TimeoutText: "10s", MaxAttempts: 5},
			{Name: "pagerduty-ops", Type: "pagerduty", Enabled: false, Events: []string{"incident_opened", "incident_updated", "incident_resolved"}, MinimumSeverity: "major", CooldownText: "5m", TimeoutText: "10s", MaxAttempts: 5},
			{Name: "opsgenie-ops", Type: "opsgenie", Enabled: false, Events: []string{"incident_opened", "incident_updated", "incident_resolved"}, MinimumSeverity: "major", CooldownText: "5m", TimeoutText: "10s", MaxAttempts: 5},
			{Name: "email-ops", Type: "email", Enabled: false, Events: []string{"analysis", "incident_opened", "incident_resolved", "test_flaky", "test_quarantined", "repair_pr_created"}, MinimumScore: 75, CooldownText: "15m", TimeoutText: "15s", MaxAttempts: 5, SMTPMode: "starttls", SMTPPort: 587},
		}},
		Connectors: []CIConnector{
			{Name: "gitlab", Provider: "gitlab", Enabled: false, TenantID: "default", BaseURL: "https://gitlab.com"},
			{Name: "buildkite", Provider: "buildkite", Enabled: false, TenantID: "default", BaseURL: "https://api.buildkite.com"},
			{Name: "circleci", Provider: "circleci", Enabled: false, TenantID: "default", BaseURL: "https://circleci.com"},
			{Name: "jenkins", Provider: "jenkins", Enabled: false, TenantID: "default"},
			{Name: "azuredevops", Provider: "azuredevops", Enabled: false, TenantID: "default", BaseURL: "https://dev.azure.com"},
			{Name: "bitrise", Provider: "bitrise", Enabled: false, TenantID: "default", BaseURL: "https://api.bitrise.io"},
			{Name: "teamcity", Provider: "teamcity", Enabled: false, TenantID: "default"},
			{Name: "travis", Provider: "travis", Enabled: false, TenantID: "default", BaseURL: "https://api.travis-ci.com"},
			{Name: "codebuild", Provider: "codebuild", Enabled: false, TenantID: "default", BaseURL: "https://codebuild.amazonaws.com"},
			{Name: "bitbucket", Provider: "bitbucket", Enabled: false, TenantID: "default", BaseURL: "https://api.bitbucket.org"},
			{Name: "drone", Provider: "drone", Enabled: false, TenantID: "default", BaseURL: "https://cloud.drone.io"},
			{Name: "semaphore", Provider: "semaphore", Enabled: false, TenantID: "default", BaseURL: "https://api.semaphoreci.com"},
			{Name: "appveyor", Provider: "appveyor", Enabled: false, TenantID: "default", BaseURL: "https://ci.appveyor.com"},
			{Name: "cloudbuild", Provider: "cloudbuild", Enabled: false, TenantID: "default", BaseURL: "https://cloudbuild.googleapis.com"},
		},
	}
}

func listenAddressIsPublic(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return true
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return Config{}, err
			}
		} else if err := json.Unmarshal(b, &cfg); err != nil {
			return Config{}, fmt.Errorf("decode config: %w", err)
		}
	}
	applyEnv(&cfg)
	if err := cfg.resolveSecrets(); err != nil {
		return Config{}, err
	}
	if err := cfg.normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) resolveSecrets() error {
	if strings.TrimSpace(c.MasterKey) != "" {
		if err := secrets.ValidateMasterKey(c.MasterKey); err != nil {
			return err
		}
	}
	resolve := func(name string, dst *string) error {
		v, err := secrets.Resolve(c.MasterKey, *dst)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		*dst = v
		return nil
	}
	for name, dst := range map[string]*string{
		"fingerprint_hmac_key":     &c.FingerprintHMACKey,
		"admin_token":              &c.AdminToken,
		"dashboard_session_secret": &c.DashboardSessionSecret,
	} {
		if err := resolve(name, dst); err != nil {
			return err
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.DatabaseDriver), "postgres") {
		if err := resolve("database_url", &c.DatabaseURL); err != nil {
			return err
		}
	}
	usesGitHubWebhook := c.GitHubAppID > 0 || strings.TrimSpace(c.GitHubPrivateKeyPath) != "" || (c.GitHubMarketplace.Enabled && strings.TrimSpace(c.GitHubMarketplace.WebhookSecret) == "")
	if usesGitHubWebhook {
		if err := resolve("github_webhook_secret", &c.GitHubWebhookSecret); err != nil {
			return err
		}
	}
	if c.GitHubMarketplace.Enabled {
		if err := resolve("github_marketplace.webhook_secret", &c.GitHubMarketplace.WebhookSecret); err != nil {
			return err
		}
	}
	if c.SSO.Enabled {
		if err := resolve("sso.session_secret", &c.SSO.SessionSecret); err != nil {
			return err
		}
		mode := strings.ToLower(strings.TrimSpace(c.SSO.Mode))
		if mode == "" || mode == "oidc" {
			if err := resolve("sso.client_secret", &c.SSO.ClientSecret); err != nil {
				return err
			}
		}
		if mode == "proxy" || mode == "saml_proxy" {
			if err := resolve("sso.proxy_secret", &c.SSO.ProxySecret); err != nil {
				return err
			}
		}
	}
	semanticMode := strings.ToLower(strings.TrimSpace(c.Semantic.Mode))
	remoteSemantic := c.Semantic.RemoteEmbeddings || semanticMode == "remote"
	if c.LLM.Enabled || remoteSemantic {
		if err := resolve("llm.api_key", &c.LLM.APIKey); err != nil {
			return err
		}
	}
	localSemantic := c.Semantic.Enabled && (semanticMode == "" || semanticMode == "ollama")
	if localSemantic && strings.TrimSpace(c.Semantic.LocalAPIKey) != "" {
		if err := resolve("semantic_similarity.local_api_key", &c.Semantic.LocalAPIKey); err != nil {
			return err
		}
	}
	if c.ChatOps.Enabled {
		for name, dst := range map[string]*string{
			"chatops.slack_signing_secret": &c.ChatOps.SlackSigningSecret,
			"chatops.teams_signing_secret": &c.ChatOps.TeamsSigningSecret,
		} {
			if err := resolve(name, dst); err != nil {
				return err
			}
		}
	}
	if c.Notifications.Enabled {
		for i := range c.Notifications.Channels {
			ch := &c.Notifications.Channels[i]
			if !ch.Enabled {
				continue
			}
			for name, dst := range map[string]*string{
				"url":           &ch.URL,
				"bot_token":     &ch.BotToken,
				"chat_id":       &ch.ChatID,
				"hmac_secret":   &ch.HMACSecret,
				"api_key":       &ch.APIKey,
				"routing_key":   &ch.RoutingKey,
				"smtp_username": &ch.SMTPUsername,
				"smtp_password": &ch.SMTPPassword,
				"email_from":    &ch.EmailFrom,
			} {
				if err := resolve("notification channel "+ch.Name+"."+name, dst); err != nil {
					return err
				}
			}
		}
	}
	for i := range c.Connectors {
		co := &c.Connectors[i]
		if !co.Enabled {
			continue
		}
		for name, dst := range map[string]*string{"token": &co.Token, "webhook_secret": &co.WebhookSecret} {
			if err := resolve("connector "+co.Name+"."+name, dst); err != nil {
				return err
			}
		}
		for key, raw := range co.Headers {
			v, err := secrets.Resolve(c.MasterKey, raw)
			if err != nil {
				return fmt.Errorf("connector %q header %q: %w", co.Name, key, err)
			}
			co.Headers[key] = v
		}
	}
	return nil
}

func (c *Config) normalize() error {
	if c.DataDirectory == "" {
		c.DataDirectory = ".ciradar"
	}
	if c.RulesDirectory == "" {
		c.RulesDirectory = "rules"
	}
	c.DatabaseDriver = strings.ToLower(strings.TrimSpace(c.DatabaseDriver))
	if c.DatabaseDriver == "" {
		c.DatabaseDriver = "embedded"
	}
	if c.DatabaseDriver != "embedded" && c.DatabaseDriver != "postgres" {
		return fmt.Errorf("unsupported database_driver %q", c.DatabaseDriver)
	}
	if c.DatabaseDriver == "postgres" && strings.TrimSpace(c.DatabaseURL) == "" {
		return errors.New("database_url is required when database_driver is postgres")
	}
	if c.DatabasePath == "" {
		c.DatabasePath = filepath.Join(c.DataDirectory, "ciradar-state.json")
	}
	if c.IncidentWindowText == "" {
		c.IncidentWindowText = "15m"
	}
	d, err := time.ParseDuration(c.IncidentWindowText)
	if err != nil || d <= 0 {
		return fmt.Errorf("invalid incident_window %q", c.IncidentWindowText)
	}
	c.IncidentWindow = d
	if c.ProviderPollIntervalText == "" {
		c.ProviderPollIntervalText = "2m"
	}
	d, err = time.ParseDuration(c.ProviderPollIntervalText)
	if err != nil || d <= 0 {
		return fmt.Errorf("invalid provider_poll_interval %q", c.ProviderPollIntervalText)
	}
	c.ProviderPollInterval = d
	if c.IncidentRepoThreshold < 2 {
		c.IncidentRepoThreshold = 2
	}
	if c.IncidentOrgThreshold < 2 {
		c.IncidentOrgThreshold = 2
	}
	if c.WorkerCount < 1 {
		c.WorkerCount = 1
	}
	if c.WorkerCount > 32 {
		c.WorkerCount = 32
	}
	if c.MaxLogBytes < 1024 {
		c.MaxLogBytes = 32 << 20
	}
	if c.MaxLogBytes > MaxLogBytesLimit {
		return fmt.Errorf("max_log_bytes must not exceed %d bytes", MaxLogBytesLimit)
	}
	if c.GitHubAPIURL == "" {
		c.GitHubAPIURL = "https://api.github.com"
	}
	if strings.TrimSpace(c.PublicBaseURL) == "" && listenAddressIsPublic(c.ListenAddress) {
		return fmt.Errorf("public_base_url is required when listen_address is not loopback")
	}
	if strings.TrimSpace(c.PublicBaseURL) != "" {
		publicURL, err := url.Parse(strings.TrimSpace(c.PublicBaseURL))
		if err != nil {
			return fmt.Errorf("invalid public_base_url %q: use an absolute HTTP(S) origin without a path, query, fragment, or credentials", c.PublicBaseURL)
		}
		publicURL.Scheme = strings.ToLower(publicURL.Scheme)
		if publicURL.Host == "" || publicURL.Hostname() == "" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.ForceQuery || publicURL.Fragment != "" || publicURL.RawPath != "" || (publicURL.Path != "" && publicURL.Path != "/") || (publicURL.Scheme != "http" && publicURL.Scheme != "https") {
			return fmt.Errorf("invalid public_base_url %q: use an absolute HTTP(S) origin without a path, query, fragment, or credentials", c.PublicBaseURL)
		}
		c.PublicBaseURL = strings.TrimRight(publicURL.String(), "/")
		if publicURL.Scheme == "https" {
			c.DashboardCookieSecure = true
		}
	}
	c.DefaultTenantID = strings.ToLower(strings.TrimSpace(c.DefaultTenantID))
	if c.DefaultTenantID == "" {
		c.DefaultTenantID = "default"
	}
	if c.IncidentResolveAfterText == "" {
		c.IncidentResolveAfterText = "30m"
	}
	d, err = time.ParseDuration(c.IncidentResolveAfterText)
	if err != nil || d < c.IncidentWindow {
		return fmt.Errorf("invalid incident_resolve_after %q", c.IncidentResolveAfterText)
	}
	c.IncidentResolveAfter = d
	c.PRComments.Mode = strings.ToLower(strings.TrimSpace(c.PRComments.Mode))
	if c.PRComments.Mode == "" {
		c.PRComments.Mode = "external_or_strong"
	}
	switch c.PRComments.Mode {
	case "all", "strong_only", "external_only", "external_or_strong":
	default:
		return fmt.Errorf("invalid pr_comments.mode %q", c.PRComments.Mode)
	}
	if c.PRComments.MinimumScore < 0 {
		c.PRComments.MinimumScore = 0
	}
	if c.PRComments.MinimumScore > 100 {
		c.PRComments.MinimumScore = 100
	}
	if c.CrossTenantCorrelation && strings.TrimSpace(c.FingerprintHMACKey) == "" {
		return errors.New("cross_tenant_correlation requires fingerprint_hmac_key")
	}
	names := map[string]struct{}{}
	for i := range c.Notifications.Channels {
		ch := &c.Notifications.Channels[i]
		ch.Name = strings.TrimSpace(ch.Name)
		ch.Type = strings.ToLower(strings.TrimSpace(ch.Type))
		if ch.Name == "" {
			ch.Name = fmt.Sprintf("%s-%d", ch.Type, i+1)
		}
		if _, exists := names[ch.Name]; exists {
			return fmt.Errorf("duplicate notification channel name %q", ch.Name)
		}
		names[ch.Name] = struct{}{}
		switch ch.Type {
		case "slack", "discord", "telegram", "webhook", "teams", "pagerduty", "opsgenie", "email":
		default:
			return fmt.Errorf("notification channel %q has unsupported type %q", ch.Name, ch.Type)
		}
		if ch.CooldownText == "" {
			ch.CooldownText = "15m"
		}
		var err error
		ch.Cooldown, err = time.ParseDuration(ch.CooldownText)
		if err != nil || ch.Cooldown < 0 {
			return fmt.Errorf("notification channel %q has invalid cooldown %q", ch.Name, ch.CooldownText)
		}
		if ch.TimeoutText == "" {
			ch.TimeoutText = "10s"
		}
		ch.Timeout, err = time.ParseDuration(ch.TimeoutText)
		if err != nil || ch.Timeout <= 0 || ch.Timeout > 2*time.Minute {
			return fmt.Errorf("notification channel %q has invalid timeout %q", ch.Name, ch.TimeoutText)
		}
		if ch.MaxAttempts < 1 {
			ch.MaxAttempts = 5
		}
		if ch.MaxAttempts > 10 {
			ch.MaxAttempts = 10
		}
		if ch.MinimumScore < 0 {
			ch.MinimumScore = 0
		}
		if ch.MinimumScore > 100 {
			ch.MinimumScore = 100
		}
		if len(ch.Events) == 0 {
			ch.Events = []string{"analysis", "environment_changed", "incident_opened", "incident_updated", "incident_resolved", "test_flaky", "test_quarantined", "repair_pr_created"}
		}
		if ch.Timezone == "" {
			ch.Timezone = "UTC"
		}
		if ch.QuietHoursBypassSeverity == "" {
			ch.QuietHoursBypassSeverity = "critical"
		}
		if !validSeverity(ch.MinimumSeverity, true) {
			return fmt.Errorf("notification channel %q has invalid minimum_severity %q", ch.Name, ch.MinimumSeverity)
		}
		if !validSeverity(ch.QuietHoursBypassSeverity, false) {
			return fmt.Errorf("notification channel %q has invalid quiet_hours_bypass_severity %q", ch.Name, ch.QuietHoursBypassSeverity)
		}
		for _, event := range ch.Events {
			if !validNotificationEvent(event) {
				return fmt.Errorf("notification channel %q has unsupported event %q", ch.Name, event)
			}
		}
		for _, pattern := range append(append([]string(nil), ch.IncludeRepositories...), ch.ExcludeRepositories...) {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				return fmt.Errorf("notification channel %q has an empty repository pattern", ch.Name)
			}
			if _, err := path.Match(strings.ToLower(pattern), "example/repository"); err != nil {
				return fmt.Errorf("notification channel %q has invalid repository pattern %q: %w", ch.Name, pattern, err)
			}
		}
		if (ch.QuietHoursStart == "") != (ch.QuietHoursEnd == "") {
			return fmt.Errorf("notification channel %q requires both quiet_hours_start and quiet_hours_end", ch.Name)
		}
		if ch.QuietHoursStart != "" {
			if _, err := time.Parse("15:04", ch.QuietHoursStart); err != nil {
				return fmt.Errorf("notification channel %q has invalid quiet_hours_start", ch.Name)
			}
			if _, err := time.Parse("15:04", ch.QuietHoursEnd); err != nil {
				return fmt.Errorf("notification channel %q has invalid quiet_hours_end", ch.Name)
			}
			if _, err := time.LoadLocation(ch.Timezone); err != nil {
				return fmt.Errorf("notification channel %q has invalid timezone %q", ch.Name, ch.Timezone)
			}
		}
		ch.SMTPMode = strings.ToLower(strings.TrimSpace(ch.SMTPMode))
		if ch.SMTPMode == "" {
			ch.SMTPMode = "starttls"
		}
		if ch.SMTPPort == 0 {
			if ch.SMTPMode == "tls" {
				ch.SMTPPort = 465
			} else {
				ch.SMTPPort = 587
			}
		}
		if ch.SMTPMode != "plain" && ch.SMTPMode != "starttls" && ch.SMTPMode != "tls" {
			return fmt.Errorf("notification channel %q has invalid smtp_mode %q", ch.Name, ch.SMTPMode)
		}
		if ch.Enabled {
			if (ch.Type == "slack" || ch.Type == "discord" || ch.Type == "webhook" || ch.Type == "teams") && strings.TrimSpace(ch.URL) == "" {
				return fmt.Errorf("notification channel %q requires url", ch.Name)
			}
			if ch.Type == "telegram" && (strings.TrimSpace(ch.BotToken) == "" || strings.TrimSpace(ch.ChatID) == "") {
				return fmt.Errorf("notification channel %q requires bot_token and chat_id", ch.Name)
			}
			if ch.Type == "pagerduty" && strings.TrimSpace(ch.RoutingKey) == "" {
				return fmt.Errorf("notification channel %q requires routing_key", ch.Name)
			}
			if ch.Type == "opsgenie" && strings.TrimSpace(ch.APIKey) == "" {
				return fmt.Errorf("notification channel %q requires api_key", ch.Name)
			}
			if ch.Type == "email" {
				if strings.TrimSpace(ch.SMTPHost) == "" || strings.TrimSpace(ch.EmailFrom) == "" || len(ch.EmailTo) == 0 {
					return fmt.Errorf("notification channel %q requires smtp_host, email_from and email_to", ch.Name)
				}
				if err := validateEmailAddress(ch.EmailFrom); err != nil {
					return fmt.Errorf("notification channel %q has invalid email_from: %w", ch.Name, err)
				}
				for _, recipient := range ch.EmailTo {
					if err := validateEmailAddress(recipient); err != nil {
						return fmt.Errorf("notification channel %q has invalid email_to: %w", ch.Name, err)
					}
				}
			}
		}
	}
	if c.TestIntelligence.AutoQuarantineMinRuns < 3 {
		c.TestIntelligence.AutoQuarantineMinRuns = 5
	}
	if c.TestIntelligence.AutoQuarantineMinScore <= 0 || c.TestIntelligence.AutoQuarantineMinScore > 100 {
		c.TestIntelligence.AutoQuarantineMinScore = 65
	}
	if c.TestIntelligence.AutoQuarantineDurationText == "" {
		c.TestIntelligence.AutoQuarantineDurationText = "7d"
	}
	qText := strings.TrimSpace(c.TestIntelligence.AutoQuarantineDurationText)
	if strings.HasSuffix(qText, "d") {
		days, parseErr := strconv.Atoi(strings.TrimSuffix(qText, "d"))
		if parseErr != nil {
			err = parseErr
		} else {
			c.TestIntelligence.AutoQuarantineDuration = time.Duration(days) * 24 * time.Hour
		}
	} else {
		c.TestIntelligence.AutoQuarantineDuration, err = time.ParseDuration(qText)
	}
	if err != nil || c.TestIntelligence.AutoQuarantineDuration <= 0 || c.TestIntelligence.AutoQuarantineDuration > 30*24*time.Hour {
		return fmt.Errorf("invalid auto_quarantine_duration %q", c.TestIntelligence.AutoQuarantineDurationText)
	}
	connectorNames := map[string]struct{}{}
	if err := c.normalizeEnterprise(); err != nil {
		return err
	}
	if err := c.normalizeHardening(); err != nil {
		return err
	}
	for i := range c.Connectors {
		co := &c.Connectors[i]
		co.Name = strings.TrimSpace(co.Name)
		co.Provider = strings.ToLower(strings.TrimSpace(co.Provider))
		co.TenantID = strings.ToLower(strings.TrimSpace(co.TenantID))
		if co.TenantID == "" {
			co.TenantID = c.DefaultTenantID
		}
		if co.Name == "" {
			co.Name = co.Provider
		}
		if _, ok := connectorNames[co.Name]; ok {
			return fmt.Errorf("duplicate connector name %q", co.Name)
		}
		connectorNames[co.Name] = struct{}{}
		switch co.Provider {
		case "gitlab", "buildkite", "circleci", "jenkins", "azuredevops", "bitrise", "teamcity", "travis", "codebuild", "bitbucket", "drone", "semaphore", "appveyor", "cloudbuild":
		default:
			return fmt.Errorf("connector %q has unsupported provider %q", co.Name, co.Provider)
		}
		if co.Enabled && strings.TrimSpace(co.WebhookSecret) == "" {
			return fmt.Errorf("connector %q requires webhook_secret", co.Name)
		}
		if co.BaseURL == "" {
			switch co.Provider {
			case "gitlab":
				co.BaseURL = "https://gitlab.com"
			case "buildkite":
				co.BaseURL = "https://api.buildkite.com"
			case "circleci":
				co.BaseURL = "https://circleci.com"
			case "azuredevops":
				co.BaseURL = "https://dev.azure.com"
			case "bitrise":
				co.BaseURL = "https://api.bitrise.io"
			case "travis":
				co.BaseURL = "https://api.travis-ci.com"
			case "codebuild":
				co.BaseURL = "https://codebuild.amazonaws.com"
			case "bitbucket":
				co.BaseURL = "https://api.bitbucket.org"
			case "drone":
				co.BaseURL = "https://cloud.drone.io"
			case "semaphore":
				co.BaseURL = "https://api.semaphoreci.com"
			case "appveyor":
				co.BaseURL = "https://ci.appveyor.com"
			case "cloudbuild":
				co.BaseURL = "https://cloudbuild.googleapis.com"
			}
		}
	}
	return nil
}

func (c Config) Connector(provider string) *CIConnector {
	provider = strings.ToLower(strings.TrimSpace(provider))
	for i := range c.Connectors {
		if c.Connectors[i].Enabled && c.Connectors[i].Provider == provider {
			v := c.Connectors[i]
			return &v
		}
	}
	return nil
}

func validateEmailAddress(raw string) error {
	if strings.ContainsAny(raw, "\r\n") {
		return errors.New("address contains a line break")
	}
	address, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if strings.TrimSpace(address.Address) == "" {
		return errors.New("address is empty")
	}
	return nil
}

func validSeverity(v string, allowEmpty bool) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return allowEmpty
	}
	switch v {
	case "info", "minor", "major", "critical":
		return true
	default:
		return false
	}
}

func validNotificationEvent(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "analysis", "environment_changed", "incident_opened", "incident_updated", "incident_resolved", "test", "test_flaky", "test_quarantined", "repair_pr_created":
		return true
	default:
		return false
	}
}

func SaveDefault(path string) error {
	cfg := Default()
	var err error
	cfg.AdminToken, err = generateToken(32)
	if err != nil {
		return err
	}
	cfg.FingerprintHMACKey, err = generateSecret(32)
	if err != nil {
		return err
	}
	cfg.DashboardSessionSecret, err = generateSecret(32)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func generateToken(n int) (string, error) {
	secret, err := generateSecret(n)
	if err != nil {
		return "", err
	}
	return "cir_root_" + secret, nil
}

func generateSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c Config) GitHubConfigured() bool {
	return c.GitHubAppID > 0 && c.GitHubPrivateKeyPath != "" && c.GitHubWebhookSecret != ""
}

func applyEnv(c *Config) {
	setString(&c.ListenAddress, "CIRADAR_LISTEN")
	setString(&c.DatabaseDriver, "CIRADAR_DATABASE_DRIVER")
	setString(&c.DatabaseURL, "CIRADAR_DATABASE_URL")
	setString(&c.DatabasePath, "CIRADAR_DATABASE")
	setString(&c.MasterKey, "CIRADAR_MASTER_KEY")
	setString(&c.DataDirectory, "CIRADAR_DATA_DIR")
	setString(&c.RulesDirectory, "CIRADAR_RULES_DIR")
	setString(&c.LogLevel, "CIRADAR_LOG_LEVEL")
	setString(&c.GitHubPrivateKeyPath, "CIRADAR_GITHUB_PRIVATE_KEY")
	setString(&c.GitHubWebhookSecret, "CIRADAR_GITHUB_WEBHOOK_SECRET")
	setString(&c.GitHubAPIURL, "CIRADAR_GITHUB_API_URL")
	setBool(&c.GitHubAllowPrivateNetwork, "CIRADAR_GITHUB_ALLOW_PRIVATE_NETWORK")
	setString(&c.PublicBaseURL, "CIRADAR_PUBLIC_BASE_URL")
	setString(&c.FingerprintHMACKey, "CIRADAR_FINGERPRINT_KEY")
	setString(&c.AdminToken, "CIRADAR_ADMIN_TOKEN")
	setString(&c.DefaultTenantID, "CIRADAR_DEFAULT_TENANT")
	setString(&c.IncidentWindowText, "CIRADAR_INCIDENT_WINDOW")
	setString(&c.IncidentResolveAfterText, "CIRADAR_INCIDENT_RESOLVE_AFTER")
	setString(&c.ProviderPollIntervalText, "CIRADAR_PROVIDER_POLL_INTERVAL")
	setBool(&c.StoreRawLogs, "CIRADAR_STORE_RAW_LOGS")
	setBool(&c.CrossTenantCorrelation, "CIRADAR_CROSS_TENANT_CORRELATION")
	setBool(&c.RequireInstallationBinding, "CIRADAR_REQUIRE_INSTALLATION_BINDING")
	setBool(&c.ProviderPolling, "CIRADAR_PROVIDER_POLLING")
	setBool(&c.AutomaticRetryEnabled, "CIRADAR_AUTO_RETRY")
	setBool(&c.Notifications.Enabled, "CIRADAR_NOTIFICATIONS_ENABLED")
	setBool(&c.AllowUnauthenticatedLocalhost, "CIRADAR_ALLOW_UNAUTHENTICATED_LOCALHOST")
	setBool(&c.DashboardEnabled, "CIRADAR_DASHBOARD_ENABLED")
	if v := strings.TrimSpace(os.Getenv("CIRADAR_TRUSTED_PROXY_CIDRS")); v != "" {
		c.TrustedProxyCIDRs = splitCSV(v)
	}
	setString(&c.DashboardSessionSecret, "CIRADAR_DASHBOARD_SESSION_SECRET")
	setBool(&c.DashboardCookieSecure, "CIRADAR_DASHBOARD_COOKIE_SECURE")
	setBool(&c.RedactionEntropyDetection, "CIRADAR_REDACTION_ENTROPY")
	setBool(&c.GitHubMarketplace.Enabled, "CIRADAR_MARKETPLACE_ENABLED")
	setString(&c.GitHubMarketplace.WebhookSecret, "CIRADAR_MARKETPLACE_WEBHOOK_SECRET")
	setBool(&c.SSO.Enabled, "CIRADAR_SSO_ENABLED")
	setString(&c.SSO.Mode, "CIRADAR_SSO_MODE")
	setString(&c.SSO.IssuerURL, "CIRADAR_SSO_ISSUER")
	setString(&c.SSO.ClientID, "CIRADAR_SSO_CLIENT_ID")
	setString(&c.SSO.ClientSecret, "CIRADAR_SSO_CLIENT_SECRET")
	setString(&c.SSO.RedirectURL, "CIRADAR_SSO_REDIRECT_URL")
	setString(&c.SSO.SessionSecret, "CIRADAR_SSO_SESSION_SECRET")
	setString(&c.SSO.SAMLXMLSecPath, "CIRADAR_SAML_XMLSEC_PATH")
	setString(&c.SSO.SAMLSecurityProfile, "CIRADAR_SAML_SECURITY_PROFILE")
	setBool(&c.LLM.Enabled, "CIRADAR_LLM_ENABLED")
	setString(&c.LLM.Provider, "CIRADAR_LLM_PROVIDER")
	setString(&c.LLM.Endpoint, "CIRADAR_LLM_ENDPOINT")
	setString(&c.LLM.APIKey, "CIRADAR_LLM_API_KEY")
	setString(&c.LLM.Model, "CIRADAR_LLM_MODEL")
	setString(&c.LLM.DataPolicy, "CIRADAR_LLM_DATA_POLICY")
	setBool(&c.LLM.SendSourceCode, "CIRADAR_LLM_SEND_SOURCE_CODE")
	setInt(&c.LLM.MaxSourceFiles, "CIRADAR_LLM_MAX_SOURCE_FILES")
	setInt(&c.LLM.MaxSourceFileCharacters, "CIRADAR_LLM_MAX_SOURCE_FILE_CHARACTERS")
	setBool(&c.LLM.BlockOnResidualSecret, "CIRADAR_LLM_BLOCK_ON_REDACTION_RISK")
	setBool(&c.LLM.AllowRemoteSourceCode, "CIRADAR_LLM_ALLOW_REMOTE_SOURCE_CODE")
	setBool(&c.LLM.AllowPrivateNetwork, "CIRADAR_LLM_ALLOW_PRIVATE_NETWORK")
	setBool(&c.ChatOps.Enabled, "CIRADAR_CHATOPS_ENABLED")
	setString(&c.ChatOps.SlackSigningSecret, "CIRADAR_SLACK_SIGNING_SECRET")
	setString(&c.ChatOps.TeamsSigningSecret, "CIRADAR_TEAMS_SIGNING_SECRET")
	setInt(&c.RetentionDays, "CIRADAR_RETENTION_DAYS")
	setInt(&c.WorkerCount, "CIRADAR_WORKERS")
	setInt(&c.IncidentRepoThreshold, "CIRADAR_INCIDENT_REPO_THRESHOLD")
	setInt(&c.IncidentOrgThreshold, "CIRADAR_INCIDENT_ORG_THRESHOLD")
	setInt(&c.AutomaticRetryMinScore, "CIRADAR_AUTO_RETRY_MIN_SCORE")
	if v := strings.TrimSpace(os.Getenv("CIRADAR_GITHUB_APP_ID")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			c.GitHubAppID = n
		}
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func setString(dst *string, key string) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		*dst = v
	}
}
func setBool(dst *bool, key string) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}
func setInt(dst *int, key string) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}
