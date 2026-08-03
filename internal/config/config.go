package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddress            string        `json:"listen_address"`
	DatabasePath             string        `json:"database_path"`
	DataDirectory            string        `json:"data_directory"`
	RulesDirectory           string        `json:"rules_directory"`
	LogLevel                 string        `json:"log_level"`
	RetentionDays            int           `json:"retention_days"`
	StoreRedactedExcerpts    bool          `json:"store_redacted_excerpts"`
	StoreRawLogs             bool          `json:"store_raw_logs"`
	CrossRepositorySharing   bool          `json:"cross_repository_sharing"`
	IncidentWindow           time.Duration `json:"-"`
	IncidentWindowText       string        `json:"incident_window"`
	IncidentRepoThreshold    int           `json:"incident_repo_threshold"`
	IncidentOrgThreshold     int           `json:"incident_org_threshold"`
	WorkerCount              int           `json:"worker_count"`
	MaxLogBytes              int64         `json:"max_log_bytes"`
	ProviderPolling          bool          `json:"provider_polling"`
	ProviderPollInterval     time.Duration `json:"-"`
	ProviderPollIntervalText string        `json:"provider_poll_interval"`
	AutomaticRetryEnabled    bool          `json:"automatic_retry_enabled"`
	AutomaticRetryMinScore   int           `json:"automatic_retry_min_score"`
	GitHubAppID              int64         `json:"github_app_id"`
	GitHubPrivateKeyPath     string        `json:"github_private_key_path"`
	GitHubWebhookSecret      string        `json:"github_webhook_secret"`
	GitHubAPIURL             string        `json:"github_api_url"`
	PublicBaseURL            string        `json:"public_base_url"`
	FingerprintHMACKey       string        `json:"fingerprint_hmac_key"`
	AdminToken               string        `json:"admin_token"`
}

func Default() Config {
	dataDir := ".ciradar"
	return Config{
		ListenAddress:            "127.0.0.1:8787",
		DatabasePath:             filepath.Join(dataDir, "ciradar-state.json"),
		DataDirectory:            dataDir,
		RulesDirectory:           "rules",
		LogLevel:                 "info",
		RetentionDays:            30,
		StoreRedactedExcerpts:    true,
		StoreRawLogs:             false,
		CrossRepositorySharing:   false,
		IncidentWindowText:       "15m",
		IncidentWindow:           15 * time.Minute,
		IncidentRepoThreshold:    3,
		IncidentOrgThreshold:     2,
		WorkerCount:              2,
		MaxLogBytes:              32 << 20,
		ProviderPolling:          true,
		ProviderPollIntervalText: "2m",
		ProviderPollInterval:     2 * time.Minute,
		AutomaticRetryEnabled:    false,
		AutomaticRetryMinScore:   85,
		GitHubAPIURL:             "https://api.github.com",
	}
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
	if err := cfg.normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) normalize() error {
	if c.DataDirectory == "" {
		c.DataDirectory = ".ciradar"
	}
	if c.RulesDirectory == "" {
		c.RulesDirectory = "rules"
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
	if c.WorkerCount < 1 {
		c.WorkerCount = 1
	}
	if c.WorkerCount > 32 {
		c.WorkerCount = 32
	}
	if c.MaxLogBytes < 1024 {
		c.MaxLogBytes = 32 << 20
	}
	if c.GitHubAPIURL == "" {
		c.GitHubAPIURL = "https://api.github.com"
	}
	return nil
}

func SaveDefault(path string) error {
	cfg := Default()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (c Config) GitHubConfigured() bool {
	return c.GitHubAppID > 0 && c.GitHubPrivateKeyPath != "" && c.GitHubWebhookSecret != ""
}

func applyEnv(c *Config) {
	setString(&c.ListenAddress, "CIRADAR_LISTEN")
	setString(&c.DatabasePath, "CIRADAR_DATABASE")
	setString(&c.DataDirectory, "CIRADAR_DATA_DIR")
	setString(&c.RulesDirectory, "CIRADAR_RULES_DIR")
	setString(&c.LogLevel, "CIRADAR_LOG_LEVEL")
	setString(&c.GitHubPrivateKeyPath, "CIRADAR_GITHUB_PRIVATE_KEY")
	setString(&c.GitHubWebhookSecret, "CIRADAR_GITHUB_WEBHOOK_SECRET")
	setString(&c.GitHubAPIURL, "CIRADAR_GITHUB_API_URL")
	setString(&c.PublicBaseURL, "CIRADAR_PUBLIC_BASE_URL")
	setString(&c.FingerprintHMACKey, "CIRADAR_FINGERPRINT_KEY")
	setString(&c.AdminToken, "CIRADAR_ADMIN_TOKEN")
	setString(&c.IncidentWindowText, "CIRADAR_INCIDENT_WINDOW")
	setString(&c.ProviderPollIntervalText, "CIRADAR_PROVIDER_POLL_INTERVAL")
	setBool(&c.StoreRawLogs, "CIRADAR_STORE_RAW_LOGS")
	setBool(&c.CrossRepositorySharing, "CIRADAR_CROSS_REPO_SHARING")
	setBool(&c.ProviderPolling, "CIRADAR_PROVIDER_POLLING")
	setBool(&c.AutomaticRetryEnabled, "CIRADAR_AUTO_RETRY")
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
