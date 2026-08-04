package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type SSOConfig struct {
	Enabled            bool     `json:"enabled"`
	Mode               string   `json:"mode"`
	IssuerURL          string   `json:"issuer_url,omitempty"`
	ClientID           string   `json:"client_id,omitempty"`
	ClientSecret       string   `json:"client_secret,omitempty"`
	RedirectURL        string   `json:"redirect_url,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	AllowedDomains     []string `json:"allowed_domains,omitempty"`
	TenantClaim        string   `json:"tenant_claim,omitempty"`
	RoleClaim          string   `json:"role_claim,omitempty"`
	GroupsClaim        string   `json:"groups_claim,omitempty"`
	AdminGroups        []string `json:"admin_groups,omitempty"`
	OperatorGroups     []string `json:"operator_groups,omitempty"`
	ViewerGroups       []string `json:"viewer_groups,omitempty"`
	DefaultTenant      string   `json:"default_tenant,omitempty"`
	DefaultRole        string   `json:"default_role,omitempty"`
	SessionSecret      string   `json:"session_secret,omitempty"`
	CookieName         string   `json:"cookie_name,omitempty"`
	CookieSecure       bool     `json:"cookie_secure"`
	TrustedProxyCIDRs  []string `json:"trusted_proxy_cidrs,omitempty"`
	ProxySecretHeader  string   `json:"proxy_secret_header,omitempty"`
	ProxySecret        string   `json:"proxy_secret,omitempty"`
	ProxySubjectHeader string   `json:"proxy_subject_header,omitempty"`
	ProxyEmailHeader   string   `json:"proxy_email_header,omitempty"`
	ProxyNameHeader    string   `json:"proxy_name_header,omitempty"`
	ProxyGroupsHeader  string   `json:"proxy_groups_header,omitempty"`
	ProxyTenantHeader  string   `json:"proxy_tenant_header,omitempty"`
	ProxyRoleHeader    string   `json:"proxy_role_header,omitempty"`
}

type LLMConfig struct {
	Enabled             bool          `json:"enabled"`
	Provider            string        `json:"provider,omitempty"`
	Endpoint            string        `json:"endpoint,omitempty"`
	APIKey              string        `json:"api_key,omitempty"`
	Model               string        `json:"model,omitempty"`
	EmbeddingsEndpoint  string        `json:"embeddings_endpoint,omitempty"`
	EmbeddingModel      string        `json:"embedding_model,omitempty"`
	AutoEnhance         bool          `json:"auto_enhance"`
	MinimumScore        int           `json:"minimum_score,omitempty"`
	MaxInputCharacters  int           `json:"max_input_characters,omitempty"`
	MaxOutputTokens     int           `json:"max_output_tokens,omitempty"`
	TimeoutText         string        `json:"timeout,omitempty"`
	Timeout             time.Duration `json:"-"`
	SendRedactedExcerpt bool          `json:"send_redacted_excerpt"`
	SendChangedFiles    bool          `json:"send_changed_files"`
}

type ChatOpsConfig struct {
	Enabled            bool     `json:"enabled"`
	DefaultTenant      string   `json:"default_tenant,omitempty"`
	SlackSigningSecret string   `json:"slack_signing_secret,omitempty"`
	SlackAllowedUsers  []string `json:"slack_allowed_users,omitempty"`
	SlackAllowedTeams  []string `json:"slack_allowed_teams,omitempty"`
	TeamsSigningSecret string   `json:"teams_signing_secret,omitempty"`
	TeamsAllowedUsers  []string `json:"teams_allowed_users,omitempty"`
	AllowAcknowledge   bool     `json:"allow_acknowledge"`
	AllowResolve       bool     `json:"allow_resolve"`
	AllowQuarantine    bool     `json:"allow_quarantine"`
	QuarantineDuration string   `json:"quarantine_duration,omitempty"`
}

type CostConfig struct {
	Enabled       bool               `json:"enabled"`
	Currency      string             `json:"currency,omitempty"`
	DefaultRates  map[string]float64 `json:"default_rates,omitempty"`
	RunnerRates   map[string]float64 `json:"runner_rates,omitempty"`
	BillingRounds map[string]int     `json:"billing_rounds,omitempty"`
}

type SemanticConfig struct {
	Enabled          bool `json:"enabled"`
	RemoteEmbeddings bool `json:"remote_embeddings"`
	VectorDimensions int  `json:"vector_dimensions,omitempty"`
	CandidateLimit   int  `json:"candidate_limit,omitempty"`
}

type PredictiveTestConfig struct {
	Enabled         bool    `json:"enabled"`
	DefaultLimit    int     `json:"default_limit,omitempty"`
	MinimumScore    float64 `json:"minimum_score,omitempty"`
	AlwaysRunFlaky  bool    `json:"always_run_flaky"`
	AlwaysRunFailed bool    `json:"always_run_failed"`
}

func (c *Config) normalizeEnterprise() error {
	c.SSO.Mode = strings.ToLower(strings.TrimSpace(c.SSO.Mode))
	if c.SSO.Mode == "" {
		c.SSO.Mode = "oidc"
	}
	if c.SSO.DefaultTenant == "" {
		c.SSO.DefaultTenant = c.DefaultTenantID
	}
	if c.SSO.DefaultRole == "" {
		c.SSO.DefaultRole = "viewer"
	}
	if c.SSO.CookieName == "" {
		c.SSO.CookieName = "ciradar_session"
	}
	if c.SSO.TenantClaim == "" {
		c.SSO.TenantClaim = "tenant_id"
	}
	if c.SSO.RoleClaim == "" {
		c.SSO.RoleClaim = "role"
	}
	if c.SSO.GroupsClaim == "" {
		c.SSO.GroupsClaim = "groups"
	}
	if c.SSO.ProxySecretHeader == "" {
		c.SSO.ProxySecretHeader = "X-CI-Radar-Proxy-Secret"
	}
	if c.SSO.ProxySubjectHeader == "" {
		c.SSO.ProxySubjectHeader = "X-Forwarded-User"
	}
	if c.SSO.ProxyEmailHeader == "" {
		c.SSO.ProxyEmailHeader = "X-Forwarded-Email"
	}
	if c.SSO.ProxyNameHeader == "" {
		c.SSO.ProxyNameHeader = "X-Forwarded-Name"
	}
	if c.SSO.ProxyGroupsHeader == "" {
		c.SSO.ProxyGroupsHeader = "X-Forwarded-Groups"
	}
	if c.SSO.ProxyTenantHeader == "" {
		c.SSO.ProxyTenantHeader = "X-Forwarded-Tenant"
	}
	if c.SSO.ProxyRoleHeader == "" {
		c.SSO.ProxyRoleHeader = "X-Forwarded-Role"
	}
	if len(c.SSO.Scopes) == 0 {
		c.SSO.Scopes = []string{"openid", "profile", "email"}
	}
	if c.SSO.Enabled {
		if len(strings.TrimSpace(c.SSO.SessionSecret)) < 32 {
			return errors.New("sso session_secret must contain at least 32 characters")
		}
		switch c.SSO.Mode {
		case "oidc":
			if c.SSO.IssuerURL == "" || c.SSO.ClientID == "" || c.SSO.RedirectURL == "" || c.SSO.SessionSecret == "" {
				return errors.New("sso oidc requires issuer_url, client_id, redirect_url, and session_secret")
			}
			if _, err := url.ParseRequestURI(c.SSO.IssuerURL); err != nil {
				return fmt.Errorf("invalid sso issuer_url: %w", err)
			}
		case "proxy", "saml_proxy":
			if len(c.SSO.TrustedProxyCIDRs) == 0 || c.SSO.ProxySecret == "" || c.SSO.SessionSecret == "" {
				return errors.New("sso proxy mode requires trusted_proxy_cidrs, proxy_secret, and session_secret")
			}
			for _, raw := range c.SSO.TrustedProxyCIDRs {
				if _, _, err := net.ParseCIDR(raw); err != nil {
					return fmt.Errorf("invalid trusted proxy cidr %q", raw)
				}
			}
		default:
			return fmt.Errorf("unsupported sso mode %q", c.SSO.Mode)
		}
	}
	if c.LLM.Provider == "" {
		c.LLM.Provider = "openai-compatible"
	}
	if c.LLM.Model == "" {
		c.LLM.Model = "gpt-5-mini"
	}
	if c.LLM.MinimumScore < 0 || c.LLM.MinimumScore > 100 {
		c.LLM.MinimumScore = 60
	}
	if c.LLM.MaxInputCharacters < 1000 {
		c.LLM.MaxInputCharacters = 24000
	}
	if c.LLM.MaxInputCharacters > 200000 {
		c.LLM.MaxInputCharacters = 200000
	}
	if c.LLM.MaxOutputTokens < 128 {
		c.LLM.MaxOutputTokens = 1200
	}
	if c.LLM.TimeoutText == "" {
		c.LLM.TimeoutText = "45s"
	}
	d, err := time.ParseDuration(c.LLM.TimeoutText)
	if err != nil || d <= 0 || d > 5*time.Minute {
		return fmt.Errorf("invalid llm timeout %q", c.LLM.TimeoutText)
	}
	c.LLM.Timeout = d
	if c.LLM.Enabled && (c.LLM.Endpoint == "" || c.LLM.APIKey == "") {
		return errors.New("llm requires endpoint and api_key")
	}
	if c.ChatOps.DefaultTenant == "" {
		c.ChatOps.DefaultTenant = c.DefaultTenantID
	}
	if c.ChatOps.QuarantineDuration == "" {
		c.ChatOps.QuarantineDuration = "7d"
	}
	if c.ChatOps.Enabled && c.ChatOps.SlackSigningSecret == "" && c.ChatOps.TeamsSigningSecret == "" {
		return errors.New("chatops requires a Slack or Teams signing secret")
	}
	if c.Costs.Currency == "" {
		c.Costs.Currency = "USD"
	}
	if c.Costs.DefaultRates == nil {
		c.Costs.DefaultRates = map[string]float64{}
	}
	if c.Costs.RunnerRates == nil {
		c.Costs.RunnerRates = map[string]float64{}
	}
	if c.Costs.BillingRounds == nil {
		c.Costs.BillingRounds = map[string]int{}
	}
	if c.Semantic.VectorDimensions < 32 {
		c.Semantic.VectorDimensions = 128
	}
	if c.Semantic.VectorDimensions > 1024 {
		c.Semantic.VectorDimensions = 1024
	}
	if c.Semantic.CandidateLimit < 10 {
		c.Semantic.CandidateLimit = 500
	}
	if c.Semantic.CandidateLimit > 10000 {
		c.Semantic.CandidateLimit = 10000
	}
	if c.PredictiveTests.DefaultLimit < 1 {
		c.PredictiveTests.DefaultLimit = 100
	}
	if c.PredictiveTests.DefaultLimit > 5000 {
		c.PredictiveTests.DefaultLimit = 5000
	}
	if c.PredictiveTests.MinimumScore <= 0 || c.PredictiveTests.MinimumScore > 100 {
		c.PredictiveTests.MinimumScore = 20
	}
	return nil
}
