package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type SSOConfig struct {
	Enabled             bool          `json:"enabled"`
	Mode                string        `json:"mode"`
	IssuerURL           string        `json:"issuer_url,omitempty"`
	ClientID            string        `json:"client_id,omitempty"`
	ClientSecret        string        `json:"client_secret,omitempty"`
	RedirectURL         string        `json:"redirect_url,omitempty"`
	Scopes              []string      `json:"scopes,omitempty"`
	AllowedDomains      []string      `json:"allowed_domains,omitempty"`
	TenantClaim         string        `json:"tenant_claim,omitempty"`
	RoleClaim           string        `json:"role_claim,omitempty"`
	GroupsClaim         string        `json:"groups_claim,omitempty"`
	AdminGroups         []string      `json:"admin_groups,omitempty"`
	OperatorGroups      []string      `json:"operator_groups,omitempty"`
	ViewerGroups        []string      `json:"viewer_groups,omitempty"`
	DefaultTenant       string        `json:"default_tenant,omitempty"`
	DefaultRole         string        `json:"default_role,omitempty"`
	SessionSecret       string        `json:"session_secret,omitempty"`
	CookieName          string        `json:"cookie_name,omitempty"`
	CookieSecure        bool          `json:"cookie_secure"`
	TrustedProxyCIDRs   []string      `json:"trusted_proxy_cidrs,omitempty"`
	ProxySecretHeader   string        `json:"proxy_secret_header,omitempty"`
	ProxySecret         string        `json:"proxy_secret,omitempty"`
	ProxySubjectHeader  string        `json:"proxy_subject_header,omitempty"`
	ProxyEmailHeader    string        `json:"proxy_email_header,omitempty"`
	ProxyNameHeader     string        `json:"proxy_name_header,omitempty"`
	ProxyGroupsHeader   string        `json:"proxy_groups_header,omitempty"`
	ProxyTenantHeader   string        `json:"proxy_tenant_header,omitempty"`
	ProxyRoleHeader     string        `json:"proxy_role_header,omitempty"`
	SAMLEntityID        string        `json:"saml_entity_id,omitempty"`
	SAMLIdPSSOURL       string        `json:"saml_idp_sso_url,omitempty"`
	SAMLIdPEntityID     string        `json:"saml_idp_entity_id,omitempty"`
	SAMLIdPCertificate  string        `json:"saml_idp_certificate,omitempty"`
	SAMLACSURL          string        `json:"saml_acs_url,omitempty"`
	SAMLXMLSecPath      string        `json:"saml_xmlsec_path,omitempty"`
	SAMLXMLSecSHA256    string        `json:"saml_xmlsec_sha256,omitempty"`
	SAMLSecurityProfile string        `json:"saml_security_profile,omitempty"`
	SAMLNameAttribute   string        `json:"saml_name_attribute,omitempty"`
	SAMLEmailAttribute  string        `json:"saml_email_attribute,omitempty"`
	SAMLClockSkewText   string        `json:"saml_clock_skew,omitempty"`
	SAMLClockSkew       time.Duration `json:"-"`
	AllowPrivateNetwork bool          `json:"allow_private_network,omitempty"`
}

type LLMConfig struct {
	Enabled                 bool          `json:"enabled"`
	Provider                string        `json:"provider,omitempty"`
	Endpoint                string        `json:"endpoint,omitempty"`
	APIKey                  string        `json:"api_key,omitempty"`
	Model                   string        `json:"model,omitempty"`
	EmbeddingsEndpoint      string        `json:"embeddings_endpoint,omitempty"`
	EmbeddingModel          string        `json:"embedding_model,omitempty"`
	AutoEnhance             bool          `json:"auto_enhance"`
	MinimumScore            int           `json:"minimum_score,omitempty"`
	MaxInputCharacters      int           `json:"max_input_characters,omitempty"`
	MaxOutputTokens         int           `json:"max_output_tokens,omitempty"`
	TimeoutText             string        `json:"timeout,omitempty"`
	Timeout                 time.Duration `json:"-"`
	SendRedactedExcerpt     bool          `json:"send_redacted_excerpt"`
	SendChangedFiles        bool          `json:"send_changed_files"`
	SendSourceCode          bool          `json:"send_source_code"`
	MaxSourceFiles          int           `json:"max_source_files,omitempty"`
	MaxSourceFileCharacters int           `json:"max_source_file_characters,omitempty"`
	DataPolicy              string        `json:"data_policy,omitempty"`
	BlockOnResidualSecret   bool          `json:"block_on_residual_secret"`
	AllowRemoteSourceCode   bool          `json:"allow_remote_source_code"`
	AllowPrivateNetwork     bool          `json:"allow_private_network,omitempty"`
}

type RepairConfig struct {
	Enabled      bool   `json:"enabled"`
	AutoDraftPR  bool   `json:"auto_draft_pr"`
	MinimumScore int    `json:"minimum_score,omitempty"`
	BranchPrefix string `json:"branch_prefix,omitempty"`
	MaximumFiles int    `json:"maximum_files,omitempty"`
	MaximumLines int    `json:"maximum_lines,omitempty"`
}

type ChatOpsConfig struct {
	Enabled            bool              `json:"enabled"`
	DefaultTenant      string            `json:"default_tenant,omitempty"`
	SlackSigningSecret string            `json:"slack_signing_secret,omitempty"`
	SlackAllowedUsers  []string          `json:"slack_allowed_users,omitempty"`
	SlackAllowedTeams  []string          `json:"slack_allowed_teams,omitempty"`
	SlackTeamTenants   map[string]string `json:"slack_team_tenants,omitempty"`
	TeamsSigningSecret string            `json:"teams_signing_secret,omitempty"`
	TeamsAllowedUsers  []string          `json:"teams_allowed_users,omitempty"`
	AllowAcknowledge   bool              `json:"allow_acknowledge"`
	AllowResolve       bool              `json:"allow_resolve"`
	AllowQuarantine    bool              `json:"allow_quarantine"`
	QuarantineDuration string            `json:"quarantine_duration,omitempty"`
}

type CostConfig struct {
	Enabled       bool               `json:"enabled"`
	Currency      string             `json:"currency,omitempty"`
	DefaultRates  map[string]float64 `json:"default_rates,omitempty"`
	RunnerRates   map[string]float64 `json:"runner_rates,omitempty"`
	BillingRounds map[string]int     `json:"billing_rounds,omitempty"`
}

type SemanticConfig struct {
	Enabled          bool   `json:"enabled"`
	Mode             string `json:"mode,omitempty"`
	RemoteEmbeddings bool   `json:"remote_embeddings"`
	VectorDimensions int    `json:"vector_dimensions,omitempty"`
	CandidateLimit   int    `json:"candidate_limit,omitempty"`
	LocalEndpoint    string `json:"local_endpoint,omitempty"`
	LocalModel       string `json:"local_model,omitempty"`
	LocalAPIKey      string `json:"local_api_key,omitempty"`
	LocalVectorPath  string `json:"local_vector_path,omitempty"`
}

type PredictiveTestConfig struct {
	Enabled         bool    `json:"enabled"`
	DefaultLimit    int     `json:"default_limit,omitempty"`
	MinimumScore    float64 `json:"minimum_score,omitempty"`
	AlwaysRunFlaky  bool    `json:"always_run_flaky"`
	AlwaysRunFailed bool    `json:"always_run_failed"`
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
		case "saml":
			if c.SSO.SAMLEntityID == "" || c.SSO.SAMLIdPSSOURL == "" || c.SSO.SAMLIdPEntityID == "" || c.SSO.SAMLIdPCertificate == "" || c.SSO.SAMLACSURL == "" {
				return errors.New("sso saml requires saml_entity_id, saml_idp_sso_url, saml_idp_entity_id, saml_idp_certificate, and saml_acs_url")
			}
			for label, raw := range map[string]string{"saml_idp_sso_url": c.SSO.SAMLIdPSSOURL, "saml_acs_url": c.SSO.SAMLACSURL} {
				parsed, parseErr := url.Parse(raw)
				if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
					return fmt.Errorf("%s must be an absolute HTTPS URL without embedded credentials", label)
				}
			}
			if c.SSO.SAMLXMLSecPath == "" || !filepath.IsAbs(c.SSO.SAMLXMLSecPath) {
				return errors.New("sso saml requires an absolute saml_xmlsec_path to a pinned xmlsec1 executable")
			}
			resolvedXMLSec, resolveErr := filepath.EvalSymlinks(c.SSO.SAMLXMLSecPath)
			if resolveErr != nil {
				return fmt.Errorf("resolve saml_xmlsec_path: %w", resolveErr)
			}
			info, statErr := os.Stat(resolvedXMLSec)
			if statErr != nil {
				return fmt.Errorf("stat saml_xmlsec_path: %w", statErr)
			}
			if !info.Mode().IsRegular() {
				return errors.New("saml_xmlsec_path is not a regular file")
			}
			if _, lookupErr := exec.LookPath(resolvedXMLSec); lookupErr != nil {
				return fmt.Errorf("saml_xmlsec_path is not executable: %w", lookupErr)
			}
			wantedXMLSecHash := strings.ToLower(strings.TrimSpace(c.SSO.SAMLXMLSecSHA256))
			if len(wantedXMLSecHash) != sha256.Size*2 {
				return errors.New("sso saml requires saml_xmlsec_sha256 for executable integrity pinning")
			}
			if _, decodeErr := hex.DecodeString(wantedXMLSecHash); decodeErr != nil {
				return errors.New("saml_xmlsec_sha256 must be a 64-character hexadecimal SHA-256 digest")
			}
			actualXMLSecHash, hashErr := fileSHA256Hex(resolvedXMLSec)
			if hashErr != nil {
				return fmt.Errorf("hash saml_xmlsec_path: %w", hashErr)
			}
			if actualXMLSecHash != wantedXMLSecHash {
				return errors.New("saml_xmlsec_path SHA-256 does not match saml_xmlsec_sha256")
			}
			c.SSO.SAMLXMLSecPath = resolvedXMLSec
			c.SSO.SAMLXMLSecSHA256 = wantedXMLSecHash
			if !strings.Contains(c.SSO.SAMLIdPCertificate, "BEGIN CERTIFICATE") && !filepath.IsAbs(c.SSO.SAMLIdPCertificate) {
				return errors.New("saml_idp_certificate must contain PEM data or use an absolute file path")
			}
			if err := validateSAMLSigningCertificate(c.SSO.SAMLIdPCertificate, time.Now().UTC()); err != nil {
				return err
			}
			c.SSO.SAMLSecurityProfile = strings.ToLower(strings.TrimSpace(c.SSO.SAMLSecurityProfile))
			if c.SSO.SAMLSecurityProfile == "" {
				c.SSO.SAMLSecurityProfile = "strict"
			}
			if c.SSO.SAMLSecurityProfile != "strict" && c.SSO.SAMLSecurityProfile != "compatibility" {
				return fmt.Errorf("unsupported saml_security_profile %q", c.SSO.SAMLSecurityProfile)
			}
			if c.SSO.SAMLEmailAttribute == "" {
				c.SSO.SAMLEmailAttribute = "email"
			}
			if c.SSO.SAMLNameAttribute == "" {
				c.SSO.SAMLNameAttribute = "name"
			}
			if c.SSO.SAMLClockSkewText == "" {
				c.SSO.SAMLClockSkewText = "2m"
			}
			d, e := time.ParseDuration(c.SSO.SAMLClockSkewText)
			if e != nil || d < 0 || d > 10*time.Minute {
				return fmt.Errorf("invalid saml_clock_skew %q", c.SSO.SAMLClockSkewText)
			}
			c.SSO.SAMLClockSkew = d
		default:
			return fmt.Errorf("unsupported sso mode %q", c.SSO.Mode)
		}
	}
	c.LLM.DataPolicy = strings.ToLower(strings.TrimSpace(c.LLM.DataPolicy))
	if c.LLM.DataPolicy == "" {
		c.LLM.DataPolicy = "local_only"
	}
	switch c.LLM.DataPolicy {
	case "local_only", "redacted_remote", "metadata_only":
	default:
		return fmt.Errorf("unsupported llm data_policy %q", c.LLM.DataPolicy)
	}
	c.LLM.Provider = strings.ToLower(strings.TrimSpace(c.LLM.Provider))
	if c.LLM.Provider == "" {
		c.LLM.Provider = "openai-compatible"
	}
	switch c.LLM.Provider {
	case "openai", "openai-compatible", "anthropic":
	default:
		return fmt.Errorf("unsupported llm provider %q", c.LLM.Provider)
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
	if c.LLM.MaxSourceFiles < 1 || c.LLM.MaxSourceFiles > 20 {
		c.LLM.MaxSourceFiles = 8
	}
	if c.LLM.MaxSourceFileCharacters < 1000 || c.LLM.MaxSourceFileCharacters > 100000 {
		c.LLM.MaxSourceFileCharacters = 32000
	}
	if c.LLM.TimeoutText == "" {
		c.LLM.TimeoutText = "45s"
	}
	d, err := time.ParseDuration(c.LLM.TimeoutText)
	if err != nil || d <= 0 || d > 5*time.Minute {
		return fmt.Errorf("invalid llm timeout %q", c.LLM.TimeoutText)
	}
	c.LLM.Timeout = d
	if c.LLM.Enabled && c.LLM.Endpoint == "" {
		return errors.New("llm requires endpoint")
	}
	if c.LLM.Enabled {
		parsedEndpoint, parseErr := url.Parse(c.LLM.Endpoint)
		if parseErr != nil || parsedEndpoint.Host == "" || parsedEndpoint.User != nil || (parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https") {
			return errors.New("llm endpoint must be an absolute HTTP or HTTPS URL without embedded credentials")
		}
		if !isLoopbackEndpoint(c.LLM.Endpoint) && parsedEndpoint.Scheme != "https" {
			return errors.New("remote llm endpoint must use HTTPS")
		}
	}
	if c.LLM.Enabled && c.LLM.Provider != "anthropic" && strings.Contains(strings.ToLower(c.LLM.Endpoint), "anthropic.com") {
		return errors.New("anthropic endpoints require llm provider anthropic; the OpenAI compatibility layer is not accepted for production configuration")
	}
	if c.LLM.Enabled && c.LLM.DataPolicy == "local_only" && !isLoopbackEndpoint(c.LLM.Endpoint) {
		return errors.New("llm data_policy local_only requires a loopback endpoint; use redacted_remote or metadata_only only after an explicit data review")
	}
	if c.LLM.DataPolicy == "metadata_only" {
		c.LLM.SendRedactedExcerpt = false
		c.LLM.SendChangedFiles = false
		c.LLM.SendSourceCode = false
	}
	if c.LLM.Enabled && c.LLM.DataPolicy == "redacted_remote" && !c.LLM.BlockOnResidualSecret {
		return errors.New("llm data_policy redacted_remote requires block_on_residual_secret=true")
	}
	if c.LLM.Enabled && c.LLM.DataPolicy == "redacted_remote" && c.LLM.SendSourceCode && !c.LLM.AllowRemoteSourceCode {
		return errors.New("remote source-code transmission requires llm.allow_remote_source_code=true after an explicit data review")
	}
	if c.Repair.MinimumScore < 0 || c.Repair.MinimumScore > 100 {
		c.Repair.MinimumScore = 60
	}
	if c.Repair.BranchPrefix == "" {
		c.Repair.BranchPrefix = "ciradar/repair-"
	}
	if strings.Contains(c.Repair.BranchPrefix, "..") || strings.HasPrefix(c.Repair.BranchPrefix, "/") {
		return errors.New("repair branch_prefix is invalid")
	}
	if c.Repair.MaximumFiles < 1 || c.Repair.MaximumFiles > 25 {
		c.Repair.MaximumFiles = 10
	}
	if c.Repair.MaximumLines < 1 || c.Repair.MaximumLines > 5000 {
		c.Repair.MaximumLines = 1000
	}
	if c.Repair.AutoDraftPR && (!c.Repair.Enabled || !c.LLM.Enabled) {
		return errors.New("repair auto_draft_pr requires repair.enabled and llm.enabled")
	}
	if c.ChatOps.DefaultTenant == "" {
		c.ChatOps.DefaultTenant = c.DefaultTenantID
	}
	if c.ChatOps.QuarantineDuration == "" {
		c.ChatOps.QuarantineDuration = "7d"
	}
	if c.ChatOps.SlackTeamTenants == nil {
		c.ChatOps.SlackTeamTenants = map[string]string{}
	}
	normalizedSlackTeams := make(map[string]string, len(c.ChatOps.SlackTeamTenants))
	for rawTeam, rawTenant := range c.ChatOps.SlackTeamTenants {
		team := strings.TrimSpace(rawTeam)
		tenant := strings.ToLower(strings.TrimSpace(rawTenant))
		if team == "" || tenant == "" {
			return errors.New("chatops slack_team_tenants requires non-empty team and tenant ids")
		}
		if existing, ok := normalizedSlackTeams[strings.ToLower(team)]; ok && existing != tenant {
			return fmt.Errorf("chatops Slack team %q is mapped to multiple tenants", team)
		}
		normalizedSlackTeams[strings.ToLower(team)] = tenant
	}
	c.ChatOps.SlackTeamTenants = normalizedSlackTeams
	if c.ChatOps.Enabled {
		if c.ChatOps.SlackSigningSecret == "" && c.ChatOps.TeamsSigningSecret == "" {
			return errors.New("chatops requires a Slack or Teams signing secret")
		}
		if c.ChatOps.SlackSigningSecret != "" {
			if len(c.ChatOps.SlackAllowedUsers) == 0 && len(c.ChatOps.SlackAllowedTeams) == 0 {
				return errors.New("chatops Slack requires slack_allowed_users or slack_allowed_teams")
			}
			if len(c.ChatOps.SlackTeamTenants) == 0 {
				return errors.New("chatops Slack requires explicit slack_team_tenants bindings")
			}
			for _, rawTeam := range c.ChatOps.SlackAllowedTeams {
				team := strings.ToLower(strings.TrimSpace(rawTeam))
				if team == "" {
					return errors.New("chatops slack_allowed_teams contains an empty team id")
				}
				if _, ok := c.ChatOps.SlackTeamTenants[team]; !ok {
					return fmt.Errorf("chatops Slack team %q has no tenant binding", rawTeam)
				}
			}
		}
		if c.ChatOps.TeamsSigningSecret != "" && len(c.ChatOps.TeamsAllowedUsers) == 0 {
			return errors.New("chatops Teams requires teams_allowed_users")
		}
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
	c.Semantic.Mode = strings.ToLower(strings.TrimSpace(c.Semantic.Mode))
	if c.Semantic.Mode == "" {
		if c.Semantic.RemoteEmbeddings {
			c.Semantic.Mode = "remote"
		} else if c.Semantic.LocalEndpoint != "" {
			c.Semantic.Mode = "ollama"
		} else if c.Semantic.LocalVectorPath != "" {
			c.Semantic.Mode = "local-vectors"
		} else if c.Semantic.Enabled {
			c.Semantic.Mode = "ollama"
		} else {
			c.Semantic.Mode = "lexical"
		}
	}
	if c.Semantic.Mode == "local-hash" {
		c.Semantic.Mode = "lexical"
	}
	switch c.Semantic.Mode {
	case "lexical", "local-vectors", "ollama", "remote":
	default:
		return fmt.Errorf("unsupported semantic mode %q", c.Semantic.Mode)
	}
	if c.Semantic.Mode == "local-vectors" && strings.TrimSpace(c.Semantic.LocalVectorPath) == "" {
		return errors.New("semantic local-vectors mode requires local_vector_path")
	}
	if c.Semantic.Mode == "ollama" {
		if c.Semantic.LocalEndpoint == "" {
			c.Semantic.LocalEndpoint = "http://127.0.0.1:11434/api/embed"
		}
		if c.Semantic.LocalModel == "" {
			c.Semantic.LocalModel = "embeddinggemma"
		}
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

func validateSAMLSigningCertificate(raw string, now time.Time) error {
	content := []byte(raw)
	if !strings.Contains(raw, "BEGIN CERTIFICATE") {
		read, err := os.ReadFile(raw)
		if err != nil {
			return fmt.Errorf("read saml_idp_certificate: %w", err)
		}
		content = read
	}
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("saml_idp_certificate must contain a valid PEM certificate")
	}
	for len(strings.TrimSpace(string(rest))) > 0 {
		next, remaining := pem.Decode(rest)
		if next == nil || next.Type != "CERTIFICATE" {
			return errors.New("saml_idp_certificate contains unsupported trailing data")
		}
		rest = remaining
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse saml_idp_certificate: %w", err)
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("saml_idp_certificate is not currently valid")
	}
	if certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("saml_idp_certificate does not permit digital signatures")
	}
	return nil
}

func isLoopbackEndpoint(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
