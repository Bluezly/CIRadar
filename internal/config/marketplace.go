package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type MarketplaceConfig struct {
	Enabled            bool   `json:"enabled"`
	WebhookSecret      string `json:"webhook_secret,omitempty"`
	AutoCreateTenant   bool   `json:"auto_create_tenant"`
	CancellationPolicy string `json:"cancellation_policy,omitempty"`
	FreePlanName       string `json:"free_plan_name,omitempty"`
}

var marketplacePlanPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func (c *Config) normalizeHardening() error {
	for _, raw := range c.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("invalid trusted_proxy_cidrs entry %q", raw)
		}
	}
	if strings.TrimSpace(c.DashboardSessionSecret) == "" {
		for _, fallback := range []string{c.MasterKey, c.AdminToken, c.FingerprintHMACKey} {
			if strings.TrimSpace(fallback) != "" {
				c.DashboardSessionSecret = fallback
				break
			}
		}
	}
	if c.DashboardSessionSecret != "" && len(strings.TrimSpace(c.DashboardSessionSecret)) < 32 {
		return errors.New("dashboard_session_secret must contain at least 32 characters")
	}
	for _, raw := range c.RedactionPatterns {
		if strings.TrimSpace(raw) == "" {
			return errors.New("redaction_patterns cannot contain empty expressions")
		}
		if _, err := regexp.Compile(raw); err != nil {
			return fmt.Errorf("invalid redaction pattern %q: %w", raw, err)
		}
	}
	m := &c.GitHubMarketplace
	m.CancellationPolicy = strings.ToLower(strings.TrimSpace(m.CancellationPolicy))
	if m.CancellationPolicy == "" {
		m.CancellationPolicy = "retain_free"
	}
	if m.FreePlanName == "" {
		m.FreePlanName = "free"
	}
	if !marketplacePlanPattern.MatchString(m.FreePlanName) {
		return fmt.Errorf("invalid github_marketplace.free_plan_name %q", m.FreePlanName)
	}
	if m.CancellationPolicy != "retain_free" && m.CancellationPolicy != "disable_tenant" {
		return fmt.Errorf("unsupported github_marketplace.cancellation_policy %q", m.CancellationPolicy)
	}
	if m.Enabled && strings.TrimSpace(m.WebhookSecret) == "" && strings.TrimSpace(c.GitHubWebhookSecret) == "" {
		return errors.New("github marketplace requires webhook_secret or github_webhook_secret")
	}
	return nil
}
