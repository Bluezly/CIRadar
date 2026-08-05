package marketplace

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

type Account struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

type Plan struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type Purchase struct {
	Account         Account `json:"account"`
	Plan            Plan    `json:"plan"`
	UnitCount       int     `json:"unit_count"`
	OnFreeTrial     bool    `json:"on_free_trial"`
	BillingCycle    string  `json:"billing_cycle"`
	NextBillingDate string  `json:"next_billing_date"`
}

type Payload struct {
	Action              string   `json:"action"`
	EffectiveDate       string   `json:"effective_date"`
	MarketplacePurchase Purchase `json:"marketplace_purchase"`
	Installation        struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

type Subscription struct {
	AccountID          int64     `json:"account_id"`
	AccountLogin       string    `json:"account_login"`
	AccountType        string    `json:"account_type"`
	TenantID           string    `json:"tenant_id"`
	InstallationID     int64     `json:"installation_id,omitempty"`
	PlanID             int64     `json:"plan_id"`
	PlanName           string    `json:"plan_name"`
	Status             string    `json:"status"`
	UnitCount          int       `json:"unit_count"`
	OnFreeTrial        bool      `json:"on_free_trial"`
	BillingCycle       string    `json:"billing_cycle,omitempty"`
	EffectiveAt        time.Time `json:"effective_at"`
	NextBillingDate    time.Time `json:"next_billing_date,omitempty"`
	PendingAction      string    `json:"pending_action,omitempty"`
	PendingPlanID      int64     `json:"pending_plan_id,omitempty"`
	PendingPlanName    string    `json:"pending_plan_name,omitempty"`
	PendingEffectiveAt time.Time `json:"pending_effective_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type Service struct {
	cfg   config.MarketplaceConfig
	store db.Backend
}

// PayloadError identifies a webhook payload that the sender must correct.
// Storage and other operational failures intentionally remain unwrapped so
// the HTTP layer can return a retryable 5xx response instead of a misleading
// 4xx response.
type PayloadError struct {
	Err error
}

func (e *PayloadError) Error() string { return e.Err.Error() }
func (e *PayloadError) Unwrap() error { return e.Err }

// PostCommitError reports a failure that occurred after the subscription was
// persisted. Retrying the webhook as though nothing was applied could produce
// duplicate side effects, so callers should acknowledge the delivery while
// surfacing the warning operationally.
type PostCommitError struct {
	Err error
}

func (e *PostCommitError) Error() string { return e.Err.Error() }
func (e *PostCommitError) Unwrap() error { return e.Err }

func payloadErrorf(format string, args ...any) error {
	return &PayloadError{Err: fmt.Errorf(format, args...)}
}

var tenantCleaner = regexp.MustCompile(`[^a-z0-9_-]+`)

func New(cfg config.MarketplaceConfig, store db.Backend) *Service {
	return &Service{cfg: cfg, store: store}
}

func (s *Service) Handle(ctx context.Context, raw []byte) (Subscription, error) {
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return Subscription{}, payloadErrorf("decode marketplace payload: %w", err)
	}
	action := strings.ToLower(strings.TrimSpace(payload.Action))
	switch action {
	case "purchased", "cancelled", "changed", "pending_change", "pending_change_cancelled":
	default:
		return Subscription{}, payloadErrorf("unsupported marketplace action %q", action)
	}
	purchase := payload.MarketplacePurchase
	if purchase.Account.ID <= 0 || strings.TrimSpace(purchase.Account.Login) == "" {
		return Subscription{}, payloadErrorf("marketplace account is missing")
	}
	now := time.Now().UTC()
	effective, err := parseDateField("effective_date", payload.EffectiveDate, now)
	if err != nil {
		return Subscription{}, &PayloadError{Err: err}
	}
	nextBilling, err := parseDateField("next_billing_date", purchase.NextBillingDate, time.Time{})
	if err != nil {
		return Subscription{}, &PayloadError{Err: err}
	}
	id := strconv.FormatInt(purchase.Account.ID, 10)
	var existing Subscription
	found, err := s.store.GetObject(ctx, model.DefaultTenantID, "marketplace_account_index", id, &existing)
	if err != nil {
		return Subscription{}, err
	}
	tenantID := existing.TenantID
	if payload.Installation.ID > 0 {
		if bound, ok := s.store.ResolveInstallationTenant(ctx, payload.Installation.ID); ok {
			tenantID = bound
		}
	}
	if tenantID == "" {
		if !s.cfg.AutoCreateTenant {
			return Subscription{}, fmt.Errorf("marketplace account is not linked to a tenant")
		}
		tenantID = tenantIDFor(purchase.Account.Login, purchase.Account.ID)
		tenant, err := s.store.GetTenant(ctx, tenantID)
		if err != nil {
			return Subscription{}, fmt.Errorf("check marketplace tenant: %w", err)
		}
		if tenant == nil {
			if _, err := s.store.CreateTenant(ctx, tenantID, purchase.Account.Login); err != nil {
				return Subscription{}, err
			}
		}
	}
	if payload.Installation.ID > 0 {
		if err := s.store.BindInstallation(ctx, tenantID, payload.Installation.ID); err != nil {
			return Subscription{}, err
		}
	}
	if found && !existing.EffectiveAt.IsZero() && effective.Before(existing.EffectiveAt) {
		return existing, nil
	}
	base := existing
	if !found || action == "purchased" || action == "changed" {
		base = Subscription{AccountID: purchase.Account.ID, AccountLogin: purchase.Account.Login, AccountType: purchase.Account.Type, TenantID: tenantID, InstallationID: payload.Installation.ID, PlanID: purchase.Plan.ID, PlanName: strings.TrimSpace(purchase.Plan.Name), Status: "active", UnitCount: purchase.UnitCount, OnFreeTrial: purchase.OnFreeTrial, BillingCycle: purchase.BillingCycle, EffectiveAt: effective, NextBillingDate: nextBilling}
	}
	sub := base
	sub.AccountID = purchase.Account.ID
	sub.AccountLogin = purchase.Account.Login
	sub.AccountType = purchase.Account.Type
	sub.TenantID = tenantID
	if payload.Installation.ID > 0 {
		sub.InstallationID = payload.Installation.ID
	}
	sub.UpdatedAt = now
	if sub.PlanName == "" {
		sub.PlanName = s.cfg.FreePlanName
	}
	switch action {
	case "cancelled":
		sub.EffectiveAt = effective
		sub.PendingAction = ""
		sub.PendingPlanID = 0
		sub.PendingPlanName = ""
		sub.PendingEffectiveAt = time.Time{}
		if s.cfg.CancellationPolicy == "disable_tenant" {
			sub.Status = "cancelled"
			if err := s.store.SetTenantEnabled(ctx, tenantID, false); err != nil {
				return Subscription{}, err
			}
		} else {
			sub.Status = "free"
			sub.PlanName = s.cfg.FreePlanName
			sub.PlanID = 0
			sub.UnitCount = 0
			sub.OnFreeTrial = false
			sub.NextBillingDate = time.Time{}
		}
	case "pending_change":
		sub.Status = "active"
		sub.PendingAction = action
		sub.PendingPlanID = purchase.Plan.ID
		sub.PendingPlanName = strings.TrimSpace(purchase.Plan.Name)
		sub.PendingEffectiveAt = effective
	case "pending_change_cancelled":
		sub.Status = "active"
		sub.PendingAction = ""
		sub.PendingPlanID = 0
		sub.PendingPlanName = ""
		sub.PendingEffectiveAt = time.Time{}
	}
	if err := s.store.PutObject(ctx, tenantID, "marketplace_subscription", id, sub); err != nil {
		return Subscription{}, err
	}
	if err := s.store.PutObject(ctx, model.DefaultTenantID, "marketplace_account_index", id, sub); err != nil {
		return Subscription{}, err
	}
	if err := s.store.RecordAudit(ctx, model.AuditEvent{TenantID: tenantID, Actor: "github-marketplace", Role: model.RoleAdmin, Action: "marketplace." + action, Resource: "subscription", ResourceID: id, Metadata: map[string]string{"plan": sub.PlanName, "status": sub.Status}}); err != nil {
		return sub, &PostCommitError{Err: fmt.Errorf("marketplace subscription updated, but recording its audit event failed: %w", err)}
	}
	return sub, nil
}

func tenantIDFor(login string, accountID int64) string {
	value := strings.ToLower(strings.TrimSpace(login))
	value = tenantCleaner.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-_")
	if value == "" {
		value = "github"
	}
	suffix := strconv.FormatInt(accountID, 36)
	limit := 62 - len(suffix) - 1
	if limit < 1 {
		limit = 1
	}
	if len(value) > limit {
		value = value[:limit]
	}
	return value + "-" + suffix
}

func parseDateField(name, raw string, fallback time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%s is not a valid date: %q", name, raw)
}
