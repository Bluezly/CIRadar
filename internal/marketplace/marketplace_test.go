package marketplace

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

func TestPurchaseCreatesTenantAndSubscription(t *testing.T) {
	store, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true, CancellationPolicy: "retain_free", FreePlanName: "free"}, store)
	raw := []byte(`{"action":"purchased","effective_date":"2026-08-04T00:00:00Z","marketplace_purchase":{"account":{"id":42,"login":"Acme Corp","type":"Organization"},"plan":{"id":7,"name":"community"},"unit_count":10},"installation":{"id":99}}`)
	sub, err := service.Handle(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if sub.TenantID == "" || sub.Status != "active" || sub.InstallationID != 99 {
		t.Fatalf("subscription=%+v", sub)
	}
	if tenant, ok := store.ResolveInstallationTenant(context.Background(), 99); !ok || tenant != sub.TenantID {
		t.Fatalf("binding=%q %v", tenant, ok)
	}
}

func TestCancellationFallsBackToFree(t *testing.T) {
	store, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true, CancellationPolicy: "retain_free", FreePlanName: "free"}, store)
	purchase := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"id":42,"login":"acme","type":"Organization"},"plan":{"id":7,"name":"pro"}}}`)
	if _, err = service.Handle(context.Background(), purchase); err != nil {
		t.Fatal(err)
	}
	cancel := []byte(`{"action":"cancelled","marketplace_purchase":{"account":{"id":42,"login":"acme","type":"Organization"},"plan":{"id":7,"name":"pro"}}}`)
	sub, err := service.Handle(context.Background(), cancel)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "free" || sub.PlanName != "free" {
		t.Fatalf("subscription=%+v", sub)
	}
}

func TestPendingChangeDoesNotReplaceCurrentPlan(t *testing.T) {
	store, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true, CancellationPolicy: "retain_free", FreePlanName: "free"}, store)
	purchase := []byte(`{"action":"purchased","effective_date":"2026-08-01T00:00:00Z","marketplace_purchase":{"account":{"id":52,"login":"acme","type":"Organization"},"plan":{"id":1,"name":"community"}}}`)
	if _, err = service.Handle(context.Background(), purchase); err != nil {
		t.Fatal(err)
	}
	pending := []byte(`{"action":"pending_change","effective_date":"2026-09-01T00:00:00Z","marketplace_purchase":{"account":{"id":52,"login":"acme","type":"Organization"},"plan":{"id":2,"name":"enterprise"}}}`)
	sub, err := service.Handle(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if sub.PlanName != "community" || sub.PendingPlanName != "enterprise" || sub.PendingAction != "pending_change" {
		t.Fatalf("subscription=%+v", sub)
	}
}

func TestOlderMarketplaceEventIsIgnored(t *testing.T) {
	store, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true, CancellationPolicy: "retain_free", FreePlanName: "free"}, store)
	newer := []byte(`{"action":"changed","effective_date":"2026-09-01T00:00:00Z","marketplace_purchase":{"account":{"id":62,"login":"acme","type":"Organization"},"plan":{"id":2,"name":"new"}}}`)
	if _, err = service.Handle(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	older := []byte(`{"action":"changed","effective_date":"2026-08-01T00:00:00Z","marketplace_purchase":{"account":{"id":62,"login":"acme","type":"Organization"},"plan":{"id":1,"name":"old"}}}`)
	sub, err := service.Handle(context.Background(), older)
	if err != nil {
		t.Fatal(err)
	}
	if sub.PlanName != "new" {
		t.Fatalf("stale event replaced plan: %+v", sub)
	}
}

type failingTenantLookupStore struct {
	db.Backend
	err error
}

func (s failingTenantLookupStore) GetTenant(context.Context, string) (*model.Tenant, error) {
	return nil, s.err
}

func TestMarketplaceDoesNotAutoCreateWhenTenantLookupFails(t *testing.T) {
	base, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	sentinel := errors.New("tenant lookup unavailable")
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true}, failingTenantLookupStore{Backend: base, err: sentinel})
	raw := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"id":77,"login":"acme","type":"Organization"},"plan":{"id":1,"name":"community"}}}`)
	if _, err := service.Handle(context.Background(), raw); !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestMarketplaceRejectsInvalidDatesBeforeCreatingTenant(t *testing.T) {
	store, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true}, store)
	raw := []byte(`{"action":"purchased","effective_date":"not-a-date","marketplace_purchase":{"account":{"id":88,"login":"acme","type":"Organization"},"plan":{"id":1,"name":"community"}}}`)
	if _, err := service.Handle(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "effective_date") {
		t.Fatalf("err=%v", err)
	}
	tenantID := tenantIDFor("acme", 88)
	if tenant, err := store.GetTenant(context.Background(), tenantID); err != nil || tenant != nil {
		t.Fatalf("tenant=%#v err=%v", tenant, err)
	}
}

type failingMarketplaceAuditStore struct {
	db.Backend
	err error
}

func (s failingMarketplaceAuditStore) RecordAudit(context.Context, model.AuditEvent) error {
	return s.err
}

func TestMarketplaceSurfacesAuditFailureAfterPersistingSubscription(t *testing.T) {
	base, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	sentinel := errors.New("audit unavailable")
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true, FreePlanName: "free"}, failingMarketplaceAuditStore{Backend: base, err: sentinel})
	raw := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"id":99,"login":"acme","type":"Organization"},"plan":{"id":1,"name":"community"}}}`)
	sub, err := service.Handle(context.Background(), raw)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
	var postCommitErr *PostCommitError
	if !errors.As(err, &postCommitErr) {
		t.Fatalf("err type=%T, want *PostCommitError", err)
	}
	if sub.TenantID == "" || sub.PlanName != "community" {
		t.Fatalf("subscription result=%+v", sub)
	}
	var stored Subscription
	found, getErr := base.GetObject(context.Background(), model.DefaultTenantID, "marketplace_account_index", "99", &stored)
	if getErr != nil || !found || stored.TenantID != sub.TenantID {
		t.Fatalf("persisted subscription=%+v found=%v err=%v", stored, found, getErr)
	}
}

func TestMarketplaceClassifiesInvalidPayloadSeparatelyFromStoreFailure(t *testing.T) {
	base, err := db.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	service := New(config.MarketplaceConfig{Enabled: true, AutoCreateTenant: true}, base)
	_, err = service.Handle(context.Background(), []byte(`{"action":"unknown"}`))
	var payloadErr *PayloadError
	if !errors.As(err, &payloadErr) {
		t.Fatalf("err=%v type=%T, want *PayloadError", err, err)
	}
}
