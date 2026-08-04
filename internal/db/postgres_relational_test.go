package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ciradar/internal/model"
)

func TestRelationalObjectsRoundTripTenantData(t *testing.T) {
	store, err := newMemoryStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	result := model.AnalysisResult{ID: "analysis-1", TenantID: "alpha", Repository: "acme/api", Organization: "acme", Fingerprint: "fp-1", Category: model.CategoryNetworkFailure, Attribution: model.AttributionExternal, CreatedAt: time.Now().UTC()}
	input := model.AnalysisInput{TenantID: "alpha", Repository: "acme/api", Organization: "acme"}
	if err = store.RecordAnalysisForTenant(context.Background(), "alpha", input, result, true, false); err != nil {
		t.Fatal(err)
	}
	objects, err := stateObjects(store.state)
	if err != nil {
		t.Fatal(err)
	}
	var selected []pgObject
	for _, object := range objects {
		if matchesSpec([]pgSpec{pgOne("alpha", pgKindAnalysis, "analysis-1")}, object) || matchesSpec([]pgSpec{pgGlobalOne(pgKindTenant, "alpha")}, object) {
			selected = append(selected, object)
		}
	}
	hydrated, err := hydrateStore(selected)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hydrated.GetAnalysisForTenant(context.Background(), "alpha", "analysis-1")
	if err != nil || got == nil || got.Fingerprint != "fp-1" {
		t.Fatalf("analysis=%+v err=%v", got, err)
	}
	tenant, err := hydrated.GetTenant(context.Background(), "alpha")
	if err != nil || tenant == nil || !tenant.Enabled {
		t.Fatalf("tenant=%+v err=%v", tenant, err)
	}
}

func TestRelationalAPIKeyCarriesIndexedFingerprint(t *testing.T) {
	store, err := newMemoryStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, token, err := store.CreateAPIKey(context.Background(), model.DefaultTenantID, "viewer", model.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := stateObjects(store.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		if object.Kind == pgKindAPIKey && object.ID == key.ID {
			if object.Fingerprint != hashToken(token) || object.Status != "active" {
				t.Fatalf("object=%+v", object)
			}
			return
		}
	}
	t.Fatal("API key object not found")
}

func TestRelationalExtensionObjectUsesSeparateKind(t *testing.T) {
	store, err := newMemoryStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.PutObject(context.Background(), "alpha", "marketplace_subscription", "42", map[string]string{"status": "free"}); err != nil {
		t.Fatal(err)
	}
	objects, err := stateObjects(store.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		if object.Kind != extensionKind("marketplace_subscription") {
			continue
		}
		var extension ExtensionObject
		if err := json.Unmarshal(object.Payload, &extension); err != nil {
			t.Fatal(err)
		}
		if extension.TenantID != "alpha" || extension.ID != "42" || !strings.Contains(string(extension.Value), "free") {
			t.Fatalf("extension=%+v", extension)
		}
		return
	}
	t.Fatal("extension object not found")
}

func TestSpecWhereTargetsSingleObject(t *testing.T) {
	where := specWhere([]pgSpec{pgGlobalOne(pgKindTenant, "alpha")})
	if !strings.Contains(where, "object_id='alpha'") || strings.Contains(where, " OR ") {
		t.Fatalf("where=%s", where)
	}
}
