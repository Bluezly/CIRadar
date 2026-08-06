package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ciradar/internal/model"
	"ciradar/internal/pgwire"
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

func TestParsePostgresIntRejectsMalformedValues(t *testing.T) {
	valid := "42"
	if got, err := parsePostgresInt(&valid, "count"); err != nil || got != 42 {
		t.Fatalf("got=%d err=%v", got, err)
	}
	invalid := "not-a-number"
	if _, err := parsePostgresInt(&invalid, "count"); err == nil {
		t.Fatal("malformed PostgreSQL integer was accepted")
	}
	if _, err := parsePostgresInt(nil, "count"); err == nil {
		t.Fatal("NULL PostgreSQL integer was accepted")
	}
}

func TestObservationPartitionStatementsMoveDefaultRowsBeforeAttach(t *testing.T) {
	statements := observationPartitionStatements(time.Date(2026, time.August, 6, 0, 0, 0, 0, time.UTC))
	if len(statements) != 4 {
		t.Fatalf("partition statements=%d", len(statements))
	}
	joined := strings.Join(statements, "\n")
	for _, want := range []string{
		"ciradar_test_observations_202607",
		"ciradar_test_observations_202608",
		"ciradar_test_observations_202609",
		"ciradar_test_observations_202610",
		"ACCESS EXCLUSIVE",
		"INSERT INTO ciradar_test_observations_202608 SELECT * FROM ciradar_test_observations_default",
		"DELETE FROM ciradar_test_observations_default",
		"ATTACH PARTITION ciradar_test_observations_202608",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("partition maintenance SQL missing %q:\n%s", want, joined)
		}
	}
}

func TestExpiredObservationPartitionsOnlyDropsWholeMonths(t *testing.T) {
	value := func(s string) *string { return &s }
	rows := pgwire.Rows{Values: [][]*string{
		{value("ciradar_test_observations_202604")},
		{value("ciradar_test_observations_202605")},
		{value("ciradar_test_observations_default")},
		{value("not_a_partition")},
		{value("ciradar_test_observations_2026xx")},
	}}
	got := expiredObservationPartitions(rows, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	if len(got) != 2 || got[0] != "ciradar_test_observations_202604" || got[1] != "ciradar_test_observations_202605" {
		t.Fatalf("expired partitions=%v", got)
	}
}
