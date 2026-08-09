package db

import (
	"context"
	"math"
	"path/filepath"
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestFeedbackMetricsSeparatesAgreementFromLabeledAccuracy(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	analyses := []model.AnalysisResult{
		{ID: "a1", TenantID: model.DefaultTenantID, Category: model.CategoryNetworkFailure, Attribution: model.AttributionExternal},
		{ID: "a2", TenantID: model.DefaultTenantID, Category: model.CategoryCodeFailure, Attribution: model.AttributionCode},
		{ID: "a3", TenantID: model.DefaultTenantID, Category: model.CategoryDependencyRegistry, Attribution: model.AttributionExternal},
	}
	for _, analysis := range analyses {
		if err := store.RecordAnalysisForTenant(ctx, model.DefaultTenantID, model.AnalysisInput{Repository: "acme/api", Log: "x"}, analysis, false, false); err != nil {
			t.Fatal(err)
		}
	}
	feedback := []model.DiagnosisFeedback{
		{TenantID: model.DefaultTenantID, AnalysisID: "a1", Actor: "u1", Verdict: "correct"},
		{TenantID: model.DefaultTenantID, AnalysisID: "a2", Actor: "u1", Verdict: "incorrect", ActualCategory: model.CategoryTestFlake, ActualCause: model.AttributionMixed},
		{TenantID: model.DefaultTenantID, AnalysisID: "a3", Actor: "u1", Verdict: "partial", ActualCategory: model.CategoryDependencyRegistry, ActualCause: model.AttributionExternal},
	}
	for _, item := range feedback {
		if _, err := store.UpsertDiagnosisFeedback(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	m, err := store.FeedbackMetrics(ctx, model.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Total != 3 || m.Correct != 1 || m.Partial != 1 || m.Incorrect != 1 {
		t.Fatalf("counts=%#v", m)
	}
	if math.Abs(m.AgreementPercent-50) > 0.001 || m.PrecisionPercent != m.AgreementPercent {
		t.Fatalf("agreement=%v legacy=%v", m.AgreementPercent, m.PrecisionPercent)
	}
	if m.LabeledCategoryCases != 3 || math.Abs(m.CategoryAccuracyPercent-66.6666667) > 0.01 {
		t.Fatalf("category metrics=%#v", m)
	}
	if m.LabeledAttributionCases != 3 || math.Abs(m.AttributionAccuracyPercent-66.6666667) > 0.01 {
		t.Fatalf("attribution metrics=%#v", m)
	}
	if math.Abs(m.ExternalAgreementPercent-50) > 0.001 || m.ExternalPrecision != m.ExternalAgreementPercent {
		t.Fatalf("external agreement=%v legacy=%v", m.ExternalAgreementPercent, m.ExternalPrecision)
	}
}

func TestFeedbackRejectsInvalidGroundTruthLabels(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	analysis := model.AnalysisResult{ID: "a1", TenantID: model.DefaultTenantID, Category: model.CategoryUnknown, Attribution: model.AttributionUnknown}
	if err := store.RecordAnalysisForTenant(ctx, model.DefaultTenantID, model.AnalysisInput{Repository: "acme/api", Log: "x"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertDiagnosisFeedback(ctx, model.DiagnosisFeedback{TenantID: model.DefaultTenantID, AnalysisID: "a1", Actor: "u", Verdict: "incorrect", ActualCategory: model.Category("MADE_UP")}); err == nil {
		t.Fatal("invalid category accepted")
	}
	if _, err := store.UpsertDiagnosisFeedback(ctx, model.DiagnosisFeedback{TenantID: model.DefaultTenantID, AnalysisID: "a1", Actor: "u", Verdict: "incorrect", ActualCause: model.Attribution("MADE_UP")}); err == nil {
		t.Fatal("invalid attribution accepted")
	}
}
