package main

import (
	"ciradar/internal/db"
	"ciradar/internal/model"
	"testing"
	"time"
)

func TestEvaluateTestGate(t *testing.T) {
	passed := model.TestObservation{TenantID: "default", Repository: "acme/api", Suite: "unit", ClassName: "Calc", Name: "ok", Status: "passed"}
	failed := model.TestObservation{TenantID: "default", Repository: "acme/api", Suite: "unit", ClassName: "Calc", Name: "flaky", Status: "failed"}
	key := db.TestKey(failed)
	r := evaluateTestGate([]model.TestObservation{passed, failed}, []model.TestQuarantine{{TestKey: key, Active: true, ExpiresAt: time.Now().Add(time.Hour)}})
	if len(r.QuarantinedFailures) != 1 || len(r.UnquarantinedFailures) != 0 {
		t.Fatalf("%+v", r)
	}
	r = evaluateTestGate([]model.TestObservation{failed}, nil)
	if len(r.UnquarantinedFailures) != 1 {
		t.Fatalf("%+v", r)
	}
}
