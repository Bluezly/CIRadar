package insights

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

func ID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

func RecordDeployment(ctx context.Context, store db.Backend, ev model.DeploymentEvent) (model.DeploymentEvent, error) {
	if ev.ID == "" {
		ev.ID = "dep_" + ID(ev.TenantID, ev.Repository, ev.Environment, ev.CommitSHA, ev.CompletedAt.UTC().Format(time.RFC3339Nano))
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if ev.CompletedAt.IsZero() {
		ev.CompletedAt = ev.CreatedAt
	}
	if ev.StartedAt.IsZero() {
		ev.StartedAt = ev.CompletedAt
	}
	if ev.Status == "" {
		ev.Status = "success"
	}
	return ev, store.PutObject(ctx, ev.TenantID, "deployment", ev.ID, ev)
}

func RecordUsage(ctx context.Context, store db.Backend, ev model.CIEvent, costPerMinute float64, currency string) (model.CIUsageRecord, error) {
	if ev.DurationSeconds <= 0 && !ev.StartedAt.IsZero() && !ev.CompletedAt.IsZero() {
		ev.DurationSeconds = int64(ev.CompletedAt.Sub(ev.StartedAt).Seconds())
	}
	if ev.DurationSeconds < 0 {
		ev.DurationSeconds = 0
	}
	minutes := math.Ceil(float64(ev.DurationSeconds)/60*100) / 100
	if ev.EstimatedCost <= 0 {
		ev.EstimatedCost = minutes * costPerMinute
	}
	if ev.Currency == "" {
		ev.Currency = currency
	}
	if ev.Currency == "" {
		ev.Currency = "USD"
	}
	id := "usage_" + ID(ev.TenantID, ev.Provider, ev.Repository, ev.JobID, ev.CompletedAt.UTC().Format(time.RFC3339Nano))
	r := model.CIUsageRecord{ID: id, TenantID: ev.TenantID, Provider: ev.Provider, Repository: ev.Repository, Workflow: ev.Workflow, Job: ev.Job, RunID: ev.RunID, RunnerClass: ev.RunnerClass, RunnerLabels: ev.RunnerLabels, DurationSeconds: ev.DurationSeconds, BillableMinutes: minutes, EstimatedCost: ev.EstimatedCost, Currency: ev.Currency, StartedAt: ev.StartedAt, CompletedAt: ev.CompletedAt, Metadata: ev.Metadata}
	return r, store.PutObject(ctx, ev.TenantID, "ci_usage", id, r)
}

func Usage(ctx context.Context, store db.Backend, tenant string, since, until time.Time) (model.CIUsageSummary, error) {
	items, err := store.ListObjects(ctx, tenant, "ci_usage", 10000)
	if err != nil {
		return model.CIUsageSummary{}, err
	}
	s := model.CIUsageSummary{TenantID: tenant, Since: since, Until: until, Currency: "USD", ByRepository: map[string]float64{}, MinutesByRepo: map[string]float64{}, RunsByProvider: map[string]int{}, GeneratedAt: time.Now().UTC()}
	for _, item := range items {
		var r model.CIUsageRecord
		if json.Unmarshal(item.Value, &r) != nil || r.CompletedAt.Before(since) || r.CompletedAt.After(until) {
			continue
		}
		s.Runs++
		s.DurationHours += float64(r.DurationSeconds) / 3600
		s.BillableMinutes += r.BillableMinutes
		s.EstimatedCost += r.EstimatedCost
		s.ByRepository[r.Repository] += r.EstimatedCost
		s.MinutesByRepo[r.Repository] += r.BillableMinutes
		s.RunsByProvider[r.Provider]++
		if r.Currency != "" {
			s.Currency = r.Currency
		}
	}
	return s, nil
}

func DORA(ctx context.Context, store db.Backend, tenant, environment string, since, until time.Time) (model.DORAMetrics, error) {
	items, err := store.ListObjects(ctx, tenant, "deployment", 10000)
	if err != nil {
		return model.DORAMetrics{}, err
	}
	m := model.DORAMetrics{TenantID: tenant, Environment: environment, Since: since, Until: until, GeneratedAt: time.Now().UTC()}
	incidents, err := store.ListIncidentsForTenant(ctx, tenant, 5000, "")
	if err != nil {
		return model.DORAMetrics{}, fmt.Errorf("list incidents for DORA metrics: %w", err)
	}
	incidentIndex := map[string]model.Incident{}
	for _, incident := range incidents {
		incidentIndex[incident.ID] = incident
		incidentIndex[incident.Fingerprint] = incident
	}
	var lead, restore []float64
	for _, item := range items {
		var d model.DeploymentEvent
		if json.Unmarshal(item.Value, &d) != nil || d.CompletedAt.Before(since) || d.CompletedAt.After(until) || (environment != "" && !strings.EqualFold(d.Environment, environment)) {
			continue
		}
		m.Deployments++
		if strings.EqualFold(d.Status, "success") || strings.EqualFold(d.Status, "succeeded") {
			m.SuccessfulDeployments++
		} else {
			m.FailedDeployments++
		}
		if !d.FirstCommitAt.IsZero() && d.CompletedAt.After(d.FirstCommitAt) {
			lead = append(lead, d.CompletedAt.Sub(d.FirstCommitAt).Minutes())
		}
		if d.IncidentID != "" {
			if incident, ok := incidentIndex[d.IncidentID]; ok && !incident.ResolvedAt.IsZero() && incident.ResolvedAt.After(incident.FirstSeenAt) {
				restore = append(restore, incident.ResolvedAt.Sub(incident.FirstSeenAt).Minutes())
			} else if d.CompletedAt.After(d.StartedAt) {
				restore = append(restore, d.CompletedAt.Sub(d.StartedAt).Minutes())
			}
		}
	}
	days := until.Sub(since).Hours() / 24
	if days < 1 {
		days = 1
	}
	m.DeploymentFrequencyPerDay = float64(m.SuccessfulDeployments) / days
	m.LeadTimeForChangesMinutes = median(lead)
	m.MeanTimeToRestoreMinutes = median(restore)
	if m.Deployments > 0 {
		m.ChangeFailureRatePercent = float64(m.FailedDeployments) * 100 / float64(m.Deployments)
	}
	return m, nil
}

func Trends(ctx context.Context, store db.Backend, tenant string, since, until time.Time) (map[string]map[string]float64, error) {
	usage, err := store.ListObjects(ctx, tenant, "ci_usage", 10000)
	if err != nil {
		return nil, err
	}
	deployments, err := store.ListObjects(ctx, tenant, "deployment", 10000)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]float64{"runs": {}, "cost": {}, "minutes": {}, "deployments": {}, "deployment_failures": {}}
	for _, x := range usage {
		var r model.CIUsageRecord
		if json.Unmarshal(x.Value, &r) == nil && !r.CompletedAt.Before(since) && !r.CompletedAt.After(until) {
			d := r.CompletedAt.UTC().Format("2006-01-02")
			out["runs"][d]++
			out["cost"][d] += r.EstimatedCost
			out["minutes"][d] += r.BillableMinutes
		}
	}
	for _, x := range deployments {
		var d model.DeploymentEvent
		if json.Unmarshal(x.Value, &d) == nil && !d.CompletedAt.Before(since) && !d.CompletedAt.After(until) {
			k := d.CompletedAt.UTC().Format("2006-01-02")
			out["deployments"][k]++
			if !strings.EqualFold(d.Status, "success") && !strings.EqualFold(d.Status, "succeeded") {
				out["deployment_failures"][k]++
			}
		}
	}
	return out, nil
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}
