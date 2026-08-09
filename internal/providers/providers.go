package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/httpguard"
	"github.com/Bluezly/CIRadar/internal/model"
)

type Endpoint struct {
	Name              string
	URL               string
	ComponentKeywords []string
}

type Poller struct {
	store                db.Backend
	http                 *http.Client
	log                  *slog.Logger
	endpoints            []Endpoint
	mu                   sync.Mutex
	lastFailureSignature string
}

func NewPoller(store db.Backend, log *slog.Logger) *Poller {
	return &Poller{
		store: store,
		log:   log,
		http:  httpguard.NewClient(15*time.Second, false),
		endpoints: []Endpoint{
			{Name: "GitHub Actions", URL: "https://www.githubstatus.com/api/v2/summary.json", ComponentKeywords: []string{"actions"}},
			{Name: "npm", URL: "https://status.npmjs.org/api/v2/summary.json"},
			{Name: "PyPI", URL: "https://status.python.org/api/v2/summary.json"},
			{Name: "Docker Hub", URL: "https://www.dockerstatus.com/api/v2/summary.json", ComponentKeywords: []string{"registry", "hub", "authentication"}},
		},
	}
}

type summaryResponse struct {
	Status struct {
		Indicator   string `json:"indicator"`
		Description string `json:"description"`
	} `json:"status"`
	Page struct {
		URL string `json:"url"`
	} `json:"page"`
	Components []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"components"`
	Incidents []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Impact string `json:"impact"`
	} `json:"incidents"`
}

func (p *Poller) Poll(ctx context.Context) {
	failed := make([]string, 0)
	details := make([]string, 0)
	for _, ep := range p.endpoints {
		st, err := p.fetch(ctx, ep)
		if err != nil {
			failed = append(failed, ep.Name)
			details = append(details, ep.Name+": "+err.Error())
			continue
		}
		if err := p.store.RecordProviderStatus(ctx, st); err != nil {
			failed = append(failed, ep.Name)
			details = append(details, ep.Name+": store: "+err.Error())
		}
	}
	p.reportPollFailures(failed, details)
}

func (p *Poller) reportPollFailures(failed, details []string) {
	sort.Strings(failed)
	sort.Strings(details)
	signature := strings.Join(failed, ",")
	p.mu.Lock()
	previous := p.lastFailureSignature
	p.lastFailureSignature = signature
	p.mu.Unlock()
	for _, detail := range details {
		p.log.Debug("provider status poll detail", "detail", detail)
	}
	if signature == previous {
		return
	}
	if signature == "" {
		if previous != "" {
			p.log.Info("provider status polling recovered")
		}
		return
	}
	p.log.Warn("provider status polling incomplete", "failed_count", len(failed), "providers", signature, "hint", "set provider_polling=false when outbound status checks are intentionally unavailable")
}

func (p *Poller) Run(ctx context.Context, interval time.Duration) {
	p.Poll(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Poll(ctx)
		}
	}
}

func (p *Poller) fetch(ctx context.Context, ep Endpoint) (model.ProviderStatus, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ep.URL, nil)
	if err != nil {
		return model.ProviderStatus{}, err
	}
	req.Header.Set("User-Agent", "CI-Radar/0.1")
	resp, err := p.http.Do(req)
	if err != nil {
		return model.ProviderStatus{}, err
	}
	defer resp.Body.Close()
	bodyBytes, err := readProviderBody(resp.Body, 1<<20)
	if err != nil {
		return model.ProviderStatus{}, fmt.Errorf("read provider status response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := bodyBytes
		if len(message) > 2048 {
			message = message[:2048]
		}
		return model.ProviderStatus{}, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(message)))
	}
	var body summaryResponse
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return model.ProviderStatus{}, err
	}

	indicator := strings.ToLower(strings.TrimSpace(body.Status.Indicator))
	description := strings.TrimSpace(body.Status.Description)
	var affected []string
	if len(ep.ComponentKeywords) > 0 {
		indicator = "none"
		for _, c := range body.Components {
			if !containsAny(strings.ToLower(c.Name), ep.ComponentKeywords) {
				continue
			}
			if statusRank(c.Status) > statusRank(indicator) {
				indicator = strings.ToLower(c.Status)
			}
			if statusRank(c.Status) > 0 {
				affected = append(affected, c.Name+"="+c.Status)
			}
		}
		if len(affected) == 0 {
			description = "Selected components operational"
		} else {
			sort.Strings(affected)
			description = strings.Join(affected, ", ")
		}
	}
	for _, incident := range body.Incidents {
		if strings.EqualFold(incident.Status, "resolved") || strings.EqualFold(incident.Status, "completed") {
			continue
		}
		if len(ep.ComponentKeywords) == 0 || containsAny(strings.ToLower(incident.Name), ep.ComponentKeywords) {
			if description != "" {
				description += "; "
			}
			description += "incident: " + incident.Name
			if statusRank(incident.Impact) > statusRank(indicator) {
				indicator = strings.ToLower(incident.Impact)
			}
		}
	}
	incident := statusRank(indicator) > 0
	return model.ProviderStatus{
		Provider:    ep.Name,
		Indicator:   indicator,
		Description: description,
		Incident:    incident,
		CheckedAt:   time.Now().UTC(),
		Source:      ep.URL,
	}, nil
}

func readProviderBody(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, fmt.Errorf("provider response body limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("provider response body exceeds %d bytes", max)
	}
	return body, nil
}

func statusRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "none", "operational", "resolved", "completed", "":
		return 0
	case "under_maintenance", "maintenance", "minor", "degraded_performance":
		return 1
	case "partial_outage", "major":
		return 2
	case "major_outage", "critical":
		return 3
	default:
		return 1
	}
}

func containsAny(s string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(s, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func MatchesStatusProvider(ruleProvider, statusProvider string) bool {
	r := strings.ToLower(ruleProvider)
	s := strings.ToLower(statusProvider)
	if r == s {
		return true
	}
	if strings.Contains(r, "github") && strings.Contains(s, "github") {
		return true
	}
	if strings.Contains(r, "docker") && strings.Contains(s, "docker") {
		return true
	}
	if strings.Contains(r, "container-registry") && strings.Contains(s, "docker") {
		return true
	}
	if strings.Contains(r, "ghcr") && strings.Contains(s, "github") {
		return true
	}
	if strings.Contains(r, "pypi") && strings.Contains(s, "pypi") {
		return true
	}
	if strings.Contains(r, "npm") && strings.Contains(s, "npm") {
		return true
	}
	return false
}
