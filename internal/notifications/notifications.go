package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/httpguard"
	"ciradar/internal/model"
	"ciradar/internal/version"
)

type Dispatcher struct {
	cfg   config.NotificationConfig
	store db.Backend
	log   *slog.Logger
}

func New(cfg config.NotificationConfig, store db.Backend, log *slog.Logger) *Dispatcher {
	return &Dispatcher{cfg: cfg, store: store, log: log}
}

func (d *Dispatcher) Enabled() bool {
	if !d.cfg.Enabled {
		return false
	}
	for _, ch := range d.cfg.Channels {
		if ch.Enabled {
			return true
		}
	}
	return false
}

func (d *Dispatcher) Dispatch(ctx context.Context, ev model.NotificationEvent) error {
	if !d.Enabled() {
		return nil
	}
	var retryable []error
	routedChannels := append([]string(nil), ev.TargetChannels...)
	if ev.Repository != "" {
		profile, err := d.store.GetRepositoryProfile(ctx, ev.TenantID, ev.Repository)
		if err != nil {
			return fmt.Errorf("load repository notification profile: %w", err)
		}
		if profile != nil {
			if len(routedChannels) == 0 {
				routedChannels = profile.NotificationChannels
			}
			ev.Severity = elevateSeverityForCriticality(ev.Severity, profile.Criticality)
		}
	}
	for _, ch := range d.cfg.Channels {
		if !ch.Enabled || !matches(ch, ev) {
			continue
		}
		if len(routedChannels) > 0 && !containsFold(routedChannels, ch.Name) {
			continue
		}
		if err := d.dispatchChannel(ctx, ch, ev); err != nil {
			var pe *permanentError
			if errors.As(err, &pe) {
				d.log.Warn("notification permanently failed", "channel", ch.Name, "event_id", ev.ID, "error", pe.Error())
				continue
			}
			retryable = append(retryable, fmt.Errorf("%s: %w", ch.Name, err))
		}
	}
	return errors.Join(retryable...)
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func (d *Dispatcher) dispatchChannel(ctx context.Context, ch config.NotificationChannel, ev model.NotificationEvent) error {
	tenantID := ev.TenantID
	if strings.TrimSpace(tenantID) == "" {
		tenantID = model.DefaultTenantID
	}
	decision, delivery, err := d.store.BeginNotificationDeliveryForTenant(ctx, tenantID, ev.ID, ch.Name, ch.Type, ev.DedupeKey, ch.Cooldown, ch.MaxAttempts)
	if err != nil {
		return err
	}
	if decision != "send" {
		return nil
	}
	if quiet, reason := inQuietHours(ch, ev); quiet {
		now := time.Now().UTC()
		return d.store.RecordNotificationDelivery(ctx, model.NotificationDelivery{ID: delivery.ID, TenantID: tenantID, EventID: ev.ID, DedupeKey: ev.DedupeKey, Channel: ch.Name, ChannelType: ch.Type, Status: "suppressed", Attempts: delivery.Attempts, SuppressedReason: reason, CreatedAt: delivery.CreatedAt, UpdatedAt: now})
	}
	attempt := delivery.Attempts
	if ch.Type == "email" {
		err := sendEmail(ctx, ch, ev)
		if err != nil {
			return d.recordFailure(ctx, ch, ev, attempt, 0, sanitizeError(err, ch, "smtp://"+ch.SMTPHost), false)
		}
		now := time.Now().UTC()
		return d.store.RecordNotificationDelivery(ctx, model.NotificationDelivery{ID: delivery.ID, TenantID: tenantID, EventID: ev.ID, DedupeKey: ev.DedupeKey, Channel: ch.Name, ChannelType: ch.Type, Status: "sent", Attempts: attempt, CreatedAt: delivery.CreatedAt, UpdatedAt: now, SentAt: now})
	}
	body, endpoint, headers, err := buildRequest(ch, ev)
	if err != nil {
		return d.recordFailure(ctx, ch, ev, attempt, 0, err, true)
	}

	timeout := ch.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return d.recordFailure(ctx, ch, ev, attempt, 0, err, true)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CI-Radar/"+version.Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpguard.NewClient(timeout, ch.AllowPrivateNetwork).Do(req)
	if err != nil {
		return d.recordFailure(ctx, ch, ev, attempt, 0, sanitizeError(err, ch, endpoint), false)
	}
	defer resp.Body.Close()
	limited, err := readResponseSnippet(resp.Body, 8<<10)
	if err != nil {
		return d.recordFailure(ctx, ch, ev, attempt, resp.StatusCode, sanitizeError(fmt.Errorf("read HTTP response: %w", err), ch, endpoint), false)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if ch.Type == "telegram" {
			var result struct {
				OK          bool   `json:"ok"`
				Description string `json:"description"`
			}
			if len(limited) > 0 && json.Unmarshal(limited, &result) == nil && !result.OK {
				return d.recordFailure(ctx, ch, ev, attempt, resp.StatusCode, fmt.Errorf("Telegram rejected message: %s", sanitizeText(result.Description, ch, endpoint)), true)
			}
		}
		now := time.Now().UTC()
		return d.store.RecordNotificationDelivery(ctx, model.NotificationDelivery{ID: delivery.ID, TenantID: tenantID, EventID: ev.ID, DedupeKey: ev.DedupeKey, Channel: ch.Name, ChannelType: ch.Type, Status: "sent", Attempts: attempt, HTTPStatus: resp.StatusCode, CreatedAt: delivery.CreatedAt, UpdatedAt: now, SentAt: now})
	}
	msg := fmt.Errorf("HTTP %d: %s", resp.StatusCode, sanitizeText(strings.TrimSpace(string(limited)), ch, endpoint))
	permanent := resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 408 && resp.StatusCode != 409 && resp.StatusCode != 425 && resp.StatusCode != 429
	if resp.StatusCode == 429 {
		if wait := retryDelay(resp, limited); wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	return d.recordFailure(ctx, ch, ev, attempt, resp.StatusCode, msg, permanent)
}

func readResponseSnippet(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("response body limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		body = body[:max]
	}
	return body, nil
}

func (d *Dispatcher) recordFailure(ctx context.Context, ch config.NotificationChannel, ev model.NotificationEvent, attempts, code int, err error, permanent bool) error {
	tenantID := ev.TenantID
	if strings.TrimSpace(tenantID) == "" {
		tenantID = model.DefaultTenantID
	}
	old, lookupErr := d.store.GetNotificationDeliveryForTenant(ctx, tenantID, ev.ID, ch.Name)
	if lookupErr != nil {
		err = errors.Join(err, fmt.Errorf("read notification delivery: %w", lookupErr))
		if permanent {
			return &permanentError{err}
		}
		return err
	}
	created := time.Now().UTC()
	if old != nil {
		created = old.CreatedAt
	}
	if attempts < 1 {
		attempts = 1
	}
	status := "retrying"
	if permanent || attempts >= ch.MaxAttempts {
		status = "failed"
		permanent = true
	}
	now := time.Now().UTC()
	deliveryID := ""
	if old != nil {
		deliveryID = old.ID
	}
	recordErr := d.store.RecordNotificationDelivery(ctx, model.NotificationDelivery{ID: deliveryID, TenantID: tenantID, EventID: ev.ID, DedupeKey: ev.DedupeKey, Channel: ch.Name, ChannelType: ch.Type, Status: status, Attempts: attempts, HTTPStatus: code, LastError: trim(err.Error(), 2000), CreatedAt: created, UpdatedAt: now})
	if recordErr != nil {
		err = errors.Join(err, fmt.Errorf("record notification failure: %w", recordErr))
	}
	if permanent {
		return &permanentError{err}
	}
	return err
}

func matches(ch config.NotificationChannel, ev model.NotificationEvent) bool {
	if ev.Type == "test" {
		return true
	}
	if !containsFold(ch.Events, ev.Type) {
		return false
	}
	if ev.Type == "analysis" {
		if model.NotificationEvidenceStrength(ev) < ch.MinimumScore {
			return false
		}
		if ch.ExternalOnly && eventAttribution(ev) != model.AttributionExternal {
			return false
		}
		if len(ch.Categories) > 0 && !containsFold(ch.Categories, string(ev.Category)) {
			return false
		}
	}
	if ev.Incident != nil && severityRank(ev.Incident.Severity) < severityRank(ch.MinimumSeverity) {
		return false
	}
	if ev.Repository != "" && len(ch.IncludeRepositories) > 0 && !matchesAny(ch.IncludeRepositories, ev.Repository) {
		return false
	}
	if ev.Repository != "" && matchesAny(ch.ExcludeRepositories, ev.Repository) {
		return false
	}
	return true
}

func eventAttribution(ev model.NotificationEvent) model.Attribution {
	if ev.Attribution != "" {
		return ev.Attribution
	}
	switch ev.Confidence {
	case model.ConfidenceStrong, model.ConfidenceModerate:
		return model.AttributionExternal
	case model.ConfidenceLikelyCode:
		return model.AttributionCode
	case model.ConfidenceMixed:
		return model.AttributionMixed
	default:
		return model.AttributionUnknown
	}
}

func inQuietHours(ch config.NotificationChannel, ev model.NotificationEvent) (bool, string) {
	if ch.QuietHoursStart == "" || ch.QuietHoursEnd == "" {
		return false, ""
	}
	if severityRank(ev.Severity) >= severityRank(ch.QuietHoursBypassSeverity) {
		return false, ""
	}
	loc, err := time.LoadLocation(ch.Timezone)
	if err != nil {
		return false, ""
	}
	now := time.Now().In(loc)
	start, _ := time.ParseInLocation("15:04", ch.QuietHoursStart, loc)
	end, _ := time.ParseInLocation("15:04", ch.QuietHoursEnd, loc)
	mins := now.Hour()*60 + now.Minute()
	sm := start.Hour()*60 + start.Minute()
	em := end.Hour()*60 + end.Minute()
	quiet := false
	if sm < em {
		quiet = mins >= sm && mins < em
	} else {
		quiet = mins >= sm || mins < em
	}
	if quiet {
		return true, "quiet_hours:" + ch.Timezone
	}
	return false, ""
}

func elevateSeverityForCriticality(severity, criticality string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	switch strings.ToLower(strings.TrimSpace(criticality)) {
	case "critical":
		return "critical"
	case "high":
		if severityRank(severity) < severityRank("major") {
			return "major"
		}
	}
	if severity == "" {
		return "minor"
	}
	return severity
}

func buildRequest(ch config.NotificationChannel, ev model.NotificationEvent) ([]byte, string, map[string]string, error) {
	headers := map[string]string{}
	for k, v := range ch.Headers {
		headers[k] = v
	}
	var payload any
	endpoint := ch.URL
	switch ch.Type {
	case "slack":
		payload = slackPayload(ch, ev)
	case "discord":
		payload = discordPayload(ch, ev)
	case "telegram":
		endpoint = ch.URL
		if endpoint == "" {
			endpoint = "https://api.telegram.org/bot" + ch.BotToken + "/sendMessage"
		}
		m := map[string]any{"chat_id": ch.ChatID, "text": telegramText(ev), "parse_mode": "HTML", "disable_web_page_preview": true}
		if ch.MessageThreadID != 0 {
			m["message_thread_id"] = ch.MessageThreadID
		}
		payload = m
	case "webhook":
		payload = ev
	case "teams":
		payload = teamsPayload(ev)
	case "pagerduty":
		if endpoint == "" {
			endpoint = "https://events.pagerduty.com/v2/enqueue"
		}
		payload = pagerDutyPayload(ch, ev)
	case "opsgenie":
		endpoint, payload = opsgenieEndpointAndPayload(ch, ev)
		headers["Authorization"] = "GenieKey " + ch.APIKey
	case "email":
		return nil, "", nil, fmt.Errorf("email uses SMTP transport")
	default:
		return nil, "", nil, fmt.Errorf("unsupported notification type %q", ch.Type)
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, "", nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", nil, err
	}
	if ch.Type == "webhook" && ch.HMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(ch.HMACSecret))
		_, _ = mac.Write(body)
		headers["X-CI-Radar-Signature-256"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		headers["X-CI-Radar-Event"] = ev.Type
		headers["X-CI-Radar-Delivery"] = ev.ID
	}
	return body, endpoint, headers, nil
}

func slackPayload(ch config.NotificationChannel, ev model.NotificationEvent) map[string]any {
	text := plainText(ev)
	blocks := []any{
		map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(ev.Title, 140)}},
		map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": slackBody(ch, ev)}},
	}
	prefix := ev.TenantID + "|"
	if ev.Incident != nil && ev.Fingerprint != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{
			map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": "Acknowledge"}, "style": "primary", "action_id": "ciradar_ack", "value": prefix + "ack|" + ev.Fingerprint},
			map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": "Resolve"}, "style": "danger", "action_id": "ciradar_resolve", "value": prefix + "resolve|" + ev.Fingerprint},
		}})
	} else if ev.Type == "test_flaky" && ev.Fingerprint != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": "Quarantine 7 days"}, "style": "danger", "action_id": "ciradar_quarantine", "value": prefix + "quarantine|" + ev.Fingerprint}}})
	}
	return map[string]any{"text": text, "blocks": blocks}
}
func slackBody(ch config.NotificationChannel, ev model.NotificationEvent) string {
	var b strings.Builder
	if ch.Mention != "" {
		b.WriteString(ch.Mention + "\n")
	}
	fmt.Fprintf(&b, "*Summary:* %s\n", escapeSlack(ev.Summary))
	if ev.Repository != "" {
		fmt.Fprintf(&b, "*Repository:* `%s`\n", escapeSlack(ev.Repository))
	}
	if ev.Category != "" {
		fmt.Fprintf(&b, "*Category:* `%s` · *Attribution:* `%s` · *Confidence:* `%s` · *Evidence:* %d/100 · *Externality:* %+d\n", ev.Category, ev.Attribution, ev.Confidence, model.NotificationEvidenceStrength(ev), model.NotificationExternalityScore(ev))
	}
	if ev.Provider != "" {
		fmt.Fprintf(&b, "*Provider:* `%s` · *Operation:* `%s`\n", escapeSlack(ev.Provider), escapeSlack(ev.Operation))
	}
	if ev.Recommendation != "" {
		fmt.Fprintf(&b, "*Action:* %s\n", escapeSlack(ev.Recommendation))
	}
	if ev.DetailsURL != "" {
		fmt.Fprintf(&b, "<%s|Open details>", ev.DetailsURL)
	}
	return b.String()
}
func discordPayload(ch config.NotificationChannel, ev model.NotificationEvent) map[string]any {
	p := map[string]any{"content": ch.Mention, "embeds": []any{map[string]any{
		"title": truncate(ev.Title, 256), "description": truncate(ev.Summary, 4096), "url": ev.DetailsURL,
		"fields": discordFields(ev), "timestamp": ev.OccurredAt.UTC().Format(time.RFC3339),
	}}}
	if ch.Username != "" {
		p["username"] = ch.Username
	}
	return p
}
func discordFields(ev model.NotificationEvent) []any {
	out := []any{}
	add := func(n, v string, inline bool) {
		if v != "" {
			out = append(out, map[string]any{"name": n, "value": truncate(v, 1024), "inline": inline})
		}
	}
	add("Repository", ev.Repository, true)
	add("Category", string(ev.Category), true)
	add("Confidence", string(ev.Confidence), true)
	add("Evidence", fmt.Sprintf("%d/100", model.NotificationEvidenceStrength(ev)), true)
	add("Externality", fmt.Sprintf("%+d", model.NotificationExternalityScore(ev)), true)
	add("Provider", ev.Provider, true)
	add("Recommendation", ev.Recommendation, false)
	return out
}
func telegramText(ev model.NotificationEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b>\n", html.EscapeString(ev.Title))
	fmt.Fprintf(&b, "%s\n", html.EscapeString(ev.Summary))
	if ev.Repository != "" {
		fmt.Fprintf(&b, "\n<b>Repository:</b> <code>%s</code>", html.EscapeString(ev.Repository))
	}
	if ev.Category != "" {
		fmt.Fprintf(&b, "\n<b>Category:</b> <code>%s</code>\n<b>Confidence:</b> <code>%s</code>\n<b>Evidence:</b> %d/100\n<b>Externality:</b> %+d", ev.Category, ev.Confidence, model.NotificationEvidenceStrength(ev), model.NotificationExternalityScore(ev))
	}
	if ev.Recommendation != "" {
		fmt.Fprintf(&b, "\n\n<b>Action:</b> %s", html.EscapeString(ev.Recommendation))
	}
	if ev.DetailsURL != "" {
		fmt.Fprintf(&b, "\n\n<a href=\"%s\">Open details</a>", html.EscapeString(ev.DetailsURL))
	}
	return truncate(b.String(), 4096)
}
func plainText(ev model.NotificationEvent) string {
	parts := []string{ev.Title, ev.Summary}
	if ev.Repository != "" {
		parts = append(parts, "Repository: "+ev.Repository)
	}
	if ev.Category != "" {
		parts = append(parts, fmt.Sprintf("Category: %s | Confidence: %s | Evidence: %d/100 | Externality: %+d", ev.Category, ev.Confidence, model.NotificationEvidenceStrength(ev), model.NotificationExternalityScore(ev)))
	}
	if ev.Recommendation != "" {
		parts = append(parts, "Action: "+ev.Recommendation)
	}
	if ev.DetailsURL != "" {
		parts = append(parts, ev.DetailsURL)
	}
	return strings.Join(parts, "\n")
}
func retryDelay(resp *http.Response, body []byte) time.Duration {
	raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if raw != "" {
		if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds > 0 {
			return time.Duration(minFloat(seconds, 30) * float64(time.Second))
		}
	}
	var payload struct {
		RetryAfter float64 `json:"retry_after"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.RetryAfter > 0 {
		return time.Duration(minFloat(payload.RetryAfter, 30) * float64(time.Second))
	}
	return 0
}
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func sanitizeError(err error, ch config.NotificationChannel, endpoint string) error {
	if err == nil {
		return nil
	}
	return errors.New(sanitizeText(err.Error(), ch, endpoint))
}
func sanitizeText(s string, ch config.NotificationChannel, endpoint string) string {
	for _, secret := range []string{endpoint, ch.URL, ch.BotToken, ch.HMACSecret, ch.APIKey, ch.RoutingKey, ch.SMTPPassword} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[REDACTED]")
		}
	}
	return s
}

func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("notification endpoint must use http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("notification endpoint host is missing")
	}
	return nil
}
func matchesAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(strings.ToLower(p), strings.ToLower(value)); ok {
			return true
		}
	}
	return false
}
func containsFold(items []string, value string) bool {
	for _, x := range items {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "major":
		return 3
	case "minor":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
func escapeSlack(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	end := n
	for end > 0 && !utf8.ValidString(s[:end]) {
		end--
	}
	return s[:end]
}
func trim(s string, n int) string { return truncate(s, n) }
func AnalysisEvent(in model.AnalysisInput, r model.AnalysisResult, publicBaseURL string) model.NotificationEvent {
	details := ""
	if publicBaseURL != "" {
		details = strings.TrimRight(publicBaseURL, "/") + "/api/v1/analyses/" + r.ID
	}
	return model.NotificationEvent{ID: "evt_analysis_" + r.ID, TenantID: r.TenantID, Type: "analysis", DedupeKey: "analysis:" + in.Repository + ":" + r.Fingerprint, OccurredAt: r.CreatedAt, Severity: analysisSeverity(r), Title: "CI Radar: " + r.Summary, Summary: r.Summary, Repository: in.Repository, Organization: in.Organization, Workflow: in.Workflow, Job: in.Job, RunID: in.RunID, CommitSHA: in.CommitSHA, DetailsURL: details, Category: r.Category, Confidence: r.Confidence, Attribution: r.Attribution, Score: r.Score, ExternalityScore: model.ExternalityScoreOf(r), EvidenceStrength: model.EvidenceStrengthOf(r), ExternalEvidenceScore: model.ExternalEvidenceScoreOf(r), CodeEvidenceScore: model.CodeEvidenceScoreOf(r), Provider: r.Provider, Operation: r.Operation, Fingerprint: r.Fingerprint, Recommendation: r.Recommendation, Evidence: r.Evidence}
}
func IncidentEvent(kind string, i model.Incident, publicBaseURL string) model.NotificationEvent {
	title := "CI incident opened: " + i.Title
	if kind == "incident_updated" {
		title = "CI incident updated: " + i.Title
	}
	if kind == "incident_resolved" {
		title = "CI incident resolved: " + i.Title
	}
	return model.NotificationEvent{ID: fmt.Sprintf("evt_%s_%s_%d", kind, i.Fingerprint, i.LastSeenAt.Unix()), TenantID: i.TenantID, Type: kind, DedupeKey: kind + ":" + i.Fingerprint, OccurredAt: time.Now().UTC(), Severity: i.Severity, Title: title, Summary: fmt.Sprintf("%d repositories, %d organizations, %d occurrences", i.RepositoryCount, i.OrganizationCount, i.OccurrenceCount), Provider: i.Provider, Fingerprint: i.Fingerprint, Incident: &i}
}

func EnvironmentChangedEvent(tenantID, repository, organization, workflow, job, commitSHA, detailsURL string, changes []string) model.NotificationEvent {
	now := time.Now().UTC()
	summary := fmt.Sprintf("%d CI environment changes detected: %s", len(changes), strings.Join(changes, "; "))
	h := sha256.Sum256([]byte(repository + "\x00" + workflow + "\x00" + job + "\x00" + strings.Join(changes, "\x00")))
	return model.NotificationEvent{
		ID:       "evt_environment_" + hex.EncodeToString(h[:8]) + "_" + fmt.Sprint(now.Unix()),
		TenantID: tenantID, Type: "environment_changed", DedupeKey: "environment:" + repository + ":" + workflow + ":" + job + ":" + hex.EncodeToString(h[:8]),
		OccurredAt: now, Severity: "minor", Title: "CI environment changed: " + repository, Summary: summary,
		Repository: repository, Organization: organization, Workflow: workflow, Job: job, CommitSHA: commitSHA, DetailsURL: detailsURL,
		Category: model.CategoryRunnerImageDrift, Attribution: model.AttributionExternal, Score: 70, ExternalityScore: 70, EvidenceStrength: 70, ExternalEvidenceScore: 70, Provider: "GitHub Actions", Operation: "runner-environment",
		Recommendation: "Review and pin tool versions before the environment change reaches critical workflows.",
	}
}

func FlakyTestEvent(st model.TestCaseStats, publicBaseURL string) model.NotificationEvent {
	now := time.Now().UTC()
	details := ""
	if publicBaseURL != "" {
		details = strings.TrimRight(publicBaseURL, "/") + "/?test=" + st.TestKey
	}
	return model.NotificationEvent{ID: fmt.Sprintf("evt_test_flaky_%s_%d", st.TestKey, now.Unix()), TenantID: st.TenantID, Type: "test_flaky", DedupeKey: "test_flaky:" + st.TestKey, OccurredAt: now, Severity: "minor", Title: "Flaky test detected: " + st.Name, Summary: fmt.Sprintf("%s has a %.1f flake score across %d runs. Likely cause: %s.", st.Name, st.FlakeScore, st.TotalRuns, st.PrimaryFlakeCause), Repository: st.Repository, DetailsURL: details, Category: model.CategoryTestFlake, Attribution: model.AttributionCode, Score: -int(st.FlakeScore), ExternalityScore: -int(st.FlakeScore), EvidenceStrength: int(st.FlakeScore), CodeEvidenceScore: int(st.FlakeScore), Provider: st.Framework, Operation: "test", Fingerprint: st.TestKey, Recommendation: "Assign an owner, reproduce the failure, and quarantine only while the root cause is under investigation."}
}

func TestEvent() model.NotificationEvent {
	now := time.Now().UTC()
	return model.NotificationEvent{ID: fmt.Sprintf("evt_test_%d", now.UnixNano()), TenantID: model.DefaultTenantID, Type: "test", DedupeKey: "", OccurredAt: now, Severity: "info", Title: "CI Radar notification test", Summary: "Your notification channel is configured correctly.", Repository: "example/repository", Category: model.CategoryNetworkFailure, Confidence: model.ConfidenceModerate, Score: 75, ExternalityScore: 75, EvidenceStrength: 75, ExternalEvidenceScore: 75, Provider: "example-provider", Operation: "connect", Recommendation: "No action is required."}
}
func analysisSeverity(r model.AnalysisResult) string {
	strength := model.EvidenceStrengthOf(r)
	if r.ProviderIncident && strength >= 90 {
		return "critical"
	}
	if strength >= 85 {
		return "major"
	}
	return "minor"
}
