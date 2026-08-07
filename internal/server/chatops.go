package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/model"
)

func (s *Server) slackChatOps(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ChatOps.Enabled || s.cfg.ChatOps.SlackSigningSecret == "" {
		writeError(w, 404, "chatops disabled")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	ts := r.Header.Get("X-Slack-Request-Timestamp")
	n, e := strconv.ParseInt(ts, 10, 64)
	if e != nil || time.Since(time.Unix(n, 0)) > 5*time.Minute || time.Until(time.Unix(n, 0)) > time.Minute {
		writeError(w, 401, "stale Slack request")
		return
	}
	base := "v0:" + ts + ":" + string(body)
	mac := hmac.New(sha256.New, []byte(s.cfg.ChatOps.SlackSigningSecret))
	_, _ = mac.Write([]byte(base))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Slack-Signature"))) {
		writeError(w, 401, "invalid Slack signature")
		return
	}
	form, e := url.ParseQuery(string(body))
	if e != nil {
		writeError(w, 400, "invalid form")
		return
	}
	var payload struct {
		Type string `json:"type"`
		Team struct {
			ID string `json:"id"`
		} `json:"team"`
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
		ResponseURL string `json:"response_url"`
	}
	if e := json.Unmarshal([]byte(form.Get("payload")), &payload); e != nil {
		writeError(w, 400, "invalid Slack payload")
		return
	}
	if !allowed(payload.User.ID, s.cfg.ChatOps.SlackAllowedUsers) || !allowed(payload.Team.ID, s.cfg.ChatOps.SlackAllowedTeams) {
		writeError(w, 403, "Slack user or team is not allowed")
		return
	}
	tenant, ok := s.slackTenant(payload.Team.ID)
	if !ok {
		writeError(w, 403, "Slack workspace is not bound to a tenant")
		return
	}
	if len(payload.Actions) == 0 {
		writeError(w, 400, "missing action")
		return
	}
	deliveryHash := sha256.Sum256(append([]byte(ts+":"), body...))
	deliveryID := "chatops:slack:" + hex.EncodeToString(deliveryHash[:16])
	fresh, e := s.store.RecordDelivery(r.Context(), deliveryID, "chatops.slack")
	if e != nil {
		writeError(w, http.StatusInternalServerError, "could not record Slack request")
		return
	}
	if !fresh {
		writeJSON(w, http.StatusOK, map[string]any{"response_type": "ephemeral", "text": "CI Radar: duplicate request ignored"})
		return
	}
	msg, e := s.performChatActionForTenant(r, payload.Actions[0].Value, firstNonEmpty(payload.User.Username, payload.User.ID), tenant)
	if e != nil {
		writeJSON(w, 200, map[string]any{"response_type": "ephemeral", "text": "CI Radar: " + e.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"response_type": "in_channel", "replace_original": false, "text": msg})
}

func (s *Server) teamsChatOps(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ChatOps.Enabled || s.cfg.ChatOps.TeamsSigningSecret == "" {
		writeError(w, 404, "chatops disabled")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	key, err := base64.StdEncoding.DecodeString(s.cfg.ChatOps.TeamsSigningSecret)
	if err != nil {
		key = []byte(s.cfg.ChatOps.TeamsSigningSecret)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	expected := "HMAC " + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(r.Header.Get("Authorization"))) {
		writeError(w, 401, "invalid Teams signature")
		return
	}
	var payload struct {
		ID        string    `json:"id"`
		Timestamp time.Time `json:"timestamp"`
		Text      string    `json:"text"`
		From      struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"from"`
		Conversation struct {
			ID string `json:"id"`
		} `json:"conversation"`
	}
	if e := json.Unmarshal(body, &payload); e != nil {
		writeError(w, 400, "invalid Teams payload")
		return
	}
	if payload.ID == "" || payload.Timestamp.IsZero() || time.Since(payload.Timestamp) > 5*time.Minute || time.Until(payload.Timestamp) > time.Minute {
		writeError(w, http.StatusUnauthorized, "stale or unidentified Teams request")
		return
	}
	if !allowed(payload.From.ID, s.cfg.ChatOps.TeamsAllowedUsers) {
		writeError(w, 403, "Teams user is not allowed")
		return
	}
	fresh, e := s.store.RecordDelivery(r.Context(), "chatops:teams:"+payload.ID, "chatops.teams")
	if e != nil {
		writeError(w, http.StatusInternalServerError, "could not record Teams request")
		return
	}
	if !fresh {
		writeJSON(w, http.StatusOK, map[string]any{"type": "message", "text": "CI Radar: duplicate request ignored"})
		return
	}
	value, e := teamsCommand(payload.Text, s.cfg.ChatOps.DefaultTenant)
	if e != nil {
		writeJSON(w, 200, map[string]any{"type": "message", "text": "CI Radar: " + e.Error()})
		return
	}
	msg, e := s.performChatAction(r, value, firstNonEmpty(payload.From.Name, payload.From.ID))
	if e != nil {
		msg = "CI Radar: " + e.Error()
	}
	writeJSON(w, 200, map[string]any{"type": "message", "text": msg})
}

func teamsCommand(text, tenant string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(text, "@CI Radar")))
	if len(fields) < 2 {
		return "", fmt.Errorf("use ack <fingerprint>, resolve <fingerprint>, or quarantine <test-key>")
	}
	action := strings.ToLower(fields[0])
	switch action {
	case "ack", "acknowledge", "resolve":
		if action == "acknowledge" {
			action = "ack"
		}
		return tenant + "|" + action + "|" + fields[1], nil
	case "quarantine":
		return tenant + "|quarantine|" + fields[1], nil
	default:
		return "", fmt.Errorf("unsupported command %q", action)
	}
}
func allowed(v string, list []string) bool {
	if len(list) == 0 {
		return true
	}
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}
func (s *Server) slackTenant(teamID string) (string, bool) {
	teamID = strings.ToLower(strings.TrimSpace(teamID))
	if teamID == "" {
		return "", false
	}
	tenant, ok := s.cfg.ChatOps.SlackTeamTenants[teamID]
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	return tenant, ok && tenant != ""
}

func (s *Server) performChatAction(r *http.Request, value, actor string) (string, error) {
	return s.performChatActionForTenant(r, value, actor, "")
}

func (s *Server) performChatActionForTenant(r *http.Request, value, actor, boundTenant string) (string, error) {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid action")
	}
	tenant, action, id := strings.ToLower(strings.TrimSpace(parts[0])), parts[1], parts[2]
	boundTenant = strings.ToLower(strings.TrimSpace(boundTenant))
	if boundTenant != "" {
		if tenant != "" && tenant != boundTenant {
			return "", fmt.Errorf("action tenant does not match Slack workspace")
		}
		tenant = boundTenant
	} else if tenant == "" {
		tenant = strings.ToLower(strings.TrimSpace(s.cfg.ChatOps.DefaultTenant))
	}
	switch action {
	case "ack":
		if !s.cfg.ChatOps.AllowAcknowledge {
			return "", fmt.Errorf("acknowledge is disabled")
		}
		inc, e := s.store.UpdateIncidentState(r.Context(), tenant, id, "acknowledged", actor, "ChatOps")
		if e != nil {
			return "", e
		}
		if err := s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: tenant, Actor: actor, Role: model.RoleOperator, Action: "incident.acknowledge.chatops", Resource: "incident", ResourceID: id, Metadata: map[string]string{"channel": "chatops"}}); err != nil {
			s.log.Error("record ChatOps acknowledgement audit failed", "tenant_id", tenant, "incident_id", id, "error", err)
		}
		return "CI Radar acknowledged incident " + inc.Title, nil
	case "resolve":
		if !s.cfg.ChatOps.AllowResolve {
			return "", fmt.Errorf("resolve is disabled")
		}
		inc, e := s.store.UpdateIncidentState(r.Context(), tenant, id, "resolved", actor, "ChatOps")
		if e != nil {
			return "", e
		}
		if err := s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: tenant, Actor: actor, Role: model.RoleOperator, Action: "incident.resolve.chatops", Resource: "incident", ResourceID: id, Metadata: map[string]string{"channel": "chatops"}}); err != nil {
			s.log.Error("record ChatOps resolution audit failed", "tenant_id", tenant, "incident_id", id, "error", err)
		}
		return "CI Radar resolved incident " + inc.Title, nil
	case "quarantine":
		if !s.cfg.ChatOps.AllowQuarantine {
			return "", fmt.Errorf("quarantine is disabled")
		}
		d := parseDays(s.cfg.ChatOps.QuarantineDuration)
		q, e := s.store.SetTestQuarantine(r.Context(), model.TestQuarantine{TenantID: tenant, TestKey: id, Owner: actor, Reason: "ChatOps quarantine", CreatedBy: actor, ExpiresAt: time.Now().UTC().Add(d)})
		if e != nil {
			return "", e
		}
		if err := s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: tenant, Actor: actor, Role: model.RoleOperator, Action: "test.quarantine.chatops", Resource: "test", ResourceID: id}); err != nil {
			s.log.Error("record ChatOps quarantine audit failed", "tenant_id", tenant, "test_key", id, "error", err)
		}
		return "CI Radar quarantined test until " + q.ExpiresAt.Format(time.RFC3339), nil
	default:
		return "", fmt.Errorf("unsupported action %q", action)
	}
}
func parseDays(v string) time.Duration {
	v = strings.TrimSpace(strings.ToLower(v))
	if strings.HasSuffix(v, "d") {
		n, _ := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if n > 0 && n <= 90 {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	if d, e := time.ParseDuration(v); e == nil && d > 0 {
		return d
	}
	return 7 * 24 * time.Hour
}
