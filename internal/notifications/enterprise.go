package notifications

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/model"
)

func teamsPayload(ev model.NotificationEvent) map[string]any {
	facts := []any{
		map[string]any{"title": "Repository", "value": ev.Repository},
		map[string]any{"title": "Category", "value": string(ev.Category)},
		map[string]any{"title": "Attribution", "value": string(ev.Attribution)},
		map[string]any{"title": "Confidence", "value": string(ev.Confidence)},
		map[string]any{"title": "Score", "value": fmt.Sprintf("%d/100", ev.Score)},
	}
	body := []any{
		map[string]any{"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": truncate(ev.Title, 240), "wrap": true},
		map[string]any{"type": "TextBlock", "text": truncate(ev.Summary, 2500), "wrap": true},
		map[string]any{"type": "FactSet", "facts": facts},
	}
	if ev.Recommendation != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": "Recommended action: " + truncate(ev.Recommendation, 1200), "wrap": true, "weight": "Bolder"})
	}
	card := map[string]any{"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": body}
	if ev.DetailsURL != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open CI Radar", "url": ev.DetailsURL}}
	}
	return map[string]any{"type": "message", "attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": nil, "content": card}}}
}

func pagerDutyPayload(ch config.NotificationChannel, ev model.NotificationEvent) map[string]any {
	action := "trigger"
	if ev.Type == "incident_resolved" {
		action = "resolve"
	}
	out := map[string]any{"routing_key": ch.RoutingKey, "event_action": action, "dedup_key": nonEmpty(ev.DedupeKey, ev.ID)}
	if action == "trigger" {
		out["payload"] = map[string]any{
			"summary":        truncate(ev.Title+": "+ev.Summary, 1024),
			"source":         nonEmpty(ev.Repository, nonEmpty(ev.Provider, "ci-radar")),
			"severity":       pagerDutySeverity(ev.Severity),
			"component":      ev.Repository,
			"group":          ev.Organization,
			"class":          string(ev.Category),
			"custom_details": ev,
		}
		if ev.DetailsURL != "" {
			out["links"] = []any{map[string]any{"href": ev.DetailsURL, "text": "Open CI Radar"}}
		}
	}
	return out
}

func pagerDutySeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "major":
		return "error"
	case "minor":
		return "warning"
	default:
		return "info"
	}
}

func opsgenieEndpointAndPayload(ch config.NotificationChannel, ev model.NotificationEvent) (string, map[string]any) {
	base := strings.TrimRight(ch.URL, "/")
	if base == "" {
		base = "https://api.opsgenie.com"
	}
	alias := nonEmpty(ev.DedupeKey, ev.ID)
	if ev.Type == "incident_resolved" {
		return base + "/v2/alerts/" + urlPathEscape(alias) + "/close?identifierType=alias", map[string]any{"note": truncate(ev.Summary, 25000), "source": "CI Radar"}
	}
	payload := map[string]any{
		"message": truncate(ev.Title, 130), "alias": alias, "description": truncate(plainText(ev), 15000),
		"priority": opsgeniePriority(ev.Severity), "source": "CI Radar",
		"details": map[string]string{"repository": ev.Repository, "category": string(ev.Category), "confidence": string(ev.Confidence), "score": strconv.Itoa(ev.Score), "provider": ev.Provider},
	}
	return base + "/v2/alerts", payload
}

func opsgeniePriority(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "P1"
	case "major":
		return "P2"
	case "minor":
		return "P3"
	default:
		return "P4"
	}
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
func urlPathEscape(s string) string {
	return strings.NewReplacer("%", "%25", "/", "%2F", "?", "%3F", "#", "%23", " ", "%20").Replace(s)
}

func sendEmail(ctx context.Context, ch config.NotificationChannel, ev model.NotificationEvent) error {
	timeout := ch.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(ch.SMTPHost, strconv.Itoa(ch.SMTPPort))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	tlsCfg := &tls.Config{ServerName: ch.SMTPHost, MinVersion: tls.VersionTLS12}
	if ch.SMTPMode == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	client, err := smtp.NewClient(conn, ch.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()
	if ch.SMTPMode == "starttls" {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if ch.SMTPUsername != "" {
		auth := smtp.PlainAuth("", ch.SMTPUsername, ch.SMTPPassword, ch.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(ch.EmailFrom); err != nil {
		return err
	}
	for _, recipient := range ch.EmailTo {
		if err := client.Rcpt(strings.TrimSpace(recipient)); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	msg := buildEmailMessage(ch, ev)
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildEmailMessage(ch config.NotificationChannel, ev model.NotificationEvent) []byte {
	h := textproto.MIMEHeader{}
	h.Set("From", ch.EmailFrom)
	h.Set("To", strings.Join(ch.EmailTo, ", "))
	h.Set("Subject", "[CI Radar] "+truncate(ev.Title, 160))
	h.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
	h.Set("MIME-Version", "1.0")
	h.Set("Content-Type", "text/plain; charset=UTF-8")
	h.Set("Content-Transfer-Encoding", "8bit")
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	b.WriteString(plainText(ev))
	b.WriteString("\r\n")
	return []byte(b.String())
}
