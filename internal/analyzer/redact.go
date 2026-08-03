package analyzer

import (
	"regexp"
	"strings"
)

type Redactor struct {
	patterns []redactPattern
}

type redactPattern struct {
	re          *regexp.Regexp
	replacement string
}

func NewRedactor() *Redactor {
	return &Redactor{patterns: []redactPattern{
		{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\s*[=:]\s*)[^\s,;]+`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)(\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`), `${1}[REDACTED]`},
		{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`), `[REDACTED_GITHUB_TOKEN]`},
		{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), `[REDACTED_GITHUB_TOKEN]`},
		{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `[REDACTED_AWS_KEY]`},
		{regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), `[REDACTED_PRIVATE_KEY]`},
		{regexp.MustCompile(`(?i)https?://[^\s/@:]+:[^\s/@]+@`), `https://[REDACTED]@`},
		{regexp.MustCompile(`(?i)(?:[A-Z]:\\Users\\|/home/|/Users/)[^\s/\\]+`), `[USER_HOME]`},
		{regexp.MustCompile(`\b[A-Fa-f0-9]{40,64}\b`), `[LONG_HEX]`},
		{regexp.MustCompile(`(?i)\b(?:sk|rk|pk)_[A-Za-z0-9_-]{20,}\b`), `[REDACTED_KEY]`},
	}}
}

func (r *Redactor) Redact(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	for _, p := range r.patterns {
		s = p.re.ReplaceAllString(s, p.replacement)
	}
	return s
}
