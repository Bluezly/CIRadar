package analyzer

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

type Redactor struct {
	patterns       []redactPattern
	entropyPattern *regexp.Regexp
	entropyEnabled bool
}

type redactPattern struct {
	re          *regexp.Regexp
	replacement string
}

func NewRedactor() *Redactor {
	return NewRedactorWithPatterns(nil, true)
}

func NewRedactorWithPatterns(custom []string, entropyEnabled bool) *Redactor {
	patterns := []redactPattern{
		{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|token|basic)\s+)[^\s]+`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|credential)\s*[=:]\s*)[^\s,;]+`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)(\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`), `${1}[REDACTED]`},
		{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`), `[REDACTED_GITHUB_TOKEN]`},
		{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), `[REDACTED_GITHUB_TOKEN]`},
		{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `[REDACTED_AWS_KEY]`},
		{regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), `[REDACTED_PRIVATE_KEY]`},
		{regexp.MustCompile(`(?i)https?://[^\s/@:]+:[^\s/@]+@`), `https://[REDACTED]@`},
		{regexp.MustCompile(`(?i)(?:[A-Z]:\\Users\\|/home/|/Users/)[^\s/\\]+`), `[USER_HOME]`},
		{regexp.MustCompile(`\b[A-Fa-f0-9]{40,128}\b`), `[LONG_HEX]`},
		{regexp.MustCompile(`(?i)\b(?:sk|rk|pk)_[A-Za-z0-9_-]{20,}\b`), `[REDACTED_KEY]`},
		{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), `[REDACTED_JWT]`},
	}
	for _, raw := range custom {
		if re, err := regexp.Compile(raw); err == nil {
			patterns = append(patterns, redactPattern{re: re, replacement: `[REDACTED_CUSTOM]`})
		}
	}
	return &Redactor{patterns: patterns, entropyPattern: regexp.MustCompile(`[A-Za-z0-9_~+/.=-]{32,256}`), entropyEnabled: entropyEnabled}
}

func (r *Redactor) Redact(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	for _, p := range r.patterns {
		s = p.re.ReplaceAllString(s, p.replacement)
	}
	if r.entropyEnabled {
		s = r.redactHighEntropy(s)
	}
	return s
}

func (r *Redactor) redactHighEntropy(s string) string {
	indexes := r.entropyPattern.FindAllStringIndex(s, -1)
	if len(indexes) == 0 {
		return s
	}
	var out strings.Builder
	last := 0
	for _, span := range indexes {
		candidate := s[span[0]:span[1]]
		if !looksLikeSecret(candidate, s, span[0], span[1]) {
			continue
		}
		out.WriteString(s[last:span[0]])
		out.WriteString("[REDACTED_HIGH_ENTROPY]")
		last = span[1]
	}
	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

func looksLikeSecret(candidate, source string, start, end int) bool {
	if len(candidate) < 32 || allHex(candidate) {
		return false
	}
	classes := 0
	upper, lower, digit, symbol := false, false, false, false
	for _, r := range candidate {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	for _, value := range []bool{upper, lower, digit, symbol} {
		if value {
			classes++
		}
	}
	if classes < 3 || shannonEntropy(candidate) < 4.1 {
		return false
	}
	left := start - 48
	if left < 0 {
		left = 0
	}
	right := end + 48
	if right > len(source) {
		right = len(source)
	}
	context := strings.ToLower(source[left:right])
	for _, word := range []string{"token", "secret", "password", "credential", "authorization", "bearer", "api_key", "apikey", "private_key", "access_key"} {
		if strings.Contains(context, word) {
			return true
		}
	}
	return len(candidate) >= 48 && classes == 4
}

func shannonEntropy(value string) float64 {
	counts := map[rune]int{}
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	if total == 0 {
		return 0
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func allHex(value string) bool {
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
