package analyzer

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Redactor struct {
	patterns                []redactPattern
	entropyPattern          *regexp.Regexp
	encodedPattern          *regexp.Regexp
	multilineEncodedPattern *regexp.Regexp
	entropyEnabled          bool
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
		{regexp.MustCompile(`(?is)((?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|credential)\s*[=:]\s*["'])([^"']{1,1000})(["'])`), `${1}[REDACTED_MULTILINE]${3}`},
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
		{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`), `[REDACTED_GOOGLE_API_KEY]`},
		{regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), `[REDACTED_SLACK_TOKEN]`},
		{regexp.MustCompile(`\bnpm_[0-9A-Za-z]{20,}\b`), `[REDACTED_NPM_TOKEN]`},
		{regexp.MustCompile(`\bpypi-[0-9A-Za-z_-]{20,}\b`), `[REDACTED_PYPI_TOKEN]`},
		{regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b`), `[REDACTED_STRIPE_KEY]`},
	}
	for _, raw := range custom {
		if re, err := regexp.Compile(raw); err == nil {
			patterns = append(patterns, redactPattern{re: re, replacement: `[REDACTED_CUSTOM]`})
		}
	}
	return &Redactor{
		patterns:                patterns,
		entropyPattern:          regexp.MustCompile(`[A-Za-z0-9_~+/.=-]{32,256}`),
		encodedPattern:          regexp.MustCompile(`[A-Za-z0-9+/_-]{32,998}={0,2}`),
		multilineEncodedPattern: regexp.MustCompile(`(?:[A-Za-z0-9+/_-]{16,998}[ \t\r\n]+)+[A-Za-z0-9+/_-]{4,998}={0,2}`),
		entropyEnabled:          entropyEnabled,
	}
}

func (r *Redactor) Redact(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	for _, p := range r.patterns {
		s = p.re.ReplaceAllString(s, p.replacement)
	}
	s = r.redactEncodedSecrets(s)
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

// ResidualSecretRisk performs a conservative second pass intended for outbound
// LLM payloads. A positive result should block transmission rather than trying
// to guess whether an unfamiliar high-entropy value is harmless.
func (r *Redactor) ResidualSecretRisk(s string) bool {
	if r == nil {
		r = NewRedactor()
	}
	lower := strings.ToLower(s)
	for _, marker := range []string{"-----begin private key-----", "-----begin rsa private key-----", "authorization: bearer ", "authorization: basic ", "github_pat_", "ghp_", "xoxb-", "pypi-", "npm_"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, span := range r.entropyPattern.FindAllStringIndex(s, -1) {
		if looksLikeSecret(s[span[0]:span[1]], s, span[0], span[1]) {
			return true
		}
	}
	return r.containsEncodedSecret(s)
}

func (r *Redactor) redactEncodedSecrets(s string) string {
	if r.multilineEncodedPattern != nil {
		s = redactEncodedMatches(s, r.multilineEncodedPattern)
	}
	return redactEncodedMatches(s, r.encodedPattern)
}

func redactEncodedMatches(s string, pattern *regexp.Regexp) string {
	if pattern == nil {
		return s
	}
	indexes := pattern.FindAllStringIndex(s, -1)
	if len(indexes) == 0 {
		return s
	}
	var out strings.Builder
	last := 0
	for _, span := range indexes {
		candidate := s[span[0]:span[1]]
		if !encodedSecret(candidate) {
			continue
		}
		out.WriteString(s[last:span[0]])
		out.WriteString("[REDACTED_ENCODED_SECRET]")
		last = span[1]
	}
	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

func (r *Redactor) containsEncodedSecret(s string) bool {
	for _, pattern := range []*regexp.Regexp{r.multilineEncodedPattern, r.encodedPattern} {
		if pattern == nil {
			continue
		}
		for _, candidate := range pattern.FindAllString(s, -1) {
			if encodedSecret(candidate) {
				return true
			}
		}
	}
	return false
}

func encodedSecret(candidate string) bool {
	clean := compactEncodedValue(candidate)
	if len(clean) < 32 || len(clean) > 4096 {
		return false
	}
	decoders := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, decoder := range decoders {
		decoded, err := decoder.DecodeString(clean)
		if err != nil || len(decoded) < 12 {
			continue
		}
		if decodedSecret(decoded) {
			return true
		}
	}
	return false
}

func compactEncodedValue(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
}

func decodedSecret(decoded []byte) bool {
	if !utf8.Valid(decoded) {
		return false
	}
	value := string(decoded)
	text := strings.ToLower(value)
	for _, marker := range []string{
		"private key", "authorization:", "bearer ", "password=", "password:", "secret=", "secret:",
		"api_key", "apikey", "client_secret", "access_token", "refresh_token", "aws_secret_access_key",
		"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "xoxb-", "xoxp-", "npm_", "pypi-", "sk_live_", "rk_live_",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	// JSON-encoded credentials frequently have quoted sensitive keys.
	if strings.Contains(text, `"`) && (strings.Contains(text, `"token"`) || strings.Contains(text, `"password"`) || strings.Contains(text, `"secret"`) || strings.Contains(text, `"private_key"`) || strings.Contains(text, `"client_secret"`)) {
		return true
	}
	// A decoded printable, random-looking value near no labels is still likely a
	// credential when it has the shape of an opaque API key. Keep this threshold
	// deliberately high to avoid erasing ordinary base64-encoded log text.
	trimmed := strings.TrimSpace(value)
	return len(trimmed) >= 40 && len(trimmed) <= 512 && looksLikeStandaloneOpaqueSecret(trimmed)
}

func looksLikeStandaloneOpaqueSecret(value string) bool {
	classes := 0
	upper, lower, digit, symbol := false, false, false, false
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
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
	for _, present := range []bool{upper, lower, digit, symbol} {
		if present {
			classes++
		}
	}
	return classes >= 3 && shannonEntropy(value) >= 4.3
}
