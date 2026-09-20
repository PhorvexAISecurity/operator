package model

import (
	"regexp"
	"strings"
	"testing"
)

var (
	frozenAuthorizationPattern = regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*[^\r\n]+`)
	frozenBearerPattern        = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]+`)
	frozenSecretKVPattern      = regexp.MustCompile(`(?i)\b(x-api-key|api[_-]?key|password|passwd|token|credential)\s*[:=]\s*[^\s,;]+`)
	frozenURIUserInfoPattern   = regexp.MustCompile(`://[^/@\s]+:[^/@\s]+@`)
)

// frozenOriginalRedactTraceString is the pre-optimization four-regexp sequence.
// Keep it independent of the production regexp values so the differential test
// detects changes to either the guards or the expressions and replacements.
func frozenOriginalRedactTraceString(s string) string {
	s = frozenAuthorizationPattern.ReplaceAllString(s, "Authorization:[REDACTED]")
	s = frozenBearerPattern.ReplaceAllString(s, "Bearer [REDACTED]")
	s = frozenURIUserInfoPattern.ReplaceAllString(s, "://[REDACTED]@")
	return frozenSecretKVPattern.ReplaceAllStringFunc(s, func(match string) string {
		if i := strings.IndexAny(match, ":="); i >= 0 {
			return strings.TrimSpace(match[:i]) + string(match[i]) + "[REDACTED]"
		}
		return "[REDACTED]"
	})
}

func redactionDifferentialCorpus() []string {
	corpus := []string{
		"",
		"decision-7fbe tenant-blue ns-a/pod-17 selected feasible",
		"registry.example/phorvex@sha256-deadbeef",
		"namespace/name:tag",
		"a=b without a credential key",
		"Authorization: Basic dXNlcjpwYXNz",
		"AUTHORIZATION = Bearer abc.DEF-123",
		"prefix Authorization:\tToken secret-value suffix",
		"Bearer abc123",
		"BEARER\tabc.DEF_123-~+/=",
		"bearer\nline-token",
		"bearer\vnot-regexp-whitespace",
		"password=hunter2 token:abc123 credential = value",
		"x-api-key: first; api_key=second, api-key:third",
		"passwd = first password=second token=third credential:fourth",
		"https://user:registry-password@registry.example/phorvex:tag",
		"prefix ssh://first:one@example.test/path https://second:two@example.test/end",
		"https://user@example.test/no-password",
		"notauthorization: visible notbearer secret",
		"Authorization: Bearer abc password=hunter2",
		"Bearer password=hunter2 token=still-visible-to-ordering",
		"password=https://user:pass@example.test/path",
		"https://token=value:pass@example.test/path",
		"paſſword=unicode-long-s-secret",
		"api-Key=unicode-kelvin-secret",
		"PaſſWoRd : mixed-unicode-secret",
		string([]byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '=', 0xff, 0xfe, 'x'}),
		string([]byte{0xff, 'B', 'e', 'a', 'r', 'e', 'r', ' ', 'a', 'b', 'c', 0x80}),
	}

	// Put every ASCII byte into raw text and into each pattern boundary. This
	// covers separators, regex whitespace/control bytes and word boundaries.
	for value := 0; value < 128; value++ {
		separator := string([]byte{byte(value)})
		corpus = append(corpus,
			"left"+separator+"right",
			"Authorization"+separator+": secret\nrest",
			"Bearer"+separator+"abc.DEF-123",
			"password"+separator+"=secret",
			"https://user"+separator+":pass@example.test/path",
		)
	}

	// Production-shaped combinations ensure replacements that remove a later
	// match retain the original ordered behavior.
	parts := []string{
		"decision-uid", "Authorization: Basic dXNlcjpwYXNz", "Bearer abc123",
		"password=hunter2", "https://user:pass@example.test/path",
		"tenant/ns/pod", "api_key=second", "plain-reason",
	}
	for _, left := range parts {
		for _, right := range parts {
			corpus = append(corpus, left+" | "+right)
		}
	}
	return corpus
}

func TestRedactTraceStringMatchesFrozenOriginal(t *testing.T) {
	for index, input := range redactionDifferentialCorpus() {
		want := frozenOriginalRedactTraceString(input)
		if got := redactTraceString(input); got != want {
			t.Fatalf("case %d input %q:\n got %q\nwant %q", index, input, got, want)
		}
	}
}

func TestRedactTraceStringRetainsUnicodeCaseFoldMatches(t *testing.T) {
	for _, input := range []string{
		"paſſword=long-s-secret",
		"api-Key=kelvin-secret",
	} {
		got := redactTraceString(input)
		if got == input || strings.Contains(got, "secret") {
			t.Fatalf("Unicode case-fold credential was not redacted: input=%q output=%q", input, got)
		}
	}
}

var redactTraceStringBenchmarkSink string

func BenchmarkRedactTraceString(b *testing.B) {
	corpus := redactionDifferentialCorpus()
	b.Run("guarded", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			redactTraceStringBenchmarkSink = redactTraceString(corpus[i%len(corpus)])
		}
	})
	b.Run("frozen-original", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			redactTraceStringBenchmarkSink = frozenOriginalRedactTraceString(corpus[i%len(corpus)])
		}
	})
}
