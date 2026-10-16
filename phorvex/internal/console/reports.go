/*
 * Phorvex Console — curated REPORTS endpoint (P-DASHBOARD). Serves the on-disk evidence/
 * investor artifacts (COMPARISON.md, the benchmark reports, EFFECTIVENESS-PHORVEX.md, the P3
 * reports) dynamically from disk — read-only, whitelisted by id (no arbitrary path), so the
 * dashboard shows the real curated markdown rather than re-deriving or hardcoding it.
 */

package console

import (
	"os"
	"path/filepath"
	"strings"
)

type reportMeta struct {
	ID, Title, Group, rel string
}

// reportRegistry is the WHITELIST of curated reports (id -> relative path under Root). Serving by
// id (not a caller path) means there is no path-traversal surface.
func (c *Config) reportRegistry() []reportMeta {
	j := filepath.Join
	return []reportMeta{
		{"comparison", "Phorvex vs Without-Phorvex — head-to-head", "Comparison", "COMPARISON.md"},
		{"effectiveness", "Effectiveness — Phorvex (full evidence)", "Effectiveness", j("phorvex", "EFFECTIVENESS-PHORVEX.md")},
		{"bench-k8s", "Benchmark — K8s attack suite", "Benchmarks", j("build", "test-harness", "out-bench", "report.md")},
		{"bench-ai", "Benchmark — AI / inference suite", "Benchmarks", j("build", "test-harness", "out-ai-bench", "report.md")},
		{"bench-dollars", "Benchmark — cost / ROI", "Benchmarks", j("build", "test-harness", "out-bench", "report-dollars.md")},
		{"p3", "P3 — structural zero-day", "Zero-day", j("phorvex", "P3-REPORT.md")},
		{"p3deep", "P3-DEEP — zero-day frontier (full)", "Zero-day", j("build", "test-harness", "out-p3-full", "report.md")},
	}
}

// Reports returns the catalog with live existence + line counts (so the UI lists only real files).
func (c *Config) Reports() []map[string]any {
	out := []map[string]any{}
	for _, r := range c.reportRegistry() {
		lines, exists := 0, false
		if b, err := os.ReadFile(filepath.Join(c.Root, r.rel)); err == nil {
			exists = true
			lines = strings.Count(string(b), "\n")
		}
		out = append(out, map[string]any{"id": r.ID, "title": r.Title, "group": r.Group, "exists": exists, "lines": lines})
	}
	return out
}

// ReportContent returns one whitelisted report's live markdown (size-capped). ok=false if unknown
// id or the file is absent.
func (c *Config) ReportContent(id string) (title, content string, ok bool) {
	for _, r := range c.reportRegistry() {
		if r.ID != id {
			continue
		}
		b, err := os.ReadFile(filepath.Join(c.Root, r.rel))
		if err != nil {
			return r.Title, "", false
		}
		if len(b) > 1<<20 {
			b = b[:1<<20]
		}
		return r.Title, string(b), true
	}
	return "", "", false
}
