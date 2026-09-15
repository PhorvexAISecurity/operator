/*
 * Phorvex Console (P-DASHBOARD-3) — LIVE COMPUTATION layer. Replaces the previously
 * stated-from-report constants with numbers computed from real sources:
 *   - explainability  <- the real decision audit (explained / total decisions)
 *   - prevention      <- the harness c1-fast-attacker rows (objective-denied rate)
 *   - native actuator <- the real actuator.HandlerRegistry (completeness invariant)
 *   - recon-per-$     <- the live `phorvex --ablation` run (cached), NOT a constant
 * Nothing here is hardcoded; if a source is absent the value is omitted or labeled pending.
 */

package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audittransport"
)

// auditFile resolves the decision-audit JSONL (the same source the live SSE tails).
func (c *Config) auditFile() string {
	if c.AuditSource != nil {
		return "audit://live"
	}
	if c.AuditPath != "" {
		return c.AuditPath
	}
	for _, p := range []string{
		filepath.Join(c.Root, "phorvex", "bin", "console-audit.jsonl"),
		filepath.Join(c.HarnessDir, "console-audit.jsonl"),
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// RegistryView is the REAL native actuator registry + the completeness invariant — read
// from actuator.HandlerRegistry, not a hardcoded list.
type RegistryView struct {
	Names        []string `json:"names"`
	Generatable  []string `json:"generatable"`
	Missing      []string `json:"missing"`
	Orphans      []string `json:"orphans"`
	Count        int      `json:"count"`
	Generatables int      `json:"generatables"`
	Complete     bool     `json:"complete"`
}

func HandlerRegistryView() RegistryView {
	names := actuator.HandlerRegistry.Names()
	gen := []string{} // non-nil so empty marshals as [] not null (the Phase-1 lesson)
	for _, a := range actionset.GeneratableActions() {
		gen = append(gen, string(a))
	}
	miss := []string{}
	for _, a := range actuator.MissingHandlers() {
		miss = append(miss, string(a))
	}
	orphans := actuator.OrphanHandlers()
	if orphans == nil {
		orphans = []string{}
	}
	if names == nil {
		names = []string{}
	}
	return RegistryView{
		Names: names, Generatable: gen, Missing: miss, Orphans: orphans,
		Count: len(names), Generatables: len(gen), Complete: len(miss) == 0,
	}
}

// explainabilityFromAudit counts decisions that carry a machine explanation (a Reason or a
// SHAP attribution) vs total decisions — the REAL audit, not a stated 100%.
func explainabilityFromAudit(path string, source *audittransport.Client) (explained, total int, sourceErr error) {
	return explainabilityFromAuditContext(context.Background(), path, source)
}
func explainabilityFromAuditContext(parent context.Context, path string, source *audittransport.Client) (explained, total int, sourceErr error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	f, err := openDecisionSource(ctx, path, source)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	if source != nil {
		st, e := f.Stat()
		if e != nil {
			return 0, 0, e
		}
		if st.Size() > 16<<20 {
			return 0, 0, errors.New("full-range explainability unavailable: audit exceeds 16 MiB derived-reader budget; use paged history")
		}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		if e := ctx.Err(); e != nil {
			return 0, 0, e
		}
		var r struct {
			Kind        string `json:"kind"`
			Reason      string `json:"reason"`
			Attribution []any  `json:"attribution"`
		}
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Kind != "phorvex.decision" {
			continue
		}
		total++
		if r.Reason != "" || len(r.Attribution) > 0 {
			explained++
		}
	}
	if e := sc.Err(); e != nil {
		return 0, 0, e
	}
	if remote, ok := f.(interface{ Verify() error }); ok {
		if e := remote.Verify(); e != nil {
			return 0, 0, e
		}
	}
	return explained, total, nil
}

// preventionRows returns (prevented, n) for a scenario/defender from real harness rows:
// prevented = the attacker's oracle objective was DENIED (!OracleAchieved).
func preventionRows(rows []metricRow, scenario, defender string) (prevented, n int) {
	for _, m := range rows {
		if m.Scenario != scenario || m.Defender != defender || m.Skipped {
			continue
		}
		n++
		if !m.OracleAchieved {
			prevented++
		}
	}
	return
}
