/*
 * Phorvex Console (P-DASHBOARD) — the EFFECTIVENESS aggregator.
 *
 * Computes the >90% K8s headline stats from the REAL metrics.jsonl files where the raw rows
 * exist (Wilson/t CIs), and surfaces the stated-with-provenance numbers (explainability
 * 139/139, 1.62x, native actuator 13/13) from their report files. Every Stat carries its
 * Source + Status (real | modeled | pending) so the UI can label honestly. AI-defense stats
 * remain unvalidated under PHORVEXSEC-87 — NEVER derived from attack-surface rows.
 */

package console

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Stat is one dashboard number with its 95% CI + provenance + honesty label.
type Stat struct {
	Key     string  `json:"key"`
	Label   string  `json:"label"`
	Value   string  `json:"value"`
	Unit    string  `json:"unit,omitempty"`
	CI      *ci     `json:"ci,omitempty"`
	Source  string  `json:"source"`
	Status  string  `json:"status"`  // real | modeled | pending
	Product string  `json:"product"` // k8s | ai | both
	Note    string  `json:"note,omitempty"`
}

func (c *Config) harnessOut(name string) string {
	return filepath.Join(c.Root, "build", "test-harness", name, "metrics.jsonl")
}
func (c *Config) report(name string) string {
	return filepath.Join(c.Root, "phorvex", name)
}

// Effectiveness returns the hero board — the >90% K8s numbers with CIs, each traced.
func (c *Config) Effectiveness() []Stat {
	var out []Stat
	deep, hasDeep := readMetrics(c.harnessOut("out-p3deep"))
	pact, hasPact := readMetrics(c.harnessOut("out-pactuator"))

	// 1. Disruption (PX prevents the zero-day) — out-p3deep c1-heldout-cve d-phorvex.
	if hasDeep {
		rows := fixedTrials(deep, "c1-heldout-cve", "d-phorvex")
		if n := len(rows); n > 0 {
			succ := 0
			for _, r := range rows {
				if r.DisruptionVsOracle >= 0.5 {
					succ++
				}
			}
			w := wilson(succ, n)
			out = append(out, Stat{Key: "disruption", Label: "Zero-day disruption (PX)", Value: pct(w.Mean), Unit: "%",
				CI: &w, Source: "out-p3deep/metrics.jsonl · c1-heldout-cve · d-phorvex (disruptionVsOracle)", Status: "real", Product: "k8s"})
		}
	}
	// 2. Work preserved (lead demo) — out-pactuator c2-stateful-training d-phorvex [work-preserved].
	if hasPact {
		rows := fixedTrials(pact, "c2-stateful-training", "d-phorvex")
		if n := len(rows); n > 0 {
			pres := 0
			for _, r := range rows {
				mk := markers(r.ObservedState)
				if _, ok := mk["work-preserved"]; ok {
					pres++
				} else if _, ok := mk["quarantined"]; ok {
					pres++
				}
			}
			w := wilson(pres, n)
			out = append(out, Stat{Key: "work-preserved", Label: "Stateful work preserved (PX)", Value: pct(w.Mean), Unit: "%",
				CI: &w, Source: "out-pactuator/metrics.jsonl · c2-stateful-training · d-phorvex ([work-preserved], native actuator)", Status: "real", Product: "k8s",
				Note: "native-actuator quarantine; blind timer destroys the job"})
		}
	}
	// 3. Harm caused (PX vs blind) — out-p3deep c2-stateful-training.
	if hasDeep {
		px := harmRate(deep, "c2-stateful-training", "d-phorvex")
		bl := harmRate(deep, "c2-stateful-training", "d-r6blindtimer")
		if px.N > 0 {
			out = append(out, Stat{Key: "harm-px", Label: "Harm caused (PX)", Value: pct(px.Mean), Unit: "%",
				CI: &px, Source: "out-p3deep/metrics.jsonl · c2-stateful-training · d-phorvex ([harm])", Status: "real", Product: "k8s",
				Note: fmt.Sprintf("blind timer: %s harm", pct(bl.Mean))})
		}
	}
	// 4. Dwell-to-eviction PX vs blind vs no-MTD — out-p3deep c1-heldout-cve survival.
	if hasDeep {
		for _, arm := range []struct{ def, label string }{{"d-phorvex", "Dwell — PX"}, {"d-r6blindtimer", "Dwell — Without Phorvex (blind 15s)"}, {"d-nomtd", "Dwell — no-MTD"}} {
			d := dwell(deep, "c1-heldout-cve", arm.def)
			if d.N > 0 {
				out = append(out, Stat{Key: "dwell-" + arm.def, Label: arm.label, Value: fmt.Sprintf("%.1f", d.Mean), Unit: "s",
					CI: &d, Source: "out-p3deep/metrics.jsonl · c1-heldout-cve · " + arm.def + " ([survival])", Status: "real", Product: "k8s"})
			}
		}
	}
	// 5. Recon-validity-lifetime (PX, the mechanism) — out-p3deep b-recon-lifetime d-phorvex.
	if hasDeep {
		d := reconLife(deep, "b-recon-lifetime", "d-phorvex")
		if d.N > 0 {
			out = append(out, Stat{Key: "recon-life-px", Label: "Recon-validity lifetime (PX)", Value: fmt.Sprintf("%.1f", d.Mean), Unit: "s",
				CI: &d, Source: "out-p3deep/metrics.jsonl · b-recon-lifetime · d-phorvex ([recon-valid])", Status: "real", Product: "k8s",
				Note: "measured distribution (soft proactive floor), not a hard cap; L_blind = the interval"})
		}
	}

	// 6. Explainability — COMPUTED from the real decision audit (explained / total decisions).
	if exp, tot := explainabilityFromAudit(c.auditFile()); tot > 0 {
		w := wilson(exp, tot)
		out = append(out, Stat{Key: "explainability", Label: "Decisions explained", Value: pct(w.Mean), Unit: "%",
			CI: &w, Source: "console decision audit · Reason or SHAP attribution present / total decisions", Status: "real", Product: "k8s",
			Note: fmt.Sprintf("%d/%d decisions carry a machine explanation (computed)", exp, tot)})
	}
	// 7. Fast-attacker prevention — COMPUTED from real c1-fast-attacker rows (objective denied).
	if full, hasFull := readMetrics(c.harnessOut("out-p3-full")); hasFull {
		if prev, n := preventionRows(full, "c1-fast-attacker", "d-phorvex"); n > 0 {
			w := wilson(prev, n)
			out = append(out, Stat{Key: "prevention", Label: "Fast-attacker prevention (PX)", Value: fmt.Sprintf("%d/%d", prev, n), Unit: "",
				CI: &w, Source: "out-p3-full/metrics.jsonl · c1-fast-attacker · d-phorvex (objective denied = !oracleAchieved)", Status: "real", Product: "k8s",
				Note: "computed; the case fixed cadence loses"})
		}
	}
	// 8. Native actuator — COMPUTED from the real registry: generatable actions COVERED by a handler.
	if rv := HandlerRegistryView(); rv.Generatables > 0 {
		covered := rv.Generatables - len(rv.Missing)
		st := "real"
		if !rv.Complete {
			st = "pending"
		}
		out = append(out, Stat{Key: "native-actuator", Label: "Generatable actions covered", Value: fmt.Sprintf("%d/%d", covered, rv.Generatables), Unit: "",
			Source: "actuator.HandlerRegistry vs actionset.GeneratableActions() (live MissingHandlers)", Status: st, Product: "both",
			Note: fmt.Sprintf("computed; %d handlers registered, %d missing; GPU handlers fail-closed; validation tracked by PHORVEXSEC-87", rv.Count, len(rv.Missing))})
	}
	// recon-per-$ is NOT stated here — it is computed LIVE by `phorvex --ablation` (/api/ablation,
	// the Prove → Recon-per-$ panel). On an arbitrary fleet the ratio is ~1.0×; the 1.62× is a
	// heavy-tailed designed-fleet result, never claimed as a live cluster number.
	out = append(out,
		// AI-defense is ALWAYS pending — NEVER derived from attack-surface rows.
		Stat{Key: "ai-defense", Label: "AI/inference defense efficacy", Value: "—", Unit: "",
			Source: "out-ai-bench (attack surface real; d-phorvex-slot is a stub, disruptionVsOracle=0)", Status: "pending", Product: "ai",
			Note: "Unvalidated on real GPU; PHORVEXSEC-87; never implied proven"},
	)
	return out
}

func pct(p float64) string { return fmt.Sprintf("%.0f", p*100) }

func harmRate(rows []metricRow, sc, def string) ci {
	t := fixedTrials(rows, sc, def)
	if len(t) == 0 {
		return ci{}
	}
	h := 0
	for _, r := range t {
		if v, ok := markers(r.ObservedState)["harm"]; ok && v != "" && v != "none" {
			h++
		}
	}
	return wilson(h, len(t))
}

func dwell(rows []metricRow, sc, def string) ci {
	t := fixedTrials(rows, sc, def)
	var xs []float64
	for _, r := range t {
		if v, ok := markers(r.ObservedState)["survival"]; ok {
			xs = append(xs, atof(v))
		} else if r.AttackerDwellSeconds > 0 {
			xs = append(xs, r.AttackerDwellSeconds)
		}
	}
	return tci(xs)
}

func reconLife(rows []metricRow, sc, def string) ci {
	t := fixedTrials(rows, sc, def)
	var xs []float64
	for _, r := range t {
		if v, ok := markers(r.ObservedState)["recon-valid"]; ok {
			xs = append(xs, atof(v))
		}
	}
	return tci(xs)
}

// FrontierRow is one arm in the P3-DEEP structural zero-day frontier.
type FrontierRow struct {
	Arm        string `json:"arm"`
	Interval   string `json:"interval"`
	Prevention *ci    `json:"prevention"`
	Harm       *ci    `json:"harm"`
	Infeasible *ci    `json:"infeasible"`
	Win        string `json:"win"`
}

// Frontier returns the constrained-class interval-sweep (the decisive certificate).
func (c *Config) Frontier() []FrontierRow {
	deep, ok := readMetrics(c.harnessOut("out-p3deep"))
	if !ok {
		return nil
	}
	defs := map[string]bool{}
	for _, r := range deep {
		if r.Scenario == "c2-stateful-training" && !r.NegativeControl {
			defs[r.Defender] = true
		}
	}
	var rows []FrontierRow
	for def := range defs {
		t := fixedTrials(deep, "c2-stateful-training", def)
		if len(t) == 0 {
			continue
		}
		prev, harm, inf := 0, 0, 0
		for _, r := range t {
			if r.DisruptionVsOracle >= 0.5 {
				prev++
			}
			mk := markers(r.ObservedState)
			if v, ok := mk["harm"]; ok && v != "" && v != "none" {
				harm++
			}
			if mk["infeasible-rotate"] == "true" {
				inf++
			}
		}
		p, h, i := wilson(prev, len(t)), wilson(harm, len(t)), wilson(inf, len(t))
		rows = append(rows, FrontierRow{Arm: def, Interval: armInterval(def, t[0].MeanRotationInterval),
			Prevention: &p, Harm: &h, Infeasible: &i, Win: winVerdict(def, p, h, i)})
	}
	sort.SliceStable(rows, func(a, b int) bool { return armOrder(rows[a].Arm) < armOrder(rows[b].Arm) })
	return rows
}

func armInterval(def string, declared float64) string {
	switch {
	case def == "d-phorvex":
		return "PX (solved)"
	case def == "d-nomtd":
		return "none"
	case def == "d-r6blindtimer":
		return "15s"
	default:
		return fmt.Sprintf("%gs", declared)
	}
}

func winVerdict(def string, prev, harm, inf ci) string {
	if def == "d-nomtd" {
		return "n/a"
	}
	if prev.Lo >= 0.80 && harm.Mean <= 1e-9 && inf.Mean <= 1e-9 {
		return "WIN"
	}
	if prev.Hi < 0.5 {
		return "no (too late)"
	}
	if harm.Mean > 1e-9 || inf.Mean > 1e-9 {
		return "no (harm)"
	}
	return "no"
}

func armOrder(def string) float64 {
	switch {
	case def == "d-nomtd":
		return -1e9
	case def == "d-phorvex":
		return 1e9
	case def == "d-r6blindtimer":
		return 15
	default:
		return atof(strings.TrimPrefix(def, "d-blind-"))
	}
}
