/*
 * Phorvex Console (P-DASHBOARD-2) — EVIDENCE data layer (Wave 1).
 * Pure read-only aggregation over the real harness catalog + metrics corpus. Nothing faked.
 */

package console

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// --- Attack Catalog (the full ~53 scenarios from the harness registry) -------------------

type CatalogItem struct {
	EntryID             string   `json:"entryID,omitempty"`
	Name                string   `json:"name"`
	Product             string   `json:"product"` // k8s | ai | structural
	Category            string   `json:"category"`
	R6Tag               string   `json:"r6Tag"`
	Techniques          []string `json:"techniques"` // declared ATT&CK applicability (legacy-compatible name)
	ExercisedTechniques []string `json:"exercisedTechniques"`
	Caps                []string `json:"caps"`
	HasRun              bool     `json:"hasRun"`
	Realism             string   `json:"realism,omitempty"`
	// BenignControl is nil for a legacy list row whose format never declared it.
	// Keeping unknown distinct from false prevents old catalogue data from being
	// silently upgraded into an attack claim.
	BenignControl *bool `json:"benignControl,omitempty"`
	// per-attack guidance (derived): which actuator(s) it should trigger, when it's meaningful,
	// what it needs to run.
	ExpectedActuators []string `json:"expectedActuators"`
	MeaningfulWhen    string   `json:"meaningfulWhen"`
	RunnableNote      string   `json:"runnableNote"`
	Prereqs           []string `json:"prereqs"`
	LaunchKind        string   `json:"launchKind"`
	ClaimClass        string   `json:"claimClass"`
	Profile           string   `json:"profile,omitempty"`
	Available         bool     `json:"available"`
	UnavailableReason string   `json:"unavailableReason,omitempty"`
	RuntimeContext    string   `json:"runtimeContext,omitempty"`
}

// Legacy harnesses used techniques; current harnesses separate declared from exercised.
// Catalogue techniques describe declared applicability, never observed attack coverage.
var currentListRe = regexp.MustCompile(`^\s*-\s+(\S+)\s+\[([A-Za-z0-9]+)\]\s+R6=(\S+)\s+realism=(\S+)\s+benign=(true|false)\s+declared=\[([^\]]*)\]\s+exercised=\[([^\]]*)\]\s+caps=\[([^\]]*)\]`)
var listRe = regexp.MustCompile(`^\s*-\s+(\S+)\s+\[([A-Za-z0-9]+)\]\s+R6=(\S+)\s+techniques=\[([^\]]*)\]\s+caps=\[([^\]]*)\]`)

func productOf(name string) string {
	switch {
	case strings.HasPrefix(name, "ai1-") || strings.HasPrefix(name, "ai2-") || strings.HasPrefix(name, "c2-vllm-") || strings.HasSuffix(name, "-ai"):
		return "ai"
	case strings.HasPrefix(name, "b-") || strings.HasPrefix(name, "e-"):
		return "structural"
	default:
		return "k8s"
	}
}

// Catalog runs `harness -list` (the authoritative registry) and parses the catalog. It
// marks which scenarios have run (appear in any out-* metrics).
func (c *Config) Catalog() []CatalogItem {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg := filepath.Join(c.HarnessDir, "config.p3.full.yaml")
	cmd := exec.CommandContext(ctx, c.HarnessBin, "-config", cfg, "-list")
	cmd.Dir = c.HarnessDir
	out, err := cmd.Output()
	if err != nil {
		return c.sortedLimitedV1Catalogue(nil)
	}
	items := parseCatalog(out, c.scenariosRun())
	if items == nil {
		return c.sortedLimitedV1Catalogue(nil)
	}
	for i := range items {
		items[i].EntryID = items[i].Name
		items[i].LaunchKind = "harness-scenario"
		items[i].ClaimClass = "security"
		items[i].Available = true
		if items[i].BenignControl != nil && *items[i].BenignControl {
			items[i].ClaimClass = "functional"
		}
	}
	return c.sortedLimitedV1Catalogue(items)
}

func (c *Config) sortedLimitedV1Catalogue(items []CatalogItem) []CatalogItem {
	items = append(items, c.limitedV1Catalogue()...)
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Product != items[j].Product {
			return items[i].Product < items[j].Product
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func parseCatalog(out []byte, hasRun map[string]bool) []CatalogItem {
	var items []CatalogItem
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		current := currentListRe.FindStringSubmatch(line)
		legacy := listRe.FindStringSubmatch(line)
		if current == nil && legacy == nil {
			if strings.Contains(sc.Text(), " R6=") {
				return nil // Reject incomplete catalogues if a scenario format is unknown.
			}
			continue
		}
		var name, category, r6, realism string
		var declared, exercised, caps []string
		var benign *bool
		if current != nil {
			name, category, r6, realism = current[1], current[2], current[3], current[4]
			value := current[5] == "true"
			benign = &value
			declared, exercised, caps = splitFields(current[6]), splitFields(current[7]), splitFields(current[8])
		} else {
			name, category, r6 = legacy[1], legacy[2], legacy[3]
			declared, caps = splitFields(legacy[4]), splitFields(legacy[5])
			exercised = []string{}
		}
		prod := productOf(name)
		meta := deriveScenarioMeta(name, prod, caps, benign != nil && *benign)
		items = append(items, CatalogItem{
			Name: name, Product: prod, Category: category, R6Tag: r6,
			Techniques: declared, ExercisedTechniques: exercised, Caps: caps, HasRun: hasRun[name],
			Realism: realism, BenignControl: benign,
			ExpectedActuators: meta.ExpectedActuators, MeaningfulWhen: meta.MeaningfulWhen,
			RunnableNote: meta.RunnableNote, Prereqs: meta.Prereqs,
		})
	}
	if sc.Err() != nil {
		return nil
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Product != items[j].Product {
			return items[i].Product < items[j].Product
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func splitFields(s string) []string {
	f := strings.Fields(s)
	if f == nil {
		return []string{} // emit [] not null, so the UI never sees a null array
	}
	return f
}

// scenariosRun returns the set of scenario names that appear in any out-* metrics file.
func (c *Config) scenariosRun() map[string]bool {
	run := map[string]bool{}
	for _, d := range c.outDirs() {
		if rows, ok := readMetrics(filepath.Join(d, "metrics.jsonl")); ok {
			for _, r := range rows {
				run[r.Scenario] = true
			}
		}
	}
	return run
}

func (c *Config) outDirs() []string {
	base := c.HarnessDir
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "out-") {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	return out
}

// --- Benchmarks / Evidence Hub -----------------------------------------------------------

type BenchArm struct {
	Defender   string `json:"defender"`
	Disruption *ci    `json:"disruption"`
	Dwell      *ci    `json:"dwell"`
	HarmRate   *ci    `json:"harmRate"`
	Trials     int    `json:"trials"`
}
type BenchGroup struct {
	Scenario string     `json:"scenario"`
	Source   string     `json:"source"`
	Arms     []BenchArm `json:"arms"`
}

// Benchmarks aggregates the decisive scenarios across the richest out-* dirs.
func (c *Config) Benchmarks() []BenchGroup {
	want := []struct{ dir, scenario string }{
		{"out-p3deep", "c1-heldout-cve"},
		{"out-p3deep", "c2-stateful-training"},
		{"out-p3deep", "b-recon-lifetime"},
		{"out-pactuator", "c2-stateful-training"},
	}
	var groups []BenchGroup
	for _, w := range want {
		rows, ok := readMetrics(filepath.Join(c.HarnessDir, w.dir, "metrics.jsonl"))
		if !ok {
			continue
		}
		defs := map[string]bool{}
		for _, r := range rows {
			if r.Scenario == w.scenario && !r.NegativeControl {
				defs[r.Defender] = true
			}
		}
		g := BenchGroup{Scenario: w.scenario, Source: w.dir + "/metrics.jsonl"}
		for def := range defs {
			t := fixedTrials(rows, w.scenario, def)
			if len(t) == 0 {
				continue
			}
			succ := 0
			var dw []float64
			for _, r := range t {
				if r.DisruptionVsOracle >= 0.5 {
					succ++
				}
				if v, ok := markers(r.ObservedState)["survival"]; ok {
					dw = append(dw, atof(v))
				} else if r.AttackerDwellSeconds > 0 {
					dw = append(dw, r.AttackerDwellSeconds)
				}
			}
			dis := wilson(succ, len(t))
			dwc := tci(dw)
			h := harmRate(rows, w.scenario, def)
			g.Arms = append(g.Arms, BenchArm{Defender: def, Disruption: &dis, Dwell: &dwc, HarmRate: &h, Trials: len(t)})
		}
		sort.SliceStable(g.Arms, func(i, j int) bool { return armOrder(g.Arms[i].Defender) < armOrder(g.Arms[j].Defender) })
		groups = append(groups, g)
	}
	return groups
}

// --- Threat-Coverage Matrix (ATT&CK techniques x coverage) -------------------------------

type CoverageTechnique struct {
	Technique string   `json:"technique"`
	Scenarios []string `json:"scenarios"`
	Product   string   `json:"product"`
	Covered   bool     `json:"covered"` // PX disrupts >=1 scenario carrying this technique
}

// ThreatMatrix maps each ATT&CK technique (from the catalog) to the scenarios that exercise
// it + whether PX has demonstrably disrupted at least one (from the metrics).
func (c *Config) ThreatMatrix() []CoverageTechnique {
	cat := c.Catalog()
	pxDisrupted := c.pxDisruptedScenarios()
	byTech := map[string]*CoverageTechnique{}
	for _, it := range cat {
		for _, tech := range it.Techniques {
			t := byTech[tech]
			if t == nil {
				t = &CoverageTechnique{Technique: tech, Product: it.Product}
				byTech[tech] = t
			}
			t.Scenarios = append(t.Scenarios, it.Name)
			if pxDisrupted[it.Name] {
				t.Covered = true
			}
		}
	}
	var out []CoverageTechnique
	for _, t := range byTech {
		sort.Strings(t.Scenarios)
		out = append(out, *t)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Technique < out[j].Technique })
	return out
}

func (c *Config) pxDisruptedScenarios() map[string]bool {
	px := map[string]bool{}
	for _, d := range c.outDirs() {
		if rows, ok := readMetrics(filepath.Join(d, "metrics.jsonl")); ok {
			for _, r := range rows {
				if r.Defender == "d-phorvex" && r.DisruptionVsOracle >= 0.5 {
					px[r.Scenario] = true
				}
			}
		}
	}
	return px
}

// --- Posture score (composite; the weighting is IP -> owner-redacted) --------------------

type PostureSub struct {
	Label string  `json:"label"`
	Score float64 `json:"score"`
	Basis string  `json:"basis"`
}
type Posture struct {
	Grade string       `json:"grade"`
	Score float64      `json:"score"`
	Subs  []PostureSub `json:"subs"`
	Note  string       `json:"note"`
}

// PostureScore is a composite readiness grade — every K8s sub-score is COMPUTED from a real
// source (no fixed 1.0). A sub with Score < 0 is honestly "pending/not-yet-computed" and is
// EXCLUDED from the average. AI validation is tracked by PHORVEXSEC-87; the grade never
// inflates it.
func (c *Config) PostureScore(ctx context.Context) Posture {
	full, hasFull := readMetrics(c.harnessOut("out-p3-full"))
	pact, hasPact := readMetrics(c.harnessOut("out-pactuator"))
	var subs []PostureSub

	// Prevention <- real c1-fast-attacker objective-denied rate.
	if hasFull {
		if prev, n := preventionRows(full, "c1-fast-attacker", "d-phorvex"); n > 0 {
			subs = append(subs, PostureSub{"Prevention", float64(prev) / float64(n), fmt.Sprintf("c1-fast-attacker %d/%d objective denied (out-p3-full, computed)", prev, n)})
		}
	}
	// Work preservation <- real out-pactuator c2-stateful-training preserved rate.
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
			subs = append(subs, PostureSub{"Work preservation", float64(pres) / float64(n), fmt.Sprintf("c2-stateful-training %d/%d preserved (out-pactuator, computed)", pres, n)})
		}
	}
	// Explainability <- the real decision audit.
	if exp, tot, sourceErr := explainabilityFromAuditContext(ctx, c.auditFile(), c.AuditSource); sourceErr != nil && c.AuditSource != nil {
		subs = append(subs, PostureSub{"Explainability", -1, "remote audit source unavailable: " + sourceErr.Error()})
	} else if tot > 0 {
		subs = append(subs, PostureSub{"Explainability", float64(exp) / float64(tot), fmt.Sprintf("%d/%d decisions explained (audit, computed)", exp, tot)})
	}
	// Actuator coverage <- the real registry completeness invariant (covered / generatable).
	if rv := HandlerRegistryView(); rv.Generatables > 0 {
		covered := rv.Generatables - len(rv.Missing)
		subs = append(subs, PostureSub{"Actuator coverage", float64(covered) / float64(rv.Generatables), fmt.Sprintf("%d/%d generatable actions covered, %d handlers registered (registry, computed)", covered, rv.Generatables, rv.Count)})
	}
	// Recon-per-$ is NOT a readiness sub — it is a fleet-dependent IP-mechanism ratio (1.0× on a
	// flat fleet, > 1 only on a heavy-tailed asset distribution), shown LIVE in the Prove →
	// Recon-per-$ panel from `phorvex --ablation`. It is deliberately excluded from the grade.
	// AI defense — pending, excluded from the grade.
	subs = append(subs, PostureSub{"AI defense", -1, "Not yet validated on real GPU; PHORVEXSEC-87"})

	// average ONLY the computed K8s subs (Score >= 0); pending (-1) excluded.
	sum, n := 0.0, 0
	for _, s := range subs {
		if s.Score < 0 {
			continue
		}
		sum += s.Score
		n++
	}
	score := 0.0
	if n > 0 {
		score = sum / float64(n)
	}
	grade := "A"
	switch {
	case n == 0:
		grade = "—"
	case score < 0.6:
		grade = "C"
	case score < 0.85:
		grade = "B"
	}
	return Posture{Grade: grade, Score: score, Subs: subs,
		Note: "K8s readiness grade — every sub computed from a real source; unvalidated subs (including AI, PHORVEXSEC-87) are excluded, never inflated."}
}

// --- Raw attack-log viewer (forensic transcript; path-validated) -------------------------

// RawLog returns a per-trial raw kubectl attack transcript, validated to live under an
// out-*/ dir so no path traversal can read outside the evidence corpus.
func (c *Config) RawLog(rel string) (string, bool) {
	rel = filepath.Clean(rel)
	if strings.Contains(rel, "..") {
		return "", false
	}
	full := filepath.Join(c.HarnessDir, rel)
	base := filepath.Clean(c.HarnessDir) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(full), base) || !strings.Contains(full, "out-") {
		return "", false
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", false
	}
	if len(b) > 200_000 {
		b = b[:200_000]
	}
	return string(b), true
}
