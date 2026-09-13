package report

// corpus_gen_test.go — the shared parity corpus is PRODUCED BY THE REAL HARNESS,
// and this is where it is produced and kept honest (V3-M161, lead review R2
// finding 1).
//
// Normal runs VERIFY: the committed corpus must still contain a byte-faithful
// real producer row, and every case's expectation must still match what the
// shared contract decides. Regeneration is explicit:
//
//	M161_REGEN_CORPUS=1 go test ./internal/report -run TestSharedParityCorpus
//
// The counterexamples are derived by mutating ONE field of a row that came out
// of Runner.Run -> MetricWriter -> ReadMetricsFile. They are deliberately not
// hand-written: a hand-written fixture can be permissive in exactly the way the
// reader under test is permissive, and would prove nothing.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phorvex/metricvalidity"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

// corpusPath is the shared module's embedded corpus, relative to this package.
const corpusPath = "../../../metricvalidity/corpus.json"

// corpusMutation is one single-field corruption of a real producer row.
type corpusMutation struct {
	name   string
	why    string
	mutate func(row map[string]any)
}

func corpusMutations() []corpusMutation {
	validity := func(row map[string]any) map[string]any { return row["validity"].(map[string]any) }
	baseline := func(row map[string]any) map[string]any {
		return validity(row)["baseline"].(map[string]any)
	}
	return []corpusMutation{
		{"positive-control", "a genuine producer row must stay certifiable everywhere", func(map[string]any) {}},
		{"legacy", "a pre-contract row is readable history, never a current measurement",
			func(r map[string]any) { delete(r, "validity") }},
		{"future-version", "a row from a newer contract cannot be interpreted by this build",
			func(r map[string]any) { validity(r)["version"] = metricvalidity.Version + 1 }},
		{"unknown-status", "an unrecognised status is conservatively invalid",
			func(r map[string]any) { validity(r)["status"] = "unrecognized" }},
		{"unknown-kind", "an unrecognised kind cannot be attributed to a comparison or a control",
			func(r map[string]any) { validity(r)["kind"] = "sideways" }},
		{"status-invalid", "an infrastructure failure is not a defensive result",
			func(r map[string]any) { validity(r)["status"] = "invalid" }},
		{"oracle-not-observed", "a scored claim with no observed oracle is a contradiction",
			func(r map[string]any) { validity(r)["oracleObserved"] = false }},
		{"baseline-contradiction", "a control marked usable whose own evidence denies it",
			func(r map[string]any) { baseline(r)["observed"] = false }},
		{"baseline-attack-failed", "a control that did not achieve its oracle cannot anchor disruption",
			func(r map[string]any) { baseline(r)["oracleAchieved"] = false }},
		{"missing-control-identity", "a comparison that cannot be traced to a control arm",
			func(r map[string]any) { delete(baseline(r), "defender") }},
		{"baseline-not-usable", "an unanchored comparison is not a measurement",
			func(r map[string]any) { baseline(r)["usable"] = false }},
		{"retained-cleanup-failure", "a dirty trial left state nobody verified",
			func(r map[string]any) {
				validity(r)["cleanup"] = map[string]any{"complete": true, "attempted": []any{
					map[string]any{"step": "env.Close", "error": "forbidden"}}}
			}},
		{"cleanup-incomplete", "cleanup that did not verify invalidates the trial",
			func(r map[string]any) { validity(r)["cleanup"] = map[string]any{"complete": false} }},
		{"cleanup-unresolved", "a cleanup call that may still be running is not a clean trial",
			func(r map[string]any) {
				validity(r)["cleanup"] = map[string]any{"complete": false, "unresolved": true}
			}},
		{"cleanup-blocked", "a step not attempted because a predecessor still holds the Env",
			func(r map[string]any) {
				validity(r)["cleanup"] = map[string]any{"complete": false, "attempted": []any{
					map[string]any{"step": "env.Close", "blocked": true}}}
			}},
		{"out-of-range-score", "a disruption outside [0,1] was never measured",
			func(r map[string]any) { r["disruptionVsOracle"] = 2 }},
		{"cost-sentinel-contradiction", "a claimed cost observation against the UNOBSERVED sentinel",
			func(r map[string]any) { r["defensiveActions"] = -1 }},
		{"wrong-baseline-kind", "an ordinary comparison anchored to an adaptive control is a different experiment",
			func(r map[string]any) { baseline(r)["kind"] = "adaptive" }},
		{"wrong-baseline-trial", "a comparison may only anchor to the control observed at its OWN index",
			func(r map[string]any) { baseline(r)["trial"] = 10 }},
		{"oracle-without-attack", "an oracle verdict with no executed stimulus has nothing to measure",
			func(r map[string]any) { validity(r)["attackExecuted"] = false }},
		{"cost-without-observer", "a cost claimed observed while nothing could have observed it",
			func(r map[string]any) { validity(r)["observerPresent"] = false }},
		{"incomplete-phase", "status valid at a setup phase: a valid measurement reached the terminal phase",
			func(r map[string]any) { validity(r)["phase"] = "scenario-setup" }},
	}
}

// buildCorpus derives the corpus from a REAL producer row.
func buildCorpus(t *testing.T) []metricvalidity.CorpusCase {
	t.Helper()
	real := r1ProducerRow(t)
	if !real.IsScored() {
		t.Fatalf("fixture relevance: the corpus must start from a genuinely scored producer row")
	}
	raw, err := json.Marshal(real)
	if err != nil {
		t.Fatal(err)
	}

	var out []metricvalidity.CorpusCase
	for _, mut := range corpusMutations() {
		var row map[string]any
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		mut.mutate(row)
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		// The expectation is whatever the SHARED contract decides for this row,
		// decoded the same way any reader decodes it.
		var decoded corpusProbe
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		out = append(out, metricvalidity.CorpusCase{
			Name: mut.name, Why: mut.why, Row: string(encoded),
			Expect: metricvalidity.VerdictOf(decoded.verdict()),
		})
	}
	return out
}

// corpusProbe decodes exactly the fields the contract needs, mirroring what a
// downstream reader does.
type corpusProbe struct {
	Trial                 int                      `json:"trial"`
	DisruptionVsOracle    float64                  `json:"disruptionVsOracle"`
	DefensiveActions      int                      `json:"defensiveActions"`
	FalseDefensiveActions int                      `json:"falseDefensiveActions"`
	TimeToActionSeconds   float64                  `json:"timeToActionSeconds"`
	AttackerDwellSeconds  float64                  `json:"attackerDwellSeconds"`
	Validity              *metricvalidity.Validity `json:"validity"`
}

func (p corpusProbe) verdict() metricvalidity.Verdict {
	return metricvalidity.Evaluate(p.Validity, metricvalidity.Observations{
		Trial:                 p.Trial,
		Disruption:            p.DisruptionVsOracle,
		DefensiveActions:      p.DefensiveActions,
		FalseDefensiveActions: p.FalseDefensiveActions,
		TimeToActionSeconds:   p.TimeToActionSeconds,
		AttackerDwellSeconds:  p.AttackerDwellSeconds,
	})
}

func TestSharedParityCorpus(t *testing.T) {
	built := buildCorpus(t)

	if os.Getenv("M161_REGEN_CORPUS") == "1" {
		b, err := json.MarshalIndent(built, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Clean(corpusPath), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s with %d case(s) from a real producer row", corpusPath, len(built))
		return
	}

	committed := metricvalidity.Corpus()
	if len(committed) != len(built) {
		t.Fatalf("committed corpus has %d case(s), the harness now produces %d; regenerate with M161_REGEN_CORPUS=1",
			len(committed), len(built))
	}
	for i, want := range built {
		got := committed[i]
		if got.Name != want.Name {
			t.Fatalf("case %d: committed %q, harness produces %q; regenerate", i, got.Name, want.Name)
		}
		if got.Expect != want.Expect {
			t.Errorf("%s: committed expectation %s, the contract now decides %s; regenerate",
				got.Name, got.Expect, want.Expect)
		}
	}

	// The corpus must be REAL producer output, not a hand-written fixture: the
	// positive control has to survive the actual harness's own verdict.
	for _, c := range committed {
		if c.Name != "positive-control" {
			continue
		}
		var probe corpusProbe
		if err := json.Unmarshal([]byte(c.Row), &probe); err != nil {
			t.Fatal(err)
		}
		if !probe.verdict().Scorable {
			t.Fatalf("the corpus positive control is not certifiable; it is not a genuine producer row")
		}
		if probe.Validity == nil || probe.Validity.Version != metricvalidity.Version {
			t.Fatalf("the corpus positive control does not carry this build's contract version")
		}
	}
}

// The harness's OWN reader must agree with the corpus, exactly as every
// downstream reader must. This is the producer side of the parity check: if the
// harness and a product reader ever disagree about the same bytes again, one of
// these tests fails instead of a dashboard quietly publishing a refused row.
func TestSharedParityCorpusMatchesTheHarnessReader(t *testing.T) {
	problems := metricvalidity.CheckCorpusParity(func(row []byte) (metricvalidity.ExpectedVerdict, error) {
		var m core.Metric
		if err := json.Unmarshal(row, &m); err != nil {
			return metricvalidity.ExpectedVerdict{}, err
		}
		return metricvalidity.VerdictOf(m.Validated()), nil
	})
	for _, p := range problems {
		t.Errorf("harness reader disagrees with the shared contract: %s", p)
	}
}
