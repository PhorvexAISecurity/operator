package report

// validity_r2_test.go — PERMANENT regressions for the report-side items in lead
// review R2 (V3-M161):
//
//   - a retained cleanup failure must not certify a clean negative-control arm
//     just because a negative control is never "scored";
//   - the same must hold in the economics view and its hypothesis caveat.

import (
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// dirtyNegControl returns a negative control whose cleanup evidence contradicts
// its claimed validity, in each of the ways that can happen.
func dirtyNegControls() map[string]func(*core.Metric) {
	return map[string]func(*core.Metric){
		"retained-cleanup-error": func(m *core.Metric) {
			m.Validity.Cleanup.Attempted = []core.CleanupStep{{Step: "env.Close", Error: "forbidden"}}
		},
		"cleanup-incomplete": func(m *core.Metric) { m.Validity.Cleanup.Complete = false },
		"cleanup-unresolved": func(m *core.Metric) {
			m.Validity.Cleanup.Complete, m.Validity.Cleanup.Unresolved = false, true
		},
		"cleanup-blocked": func(m *core.Metric) {
			m.Validity.Cleanup.Attempted = []core.CleanupStep{{Step: "env.Close", Blocked: true}}
		},
	}
}

// A negative control is never scored — that is normal for the kind — so the
// cleanup check must live OUTSIDE the scored-only path. A dirty control cannot
// establish that an arm made no false defensive moves.
func TestR2ContradictoryCleanupCannotCertifyANegativeControl(t *testing.T) {
	// POSITIVE CONTROL first: a clean, observed control still certifies.
	clean := Aggregate(replayThroughReader(t, r1ProducerRow(t),
		negControlRow("v161-mixed", "d-v161-arm", 1, 0, true)), 0.95)
	if s := armByDefender(t, clean, "d-v161-arm"); s.NegativeControl != NegControlObserved || s.NegFalseMovesMax != 0 {
		t.Fatalf("a clean negative control was rejected: state=%s max=%d", s.NegativeControl, s.NegFalseMovesMax)
	}

	for name, mutate := range dirtyNegControls() {
		t.Run(name, func(t *testing.T) {
			neg := negControlRow("v161-mixed", "d-v161-arm", 1, 0, true)
			mutate(&neg)
			metrics := replayThroughReader(t, r1ProducerRow(t), neg)

			s := armByDefender(t, Aggregate(metrics, 0.95), "d-v161-arm")
			if s.NegativeControl == NegControlObserved {
				t.Fatalf("a dirty negative control certified a clean arm: state=%s max=%d",
					s.NegativeControl, s.NegFalseMovesMax)
			}
			if s.NegFalseMovesMax != -1 {
				t.Errorf("NegFalseMovesMax = %d; an uncertified control must not present a measured value", s.NegFalseMovesMax)
			}
			md := RenderMarkdown(metrics, 0.95, nil)
			if !strings.Contains(md, "n/a (unobserved") && !strings.Contains(md, "n/a (partial") {
				t.Errorf("the report did not disclose the uncertified control:\n%s", md)
			}

			// The economics view must refuse it on the same grounds and say so.
			dollars := RenderDollars(metrics, r1DollarInputs(), 0.95)
			if !strings.Contains(dollars, "Negative controls (verdict caveat)") {
				t.Errorf("the hypothesis section did not carry the control caveat:\n%s", dollars)
			}
		})
	}
}

// The cleanup verdict must also travel into provenance, so a consumer of
// provenance.json sees the same thing the reports do.
func TestR2ProvenanceCarriesTheCleanupVerdict(t *testing.T) {
	neg := negControlRow("v161-mixed", "d-v161-arm", 1, 0, true)
	neg.Validity.Cleanup.Attempted = []core.CleanupStep{{Step: "env.Close", Error: "forbidden"}}
	pm := BuildProvenance(replayThroughReader(t, neg), 1, 1, "ctx", "ns", "out/metrics.jsonl", "cmd", nil)
	if len(pm.Entries) != 1 {
		t.Fatalf("provenance dropped the row")
	}
	e := pm.Entries[0]
	if e.CleanupComplete {
		t.Errorf("provenance reported a dirty trial as cleanly torn down: %+v", e)
	}
	if !e.Unverified || e.Scored {
		t.Errorf("provenance did not mark the contradictory row unverified: %+v", e)
	}
}

// The run outcome — including an unverified FINAL TEARDOWN — reaches provenance,
// so "the cluster was left verified" is recorded, not just what each cell
// measured.
func TestR2ProvenanceCarriesTheRunOutcome(t *testing.T) {
	out := &core.RunOutcome{
		PlannedTrials: 4, ExecutedTrials: 4, WrittenTrials: 4, Complete: false,
		Barriers:      []string{"final teardown did not verify: namespace sandbox still present"},
		FinalTeardown: &core.FinalTeardown{Attempted: true, Verified: false, Error: "namespace sandbox still present"},
	}
	pm := BuildProvenance(replayThroughReader(t, r1ProducerRow(t)), 1, 1, "ctx", "ns", "out/metrics.jsonl", "cmd", out)
	if pm.Run == nil {
		t.Fatalf("provenance did not record the run outcome")
	}
	if pm.Run.Complete {
		t.Errorf("provenance reported a run with an unverified final teardown as complete")
	}
	if pm.Run.FinalTeardown == nil || pm.Run.FinalTeardown.Verified {
		t.Fatalf("provenance did not record the unverified final teardown: %+v", pm.Run.FinalTeardown)
	}
}
