package decision

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// M-16 (note arm): the audit record's counterfactualNote must agree with its own `selected`
// flag. The fallback branch names a best standalone candidate for a feasible-but-unselected
// attack-backed pod; Reason already says "considered" and the note must not narrate that
// action as chosen/used/quarantined. Every case below runs the REAL CoverageEngine.Decide ->
// audit.Logger.Record -> JSON path; no note is injected. Selected, noop and stateful controls
// keep the assertion discriminating, and the full serialized records are snapshotted (minus
// the wall clock) so a baseline/head diff shows a label-only change.
//
// Set M016_NOTE_SNAPSHOT=<path> to write that snapshot.
func TestM016CounterfactualNoteAgreesWithSelection(t *testing.T) {
	type fixture struct {
		name       string
		views      []*model.WorkloadView
		policy     model.Policy
		wantSel    int
		wantFall   int
		wantNoop   int
		fallAction string
	}
	stateless := func(names ...string) []*model.WorkloadView {
		var vs []*model.WorkloadView
		for _, n := range names {
			vs = append(vs, covView(n, true, 2*time.Hour, false))
		}
		return vs
	}
	stateful := func(names ...string) []*model.WorkloadView {
		var vs []*model.WorkloadView
		for _, n := range names {
			vs = append(vs, covView(n, true, 2*time.Hour, true))
		}
		return vs
	}
	free := func(enabled map[model.Action]bool) model.Policy {
		p := covPolicy(1)
		p.Lambda = 0
		if enabled != nil {
			p.EnabledActions = enabled
		}
		return p
	}
	fixtures := []fixture{
		// Original failure (investigator seed): one selected rotate, two feasible pods whose
		// best standalone candidate is named but not selected.
		{name: "rotate-selected-two-fallback", views: stateless("a", "b", "c"), policy: free(nil), wantSel: 1, wantFall: 2},
		// Stateful pods: quarantine selected on one, the other is the stateful fallback arm.
		{name: "stateful-quarantine-fallback", views: stateful("db1", "db2"), policy: free(nil), wantSel: 1, wantFall: 1, fallAction: "quarantine"},
		// Stateless quarantine-only: selected quarantine plus its unselected twin.
		{name: "stateless-quarantine-fallback", views: stateless("q1", "q2"), policy: free(map[model.Action]bool{model.ActionQuarantine: true}), wantSel: 1, wantFall: 1, fallAction: "quarantine"},
		// Stateful pod with only rotate enabled: statefulIntegrity excludes it -> infeasible noop.
		{name: "stateful-noop", views: stateful("db"), policy: free(map[model.Action]bool{model.ActionRotate: true}), wantNoop: 1},
		// No enabled action at all -> noop with no invented candidate.
		{name: "no-candidate-noop", views: stateless("none"), policy: free(map[model.Action]bool{model.ActionRotate: false, model.ActionQuarantine: false}), wantNoop: 1},
	}

	var snapshot []map[string]any
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			decisions := NewCoverageEngine().Decide(fx.views, fx.policy)
			if len(decisions) != len(fx.views) {
				t.Fatalf("decisions=%d views=%d", len(decisions), len(fx.views))
			}
			var buf bytes.Buffer
			logger := audit.New(logr.Discard(), &buf)
			for _, d := range decisions {
				if err := logger.Record(d); err != nil {
					t.Fatal(err)
				}
			}
			dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
			sel, fall, noop := 0, 0, 0
			for _, d := range decisions {
				var r audit.Record
				if err := dec.Decode(&r); err != nil {
					t.Fatal(err)
				}
				// Structured facts are the engine's; the note only labels them.
				if r.Pod != d.Pod || r.Action != string(d.Action) || r.Selected != d.Selected || r.Actuated != d.Actuated || r.Feasible != d.Feasible || r.Reason != d.Reason || r.CounterfactualNote != d.CounterfactualNote {
					t.Fatalf("serialization changed structured facts: %+v vs %+v", r, d)
				}
				if r.Actuated {
					t.Fatalf("%s: DryRun fixture must not actuate", r.Pod)
				}
				if r.R6Counterfactual != string(model.ActionRotate) || !strings.HasPrefix(r.CounterfactualNote, "R6") {
					t.Errorf("%s: R6 hypothetical comparison lost: r6=%q note=%q", r.Pod, r.R6Counterfactual, r.CounterfactualNote)
				}
				note := r.CounterfactualNote
				switch {
				case r.Action == "noop":
					noop++
					if r.Selected {
						t.Errorf("%s: noop cannot be selected", r.Pod)
					}
					if !strings.Contains(note, "Phorvex selected no action") {
						t.Errorf("%s: noop note must describe no selection: %q", r.Pod, note)
					}
					// No invented blocker or score: those live in Reason/InfeasibleWhy/trace.
					if strings.Contains(note, "net-positive") || strings.Contains(note, "strict positive-gain") || strings.Contains(note, "inviolably") {
						t.Errorf("%s: noop note invents a specific blocker/score: %q", r.Pod, note)
					}
				case !r.Selected:
					fall++
					if !r.Feasible || !strings.HasPrefix(r.Reason, r.Action+": considered (") {
						t.Fatalf("%s: fixture did not reach the feasible-but-unselected fallback: feasible=%v reason=%q", r.Pod, r.Feasible, r.Reason)
					}
					if fx.fallAction != "" && r.Action != fx.fallAction {
						t.Errorf("%s: fallback named %q, fixture expects %q", r.Pod, r.Action, fx.fallAction)
					}
					if !strings.Contains(note, "Phorvex considered "+r.Action) || !strings.Contains(note, "did not select") {
						t.Errorf("%s: unselected note must say considered/not selected: %q", r.Pod, note)
					}
					// M-16 residual: an unselected record narrated as taken.
					for _, taken := range []string{"Phorvex selected " + r.Action, "Phorvex chose", "Phorvex used", "Phorvex quarantined"} {
						if strings.Contains(note, taken) {
							t.Errorf("%s: selected=false record narrates action as taken (%q): %q", r.Pod, taken, note)
						}
					}
				default:
					sel++
					if !strings.Contains(r.Reason, "strict gain") {
						t.Fatalf("%s: selected control lost its reason: %q", r.Pod, r.Reason)
					}
					if !strings.Contains(note, "Phorvex selected "+r.Action) || strings.Contains(note, "considered") || strings.Contains(note, "did not select") {
						t.Errorf("%s: selected note must describe selection of %s: %q", r.Pod, r.Action, note)
					}
				}
				// Selection is not actuation: the note never claims a completed mutation,
				// confirmed containment or continued availability for any arm.
				for _, claim := range []string{"Phorvex quarantined", "Phorvex used", "Phorvex chose", "keeps serving"} {
					if strings.Contains(note, claim) {
						t.Errorf("%s: note claims actuation/availability (%q): %q", r.Pod, claim, note)
					}
				}
				if r.Selected && d.Pod != "" && len(d.Attribution) == 0 {
					t.Errorf("%s: selected decision lost attribution", r.Pod)
				}
				var raw map[string]any
				if err := json.Unmarshal(lineFor(t, buf.Bytes(), r.Pod), &raw); err != nil {
					t.Fatal(err)
				}
				delete(raw, "time")
				raw["fixture"] = fx.name
				snapshot = append(snapshot, raw)
			}
			if sel != fx.wantSel || fall != fx.wantFall || noop != fx.wantNoop {
				t.Fatalf("positive controls: selected=%d fallback=%d noop=%d want %d/%d/%d", sel, fall, noop, fx.wantSel, fx.wantFall, fx.wantNoop)
			}
			t.Logf("actual engine -> audit JSONL: selected=%d fallback=%d noop=%d", sel, fall, noop)
		})
	}
	if path := os.Getenv("M016_NOTE_SNAPSHOT"); path != "" {
		raw, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// lineFor returns the JSONL line whose "pod" field is pod (fixtures use unique pod names).
func lineFor(t *testing.T, jsonl []byte, pod string) []byte {
	t.Helper()
	for _, line := range bytes.Split(bytes.TrimSpace(jsonl), []byte("\n")) {
		var probe struct {
			Pod string `json:"pod"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatal(err)
		}
		if probe.Pod == pod {
			return line
		}
	}
	t.Fatalf("no record for pod %q", pod)
	return nil
}
