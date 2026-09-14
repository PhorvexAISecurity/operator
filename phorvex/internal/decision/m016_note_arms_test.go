package decision

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// M-16: every counterfactualNote arm, crossed with the selected flag. The AI-native default
// arm is not reachable from the coverage fixtures without an AI signal, so it is covered here.
func TestM016CounterfactualNoteArms(t *testing.T) {
	stateless := covView("s", true, 0, false)
	stateful := covView("d", true, 0, true)
	cases := []struct {
		name     string
		action   model.Action
		selected bool
		view     *model.WorkloadView
		want     []string
		reject   []string
	}{
		{"rotate selected", model.ActionRotate, true, stateless, []string{"Phorvex selected rotate"}, []string{"considered"}},
		{"rotate fallback", model.ActionRotate, false, stateless, []string{"Phorvex considered rotate", "did not select"}, []string{"Phorvex selected rotate"}},
		{"quarantine selected", model.ActionQuarantine, true, stateless, []string{"Phorvex selected quarantine", "lateral recon"}, []string{"considered", "Phorvex chose"}},
		{"quarantine fallback", model.ActionQuarantine, false, stateless, []string{"Phorvex considered quarantine", "did not select"}, []string{"Phorvex selected quarantine", "Phorvex chose"}},
		{"stateful quarantine selected", model.ActionQuarantine, true, stateful, []string{"stateful pod", "Phorvex selected quarantine", "preserving state"}, []string{"considered", "quarantined"}},
		{"stateful quarantine fallback", model.ActionQuarantine, false, stateful, []string{"stateful pod", "Phorvex considered quarantine", "did not select"}, []string{"Phorvex selected", "quarantined"}},
		{"stateful rotate fallback", model.ActionRotate, false, stateful, []string{"stateful pod", "Phorvex considered rotate", "did not select"}, []string{"Phorvex selected"}},
		{"noop", model.ActionNoop, false, stateless, []string{"Phorvex selected no action"}, []string{"considered", "strict positive-gain", "net-positive"}},
		{"stateful noop", model.ActionNoop, false, stateful, []string{"stateful pod", "Phorvex selected no action"}, []string{"considered", "inviolably", "net-positive"}},
		{"ai-native selected", model.ActionKVReset, true, stateless, []string{"Phorvex selected kv-reset", "no non-destructive equivalent"}, []string{"considered", "used", "keeps serving", "skipped"}},
		{"ai-native fallback", model.ActionKVReset, false, stateless, []string{"Phorvex considered kv-reset", "did not select"}, []string{"Phorvex selected", "used", "keeps serving"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			note := counterfactualNote(c.action, c.selected, c.view)
			if !strings.HasPrefix(note, "R6") {
				t.Errorf("R6 comparison lost: %q", note)
			}
			for _, w := range c.want {
				if !strings.Contains(note, w) {
					t.Errorf("missing %q in %q", w, note)
				}
			}
			for _, r := range c.reject {
				if strings.Contains(note, r) {
					t.Errorf("must not contain %q: %q", r, note)
				}
			}
			// Selection is not actuation, for every arm.
			for _, claim := range []string{"Phorvex quarantined", "Phorvex used", "Phorvex chose", "keeps serving"} {
				if strings.Contains(note, claim) {
					t.Errorf("actuation/availability claim %q in %q", claim, note)
				}
			}
		})
	}
}
