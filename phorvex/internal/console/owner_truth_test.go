package console

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// TestOwnerWhyNeverClaimsUnperformedDefence pins the truthfulness invariant of the owner lens.
//
// REGRESSION: ownerWhy switched on `action` alone and ignored `actuated`, so a record that was
// only EVALUATED (Selected=true, Actuated=false) — which the owner feed admits, since its filter
// is `Selected OR Actuated` — was narrated to the customer in the past tense as a completed
// defence ("Cleared injected state on the inference workload without restarting it."). A customer
// reading that believes they were protected when nothing was done.
func TestOwnerWhyNeverClaimsUnperformedDefence(t *testing.T) {
	// Past-tense success phrases that must NEVER appear for a non-actuated record.
	claims := []string{"Cleared injected state", "Replaced the compromised instance", "Contained the threat", "Took a targeted protective action", "Applied a reversible protective change"}
	for _, action := range []string{"kv-reset", "rotate", "quarantine", "adapter-rotate", "warm-swap", "noop", ""} {
		got := ownerWhy(action, false /* actuated */, true, true, false)
		for _, c := range claims {
			if strings.Contains(got, c) {
				t.Errorf("action=%q actuated=false produced a success claim %q in: %s", action, c, got)
			}
		}
	}
	// An actuated record describes dispatch without claiming a confirmed security effect.
	if got := ownerWhy("kv-reset", true, false, false, false); !strings.Contains(got, "Dispatched a cache reset") {
		t.Errorf("actuated kv-reset lost its narrative: %s", got)
	}
}

// TestToOwnerEventNonActuatedIsHonest drives the whole projection: a genuinely-selected but
// NOT-actuated kv-reset (exactly what the live cluster produced while vLLM was unreachable) must
// not reach the customer as a defence, in either the rationale or the R6 counterfactual.
func TestToOwnerEventNonActuatedIsHonest(t *testing.T) {
	ev := ToOwnerEvent(audit.Record{
		Tenant: "vllm", Namespace: "vllm", Pod: "vllm-0",
		Action: string(model.ActionKVReset), Selected: true, Actuated: false,
		Time: time.Now(), Stage: "recon",
	})
	if ev.AttackPrevented {
		t.Error("AttackPrevented must be false when nothing was actuated")
	}
	if strings.Contains(ev.Why, "Cleared injected state") {
		t.Errorf("owner Why claims a flush that never happened: %s", ev.Why)
	}
	if strings.Contains(ev.BlindOutcome, "would have deleted") || strings.Contains(ev.BlindOutcome, "acted on a schedule") {
		t.Errorf("owner BlindOutcome flatters a non-action: %s", ev.BlindOutcome)
	}
}
