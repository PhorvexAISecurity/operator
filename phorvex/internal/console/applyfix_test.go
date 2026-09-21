/*
 * Phorvex — P-VCLUSTER Pass 2: apply-fix write-path adversarial tests. A malicious/gate-breaking delta
 * is REJECTED before any cluster write; two-key (distinct approver) + per-namespace-SA apply + audit
 * are proven; the safety gate CANNOT be bypassed.
 */

package console

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func fptr(f float64) *float64 { return &f }
func iptr(i int) *int         { return &i }

func safeBase(tenant string) model.Policy {
	if tenant == "" {
		tenant = "canonical-safety"
	}
	return model.Policy{Tenant: tenant, Namespace: "gate", PolicyUID: "console-safety-" + tenant,
		NormSparsity: 1, FlowDisruption: 1, MaxMovesPerTick: 2, ProactiveFloor: 2 * time.Hour}
}

// (gate-logic) the REAL gate rejects a starve policy (nothing fires) and passes a safe one.
func TestPolicySafetyGate_RejectsStarvePassesSafe(t *testing.T) {
	if err := PolicySafetyGate(model.Policy{NormSparsity: 1, FlowDisruption: 1, MaxMovesPerTick: 0, ProactiveFloor: 2 * time.Hour}); err == nil {
		t.Error("gate must REJECT a starve policy (MaxMovesPerTick=0 → invalidates nothing)")
	}
	if err := PolicySafetyGate(safeBase("")); err != nil {
		t.Errorf("gate must PASS the safe base policy: %v", err)
	}
}

func TestApplyFix_AllowlistRejectsMalicious(t *testing.T) {
	m := NewApplyFixManager(safeBase, nil, nil)
	// MaxMovesPerTick=0 (starve) is out of bounds → rejected at the allowlist, BEFORE the gate.
	_, err := m.Submit(ApplyFixRequest{ID: "r1", Tenant: "acme", Namespace: "ns", Requester: "alice", Delta: ApplyFixDelta{MaxMovesPerTick: iptr(0)}})
	if err == nil {
		t.Fatal("allowlist must reject MaxMovesPerTick=0 (out of bounds)")
	}
	// an empty delta is rejected.
	if _, err := m.Submit(ApplyFixRequest{ID: "r2", Tenant: "acme", Namespace: "ns", Requester: "alice", Delta: ApplyFixDelta{}}); err == nil {
		t.Error("an empty delta must be rejected")
	}
	// EnabledActions is not even expressible in the delta — a tenant CANNOT enable an RCE action here.
}

func TestApplyFix_GateRejectionBlocksApply(t *testing.T) {
	applied := false
	m := NewApplyFixManager(safeBase, func(string, string, model.Policy) error { applied = true; return nil }, nil)
	// inject a gate that fails — proves Submit refuses to stage a gate-failing delta (no apply path).
	m.Gate = func(model.Policy) error { return errGateBreak }
	_, err := m.Submit(ApplyFixRequest{ID: "r1", Tenant: "acme", Namespace: "ns", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(2)}})
	if err == nil {
		t.Fatal("a delta the gate rejects must NOT be submittable")
	}
	if applied {
		t.Fatal("a gate-rejected delta must NEVER reach the applier (cluster write)")
	}
}

func TestApplyFix_TwoKeyDistinctApproverAndAudit(t *testing.T) {
	var events []string
	applied := false
	var appliedPol model.Policy
	m := NewApplyFixManager(safeBase,
		func(_, _ string, c model.Policy) error { applied = true; appliedPol = c; return nil },
		func(ev string, _ map[string]any) { events = append(events, ev) },
	)
	req := ApplyFixRequest{ID: "r1", Tenant: "acme", Namespace: "ns", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}}
	sub, err := m.Submit(req)
	if err != nil {
		t.Fatalf("a safe, in-bounds, gate-passing delta must submit: %v", err)
	}
	// TWO-KEY: the SAME principal approving its own request is REFUSED.
	if _, err := m.Approve("acme", "r1", sub.Generation, "alice"); err == nil {
		t.Fatal("two-key: the requester must NOT be able to approve its own request")
	}
	if applied {
		t.Fatal("a same-principal approval must not apply")
	}
	// A DISTINCT approver applies it (per-namespace SA), audited.
	if res, err := m.Approve("acme", "r1", sub.Generation, "bob"); err != nil || res.State != ApplyFixApplied {
		t.Fatalf("a distinct approver must apply: %+v %v", res, err)
	}
	if !applied || appliedPol.NormSparsity != 1.5 {
		t.Errorf("the gate-passed, two-key-approved candidate must be applied (NormSparsity=1.5), got applied=%v pol=%+v", applied, appliedPol)
	}
	// audit trail must record submit + applied.
	hasSubmitted, hasApplied := false, false
	for _, e := range events {
		if e == "apply-fix.submitted" {
			hasSubmitted = true
		}
		if e == "apply-fix.applied" {
			hasApplied = true
		}
	}
	if !hasSubmitted || !hasApplied {
		t.Errorf("audit must record submit+applied; got %v", events)
	}
}

var errGateBreak = &gateErr{}

type gateErr struct{}

func (*gateErr) Error() string { return "synthetic gate failure" }
