/*
 * GATE 0 (lane p1) — k8s-object-revert == NEW native actuator for AML.T0081
 * (Modify AI Agent Configuration: an operator-trusted ConfigMap the agent re-reads for its
 * instructions / tool descriptors / policy, tampered to drift from its trusted snapshot).
 *
 * Proves OFFLINE, against the logic-frozen brain (the cost-c1e9d5f0 engine, decision math
 * UNCHANGED — this case only ADDS a vocabulary entry, a recon fact + cover, and an honest cost
 * class, and reuses the existing pod-identity exposure clock), that for a valuable, threatened pod carrying a trusted, UID-bound
 * config-object-drift observation the brain SELECTS `k8s-object-revert` over rotate / quarantine
 * — because only restoring the ConfigMap to its operator-trusted snapshot covers the config-object
 * integrity fact (rotate/quarantine churn the POD but the tampered ConfigMap keeps serving the
 * same bad config to every replacement). The ×3 vector dominance that adapter-rotate uses makes
 * the config fact out-rank the generic cheap cover.
 *
 * Additive and touches NO decision logic. The fixture mirrors the live p1-demo scenario: a
 * Deployment-backed pod that mounts an operator-trusted ConfigMap drifted from its snapshot,
 * flagged by a trusted pod-targeting SecurityEvent emitted by p1/p1-attacks.
 */

package decision

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// cfgGate0Engine builds the coverage engine with the PRODUCTION recon profile (ucw-recon), where
// the surgical cover sets (adapter-integrity, config-object-integrity, …) live — exactly as the
// existing adapter/steering selection tests do.
func cfgGate0Engine(t *testing.T) *CoverageEngine {
	t.Helper()
	e := NewCoverageEngine()
	rp, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon profile unavailable")
	}
	e.Recon = rp
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	return e
}

// cfgVictim builds the live-fixture shape: a valuable, Deployment-backed pod carrying a fully-bound
// trusted config-object-drift observation (observed hash != trusted snapshot hash) emitted as a
// pod-targeting event of type AttackVectorConfigObject.
func cfgVictim(bind bool) *model.WorkloadView {
	v := covView("cfg-victim", true /*secrets=valuable*/, 2*time.Hour, false /*Deployment-backed*/)
	// Config tamper is a per-pod object compromise, not a lateral/crown-jewel threat; drop covView's
	// generic crown neighbor so the contest is k8s-object-revert vs rotate/quarantine on THIS pod.
	// Scenario modeling only — no lambda/costCeiling/cost-weight/asset-value is touched.
	v.Neighbors = nil
	if bind {
		v.Pod.SuspectConfigObject = "agent-config"
		v.Pod.K8sObjectRevertObservation = &model.K8sObjectRevertObservation{
			EventName:       "config-drift-cfg-victim",
			EventUID:        "ev-cfg-1",
			CreatorIdentity: "system:serviceaccount:p1:p1-attacks",
			TargetPodUID:    v.Pod.UID, // u-cfg-victim
			ConfigMapName:   "agent-config",
			ObservedSHA256:  "sha256:" + strings.Repeat("b", 64),
			TrustedSHA256:   "sha256:" + strings.Repeat("a", 64),
			CreatedAt:       time.Unix(1_700_000_000, 0).UTC(),
		}
		v.Events = []model.SecurityEventInfo{{
			Name: "config-drift-cfg-victim", UID: "ev-cfg-1",
			Type: model.AttackVectorConfigObject, ThreatLevel: "critical", TargetsPod: true,
			Source: "p1-attacks", CreatorIdentity: "system:serviceaccount:p1:p1-attacks",
			Description: "agent-config ConfigMap drifted from the operator-trusted snapshot (AML.T0081)",
		}}
	} else {
		// Negative control: the SAME valuable, threatened pod, a generic trusted pod-targeting
		// event, but NO config-object-drift observation bound.
		v.Events = []model.SecurityEventInfo{{
			Name: "generic-cfg-victim", UID: "ev-gen-1",
			Type: "drift", ThreatLevel: "critical", TargetsPod: true, Source: "p1-attacks",
			Description: "generic threat, no config-object-drift observation",
		}}
	}
	return v
}

func cfgGate0Policy() model.Policy {
	pol := covPolicy(1)
	pol.ReactiveOnly = true // reactive: calm until a real trusted event targets the pod
	// Enable the surgical revert ALONGSIDE the generic moves so the selection is a genuine contest,
	// not a one-candidate walkover.
	pol.EnabledActions = map[model.Action]bool{
		model.ActionRotate:          true,
		model.ActionQuarantine:      true,
		model.ActionK8sObjectRevert: true,
	}
	return pol
}

func TestGate0_K8sObjectRevert_P1_SelectedForConfigDrift(t *testing.T) {
	e := cfgGate0Engine(t)
	pol := cfgGate0Policy()

	var last model.Decision
	for i := 0; i < 6; i++ { // let the dual lambda settle
		last = e.Decide([]*model.WorkloadView{cfgVictim(true)}, pol)[0]
	}
	if !last.Selected {
		t.Fatalf("expected the config-drifted pod to be SELECTED, got unselected (action=%s)", last.Action)
	}
	if last.Action != model.ActionK8sObjectRevert {
		t.Fatalf("expected ActionK8sObjectRevert (surgical ConfigMap snapshot restore), got %s — rotate/quarantine churn the pod but leave the tampered ConfigMap serving the same bad config", last.Action)
	}
	t.Logf("FROZEN BRAIN SELECTED k8s-object-revert on the config-drifted pod over rotate/quarantine")
}

// Negative control: the same valuable, threatened pod WITHOUT a config-object-drift observation
// must NOT be answered with k8s-object-revert (no config-object-integrity fact exists to cover), so
// the selection above is attributable to the detection, not to proactive churn.
func TestGate0_K8sObjectRevert_P1_NotSelectedWithoutDrift(t *testing.T) {
	e := cfgGate0Engine(t)
	pol := cfgGate0Policy()

	for i := 0; i < 6; i++ {
		d := e.Decide([]*model.WorkloadView{cfgVictim(false)}, pol)[0]
		if d.Action == model.ActionK8sObjectRevert {
			t.Fatalf("no config-object-drift observation => k8s-object-revert must NOT be selected, got action=%s selected=%v", d.Action, d.Selected)
		}
	}
	t.Logf("no bound config-object-drift observation => k8s-object-revert NOT selected; the revert is reactive to a real detected drift only")
}
