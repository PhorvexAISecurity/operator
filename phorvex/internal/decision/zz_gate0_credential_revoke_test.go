package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// TestGate0CredentialRevokeSelectableFrozenBrain is the Gate-0 offline proof for the
// credential-revoke loop (lane p3): the FROZEN decision engine (ucw-recon, logic unchanged,
// only additive cover/fact) SELECTS the surgical credential-revoke (stolen SA-token invalidation)
// for a pod with a trusted stolen-credential observation, OVER rotate and quarantine, with NO
// knob tuning — and does NOT select it without the observation (purely additive; rotate/quarantine
// behaviour is unchanged when no credential theft is observed).
//
// Scenario modelling: the credential-revoke attacks (AML.T0055 Unsecured Credentials / ATT&CK
// T1552.004 / T1078 Valid Accounts) are the reuse of a bearer token the attacker ALREADY HOLDS
// from OUTSIDE the pod — not lateral movement to a high-value neighbour (that is quarantine's
// job). Evicting (rotate) or network-containing the pod does not invalidate a credential an
// external attacker holds; only revoking the credential defends. So the fixture has NO crown
// neighbour under lateral attack; the threat is the stolen credential, covered uniquely by
// credential-revoke.
func TestGate0CredentialRevokeSelectableFrozenBrain(t *testing.T) {
	v := covView("credrev", true, 2*time.Hour, false)
	// Pure stolen-credential scenario: the pod's OWN leaked SA token is the threat, not a lateral
	// edge to a valued neighbour. Drop the generic crown neighbour so quarantine's lateral-edge
	// cover is (correctly) empty here — if a crown WERE under active lateral attack, a full
	// quarantine could legitimately win, which is not this attack.
	v.Neighbors = nil
	v.Pod.CredentialRevokeObservation = &model.CredentialRevokeObservation{
		EventName: "p3-credtheft-1", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:p3:p3-attacks",
		TargetPodUID: v.Pod.UID,
		PolicyName:   "demo-api-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
		ServiceAccountName: "demo-api-cred", CredentialSecrets: []string{"demo-api-cred-token"},
		CredentialSHA256: "cred-sha",
		CreatedAt:        time.Now(),
	}

	pol := covPolicy(1)
	pol.PolicyName, pol.PolicyUID, pol.PolicyGeneration = "demo-api-defense", "policy-uid", 1
	// Enable all three competing responses: prove the frozen engine prefers the surgical credential
	// revocation over BOTH the full-kill rotate and the full-containment quarantine.
	pol.EnabledActions = map[model.Action]bool{
		model.ActionRotate: true, model.ActionQuarantine: true, model.ActionCredentialRevoke: true,
	}

	e := NewCoverageEngine()
	rp, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("missing UCW profile")
	}
	e.Recon = rp

	// The credential fact must reach the candidate set as credential-revoke cover and NOWHERE else.
	fact := (recon.Fact{Scope: recon.ScopePod, Asset: v.Pod.Namespace + "/" + v.Pod.Name, Kind: recon.FactCredentialReuse}).Key()
	set, _ := e.AssembleSet([]*model.WorkloadView{v}, pol)
	foundCover := false
	for _, c := range set.Candidates {
		for _, key := range c.CoverKeys {
			if key == fact {
				if c.Action != model.ActionCredentialRevoke {
					t.Fatalf("credential fact leaked cover to %s", c.Action)
				}
				foundCover = true
			}
		}
	}
	if !foundCover {
		t.Fatalf("credential-theft observation did not reach the candidate set as credential-revoke cover: %+v", set)
	}

	// SELECTION: the frozen engine selects exactly credential-revoke for this asset.
	selected := model.Action("")
	for _, d := range e.Decide([]*model.WorkloadView{v}, pol) {
		if d.Selected {
			if selected != "" {
				t.Fatalf("more than one selected action: %s and %s", selected, d.Action)
			}
			selected = d.Action
		}
	}
	if selected != model.ActionCredentialRevoke {
		t.Fatalf("frozen brain did not select credential-revoke (selected %q) — ordinary policy+cost, no knob tuning", selected)
	}

	// NEGATIVE / additivity: with NO bound observation, credential-revoke has zero cover and is
	// never selected; the pre-existing rotate/quarantine behaviour is unchanged (frozen).
	noObs := covView("credrev", true, 2*time.Hour, false)
	noObs.Neighbors = nil
	noObsSet, _ := e.AssembleSet([]*model.WorkloadView{noObs}, pol)
	for _, c := range noObsSet.Candidates {
		if c.Action == model.ActionCredentialRevoke {
			t.Fatalf("credential-revoke gained a candidate without any observation: %+v", c)
		}
	}
	for _, d := range e.Decide([]*model.WorkloadView{noObs}, pol) {
		if d.Selected && d.Action == model.ActionCredentialRevoke {
			t.Fatalf("credential-revoke selected with no observation: %+v", d)
		}
	}

	// NEGATIVE: a mis-bound observation (wrong target UID) does not qualify.
	badBind := covView("credrev", true, 2*time.Hour, false)
	badBind.Neighbors = nil
	badBind.Pod.CredentialRevokeObservation = &model.CredentialRevokeObservation{
		EventName: "p3-credtheft-1", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:p3:p3-attacks",
		TargetPodUID: "u-someone-else", PolicyName: "demo-api-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
		ServiceAccountName: "demo-api-cred", CredentialSecrets: []string{"demo-api-cred-token"}, CredentialSHA256: "cred-sha",
	}
	if badBind.Pod.HasBoundCredentialRevokeObservation() {
		t.Fatal("observation bound to the wrong pod UID qualified")
	}
}
