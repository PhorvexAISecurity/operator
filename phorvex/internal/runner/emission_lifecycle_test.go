package runner

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/decision"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Exercise the real Upsert/lifecycle path: replacing an owner must retire its
// epoch AND reset reporting history without letting a stale tick repopulate it.
func TestM011M140ReplacementIsolatesEmissionHistoryAndEpoch(t *testing.T) {
	m := m140Manager(decision.NewCoverageEngine())
	p := m140Policy("policy", "tenant", "old-uid")
	p.Spec.Budget.AntiOverRotationWindow = metav1.Duration{Duration: time.Minute}
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	old := m.policies["ns/policy"]
	oldEpoch := m.ownerEpoch(old.ownerKey())
	t0 := time.Unix(100000, 0)
	m.emissionWindow(old, 2, t0)
	if err := m.Upsert(p.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if n, _ := m.emissionWindow(m.policies["ns/policy"], 0, t0.Add(time.Second)); n != 2 {
		t.Fatalf("same-UID update lost emissions: %d", n)
	}
	if !m.ownerCurrent(old.ownerKey(), oldEpoch) {
		t.Fatal("same-UID update invalidated owner epoch")
	}
	p.UID = "new-uid"
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	current := m.policies["ns/policy"]
	if _, exists := m.emits["ns/policy"]; exists {
		t.Fatal("replacement retained predecessor's emission history")
	}
	if m.ownerCurrent(old.ownerKey(), oldEpoch) || len(m.lifecycle) != 1 {
		t.Fatal("replacement did not invalidate and enqueue old owner")
	}
	if n, complete := m.emissionWindow(old, 5, t0.Add(2*time.Second)); n != 0 || complete {
		t.Fatal("stale tick was accepted after replacement")
	}
	if n, complete := m.emissionWindow(current, 0, t0.Add(3*time.Second)); n != 0 || complete {
		t.Fatal("replacement inherited counts or completeness")
	}
	m.emissionWindow(current, 1, t0.Add(4*time.Second))
	m.DrainLifecycle()
	if m.ownerCurrent(old.ownerKey(), oldEpoch) || !m.ownerCurrent(current.ownerKey(), m.ownerEpoch(current.ownerKey())) {
		t.Fatal("drain did not preserve replacement owner isolation")
	}
	if n, _ := m.emissionWindow(current, 0, t0.Add(5*time.Second)); n != 1 {
		t.Fatalf("old-owner drain erased replacement emissions: %d", n)
	}
	if n, complete := m.emissionWindow(current, 0, t0.Add(64*time.Second)); n != 0 || !complete {
		t.Fatal("replacement window did not independently expire and become complete")
	}
}
