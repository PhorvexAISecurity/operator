/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package exposure

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestClockSeedsFromStartedAt(t *testing.T) {
	c := NewClock()
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	started := now.Add(-90 * time.Second)
	c.Observe(Observation{
		Owner: "t", Namespace: "ns", Pod: "p", StartedAt: started,
		Fingerprints: map[string]string{model.VarPodIdentity: "uid-1", model.VarNodePlacement: "n1"},
	}, now)

	since := c.Since("t", "ns", "p", now)
	// First sight: exposure reconstructs from pod age (restart-safe), ~90s.
	if d := since[model.VarPodIdentity]; d < 89*time.Second || d > 91*time.Second {
		t.Errorf("podIdentity exposure = %v, want ~90s (seeded from StartedAt)", d)
	}
}

func TestClockResetsOnFingerprintChange(t *testing.T) {
	c := NewClock()
	t0 := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	c.Observe(Observation{Owner: "t", Namespace: "ns", Pod: "p", StartedAt: t0.Add(-time.Hour),
		Fingerprints: map[string]string{model.VarPodIdentity: "uid-1"}}, t0)

	// Later, the pod is rotated => new UID. Exposure for podIdentity resets to ~0.
	t1 := t0.Add(30 * time.Minute)
	c.Observe(Observation{Owner: "t", Namespace: "ns", Pod: "p", StartedAt: t0.Add(-time.Hour),
		Fingerprints: map[string]string{model.VarPodIdentity: "uid-2"}}, t1)

	since := c.Since("t", "ns", "p", t1)
	if d := since[model.VarPodIdentity]; d > time.Second {
		t.Errorf("after fingerprint change, exposure should reset to ~0, got %v", d)
	}
}

func TestRetainTenantPrunesDeparted(t *testing.T) {
	c := NewClock()
	now := time.Now()
	for _, pod := range []string{"p1", "p2", "p3"} {
		c.Observe(Observation{Owner: "t", Namespace: "ns", Pod: pod, StartedAt: now,
			Fingerprints: map[string]string{model.VarPodIdentity: "u-" + pod}}, now)
	}
	if c.Len() != 3 {
		t.Fatalf("expected 3 slots, got %d", c.Len())
	}
	keep := map[string]struct{}{SlotKey("t", "ns", "p1"): {}}
	dropped := c.RetainOwner("t", keep)
	if dropped != 2 || c.Len() != 1 {
		t.Errorf("RetainTenant should drop p2,p3: dropped=%d len=%d", dropped, c.Len())
	}
}
