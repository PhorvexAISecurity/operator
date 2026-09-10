package decision

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
)

// Deterministic multi-tick replay of the old and new producer. The only old
// producer difference is its extra nodePlacement fingerprint. All record fields
// outside that exposure key, including candidates/vetoes/facts/selection, must match.
func TestM030ReplayOnlyRemovesNodePlacement(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	oldClock, newClock := exposure.NewClock(), exposure.NewClock()
	oldEngine, newEngine := NewCoverageEngine(), NewCoverageEngine()
	pol := covPolicy(2)
	pol.TraceEnabled = true
	var evidence []map[string]interface{}
	for tick := 0; tick < 4; tick++ {
		now := base.Add(time.Duration(tick) * time.Minute)
		oldEngine.Now = func() time.Time { return now }
		newEngine.Now = func() time.Time { return now }
		p := model.Pod{Namespace: "ns", Name: "served", UID: "u1", Node: "n1", StartedAt: base.Add(-2 * time.Hour), SessionEpoch: "s1", QuarantineEpoch: "q1", RouteKeyEpoch: "r1", IdentityEpoch: "i1", AdapterEpoch: "a1", DrainEpoch: "d1", GuardrailEpoch: "g1"}
		if tick >= 1 {
			p.Node = "n2"
		}
		if tick >= 2 {
			p.SessionEpoch = "s2"
			p.DrainEpoch = "d2"
		}
		if tick >= 3 {
			p.UID = "u2"
		}
		fp := model.ExposureFingerprints(p)
		if _, ok := fp[model.VarNodePlacement]; ok {
			t.Fatal("nodePlacement is still clocked")
		}
		observe := func(c *exposure.Clock, fingerprints map[string]string) map[string]time.Duration {
			c.Observe(exposure.Observation{Owner: "ns", Namespace: p.Namespace, Pod: p.Name, StartedAt: p.StartedAt, Fingerprints: fingerprints}, now)
			return c.Since("ns", p.Namespace, p.Name, now)
		}
		current := observe(newClock, fp)
		fp[model.VarNodePlacement] = p.Node
		before := observe(oldClock, fp)
		expected := map[string]time.Duration{}
		for k, v := range before {
			if k != model.VarNodePlacement {
				expected[k] = v
			}
		}
		if !reflect.DeepEqual(expected, current) {
			t.Fatalf("tick %d clocks drift: %v vs %v", tick, expected, current)
		}
		run := func(e *CoverageEngine, clocks map[string]time.Duration) json.RawMessage {
			v := covView("served", true, 2*time.Hour, false)
			v.Pod = p
			v.ExposureByVariable = clocks
			ds := e.Decide([]*model.WorkloadView{v}, pol)
			if len(ds) == 0 {
				t.Fatal("empty replay")
			}
			b, err := json.Marshal(ds)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		a, b := run(oldEngine, before), run(newEngine, current)
		if string(a) != string(b) {
			t.Fatalf("tick %d decisions drift: %s vs %s", tick, a, b)
		}
		evidence = append(evidence, map[string]interface{}{"tick": tick, "beforeExposure": before, "afterExposure": current, "decisions": b, "decisionBytesIdentical": true})
	}
	if path := os.Getenv("M030_REPLAY_OUTPUT"); path != "" {
		b, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
