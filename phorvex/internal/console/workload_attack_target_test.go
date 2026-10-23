package console

import "testing"

func TestAnAttackNeverTargetsAQuarantinedPod(t *testing.T) {
	for name, tc := range map[string]struct {
		list    string
		pod     string
		skipped int
	}{
		"first running":      {"demo-0|ReplicaSet|Running|\ndemo-1|ReplicaSet|Running|\n", "demo-0", 0},
		"phoenix quarantine": {"demo-0|AdaptiveMovingTargetDefense|Running|\ndemo-1|ReplicaSet|Running|\n", "demo-1", 1},
		// The native backend leaves no owner: its label and broken selectors mark the Pod.
		"native quarantine": {"demo-0||Running|b46033b4-fdff-455d-ba24-a1ffe6c2fbe3\ndemo-1|ReplicaSet|Running|\n", "demo-1", 1},
		"not running":       {"demo-0|ReplicaSet|Pending|\ndemo-1|ReplicaSet|Running|\n", "demo-1", 0},
		"all quarantined":   {"demo-0||Running|q\ndemo-1|AdaptiveMovingTargetDefense|Running|\n", "", 2},
		// An older list without the label column still picks as before.
		"three columns": {"demo-0|ReplicaSet|Running\n", "demo-0", 0},
	} {
		t.Run(name, func(t *testing.T) {
			pod, skipped := pickAttackTarget(tc.list)
			if pod != tc.pod || skipped != tc.skipped {
				t.Fatalf("picked %q skipping %d, want %q skipping %d", pod, skipped, tc.pod, tc.skipped)
			}
		})
	}
}
