/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"os"
	"testing"
	"time"
)

// TestExportReconstructedEvidence produces the reviewable fixture bundle committed with PHVX-74.
// It is deliberately labelled reconstructed_fixture_not_live: this environment has no kubectl or
// kubeconfig, so aggregate figures from 2026-08-19 can exercise the formulas but cannot become raw
// cluster evidence by being written to CSV. Run:
//
//	PHVX_CALIB_EVIDENCE_OUT="$PWD/../reports/phvx-74-20260819/reconstructed-evidence" \
//	  go test ./internal/calib -run TestExportReconstructedEvidence -count=1
func TestExportReconstructedEvidence(t *testing.T) {
	dir := os.Getenv("PHVX_CALIB_EVIDENCE_OUT")
	if dir == "" {
		dir = t.TempDir()
	}
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	nodes, assets := reconstructedFleet(), reconstructedAssets()
	joint := CalibrateJoint(nodes, assets, 0.95, 0.95, 1, at)

	// This is a reconstructed static history only. It intentionally contains no ready-delay or
	// optimizer observations; absent live outcomes must make every cadence candidate fail, not pass.
	history := make([]CadenceSample, 0, 49)
	for i := 0; i < 49; i++ {
		history = append(history, CadenceSample{
			At: at.Add(time.Duration(i) * 5 * time.Minute), Nodes: nodes, Assets: assets,
		})
	}
	result := RefreshResult{
		GeneratedAt:    at,
		EvidenceSource: "reconstructed_fixture_not_live",
		EvidenceNote:   "rebuilt from reported 2026-08-19 aggregate counts; per-pod rows are synthetic, and no live ready-delay or optimizer observations were available",
		Nodes:          nodes, Assets: assets,
		Joint:      joint,
		ReadyDelay: CalibrateReadyDelay(nil, DefaultReadyGrid, 0.95, at),
		JointSweep: SweepJoint(nodes, assets, DefaultPercentileGrid, 1, DefaultSaturationLimit, at),
		Cadence:    EvaluateCadence(history, DefaultCadences, 0.95, 0.95, 1, DefaultSaturationLimit),
	}
	for _, row := range result.Cadence {
		if row.ClearsThreshold {
			t.Fatalf("cadence %v passed without ready-delay and optimizer evidence", row.Interval)
		}
	}
	if err := Export(dir, result); err != nil {
		t.Fatal(err)
	}
}
