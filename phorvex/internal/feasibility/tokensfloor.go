/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package feasibility

import "github.com/phorvex/phorvex/internal/model"

// tokensFloor is the PRD Layer-A "tokens/sec >= floor" hard law for AI serving — the
// constraint littleslaw.go:78 CLAIMS is enforced but which no constraint actually read
// until now. It vetoes ROTATING the sole server of an inference workload that is already
// below its tokens/sec SLO floor, because a rotate drops the replacement to ~0 tok/s
// through the cold/warm-load window and would breach the floor with no headroom to
// absorb it. Honest-absent: no floor configured, or no telemetry, or replica headroom
// exists (the availability floor covers that case) => feasible.
type tokensFloor struct{}

func (tokensFloor) Name() string { return "tokens-floor" }

func (tokensFloor) Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	if pol.MinTokensPerSec <= 0 || !view.Telemetry.Present {
		return feasible // unconstrained / honest-absent
	}
	if move.Action != model.ActionRotate {
		return feasible // quarantine/noop don't drop throughput to zero
	}
	// Only the SOLE server lacks headroom to absorb a warm-load excursion; with >1
	// ready replica the availability floor governs instead.
	soleServer := view.Pod.DesiredReplicas <= 1 && view.Pod.ReadyReplicas <= 1
	if soleServer && view.Telemetry.TokensPerSec > 0 && view.Telemetry.TokensPerSec < float64(pol.MinTokensPerSec) {
		return Verdict{Feasible: false, Reason: "tokens/sec below floor on the sole server: rotate would breach the inference SLO"}
	}
	return feasible
}

func init() { Registry.Register(tokensFloor{}) }
