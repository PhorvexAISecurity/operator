/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package killchain

// EvalMode distinguishes the ACTUAL production evaluation of a tick from a COUNTERFACTUAL
// (shadow) one. It is threaded explicitly through the assessment and action-set path
// (M-163) rather than inferred from a flag near the end, because the divergence starts at
// the very first producer: the shadow arm derives its own stage from a different physics
// witness, and any state that stage touches on the way through is production state.
//
// Production is the zero value, so a caller that predates the mode — an offline producer,
// a benchmark, a legacy test — keeps the committing behaviour it has always had.
//
//   - EvalProduction: the one evaluation whose result is acted on. It advances the stage
//     clock, the conjugate prior, the dual price and the operational counters.
//   - EvalShadow: reads exactly the same existing state, computes the hypothetical result
//     from it, and writes none of it. It must be impossible for the number of shadow
//     evaluations in a tick to change the next production decision.
type EvalMode uint8

const (
	// EvalProduction is the real, state-advancing evaluation (zero value).
	EvalProduction EvalMode = iota
	// EvalShadow is a read-only counterfactual evaluation.
	EvalShadow
)

// Commits reports whether this evaluation may write learned state or move an operational
// counter. Predicates read as `mode.Commits()` at every write site, so adding a future mode
// cannot silently inherit write permission by falling through an `!= EvalShadow` test.
func (m EvalMode) Commits() bool { return m == EvalProduction }

// String names the mode for traces and test failures.
func (m EvalMode) String() string {
	if m == EvalShadow {
		return "shadow"
	}
	return "production"
}
