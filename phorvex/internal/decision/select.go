/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package decision

import "fmt"

// EngineP1 is the supported decision brain: the submodular recon-coverage optimizer.
const EngineP1 = "p1"

// enginesRemoved names brains that were retired, so selecting one fails with a reason
// instead of being silently ignored or silently aliased to the live brain (M-107).
var enginesRemoved = map[string]string{
	"p0":        "removed; see M-107 (PHORVEXSEC-195)",
	"p0-greedy": "removed; see M-107 (PHORVEXSEC-195)",
}

// SelectOptimizer resolves the --engine value.
//
// The p0 greedy baseline is gone (PHORVEXSEC-195 / M-107): it scored with a second, deprecated
// belief vocabulary — a compromise probability multiplied by an ordinal severity, a product with
// no unit that nonetheless ranked actions. Removal is loud at the boundary: `p0` is REJECTED with
// a named error. It is deliberately not aliased to p1, because that would silently give a caller
// that asked for p0 different semantics than it asked for.
func SelectOptimizer(name string) (Optimizer, error) {
	switch {
	case name == "" || name == EngineP1:
		return NewCoverageEngine(), nil
	default:
		if why, ok := enginesRemoved[name]; ok {
			return nil, fmt.Errorf("unsupported engine %q (%s); the supported brain is %q", name, why, EngineP1)
		}
		return nil, fmt.Errorf("unknown engine %q; the supported brain is %q", name, EngineP1)
	}
}
