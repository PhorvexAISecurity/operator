/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package recon

import "math"

// finite is THE non-finite predicate for the recon weight path (PHORVEXSEC-199 / M-111).
// NaN is the register's case; ±Inf is the same hazard for a clamp (a zero-division upstream)
// and is guarded by the same predicate — labelled as the ticket's own constrained addition.
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// absentReason names the input that was not a number. A non-finite input is recorded as
// ABSENT with this reason and never becomes a value (no fact is minted for the asset).
func absentReason(field string) string { return "non-finite-input: " + field }
