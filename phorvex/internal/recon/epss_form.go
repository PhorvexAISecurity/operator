/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package recon

import "math"

// EPSS consumption — THE one layer (PHORVEXSEC-194 / M-104, ruling Q1 = (a), Q2, Q4).
//
// EPSS×CVSS is a bounded VALUE modifier on the recon fact-weight axis and nothing else: it
// does not enter belief, hazard, kill-chain stage, cost or lambda (a static test enforces
// that). The old anchor (platform: 1 + clamp01(0.5·e + 0.5·c/10)) lifted an image whose
// measured exploit probability was ZERO by up to +50% on CVSS alone; the ruled form does not.
//
//	m = 1 + e·(c/10)   when the pair is present, finite and in domain (e∈[0,1], c∈[0,10])
//	m = 1              otherwise (absent / non-finite / out-of-domain), present=false, reason set
//
// Range [1,2] follows from the domain and is enforced. A MEASURED e = 0 is present=true with
// m = 1: it is evidence, not absence. No constant is fitted here (T3 owns calibration and any
// move to belief/hazard, which must remove this value-side use in the same PR).
const (
	EPSSReasonAbsent        = "absent"         // no usable cache entry for the running image
	EPSSReasonNonFinite     = "non-finite"     // NaN/±Inf in the pair
	EPSSReasonInvalidDomain = "invalid-domain" // e outside [0,1] or c outside [0,10]
)

// EPSSMultiplier returns the ruled multiplier, whether the pair was usable, and the reason
// when it was not. ok=false always means m == 1 exactly.
func EPSSMultiplier(e, c float64, present bool) (m float64, ok bool, reason string) {
	if !present {
		return 1, false, EPSSReasonAbsent
	}
	if math.IsNaN(e) || math.IsInf(e, 0) || math.IsNaN(c) || math.IsInf(c, 0) {
		return 1, false, EPSSReasonNonFinite
	}
	if e < 0 || e > 1 || c < 0 || c > 10 {
		return 1, false, EPSSReasonInvalidDomain
	}
	m = 1 + e*(c/10)
	if m < 1 {
		m = 1
	}
	if m > 2 {
		m = 2
	}
	return m, true, ""
}
