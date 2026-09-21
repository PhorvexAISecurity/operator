/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import (
	"math"
	"sort"

	"github.com/phorvex/phorvex/internal/model"
)

// epss_aggregate.go collapses an image's vulnerability list into the ONE (epss, cvss) pair the
// exploitability multiplier consumes (PHVX-14b).
//
// EPSS is scored per CVE; epssMultiplier is per image. An image routinely carries tens to
// hundreds of CVEs, so the collapse is a modelling choice, and the wrong choice produces a term
// that looks wired and ranks nothing — which is precisely the failure PHVX-24 is about.
//
// The rule is nearest-rank P99 over the image's own EPSS values, taking the CVSS of that same
// CVE. Derived by measurement against the real FIRST.org EPSS corpus (360,781 CVEs, 2026-08-18),
// simulating fleets of 40 images and scoring them through the SHIPPED multiplier
// 1 + clamp01(0.5*EPSS + 0.5*CVSS/10). Two rules were eliminated outright and two more lost:
//
//	rule   | multiplier spread | correlation with image size
//	-------+-------------------+----------------------------
//	max    |   0.407           |   0.29     <- ranks by image SIZE, not exploitability
//	P99    |   0.399           |   0.01     <- same discrimination, no size artefact
//	P97    |   0.270           |  -0.05
//	P95    |   0.131           |  -0.03     <- collapses once images share base layers
//
// (measured with 70% base-layer sharing, which is what a real fleet looks like; under 90%
// sharing P99 beats max outright, 0.367 vs 0.353.)
//
// ELIMINATED, and why they are worth naming so nobody re-proposes them:
//
//	noisy-OR, 1-prod(1-p): the probabilistically "correct" aggregation, and unusable here. It
//	reaches 0.9995 at 200 CVEs and exactly 1.0000 at 500, so every real image scores the
//	maximum. It would replace a dead input with a dead input.
//
//	mean: 60% of all CVEs score below 0.01, so the mean sits at ~0.027 regardless of how many
//	CVEs an image has or how severe they are. It carries no ranking information at all.
//
// Why P99 behaves: with nearest rank, ceil(0.99*n) == n for n <= 99, so on a short CVE list P99
// and max are literally the same value. n=100 is the first size at which P99 steps off the
// maximum. They only diverge once the list is long — which is exactly where max stops measuring
// exploitability and starts measuring image size.
const epssAggregatePercentile = model.PlatformEPSSAggregatePercentile

// Vuln is one scored vulnerability found in an image.
type Vuln struct {
	CVE  string
	EPSS float64 // exploit-prediction score [0,1]
	CVSS float64 // base severity [0,10]
}

// AggregateVulns collapses an image's vulnerabilities to the single scored CVE that represents
// it, returning that CVE and true. Returns false for an empty list, so a clean image stays
// honest-absent (multiplier 1.0) rather than being assigned a fabricated zero.
//
// The returned pair always belongs to ONE REAL CVE. Taking the highest EPSS from one CVE and
// the highest CVSS from another would produce a vulnerability that does not exist, and the
// multiplier weights the two halves equally, so that invention would land squarely in the
// score. A rank-based selector avoids the question entirely: it returns an element, not a
// statistic.
func AggregateVulns(vs []Vuln) (Vuln, bool) {
	if len(vs) == 0 {
		return Vuln{}, false
	}
	// Sort by EPSS, then CVE id so ties are broken deterministically: the same scan must
	// produce the same score on every replica and on every re-run.
	s := append([]Vuln(nil), vs...)
	sort.Slice(s, func(i, j int) bool {
		if s[i].EPSS != s[j].EPSS {
			return s[i].EPSS < s[j].EPSS
		}
		return s[i].CVE < s[j].CVE
	})

	rank := int(math.Ceil(epssAggregatePercentile * float64(len(s))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(s) {
		rank = len(s)
	}
	return s[rank-1], true
}

// AggregateToEntry converts an image's vulnerability list into the cache entry shape SeedEPSS
// consumes. ok is false for a clean image, which the caller must leave OUT of the cache so the
// lookup degrades to honest-absent 1.0 rather than recording a real zero.
func AggregateToEntry(vs []Vuln) (epss, cvss float64, ok bool) {
	v, ok := AggregateVulns(vs)
	if !ok {
		return 0, 0, false
	}
	return v.EPSS, v.CVSS, true
}
