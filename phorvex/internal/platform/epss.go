/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import "sync"

// epss.go realizes the PRD context signal #1 (CVE/CVSS posture from image-scan + NVD)
// as a DETERMINISTIC, OFFLINE, honest-absent EMR exploitability multiplier. Rather than
// wrapping the default ctxprov 'sensed-context' provider (which computes AssetValue
// itself — the non-additivity the decision flagged), the exploitability prior enters the
// SAME Layer-C EMR weight via Physics.EPSS, multiplying the recon-fact base alongside
// image-rarity. A known-exploitable image makes its recon facts worth more to invalidate.
//
// SOURCE: an image-digest -> {EPSS in [0,1], CVSS in [0,10]} cache, populated point-in-
// time from a scanner + NVD/FIRST-EPSS (reproducible against PUBLIC data). On a cluster
// with no scan feed (kind, offline) the cache is EMPTY and every lookup degrades to 1.0
// (honest-absent) — the exploitability prior never fabricates a score and never blocks
// the <1s tick.

var (
	epssMu    sync.RWMutex
	epssCache = map[string]epssEntry{}
)

type epssEntry struct {
	EPSS float64 // exploit-prediction score [0,1]
	CVSS float64 // base severity [0,10]
}

// SeedEPSS replaces the offline exploitability cache (from a scanner export or a config
// file). Deterministic; no network in the decision path. Empty map => all lookups 1.0.
//
// [SP-0-PENDING-P4a] UNWIRED: as of P4a SeedEPSS has ZERO callers, so epssCache is empty and
// epssMultiplier returns 1.0 for EVERY image — one of the three EMR dispersion legs is inert.
// Wiring a scanner/NVD-FIRST export feed is a P4a follow-up; until then EPSS must NOT be
// presented as "live today."
func SeedEPSS(m map[string]struct {
	EPSS float64
	CVSS float64
}) {
	epssMu.Lock()
	defer epssMu.Unlock()
	epssCache = map[string]epssEntry{}
	for k, v := range m {
		epssCache[k] = epssEntry{EPSS: clamp01(v.EPSS), CVSS: v.CVSS}
	}
}

// epssMultiplier returns 1 + (0.5*EPSS + 0.5*CVSS/10) in [1,2] for a known-exploitable
// image digest, or 1.0 (honest-absent) when the cache has no entry.
func epssMultiplier(imageID string) float64 {
	if imageID == "" {
		return 1.0
	}
	epssMu.RLock()
	e, ok := epssCache[imageID]
	epssMu.RUnlock()
	if !ok {
		return 1.0
	}
	return 1 + clamp01(0.5*e.EPSS+0.5*e.CVSS/10.0)
}
