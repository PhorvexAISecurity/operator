/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import (
	"encoding/json"
	"os"
	"sync"
)

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
// WIRED (P4a follow-up): LoadEPSSFromFile below is invoked at operator/scan startup from the
// --epss-cache path (env PHORVEX_EPSS_CACHE), so the cache is populated from a real
// scanner/NVD-FIRST export when one is provided. With no file the cache stays EMPTY and every
// lookup honest-degrades to 1.0 — the prior is data-driven, never fabricated.
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

// LoadEPSSFromFile seeds the exploitability cache from a JSON file mapping image reference/digest ->
// {epss,cvss} — a point-in-time scanner + NVD/FIRST-EPSS export. Returns nil no-op when path is empty
// or the file is missing, so a cluster with no scan feed keeps EPSS honest-absent (1.0) rather than
// fabricating. Deterministic + offline: the decision path never touches the network.
func LoadEPSSFromFile(path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // honest-absent: no feed wired
		}
		return err
	}
	var raw map[string]struct {
		EPSS float64 `json:"epss"`
		CVSS float64 `json:"cvss"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	m := make(map[string]struct {
		EPSS float64
		CVSS float64
	}, len(raw))
	for k, v := range raw {
		m[k] = struct {
			EPSS float64
			CVSS float64
		}{EPSS: v.EPSS, CVSS: v.CVSS}
	}
	SeedEPSS(m)
	return nil
}

// EPSSLoaded reports how many image entries are currently seeded (for scan/audit visibility).
func EPSSLoaded() int {
	epssMu.RLock()
	defer epssMu.RUnlock()
	return len(epssCache)
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
