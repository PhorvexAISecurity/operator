/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/recon"
)

// epss.go realizes the PRD context signal #1 (CVE/CVSS posture from image-scan + NVD)
// as a DETERMINISTIC, OFFLINE, honest-absent cache of RAW (epss, cvss) pairs. Since M-104
// the value multiplier itself lives in recon.EPSSMultiplier (the one consumption layer);
// this file only looks the pair up. Rather than
// wrapping the default ctxprov 'sensed-context' provider (which computes AssetValue
// itself — the non-additivity the decision flagged), the exploitability prior enters the
// SAME Layer-C EMR weight via Physics.EPSSMultiplier, multiplying the recon-fact base alongside
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
	// epssRepoLatest is the M-141 repo-level fallback index, rebuilt with the cache: repository
	// (the image reference before "@sha256:" / the tag) -> the cache key of that repository's
	// LATEST scan. Only unambiguous entries are indexed: latest by scanTS, or the single entry
	// when the cache predates scanTS. Two undated entries for one repository are NOT guessed.
	epssRepoLatest = map[string]string{}
)

type epssEntry struct {
	EPSS   float64 // exploit-prediction score [0,1]
	CVSS   float64 // base severity [0,10]
	ScanTS string  // RFC3339 scan time from the feed; "" for caches written before M-141
}

// EPSS lookup bases (M-141). Distinguishable in the record and the counter.
const (
	EPSSBasisExact        = "exact"         // the running digest itself is scored
	EPSSBasisRepoFallback = "repo-fallback" // the latest scan of the same repository, flagged
	EPSSBasisMiss         = "miss"          // nothing for this digest or repository: neutral, present=false
)

// EPSSLookup is the typed answer of the exploitability cache for one running image. It
// carries RAW values only: the value multiplier is computed by recon.EPSSMultiplier, the
// single EPSS consumption layer (M-104).
type EPSSLookup struct {
	EPSS, CVSS    float64 // raw cache values; 0 on a miss
	Present       bool    // a cache entry supplied the value (exact or repo-fallback)
	Basis         string  // EPSSBasis* ("" when imageID is empty: no identity to look up)
	CachedDigest  string  // the cache key that answered (== RunningDigest on exact)
	RunningDigest string  // the pod's ImageID as looked up
	ScanTS        string  // audit only — never a branch condition
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
	next := make(map[string]epssEntry, len(m))
	for k, v := range m {
		next[k] = epssEntry{EPSS: clamp01(v.EPSS), CVSS: v.CVSS}
	}
	replaceEPSS(next)
}

// SeedEPSSEntries is SeedEPSS with scan timestamps (tests and the feed's own verification).
func SeedEPSSEntries(m map[string]struct {
	EPSS   float64
	CVSS   float64
	ScanTS string
}) {
	next := make(map[string]epssEntry, len(m))
	for k, v := range m {
		next[k] = epssEntry{EPSS: clamp01(v.EPSS), CVSS: v.CVSS, ScanTS: v.ScanTS}
	}
	replaceEPSS(next)
}

// LoadEPSSFromFile seeds the exploitability cache from a JSON file mapping image reference/digest ->
// {epss,cvss} — a point-in-time scanner + NVD/FIRST-EPSS export. Returns nil no-op when path is empty
// or the file is missing, so a cluster with no scan feed keeps EPSS honest-absent (1.0) rather than
// fabricating. Deterministic + offline: the decision path never touches the network.
func LoadEPSSFromFile(path string) error {
	_, _, err := loadEPSSFromFile(path, true)
	return err
}

// RefreshEPSSFromFile is the runtime variant: a configured file disappearing is
// an error, not an honest-absent startup. The previous cache remains in force.
func RefreshEPSSFromFile(path string) (entries int, changed bool, err error) {
	return loadEPSSFromFile(path, false)
}

func loadEPSSFromFile(path string, missingOK bool) (entries int, changed bool, err error) {
	if path == "" {
		return EPSSLoaded(), false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if missingOK && os.IsNotExist(err) {
			return EPSSLoaded(), false, nil // startup honest-absence: no feed wired
		}
		return EPSSLoaded(), false, err
	}
	var raw map[string]struct {
		EPSS   float64 `json:"epss"`
		CVSS   float64 `json:"cvss"`
		ScanTS string  `json:"scanTS"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return EPSSLoaded(), false, err
	}
	next := make(map[string]epssEntry, len(raw))
	for k, v := range raw {
		if k == "" || v.EPSS < 0 || v.EPSS > 1 || v.CVSS < 0 || v.CVSS > 10 {
			return EPSSLoaded(), false, fmt.Errorf("invalid EPSS cache entry %q: epss=%v cvss=%v", k, v.EPSS, v.CVSS)
		}
		next[k] = epssEntry{EPSS: v.EPSS, CVSS: v.CVSS, ScanTS: v.ScanTS}
	}
	changed = replaceEPSS(next)
	return len(next), changed, nil
}

func replaceEPSS(next map[string]epssEntry) bool {
	epssMu.Lock()
	defer epssMu.Unlock()
	changed := !reflect.DeepEqual(epssCache, next)
	if changed {
		epssCache = next
		epssRepoLatest = buildRepoIndex(next)
	}
	return changed
}

// epssRepoOf returns the repository part of an image reference: everything before
// "@sha256:..." for a digest reference, before the tag for "repo:tag". No normalisation
// (docker.io/library/x stays distinct from x): the fallback is repo-level, never fuzzy.
func epssRepoOf(imageID string) string {
	if i := strings.Index(imageID, "@"); i >= 0 {
		return imageID[:i]
	}
	slash := strings.LastIndex(imageID, "/")
	if colon := strings.LastIndex(imageID, ":"); colon > slash {
		return imageID[:colon]
	}
	return imageID
}

// buildRepoIndex picks, per repository, the cache key of the latest scan: highest scanTS
// (RFC3339 UTC compares lexically), digest as a deterministic tie-break. A repository whose
// candidates are ALL undated is indexed only when it has exactly one — two undated entries
// cannot be ordered and guessing would be the fuzzy match the ticket forbids.
func buildRepoIndex(cache map[string]epssEntry) map[string]string {
	type cand struct {
		key    string
		scanTS string
	}
	byRepo := map[string][]cand{}
	for k, e := range cache {
		repo := epssRepoOf(k)
		if repo == "" || repo == k {
			continue // no digest/tag separator: nothing to fall back from
		}
		byRepo[repo] = append(byRepo[repo], cand{key: k, scanTS: e.ScanTS})
	}
	out := make(map[string]string, len(byRepo))
	for repo, cs := range byRepo {
		best := cs[0]
		for _, c := range cs[1:] {
			if c.scanTS > best.scanTS || (c.scanTS == best.scanTS && c.key > best.key) {
				best = c
			}
		}
		if best.scanTS == "" && len(cs) > 1 {
			continue // undated and ambiguous: no fallback for this repository
		}
		out[repo] = best.key
	}
	return out
}

// EPSSLoaded reports how many image entries are currently seeded (for scan/audit visibility).
func EPSSLoaded() int {
	epssMu.RLock()
	defer epssMu.RUnlock()
	return len(epssCache)
}

// epssMultiplier returns the M-104 value multiplier for a running image digest — computed by
// recon.EPSSMultiplier, the one consumption layer — or exactly 1.0 (honest-absent) on a miss.
func epssMultiplier(imageID string) float64 {
	lk := lookupEPSS(imageID)
	m, _, _ := recon.EPSSMultiplier(lk.EPSS, lk.CVSS, lk.Present)
	return m
}

// epssInputs exposes the exact source values alongside the multiplier so the
// decision trace can distinguish the honest-neutral default from measured zero.
func epssInputs(imageID string) (multiplier, epss, cvss float64, present bool) {
	lk := lookupEPSS(imageID)
	m, ok, _ := recon.EPSSMultiplier(lk.EPSS, lk.CVSS, lk.Present)
	return m, lk.EPSS, lk.CVSS, ok
}

// lookupEPSS is THE cache lookup (M-141), in this order and no other:
//
//	exact running digest -> latest scan of the same repository (flagged repo-fallback) -> miss.
//
// No fuzzy/nearest-digest match, no cross-repository guess, no age window (a stale entry is
// stale by the fact that no running digest matches it; scanTS is recorded, never branched on),
// and no network: the decision path never resolves a registry — re-resolution is the feed's job.
// Every outcome is counted in phorvex_epss_lookup_total so a stale cache is a metric.
func lookupEPSS(imageID string) EPSSLookup {
	if imageID == "" {
		return EPSSLookup{}
	}
	epssMu.RLock()
	e, ok := epssCache[imageID]
	fallbackKey, hasFallback := "", false
	if !ok {
		fallbackKey, hasFallback = epssRepoLatest[epssRepoOf(imageID)]
		if hasFallback {
			e, ok = epssCache[fallbackKey]
		}
	}
	epssMu.RUnlock()
	switch {
	case ok && !hasFallback:
		metrics.RecordEPSSLookup("hit")
		return EPSSLookup{EPSS: e.EPSS, CVSS: e.CVSS,
			Present: true, Basis: EPSSBasisExact, CachedDigest: imageID, RunningDigest: imageID, ScanTS: e.ScanTS}
	case ok && hasFallback:
		metrics.RecordEPSSLookup("repo-fallback")
		return EPSSLookup{EPSS: e.EPSS, CVSS: e.CVSS,
			Present: true, Basis: EPSSBasisRepoFallback, CachedDigest: fallbackKey, RunningDigest: imageID, ScanTS: e.ScanTS}
	default:
		metrics.RecordEPSSLookup("miss")
		return EPSSLookup{Basis: EPSSBasisMiss, RunningDigest: imageID}
	}
}
