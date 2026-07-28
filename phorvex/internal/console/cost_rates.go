/*
 * Phorvex Console — PREVENTION RATES for the annual cost projection.
 *
 * The three cost columns are an ANNUAL exposure projection, so every arm must be the SAME KIND
 * of number: an expected loss over a year, driven by that defender's measured prevention rate.
 *
 * The previous model mixed two incompatible kinds in one row: Phorvex was scored on the BINARY
 * outcome of the single attack just fired (defended => 0 loss, landed => FULL annual loss) while
 * R6 got a flat statistical credit (a hardcoded 20%). Two things went wrong:
 *   1. one unlucky attack projected a FULL year of loss, so "WITH PHORVEX" printed higher than
 *      "WITHOUT ANY DEFENSE" and the panel reported "saves $-6/yr" — Phorvex looking worse than
 *      no defence at all;
 *   2. the 20% was not what the harness actually measured. On the SAME scenario set the blind
 *      timer prevents ~46%, not 20% — the old constant UNDERSTATED the competitor by half.
 *
 * These rates are read from the REAL harness metrics (out-<suite>/metrics.jsonl, prevented =
 * !oracleAchieved) and restricted to the scenarios where all three arms actually ran, so the
 * comparison is paired rather than apples-to-oranges. If the harness data is unavailable the
 * caller degrades to the documented fallbacks below (the paired figures measured 2026-07-28:
 * none 0.092 n=1189, r6 0.459 n=898, phorvex 0.583 n=595 over 33 common scenarios).
 */

package console

import (
	"path/filepath"
	"sync"
	"time"
)

// preventionRates carries the three paired, harness-measured prevention rates plus provenance.
type preventionRates struct {
	None, R6, Phorvex float64
	NoneN, R6N, PxN   int
	Scenarios         int
	Measured          bool // false => the documented fallbacks are in use
}

// documented fallbacks — the paired measurement recorded on 2026-07-28 (see file header).
var fallbackRates = preventionRates{None: 0.092, R6: 0.459, Phorvex: 0.583, Measured: false}

var (
	rateOnce   sync.Once
	rateCached preventionRates
	rateAt     time.Time
)

// PreventionRates computes the paired prevention rates from the harness metrics, cached for the
// process lifetime (the out-* corpus is static once baked into the image / synced to disk).
func (c *Config) PreventionRates() preventionRates {
	rateOnce.Do(func() {
		rateCached = c.computeRates()
		rateAt = time.Now()
	})
	return rateCached
}

func (c *Config) computeRates() preventionRates {
	const (
		defNone = "d-nomtd"
		defR6   = "d-r6blindtimer"
		defPx   = "d-phorvex"
	)
	var all []metricRow
	for _, d := range c.outDirs() {
		if rows, ok := readMetrics(filepath.Join(d, "metrics.jsonl")); ok {
			all = append(all, rows...)
		}
	}
	if len(all) == 0 {
		return fallbackRates
	}
	// PAIRING: only scenarios where all three arms actually ran, else a defender that happened to
	// be exercised on an easier subset would score better for the wrong reason.
	seen := map[string]map[string]bool{}
	for _, m := range all {
		if m.Skipped {
			continue
		}
		if seen[m.Defender] == nil {
			seen[m.Defender] = map[string]bool{}
		}
		seen[m.Defender][m.Scenario] = true
	}
	common := map[string]bool{}
	for sc := range seen[defNone] {
		if seen[defR6][sc] && seen[defPx][sc] {
			common[sc] = true
		}
	}
	if len(common) == 0 {
		return fallbackRates
	}
	type acc struct{ prevented, n int }
	tally := map[string]*acc{defNone: {}, defR6: {}, defPx: {}}
	for _, m := range all {
		if m.Skipped || !common[m.Scenario] {
			continue
		}
		a, ok := tally[m.Defender]
		if !ok {
			continue
		}
		a.n++
		if !m.OracleAchieved {
			a.prevented++
		}
	}
	rate := func(a *acc) float64 {
		if a.n == 0 {
			return 0
		}
		return float64(a.prevented) / float64(a.n)
	}
	if tally[defNone].n == 0 || tally[defR6].n == 0 || tally[defPx].n == 0 {
		return fallbackRates
	}
	return preventionRates{
		None: rate(tally[defNone]), R6: rate(tally[defR6]), Phorvex: rate(tally[defPx]),
		NoneN: tally[defNone].n, R6N: tally[defR6].n, PxN: tally[defPx].n,
		Scenarios: len(common), Measured: true,
	}
}
