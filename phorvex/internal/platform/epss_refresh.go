/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import (
	"context"
	"time"
)

// epss_refresh.go re-reads the exploitability cache while the operator runs.
//
// WHY THIS EXISTS. LoadEPSSFromFile is called once at startup, which is correct for a
// hand-curated file baked into a ConfigMap and never touched again. It stops being correct the
// moment a scanner pipeline owns that ConfigMap: kubelet updates the mounted file within a
// minute or so of the ConfigMap changing, but nothing re-reads it, so a freshly-scanned feed
// stays invisible until the pod happens to restart. A pipeline whose output is only observed by
// accident is not a wired feed — it is a file being written into a void (PHVX-14b).
//
// WHAT IT DELIBERATELY DOES NOT DO. It never clears a good cache. A refresh that reads a
// missing, unreadable or malformed file leaves the previous entries in place and reports the
// error, because the alternative — every pod silently dropping to EPSS 1.0 because a ConfigMap
// was mid-edit — is a fleet-wide loss of signal caused by the thing meant to supply it. Honest-
// absent is the right answer when there has never been data; it is the wrong answer when the
// data exists and one read failed.

// EPSSRefresher periodically re-seeds the exploitability cache from path. It satisfies
// controller-runtime's Runnable, so the manager owns its lifetime and shuts it down with
// everything else.
type EPSSRefresher struct {
	// Path is the mounted cache file. Empty disables the refresher entirely.
	Path string
	// Interval between reads. Non-positive disables the refresher.
	Interval time.Duration
	// OnReload, when set, is called after each successful read with the resulting entry count
	// and whether the count changed. Used for logging and metrics; never for control flow.
	OnReload func(entries int, changed bool)
	// OnError, when set, is called when a read fails. The previous cache stays in force.
	OnError func(err error)
}

// NeedLeaderElection reports false: the cache is per-process package state, so every replica
// must refresh its own copy. Gating this on leadership would leave standby replicas serving
// stale exploitability scores and then promote one of them on failover.
func (r *EPSSRefresher) NeedLeaderElection() bool { return false }

// Start blocks until ctx is cancelled, re-reading the cache every Interval. It returns nil on
// cancellation so a disabled or stopped refresher never fails the manager.
func (r *EPSSRefresher) Start(ctx context.Context) error {
	if r.Path == "" || r.Interval <= 0 {
		return nil // not wired: startup seeding stands
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.refreshOnce()
		}
	}
}

// refreshOnce performs one read. Split out so the failure semantics are directly testable.
func (r *EPSSRefresher) refreshOnce() {
	before := EPSSLoaded()
	if err := LoadEPSSFromFile(r.Path); err != nil {
		// The cache is untouched: LoadEPSSFromFile only calls SeedEPSS after a successful parse.
		if r.OnError != nil {
			r.OnError(err)
		}
		return
	}
	after := EPSSLoaded()
	if r.OnReload != nil {
		r.OnReload(after, after != before)
	}
}
