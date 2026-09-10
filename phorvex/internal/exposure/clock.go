/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package exposure is the per-VARIABLE exposure-clock scaffold (PRD §4.2 signal #4
// "exposure / time-since-last-move" + §5.3 per-variable C_norm). For each workload
// slot it tracks, per mutable VARIABLE (pod identity, node placement, image, env,
// GPU binding, network identity, session), the time since that variable last
// CHANGED — so a later phase that mutates image/env/GPU IN PLACE gets independent
// per-variable exposure without a schema change. M-23/M-30 feed eight consumed
// dimensions through model.ExposureFingerprints. Node placement, image, env and
// GPU binding remain declared-only. The clock generically tracks supplied keys.
//
// Restart-safe (NFR3): on first sight of a slot the clock seeds each variable's
// change time from the pod's StartedAt, so after an operator restart exposure is
// reconstructed from pod age rather than reset to zero.
package exposure

import (
	"sync"
	"time"
)

// Observation is one ingest sample of a pod's per-variable fingerprints. A
// fingerprint is any stable string that changes exactly when the variable changes
// (UID for pod identity, node name for placement, image digest for image, ...).
type Observation struct {
	Owner        string
	Namespace    string
	Pod          string
	StartedAt    time.Time
	Fingerprints map[string]string
}

type entry struct {
	fingerprint string
	changedAt   time.Time
}

// Clock is the concurrency-safe per-(slot,variable) exposure tracker.
type Clock struct {
	mu    sync.Mutex
	state map[string]map[string]entry // slotKey -> variable -> entry
}

// NewClock returns an empty Clock.
func NewClock() *Clock {
	return &Clock{state: make(map[string]map[string]entry)}
}

// slotKey is owner-scoped (M-140): the first segment is the disjoint owner key,
// not the display tenant name, so removing one policy cannot delete a different
// policy's slots merely because the two share a spec.tenant.
func slotKey(owner, ns, pod string) string {
	return owner + "\x00" + ns + "\x00" + pod
}

// Observe records the current fingerprints for a slot at time now. A variable seen
// for the first time seeds its change time from StartedAt (restart-safe); a variable
// whose fingerprint differs from the last sample has its change time set to now.
func (c *Clock) Observe(o Observation, now time.Time) {
	if o.Pod == "" {
		return
	}
	key := slotKey(o.Owner, o.Namespace, o.Pod)
	c.mu.Lock()
	defer c.mu.Unlock()
	vars := c.state[key]
	if vars == nil {
		vars = make(map[string]entry)
		c.state[key] = vars
	}
	for v, fp := range o.Fingerprints {
		prev, ok := vars[v]
		switch {
		case !ok:
			seed := o.StartedAt
			if seed.IsZero() || seed.After(now) {
				seed = now
			}
			vars[v] = entry{fingerprint: fp, changedAt: seed}
		case prev.fingerprint != fp:
			vars[v] = entry{fingerprint: fp, changedAt: now}
		}
	}
}

// Since returns the time-since-last-change per tracked variable for a slot.
func (c *Clock) Since(owner, ns, pod string, now time.Time) map[string]time.Duration {
	key := slotKey(owner, ns, pod)
	c.mu.Lock()
	defer c.mu.Unlock()
	vars := c.state[key]
	out := make(map[string]time.Duration, len(vars))
	for v, e := range vars {
		d := now.Sub(e.changedAt)
		if d < 0 {
			d = 0
		}
		out[v] = d
	}
	return out
}

// Forget drops a slot's clocks (call on pod deletion to bound memory).
func (c *Clock) Forget(owner, ns, pod string) {
	key := slotKey(owner, ns, pod)
	c.mu.Lock()
	delete(c.state, key)
	c.mu.Unlock()
}

// Retain prunes slots not present in the keep set (slotKeys). Returns the number of
// slots dropped. Used each tick to garbage-collect departed pods.
func (c *Clock) Retain(keep map[string]struct{}) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped := 0
	for k := range c.state {
		if _, ok := keep[k]; !ok {
			delete(c.state, k)
			dropped++
		}
	}
	return dropped
}

// SlotKey exposes the canonical slot key so callers can build the Retain keep-set.
func SlotKey(owner, ns, pod string) string { return slotKey(owner, ns, pod) }

// RetainOwner prunes only THIS owner's slots that are not in keep (a set of full
// slot keys). Used each tick so an owner's departed pods are GC'd without disturbing
// other owners whose policies did not tick this round, and on lifecycle removal with
// an empty keep set. Returns the count dropped.
func (c *Clock) RetainOwner(owner string, keep map[string]struct{}) int {
	prefix := owner + "\x00"
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped := 0
	for k := range c.state {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			if _, ok := keep[k]; !ok {
				delete(c.state, k)
				dropped++
			}
		}
	}
	return dropped
}

// Len reports the number of tracked slots (for metrics/tests).
func (c *Clock) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.state)
}
