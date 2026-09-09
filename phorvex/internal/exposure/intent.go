/*
 * Phorvex — synchronous per-action actuation intent (M-23).
 */

package exposure

import (
	"sync"
	"time"
)

// Intents records, per (slot, variable), the wall-clock time an action was EMITTED —
// stamped synchronously at the emit boundary, before the next observed snapshot moves
// the exposure Clock. It closes the cross-tick burst hole M-23 targets: between a
// successful actuation and the tick that first observes the resulting `*-epoch` marker,
// the observed clock still reads "long ago", so a second emit of the same (pod, action)
// would pass the anti-over-rotation guard. The guard takes min(observed-since,
// intent-since) — the most recent of the two — so intent throttles that gap.
//
// Keyed by the same owner-scoped slotKey as Clock, and GC'd the same way (RetainOwner each tick).
type Intents struct {
	mu sync.Mutex
	at map[string]map[string]time.Time // slotKey -> variable -> marked-at
}

// NewIntents returns an empty intent store.
func NewIntents() *Intents { return &Intents{at: make(map[string]map[string]time.Time)} }

// Mark records that `variable` was actuated on this slot at `now`. Called once per
// emitted move, on the SUCCESSFUL-emit path (a failed actuation must not throttle its
// retry). A later Mark overwrites — only the most recent emission matters.
func (i *Intents) Mark(owner, ns, pod, variable string, now time.Time) {
	if i == nil || pod == "" || variable == "" {
		return
	}
	key := slotKey(owner, ns, pod)
	i.mu.Lock()
	defer i.mu.Unlock()
	vars := i.at[key]
	if vars == nil {
		vars = make(map[string]time.Time)
		i.at[key] = vars
	}
	vars[variable] = now
}

// Since returns time-since-emission per variable for a slot (empty if none). A negative
// interval (clock skew) is clamped to 0, matching Clock.Since.
func (i *Intents) Since(owner, ns, pod string, now time.Time) map[string]time.Duration {
	if i == nil {
		return nil
	}
	key := slotKey(owner, ns, pod)
	i.mu.Lock()
	defer i.mu.Unlock()
	vars := i.at[key]
	if len(vars) == 0 {
		return nil
	}
	out := make(map[string]time.Duration, len(vars))
	for v, ts := range vars {
		d := now.Sub(ts)
		if d < 0 {
			d = 0
		}
		out[v] = d
	}
	return out
}

// RetainOwner prunes this owner's intent slots not in keep (a set of full slot keys),
// mirroring Clock.RetainOwner so a departed pod's intent is dropped with its clock.
// Returns the count dropped.
func (i *Intents) RetainOwner(owner string, keep map[string]struct{}) int {
	if i == nil {
		return 0
	}
	prefix := owner + "\x00"
	i.mu.Lock()
	defer i.mu.Unlock()
	dropped := 0
	for k := range i.at {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			if _, ok := keep[k]; !ok {
				delete(i.at, k)
				dropped++
			}
		}
	}
	return dropped
}
