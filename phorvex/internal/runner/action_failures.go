package runner

import (
	"fmt"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// failureKey includes the immutable target identity. A recreated same-name Pod must
// never inherit the old Pod's inability to execute an action.
type failureKey struct {
	owner, namespace, uid string
	action                model.Action
}

type failureRecord struct {
	consecutive int
	last        time.Time
	retry       time.Time
}

// actionFailures is owned by the serialized tick loop. The controller may retire
// owners concurrently, so writes are admitted only after Manager's epoch check.
type actionFailures struct{ at map[failureKey]failureRecord }

const maxFailureRecords = 4096

func (f *actionFailures) observe(k failureKey, now time.Time) failureRecord {
	if f.at == nil {
		f.at = make(map[failureKey]failureRecord)
	}
	r := f.at[k]
	r.consecutive++
	r.last = now
	r.retry = time.Time{}
	if r.consecutive >= 2 {
		d := 30 * time.Second
		for i := 2; i < r.consecutive && d < 5*time.Minute; i++ {
			d *= 2
		}
		if d > 5*time.Minute {
			d = 5 * time.Minute
		}
		r.retry = now.Add(d)
	}
	f.at[k] = r
	f.bound()
	return r
}

func (f *actionFailures) reset(k failureKey) { delete(f.at, k) }

func (f *actionFailures) exclusion(k failureKey, now time.Time) (string, bool) {
	r, ok := f.at[k]
	if !ok || r.retry.IsZero() || !now.Before(r.retry) {
		return "", false
	}
	return fmt.Sprintf("action-failure-cooldown: consecutive=%d retry=%s", r.consecutive, r.retry.UTC().Format(time.RFC3339Nano)), true
}

func (f *actionFailures) retain(owner string, live map[string]struct{}) {
	for k := range f.at {
		if k.owner != owner {
			continue
		}
		if _, ok := live[k.namespace+"\x00"+k.uid]; !ok {
			delete(f.at, k)
		}
	}
}

func (f *actionFailures) forgetOwner(owner string) {
	for k := range f.at {
		if k.owner == owner {
			delete(f.at, k)
		}
	}
}

func (f *actionFailures) bound() {
	if len(f.at) <= maxFailureRecords {
		return
	}
	keys := make([]failureKey, 0, len(f.at))
	for k := range f.at {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := f.at[keys[i]], f.at[keys[j]]
		if !a.last.Equal(b.last) {
			return a.last.Before(b.last)
		}
		return fmt.Sprintf("%s/%s/%s/%s", keys[i].owner, keys[i].namespace, keys[i].uid, keys[i].action) < fmt.Sprintf("%s/%s/%s/%s", keys[j].owner, keys[j].namespace, keys[j].uid, keys[j].action)
	})
	for _, k := range keys[:len(keys)-maxFailureRecords] {
		delete(f.at, k)
	}
}
