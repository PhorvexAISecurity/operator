package runner

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

type emissionBatch struct {
	at    time.Time
	count int
}
type emissionHistory struct {
	uid         string
	since, last time.Time
	window      time.Duration
	batches     []emissionBatch
}

// Reporting only. A restart/window expansion loses completeness for one window;
// retained observations are lower bounds until then. Never feeds solver accounting.
func (m *Manager) emissionWindow(e *policyEntry, n int, now time.Time) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.emits == nil {
		m.emits = make(map[string]*emissionHistory)
	}
	key := e.key.String()
	window := e.spec.EffectiveAntiOverRotationWindow()
	// A stale tick cannot put another UID's observations into the current policy.
	if current := m.policies[key]; current != nil && current.uid != e.uid {
		return 0, false
	}
	h := m.emits[key]
	if h == nil || h.uid != e.uid {
		h = &emissionHistory{uid: e.uid, since: now, window: window}
		m.emits[key] = h
	}
	if now.Before(h.last) || window > h.window {
		h.since = now
	}
	h.last = now
	h.window = window
	kept := make([]emissionBatch, 0, len(h.batches)+1)
	count := 0
	for _, b := range h.batches {
		if b.at.After(now.Add(-window)) {
			kept = append(kept, b)
			count += b.count
		}
	}
	if n > 0 {
		kept = append(kept, emissionBatch{at: now, count: n})
		count += n
	}
	h.batches = kept
	return count, !now.Before(h.since.Add(window))
}

func setEmissionHistoryCondition(p *v1alpha1.PhorvexPolicy, n int, complete bool) {
	status, reason, message := metav1.ConditionTrue, "CompleteWindow", "emission count covers the full trailing window; emission is not confirmed effect"
	if !complete {
		status, reason, message = metav1.ConditionUnknown, "HistoryIncomplete", fmt.Sprintf("history before observation/restart is unavailable; %d observed emissions is a lower bound, not a complete count", n)
	}
	meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{Type: "EmissionHistory", Status: status, Reason: reason, Message: message, ObservedGeneration: p.Generation})
}

// Runs each base tick before ingest/cadence gating. Only emission fields are
// changed; it neither invents a successful tick nor refreshes LastTickTime.
func (m *Manager) refreshEmissionStatus(ctx context.Context, now time.Time) {
	m.mu.RLock()
	entries := make([]*policyEntry, 0, len(m.policies))
	for _, e := range m.policies {
		entries = append(entries, e)
	}
	m.mu.RUnlock()
	for _, e := range entries {
		n, complete := m.emissionWindow(e, 0, now)
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var p v1alpha1.PhorvexPolicy
			if err := m.Client.Get(ctx, e.key, &p); err != nil {
				return err
			}
			if string(p.UID) != e.uid {
				return nil
			}
			before := p.Status.DeepCopy()
			p.Status.MovesThisWindow = n
			p.Status.Actuated = n > 0
			setEmissionHistoryCondition(&p, n, complete)
			if reflect.DeepEqual(*before, p.Status) {
				return nil
			}
			return m.Client.Status().Update(ctx, &p)
		})
		if err != nil {
			m.Log.Error(err, "emission status refresh failed; persisted observation may be stale", "policy", e.key.String())
		}
	}
}
