/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package slo

import (
	"sort"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// Cause distinguishes who a disruption belongs to.
//
// Two ledgers are needed, not one. The SLO itself is indifferent to cause: a
// replica that was out is out, and the TOTAL budget has to count every outage of
// the service or it will authorise moves the service cannot actually afford.
// But Phorvex's own share has to be separable from it, otherwise there is no way
// to answer whether the defender is the thing eating the budget.
//
// This ledger records CausePhorvex only. The total-service ledger needs
// cluster-wide history that is not collected yet; the type carries the field so
// the two can share it when that arrives, rather than being reconciled later.
type Cause string

const (
	// CausePhorvex is disruption caused by an action Phorvex itself actuated.
	CausePhorvex Cause = "phorvex"
	// CauseService is any other outage of the service. Reserved, not yet emitted.
	CauseService Cause = "service"
)

// Outcome is the action state known at the time an entry is written. It does not
// turn an emitted asynchronous operation into a completed one.
type Outcome string

const (
	OutcomeCompleted       Outcome = "completed"
	OutcomeFailed          Outcome = "failed"
	OutcomeDeadlineExpired Outcome = "deadline_expired"
	OutcomeRolledBack      Outcome = "rolled_back"
	OutcomeNotEmitted      Outcome = "not_emitted"
	OutcomeEmitted         Outcome = "emitted_outcome_unobserved"
	OutcomeRightCensored   Outcome = "right_censored"
)

// ImpactMeasurement distinguishes an observed zero from missing impact data.
type ImpactMeasurement string

const (
	ImpactMeasured   ImpactMeasurement = "measured"
	ImpactUnmeasured ImpactMeasurement = "unmeasured"
)

// Entry is one action observation and its disruption evidence.
type Entry struct {
	// ID identifies one disruption observation across updates. Censored entries are
	// periodically replaced under the same ID until recovery is finally observed.
	ID        string
	Tenant    string
	Namespace string
	Pod       string
	Action    model.Action
	Cause     Cause
	Outcome   Outcome

	// Replicas is how many Ready serving replicas the action removed.
	Replicas int
	// Duration is how long they stayed removed — MEASURED, from actuation to the
	// replacement becoming Ready.
	Duration time.Duration
	// StartedAt is when the Ready replica was removed. It is required for exact
	// overlap accounting at a rolling-window boundary.
	StartedAt time.Time

	// ObservedAt is the end of the known interval: recovery time for an observed
	// event, or the latest observation time for an ongoing censored event.
	ObservedAt time.Time

	// Censored marks an entry whose recovery was never observed, so Duration is a
	// floor rather than the real figure. Censored entries are still counted:
	// dropping them would understate consumption precisely when recovery went
	// worst, which is the direction that matters.
	Censored bool

	// ReplicaImpact records whether Replicas/Duration are an observation. Older
	// positive-disruption entries predate this field and remain measured for
	// backward compatibility; new zero-impact events set it explicitly.
	ReplicaImpact ImpactMeasurement

	// The deterministic contract is frozen at selection time. A historical
	// observation can therefore never be mistaken for the bound used to admit the
	// action, and an unknown bound cannot be serialized as a numeric zero.
	SelectionBoundStatus         BoundStatus
	SelectionBoundFinite         bool
	SelectionBoundReplicaSeconds float64
	SelectionBoundEvidence       string

	// Availability is measured separately from disruption. A replica can be
	// unavailable without breaching the service floor when siblings provide
	// headroom, so Duration must never be copied into this field unconditionally.
	ReadyReplicasBefore          int
	MinAvailableReplicas         int
	AvailabilityMeasured         bool
	AvailabilityBreachDuration   time.Duration
	AvailabilityBreachStartedAt  time.Time
	AvailabilityBreachObservedAt time.Time
}

// ReplicaSeconds is the entry's consumption.
func (e Entry) ReplicaSeconds() float64 {
	return float64(e.Replicas) * e.Duration.Seconds()
}

// MeasuredReplicaSeconds returns a numeric value only when impact was observed.
func (e Entry) MeasuredReplicaSeconds() (float64, bool) {
	if !e.replicaImpactMeasured() {
		return 0, false
	}
	return e.ReplicaSeconds(), true
}

func (e Entry) replicaImpactMeasured() bool {
	return e.ReplicaImpact == ImpactMeasured || (e.ReplicaImpact == "" && e.Replicas > 0 && e.Duration > 0)
}

// AvailabilityBreachSeconds returns the separately observed time below
// minAvailableReplicas. The boolean distinguishes a measured zero from absence.
func (e Entry) AvailabilityBreachSeconds() (float64, bool) {
	if !e.AvailabilityMeasured {
		return 0, false
	}
	return e.AvailabilityBreachDuration.Seconds(), true
}

// Consumption keeps the two budget dimensions separate and makes unavailable
// availability observations visible instead of silently counting them as zero.
type Consumption struct {
	ReplicaSeconds                float64
	ReplicaMeasuredEntries        int
	ReplicaUnmeasuredEntries      int
	AvailabilityBreachSeconds     float64
	AvailabilityMeasuredEntries   int
	AvailabilityUnmeasuredEntries int
}

// Ledger accumulates Phorvex-caused disruption per tenant.
//
// It is in-memory and therefore resets with the process, which is honest about
// what the cluster can currently support: the Prometheus behind this operator
// retains two hours and has no persistent volume, so there is nowhere durable to
// put a thirty-day ledger yet. Consumed() takes an explicit `since` so a caller
// can never mistake "everything this process has seen" for "everything in the
// SLO window".
type Ledger struct {
	mu      sync.RWMutex
	byOwner map[string][]Entry

	// Retain bounds how far back entries are kept. Zero means keep everything.
	Retain time.Duration
}

// NewLedger returns a ledger retaining entries for the given span. Pass the
// longest SLO window in use; entries older than that can never affect a ratio.
func NewLedger(retain time.Duration) *Ledger {
	return &Ledger{byOwner: map[string][]Entry{}, Retain: retain}
}

// Record appends an action observation. Legacy empty zero-impact records are
// still dropped; an explicit outcome or impact-measurement status retains the
// event so completed zero-impact and unknown-impact actions remain distinguishable.
func (l *Ledger) Record(e Entry) {
	if e.Replicas < 0 || e.Duration < 0 {
		return
	}
	if (e.Replicas == 0 || e.Duration == 0) && e.Outcome == "" && e.ReplicaImpact == "" {
		return
	}
	if e.Cause == "" {
		e.Cause = CausePhorvex
	}
	if e.StartedAt.IsZero() && !e.ObservedAt.IsZero() {
		e.StartedAt = e.ObservedAt.Add(-e.Duration)
	}
	if e.ObservedAt.IsZero() && !e.StartedAt.IsZero() {
		e.ObservedAt = e.StartedAt.Add(e.Duration)
	}
	if e.AvailabilityMeasured && e.AvailabilityBreachDuration > 0 {
		if e.AvailabilityBreachObservedAt.IsZero() {
			e.AvailabilityBreachObservedAt = e.ObservedAt
		}
		if e.AvailabilityBreachStartedAt.IsZero() {
			e.AvailabilityBreachStartedAt = e.AvailabilityBreachObservedAt.Add(-e.AvailabilityBreachDuration)
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byOwner == nil {
		l.byOwner = map[string][]Entry{}
	}
	entries := l.byOwner[e.Tenant]
	if e.ID != "" {
		for i := range entries {
			if entries[i].ID == e.ID {
				entries[i] = e
				l.byOwner[e.Tenant] = entries
				l.evictLocked(e.Tenant, e.ObservedAt)
				return
			}
		}
	}
	l.byOwner[e.Tenant] = append(entries, e)
	l.evictLocked(e.Tenant, e.ObservedAt)
}

// overlapReplicaSeconds returns only the part of an entry that intersects the
// rolling window [since, ObservedAt]. An outage that starts ten seconds before
// the boundary and ends ten seconds after it consumes ten in-window seconds,
// not the full twenty.
func overlapReplicaSeconds(e Entry, since time.Time) float64 {
	start, end := e.StartedAt, e.ObservedAt
	if start.IsZero() && !end.IsZero() {
		start = end.Add(-e.Duration)
	}
	if end.IsZero() && !start.IsZero() {
		end = start.Add(e.Duration)
	}
	if !end.After(since) {
		return 0
	}
	if start.Before(since) {
		start = since
	}
	d := end.Sub(start)
	if d <= 0 {
		return 0
	}
	if e.Duration > 0 && d > e.Duration {
		d = e.Duration
	}
	return float64(e.Replicas) * d.Seconds()
}

func overlapsWindow(e Entry, since time.Time) bool {
	start, end := e.StartedAt, e.ObservedAt
	if start.IsZero() && !end.IsZero() {
		start = end.Add(-e.Duration)
	}
	if end.IsZero() && !start.IsZero() {
		end = start.Add(e.Duration)
	}
	if start.IsZero() && end.IsZero() {
		return false
	}
	return end.After(since) || end.Equal(since)
}

func overlapAvailabilitySeconds(e Entry, since time.Time) float64 {
	if !e.AvailabilityMeasured || e.AvailabilityBreachDuration <= 0 {
		return 0
	}
	start, end := e.AvailabilityBreachStartedAt, e.AvailabilityBreachObservedAt
	if start.IsZero() && !end.IsZero() {
		start = end.Add(-e.AvailabilityBreachDuration)
	}
	if end.IsZero() && !start.IsZero() {
		end = start.Add(e.AvailabilityBreachDuration)
	}
	if !end.After(since) {
		return 0
	}
	if start.Before(since) {
		start = since
	}
	d := end.Sub(start)
	if d <= 0 {
		return 0
	}
	if d > e.AvailabilityBreachDuration {
		d = e.AvailabilityBreachDuration
	}
	return d.Seconds()
}

// Consumed totals the unavailable replica-seconds Phorvex caused for a tenant at
// or after `since`.
//
// This is CONSUMPTION ALREADY ON RECORD — what happened before the move being
// scored. The cost of the move under consideration is the numerator of the
// ratio and never belongs in this total; adding it here would charge a move
// against a budget it has not spent yet.
func (l *Ledger) Consumed(tenant string, since time.Time) float64 {
	return l.ConsumedImpact(tenant, since).ReplicaSeconds
}

// ConsumedImpact returns both observed dimensions and an explicit count of
// entries for which availability could not be measured.
func (l *Ledger) ConsumedImpact(tenant string, since time.Time) Consumption {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out Consumption
	for _, e := range l.byOwner[tenant] {
		if !overlapsWindow(e, since) {
			continue
		}
		if e.replicaImpactMeasured() {
			out.ReplicaMeasuredEntries++
			out.ReplicaSeconds += overlapReplicaSeconds(e, since)
		} else {
			out.ReplicaUnmeasuredEntries++
		}
		if e.AvailabilityMeasured {
			out.AvailabilityMeasuredEntries++
			out.AvailabilityBreachSeconds += overlapAvailabilitySeconds(e, since)
		} else {
			out.AvailabilityUnmeasuredEntries++
		}
	}
	return out
}

// ConsumedByAction breaks the same total down per action, so it is visible which
// actuator is spending the budget rather than only that something is.
func (l *Ledger) ConsumedByAction(tenant string, since time.Time) map[model.Action]float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := map[model.Action]float64{}
	for _, e := range l.byOwner[tenant] {
		if consumed := overlapReplicaSeconds(e, since); consumed > 0 {
			out[e.Action] += consumed
		}
	}
	return out
}

// Entries returns a copy of a tenant's entries at or after `since`, oldest first.
func (l *Ledger) Entries(tenant string, since time.Time) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []Entry
	for _, e := range l.byOwner[tenant] {
		if !e.ObservedAt.Before(since) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObservedAt.Before(out[j].ObservedAt) })
	return out
}

// evictLocked drops entries older than Retain relative to now.
func (l *Ledger) evictLocked(tenant string, now time.Time) {
	if l.Retain <= 0 {
		return
	}
	cutoff := now.Add(-l.Retain)
	src := l.byOwner[tenant]
	kept := src[:0]
	for _, e := range src {
		if !e.ObservedAt.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	l.byOwner[tenant] = kept
}
