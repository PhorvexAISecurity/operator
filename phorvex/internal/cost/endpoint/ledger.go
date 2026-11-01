package endpoint

import (
	"fmt"
	"math"
	"reflect"
	"sort"
)

func latestMoves(t Tick) ([]Move, error) {
	latest := map[string]Move{}
	for _, m := range t.Ledger.Moves {
		if m.ID == "" || m.Revision < 0 || m.WorkloadUID != t.WorkloadUID || m.PolicyUID != t.PolicyUID {
			return nil, fmt.Errorf("MOVE_IDENTITY_MISSING_OR_MISMATCH")
		}
		if m.State != "open" && m.State != "settled" {
			return nil, fmt.Errorf("MOVE_STATE_INVALID")
		}
		if !finite(m.ObservedAt) || m.ObservedAt > t.At || !m.Measured || !m.Attributed {
			return nil, fmt.Errorf("MEASURED_MOVE_ATTRIBUTION_MISSING")
		}
		if old, ok := latest[m.ID]; ok {
			if old.Action != m.Action || old.Containment != m.Containment {
				return nil, fmt.Errorf("MOVE_IDENTITY_CHANGED")
			}
			if old.Revision == m.Revision && !reflect.DeepEqual(old, m) {
				return nil, fmt.Errorf("CONFLICTING_MOVE_REVISION")
			}
			older, newer := old, m
			if older.Revision > newer.Revision {
				older, newer = newer, older
			}
			if older.Revision != newer.Revision && (newer.ObservedAt < older.ObservedAt || older.State == "settled" && newer.State == "open") {
				return nil, fmt.Errorf("MOVE_REVISION_REGRESSED")
			}
			if old.Revision >= m.Revision {
				continue
			}
			if old.State == "settled" && m.State == "open" {
				return nil, fmt.Errorf("SETTLED_MOVE_REOPENED")
			}
		}
		latest[m.ID] = m
	}
	ids := make([]string, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Move, 0, len(ids))
	for _, id := range ids {
		if latest[id].State == "open" && latest[id].ObservedAt != t.At {
			return nil, fmt.Errorf("OPEN_MOVE_OBSERVATION_STALE")
		}
		out = append(out, latest[id])
	}
	// Intervals with the same endpoint identity are physical loss evidence.
	// Overlap within a move is merged; overlap across distinct move identities
	// makes attribution ambiguous and must not silently double-charge.
	type tagged struct {
		Interval
		id string
	}
	byEndpoint := map[string][]tagged{}
	for _, m := range out {
		for _, iv := range m.Intervals {
			if iv.EndpointUID == "" || !finite(iv.Start) || !finite(iv.End) || iv.Start < 0 || iv.End < iv.Start || iv.End > m.ObservedAt {
				return nil, fmt.Errorf("ENDPOINT_INTERVAL_INVALID")
			}
			byEndpoint[iv.EndpointUID] = append(byEndpoint[iv.EndpointUID], tagged{iv, m.ID})
		}
	}
	for _, ivs := range byEndpoint {
		sort.Slice(ivs, func(i, j int) bool { return ivs[i].Start < ivs[j].Start })
		for i, a := range ivs {
			for _, b := range ivs[i+1:] {
				if b.Start >= a.End {
					break
				}
				if a.id != b.id {
					return nil, fmt.Errorf("AMBIGUOUS_MOVE_ATTRIBUTION")
				}
			}
		}
	}
	return out, nil
}

func intervalLoss(intervals []Interval, since, until float64) float64 {
	byEndpoint := map[string][]Interval{}
	for _, iv := range intervals {
		iv.Start = math.Max(iv.Start, since)
		iv.End = math.Min(iv.End, until)
		if iv.End > iv.Start {
			byEndpoint[iv.EndpointUID] = append(byEndpoint[iv.EndpointUID], iv)
		}
	}
	keys := []string{}
	for k := range byEndpoint {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	total := 0.0
	for _, k := range keys {
		ivs := byEndpoint[k]
		sort.Slice(ivs, func(i, j int) bool {
			if ivs[i].Start == ivs[j].Start {
				return ivs[i].End < ivs[j].End
			}
			return ivs[i].Start < ivs[j].Start
		})
		start, end := ivs[0].Start, ivs[0].End
		for _, iv := range ivs[1:] {
			if iv.Start <= end {
				end = math.Max(end, iv.End)
			} else {
				total += end - start
				start, end = iv.Start, iv.End
			}
		}
		total += end - start
	}
	return total
}

func Account(t Tick, cfg Config) Budget {
	b := Budget{ActingAdmission: "BLOCKED: offline experiment"}
	if t.SpecReplicas == nil || *t.SpecReplicas <= 0 {
		b.Refusal = "WORKLOAD_SPEC_REPLICAS_MISSING"
		return b
	}
	if t.SLO == nil || !finite(t.SLO.Target) || t.SLO.Target <= 0 || t.SLO.Target >= 1 || !finite(t.SLO.Window) || t.SLO.Window <= 0 {
		b.Refusal = "SLO_CONTRACT_MISSING"
		return b
	}
	if !t.SLO.Accepted && !t.SLO.StudyAssumption {
		b.Refusal = "SLO_NOT_ACCEPTED_OR_DECLARED_STUDY_ASSUMPTION"
		return b
	}
	r := (1 - t.SLO.Target) * t.SLO.Window * float64(*t.SpecReplicas)
	if !finite(r) || r <= 0 {
		b.Refusal = "SLO_BUDGET_INVALID"
		return b
	}
	b.R = ptr(r)
	if t.Ledger == nil {
		b.Refusal = "ENDPOINT_LEDGER_MISSING"
		b.TelemetryReason = b.Refusal
		return b
	}
	l := t.Ledger
	if !finite(l.At) || l.At != t.At {
		b.Refusal = "LEDGER_SNAPSHOT_TIME_MISMATCH"
		b.TelemetryReason = b.Refusal
		return b
	}
	if l.Measurement != "measured-endpoint-intervals" && l.Measurement != "watch-observed-service-ready-backends" {
		b.Refusal = "MEASURED_ENDPOINT_INTERVALS_MISSING"
		b.TelemetryReason = b.Refusal
		return b
	}
	moves, err := latestMoves(t)
	if err != nil {
		b.Refusal = err.Error()
		b.TelemetryReason = b.Refusal
		return b
	}
	from := l.CompleteFrom
	if from == nil || !finite(*from) || *from > t.At {
		b.Refusal = "LEDGER_COVERAGE_UNKNOWN"
		b.TelemetryReason = b.Refusal
		return b
	}
	used, held, spend := 0.0, 0.0, 0.0
	holdsKnown := true
	for _, m := range moves {
		loss := intervalLoss(m.Intervals, t.At-t.SLO.Window, t.At)
		if m.State == "settled" {
			used += loss
		} else {
			if !nonnegative(m.Reservation) {
				holdsKnown = false
			} else {
				hold := *m.Reservation
				if m.Overdue {
					hold = math.Max(hold, loss)
				}
				held += hold
			}
		}
		if !m.Containment {
			spend += intervalLoss(m.Intervals, t.At-cfg.Lookback, t.At)
		}
	}
	if !finite(used) || !finite(held) || !finite(spend) {
		b.Refusal = "NONFINITE_MEASURED_CONSUMPTION"
		b.TelemetryReason = b.Refusal
		return b
	}
	if *from <= t.At-cfg.Lookback {
		b.Spend = ptr(spend)
	} else {
		b.TelemetryReason = "LOOKBACK_HISTORY_INCOMPLETE"
	}
	if *from > t.At-t.SLO.Window {
		b.Refusal = "BUDGET_WINDOW_HISTORY_INCOMPLETE"
		return b
	}
	b.Used = ptr(used)
	if !holdsKnown {
		b.Refusal = "OPEN_MOVE_RESERVATION_MISSING"
		return b
	}
	b.Held = ptr(held)
	b.Left = ptr(r - used - held)
	if !l.Authoritative {
		b.ActingAdmission = "BLOCKED: shadow ledger is not authoritative"
	} else if !t.SLO.Accepted {
		b.ActingAdmission = "BLOCKED: study SLO is not tenant acceptance"
	}
	return b
}
