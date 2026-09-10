/*
 * Phorvex Console — LIVE-ATTACK MONITORING (before / during / after).
 *
 * GET /api/attack-monitoring returns, for every REAL attack fired at a live workload, the full
 * availability picture around that attack — reconstructed from the BACKGROUND sampler
 * (phorvex-uptime.jsonl, 5s cadence), not from the three scalars the attack watcher happens to
 * keep. That distinction is the whole point: the watcher only ever recorded uptimeBefore /
 * uptimeDip / uptimeAfter, so "what did availability actually do around the attack" could not be
 * answered. Here the series is windowed around the attack instant, giving a real BEFORE baseline,
 * the during-attack trough, and the recovery tail.
 *
 * The downtime cost is deliberately narrow and REAL: it prices the capacity that was actually
 * unavailable at the attacked node's live AWS on-demand rate. It is NOT a business-impact
 * estimate (lost revenue / SLA penalties / reputation) — those are not on the AWS bill and would
 * be invented numbers. Same honesty stance the cost panel already takes.
 */

package console

import (
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// monPoint is one availability sample on the attack timeline. OffsetSec is signed seconds
// relative to the attack instant: negative = before the attack, 0+ = after it landed.
type monPoint struct {
	T         string  `json:"t"`
	OffsetSec float64 `json:"offsetSec"`
	Ready     int     `json:"ready"`
	Desired   int     `json:"desired"`
	Pct       float64 `json:"pct"`
	Phase     string  `json:"phase"` // before | during | after
}

// monPhase is the aggregate for one window (before / during / after).
type monPhase struct {
	Samples  int     `json:"samples"`
	MeanPct  float64 `json:"meanPct"`
	MinPct   float64 `json:"minPct"`
	Complete bool    `json:"complete"` // false => the sampler has no data covering this window
}

// downtimeCost prices ONLY the unavailable capacity, at real AWS on-demand rates.
type downtimeCost struct {
	ReplicaSeconds float64 `json:"replicaSeconds"` // Σ (missing replicas × sample interval)
	NodeRatePerHr  float64 `json:"nodeRatePerHr"`  // live on-demand $/hr for the attacked node
	Dollars        float64 `json:"dollars"`        // replicaSeconds/3600 × rate
	Basis          string  `json:"basis"`
}

// attackMonitoring is the per-attack monitoring record the dashboard renders.
type attackMonitoring struct {
	ID        string `json:"id"`
	FiredAt   string `json:"firedAt"`
	Service   string `json:"service"`
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
	Attack    string `json:"attack"`
	AttackID  string `json:"attackId"`
	Outcome   string `json:"outcome"`
	Action    string `json:"phorvexAction"`

	Before monPhase `json:"before"`
	During monPhase `json:"during"`
	After  monPhase `json:"after"`

	// RecoveredSec is seconds from the attack instant until availability returned to the BEFORE
	// baseline and stayed there. -1 when it never recovered inside the observed window.
	RecoveredSec float64      `json:"recoveredSec"`
	Impacted     bool         `json:"impacted"` // did availability actually drop below the baseline?
	Series       []monPoint   `json:"series"`
	Downtime     downtimeCost `json:"downtime"`
	Note         string       `json:"note"`
}

const (
	monPreWindow  = 5 * time.Minute // baseline BEFORE the attack
	monPostWindow = 5 * time.Minute // recovery tail AFTER it
	monDuring     = 95 * time.Second
)

// attackMonitoringHandler builds the before/during/after picture for every recorded attack.
func (s *Server) attackMonitoringHandler(w http.ResponseWriter, r *http.Request) {
	s.loadAttacks()
	// [M-136] Same cross-tenant control as /api/attack-results: the ledger is cluster-wide, so a
	// tenant-limited grant monitors only its own namespaces.
	p := principalOf(r)
	attackMu.Lock()
	recs := make([]*attackRecord, 0, len(attackList))
	for i := len(attackList) - 1; i >= 0; i-- { // newest first
		if rec := attackList[i]; p.TenantWildcard() || p.AllowsTenant(rec.Namespace) {
			recs = append(recs, rec)
		}
	}
	attackMu.Unlock()

	samples := readUptimeSamples(uptimePath(s.cfg))
	// index samples by (ns, workload) with parsed timestamps, sorted by time
	type ts struct {
		at time.Time
		sm uptimeSample
	}
	byKey := map[string][]ts{}
	for _, sm := range samples {
		at, err := time.Parse(time.RFC3339Nano, sm.T)
		if err != nil {
			continue
		}
		k := sm.NS + "/" + sm.Workload
		byKey[k] = append(byKey[k], ts{at, sm})
	}
	for k := range byKey {
		sort.Slice(byKey[k], func(i, j int) bool { return byKey[k][i].at.Before(byKey[k][j].at) })
	}

	// BOUNDED lookups: resolving each attacked pod's node rate individually shells out to kubectl
	// twice PER POD, which timed out the endpoint outright on a real attack history (60 records,
	// dozens of distinct pods, most already rotated away so every lookup still paid a round-trip).
	// Two cluster-wide calls build the pod->node and node->rate maps once; everything after is
	// in-memory.
	rateFor := s.buildRateResolver("")

	out := make([]attackMonitoring, 0, len(recs))
	for _, rec := range recs {
		fired, err := time.Parse(time.RFC3339, rec.FiredAt)
		if err != nil {
			continue
		}
		wl := rec.Deploy
		if wl == "" {
			wl = rec.Service
		}
		m := attackMonitoring{
			ID: rec.ID, FiredAt: rec.FiredAt, Service: rec.Service, Namespace: rec.Namespace,
			Workload: wl, Attack: rec.Attack, AttackID: rec.AttackID,
			Outcome: rec.Outcome, Action: rec.Action, RecoveredSec: -1,
		}

		rows := byKey[rec.Namespace+"/"+wl]
		lo := fired.Add(-monPreWindow)
		hi := fired.Add(monDuring + monPostWindow)

		var beforeVals, duringVals, afterVals []float64
		var missingReplicaSeconds float64
		for _, row := range rows {
			if row.at.Before(lo) || row.at.After(hi) {
				continue
			}
			off := row.at.Sub(fired).Seconds()
			pct := -1.0
			if row.sm.Desired > 0 {
				pct = float64(row.sm.Ready) / float64(row.sm.Desired) * 100
			}
			if pct < 0 {
				continue
			}
			phase := "after"
			switch {
			case off < 0:
				phase = "before"
				beforeVals = append(beforeVals, pct)
			case off <= monDuring.Seconds():
				phase = "during"
				duringVals = append(duringVals, pct)
			default:
				afterVals = append(afterVals, pct)
			}
			// capacity actually missing, only counted from the attack instant onward
			if off >= 0 && row.sm.Desired > 0 && row.sm.Ready < row.sm.Desired {
				missing := float64(row.sm.Desired - row.sm.Ready)
				missingReplicaSeconds += missing * uptimeInterval.Seconds()
			}
			m.Series = append(m.Series, monPoint{
				T: row.sm.T, OffsetSec: round2(off), Ready: row.sm.Ready,
				Desired: row.sm.Desired, Pct: round2(pct), Phase: phase,
			})
		}
		m.Before = phaseStats(beforeVals)
		m.During = phaseStats(duringVals)
		m.After = phaseStats(afterVals)

		// Impact + recovery are measured against the pre-attack baseline, not against 100%: a
		// workload already running degraded must not be reported as "attack caused a dip".
		baseline := m.Before.MeanPct
		if m.Before.Complete && m.During.Complete && m.During.MinPct < baseline-0.01 {
			m.Impacted = true
			// Recovery is measured from the END of the dip, not from the first post-attack sample
			// that happens to sit at baseline: Phorvex acts ~10s in, so the samples immediately
			// after t=0 are still healthy and would report an impossible ~2s "recovery". Find the
			// LAST sample below baseline, then the first sample at/above it after that.
			lastBelow := -1
			for i, p := range m.Series {
				if p.OffsetSec >= 0 && p.Pct < baseline-0.01 {
					lastBelow = i
				}
			}
			if lastBelow >= 0 {
				for i := lastBelow + 1; i < len(m.Series); i++ {
					if m.Series[i].Pct >= baseline-0.01 {
						m.RecoveredSec = m.Series[i].OffsetSec
						break
					}
				}
			}
		}

		rate := rateFor(rec.Namespace, rec.Pod)
		m.Downtime = downtimeCost{
			ReplicaSeconds: round2(missingReplicaSeconds),
			NodeRatePerHr:  round2(rate),
			// round2 would collapse a real sub-cent figure to $0.00; these are genuinely small
			// numbers (seconds of one replica), so keep enough precision to stay truthful.
			Dollars: round4(missingReplicaSeconds / 3600.0 * rate),
			Basis: "unavailable replica-seconds x the attacked node's live AWS on-demand $/hr. " +
				"INFRASTRUCTURE cost of lost capacity only — not lost revenue, SLA penalties or reputation.",
		}
		if !m.Before.Complete {
			m.Note = "no sampler coverage before this attack (fired before the sampler started, or the samples have rotated out) — before/after cannot be compared for this record."
		} else if !m.Impacted {
			m.Note = "availability never dropped below the pre-attack baseline — the defence cost this workload no capacity."
		}
		out = append(out, m)
	}

	writeJSON(w, 200, map[string]any{
		"attacks":        out,
		"sampleInterval": uptimeInterval.Seconds(),
		"preWindowSec":   monPreWindow.Seconds(),
		"postWindowSec":  monPostWindow.Seconds(),
		"note": "availability reconstructed from the background sampler (" + uptimeInterval.String() +
			" cadence), windowed around each real attack. Before = the " + monPreWindow.String() +
			" baseline preceding the attack.",
	})
}

func phaseStats(v []float64) monPhase {
	if len(v) == 0 {
		return monPhase{Complete: false, MinPct: -1, MeanPct: -1}
	}
	sum, min := 0.0, v[0]
	for _, x := range v {
		sum += x
		if x < min {
			min = x
		}
	}
	return monPhase{Samples: len(v), MeanPct: round2(sum / float64(len(v))), MinPct: round2(min), Complete: true}
}

// buildRateResolver returns a closure resolving (namespace, pod) -> live on-demand $/hr using
// exactly TWO cluster-wide kubectl calls, regardless of how many pods are asked about. Pods that
// no longer exist (rotated away by a defence) resolve to the cluster's mean node rate rather than
// costing a round-trip each. Returns 0 when pricing is unavailable — the caller then reports a $0
// downtime cost instead of inventing a rate.
func (s *Server) buildRateResolver(ctxName string) func(ns, pod string) float64 {
	pr := s.clusterPricing(ctxName)
	rateByType := map[string]float64{}
	for _, n := range pr.Nodes {
		rateByType[n.InstanceType] = n.PricePerHr
	}
	mean := 0.0
	if total := func() int {
		t := 0
		for _, n := range pr.Nodes {
			t += n.Count
		}
		return t
	}(); total > 0 && pr.TotalPerHr > 0 {
		mean = pr.TotalPerHr / float64(total)
	}

	// node -> instance type (one call)
	rateByNode := map[string]float64{}
	if out, _ := s.cfg.execText(10*time.Second, "kubectl", "get", "nodes", "--no-headers",
		"-o", "custom-columns=N:.metadata.name,T:.metadata.labels.node\\.kubernetes\\.io/instance-type"); out != "" {
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				if rt, ok := rateByType[f[1]]; ok {
					rateByNode[f[0]] = rt
				}
			}
		}
	}
	// pod -> node, cluster-wide (one call)
	podNode := map[string]string{}
	if out, _ := s.cfg.execText(12*time.Second, "kubectl", "get", "pods", "-A", "--no-headers",
		"-o", "custom-columns=NS:.metadata.namespace,N:.metadata.name,ND:.spec.nodeName"); out != "" {
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(ln)
			if len(f) >= 3 {
				podNode[f[0]+"/"+f[1]] = f[2]
			}
		}
	}
	return func(ns, pod string) float64 {
		if node := podNode[ns+"/"+pod]; node != "" {
			if r, ok := rateByNode[node]; ok {
				return r
			}
		}
		return mean // pod gone (rotated) or type unpriced -> cluster mean, never a fabricated rate
	}
}

// round4 keeps sub-cent downtime figures honest (round2 would print a real cost as $0.00).
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }
