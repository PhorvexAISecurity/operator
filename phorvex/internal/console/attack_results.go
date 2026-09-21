/*
 * Phorvex Console — LIVE ATTACK RESULTS capture.
 *
 * When a REAL attack is fired at a live workload (/api/workload/attack, /api/vllm/attack), we
 * snapshot the workload's uptime, then a watcher observes the GROUND-TRUTH outcome on the real
 * cluster — did Phorvex DEFEND it (attacked pod rotated / adapter rotated / quarantined) or did
 * the attack LAND (foothold survived) — records the real decision reasoning, the uptime dip +
 * recovery, and a three-way cost (WITHOUT any defense / R6 blind-timer / WITH Phorvex) computed
 * from live AWS pricing. Nothing here is fabricated: outcome is measured, pricing is real, and the
 * R6 column is a clearly-labelled blind-timer counterfactual derived from Phorvex's own r6 note.
 *
 * GET /api/attack-results returns the records (newest first) for the Report tab.
 */

package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

type attackCost struct {
	ValueAtRisk float64 `json:"valueAtRisk"` // real AWS $/yr the attacked node exposes
	Without     float64 `json:"without"`     // no defense: attack lands, full exposure
	R6          float64 `json:"r6"`          // R6 blind timer: residual + churn (+ data loss if stateful)
	With        float64 `json:"with"`        // Phorvex: residual after the measured disruption + defense cost
	Savings     float64 `json:"savings"`     // without - with
	Note        string  `json:"note"`

	// SHOW-YOUR-WORKING: every input the three numbers above are built from, so the dashboard can
	// print the arithmetic instead of asking the reader to trust a total. These were previously
	// buried inside Note as prose, which meant the breakdown could not be rendered or checked.
	NodeInstance   string  `json:"nodeInstance"`   // instance type the attacked pod runs on
	NodeRatePerHr  float64 `json:"nodeRatePerHr"`  // its live on-demand $/hr
	PreventNone    float64 `json:"preventNone"`    // harness-measured prevention rate, no defense
	PreventR6      float64 `json:"preventR6"`      // ... R6 blind timer
	PreventPhorvex float64 `json:"preventPhorvex"` // ... Phorvex
	RatesSource    string  `json:"ratesSource"`    // where those rates came from + sample size
	OperatorCost   float64 `json:"operatorCost"`   // Phorvex's own $/yr footprint
	R6Churn        float64 `json:"r6Churn"`        // blind-rotation churn $/yr added to the R6 arm
}

type attackRecord struct {
	Claim        *model.ClaimScope `json:"claim,omitempty"`
	ID           string            `json:"id"`
	FiredAt      string            `json:"firedAt"`
	Service      string            `json:"service"`
	Namespace    string            `json:"namespace"`
	Pod          string            `json:"pod"`
	TargetUID    string            `json:"targetUid,omitempty"`
	Deploy       string            `json:"deploy"`
	Attack       string            `json:"attack"`
	AttackID     string            `json:"attackId"`
	MITRE        string            `json:"mitre"`
	Expected     string            `json:"expectedActuator"`
	Stateful     bool              `json:"stateful"`
	EvidenceKind string            `json:"evidenceKind,omitempty"`

	Status          string  `json:"status"`  // running | done
	Outcome         string  `json:"outcome"` // DEFENDED | LANDED
	Action          string  `json:"phorvexAction"`
	DefendedPod     string  `json:"defendedPod"` // pod Phorvex actually actuated on (may differ from the attacked pod: on a stateful cluster it quarantines the highest lateral-coverage node to contain spread)
	Actuated        bool    `json:"actuated"`
	TimeToDefendSec float64 `json:"timeToDefendSec"`
	// attacker dwell = seconds the foothold held effective access. DEFENDED => from the attack landing
	// until Phorvex contained/evicted it (= timeToDefend); LANDED => the observation window and STILL
	// COUNTING (dwellOngoing=true — the attacker was never evicted). This is the security-standard metric:
	// how long the intruder operated. Without any defense it is unbounded.
	DwellSec     float64 `json:"dwellSec"`
	DwellOngoing bool    `json:"dwellOngoing"`
	// what the defensive action actually did to the FOOTHOLD (the attacked pod), not just "an action fired":
	//   evicted         = the foothold pod was rotated away (destroyed) — attacker gone.
	//   contained       = the foothold pod itself was quarantined (network-isolated on its own node).
	//   foothold-active = only a NEIGHBOR was quarantined — the attacker still holds the attacked pod.
	//   landed          = no defensive action reached the foothold.
	// Dwell is bounded ONLY for evicted/contained; otherwise the intruder was never removed from the
	// attacked pod, so its dwell is open-ended (DwellOngoing=true).
	Containment string `json:"containment"`
	// A synthetic detector signal can prove only an identity-bound workload response.
	// Keep that evidence separate from attacker outcome, containment and dwell.
	ResponseObserved bool              `json:"responseObserved,omitempty"`
	ResponseAction   string            `json:"responseAction,omitempty"`
	ResponsePod      string            `json:"responsePod,omitempty"`
	ResponseSeconds  float64           `json:"responseSeconds,omitempty"`
	ObservationError string            `json:"observationError,omitempty"`
	DecisionEvidence *decisionEvidence `json:"decisionEvidence,omitempty"`

	// real decision reasoning (from the in-cluster operator's audit)
	Why                       string  `json:"why"`
	PerDollar                 float64 `json:"perDollar"`
	PerDollarAvailable        bool    `json:"perDollarAvailable"`
	Stage                     string  `json:"stage"`
	CoveredFacts              int     `json:"coveredFacts"`
	CoveredFactsAvailable     bool    `json:"coveredFactsAvailable"`
	PHold                     float64 `json:"pHold"`
	Lambda                    float64 `json:"lambda"`
	LambdaAvailable           bool    `json:"lambdaAvailable"`
	EconomicsVersion          string  `json:"economicsVersion,omitempty"`
	DisruptionAversion        float64 `json:"disruptionAversion,omitempty"`
	DisruptionAversionPresent bool    `json:"disruptionAversionPresent"`
	EffectiveCostCoefficient  float64 `json:"effectiveCostCoefficient,omitempty"`
	EconomicsAvailable        bool    `json:"economicsAvailable"`
	R6Would                   string  `json:"r6Would"`
	R6Note                    string  `json:"r6Note"`

	// real uptime, sampled around the attack (ready/desired * 100)
	UptimeBefore float64 `json:"uptimeBefore"`
	UptimeDip    float64 `json:"uptimeDip"`
	UptimeAfter  float64 `json:"uptimeAfter"`

	Cost             attackCost `json:"cost"`
	PersistenceError string     `json:"persistenceError,omitempty"`

	started     time.Time       // unexported, for elapsed timing
	accepted    time.Time       // producer acknowledgement, for signal-response latency
	baseEpoch   string          // pre-attack adapter epoch (poison detection)
	baseKVEpoch string          // pre-attack kv-reset epoch (kvcache detection)
	baseQuar    map[string]bool // pre-attack quarantine SecurityEvent names
	baseNP      map[string]bool // pre-attack quarantine NetworkPolicy names
}

type decisionEvidence struct {
	Correlation string `json:"correlation"`
	Time        string `json:"time"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`
	Selected    bool   `json:"selected"`
	Actuated    bool   `json:"actuated"`
}

// defenseBaseline is the snapshot of pre-existing defense artifacts, taken by the attack handler BEFORE
// the attack is applied. Capturing it pre-fire (not at watcher start) is essential: the operator can
// react within ~1s, faster than the watcher's own baseline kubectl calls would complete — so a
// watcher-side snapshot would absorb this attack's own quarantine and misreport it as LANDED.
type defenseBaseline struct {
	uid     string
	epoch   string
	kvEpoch string
	quar    map[string]bool
	nps     map[string]bool
	// uptime is the workload availability read BEFORE the attack is applied. It must be captured
	// here for the same reason as the quarantine/NP baselines: the operator is event-driven and
	// reacts in ~1s, faster than startAttackRecord runs, so reading it afterwards recorded the
	// attack's OWN dip as the "before" value (a 3/3 broker was reported as 66.67% before).
	uptime float64
}

// snapshotBaseline captures the defense baseline for a namespace/pod. Call BEFORE applying the attack.
func (s *Server) snapshotBaseline(ns, pod string) defenseBaseline {
	return defenseBaseline{
		uid:     s.podAnno(ns, pod, "metadata.uid"),
		uptime:  s.workloadUptime(ns, s.firstDeploy(ns)),
		epoch:   s.podAnno(ns, pod, "phorvex.ai/adapter-epoch"),
		kvEpoch: s.podAnno(ns, pod, "phorvex.ai/kv-reset-epoch"),
		quar:    s.quarantineEvents(ns),
		nps:     s.quarantineNPs(ns),
	}
}

var (
	attackMu     sync.Mutex
	attackList   []*attackRecord
	attackLoaded bool
	attackFileMu sync.Mutex
	attackLoadMu sync.Mutex
)

// cloneAttackRecord copies every mutable member before a record crosses the watcher/ledger
// boundary. Add copies here if attackRecord gains another map, slice or pointer field.
func cloneAttackRecord(r *attackRecord) *attackRecord {
	c := *r
	if r.DecisionEvidence != nil {
		evidence := *r.DecisionEvidence
		c.DecisionEvidence = &evidence
	}
	if r.Claim != nil {
		claim := *r.Claim
		claim.DetectorSet = append([]string(nil), r.Claim.DetectorSet...)
		c.Claim = &claim
	}
	if r.baseQuar != nil {
		c.baseQuar = make(map[string]bool, len(r.baseQuar))
		for k, v := range r.baseQuar {
			c.baseQuar[k] = v
		}
	}
	if r.baseNP != nil {
		c.baseNP = make(map[string]bool, len(r.baseNP))
		for k, v := range r.baseNP {
			c.baseNP[k] = v
		}
	}
	return &c
}

// publishAttack replaces only this attack's ledger entry. The watcher retains its private
// working record; neither it nor its mutable nested fields are shared with readers.
func publishAttack(r *attackRecord) {
	snapshot := cloneAttackRecord(r)
	attackMu.Lock()
	defer attackMu.Unlock()
	for i, old := range attackList {
		if old.ID == r.ID {
			attackList[i] = snapshot
			return
		}
	}
	attackList = append(attackList, snapshot)
}

func attackSnapshots(p *Principal) []*attackRecord {
	attackMu.Lock()
	defer attackMu.Unlock()
	out := make([]*attackRecord, 0, len(attackList))
	for i := len(attackList) - 1; i >= 0; i-- {
		if rec := attackList[i]; p.TenantWildcard() || p.AllowsTenant(rec.Namespace) {
			out = append(out, cloneAttackRecord(rec))
		}
	}
	return out
}

func realAttackSnapshots(p *Principal) []*attackRecord {
	all := attackSnapshots(p)
	out := make([]*attackRecord, 0, len(all))
	for _, rec := range all {
		if rec.EvidenceKind == "" {
			out = append(out, rec)
		}
	}
	return out
}

func pagedRealAttackSnapshots(endpoint string, p *Principal, pg collectionPaging, search, exactID string) ([]*attackRecord, collectionPage, error) {
	attackMu.Lock()
	defer attackMu.Unlock()
	snapshot := len(attackList)
	if pg.Cursor.Version != 0 {
		snapshot = pg.Cursor.Snapshot
	}
	if snapshot < 0 || snapshot > len(attackList) {
		return nil, collectionPage{}, fmt.Errorf("cursor snapshot is no longer available; refresh latest")
	}
	ids := make([]string, 0, snapshot)
	for i := 0; i < snapshot; i++ {
		ids = append(ids, strconv.Itoa(i)+":"+attackList[i].ID)
	}
	cursor := pg.establish(endpoint, snapshot, collectionAnchor(ids))
	if cursor.Anchor != collectionAnchor(ids) {
		return nil, collectionPage{}, fmt.Errorf("cursor snapshot changed; refresh latest")
	}
	matching := make([]*attackRecord, 0, snapshot)
	for i := snapshot - 1; i >= 0; i-- {
		rec := attackList[i]
		if rec.EvidenceKind != "" || (!p.TenantWildcard() && !p.AllowsTenant(rec.Namespace)) {
			continue
		}
		if exactID != "" && rec.ID != exactID {
			continue
		}
		if !containsFold(rec.ID+" "+rec.Service+" "+rec.Namespace+" "+rec.Attack, search) {
			continue
		}
		matching = append(matching, rec)
	}
	start, end, page, err := collectionPageFor(cursor, len(matching))
	if err != nil {
		return nil, collectionPage{}, err
	}
	out := make([]*attackRecord, 0, end-start)
	for _, rec := range matching[start:end] {
		out = append(out, cloneAttackRecord(rec))
	}
	return out, page, nil
}

func (s *Server) attacksPath() string {
	if p := s.cfg.statePath("phorvex-attacks.jsonl"); p != "" {
		return p
	}
	if s.cfg.Root != "" {
		return filepath.Join(s.cfg.Root, "phorvex-attacks.jsonl")
	}
	return ""
}

func (s *Server) loadAttacks() error {
	attackLoadMu.Lock()
	defer attackLoadMu.Unlock()
	attackMu.Lock()
	if attackLoaded {
		attackMu.Unlock()
		return nil
	}
	attackMu.Unlock()
	attackFileMu.Lock()
	b, err := readStateLedger(s.attacksPath())
	attackFileMu.Unlock()
	loaded := []*attackRecord{}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read retained attack results: %w", err)
	}
	if err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if ln = strings.TrimSpace(ln); ln == "" {
				continue
			}
			var r attackRecord
			if err := json.Unmarshal([]byte(ln), &r); err != nil {
				return fmt.Errorf("malformed retained attack result: %w", err)
			}
			if r.Status != "partial" || r.ObservationError == "" {
				r.Status = "done"
			}
			if r.EvidenceKind == "" && r.Containment == "" && r.Outcome != "" { // classify legacy real-attack records only
				classifyContainment(&r, 95) // 95s = the observation window (dwell floor for un-neutralized footholds)
			}
			loaded = append(loaded, cloneAttackRecord(&r))
		}
	}
	attackMu.Lock()
	attackList = append(loaded, attackList...)
	attackLoaded = true
	attackMu.Unlock()
	return nil
}

// classifyContainment sets Containment + the honest dwell. `elapsed` is the observation window used as
// the dwell floor when the foothold was NOT neutralized (foothold-active / landed).
func classifyContainment(r *attackRecord, elapsed float64) {
	switch {
	case r.Outcome == "DEFENDED" && (r.Action == "rotate" || r.Action == "adapter-rotate"):
		r.Containment, r.DwellSec, r.DwellOngoing = "evicted", r.TimeToDefendSec, false
	case r.Outcome == "DEFENDED" && r.Action == "kv-reset":
		// The pod is deliberately kept ALIVE; what ends is the attacker's PLANTED STATE (the primed
		// cache entry). Distinct from "evicted" (pod replaced) — labelling it evicted would claim a
		// rotation that never happened. Dwell is bounded: the injected state is gone at flush time.
		r.Containment, r.DwellSec, r.DwellOngoing = "flushed", r.TimeToDefendSec, false
	case r.Outcome == "DEFENDED" && r.Action == "quarantine" && r.DefendedPod != "" && r.DefendedPod == r.Pod:
		r.Containment, r.DwellSec, r.DwellOngoing = "contained", r.TimeToDefendSec, false
	case r.Outcome == "DEFENDED" && r.Action == "quarantine":
		// a clean neighbor was isolated — the attacker still holds the attacked pod: dwell is open-ended.
		r.Containment, r.DwellSec, r.DwellOngoing = "foothold-active", elapsed, true
	default:
		r.Containment, r.DwellSec, r.DwellOngoing = "landed", elapsed, true
	}
}

func (s *Server) persistAttack(r *attackRecord) error {
	b, err := json.Marshal(cloneAttackRecord(r))
	if err != nil {
		return err
	}
	return s.cfg.appendState(s.attacksPath(), b)
}

// startAttackRecord registers a running attack and launches the ground-truth watcher. Called by the
// attack handlers immediately after the real attack is applied to the cluster.
func (s *Server) startAttackRecord(ctxName, service, ns, pod, attack, attackID, mitre, expected string, stateful bool, base defenseBaseline) string {
	d := s.cfg.AttackWatchDuration
	if d <= 0 {
		d = 95 * time.Second
	}
	started := s.cfg.now()
	return s.startAttackRecordAt(ctxName, service, ns, pod, attack, attackID, mitre, expected, stateful, base, started, started.Add(d))
}

// startAttackRecordAt pre-registers one exact observation window. Experiment arms use
// this form so producer/API overhead cannot make one arm's measurement longer than another.
func (s *Server) startAttackRecordAt(ctxName, service, ns, pod, attack, attackID, mitre, expected string, stateful bool, base defenseBaseline, started, deadline time.Time) string {
	return s.startAttackRecordAtKind(ctxName, service, ns, pod, attack, attackID, mitre, expected, stateful, base, started, deadline, "", started)
}

func (s *Server) startAttackRecordAtKind(ctxName, service, ns, pod, attack, attackID, mitre, expected string, stateful bool, base defenseBaseline, started, deadline time.Time, evidenceKind string, accepted time.Time) string {
	if err := s.loadAttacks(); err != nil {
		s.recordStateError(err)
	}
	deploy := s.firstDeploy(ns)
	r := &attackRecord{
		ID:      "atk-" + strconv.FormatInt(started.UnixNano(), 36),
		FiredAt: started.UTC().Format(time.RFC3339Nano),
		Service: service, Namespace: ns, Pod: pod, Deploy: deploy,
		Attack: attack, AttackID: attackID, MITRE: mitre, Expected: expected, Stateful: stateful, EvidenceKind: evidenceKind,
		TargetUID: base.uid,
		Status:    "running",
		// PRE-FIRE value when the caller captured one (>=0); fall back to a live read only if the
		// baseline predates this field, so an old caller still gets a number rather than 0.
		UptimeBefore: func() float64 {
			if base.uptime >= 0 {
				return base.uptime
			}
			return s.workloadUptime(ns, deploy)
		}(),
		started:     started,
		accepted:    accepted,
		baseEpoch:   base.epoch,
		baseKVEpoch: base.kvEpoch,
		baseQuar:    base.quar,
		baseNP:      base.nps,
	}
	// capture value-at-risk NOW (the attacked pod's node still exists; it may be rotated away before
	// the watcher finishes) so the cost is grounded in the real node price, not the cluster fallback.
	r.Cost.ValueAtRisk = s.nodeAnnualCost("", ns, pod)
	r = cloneAttackRecord(r) // detach the handler's baseline maps before the watcher owns them
	publishAttack(r)
	interval := s.cfg.AttackWatchInterval
	if interval <= 0 {
		interval = 3 * time.Second
	}
	go s.watchAttackUntil(ctxName, r, deadline, interval)
	return r.ID
}

func attackSnapshotByID(id string) *attackRecord {
	attackMu.Lock()
	defer attackMu.Unlock()
	for _, r := range attackList {
		if r.ID == id {
			return cloneAttackRecord(r)
		}
	}
	return nil
}

func persistedAttackByID(cfg Config, id string) *attackRecord {
	b, err := readStateLedgerHistory(cfg.statePath("phorvex-attacks.jsonl"))
	if err != nil {
		return nil
	}
	var found *attackRecord
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r attackRecord
		if json.Unmarshal([]byte(line), &r) == nil && r.ID == id && r.Status == "done" {
			found = cloneAttackRecord(&r)
		}
	}
	return found
}

func (s *Server) watchAttack(ctxName string, r *attackRecord) {
	d, interval := s.cfg.AttackWatchDuration, s.cfg.AttackWatchInterval
	if d <= 0 {
		d = 95 * time.Second
	}
	if interval <= 0 {
		interval = 3 * time.Second
	}
	s.watchAttackUntil(ctxName, r, s.cfg.now().Add(d), interval)
}

// watchAttackUntil keeps the production window unchanged and gives local producer fixtures
// a bounded clock. A caller must give this watcher exclusive ownership of r.
func (s *Server) watchAttackUntil(ctxName string, r *attackRecord, deadline time.Time, interval time.Duration) {
	minUp := r.UptimeBefore
	// baselines were captured PRE-FIRE by the handler (see defenseBaseline) — using a watcher-side
	// snapshot here would race a fast operator and misreport a real quarantine as LANDED.
	epoch0 := r.baseEpoch
	kvEpoch0 := r.baseKVEpoch
	quar0 := r.baseQuar
	np0 := r.baseNP
	for s.cfg.now().Before(deadline) {
		remaining := deadline.Sub(s.cfg.now())
		if remaining < interval {
			s.cfg.sleep(remaining)
		} else {
			s.cfg.sleep(interval)
		}
		if !s.cfg.now().Before(deadline) {
			break
		}
		if up := s.workloadUptime(r.Namespace, r.Deploy); up >= 0 && up < minUp {
			minUp = up
		}
		if r.Outcome != "" || r.ResponseObserved {
			continue
		}
		switch r.AttackID {
		case "poison": // adapter-rotate: real actuation bumps the adapter epoch
			if ep := s.podAnno(r.Namespace, r.Pod, "phorvex.ai/adapter-epoch"); ep != "" && ep != epoch0 {
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "adapter-rotate", true
				r.TimeToDefendSec = round2(s.cfg.now().Sub(r.started).Seconds())
			}
		case "kvcache":
			// [DETECTION FIX] kv-reset's DEFINING property is that the pod stays ALIVE, so the
			// default branch below (which looks for the pod being deleted or quarantined) could
			// never observe it: every kvcache attack was scored LANDED no matter how well Phorvex
			// defended — while vLLM's own log showed POST /reset_prefix_cache 200 OK. The real
			// evidence of a flush is the kv-reset epoch annotation the handler writes ONLY after
			// the serving stack confirms the flush.
			if ep := s.podAnno(r.Namespace, r.Pod, "phorvex.ai/kv-reset-epoch"); ep != "" && ep != kvEpoch0 {
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "kv-reset", true
				r.DefendedPod = r.Pod // the flush happens IN the attacked pod; it is never a neighbor
				r.TimeToDefendSec = round2(s.cfg.now().Sub(r.started).Seconds())
			}
		default: // foothold signal: only replacement of the exact pre-signal UID proves a target response
			replaced, probeErr := s.targetUIDReplaced(r.Namespace, r.Pod, r.TargetUID)
			if probeErr != nil {
				r.ObservationError = "target identity observation: " + probeErr.Error()
				publishAttack(r)
				continue
			}
			if !s.cfg.now().Before(deadline) {
				r.ObservationError = "target identity observation completed outside the registered window"
				publishAttack(r)
				continue
			}
			if replaced && r.EvidenceKind == "synthetic-detector-signal" {
				r.ResponseObserved = true
				r.ResponseAction = "rotate"
				r.ResponsePod = r.Pod
				r.ResponseSeconds = round2(s.cfg.now().Sub(r.accepted).Seconds())
				publishAttack(r)
			} else if replaced {
				r.Outcome, r.Actuated = "DEFENDED", true
				r.Action = "rotate"
				r.DefendedPod = r.Pod
				r.TimeToDefendSec = round2(s.cfg.now().Sub(r.started).Seconds())
			} else if r.EvidenceKind == "synthetic-detector-signal" {
				continue
			} else if qn := s.freshQuarantineName(r.Namespace, quar0); qn != "" {
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "quarantine", true
				// capture the REAL target Phorvex quarantined (may be a neighbor node it isolates to cut
				// lateral spread, not necessarily the attacked pod) + the decision reasoning from the event.
				r.DefendedPod = strings.TrimPrefix(s.kctlOut(r.Namespace, "get", "securityevent", qn, "-o", "jsonpath={.spec.targets[0]}"), r.Namespace+"/")
				if r.DefendedPod != r.Pod {
					r.Outcome, r.Action, r.Actuated, r.DefendedPod = "", "", false, ""
					continue
				}
				r.Why = s.kctlOut(r.Namespace, "get", "securityevent", qn, "-o", "jsonpath={.spec.description}")
				r.TimeToDefendSec = round2(s.cfg.now().Sub(r.started).Seconds())
			} else if np := s.newQuarantineNP(r.Namespace, np0); np != "" {
				// native-actuator path (no phorvex-quarantine SecurityEvent): a fresh quarantine NetworkPolicy.
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "quarantine", true
				r.DefendedPod = podFromNP(np, r.Namespace)
				if r.DefendedPod != r.Pod {
					r.Outcome, r.Action, r.Actuated, r.DefendedPod = "", "", false, ""
					continue
				}
				r.TimeToDefendSec = round2(s.cfg.now().Sub(r.started).Seconds())
			}
		}
		if r.Outcome != "" {
			publishAttack(r)
		}
	}
	if r.EvidenceKind == "synthetic-detector-signal" {
		// A detector signal is not an exploit and supplies no attacker foothold. Persist
		// response evidence without manufacturing DEFENDED/LANDED, containment or dwell.
		r.Outcome, r.Action, r.DefendedPod, r.Containment = "", "", "", ""
		r.Actuated, r.TimeToDefendSec, r.DwellSec, r.DwellOngoing = false, 0, 0, false
	} else if r.Outcome == "" {
		r.Outcome = "LANDED"
		r.Actuated = false
		if r.Action == "" {
			r.Action = "noop"
		}
	}
	if r.EvidenceKind == "" {
		classifyContainment(r, round2(s.cfg.now().Sub(r.started).Seconds()))
	}
	r.UptimeDip = minUp
	r.UptimeAfter = s.workloadUptime(r.Namespace, r.Deploy)
	if r.EvidenceKind == "" {
		s.fillReasoning(ctxName, r)
		s.fillCost(ctxName, r)
	}
	r.Status = "done"
	if r.ObservationError != "" {
		r.Status = "partial"
	}
	publishAttack(r)
	if err := s.persistAttack(r); err != nil {
		r.Status = "partial"
		r.PersistenceError = "effect observed but outcome evidence unavailable; unsafe to retry: " + err.Error()
		s.recordStateError(fmt.Errorf("persist attack outcome: %w", err))
		publishAttack(r)
	}
}

// --- ground-truth probes (real kubectl) ---

func (s *Server) kctlOut(ns string, args ...string) string {
	full := append([]string{"-n", ns}, args...)
	out, _ := s.cfg.execText(8*time.Second, "kubectl", full...)
	return strings.TrimSpace(out)
}

// firstDeploy returns the namespace's primary workload name — a Deployment, or a StatefulSet (e.g.
// NATS JetStream) when there's no Deployment. Used to sample availability around an attack. Uses
// `-o name` (not jsonpath {.items[0]}), which returns empty (not an array-index error) on an empty
// list — the console's execText folds stderr in, so an errored jsonpath would poison the name.
func (s *Server) firstDeploy(ns string) string {
	if d := firstName(s.kctlOut(ns, "get", "deploy", "-o", "name")); d != "" {
		return d
	}
	return firstName(s.kctlOut(ns, "get", "statefulset", "-o", "name"))
}

// firstName extracts the first resource short-name from `kubectl -o name` output
// ("deployment.apps/litellm\n..." => "litellm"); "" if none.
func firstName(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if i := strings.LastIndex(ln, "/"); i >= 0 {
			return ln[i+1:]
		}
		return ln
	}
	return ""
}

func (s *Server) podGone(ns, pod string) bool {
	_, err := s.cfg.execText(6*time.Second, "kubectl", "-n", ns, "get", "pod", pod, "-o", "name")
	return err != nil // NotFound => gone (rotated)
}

func (s *Server) targetUIDReplaced(ns, pod, uid string) (bool, error) {
	if uid == "" {
		return false, fmt.Errorf("target UID unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	live, found, err := s.experimentCluster().PodUID(ctx, ns, pod)
	if err != nil {
		return false, err
	}
	if !found {
		return true, nil
	}
	if live == "" {
		return false, fmt.Errorf("live target UID unavailable")
	}
	return live != uid, nil
}

// quarantineNPs returns the set of Phorvex/Phoenix QUARANTINE NetworkPolicy names in the namespace:
// phorvex-quarantine-<pod> (native actuator) or <ns>-<pod>-policy (Phoenix actuator). Baselined at watch
// start so a STALE policy from a prior attack cannot false-trigger THIS attack's outcome.
func (s *Server) quarantineNPs(ns string) map[string]bool {
	out := s.kctlOut(ns, "get", "networkpolicy", "--no-headers", "-o", "custom-columns=N:.metadata.name")
	set := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		if n := strings.TrimSpace(ln); strings.Contains(n, "quarantine") || strings.HasSuffix(n, "-policy") {
			set[n] = true
		}
	}
	return set
}

// newQuarantineNP returns a quarantine NetworkPolicy name that appeared since the baseline, or "".
func (s *Server) newQuarantineNP(ns string, baseline map[string]bool) string {
	for n := range s.quarantineNPs(ns) {
		if !baseline[n] {
			return n
		}
	}
	return ""
}

// podFromNP extracts the quarantined pod from a quarantine NetworkPolicy name:
// Phoenix "<ns>-<pod>-policy" => pod; native "phorvex-quarantine-<pod>" => pod.
func podFromNP(name, ns string) string {
	if strings.HasPrefix(name, "phorvex-quarantine-") {
		return strings.TrimPrefix(name, "phorvex-quarantine-")
	}
	return strings.TrimSuffix(strings.TrimPrefix(name, ns+"-"), "-policy")
}

// quarantineEvents returns the set of Phorvex QUARANTINE SecurityEvent names in the namespace. The
// in-cluster (Phoenix) actuator records a quarantine as a phorvex-quarantine-<hash> SecurityEvent
// (spec.targets = ["<ns>/<pod>"]) — NOT a NetworkPolicy — so we snapshot this set at watch start and
// detect a NEW entry to attribute a quarantine to THIS attack (ignoring stale records from prior runs).
func (s *Server) quarantineEvents(ns string) map[string]bool {
	out := s.kctlOut(ns, "get", "securityevent", "--no-headers", "-o", "custom-columns=N:.metadata.name")
	set := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		if n := strings.TrimSpace(ln); strings.HasPrefix(n, "phorvex-quarantine-") {
			set[n] = true
		}
	}
	return set
}

// freshQuarantineName returns the name of a phorvex-quarantine SecurityEvent that appeared since the
// baseline snapshot (i.e. THIS attack's), or "" if none. Namespace-scoped: a Phorvex quarantine records
// its own target in the event, which the caller reads back.
func (s *Server) freshQuarantineName(ns string, baseline map[string]bool) string {
	for name := range s.quarantineEvents(ns) {
		if !baseline[name] {
			return name
		}
	}
	return ""
}

func (s *Server) podAnno(ns, pod, key string) string {
	if key == "metadata.uid" {
		return s.kctlOut(ns, "get", "pod", pod, "-o", "jsonpath={.metadata.uid}")
	}
	return s.kctlOut(ns, "get", "pod", pod, "-o", "jsonpath={.metadata.annotations."+strings.ReplaceAll(key, ".", "\\.")+"}")
}

// workloadUptime = readyReplicas/replicas * 100 for the Deployment OR StatefulSet (real availability).
// -1 if unknown.
func (s *Server) workloadUptime(ns, deploy string) float64 {
	if deploy == "" {
		return -1
	}
	out := s.kctlOut(ns, "get", "deploy", deploy, "--ignore-not-found", "-o", "jsonpath={.status.readyReplicas}|{.spec.replicas}")
	if strings.TrimSpace(out) == "" {
		out = s.kctlOut(ns, "get", "statefulset", deploy, "--ignore-not-found", "-o", "jsonpath={.status.readyReplicas}|{.spec.replicas}")
	}
	parts := strings.SplitN(out, "|", 2)
	if len(parts) != 2 {
		return -1
	}
	ready, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	desired, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
	if desired <= 0 {
		return -1
	}
	return round2(float64(ready) / float64(desired) * 100)
}

// fillReasoning preserves event-derived facts and, separately, attaches a bounded temporal
// candidate from the canonical decision audit. Time/workload proximity is evidence, not identity.
func (s *Server) fillReasoning(ctxName string, r *attackRecord) {
	s.parseDescReasoning(r)
	target := r.Pod
	if r.DefendedPod != "" {
		target = r.DefendedPod
	}
	fired, err := time.Parse(time.RFC3339Nano, r.FiredAt)
	if err != nil {
		return
	}
	deadline := s.cfg.now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	records, err := s.readDecisionWindow(ctx, ctxName)
	if err != nil {
		return
	}
	var best *audit.Record
	for i := range records {
		d := &records[i]
		if d.Namespace != r.Namespace || d.Pod != target || (!d.Selected && !d.Actuated) || d.Time.Before(fired) || d.Time.After(deadline) {
			continue
		}
		// When an observed action exists, a different selected action is not evidence for it.
		if r.Action != "" && r.Action != "noop" && d.Action != r.Action {
			continue
		}
		if best == nil || d.Time.Before(best.Time) {
			best = d
		}
	}
	if best != nil {
		r.DecisionEvidence = &decisionEvidence{Correlation: "temporal-workload", Time: best.Time.UTC().Format(time.RFC3339Nano), Action: best.Action, Reason: best.Reason, Selected: best.Selected, Actuated: best.Actuated}
		if economics, ok := decodeAuditEconomics(best.Economics, best.Lambda); ok {
			r.Lambda = best.Lambda
			r.LambdaAvailable = true
			r.EconomicsVersion = economics.Version
			r.EffectiveCostCoefficient = economics.EffectiveCostCoefficient
			r.DisruptionAversionPresent = economics.DisruptionAversion.Present
			if economics.DisruptionAversion.Present {
				r.DisruptionAversion = economics.DisruptionAversion.Value
			}
			r.EconomicsAvailable = true
		}
	}
}

func (s *Server) readDecisionWindow(ctx context.Context, ctxName string) ([]audit.Record, error) {
	path := s.cfg.auditPathForContext(ctxName)
	f, err := openDecisionSource(ctx, path, s.cfg.AuditSource)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	generation, err := auditGeneration(f)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const window = int64(16 << 20)
	start := max(int64(0), st.Size()-window)
	startAnchor, err := auditAnchor(f, start)
	if err != nil {
		return nil, err
	}
	snapshotAnchor, err := auditAnchor(f, st.Size())
	if err != nil {
		return nil, err
	}
	b := make([]byte, st.Size()-start)
	if len(b) > 0 {
		if _, err = f.ReadAt(b, start); err != nil {
			return nil, err
		}
	}
	if remote, ok := f.(interface{ Verify() error }); ok {
		if err = remote.Verify(); err != nil {
			return nil, err
		}
	} else {
		capturedHash := sha256.Sum256(b)
		verify, openErr := openDecisionSource(ctx, path, s.cfg.AuditSource)
		if openErr != nil {
			return nil, errAuditChanged
		}
		defer verify.Close()
		verifyGeneration, verifyErr := auditGeneration(verify)
		if verifyErr != nil || verifyGeneration != generation {
			return nil, errAuditChanged
		}
		if anchor, anchorErr := auditAnchor(verify, start); anchorErr != nil || anchor != startAnchor {
			return nil, errAuditChanged
		}
		if anchor, anchorErr := auditAnchor(verify, st.Size()); anchorErr != nil || anchor != snapshotAnchor {
			return nil, errAuditChanged
		}
		verifiedHash, hashErr := auditRangeHash(verify, uint64(start), uint64(len(b)))
		if hashErr != nil || verifiedHash != capturedHash {
			return nil, errAuditChanged
		}
	}
	if start > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		} else {
			return nil, nil
		}
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
			b = b[:i+1]
		} else {
			return nil, nil
		}
	}
	var out []audit.Record
	for len(b) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break
		}
		line := b[:i]
		b = b[i+1:]
		if len(line) == 0 || len(line) > liveRecordBytes {
			continue
		}
		var rec audit.Record
		if json.Unmarshal(line, &rec) == nil && rec.Kind == "phorvex.decision" {
			out = append(out, rec)
		}
	}
	return out, nil
}

func decodeAuditEconomics(raw any, roundedLambda float64) (model.EconomicsMetadata, bool) {
	data, err := json.Marshal(raw)
	if err != nil {
		return model.EconomicsMetadata{}, false
	}
	var economics model.EconomicsMetadata
	if json.Unmarshal(data, &economics) != nil || model.ValidateEconomicsMetadata(&economics) != nil ||
		!audit.EconomicsMatchesRoundedLambda(&economics, roundedLambda) {
		return model.EconomicsMetadata{}, false
	}
	return economics, true
}

func auditFieldAvailable(rec map[string]any, name string) bool {
	b, err := json.Marshal(rec)
	if err != nil {
		return false
	}
	var decoded audit.Record
	if err := json.Unmarshal(b, &decoded); err != nil || decoded.Measurements == nil {
		return false
	}
	m := decoded.Measurements
	switch name {
	case "perDollar":
		return m.PerDollar.Present
	case "lambda":
		return m.Lambda.Present
	case "coveredFacts":
		return m.CoveredFacts.Present
	}
	return false
}

var (
	reDescPerDollar = regexp.MustCompile(`=([0-9.]+) per-\$`)
	reDescPHold     = regexp.MustCompile(`pHold=([0-9.]+)`)
	reDescStage     = regexp.MustCompile(`stage=(\S+)`)
)

// parseDescReasoning derives the numeric decision fields from a Phorvex SecurityEvent description, e.g.
// "quarantine nats/nats-1: cuts lateral recon (cov=34.33/$0.28=121.15 per-$); stage=recon→lateral pHold=0.31".
// Only fills fields that are still zero/empty so a real audit decision always wins.
func (s *Server) parseDescReasoning(r *attackRecord) {
	if r.Why == "" {
		return
	}
	if !r.PerDollarAvailable {
		if m := reDescPerDollar.FindStringSubmatch(r.Why); len(m) == 2 {
			r.PerDollar = atof(m[1])
			r.PerDollarAvailable = true
		}
	}
	if r.PHold == 0 {
		if m := reDescPHold.FindStringSubmatch(r.Why); len(m) == 2 {
			r.PHold = atof(m[1])
		}
	}
	if r.Stage == "" {
		if m := reDescStage.FindStringSubmatch(r.Why); len(m) == 2 {
			r.Stage = m[1]
		}
	}
}

// nodeAnnualCost = the pod's node annual on-demand cost (real AWS list price). Falls back to the
// cluster per-node average when the type isn't priced or the pod is already gone.
func (s *Server) nodeAnnualCost(ctxName, ns, pod string) float64 {
	pr := s.clusterPricing(ctxName)
	node := s.kctlOut(ns, "get", "pod", pod, "-o", "jsonpath={.spec.nodeName}")
	var perHr float64
	if node != "" {
		it, _ := s.cfg.execText(6*time.Second, "kubectl", "get", "node", node,
			"-o", "jsonpath={.metadata.labels.node\\.kubernetes\\.io/instance-type}")
		it = strings.TrimSpace(it)
		for _, n := range pr.Nodes {
			if n.InstanceType == it {
				perHr = n.PricePerHr
				break
			}
		}
	}
	if perHr <= 0 && pr.TotalPerHr > 0 { // fallback: cluster average per node (sum of counts)
		total := 0
		for _, n := range pr.Nodes {
			total += n.Count
		}
		perHr = pr.TotalPerHr / float64(maxi(total, 1))
	}
	return round2(perHr * 8760)
}

// fillCost computes the three-way cost from LIVE AWS pricing + the measured outcome.
func (s *Server) fillCost(ctxName string, r *attackRecord) {
	valueAtRisk := r.Cost.ValueAtRisk // captured at attack start (pod's real node price)
	if valueAtRisk <= 0 {
		valueAtRisk = s.nodeAnnualCost(ctxName, r.Namespace, r.Pod)
	}
	opCost, _ := s.phorvexOperatorCost(ctxName) // $/yr operator footprint (real)

	// ANNUAL projection: every arm is an EXPECTED yearly loss driven by that defender's PAIRED,
	// harness-measured prevention rate. Previously this row mixed kinds — Phorvex was scored on the
	// binary outcome of the single attack just fired (a miss projected a FULL year of loss, so
	// "WITH PHORVEX" printed above "WITHOUT ANY DEFENSE" and savings went negative) while R6 got a
	// flat hardcoded 20% credit that understated it by half. A single event is not an annual rate.
	pr := s.cfg.PreventionRates()
	r6Churn := opCost * 3 // constant blind rotations cost ~3x the operator footprint (measured order-of-magnitude)
	without := round2(valueAtRisk * (1 - pr.None))
	with := round2(valueAtRisk*(1-pr.Phorvex) + opCost)
	var r6 float64
	if r.Stateful {
		r6 = round2(valueAtRisk + r6Churn) // blind rotate destroys the stateful data => full loss + churn
	} else {
		r6 = round2(valueAtRisk*(1-pr.R6) + r6Churn)
	}
	src := "documented fallback rates"
	if pr.Measured {
		src = fmt.Sprintf("harness-measured over %d paired scenarios (n=%d/%d/%d)", pr.Scenarios, pr.NoneN, pr.R6N, pr.PxN)
	}
	r.Cost = attackCost{
		ValueAtRisk: valueAtRisk, Without: without, R6: r6, With: with,
		Savings: round2(without - with),
		// the inputs, so the dashboard can print the arithmetic rather than a bare total
		NodeInstance:   s.nodeInstanceType(ctxName, r.Namespace, r.Pod),
		NodeRatePerHr:  round4(s.buildRateResolver(ctxName)(r.Namespace, r.Pod)),
		PreventNone:    round4(pr.None),
		PreventR6:      round4(pr.R6),
		PreventPhorvex: round4(pr.Phorvex),
		RatesSource:    src,
		OperatorCost:   round2(opCost),
		R6Churn:        round2(r6Churn),
		Note: fmt.Sprintf("MODELLED annual projection (not this attack's outcome — see the DEFENDED/LANDED badge for that). "+
			"value-at-risk = attacked node's real AWS on-demand $/yr; each arm = value-at-risk x (1 - prevention rate), "+
			"prevention rates %s: none %.1f%%, R6 blind timer %.1f%%, Phorvex %.1f%%. WITH adds the real operator footprint; "+
			"R6 adds blind-rotation churn and destroys stateful data.",
			src, pr.None*100, pr.R6*100, pr.Phorvex*100),
	}
}

func (s *Server) attackResults(w http.ResponseWriter, r *http.Request) {
	if err := s.loadAttacks(); err != nil {
		s.recordStateError(err)
		writeJSON(w, 503, map[string]any{"attacks": []*attackRecord{}, "error": err.Error()})
		return
	}
	// [M-136] The attack ledger spans every namespace the console has ever fired at, so it is
	// filtered to the tenants this identity is granted. A cross-tenant grant sees all of it.
	p := principalOf(r)
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	exactID := strings.TrimSpace(r.URL.Query().Get("id"))
	pg, err := collectionPagingFromRequest(r, "/api/attack-results", p, map[string]string{"id": exactID, "q": search})
	if err != nil {
		writeCollectionPagingError(w, err)
		return
	}
	if pg.Enabled {
		out, page, err := pagedRealAttackSnapshots("/api/attack-results", p, pg, search, exactID)
		if err != nil {
			writeCollectionPagingError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"attacks": out, "page": page})
		return
	}
	// Synthetic detector signals support the dedicated three-arm comparison, but
	// they are not exploits and therefore do not belong in the global attack report.
	out := realAttackSnapshots(p)
	writeJSON(w, 200, map[string]any{"attacks": out})
}

func numf(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return 0
}
func maxi(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// nodeInstanceType returns the EC2 instance type backing the attacked pod, so the cost breakdown
// can name the hardware the $/hr came from instead of showing an unexplained rate.
func (s *Server) nodeInstanceType(ctxName, ns, pod string) string {
	if pod == "" {
		return ""
	}
	node := strings.TrimSpace(s.kctlOut(ns, "get", "pod", pod, "--ignore-not-found", "-o", "jsonpath={.spec.nodeName}"))
	if node == "" {
		return ""
	}
	it, _ := s.cfg.execText(6*time.Second, "kubectl", "get", "node", node,
		"-o", "jsonpath={.metadata.labels.node\\.kubernetes\\.io/instance-type}")
	return strings.TrimSpace(it)
}
