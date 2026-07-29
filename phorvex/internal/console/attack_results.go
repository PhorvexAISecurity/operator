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
)

type attackCost struct {
	ValueAtRisk float64 `json:"valueAtRisk"` // real AWS $/yr the attacked node exposes
	Without     float64 `json:"without"`     // no defense: attack lands, full exposure
	R6          float64 `json:"r6"`          // R6 blind timer: residual + churn (+ data loss if stateful)
	With        float64 `json:"with"`        // Phorvex: residual after the measured disruption + defense cost
	Savings     float64 `json:"savings"`     // without - with
	Note        string  `json:"note"`
}

type attackRecord struct {
	ID        string `json:"id"`
	FiredAt   string `json:"firedAt"`
	Service   string `json:"service"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Deploy    string `json:"deploy"`
	Attack    string `json:"attack"`
	AttackID  string `json:"attackId"`
	MITRE     string `json:"mitre"`
	Expected  string `json:"expectedActuator"`
	Stateful  bool   `json:"stateful"`

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

	// real decision reasoning (from the in-cluster operator's audit)
	Why          string  `json:"why"`
	PerDollar    float64 `json:"perDollar"`
	Stage        string  `json:"stage"`
	CoveredFacts int     `json:"coveredFacts"`
	PHold        float64 `json:"pHold"`
	Lambda       float64 `json:"lambda"`
	R6Would      string  `json:"r6Would"`
	R6Note       string  `json:"r6Note"`

	// real uptime, sampled around the attack (ready/desired * 100)
	UptimeBefore float64 `json:"uptimeBefore"`
	UptimeDip    float64 `json:"uptimeDip"`
	UptimeAfter  float64 `json:"uptimeAfter"`

	Cost attackCost `json:"cost"`

	started     time.Time       // unexported, for elapsed timing
	baseEpoch   string          // pre-attack adapter epoch (poison detection)
	baseKVEpoch string          // pre-attack kv-reset epoch (kvcache detection)
	baseQuar    map[string]bool // pre-attack quarantine SecurityEvent names
	baseNP      map[string]bool // pre-attack quarantine NetworkPolicy names
}

// defenseBaseline is the snapshot of pre-existing defense artifacts, taken by the attack handler BEFORE
// the attack is applied. Capturing it pre-fire (not at watcher start) is essential: the operator can
// react within ~1s, faster than the watcher's own baseline kubectl calls would complete — so a
// watcher-side snapshot would absorb this attack's own quarantine and misreport it as LANDED.
type defenseBaseline struct {
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
)

func (s *Server) attacksPath() string {
	base := s.cfg.AuditPath
	if base == "" {
		base = filepath.Join(s.cfg.Root, "phorvex-live.jsonl")
	}
	return filepath.Join(filepath.Dir(base), "phorvex-attacks.jsonl")
}

func (s *Server) loadAttacks() {
	attackMu.Lock()
	defer attackMu.Unlock()
	if attackLoaded {
		return
	}
	attackLoaded = true
	b, err := os.ReadFile(s.attacksPath())
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		var r attackRecord
		if json.Unmarshal([]byte(ln), &r) == nil {
			r.Status = "done"
			if r.Containment == "" { // (re)classify records persisted before the field existed
				classifyContainment(&r, 95) // 95s = the observation window (dwell floor for un-neutralized footholds)
			}
			attackList = append(attackList, &r)
		}
	}
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

func (s *Server) persistAttack(r *attackRecord) {
	f, err := os.OpenFile(s.attacksPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if b, err := json.Marshal(r); err == nil {
		_, _ = f.Write(append(b, '\n'))
	}
}

// startAttackRecord registers a running attack and launches the ground-truth watcher. Called by the
// attack handlers immediately after the real attack is applied to the cluster.
func (s *Server) startAttackRecord(ctxName, service, ns, pod, attack, attackID, mitre, expected string, stateful bool, base defenseBaseline) {
	s.loadAttacks()
	now := time.Now()
	deploy := s.firstDeploy(ns)
	r := &attackRecord{
		ID:        "atk-" + strconv.FormatInt(now.UnixNano(), 36),
		FiredAt:   now.UTC().Format(time.RFC3339),
		Service:   service, Namespace: ns, Pod: pod, Deploy: deploy,
		Attack: attack, AttackID: attackID, MITRE: mitre, Expected: expected, Stateful: stateful,
		Status:       "running",
		// PRE-FIRE value when the caller captured one (>=0); fall back to a live read only if the
		// baseline predates this field, so an old caller still gets a number rather than 0.
		UptimeBefore: func() float64 {
			if base.uptime >= 0 {
				return base.uptime
			}
			return s.workloadUptime(ns, deploy)
		}(),
		started:      now,
		baseEpoch:    base.epoch,
		baseKVEpoch:  base.kvEpoch,
		baseQuar:     base.quar,
		baseNP:       base.nps,
	}
	// capture value-at-risk NOW (the attacked pod's node still exists; it may be rotated away before
	// the watcher finishes) so the cost is grounded in the real node price, not the cluster fallback.
	r.Cost.ValueAtRisk = s.nodeAnnualCost("", ns, pod)
	attackMu.Lock()
	attackList = append(attackList, r)
	attackMu.Unlock()
	go s.watchAttack(ctxName, r)
}

func (s *Server) watchAttack(ctxName string, r *attackRecord) {
	deadline := time.Now().Add(95 * time.Second)
	minUp := r.UptimeBefore
	// baselines were captured PRE-FIRE by the handler (see defenseBaseline) — using a watcher-side
	// snapshot here would race a fast operator and misreport a real quarantine as LANDED.
	epoch0 := r.baseEpoch
	kvEpoch0 := r.baseKVEpoch
	quar0 := r.baseQuar
	np0 := r.baseNP
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		if up := s.workloadUptime(r.Namespace, r.Deploy); up >= 0 && up < minUp {
			minUp = up
		}
		if r.Outcome != "" {
			continue
		}
		switch r.AttackID {
		case "poison": // adapter-rotate: real actuation bumps the adapter epoch
			if ep := s.podAnno(r.Namespace, r.Pod, "phorvex.ai/adapter-epoch"); ep != "" && ep != epoch0 {
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "adapter-rotate", true
				r.TimeToDefendSec = round2(time.Since(r.started).Seconds())
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
				r.TimeToDefendSec = round2(time.Since(r.started).Seconds())
			}
		default: // foothold: rotate (stateless) removes the attacked pod; quarantine (stateful) is recorded as a fresh phorvex-quarantine SecurityEvent
			if s.podGone(r.Namespace, r.Pod) {
				r.Outcome, r.Actuated = "DEFENDED", true
				r.Action = "rotate"
				r.DefendedPod = r.Pod
				r.TimeToDefendSec = round2(time.Since(r.started).Seconds())
			} else if qn := s.freshQuarantineName(r.Namespace, quar0); qn != "" {
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "quarantine", true
				// capture the REAL target Phorvex quarantined (may be a neighbor node it isolates to cut
				// lateral spread, not necessarily the attacked pod) + the decision reasoning from the event.
				r.DefendedPod = strings.TrimPrefix(s.kctlOut(r.Namespace, "get", "securityevent", qn, "-o", "jsonpath={.spec.targets[0]}"), r.Namespace+"/")
				r.Why = s.kctlOut(r.Namespace, "get", "securityevent", qn, "-o", "jsonpath={.spec.description}")
				r.TimeToDefendSec = round2(time.Since(r.started).Seconds())
			} else if np := s.newQuarantineNP(r.Namespace, np0); np != "" {
				// native-actuator path (no phorvex-quarantine SecurityEvent): a fresh quarantine NetworkPolicy.
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "quarantine", true
				r.DefendedPod = podFromNP(np, r.Namespace)
				r.TimeToDefendSec = round2(time.Since(r.started).Seconds())
			}
		}
	}
	if r.Outcome == "" {
		r.Outcome = "LANDED"
		r.Actuated = false
		if r.Action == "" {
			r.Action = "noop"
		}
	}
	classifyContainment(r, round2(time.Since(r.started).Seconds()))
	r.UptimeDip = minUp
	r.UptimeAfter = s.workloadUptime(r.Namespace, r.Deploy)
	s.fillReasoning(ctxName, r)
	s.fillCost(ctxName, r)
	r.Status = "done"
	s.persistAttack(r)
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

// fillReasoning pulls the ACTUAL decision (action, why, per-$, stage, r6) for the attacked pod from
// the in-cluster operator's audit log — the operator that really actuated.
func (s *Server) fillReasoning(ctxName string, r *attackRecord) {
	op, _ := s.cfg.execText(8*time.Second, "kubectl", "get", "pods", "-n", "phorvex-system",
		"-l", "app.kubernetes.io/name=phorvex", "-o", "jsonpath={.items[0].metadata.name}")
	op = strings.TrimSpace(op)
	if op == "" {
		return
	}
	logs, _ := s.cfg.execText(10*time.Second, "kubectl", "logs", "-n", "phorvex-system", op, "--tail=400")
	// the real decision is for the pod Phorvex actuated on — the quarantined/rotated pod, which on a
	// stateful cluster may be a neighbor of the attacked pod. Fall back to the attacked pod.
	target := r.Pod
	if r.DefendedPod != "" {
		target = r.DefendedPod
	}
	var best map[string]any
	for _, ln := range strings.Split(logs, "\n") {
		i := strings.Index(ln, "decision\t")
		if i < 0 || !strings.Contains(ln, r.Namespace+"/"+target) {
			continue
		}
		var d map[string]any
		if json.Unmarshal([]byte(ln[i+len("decision\t"):]), &d) != nil {
			continue
		}
		// prefer a non-noop selected decision; else keep the last
		if best == nil {
			best = d
		}
		if act, _ := d["action"].(string); act != "noop" && act != "" {
			best = d
		}
	}
	if best == nil {
		// no structured audit decision (e.g. in-cluster Phoenix actuator records reasoning in the
		// SecurityEvent, not the operator audit log): derive the numbers from the event description.
		s.parseDescReasoning(r)
		return
	}
	if v, ok := best["action"].(string); ok && v != "" && v != "noop" {
		r.Action = v
	}
	if w, _ := best["why"].(string); w != "" { // don't clobber an event-derived reason with an empty audit why
		r.Why = w
	}
	r.Stage, _ = best["stage"].(string)
	r.R6Would, _ = best["r6Would"].(string)
	r.R6Note, _ = best["r6Note"].(string)
	r.PerDollar = numf(best["perDollar"])
	r.PHold = numf(best["pHold"])
	r.Lambda = numf(best["lambda"])
	r.CoveredFacts = int(numf(best["coveredFacts"]))
	s.parseDescReasoning(r) // backfill any numbers the audit line lacked (e.g. per-$ from the event desc)
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
	if r.PerDollar == 0 {
		if m := reDescPerDollar.FindStringSubmatch(r.Why); len(m) == 2 {
			r.PerDollar = atof(m[1])
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
		Note: fmt.Sprintf("MODELLED annual projection (not this attack's outcome — see the DEFENDED/LANDED badge for that). "+
			"value-at-risk = attacked node's real AWS on-demand $/yr; each arm = value-at-risk x (1 - prevention rate), "+
			"prevention rates %s: none %.1f%%, R6 blind timer %.1f%%, Phorvex %.1f%%. WITH adds the real operator footprint; "+
			"R6 adds blind-rotation churn and destroys stateful data.",
			src, pr.None*100, pr.R6*100, pr.Phorvex*100),
	}
}

func (s *Server) attackResults(w http.ResponseWriter, r *http.Request) {
	s.loadAttacks()
	attackMu.Lock()
	out := make([]*attackRecord, 0, len(attackList))
	for i := len(attackList) - 1; i >= 0; i-- { // newest first
		out = append(out, attackList[i])
	}
	attackMu.Unlock()
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
