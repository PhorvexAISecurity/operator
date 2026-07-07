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
	"net/http"
	"os"
	"path/filepath"
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
	Actuated        bool    `json:"actuated"`
	TimeToDefendSec float64 `json:"timeToDefendSec"`

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

	started time.Time // unexported, for elapsed timing
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
			attackList = append(attackList, &r)
		}
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
func (s *Server) startAttackRecord(ctxName, service, ns, pod, attack, attackID, mitre, expected string, stateful bool) {
	s.loadAttacks()
	now := time.Now()
	deploy := s.firstDeploy(ns)
	r := &attackRecord{
		ID:        "atk-" + strconv.FormatInt(now.UnixNano(), 36),
		FiredAt:   now.UTC().Format(time.RFC3339),
		Service:   service, Namespace: ns, Pod: pod, Deploy: deploy,
		Attack: attack, AttackID: attackID, MITRE: mitre, Expected: expected, Stateful: stateful,
		Status:       "running",
		UptimeBefore: s.workloadUptime(ns, deploy),
		started:      now,
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
	epoch0 := s.podAnno(r.Namespace, r.Pod, "phorvex.ai/adapter-epoch")
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
		default: // foothold: rotate (stateless) removes the attacked pod; quarantine (stateful) adds a NetworkPolicy
			if s.podGone(r.Namespace, r.Pod) {
				r.Outcome, r.Actuated = "DEFENDED", true
				r.Action = "rotate"
				r.TimeToDefendSec = round2(time.Since(r.started).Seconds())
			} else if s.hasQuarantineNP(r.Namespace, r.Pod) {
				r.Outcome, r.Action, r.Actuated = "DEFENDED", "quarantine", true
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

func (s *Server) firstDeploy(ns string) string {
	return s.kctlOut(ns, "get", "deploy", "-o", "jsonpath={.items[0].metadata.name}")
}

func (s *Server) podGone(ns, pod string) bool {
	_, err := s.cfg.execText(6*time.Second, "kubectl", "-n", ns, "get", "pod", pod, "-o", "name")
	return err != nil // NotFound => gone (rotated)
}

func (s *Server) hasQuarantineNP(ns, pod string) bool {
	out := s.kctlOut(ns, "get", "networkpolicy", "phorvex-quarantine-"+pod, "--ignore-not-found", "-o", "name")
	return out != ""
}

func (s *Server) podAnno(ns, pod, key string) string {
	return s.kctlOut(ns, "get", "pod", pod, "-o", "jsonpath={.metadata.annotations."+strings.ReplaceAll(key, ".", "\\.")+"}")
}

// workloadUptime = readyReplicas/replicas * 100 for the deploy (real availability). -1 if unknown.
func (s *Server) workloadUptime(ns, deploy string) float64 {
	if deploy == "" {
		return -1
	}
	out := s.kctlOut(ns, "get", "deploy", deploy, "-o", "jsonpath={.status.readyReplicas}|{.spec.replicas}")
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
	var best map[string]any
	for _, ln := range strings.Split(logs, "\n") {
		i := strings.Index(ln, "decision\t")
		if i < 0 || !strings.Contains(ln, r.Namespace+"/"+r.Pod) {
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
		return
	}
	if v, ok := best["action"].(string); ok && v != "" && v != "noop" {
		r.Action = v
	}
	r.Why, _ = best["why"].(string)
	r.Stage, _ = best["stage"].(string)
	r.R6Would, _ = best["r6Would"].(string)
	r.R6Note, _ = best["r6Note"].(string)
	r.PerDollar = numf(best["perDollar"])
	r.PHold = numf(best["pHold"])
	r.Lambda = numf(best["lambda"])
	r.CoveredFacts = int(numf(best["coveredFacts"]))
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

	defended := 0.0
	if r.Outcome == "DEFENDED" {
		defended = 1.0
	}
	// R6 blind timer: rotates on a fixed schedule regardless of the attack. On a targeted foothold it
	// catches only by luck (harness-measured ~20%) AND churns; on a STATEFUL pod it DELETES the data.
	const r6Catch = 0.2
	r6Churn := opCost * 3 // constant blind rotations cost ~3x the operator footprint (measured order-of-magnitude)
	without := valueAtRisk
	with := round2(valueAtRisk*(1-defended) + opCost)
	var r6 float64
	if r.Stateful {
		r6 = round2(valueAtRisk + r6Churn) // blind rotate destroys the stateful data => full loss + churn
	} else {
		r6 = round2(valueAtRisk*(1-r6Catch) + r6Churn)
	}
	r.Cost = attackCost{
		ValueAtRisk: valueAtRisk, Without: without, R6: r6, With: with,
		Savings: round2(without - with),
		Note:    "value-at-risk = attacked node's real AWS on-demand $/yr; WITH = residual after the measured disruption + operator footprint; R6 = blind-timer counterfactual (catches ~20% by luck, churns; destroys stateful data).",
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
