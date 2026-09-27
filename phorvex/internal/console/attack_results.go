/*
 * Phorvex Console — bounded case observations.
 *
 * Records may contain a behavioral oracle, a target-bound mechanism effect, or only a synthetic
 * detector signal. Those stages stay typed and separate: accepted signals and manager decisions
 * never become LANDED/DEFENDED outcomes without a behavioral oracle. GET /api/attack-results
 * returns the authorized records (newest first) for the Report tab.
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"

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
	OwnerKind    string            `json:"ownerKind,omitempty"`
	OwnerUID     string            `json:"ownerUid,omitempty"`
	Attack       string            `json:"attack"`
	AttackID     string            `json:"attackId"`
	MITRE        string            `json:"mitre"`
	Expected     string            `json:"expectedActuator"`
	Stateful     bool              `json:"stateful"`
	EvidenceKind string            `json:"evidenceKind,omitempty"`
	// StimulusEvidence and EffectEvidence keep setup, controller effect and attacker outcome
	// separate. A selector or guardrail-state transition is useful operational evidence, but it
	// does not by itself establish that an attack was executed or mitigated.
	StimulusEvidence     *attackStimulusEvidence     `json:"stimulusEvidence,omitempty"`
	EffectEvidence       *attackEffectEvidence       `json:"effectEvidence,omitempty"`
	GuardrailEffectProbe *guardrailEffectProbeResult `json:"guardrailEffectProbe,omitempty"`
	GuardrailOutputProbe *guardrailOutputProbeResult `json:"guardrailOutputProbe,omitempty"`
	VoiceMemoryProbe     *voiceMemoryProbeResult     `json:"voiceMemoryProbe,omitempty"`
	VoiceAgencyProbe     *voiceAgencyProbeResult     `json:"voiceAgencyProbe,omitempty"`
	VoiceMCPProbe        *voiceMCPLiveProbeResult    `json:"voiceMCPProbe,omitempty"`
	LiteLLMLiveProbe     *liteLLMLiveProbeResult     `json:"litellmLiveProbe,omitempty"`
	OutcomeClass         string                      `json:"outcomeClass,omitempty"`
	LoRACleanupStatus    string                      `json:"loraCleanupStatus,omitempty"`
	LoRACleanupError     string                      `json:"loraCleanupError,omitempty"`
	ProducerRoute        string                      `json:"producerRoute,omitempty"`
	ResultSchema         string                      `json:"resultSchemaVersion,omitempty"`
	ObservationStart     string                      `json:"observationStartedAt,omitempty"`
	ObservationEnd       string                      `json:"observationDeadline,omitempty"`

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
	ResponseObserved         bool               `json:"responseObserved,omitempty"`
	ResponseAction           string             `json:"responseAction,omitempty"`
	ResponsePod              string             `json:"responsePod,omitempty"`
	ResponseSeconds          float64            `json:"responseSeconds,omitempty"`
	ObservationError         string             `json:"observationError,omitempty"`
	DecisionEvidence         *decisionEvidence  `json:"decisionEvidence,omitempty"`
	DecisionTraceEvidence    []decisionEvidence `json:"decisionTraceEvidence,omitempty"`
	TemporalDecisionEvidence *decisionEvidence  `json:"temporalDecisionEvidence,omitempty"`

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

	started                   time.Time       // unexported, for elapsed timing
	accepted                  time.Time       // producer acknowledgement, for signal-response latency
	baseEpoch                 string          // pre-attack adapter epoch (poison detection)
	baseKVEpoch               string          // pre-attack kv-reset epoch (kvcache detection)
	baseQuar                  map[string]bool // pre-attack quarantine SecurityEvent names
	baseNP                    map[string]bool // pre-attack quarantine NetworkPolicy names
	vllmEffect                *vllmEffectBaseline
	loRATerminalPersisted     bool
	loRATerminalPersistFailed bool
}

type attackStimulusEvidence struct {
	Kind               string `json:"kind"`
	Observed           bool   `json:"observed"`
	TargetUID          string `json:"targetUid"`
	EventName          string `json:"eventName"`
	EventUID           string `json:"eventUid"`
	EventCreatedAt     string `json:"eventCreatedAt"`
	EventRule          string `json:"eventRule"`
	Correlation        string `json:"correlation"`
	BehavioralExecuted bool   `json:"behavioralExecuted"`
	Limitation         string `json:"limitation"`
	// Original create request/reply are retained only in the private measured
	// effect package; these never appear in attack history JSON.
	createManifest []byte
	createReply    []byte
}

type attackEffectEvidence struct {
	Kind        string  `json:"kind"`
	Observed    bool    `json:"observed"`
	ObservedAt  string  `json:"observedAt,omitempty"`
	TargetUID   string  `json:"targetUid"`
	Before      string  `json:"before,omitempty"`
	After       string  `json:"after,omitempty"`
	ServiceUID  string  `json:"serviceUid,omitempty"`
	Correlation string  `json:"correlation"`
	Limitation  string  `json:"limitation"`
	Seconds     float64 `json:"seconds"`
}

// vllmEffectBaseline is private watcher authority captured and checked by the launch path.
// It is deliberately not reconstructed from old receipts or Pod annotations.
type vllmEffectBaseline struct {
	kind        string
	before      string
	serviceName string
	serviceUID  string
	adapterName string
}

type decisionEvidence struct {
	Correlation         string                   `json:"correlation"`
	Source              string                   `json:"source,omitempty"`
	Time                string                   `json:"time"`
	EventName           string                   `json:"eventName,omitempty"`
	EventUID            string                   `json:"eventUid,omitempty"`
	EventRule           string                   `json:"eventRule,omitempty"`
	DeclaredSource      string                   `json:"declaredSource,omitempty"`
	TrustVerdict        string                   `json:"trustVerdict,omitempty"`
	CreatorIdentity     string                   `json:"creatorIdentity,omitempty"`
	TargetUID           string                   `json:"targetUid,omitempty"`
	DecisionID          string                   `json:"decisionId,omitempty"`
	TickID              string                   `json:"tickId,omitempty"`
	BrainImage          string                   `json:"brainImage,omitempty"`
	GitSHA              string                   `json:"gitSha,omitempty"`
	PolicyNamespace     string                   `json:"policyNamespace,omitempty"`
	PolicyName          string                   `json:"policyName,omitempty"`
	PolicyUID           string                   `json:"policyUid,omitempty"`
	Action              string                   `json:"action"`
	Reason              string                   `json:"reason"`
	Selected            bool                     `json:"selected"`
	Feasible            bool                     `json:"feasible"`
	InfeasibleWhy       string                   `json:"infeasibleWhy,omitempty"`
	DryRun              bool                     `json:"dryRun"`
	DryRunCause         string                   `json:"dryRunCause,omitempty"`
	ActuationBrakeCause string                   `json:"actuationBrakeCause,omitempty"`
	KillSwitch          bool                     `json:"killSwitch"`
	KillSwitchCause     string                   `json:"killSwitchCause,omitempty"`
	Actuated            bool                     `json:"actuated"`
	DispatchOutcome     string                   `json:"dispatchOutcome,omitempty"`
	DispatchReason      string                   `json:"dispatchReason,omitempty"`
	Handler             string                   `json:"handler,omitempty"`
	ObjectsTouched      []string                 `json:"objectsTouched,omitempty"`
	RollbackRef         string                   `json:"rollbackRef,omitempty"`
	MutationKind        string                   `json:"mutationKind,omitempty"`
	ActionStatus        []decisionActionEvidence `json:"actionStatus,omitempty"`
}

type decisionActionEvidence struct {
	Action        string `json:"action"`
	Status        string `json:"status"`
	ExclusionKind string `json:"exclusionKind,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Scored        bool   `json:"scored"`
	RBACUnknown   bool   `json:"rbacUnknown,omitempty"`
}

// defenseBaseline is the snapshot of pre-existing defense artifacts, taken by the attack handler BEFORE
// the attack is applied. Capturing it pre-fire (not at watcher start) is essential: the operator can
// react within ~1s, faster than the watcher's own baseline kubectl calls would complete — so a
// watcher-side snapshot would absorb this attack's own quarantine and misreport it as LANDED.
type defenseBaseline struct {
	uid           string
	deploy        string
	ownerKind     string
	ownerUID      string
	epoch         string
	kvEpoch       string
	quar          map[string]bool
	nps           map[string]bool
	stimulus      *attackStimulusEvidence
	vllmEffect    *vllmEffectBaseline
	outcomeClass  string
	producerRoute string
	resultSchema  string
	// uptime is the workload availability read BEFORE the attack is applied. It must be captured
	// here for the same reason as the quarantine/NP baselines: the operator is event-driven and
	// reacts in ~1s, faster than startAttackRecord runs, so reading it afterwards recorded the
	// attack's OWN dip as the "before" value (a 3/3 broker was reported as 66.67% before).
	uptime float64
}

// snapshotBaseline captures the defense baseline for a namespace/pod. Call BEFORE applying the attack.
func (s *Server) snapshotBaseline(ns, pod string) defenseBaseline {
	return s.snapshotBaselineForOwner(ns, pod, s.firstDeploy(ns), "", s.podAnno(ns, pod, "metadata.uid"))
}

// A vLLM observation is bound to the selected Pod's controller. Other
// Deployments in the namespace cannot supply its availability baseline.
func (s *Server) snapshotVLLMBaseline(pod vllmPodState) defenseBaseline {
	kind, name, uid := s.vllmPodWorkloadOwner(pod)
	return s.snapshotBaselineForOwnerKind(vllmAttackNS, pod.Metadata.Name, kind, name, uid, pod.Metadata.UID)
}

func (s *Server) vllmPodWorkloadOwner(pod vllmPodState) (string, string, string) {
	if len(pod.Metadata.OwnerReferences) != 1 {
		return "", "", ""
	}
	owner := pod.Metadata.OwnerReferences[0]
	if owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" || owner.Name == "" || owner.UID == "" || owner.Controller == nil || !*owner.Controller {
		return "", "", ""
	}
	var rs appsv1.ReplicaSet
	if err := s.scenarioObject(vllmAttackNS, "replicaset", owner.Name, &rs); err != nil || rs.Namespace != vllmAttackNS || rs.Name != owner.Name || string(rs.UID) != owner.UID || rs.ResourceVersion == "" || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
		return "", "", ""
	}
	depRef := rs.OwnerReferences[0]
	if depRef.APIVersion != "apps/v1" || depRef.Kind != "Deployment" || depRef.Name == "" || depRef.UID == "" || depRef.Controller == nil || !*depRef.Controller {
		return "", "", ""
	}
	var dep appsv1.Deployment
	if err := s.scenarioObject(vllmAttackNS, "deployment", depRef.Name, &dep); err != nil || dep.Namespace != vllmAttackNS || dep.Name != depRef.Name || dep.UID != depRef.UID || dep.ResourceVersion == "" || dep.DeletionTimestamp != nil {
		return "", "", ""
	}
	return "Deployment", dep.Name, string(dep.UID)
}

// Exact catalogue targets use the selected Deployment. A namespace-first
// Deployment would silently report an unrelated business workload's uptime.
func (s *Server) snapshotBaselineForOwner(ns, pod, deploy, ownerUID, podUID string) defenseBaseline {
	return s.snapshotBaselineForOwnerKind(ns, pod, "Deployment", deploy, ownerUID, podUID)
}

// Exact catalogue targets keep their controller kind through every availability read.
// The empty UID path retains the namespace-only compatibility behavior.
func (s *Server) snapshotBaselineForOwnerKind(ns, pod, ownerKind, ownerName, ownerUID, podUID string) defenseBaseline {
	if ownerUID == "" {
		ownerKind = ""
	}
	return defenseBaseline{
		uid:       podUID,
		deploy:    ownerName,
		ownerKind: ownerKind,
		ownerUID:  ownerUID,
		uptime:    s.workloadUptimeBoundKind(ns, ownerName, ownerKind, ownerUID),
		epoch:     s.podAnno(ns, pod, "phorvex.ai/adapter-epoch"),
		kvEpoch:   s.podAnno(ns, pod, "phorvex.ai/kv-reset-epoch"),
		quar:      s.quarantineEvents(ns),
		nps:       s.quarantineNPs(ns),
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
	if r.StimulusEvidence != nil {
		stimulus := *r.StimulusEvidence
		stimulus.createManifest = append([]byte(nil), r.StimulusEvidence.createManifest...)
		stimulus.createReply = append([]byte(nil), r.StimulusEvidence.createReply...)
		c.StimulusEvidence = &stimulus
	}
	if r.EffectEvidence != nil {
		effect := *r.EffectEvidence
		c.EffectEvidence = &effect
	}
	if r.GuardrailEffectProbe != nil {
		probe := *r.GuardrailEffectProbe
		probe.Issues = append([]string(nil), r.GuardrailEffectProbe.Issues...)
		c.GuardrailEffectProbe = &probe
	}
	if r.GuardrailOutputProbe != nil {
		probe := *r.GuardrailOutputProbe
		probe.Issues = append([]string(nil), r.GuardrailOutputProbe.Issues...)
		c.GuardrailOutputProbe = &probe
	}
	if r.VoiceMemoryProbe != nil {
		probe := *r.VoiceMemoryProbe
		c.VoiceMemoryProbe = &probe
	}
	if r.VoiceAgencyProbe != nil {
		probe := *r.VoiceAgencyProbe
		probe.Issues = append([]string(nil), r.VoiceAgencyProbe.Issues...)
		c.VoiceAgencyProbe = &probe
	}
	if r.vllmEffect != nil {
		baseline := *r.vllmEffect
		c.vllmEffect = &baseline
	}
	if r.DecisionEvidence != nil {
		evidence := *r.DecisionEvidence
		evidence.ObjectsTouched = append([]string(nil), r.DecisionEvidence.ObjectsTouched...)
		evidence.ActionStatus = append([]decisionActionEvidence(nil), r.DecisionEvidence.ActionStatus...)
		c.DecisionEvidence = &evidence
	}
	if r.TemporalDecisionEvidence != nil {
		evidence := *r.TemporalDecisionEvidence
		evidence.ObjectsTouched = append([]string(nil), r.TemporalDecisionEvidence.ObjectsTouched...)
		evidence.ActionStatus = append([]decisionActionEvidence(nil), r.TemporalDecisionEvidence.ActionStatus...)
		c.TemporalDecisionEvidence = &evidence
	}
	c.DecisionTraceEvidence = append([]decisionEvidence(nil), r.DecisionTraceEvidence...)
	for i := range c.DecisionTraceEvidence {
		c.DecisionTraceEvidence[i].ObjectsTouched = append([]string(nil), r.DecisionTraceEvidence[i].ObjectsTouched...)
		c.DecisionTraceEvidence[i].ActionStatus = append([]decisionActionEvidence(nil), r.DecisionTraceEvidence[i].ActionStatus...)
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

// Live views include reviewed Voice observations. Experiment-only signals
// and unknown evidence kinds remain excluded, as do observations in default reports.
func visibleAttackRecord(rec *attackRecord, observations bool) bool {
	return rec.EvidenceKind == "" || rec.EvidenceKind == "voice-memory-live" || rec.EvidenceKind == "voice-agency-live" || rec.EvidenceKind == "voice-mcp-live" || (observations && (rec.EvidenceKind == "vllm-in-place-effect" || rec.EvidenceKind == "vllm-unsupported-stimulus" || rec.EvidenceKind == "catalogue-signal"))
}

func realAttackSnapshots(p *Principal, includeObservations ...bool) []*attackRecord {
	observations := len(includeObservations) > 0 && includeObservations[0]
	all := attackSnapshots(p)
	out := make([]*attackRecord, 0, len(all))
	for _, rec := range all {
		if visibleAttackRecord(rec, observations) {
			out = append(out, rec)
		}
	}
	return out
}

func pagedRealAttackSnapshots(endpoint string, p *Principal, pg collectionPaging, search, exactID string, includeObservations ...bool) ([]*attackRecord, collectionPage, error) {
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
		if !visibleAttackRecord(rec, len(includeObservations) > 0 && includeObservations[0]) || (!p.TenantWildcard() && !p.AllowsTenant(rec.Namespace)) {
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

func (s *Server) startVLLMEffectRecord(service, pod, attack, attackID, evidenceLabel, expected string, base defenseBaseline) string {
	d := s.cfg.AttackWatchDuration
	if d <= 0 {
		d = 95 * time.Second
	}
	started := s.cfg.now()
	return s.startAttackRecordAtKind("", service, vllmAttackNS, pod, attack, attackID, evidenceLabel, expected, false, base, started, started.Add(d), "vllm-in-place-effect", started)
}

func (s *Server) startVLLMUnsupportedRecord(service, pod, attack, attackID, evidenceLabel, expected string, base defenseBaseline) string {
	d := s.cfg.AttackWatchDuration
	if d <= 0 {
		d = 95 * time.Second
	}
	started := s.cfg.now()
	return s.startAttackRecordAtKind("", service, vllmAttackNS, pod, attack, attackID, evidenceLabel, expected, false, base, started, started.Add(d), "vllm-unsupported-stimulus", started)
}

func (s *Server) startCatalogueSignalRecord(ns, pod, scenario, mitre, expected string, stateful bool, base defenseBaseline) string {
	d := s.cfg.AttackWatchDuration
	if d <= 0 {
		d = 95 * time.Second
	}
	started := s.cfg.now()
	return s.startAttackRecordAtKind("", ns, ns, pod, scenario, scenario, mitre, expected, stateful, base, started, started.Add(d), "catalogue-signal", started)
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
	deploy := base.deploy
	if deploy == "" && base.ownerUID == "" && evidenceKind != "vllm-in-place-effect" && evidenceKind != "vllm-unsupported-stimulus" {
		deploy = s.firstDeploy(ns)
	}
	r := &attackRecord{
		ID:      "atk-" + strconv.FormatInt(started.UnixNano(), 36),
		FiredAt: started.UTC().Format(time.RFC3339Nano),
		Service: service, Namespace: ns, Pod: pod, Deploy: deploy, OwnerKind: base.ownerKind, OwnerUID: base.ownerUID,
		Attack: attack, AttackID: attackID, MITRE: mitre, Expected: expected, Stateful: stateful, EvidenceKind: evidenceKind,
		TargetUID:        base.uid,
		StimulusEvidence: base.stimulus,
		OutcomeClass:     base.outcomeClass,
		ProducerRoute:    base.producerRoute,
		ResultSchema:     base.resultSchema,
		ObservationStart: started.UTC().Format(time.RFC3339Nano),
		ObservationEnd:   deadline.UTC().Format(time.RFC3339Nano),
		Status:           "running",
		// PRE-FIRE value when the caller captured one (>=0); fall back to a live read only if the
		// baseline predates this field, so an old caller still gets a number rather than 0.
		UptimeBefore: func() float64 {
			if base.uptime >= 0 {
				return base.uptime
			}
			return s.workloadUptimeBoundKind(ns, deploy, base.ownerKind, base.ownerUID)
		}(),
		started:     started,
		accepted:    accepted,
		baseEpoch:   base.epoch,
		baseKVEpoch: base.kvEpoch,
		baseQuar:    base.quar,
		baseNP:      base.nps,
		vllmEffect:  base.vllmEffect,
	}
	// capture value-at-risk NOW (the attacked pod's node still exists; it may be rotated away before
	// the watcher finishes) so the cost is grounded in the real node price, not the cluster fallback.
	if evidenceKind != "vllm-in-place-effect" && evidenceKind != "vllm-unsupported-stimulus" {
		r.Cost.ValueAtRisk = s.nodeAnnualCost("", ns, pod)
	}
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
		if up := s.workloadUptimeBoundKind(r.Namespace, r.Deploy, r.OwnerKind, r.OwnerUID); up >= 0 && up < minUp {
			minUp = up
		}
		if r.Outcome != "" || r.ResponseObserved || (r.EffectEvidence != nil && r.AttackID != "poison") {
			continue
		}
		if r.EvidenceKind == "vllm-in-place-effect" {
			if r.AttackID == "poison" {
				s.observeOwnedLoRAOutcome(ctxName, r, deadline)
				publishAttack(r)
				if r.loRATerminalPersisted {
					break
				}
				continue
			}
			effect, probeErr := s.observeVLLMInPlaceEffect(r)
			if probeErr != nil {
				r.ObservationError = "in-place effect observation: " + probeErr.Error()
				publishAttack(r)
				continue
			}
			if effect != nil {
				if !s.cfg.now().Before(deadline) {
					r.ObservationError = "in-place effect observation completed outside the registered window"
					publishAttack(r)
					continue
				}
				effect.Seconds = round2(s.cfg.now().Sub(r.started).Seconds())
				r.EffectEvidence = effect
				// Exact mechanism evidence is not by itself a behavioral or causal verdict.
				r.Action, r.Actuated, r.TimeToDefendSec = r.AttackID, false, 0
				r.OutcomeClass = "effect-only"
				publishAttack(r)
			}
			continue
		}
		if r.EvidenceKind == "vllm-unsupported-stimulus" {
			continue
		}
		if r.EvidenceKind == "synthetic-detector-signal" || r.EvidenceKind == "catalogue-signal" {
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
			if replaced {
				r.ResponseObserved = true
				r.ResponseAction = "rotate"
				r.ResponsePod = r.Pod
				r.ResponseSeconds = round2(s.cfg.now().Sub(r.accepted).Seconds())
				if r.EvidenceKind == "catalogue-signal" {
					r.OutcomeClass = "response-only"
				}
				publishAttack(r)
			}
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
		default: // behavioral foothold: exact target replacement or target-bound quarantine is scored
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
			if replaced {
				r.Outcome, r.Actuated = "DEFENDED", true
				r.Action = "rotate"
				r.DefendedPod = r.Pod
				r.TimeToDefendSec = round2(s.cfg.now().Sub(r.started).Seconds())
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
	if r.EvidenceKind == "vllm-in-place-effect" && r.AttackID == "poison" {
		s.finishOwnedLoRAOutcome(ctxName, r)
	} else if r.EvidenceKind == "vllm-in-place-effect" {
		// These scenarios currently have an exact setup/effect oracle but no behavioral attack
		// oracle. Preserve the action evidence without manufacturing DEFENDED/LANDED, dwell or
		// containment. In particular, an epoch/selector transition is not attacker mitigation.
		r.Outcome, r.DefendedPod, r.Containment = "", "", ""
		r.DwellSec, r.DwellOngoing = 0, false
		if r.EffectEvidence == nil {
			r.Actuated, r.Action, r.TimeToDefendSec = false, "", 0
			r.OutcomeClass = "effect-unverified"
			if r.ObservationError == "" {
				r.ObservationError = "no exact target-bound in-place effect observed within the registered window"
			}
		}
	} else if r.EvidenceKind == "synthetic-detector-signal" || r.EvidenceKind == "vllm-unsupported-stimulus" || r.EvidenceKind == "catalogue-signal" {
		// A detector signal is not an exploit and supplies no attacker foothold. Persist
		// response evidence without manufacturing DEFENDED/LANDED, containment or dwell.
		r.Outcome, r.Action, r.DefendedPod, r.Containment = "", "", "", ""
		r.Actuated, r.TimeToDefendSec, r.DwellSec, r.DwellOngoing = false, 0, 0, false
		if r.EvidenceKind == "catalogue-signal" && !r.ResponseObserved {
			if r.ObservationError == "" {
				r.ObservationError = "no exact target response observed within the registered window"
				r.OutcomeClass = "response-unconfirmed"
			} else {
				r.OutcomeClass = "observation-unavailable"
			}
		}
	} else if r.Outcome == "" && r.ObservationError == "" {
		r.Outcome = "LANDED"
		r.Actuated = false
		if r.Action == "" {
			r.Action = "noop"
		}
	} else if r.Outcome == "" {
		r.Action, r.DefendedPod, r.Containment = "", "", ""
		r.Actuated, r.TimeToDefendSec, r.DwellSec, r.DwellOngoing = false, 0, 0, false
		r.OutcomeClass = "observation-unavailable"
	}
	if r.EvidenceKind == "" && r.Outcome != "" {
		classifyContainment(r, round2(s.cfg.now().Sub(r.started).Seconds()))
	}
	r.UptimeDip = minUp
	r.UptimeAfter = s.workloadUptimeBoundKind(r.Namespace, r.Deploy, r.OwnerKind, r.OwnerUID)
	if r.EvidenceKind == "" {
		s.fillReasoning(ctxName, r)
		s.fillCost(ctxName, r)
	} else if r.EvidenceKind == "vllm-in-place-effect" || r.EvidenceKind == "vllm-unsupported-stimulus" || r.EvidenceKind == "catalogue-signal" {
		// The manager audit can carry the SecurityEvent UID in steeredBy facts, but this
		// bounded console correlator does not consume that binding yet. Keep this temporal.
		s.fillReasoning(ctxName, r)
	}
	if r.EvidenceKind == "catalogue-signal" && r.DecisionEvidence == nil {
		missing := "no manager decision could be correlated to the exact catalogue signal; brain disposition is unavailable"
		if r.ObservationError == "" {
			r.ObservationError = missing
		} else {
			r.ObservationError += "; " + missing
		}
	}
	r.Status = "done"
	if r.ObservationError != "" || (r.EvidenceKind == "vllm-in-place-effect" && r.AttackID == "poison" && (r.LoRACleanupStatus == "unknown" || r.PersistenceError != "")) {
		r.Status = "partial"
	}
	if r.EvidenceKind == "vllm-in-place-effect" && r.AttackID == "poison" {
		if !r.loRATerminalPersisted {
			if err := s.persistAttack(r); err != nil {
				r.Outcome, r.Action, r.DefendedPod, r.Actuated, r.TimeToDefendSec = "", "", "", false, 0
				r.OutcomeClass = "unapproved-adapter-capability-unresolved"
				r.ObservationError = "terminal LoRA outcome evidence was not durable"
				r.Status = "partial"
				r.PersistenceError = "LoRA terminal evidence persistence failed; unsafe to retry: " + err.Error()
				s.recordStateError(fmt.Errorf("persist LoRA outcome: %w", err))
			}
		}
		publishAttack(r)
		return
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
func (s *Server) workloadUptimeBound(ns, deploy, ownerUID string) float64 {
	ownerKind := "Deployment"
	if ownerUID == "" {
		ownerKind = ""
	}
	return s.workloadUptimeBoundKind(ns, deploy, ownerKind, ownerUID)
}

func (s *Server) workloadUptimeBoundKind(ns, name, ownerKind, ownerUID string) float64 {
	if ownerUID != "" {
		switch ownerKind {
		case "", "Deployment": // Empty kind belongs to persisted Deployment records.
			var live appsv1.Deployment
			if err := s.scenarioObject(ns, "deployment", name, &live); err != nil || live.Namespace != ns || live.Name != name || string(live.UID) != ownerUID || live.ResourceVersion == "" || live.DeletionTimestamp != nil || live.Spec.Replicas == nil || *live.Spec.Replicas <= 0 {
				return -1
			}
			return round2(float64(live.Status.ReadyReplicas) / float64(*live.Spec.Replicas) * 100)
		case "StatefulSet":
			var live appsv1.StatefulSet
			if err := s.scenarioObject(ns, "statefulset", name, &live); err != nil || live.Namespace != ns || live.Name != name || string(live.UID) != ownerUID || live.ResourceVersion == "" || live.DeletionTimestamp != nil || live.Spec.Replicas == nil || *live.Spec.Replicas <= 0 {
				return -1
			}
			return round2(float64(live.Status.ReadyReplicas) / float64(*live.Spec.Replicas) * 100)
		default:
			return -1
		}
	}
	if ownerKind != "" {
		return -1
	}
	return s.workloadUptime(ns, name)
}

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

const maxDecisionTraceEvidence = 16

type matchedEventReference struct {
	source, name, uid, rule, declaredSource, trust, creator, targetUID string
}

type exactDecisionMatch struct {
	evidence decisionEvidence
	record   *audit.Record
}

// fillReasoning preserves event-derived facts and attaches exact event-bound manager
// dispositions when the audit carries immutable identity. A workload/time candidate is
// retained separately for old records; it never becomes causal evidence.
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
	collectedAt := s.cfg.now()
	temporalStart, temporalDeadline := fired, collectedAt
	if persistedStart, parseErr := time.Parse(time.RFC3339Nano, r.ObservationStart); parseErr == nil && !persistedStart.IsZero() {
		temporalStart = persistedStart
	}
	if persistedEnd, parseErr := time.Parse(time.RFC3339Nano, r.ObservationEnd); parseErr == nil && persistedEnd.After(temporalStart) && persistedEnd.Before(temporalDeadline) {
		temporalDeadline = persistedEnd
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	records, err := s.readDecisionWindow(ctx, ctxName)
	if err != nil {
		return
	}
	var best, noop *audit.Record
	exact := make([]exactDecisionMatch, 0)
	for i := range records {
		d := &records[i]
		if d.Namespace != r.Namespace || d.Pod != target || d.Time.Before(temporalStart) || d.Time.After(temporalDeadline) {
			// Exact event evidence may occur after the verified event creation but before
			// a post-create observation record was registered. exactDecisionEvidence
			// applies the persisted immutable bounds instead of this temporal filter.
			if evidence, ok := exactDecisionEvidence(r, d, collectedAt); ok {
				exact = append(exact, exactDecisionMatch{evidence: evidence, record: d})
			}
			continue
		}
		if evidence, ok := exactDecisionEvidence(r, d, collectedAt); ok {
			exact = append(exact, exactDecisionMatch{evidence: evidence, record: d})
		}
		if !d.Selected && !d.Actuated {
			if (r.EvidenceKind == "catalogue-signal" || r.EvidenceKind == "synthetic-detector-signal") && (noop == nil || d.Time.Before(noop.Time)) {
				noop = d
			}
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
	sort.SliceStable(exact, func(i, j int) bool { return exact[i].record.Time.Before(exact[j].record.Time) })
	var chosen *audit.Record
	correlation := "temporal-workload"
	if best == nil && noop != nil {
		best = noop
		correlation = "temporal-workload-noop"
	}
	if best != nil {
		temporal := decisionEvidenceFromAudit(best, correlation, "temporal-candidate", matchedEventReference{})
		r.TemporalDecisionEvidence = &temporal
		if len(exact) == 0 {
			r.DecisionEvidence = &temporal
		}
	}
	if len(exact) > 0 {
		summary := exact[0]
		for i := 1; i < len(exact); i++ {
			if decisionDispositionRank(exact[i].evidence) > decisionDispositionRank(summary.evidence) ||
				(decisionDispositionRank(exact[i].evidence) == decisionDispositionRank(summary.evidence) && exact[i].record.Time.After(summary.record.Time)) {
				summary = exact[i]
			}
		}
		evidence := summary.evidence
		r.DecisionEvidence = &evidence
		chosen = summary.record
		exact = boundedDecisionMatches(exact, summary)
		r.DecisionTraceEvidence = make([]decisionEvidence, len(exact))
		for i := range exact {
			r.DecisionTraceEvidence[i] = exact[i].evidence
		}
	}
	if len(exact) == 0 {
		chosen = best
	}
	if chosen != nil {
		if economics, ok := decodeAuditEconomics(chosen.Economics, chosen.Lambda); ok {
			r.Lambda = chosen.Lambda
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

func boundedDecisionMatches(all []exactDecisionMatch, summary exactDecisionMatch) []exactDecisionMatch {
	if len(all) <= maxDecisionTraceEvidence {
		return all
	}
	// Preserve the beginning and end of a long-lived event plus the authoritative
	// summary disposition. Audit records are immutable; pointer identity is safe here.
	out := append([]exactDecisionMatch(nil), all[:maxDecisionTraceEvidence/2]...)
	for _, candidate := range all[len(all)-maxDecisionTraceEvidence/2:] {
		if len(out) == maxDecisionTraceEvidence {
			break
		}
		out = append(out, candidate)
	}
	found := false
	for i := range out {
		found = found || out[i].record == summary.record
	}
	if !found {
		out[len(out)/2] = summary
		sort.SliceStable(out, func(i, j int) bool { return out[i].record.Time.Before(out[j].record.Time) })
	}
	return out
}

func exactDecisionEvidence(r *attackRecord, d *audit.Record, collectedAt time.Time) (decisionEvidence, bool) {
	if r.AttackID == "poison" && r.EvidenceKind == "vllm-in-place-effect" {
		trace := d.DecisionTrace
		if trace == nil || trace.Validate() != nil || trace.SelectedAction != d.Action ||
			trace.DispatchOutcome != d.DispatchOutcome || trace.DecisionID == "" || trace.TickID == "" {
			return decisionEvidence{}, false
		}
	}
	if r.StimulusEvidence == nil || !r.StimulusEvidence.Observed || r.StimulusEvidence.EventName == "" ||
		r.StimulusEvidence.EventUID == "" || r.StimulusEvidence.EventRule == "" || r.TargetUID == "" ||
		r.StimulusEvidence.TargetUID != r.TargetUID {
		return decisionEvidence{}, false
	}
	created, err := time.Parse(time.RFC3339Nano, r.StimulusEvidence.EventCreatedAt)
	if err != nil || created.IsZero() {
		return decisionEvidence{}, false
	}
	start, err := time.Parse(time.RFC3339Nano, r.ObservationStart)
	if err != nil || start.IsZero() {
		return decisionEvidence{}, false
	}
	end, err := time.Parse(time.RFC3339Nano, r.ObservationEnd)
	if err != nil || !end.After(start) || created.After(end) || d.Time.Before(created) || d.Time.After(end) || d.Time.After(collectedAt) {
		return decisionEvidence{}, false
	}
	if d.Namespace != r.Namespace || d.Pod != r.Pod {
		return decisionEvidence{}, false
	}
	ref, ok := exactAuditEventReference(r, d)
	if !ok {
		return decisionEvidence{}, false
	}
	return decisionEvidenceFromAudit(d, "exact-event-uid", ref.source, ref), true
}

func exactAuditEventReference(r *attackRecord, d *audit.Record) (matchedEventReference, bool) {
	stimulus := r.StimulusEvidence
	matches := make([]matchedEventReference, 0, 2)
	if d.DecisionTrace != nil {
		if d.DecisionTrace.Validate() != nil || d.DecisionTrace.AssetNamespace != r.Namespace ||
			d.DecisionTrace.AssetName != r.Pod || d.DecisionTrace.AssetUID != r.TargetUID {
			return matchedEventReference{}, false
		}
		for _, fact := range d.DecisionTrace.Facts {
			if fact.SteeredBy == nil {
				continue
			}
			for _, event := range fact.SteeredBy.Events {
				if event.EventName == stimulus.EventName && event.EventUID == stimulus.EventUID && event.RuleType == stimulus.EventRule &&
					(event.TargetPodUID == "" || event.TargetPodUID == r.TargetUID) {
					matches = append(matches, matchedEventReference{source: "decision-trace-steered-event", name: event.EventName, uid: event.EventUID,
						rule: event.RuleType, declaredSource: event.DeclaredSource, trust: event.TrustVerdict,
						creator: event.CreatorIdentity, targetUID: r.TargetUID})
				}
			}
		}
	}
	for _, event := range d.Events {
		if event.TargetsPod && event.Name == stimulus.EventName && event.EventUID == stimulus.EventUID &&
			event.Type == stimulus.EventRule && event.TargetPodUID == r.TargetUID {
			matches = append(matches, matchedEventReference{source: "generic-event-evidence", name: event.Name, uid: event.EventUID,
				rule: event.Type, declaredSource: event.Source, trust: event.TrustVerdict,
				creator: event.CreatorIdentity, targetUID: event.TargetPodUID})
		}
	}
	if len(matches) == 0 {
		return matchedEventReference{}, false
	}
	merged := matches[0]
	for _, candidate := range matches[1:] {
		if candidate.name != merged.name || candidate.uid != merged.uid || candidate.rule != merged.rule || candidate.targetUID != merged.targetUID ||
			conflictingNonempty(candidate.declaredSource, merged.declaredSource) || conflictingNonempty(candidate.trust, merged.trust) ||
			conflictingNonempty(candidate.creator, merged.creator) {
			return matchedEventReference{}, false
		}
		merged.declaredSource = richerString(merged.declaredSource, candidate.declaredSource)
		merged.trust = richerString(merged.trust, candidate.trust)
		merged.creator = richerString(merged.creator, candidate.creator)
		if candidate.source == "decision-trace-steered-event" {
			merged.source = candidate.source
		}
	}
	return merged, true
}

func conflictingNonempty(a, b string) bool { return a != "" && b != "" && a != b }

func richerString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func decisionEvidenceFromAudit(d *audit.Record, correlation, source string, ref matchedEventReference) decisionEvidence {
	e := decisionEvidence{
		Correlation: correlation, Source: source, Time: d.Time.UTC().Format(time.RFC3339Nano), EventName: ref.name,
		EventUID: ref.uid, EventRule: ref.rule, DeclaredSource: ref.declaredSource, TrustVerdict: ref.trust,
		CreatorIdentity: ref.creator, TargetUID: ref.targetUID, Action: d.Action, Reason: d.Reason,
		Selected: d.Selected, Feasible: d.Feasible, InfeasibleWhy: d.InfeasibleWhy, DryRun: d.DryRun,
		DryRunCause: d.DryRunCause, ActuationBrakeCause: d.ActuationBrakeCause, KillSwitch: d.KillSwitch,
		KillSwitchCause: d.KillSwitchCause, Actuated: d.Actuated, DispatchOutcome: d.DispatchOutcome,
		DispatchReason: d.DispatchReason, Handler: d.Handler, ObjectsTouched: append([]string(nil), d.ObjectsTouched...),
		RollbackRef: d.RollbackRef, MutationKind: d.MutationKind,
	}
	if trace := d.DecisionTrace; trace != nil && trace.Validate() == nil {
		e.DecisionID, e.TickID, e.BrainImage, e.GitSHA = trace.DecisionID, trace.TickID, trace.BrainImage, trace.GitSHA
		e.PolicyNamespace, e.PolicyName, e.PolicyUID = trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID
		e.ActionStatus = make([]decisionActionEvidence, 0, len(trace.ActionStatus))
		for _, row := range trace.ActionStatus {
			e.ActionStatus = append(e.ActionStatus, decisionActionEvidence{Action: row.Action, Status: row.Status,
				ExclusionKind: row.ExclusionKind, Reason: row.Reason, Scored: row.Scored, RBACUnknown: row.RBACUnknown})
		}
	}
	return e
}

func decisionDispositionRank(e decisionEvidence) int {
	switch e.DispatchOutcome {
	case model.DispatchEmitted, model.DispatchEmittedFalse, model.DispatchSatisfied, model.DispatchReconciled:
		return 5
	case model.DispatchError, model.DispatchRefused:
		return 4
	case model.DispatchDeclared:
		return 3
	case model.DispatchNotAttempted:
		// Keep the actual selection/no-op rank below a later dispatch disposition.
	default:
		if e.Actuated {
			return 3
		}
	}
	switch {
	case e.Actuated:
		return 3
	case e.Selected:
		return 2
	default:
		return 1
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
	observations := r.URL.Query().Get("includeObservations")
	if observations != "" && observations != "true" && observations != "false" {
		writeJSON(w, 400, map[string]string{"error": "includeObservations must be true or false"})
		return
	}
	filters := map[string]string{"id": exactID, "q": search}
	if observations == "true" {
		filters["includeObservations"] = "true"
	}
	pg, err := collectionPagingFromRequest(r, "/api/attack-results", p, filters)
	if err != nil {
		writeCollectionPagingError(w, err)
		return
	}
	if pg.Enabled {
		out, page, err := pagedRealAttackSnapshots("/api/attack-results", p, pg, search, exactID, observations == "true")
		if err != nil {
			writeCollectionPagingError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"attacks": out, "page": page})
		return
	}
	// Synthetic detector signals support the dedicated three-arm comparison, but
	// they are not exploits and therefore do not belong in the global attack report.
	out := realAttackSnapshots(p, observations == "true")
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
