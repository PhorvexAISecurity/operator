/*
 * Phorvex Console — THREE-ARM EXPERIMENT RUNNER (user-triggered, live status).
 *
 * POST /api/availability-arms/run {namespace, attack} starts the three-arm comparison for ONE app
 * and returns immediately; the dashboard polls /api/availability-arms and watches it progress
 * arm-by-arm, then sees the finished run appear in the list.
 *
 * This is deliberately a user-triggered job, not something that happens on every attack: it puts
 * the tenant's policy into dryRun for the first two arms and rotates pods on a timer, which is
 * genuinely disruptive. Doing that silently behind a normal "fire attack" click would be a nasty
 * surprise. The UI says what it will do before it runs.
 *
 * SAFETY: the policy mode is restored to its ORIGINAL value in a defer, so an error, a panic or a
 * console restart mid-run cannot strand a tenant in dryRun (undefended). Only one experiment per
 * namespace at a time.
 */

package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// armsJob is the live status of one running experiment.
type armsJob struct {
	Namespace string `json:"namespace"`
	Deploy    string `json:"deploy"`
	Attack    string `json:"attack"`
	StartedAt string `json:"startedAt"`
	Phase     string `json:"phase"`    // arm-a | arm-b | arm-c | done | failed
	Detail    string `json:"detail"`   // human-readable current step
	Progress  int    `json:"progress"` // 0..100
	Error     string `json:"error,omitempty"`
}

var (
	armsMu   sync.Mutex
	armsJobs = map[string]*armsJob{} // namespace -> live job
)

func armsJobSnapshot() []armsJob {
	armsMu.Lock()
	defer armsMu.Unlock()
	out := make([]armsJob, 0, len(armsJobs))
	for _, j := range armsJobs {
		out = append(out, *j)
	}
	return out
}

func armsJobSnapshotFor(p *Principal) []armsJob {
	all := armsJobSnapshot()
	out := make([]armsJob, 0, len(all))
	for _, j := range all {
		if p != nil && (p.TenantWildcard() || p.AllowsTenant(j.Namespace)) {
			out = append(out, j)
		}
	}
	return out
}

func (s *Server) visibleArmsJobs(p *Principal) []armsJob {
	out := armsJobSnapshotFor(p)
	seen := map[string]bool{}
	for _, j := range out {
		seen[j.Namespace] = true
	}
	for _, e := range s.unresolvedExperiments() {
		if e.Namespace == "" || seen[e.Namespace] || p == nil || (!p.TenantWildcard() && !p.AllowsTenant(e.Namespace)) {
			continue
		}
		out = append(out, armsJob{Namespace: e.Namespace, Attack: e.Attack, StartedAt: e.At, Phase: "recovery-required", Detail: e.Phase, Progress: 100, Error: e.Error})
	}
	return out
}

func (s *Server) setArmsPhase(ns, phase, detail string, pct int) {
	armsMu.Lock()
	defer armsMu.Unlock()
	if j := armsJobs[ns]; j != nil {
		j.Phase, j.Detail, j.Progress = phase, detail, pct
	}
}

// runArmsExperiment starts the three-arm comparison for one namespace.
func (s *Server) runArmsExperiment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	if ok, reason := s.stateStatus(); !ok {
		writeJSON(w, 503, map[string]string{"error": "experiment state unavailable: " + reason})
		return
	}
	var body struct {
		Namespace string `json:"namespace"`
		Attack    string `json:"attack"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ns := strings.TrimSpace(body.Namespace)
	if ns == "" || !scenarioRe.MatchString(ns) {
		writeJSON(w, 400, map[string]string{"error": "namespace required"})
		return
	}
	// vllm is attacked through /api/vllm/attack (kvcache/poison) rather than the generic
	// workload-attack endpoint, so it is not in armedWorkloads — but it IS attackable and the
	// runner already routes it correctly. Accept both sets.
	if !armedWorkloads[ns] && ns != "vllm" {
		writeJSON(w, 400, map[string]string{"error": "namespace not armed for live attack: " + ns})
		return
	}
	attack := body.Attack
	if attack == "" {
		attack = "foothold"
	}
	if ns != "voice" || attack != "foothold" {
		writeJSON(w, 400, map[string]string{"error": "unsupported comparison: only the resettable stateless voice/foothold fixture is currently verified"})
		return
	}
	if _, _, err := s.resettableTarget(ns); err != nil {
		writeJSON(w, 400, map[string]string{"error": "comparison preflight: " + err.Error()})
		return
	}
	for _, e := range s.unresolvedExperiments() {
		if e.Namespace == ns {
			writeJSON(w, 409, map[string]string{"error": "an experiment in this namespace requires recovery"})
			return
		}
	}

	armsMu.Lock()
	if j := armsJobs[ns]; j != nil && j.Phase != "done" && j.Phase != "failed" {
		armsMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "an experiment is already running for " + ns})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	policyState, policyErr := s.experimentCluster().Policy(ctx, ns)
	cancel()
	deploy := s.firstDeploy(ns)
	job := &armsJob{Namespace: ns, Deploy: deploy, Attack: attack,
		StartedAt: time.Now().UTC().Format(time.RFC3339), Phase: "arm-a",
		Detail: "starting — switching the policy to dryRun", Progress: 1}
	armsJobs[ns] = job
	armsMu.Unlock()

	if policyErr != nil || deploy == "" {
		s.failArms(ns, "comparison preflight failed")
		writeJSON(w, 400, map[string]string{"error": "comparison preflight failed: " + fmt.Sprint(policyErr)})
		return
	}
	op := fmt.Sprintf("exp-%x", s.cfg.now().UnixNano())
	event := experimentEvent{Operation: op, Phase: "prepared", Actor: actorOf(r), Namespace: ns, Attack: attack, Policy: policyState, OriginalMode: policyState.Mode, OwnedMode: policyState.Mode, OwnedSpecHash: policyState.SpecHash, OwnedMetadataHash: policyState.MetadataHash}
	if err := s.appendExperiment(event); err != nil {
		s.failArms(ns, "experiment evidence unavailable: "+err.Error())
		writeJSON(w, 503, map[string]string{"error": "experiment refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}
	go s.armsWorker(event, deploy)

	writeJSON(w, 200, map[string]any{"ok": true, "namespace": ns, "deploy": deploy,
		"note": "three-arm comparison started (~7 minutes). Watch it in Availability: 3-way."})
}

func (s *Server) failArms(ns, msg string) {
	armsMu.Lock()
	defer armsMu.Unlock()
	if j := armsJobs[ns]; j != nil {
		j.Phase, j.Error, j.Detail, j.Progress = "failed", msg, "failed", 100
	}
}

func (s *Server) armsWorker(op experimentEvent, deploy string) {
	ns := op.Namespace
	fail := func(err error) {
		op.Error = err.Error()
		if op.Phase == "prepared" {
			op.Phase = "no-effect"
		}
		_ = s.appendExperiment(op)
		s.failArms(ns, err.Error())
	}
	defer func() {
		if r := recover(); r != nil {
			fail(fmt.Errorf("experiment panic: %v", r))
		}
	}()
	transition := func(mode string) error {
		op.OwnedMode = mode
		op.OwnedSpecHash = specHashWithMode(op.Policy, mode)
		op.OwnedMetadataHash = op.Policy.MetadataHash
		op.Phase = "transition-intent"
		if err := s.appendExperiment(op); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p, err := s.experimentCluster().SetPolicyMode(ctx, op.Policy, mode, op.Operation, false)
		if err != nil {
			return err
		}
		op.Policy = p
		op.OwnedMode = mode
		op.OwnedSpecHash = p.SpecHash
		op.OwnedMetadataHash = p.MetadataHash
		op.Phase = "applied"
		return s.appendExperiment(op)
	}
	observe := func(id string) (*attackRecord, error) {
		for i := 0; i < 110; i++ {
			if r := attackSnapshotByID(id); r != nil && (r.Status == "done" || r.Status == "partial") {
				if r.Status != "done" {
					return r, fmt.Errorf("attack observation persistence partial")
				}
				if persistedAttackByID(s.cfg, id) != nil {
					return r, nil
				}
			}
			s.cfg.sleep(time.Second)
		}
		return nil, fmt.Errorf("attack observation timeout")
	}
	ready := func() bool {
		out, err := s.cfg.execText(8*time.Second, "kubectl", "-n", ns, "get", "deploy", deploy, "-o", `jsonpath={.status.readyReplicas}|{.status.replicas}`)
		return err == nil && strings.TrimSpace(out) != "" && !strings.HasPrefix(strings.TrimSpace(out), "0|") && strings.Split(strings.TrimSpace(out), "|")[0] == strings.Split(strings.TrimSpace(out), "|")[1]
	}
	var arms []armEvidence
	for i, spec := range []struct{ id, label, mode string }{{"nodefense", "No defense", "dryRun"}, {"r6blind", "Blind fixed-interval rotator", "dryRun"}, {"phorvex", "Phorvex", "active"}} {
		if err := transition(spec.mode); err != nil {
			fail(fmt.Errorf("%s mode transition: %w", spec.id, err))
			return
		}
		s.cfg.sleep(2 * time.Second)
		a := armEvidence{ID: spec.id, Label: spec.label, Start: s.cfg.now().UTC().Format(time.RFC3339)}
		receipt, err := s.executeResettableFoothold(op.Actor, ns, "")
		if err != nil {
			a.Error = err.Error()
			arms = append(arms, a)
			fail(err)
			return
		}
		a.StimulusAccepted = true
		a.AttackID = receipt.AttackID
		a.TargetPod = receipt.Pod
		a.TargetUID = receipt.PodUID
		if spec.id == "r6blind" {
			rv := strings.TrimSpace(s.kctlOut(ns, "get", "pod", receipt.Pod, "-o", "jsonpath={.metadata.resourceVersion}"))
			if rv == "" {
				err = fmt.Errorf("target resourceVersion unavailable")
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err = s.experimentCluster().DeletePod(ctx, ns, receipt.Pod, receipt.PodUID, rv)
				cancel()
			}
			a.RotationConfirmed = err == nil
			if err != nil {
				a.Error = "identity-bound timer rotation: " + err.Error()
			}
		}
		obs, oerr := observe(receipt.AttackID)
		if obs != nil {
			a.Outcome = obs.Outcome
			a.Action = obs.Action
			a.Containment = obs.Containment
			a.DwellOngoing = obs.DwellOngoing
			a.ObservationPersisted = obs.Status == "done"
		}
		if oerr != nil && a.Error == "" {
			a.Error = oerr.Error()
		}
		if err = s.resetExperimentStimulus(receipt); err != nil && a.Error == "" {
			a.Error = err.Error()
		}
		for j := 0; j < 30 && !ready(); j++ {
			s.cfg.sleep(time.Second)
		}
		a.BaselineReady = ready()
		a.End = s.cfg.now().UTC().Format(time.RFC3339)
		if !a.BaselineReady && a.Error == "" {
			a.Error = "workload baseline not ready after reset"
		}
		arms = append(arms, a)
		op.Arm = &arms[len(arms)-1]
		op.Phase = "arm-result"
		if err = s.appendExperiment(op); err != nil {
			fail(err)
			return
		}
		if a.Error != "" {
			fail(fmt.Errorf("%s incomplete: %s", spec.id, a.Error))
			return
		}
		_ = i
	}
	op.Phase = "restore-intent"
	op.Arm = nil
	if err := s.appendExperiment(op); err != nil {
		fail(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	restored, err := s.experimentCluster().SetPolicyMode(ctx, op.Policy, op.OriginalMode, op.Operation, true)
	cancel()
	if err != nil {
		fail(fmt.Errorf("restore policy: %w", err))
		return
	}
	op.Policy = restored
	op.OwnedMode = op.OriginalMode
	op.OwnedSpecHash = restored.SpecHash
	op.OwnedMetadataHash = restored.MetadataHash
	op.Phase = "restored"
	if err = s.appendExperiment(op); err != nil {
		fail(err)
		return
	}
	rec := armExperiment{Operation: op.Operation, RunAt: s.cfg.now().UTC().Format(time.RFC3339), Namespace: ns, Deploy: deploy, Attack: op.Attack, Arms: arms, Restored: true}
	if len(arms) == 3 {
		rec.ArmAStart, rec.ArmAEnd = arms[0].Start, arms[0].End
		rec.ArmBStart, rec.ArmBEnd = arms[1].Start, arms[1].End
		rec.ArmCStart, rec.ArmCEnd = arms[2].Start, arms[2].End
	}
	b, _ := json.Marshal(rec)
	if err = s.cfg.appendState(armsPath(s.cfg), b); err != nil {
		fail(err)
		return
	}
	op.Phase = "complete"
	if err = s.appendExperiment(op); err != nil {
		fail(err)
		return
	}
	s.setArmsPhase(ns, "done", "complete — correlated results below", 100)
}
