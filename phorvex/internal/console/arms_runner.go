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
 * SAFETY: every exit attempts operation-owned signal cleanup and policy restoration. Conflicts are
 * retained as recovery-required work; restart recovery never replays a stimulus.
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
	target, err := s.resettableTarget(ns)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "comparison preflight: " + err.Error()})
		return
	}
	unresolved := s.unresolvedExperiments()
	// The retained journal is parsed by unresolvedExperiments. A corruption may be
	// discovered after the entry health check above, so recheck before any policy
	// read or mutation and never let the synthetic "corrupt" entry evade the
	// namespace filter below.
	if ok, reason := s.stateStatus(); !ok {
		writeJSON(w, 503, map[string]string{"error": "experiment state unavailable: " + reason})
		return
	}
	for _, e := range unresolved {
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
	deploy := target.Deploy
	job := &armsJob{Namespace: ns, Deploy: deploy, Attack: attack,
		StartedAt: time.Now().UTC().Format(time.RFC3339), Phase: "arm-a",
		Detail: "starting — switching the policy to dryRun", Progress: 1}
	armsJobs[ns] = job
	armsMu.Unlock()

	if policyErr == nil {
		policyErr = supportsResettablePolicy(policyState)
	}
	if policyErr != nil || deploy == "" {
		s.failArms(ns, "comparison preflight failed")
		writeJSON(w, 400, map[string]string{"error": "comparison preflight failed: " + fmt.Sprint(policyErr)})
		return
	}
	op := fmt.Sprintf("exp-%x", s.cfg.now().UnixNano())
	event := experimentEvent{Operation: op, Phase: "prepared", Actor: actorOf(r), Namespace: ns, Attack: attack, Deployment: target.Deploy, DeploymentUID: target.OwnerUID, Policy: policyState, OriginalMode: policyState.Mode, OwnedMode: policyState.Mode, OwnedSpecHash: policyState.SpecHash, OwnedMetadataHash: policyState.MetadataHash}
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
	var receipts []experimentStimulusReceipt
	fail := func(err error) {
		if cleanupErr := s.abortExperiment(&op, receipts); cleanupErr != nil {
			err = fmt.Errorf("%v; cleanup/recovery: %w", err, cleanupErr)
		}
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		live, err := s.experimentCluster().Policy(ctx, ns)
		cancel()
		if err != nil {
			return err
		}
		if live.UID != op.Policy.UID || live.Marker != op.Policy.Marker || live.Mode != op.OwnedMode || live.SpecHash != op.OwnedSpecHash || live.MetadataHash != op.OwnedMetadataHash {
			return fmt.Errorf("policy changed outside this experiment")
		}
		// A status-only controller update may advance resourceVersion. Persist the
		// freshly verified identity/fingerprint and CAS that current version.
		op.Policy = live
		op.OwnedMode = mode
		op.OwnedSpecHash = specHashWithMode(op.Policy, mode)
		op.OwnedMetadataHash = op.Policy.MetadataHash
		op.Phase = "transition-intent"
		if err := s.appendExperiment(op); err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p, err := s.experimentCluster().SetPolicyMode(ctx, live, mode, op.Operation, false)
		if err != nil {
			return err
		}
		if p.UID != live.UID || p.Marker != op.Operation || p.Mode != mode || p.SpecHash != op.OwnedSpecHash || p.MetadataHash != op.OwnedMetadataHash {
			return fmt.Errorf("policy transition acknowledgement mismatched intended state")
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
				if persisted := persistedAttackByID(s.cfg, id); persisted != nil {
					return persisted, nil
				}
			}
			s.cfg.sleep(time.Second)
		}
		return nil, fmt.Errorf("attack observation timeout")
	}
	var arms []armEvidence
	for i, spec := range []struct{ id, label, mode string }{{"nodefense", "No defense", "dryRun"}, {"r6blind", "Blind fixed-interval rotator", "dryRun"}, {"phorvex", "Phorvex", "active"}} {
		if err := transition(spec.mode); err != nil {
			fail(fmt.Errorf("%s mode transition: %w", spec.id, err))
			return
		}
		s.cfg.sleep(2 * time.Second)
		target, err := s.resettableTarget(ns)
		if err != nil {
			fail(fmt.Errorf("%s target preflight: %w", spec.id, err))
			return
		}
		if op.Deployment == "" || op.DeploymentUID == "" || target.Deploy != op.Deployment || target.OwnerUID != op.DeploymentUID {
			fail(fmt.Errorf("%s target preflight: deployment identity changed since experiment preparation", spec.id))
			return
		}
		event := fmt.Sprintf("redteam-arms-%x", s.cfg.now().UnixNano())
		window := s.cfg.AttackWatchDuration
		if window <= 0 {
			window = 95 * time.Second
		}
		windowStart := s.cfg.now()
		windowEnd := windowStart.Add(window)
		a := armEvidence{ID: spec.id, Label: spec.label, Start: windowStart.UTC().Format(time.RFC3339Nano), End: windowEnd.UTC().Format(time.RFC3339Nano), ObservationSeconds: window.Seconds(), TargetPod: target.Pod, TargetUID: target.UID, TargetRV: target.ResourceVersion, TargetOwnerUID: target.OwnerUID, Event: event, SignalKind: "synthetic-detector-signal"}
		op.Arm = &a
		op.Phase = "stimulus-intent"
		if err = s.appendExperiment(op); err != nil {
			fail(err)
			return
		}
		receipts = append(receipts, experimentStimulusReceipt{Pod: target.Pod, PodUID: target.UID, PodRV: target.ResourceVersion, Deploy: target.Deploy, Event: event, Token: op.Operation})
		receipt, err := s.executePreparedResettableSignal(op.Actor, ns, event, target, op.Operation, windowStart, windowEnd, false)
		if receipt.Event != "" {
			receipts[len(receipts)-1] = receipt
		}
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
		a.EventUID = receipt.EventUID
		a.Start = receipt.WindowStart.UTC().Format(time.RFC3339Nano)
		a.End = receipt.WindowEnd.UTC().Format(time.RFC3339Nano)
		op.Arm = &a
		op.Phase = "stimulus-accepted"
		if err = s.appendExperiment(op); err != nil {
			fail(err)
			return
		}
		if spec.id == "r6blind" {
			delay := s.cfg.BlindRotationDelay
			if delay <= 0 {
				delay = 30 * time.Second
			}
			s.cfg.sleep(delay)
			rv := receipt.PodRV
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
			a.Action = obs.ResponseAction
			a.Containment = obs.Containment
			a.DefendedPod = obs.ResponsePod
			a.ResponseSeconds = obs.ResponseSeconds
			a.ResponseObserved = obs.ResponseObserved
			a.DwellOngoing = obs.DwellOngoing
			a.ObservationPersisted = obs.Status == "done"
		}
		if obs != nil && (obs.ID != receipt.AttackID || obs.Pod != receipt.Pod || obs.TargetUID != receipt.PodUID) {
			oerr = fmt.Errorf("persisted observation identity mismatch")
		}
		if oerr != nil && a.Error == "" {
			a.Error = oerr.Error()
		}
		if remaining := receipt.WindowEnd.Sub(s.cfg.now()); remaining > 0 {
			s.cfg.sleep(remaining)
		}
		if err = s.resetExperimentStimulus(receipt); err != nil && a.Error == "" {
			a.Error = err.Error()
		}
		var postErr error
		for j := 0; j < 30; j++ {
			var post resettableTargetInfo
			post, postErr = s.resettableTarget(ns)
			if postErr == nil && post.Deploy == op.Deployment && post.OwnerUID == op.DeploymentUID {
				a.BaselineReady = true
				break
			}
			if postErr == nil {
				postErr = fmt.Errorf("deployment identity changed during reset")
			}
			if j < 29 {
				s.cfg.sleep(time.Second)
			}
		}
		if !a.BaselineReady && a.Error == "" {
			a.Error = "workload identity/readiness not restored after reset"
			if postErr != nil {
				a.Error += ": " + postErr.Error()
			}
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	live, err := s.experimentCluster().Policy(ctx, ns)
	cancel()
	if err != nil || !policyMatchesOwnedState(live, op) {
		if err == nil {
			err = fmt.Errorf("policy changed outside this experiment")
		}
		fail(fmt.Errorf("restore policy: %w", err))
		return
	}
	op.Policy = live
	op.Phase = "restore-intent"
	op.Arm = nil
	if err := s.appendExperiment(op); err != nil {
		fail(err)
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	restored, err := s.experimentCluster().SetPolicyMode(ctx, live, op.OriginalMode, op.Operation, true)
	cancel()
	if err != nil {
		fail(fmt.Errorf("restore policy: %w", err))
		return
	}
	if !restoredPolicyAcknowledged(restored, live, op) {
		fail(fmt.Errorf("restore policy acknowledgement mismatched intended state"))
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

func (s *Server) abortExperiment(op *experimentEvent, receipts []experimentStimulusReceipt) error {
	var problems []string
	for _, r := range receipts {
		if r.Event != "" {
			if err := s.cleanupExperimentSignal(op.Namespace, r); err != nil {
				problems = append(problems, err.Error())
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	live, err := s.experimentCluster().Policy(ctx, op.Namespace)
	restored, noEffect := false, false
	if err == nil && policyMatchesOwnedState(live, *op) {
		op.Phase = "restore-intent"
		if journalErr := s.appendExperiment(*op); journalErr != nil {
			problems = append(problems, "persist restore intention: "+journalErr.Error())
		}
		var acknowledged experimentPolicy
		acknowledged, err = s.experimentCluster().SetPolicyMode(ctx, live, op.OriginalMode, op.Operation, true)
		if err == nil {
			if !restoredPolicyAcknowledged(acknowledged, live, *op) {
				err = fmt.Errorf("policy restore acknowledgement mismatched intended state")
			} else {
				op.Policy = acknowledged
				op.OwnedMode = op.OriginalMode
				op.OwnedSpecHash = acknowledged.SpecHash
				op.OwnedMetadataHash = acknowledged.MetadataHash
				restored = true
			}
		}
	} else if err == nil && policyMatchesRestoredState(live, *op) {
		op.Policy = live
		op.OwnedMode = op.OriginalMode
		op.OwnedSpecHash = live.SpecHash
		op.OwnedMetadataHash = live.MetadataHash
		restored = true
	} else if err == nil && (op.Phase == "prepared" || op.Phase == "transition-intent") && policyMatchesPreparedState(live, *op) && len(receipts) == 0 {
		noEffect = true
	} else if err == nil {
		err = fmt.Errorf("policy recovery ownership conflict")
	}
	if err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		op.Phase = "recovery-required"
		op.Error = strings.Join(problems, "; ")
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	if noEffect {
		op.Phase = "no-effect"
	} else if restored {
		op.Phase = "incomplete-restored"
	} else {
		op.Phase = "recovery-required"
		op.Error = "cleanup did not establish a terminal policy state"
		return fmt.Errorf("%s", op.Error)
	}
	return nil
}
