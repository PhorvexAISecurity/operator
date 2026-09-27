package console

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// reconcileOwnedLoRA is used only for this run's unique staged adapter. A lost
// load acknowledgement is observed through inventory and the inference route;
// it never causes another load. A single unload is allowed only when both show
// the exact run-owned adapter, and its acknowledgement is never blindly retried.
// Durable intents retain identity after a process death, but there is no
// background restart replay: an unfinished cleanup requires operator
// reconciliation rather than an automatic second serving mutation.
func (s *Server) reconcileOwnedLoRA(pod, podUID, name string) error {
	if !validRunOwnedLoRA(name) || podUID == "" {
		return fmt.Errorf("run-owned LoRA cleanup identity unavailable")
	}
	if err := s.verifyZeroLoRA(pod, podUID, name); err != nil {
		return fmt.Errorf("owned adapter artifact authority: %w", err)
	}
	execIn := func(sh string) (string, error) {
		before, err := s.readVLLMPod(pod)
		if err != nil || before.Metadata.UID != podUID {
			return "", fmt.Errorf("target Pod UID changed before LoRA cleanup request")
		}
		out, err := s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", pod, "-c", "vllm", "--", "sh", "-c", sh)
		after, afterErr := s.readVLLMPod(pod)
		if afterErr != nil || after.Metadata.UID != podUID {
			return "", fmt.Errorf("target Pod UID changed across LoRA cleanup request")
		}
		return out, err
	}
	models, err := readVLLMModels(execIn)
	if err != nil {
		return fmt.Errorf("owned adapter cleanup inventory unavailable: %w", err)
	}
	basePresent, adapterPresent := false, false
	for _, model := range models {
		basePresent = basePresent || model == liveLoRABaseModel
		adapterPresent = adapterPresent || model == name
	}
	if !basePresent {
		return fmt.Errorf("base-model continuity unavailable before owned adapter cleanup")
	}
	if adapterPresent {
		if err := probeLoRARoute(execIn, name, true); err != nil {
			return fmt.Errorf("owned adapter route and inventory disagree before cleanup: %w", err)
		}
		if err := probeLoRARoute(execIn, liveLoRABaseModel, true); err != nil {
			return fmt.Errorf("base-model route unavailable before owned adapter cleanup: %w", err)
		}
		intent, _ := json.Marshal(map[string]string{"kind": "phorvex.console.vllm.lora-fixture", "phase": "unload-intent", "time": s.cfg.now().UTC().Format(time.RFC3339Nano), "namespace": vllmAttackNS, "pod": pod, "podUid": podUID, "adapter": name})
		if err := s.cfg.appendState(s.cfg.statePath("effect-intents.jsonl"), intent); err != nil {
			return fmt.Errorf("durable owned adapter unload intent: %w", err)
		}
		payload, _ := json.Marshal(map[string]string{"lora_name": name})
		response, unloadErr := vllmWorkloadHTTP(execIn, http.MethodPost, "/v1/unload_lora_adapter", string(payload))
		// Even a timeout can follow an accepted POST. Observe once; never resend.
		if unloadErr == nil && (response.Status < 200 || response.Status >= 300) {
			unloadErr = fmt.Errorf("owned adapter unload returned HTTP %d", response.Status)
		}
		for attempt := 0; attempt < 5; attempt++ {
			models, err = readVLLMModels(execIn)
			if err == nil {
				adapterPresent, basePresent = false, false
				for _, model := range models {
					adapterPresent = adapterPresent || model == name
					basePresent = basePresent || model == liveLoRABaseModel
				}
				if basePresent && !adapterPresent {
					break
				}
			}
			if attempt < 4 {
				s.cfg.sleep(250 * time.Millisecond)
			}
		}
		if err != nil || !basePresent || adapterPresent {
			return fmt.Errorf("owned adapter unload effect remains unresolved; acknowledgement: %v", unloadErr)
		}
	}
	if err := probeLoRARoute(execIn, name, false); err != nil {
		return fmt.Errorf("owned adapter absence route unconfirmed: %w", err)
	}
	if err := probeLoRARoute(execIn, liveLoRABaseModel, true); err != nil {
		return fmt.Errorf("base-model continuity after owned adapter cleanup: %w", err)
	}
	if err := s.removeZeroLoRA(pod, podUID, name); err != nil {
		return fmt.Errorf("owned adapter artifact cleanup: %w", err)
	}
	return nil
}

// A lost create acknowledgement is resolved by one exact cluster-scoped read.
// An empty successful read proves absence for this reconciliation moment; any
// read error or mismatched object remains unknown and forbids automatic unload.
func (s *Server) reconcileAdapterEventCreate(candidate *attackStimulusEvidence, pod, podUID, adapter string) (*attackStimulusEvidence, bool, error) {
	if candidate == nil || candidate.EventName == "" || candidate.Correlation == "" || candidate.TargetUID != podUID || !validRunOwnedLoRA(adapter) {
		return nil, false, fmt.Errorf("adapter event candidate identity unavailable")
	}
	out, err := s.cfg.execText(8*time.Second, "kubectl", "get", "securityevent", candidate.EventName, "-o", "json", "--ignore-not-found")
	if err != nil || len(out) > vllmHTTPMaxBytes {
		return nil, false, fmt.Errorf("adapter event reconciliation read unavailable")
	}
	if strings.TrimSpace(out) == "" {
		return nil, false, nil
	}
	var event vllmSecurityEvent
	if err := decodeOneJSON([]byte(out), &event); err != nil || event.Metadata.Name != candidate.EventName || event.Metadata.Namespace != "" || event.Metadata.UID == "" || event.Metadata.CreationTimestamp == "" ||
		event.Metadata.Labels["phorvex.ai/attack-correlation"] != candidate.Correlation || event.Metadata.Labels["phorvex.ai/console-vllm"] != "true" ||
		event.Metadata.Annotations["phorvex.ai/adapter-name"] != adapter || event.Metadata.Annotations["phorvex.ai/target-pod-uid"] != podUID ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != vllmAttackNS+"/"+pod || event.Spec.Rule.Type != candidate.EventRule || event.Spec.Rule.Source != "redteam" {
		return nil, false, fmt.Errorf("adapter event reconciliation identity changed")
	}
	copy := *candidate
	copy.Observed, copy.EventUID, copy.EventCreatedAt = true, event.Metadata.UID, event.Metadata.CreationTimestamp
	return &copy, true, nil
}

// A native adapter-rotate success is published only after its protected journal
// reaches completed and the exact Pod completion epoch has been read back. Audit
// fields from a partial or a different selected decision are never a verdict.
func ownedLoRATerminalDecision(r *attackRecord) *decisionEvidence {
	if r == nil || r.vllmEffect == nil || r.StimulusEvidence == nil || !r.StimulusEvidence.Observed ||
		r.StimulusEvidence.EventUID == "" || r.TargetUID == "" {
		return nil
	}
	for i := range r.DecisionTraceEvidence {
		d := &r.DecisionTraceEvidence[i]
		if d.Correlation != "exact-event-uid" || d.Source != "decision-trace-steered-event" ||
			d.EventUID != r.StimulusEvidence.EventUID || d.EventName != r.StimulusEvidence.EventName ||
			d.EventRule != r.StimulusEvidence.EventRule ||
			d.TargetUID != r.TargetUID || d.TrustVerdict != "trusted" ||
			d.PolicyNamespace != r.Namespace || d.PolicyName == "" || d.PolicyUID == "" ||
			d.TickID == "" || d.DecisionID == "" || d.Action != "adapter-rotate" ||
			!d.Selected || !d.Feasible || !d.Actuated || d.DryRun || d.KillSwitch ||
			d.DispatchOutcome != "emitted" || d.Handler != "adapter-rotate" || d.MutationKind != "forward-only" {
			continue
		}
		sum := sha256.Sum256([]byte("adapter-rotate/" + d.PolicyUID + "/" + r.TargetUID))
		name := fmt.Sprintf("phorvex-operation-%x", sum[:20])
		prefix := "phorvex-system/" + name + "@"
		uid := strings.TrimPrefix(d.RollbackRef, prefix)
		if !strings.HasPrefix(d.RollbackRef, prefix) || !staticUID.MatchString(uid) || len(d.ObjectsTouched) != 2 ||
			d.ObjectsTouched[0] != "ConfigMap/phorvex-system/"+name ||
			d.ObjectsTouched[1] != "Pod/"+r.Namespace+"/"+r.Pod {
			continue
		}
		return d
	}
	return nil
}

func (s *Server) observeOwnedLoRAOutcome(ctxName string, r *attackRecord, deadline time.Time) {
	if r.loRATerminalPersistFailed || r.loRATerminalPersisted {
		return
	}
	if r.EffectEvidence == nil {
		effect, err := s.observeVLLMInPlaceEffect(r)
		if err != nil {
			r.ObservationError = "adapter capability observation: " + err.Error()
			return
		}
		if effect == nil || !s.cfg.now().Before(deadline) {
			return
		}
		effect.Seconds = round2(s.cfg.now().Sub(r.started).Seconds())
		r.EffectEvidence = effect
	}
	// The audit may lag the serving readback. Keep the verified observation while
	// waiting for the exact selected terminal decision, then recheck the live route.
	s.fillReasoning(ctxName, r)
	d := ownedLoRATerminalDecision(r)
	if d == nil {
		r.ObservationError = "exact selected native adapter terminal decision is unavailable"
		return
	}
	effect, err := s.observeVLLMInPlaceEffect(r)
	if err != nil || effect == nil || !s.cfg.now().Before(deadline) {
		r.ObservationError = "adapter capability terminal readback is unresolved"
		return
	}
	if err := s.removeZeroLoRA(r.Pod, r.TargetUID, r.vllmEffect.adapterName); err != nil {
		r.ObservationError = "run-owned adapter artifact cleanup: " + err.Error()
		return
	}
	r.EffectEvidence = effect
	r.DecisionEvidence = d
	r.Outcome, r.OutcomeClass, r.Action, r.DefendedPod, r.Actuated = "DEFENDED", "unapproved-adapter-capability-removed", "adapter-rotate", r.Pod, true
	r.TimeToDefendSec = round2(s.cfg.now().Sub(r.started).Seconds())
	r.LoRACleanupStatus, r.LoRACleanupError = "completed", ""
	r.ObservationError = ""
	r.Status = "done"
	if err := s.persistAttack(r); err != nil {
		r.loRATerminalPersistFailed = true
		r.Outcome, r.Action, r.DefendedPod, r.Actuated, r.TimeToDefendSec = "", "", "", false, 0
		r.OutcomeClass = "unapproved-adapter-capability-unresolved"
		r.ObservationError = "terminal defense evidence was not durable"
		r.PersistenceError = "owned adapter removal was observed but terminal evidence persistence failed; unsafe to retry: " + err.Error()
		r.Status = "partial"
		s.recordStateError(fmt.Errorf("persist owned LoRA terminal: %w", err))
		return
	}
	r.loRATerminalPersisted = true
}

func (s *Server) finishOwnedLoRAOutcome(ctxName string, r *attackRecord) {
	// A remaining route is a narrow attacker capability outcome, independent of
	// whether the manager selected another action. A 404, malformed response or
	// unavailable control is unresolved rather than proof of mitigation.
	if r.Outcome == "" && !r.loRATerminalPersistFailed && r.vllmEffect != nil && r.StimulusEvidence != nil && r.StimulusEvidence.Observed && validRunOwnedLoRA(r.vllmEffect.adapterName) {
		before, err := s.readVLLMPod(r.Pod)
		if err == nil && before.Metadata.UID == r.TargetUID {
			err = s.validateVLLMEvent(r)
		}
		if err == nil && before.Metadata.UID == r.TargetUID {
			execIn := func(sh string) (string, error) {
				return s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", r.Pod, "-c", "vllm", "--", "sh", "-c", sh)
			}
			err = probeLoRARoute(execIn, r.vllmEffect.adapterName, true)
			if err == nil {
				err = probeLoRARoute(execIn, liveLoRABaseModel, true)
			}
			if err == nil {
				var after vllmPodState
				after, err = s.readVLLMPod(r.Pod)
				if err == nil && after.Metadata.UID != r.TargetUID {
					err = fmt.Errorf("target Pod UID changed across route readback")
				}
			}
		}
		if err == nil && before.Metadata.UID == r.TargetUID {
			r.Outcome, r.OutcomeClass, r.Action, r.Actuated = "LANDED", "unapproved-adapter-route-available", "noop", false
			r.ObservationError = ""
			r.LoRACleanupStatus = "pending"
			r.Status = "done"
			// Preserve the historical available-route verdict before cleanup removes
			// this run's adapter. Cleanup cannot retroactively become brain defense.
			if persistErr := s.persistAttack(r); persistErr != nil {
				r.Outcome, r.Action, r.LoRACleanupStatus = "", "", ""
				r.OutcomeClass = "unapproved-adapter-capability-unresolved"
				r.ObservationError = "landed adapter evidence was not durable; cleanup refused"
				r.PersistenceError = "LoRA landed evidence persistence failed; unsafe to retry: " + persistErr.Error()
				r.Status = "partial"
				r.loRATerminalPersistFailed = true
				s.recordStateError(fmt.Errorf("persist owned LoRA landed outcome: %w", persistErr))
			} else {
				r.loRATerminalPersisted = true
				if cleanupErr := s.reconcileOwnedLoRA(r.Pod, r.TargetUID, r.vllmEffect.adapterName); cleanupErr != nil {
					r.LoRACleanupStatus, r.LoRACleanupError = "unknown", cleanupErr.Error()
					r.Status = "partial"
				} else {
					r.LoRACleanupStatus, r.LoRACleanupError = "completed", ""
				}
				if persistErr := s.persistAttack(r); persistErr != nil {
					r.LoRACleanupStatus, r.LoRACleanupError = "pending", "cleanup disposition was not durable"
					r.Status = "partial"
					r.PersistenceError = "LoRA cleanup disposition persistence failed; historical LANDED retained: " + persistErr.Error()
					s.recordStateError(fmt.Errorf("persist owned LoRA cleanup: %w", persistErr))
				}
			}
		}
	}
	if r.Outcome == "" {
		r.OutcomeClass = "unapproved-adapter-capability-unresolved"
		if r.ObservationError == "" {
			r.ObservationError = "adapter capability remained unresolved within the observation window"
		}
	}
	r.Containment, r.DwellSec, r.DwellOngoing = "", 0, false
	if r.DecisionEvidence == nil {
		s.fillReasoning(ctxName, r)
	}
}
