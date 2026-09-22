/*
 * Phorvex Console — dashboard-triggered vLLM observations.
 *
 * POST /api/vllm/attack {action} runs one bounded serving-stack producer and, when that producer is
 * verified, creates an exact correlated SecurityEvent. The endpoint reports only what it observes:
 * a target-bound mechanism effect, a response-only signal, or an unsupported behavioral verdict.
 * It does not infer attacker success or mitigation from temporal Pod/epoch changes.
 *
 * The console reaches the serving stack through a bounded kubectl exec because it cannot reach Pod
 * addresses directly. Every producer and stimulus is bracketed by the exact Pod UID. The legacy reset
 * path remains a separately tracked restoration boundary and is not evidence for these observations.
 */

package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const vllmAttackNS = "vllm"

// Scenarios NEVER rewrite vllm-defense. They used to merge-patch actions.enabled down to
// [rotate, <the one expected actuator>] (+ reactiveOnly) before firing, and "reset" shrank it
// to a two-action hygiene baseline — which made every demo's outcome a property of the patch,
// not of the brain, and left the tenant's policy in whatever shape the last click chose. The
// policy is the operator's contract; which actuator answers an attack is the brain's call.
// A scenario only plants the condition and fires a SecurityEvent whose rule type names the
// attack VECTOR (model.AttackVectorFor*), the same contract workload_attack.go uses.

// vllmRuleType maps a scenario's event name to the attack vector the brain steers on, so the
// fired event lands as belief about WHICH surface was hit rather than as an opaque name.
func vllmRuleType(evType string) string {
	switch evType {
	case "KVPoisoning", "KVCacheOccupancy":
		return model.AttackVectorKV
	case "GuardrailBypass":
		return model.AttackVectorGuardrail
	case "DenialOfWallet":
		return model.AttackVectorInflight
	case "AdapterPoisoning":
		return model.AttackVectorAdapter
	}
	return evType
}

func (s *Server) writeVLLMSetupFailure(w http.ResponseWriter, r *http.Request, action, phase, targetUID, serviceUID string, candidate *attackStimulusEvidence, mutated bool, restoration string, cause error) {
	if restoration == "" {
		if mutated {
			restoration = "required"
		} else {
			restoration = "not-needed"
		}
	}
	if err := s.persistVLLMSetupFailure(actorOf(r), action, phase, targetUID, serviceUID, candidate, mutated, restoration, cause); err != nil {
		writeJSON(w, 503, map[string]string{"error": cause.Error() + "; failure evidence persistence failed: " + err.Error(), "verdict": "unsafe-to-retry"})
		return
	}
	writeJSON(w, 502, map[string]any{"error": cause.Error(), "verdict": phase + "-failed", "targetUid": targetUID, "serviceUid": serviceUID, "restoration": restoration})
}

func (s *Server) refuseVLLMReset(w http.ResponseWriter, r *http.Request, targetUID string) {
	const restoration = "not-attempted: durable per-run original/staged restoration authority is unavailable; reconciliation required"
	cause := fmt.Errorf("reset refused: exact original runtime, Pod metadata and Service selector authority is unavailable")
	if err := s.persistEffectIntent("/api/vllm/attack", actorOf(r), vllmAttackNS, "reset"); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": cause.Error() + "; refusal evidence persistence failed: " + err.Error(), "verdict": "unsafe-to-retry"})
		return
	}
	if err := s.persistVLLMSetupFailure(actorOf(r), "reset", "authority", targetUID, "", nil, false, restoration, cause); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": cause.Error() + "; refusal evidence persistence failed: " + err.Error(), "verdict": "unsafe-to-retry"})
		return
	}
	writeJSON(w, http.StatusConflict, map[string]any{
		"ok":             false,
		"action":         "reset",
		"error":          cause.Error(),
		"verdict":        "unsupported-restoration-authority",
		"targetUid":      targetUID,
		"restoration":    restoration,
		"reconciliation": "inspect the exact retained run/effect evidence and reconcile owned state explicitly",
	})
}

func (s *Server) vllmAttack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Action) == "" {
		writeJSON(w, 400, map[string]string{"error": "a valid action is required"})
		return
	}

	pod, err := s.cfg.execText(8*time.Second, "kubectl", "-n", vllmAttackNS, "get", "pod", "-l", "app=vllm", "-o", "jsonpath={.items[0].metadata.name}")
	pod = strings.TrimSpace(pod)
	if err != nil || pod == "" {
		writeJSON(w, 503, map[string]string{"error": "vLLM pod not found (is the vllm demo up?): " + strings.TrimSpace(pod)})
		return
	}
	execIn := func(sh string) (string, error) {
		return s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", pod, "--", "sh", "-c", sh)
	}

	target, err := s.readVLLMPod(pod)
	if err != nil || target.Metadata.UID == "" {
		writeJSON(w, 503, map[string]string{"error": "vLLM target identity is unavailable"})
		return
	}
	targetUID := target.Metadata.UID
	if body.Action == "reset" {
		s.refuseVLLMReset(w, r, targetUID)
		return
	}
	// Snapshot the baseline before any producer or detector stimulus. The exact UID comes from
	// the strict Pod JSON read above; the legacy convenience probes supply only optional context.
	base := s.snapshotBaseline(vllmAttackNS, pod)
	base.uid = targetUID
	base.epoch = stringMapValue(target.Metadata.Annotations, "phorvex.ai/adapter-epoch")
	base.kvEpoch = stringMapValue(target.Metadata.Annotations, "phorvex.ai/kv-reset-epoch")
	runBoundedProducer := func(producer func() error) (bool, error) {
		before, readErr := s.readVLLMPod(pod)
		if readErr != nil || before.Metadata.UID != targetUID {
			return false, fmt.Errorf("target Pod identity changed before producer")
		}
		err := producer()
		after, afterErr := s.readVLLMPod(pod)
		if afterErr != nil || after.Metadata.UID != targetUID {
			if err != nil {
				return true, fmt.Errorf("%w; target Pod identity changed across producer", err)
			}
			return true, fmt.Errorf("target Pod identity changed across producer")
		}
		return true, err
	}
	createStimulus := func(evType, description, anomaly, adapter string) (*attackStimulusEvidence, error) {
		before, readErr := s.readVLLMPod(pod)
		if readErr != nil || before.Metadata.UID != targetUID {
			return nil, fmt.Errorf("target Pod identity changed before detector stimulus")
		}
		stimulus, createErr := s.createCorrelatedVLLMEventWithAdapter(pod, targetUID, evType, description, anomaly, adapter)
		after, afterErr := s.readVLLMPod(pod)
		if afterErr != nil || after.Metadata.UID != targetUID {
			if createErr != nil {
				return stimulus, fmt.Errorf("%w; target Pod identity changed across detector stimulus", createErr)
			}
			return stimulus, fmt.Errorf("target Pod identity changed across detector stimulus")
		}
		return stimulus, createErr
	}
	setupFailure := func(action, phase string, candidate *attackStimulusEvidence, possibleEffect bool, cause error) {
		restoration := "not-needed"
		if possibleEffect {
			restoration = "unavailable: exact attempted effect identity retained; reconciliation required"
		}
		s.writeVLLMSetupFailure(w, r, action, phase, targetUID, "", candidate, possibleEffect, restoration, cause)
	}
	startEffect := func(attack, action, evidenceLabel, expected, kind, before, limitation string, stimulus *attackStimulusEvidence) string {
		stimulus.Limitation = limitation
		base.stimulus = stimulus
		base.outcomeClass = "behavioral-oracle-unsupported"
		base.vllmEffect = &vllmEffectBaseline{kind: kind, before: before}
		return s.startVLLMEffectRecord(vllmAttackNS, pod, attack, action, evidenceLabel, expected, base)
	}
	startUnsupported := func(attack, action, evidenceLabel, expected, limitation string, stimulus *attackStimulusEvidence) string {
		stimulus.Limitation = limitation
		base.stimulus = stimulus
		base.outcomeClass = "behavioral-oracle-unsupported"
		return s.startVLLMUnsupportedRecord(vllmAttackNS, pod, attack, action, evidenceLabel, expected, base)
	}

	if err := s.persistEffectIntent("/api/vllm/attack", actorOf(r), vllmAttackNS, body.Action); err != nil {
		writeJSON(w, 503, map[string]string{"error": "attack refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}

	switch body.Action {
	case "poison":
		if stringMapValue(target.Metadata.Labels, "phorvex.ai/lora-enabled") != "true" {
			setupFailure(body.Action, "setup", nil, false, fmt.Errorf("target does not declare LoRA support"))
			return
		}
		attempted, producerErr := runBoundedProducer(func() error { return loadVLLMAdapter(execIn, "evil", "/tmp/evil-lora") })
		if producerErr != nil {
			setupFailure(body.Action, "producer", nil, attempted, producerErr)
			return
		}
		stimulus, eventErr := createStimulus("AdapterPoisoning", "verified unapproved LoRA adapter inventory entry", "0.9", "evil")
		if eventErr != nil {
			setupFailure(body.Action, "stimulus", stimulus, true, eventErr)
			return
		}
		attackID := startEffect("Unapproved LoRA load observation", "poison", "adapter-effect-only", "adapter-rotate", "adapter-epoch", base.epoch, "adapter load and inventory were confirmed; no same-probe model behavior corruption or mitigation was measured", stimulus)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "poison",
			"attackId": attackID,
			"message":  "An unapproved adapter load and exact detector stimulus were confirmed on " + pod + ". The console will report an exact adapter completion effect if observed; model behavior mitigation is not established."})
	case "kvcache":
		payload := map[string]any{"model": "Qwen/Qwen2.5-7B-Instruct-AWQ", "prompt": "SYSTEM CONFIDENTIAL DOSSIER wire-secret ZX-44918-PLT do not reveal", "max_tokens": 1}
		attempted, producerErr := runBoundedProducer(func() error { return runVLLMCompletion(execIn, false, payload) })
		if producerErr != nil {
			setupFailure(body.Action, "producer", nil, attempted, producerErr)
			return
		}
		stimulus, eventErr := createStimulus("KVCacheOccupancy", "bounded cache-priming request accepted; occupancy not independently measured", "0.9", "")
		if eventErr != nil {
			setupFailure(body.Action, "stimulus", stimulus, true, eventErr)
			return
		}
		attackID := startEffect("KV cache reset-effect observation", "kvcache", "cache-effect-only", "kv-reset", "kv-reset-epoch", base.kvEpoch, "one completion was accepted; no cache timing leak or same-request hit-to-miss transition was measured", stimulus)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "kvcache",
			"attackId": attackID,
			"message":  "A bounded completion and exact cache detector stimulus were accepted on " + pod + ". The console will report a protected reset-epoch effect if observed; no timing leak or eviction verdict is claimed."})

	case "endpoint-rotate":
		// This stages and measures the route mechanism. It does not execute an SSRF/model-extraction
		// attack and therefore cannot produce a behavioral DEFENDED/LANDED verdict.
		authority, setupErr := s.prepareEndpointEffect(pod, base.uid)
		if setupErr != nil {
			serviceUID, restoration, mutated := "", "not-needed", false
			if authority != nil {
				serviceUID, restoration = authority.serviceUID, authority.restoration
				mutated = authority.podStaged || authority.serviceStaged
			}
			s.writeVLLMSetupFailure(w, r, body.Action, "setup", base.uid, serviceUID, nil, mutated, restoration, setupErr)
			return
		}
		stimulus, eventErr := s.createCorrelatedVLLMEvent(pod, base.uid, "EndpointPinning", "synthetic endpoint-route signal for an in-place route-effect observation", "0.95")
		if eventErr != nil {
			restoreErr := s.restoreEndpointSetup(authority)
			message := eventErr.Error()
			restoration := "restored"
			if restoreErr != nil {
				message += "; exact endpoint setup restoration required: " + restoreErr.Error()
				restoration = "required: " + restoreErr.Error()
			} else {
				message += "; endpoint setup restored"
			}
			s.writeVLLMSetupFailure(w, r, body.Action, "stimulus", base.uid, authority.serviceUID, stimulus, true, restoration, fmt.Errorf("%s", message))
			return
		}
		stimulus.Limitation = "synthetic route signal; no SSRF, model-extraction, locator-revocation or session-revocation attack was executed"
		base.stimulus = stimulus
		base.vllmEffect = &vllmEffectBaseline{kind: "endpoint-route-state", before: "ep-old", serviceUID: authority.serviceUID}
		base.outcomeClass = "behavioral-oracle-unsupported"
		attackID := s.startVLLMEffectRecord(vllmAttackNS, pod, "Endpoint route-effect observation", "endpoint-rotate", "route-effect-only", "endpoint-rotate", base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "endpoint-rotate",
			"attackId": attackID,
			"message":  "Endpoint route setup and a unique detector signal were accepted for " + pod + ". The console will report an exact route-key/Service/EndpointSlice effect if observed; this does not establish SSRF or model-extraction mitigation."})

	case "guardrail-rotate":
		// The currently calibrated harmless probes do not distinguish pgv1 from pgv2. Configure an
		// exact runtime stimulus variant and measure only a fresh state transition; do not manufacture
		// a jailbreak or mitigation verdict from that mechanism-level observation.
		authority, setupErr := s.prepareGuardrailEffect(pod, base.uid, execIn)
		if setupErr != nil {
			restoration, mutated := "not-needed", false
			if authority != nil {
				restoration = authority.restoration
				mutated = authority.runtimeAttempted || authority.metadataStaged
				if mutated && restoration == "" {
					if restoreErr := s.restoreGuardrailEffect(authority, execIn); restoreErr != nil {
						restoration = "required: " + restoreErr.Error()
						setupErr = fmt.Errorf("%w; exact guardrail restoration required: %v", setupErr, restoreErr)
					} else {
						restoration = "restored"
					}
				}
			}
			s.writeVLLMSetupFailure(w, r, body.Action, "setup", base.uid, "", nil, mutated, restoration, setupErr)
			return
		}
		stimulus, eventErr := s.createCorrelatedVLLMEvent(pod, base.uid, "GuardrailBypass", "synthetic guardrail signal for an in-place runtime-state observation", "0.95")
		if eventErr != nil {
			restoreErr := s.restoreGuardrailEffect(authority, execIn)
			message := eventErr.Error()
			restoration := "restored"
			if restoreErr != nil {
				message += "; exact guardrail runtime restoration required: " + restoreErr.Error()
				restoration = "required: " + restoreErr.Error()
			} else {
				message += "; guardrail runtime restored"
			}
			s.writeVLLMSetupFailure(w, r, body.Action, "stimulus", base.uid, "", stimulus, true, restoration, fmt.Errorf("%s", message))
			return
		}
		stimulus.Limitation = "synthetic guardrail signal; no preregistered pgv1-pass to pgv2-block behavioral probe was available"
		base.stimulus = stimulus
		base.vllmEffect = &vllmEffectBaseline{kind: "guardrail-runtime-state", before: "pgv1"}
		base.outcomeClass = "behavioral-oracle-unsupported"
		attackID := s.startVLLMEffectRecord(vllmAttackNS, pod, "Guardrail runtime-effect observation", "guardrail-rotate", "filter-effect-only", "guardrail-rotate", base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "guardrail-rotate",
			"attackId": attackID,
			"message":  "Guardrail runtime pgv1 and a unique detector signal were confirmed on " + pod + ". The console will report a fresh runtime variant effect if observed; no jailbreak bypass or mitigation verdict is claimed."})

	case "request-drain":
		_, producerErr := runBoundedProducer(func() error { _, err := readVLLMModels(execIn); return err })
		if producerErr != nil {
			setupFailure(body.Action, "readiness", nil, false, producerErr)
			return
		}
		stimulus, eventErr := createStimulus("DenialOfWallet", "synthetic request-drain detector signal; no untracked background requests launched", "0.9", "")
		if eventErr != nil {
			setupFailure(body.Action, "stimulus", stimulus, true, eventErr)
			return
		}
		attackID := startUnsupported("Request-drain response observation", "request-drain", "response-only", "request-drain", "synthetic detector signal; no request admission, aborted-count, reopen, or benign continuity oracle is available in this console flow", stimulus)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "request-drain",
			"attackId": attackID,
			"message":  "An exact synthetic request-drain signal was accepted for " + pod + ". No background flood was launched and no request-abort or mitigation verdict is available."})

	case "kv-migrate-invalidate":
		prefix := "ZQX-DEMO stable system context block for the disaggregated serving rig padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding"
		payload := map[string]any{"model": "Qwen/Qwen2.5-7B-Instruct-AWQ", "messages": []map[string]string{{"role": "user", "content": prefix + " reply with OK"}}, "max_tokens": 4}
		attempted, producerErr := runBoundedProducer(func() error {
			if err := runVLLMCompletion(execIn, true, payload); err != nil {
				return err
			}
			return runVLLMCompletion(execIn, true, payload)
		})
		if producerErr != nil {
			setupFailure(body.Action, "producer", nil, attempted, producerErr)
			return
		}
		stimulus, eventErr := createStimulus("KVPoisoning", "two identical bounded prefix requests accepted; cache hit and peer migration not independently measured", "0.9", "")
		if eventErr != nil {
			setupFailure(body.Action, "stimulus", stimulus, true, eventErr)
			return
		}
		beforeKV := stringMapValue(target.Metadata.Annotations, "phorvex.ai/kv-migrate-epoch") + "|" + stringMapValue(target.Metadata.Annotations, "phorvex.ai/kv-local-effect-epoch")
		attackID := startEffect("KV migration-effect observation", "kv-migrate-invalidate", "kv-effect-only", "kv-migrate-invalidate", "kv-migrate-epoch", beforeKV, "two identical completions were accepted; no cache-hit, peer-transfer, or same-request cold-after observation was measured", stimulus)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "kv-migrate-invalidate",
			"attackId": attackID,
			"message":  "Two bounded prefix requests and an exact detector stimulus were accepted on " + pod + ". The console will report protected local/remote completion metadata if observed; cache eviction is not established."})

	case "warm-swap":
		_, producerErr := runBoundedProducer(func() error { _, err := readVLLMModels(execIn); return err })
		if producerErr != nil {
			setupFailure(body.Action, "readiness", nil, false, producerErr)
			return
		}
		stimulus, eventErr := createStimulus("GPUEviction", "synthetic warm-swap detector signal; no co-tenant pressure or untracked request launched", "0.9", "")
		if eventErr != nil {
			setupFailure(body.Action, "stimulus", stimulus, true, eventErr)
			return
		}
		attackID := startUnsupported("Warm-swap response observation", "warm-swap", "response-only", "warm-swap", "synthetic detector signal; no GPU pressure, admitted old request, warm-leader/Service transition, or continuity oracle is available in this console flow", stimulus)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "warm-swap",
			"attackId": attackID,
			"message":  "An exact synthetic warm-swap signal was accepted for " + pod + ". No GPU pressure, request continuity, warm promotion, or mitigation verdict is claimed."})

	case "model-shard-replace":
		_, producerErr := runBoundedProducer(func() error { _, err := readVLLMModels(execIn); return err })
		if producerErr != nil {
			setupFailure(body.Action, "readiness", nil, false, producerErr)
			return
		}
		stimulus, eventErr := createStimulus("ModelTampering", "synthetic model-shard detector signal; no model bytes or behavior were modified", "0.9", "")
		if eventErr != nil {
			setupFailure(body.Action, "stimulus", stimulus, true, eventErr)
			return
		}
		attackID := startUnsupported("Model-shard response observation", "model-shard-replace", "response-only", "model-shard-replace", "synthetic detector signal; no model tamper, known-good shard proof, cutover identity, or behavior oracle is available in this console flow", stimulus)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "model-shard-replace",
			"attackId": attackID,
			"message":  "An exact synthetic model-shard signal was accepted for " + pod + ". No model tamper, known-good replacement, or mitigation verdict is claimed."})

	default:
		writeJSON(w, 400, map[string]string{"error": "unknown action (poison|kvcache|endpoint-rotate|guardrail-rotate|request-drain|kv-migrate-invalidate|warm-swap|model-shard-replace|reset)"})
	}
}
