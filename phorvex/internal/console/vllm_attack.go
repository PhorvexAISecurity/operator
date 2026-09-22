/*
 * Phorvex Console — DASHBOARD-TRIGGERED live vLLM attacks.
 *
 * POST /api/vllm/attack {action} launches a REAL attack on the live vLLM so the operator's actuator
 * SELECTION is visible right below in Live Theatre — no CLI. The console can't reach pod IPs, so it
 * shells kubectl: exec into the pod for the serving-stack call, label/annotate for a detector flag,
 * and temp-file + `apply` for a SecurityEvent (execText has no stdin — same path as workload_attack.go).
 *
 * poison (adapter-rotate) and kvcache (kv-reset) fire PROACTIVELY under the baseline policy. The
 * served-model actuators below each SCOPE the policy to [rotate, X] + reactiveOnly and fire a matching
 * SecurityEvent, so X is the sole feasible candidate and the pick is attributable to the click. "reset"
 * clears everything and restores the baseline. The demo fixtures (guardrail sidecar + warm-pool stand-in
 * on the vllm pod/ns) must be standing — see build/test-harness/guardrail/*-deploy.sh. warm-swap and
 * model-shard-replace are DESTRUCTIVE (they retire the leader; the Deployment recreates it in minutes).
 */

package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

// fireVllmEvent applies a Phoenix SecurityEvent CR (the detector stand-in) targeting the pod, so the
// workload becomes actionable and the reactive pick is attributable. Labeled phorvex.ai/redteam=true so
// "reset" can delete it. Mirrors workload_attack.go (execText has no stdin -> temp file + apply).
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

func (s *Server) fireVllmEvent(pod, evType, desc, anomaly string) error {
	yaml := fmt.Sprintf(`apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: redteam-vllm-%s
  namespace: %s
  labels:
    phorvex.ai/redteam: "true"
spec:
  description: %q
  targets: ["%s/%s"]
  rule:
    type: %q
    threatLevel: "critical"
    source: "redteam"
  anomalyScore: %q
`, strings.ToLower(evType), vllmAttackNS, desc, vllmAttackNS, pod, vllmRuleType(evType), anomaly)
	f, ferr := os.CreateTemp("", "phorvex-vllm-se-*.yaml")
	if ferr != nil {
		return ferr
	}
	defer os.Remove(f.Name())
	if _, ferr = f.WriteString(yaml); ferr == nil {
		ferr = f.Sync()
	}
	if cerr := f.Close(); ferr == nil {
		ferr = cerr
	}
	if ferr != nil {
		return fmt.Errorf("write SecurityEvent manifest: %w", ferr)
	}
	if out, e := s.cfg.execText(10*time.Second, "kubectl", "-n", vllmAttackNS, "apply", "-f", f.Name()); e != nil {
		return fmt.Errorf("apply SecurityEvent: %s", strings.TrimSpace(out))
	}
	return nil
}

func (s *Server) vllmAttack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	pod, err := s.cfg.execText(8*time.Second, "kubectl", "-n", vllmAttackNS, "get", "pod", "-l", "app=vllm", "-o", "jsonpath={.items[0].metadata.name}")
	pod = strings.TrimSpace(pod)
	if err != nil || pod == "" {
		writeJSON(w, 503, map[string]string{"error": "vLLM pod not found (is the vllm demo up?): " + strings.TrimSpace(pod)})
		return
	}
	execIn := func(sh string) (string, error) {
		return s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", pod, "--", "sh", "-c", sh)
	}
	kctl := func(args ...string) {
		_, _ = s.cfg.execText(8*time.Second, "kubectl", append([]string{"-n", vllmAttackNS}, args...)...)
	}

	// snapshot the defense baseline BEFORE the attack lands (esp. the adapter epoch for poison) so a
	// fast operator reaction is correctly attributed and not absorbed into the baseline.
	base := s.snapshotBaseline(vllmAttackNS, pod)
	if err := s.persistEffectIntent("/api/vllm/attack", actorOf(r), vllmAttackNS, body.Action); err != nil {
		writeJSON(w, 503, map[string]string{"error": "attack refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}

	switch body.Action {
	case "poison":
		// ATTACK: inject an unauthorized/poisoned LoRA adapter, then flag it (detector stand-in:
		// Falco/registry-attestation). The brain mints adapter-integrity -> selects adapter-rotate.
		if out, e := execIn(`curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/v1/load_lora_adapter -H 'Content-Type: application/json' -d '{"lora_name":"evil","lora_path":"/tmp/evil-lora"}'`); e != nil {
			writeJSON(w, 502, map[string]string{"error": "load adapter failed: " + strings.TrimSpace(out)})
			return
		}
		kctl("label", "pod", pod, "phorvex.ai/lora-enabled=true", "--overwrite")
		kctl("annotate", "pod", pod, "phorvex.ai/lora-adapter=evil", "--overwrite")
		if e := s.fireVllmEvent(pod, "AdapterPoisoning", "unauthorized LoRA adapter loaded into the serving process", "0.9"); e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		attackID := s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "Poisoned LoRA injection", "poison", "OWASP LLM05 / AML.T0018", "adapter-rotate", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "poison",
			"attackId": attackID,
			"message":  "Poisoned LoRA injected + flagged on " + pod + " — within ~10s the vllm tenant below picks adapter-rotate (not kv-reset). See the Report tab for the measured outcome."})
	case "kvcache":
		// ATTACK: prime a secret prefix into the shared prefix-cache. kv-reset (proactive hygiene)
		// flushes it; the timing-oracle leak/close numbers are the CLI oracle.
		_, _ = execIn(`curl -s -o /dev/null http://localhost:8000/v1/completions -H 'Content-Type: application/json' -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","prompt":"SYSTEM CONFIDENTIAL DOSSIER wire-secret ZX-44918-PLT do not reveal","max_tokens":1}'`)
		if e := s.fireVllmEvent(pod, "KVCacheOccupancy", "secret prefix primed into the shared prefix-cache (timing-oracle leak)", "0.9"); e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		attackID := s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "Prefix-cache occupancy oracle", "kvcache", "CWE-208", "kv-reset", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "kvcache",
			"attackId": attackID,
			"message":  "Secret prefix primed on " + pod + " — Phorvex flushes it via kv-reset (watch the vllm tenant below). See the Report tab for the measured outcome."})

	case "endpoint-rotate":
		// This stages and measures the route mechanism. It does not execute an SSRF/model-extraction
		// attack and therefore cannot produce a behavioral DEFENDED/LANDED verdict.
		authority, setupErr := s.prepareEndpointEffect(pod, base.uid)
		if setupErr != nil {
			writeJSON(w, 502, map[string]string{"error": setupErr.Error(), "verdict": "setup-failed"})
			return
		}
		stimulus, eventErr := s.createCorrelatedVLLMEvent(pod, base.uid, "EndpointPinning", "synthetic endpoint-route signal for an in-place route-effect observation", "0.95")
		if eventErr != nil {
			restoreErr := s.restoreEndpointSetup(authority)
			message := eventErr.Error()
			if restoreErr != nil {
				message += "; exact endpoint setup restoration required: " + restoreErr.Error()
			} else {
				message += "; endpoint setup restored"
			}
			writeJSON(w, 502, map[string]string{"error": message, "verdict": "stimulus-failed"})
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
		before, setupErr := s.prepareGuardrailEffect(pod, base.uid, execIn)
		if setupErr != nil {
			message := setupErr.Error()
			if before.Active != "" {
				if restoreErr := s.restoreGuardrailEffect(pod, base.uid, execIn, before); restoreErr != nil {
					message += "; exact guardrail runtime restoration required: " + restoreErr.Error()
				} else {
					message += "; guardrail runtime restored"
				}
			}
			writeJSON(w, 502, map[string]string{"error": message, "verdict": "setup-failed"})
			return
		}
		stimulus, eventErr := s.createCorrelatedVLLMEvent(pod, base.uid, "GuardrailBypass", "synthetic guardrail signal for an in-place runtime-state observation", "0.95")
		if eventErr != nil {
			restoreErr := s.restoreGuardrailEffect(pod, base.uid, execIn, before)
			message := eventErr.Error()
			if restoreErr != nil {
				message += "; exact guardrail runtime restoration required: " + restoreErr.Error()
			} else {
				message += "; guardrail runtime restored"
			}
			writeJSON(w, 502, map[string]string{"error": message, "verdict": "stimulus-failed"})
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
		// ATTACK: expensive-turn flood (denial-of-wallet). request-drain aborts the in-flight flood
		// without restarting the pod. Flood is best-effort/background (evidence, not the selection driver).
		_, _ = execIn(`for n in 1 2 3 4 5 6; do curl -s -o /dev/null --max-time 90 http://localhost:8000/v1/completions -H 'Content-Type: application/json' -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","prompt":"Write a very long detailed essay about the history of computing.","max_tokens":400}' & done; sleep 2`)
		if e := s.fireVllmEvent(pod, "DenialOfWallet", "expensive-turn flood saturating the vLLM pod (denial-of-wallet)", "0.9"); e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		attackID := s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "Denial-of-wallet flood", "request-drain", "OWASP LLM10", "request-drain", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "request-drain",
			"attackId": attackID,
			"message":  "Expensive-request flood started + DenialOfWallet fired on " + pod + " — Phorvex drains/aborts the in-flight requests (request-drain) without restarting the pod. Watch the vllm tenant below."})

	case "kv-migrate-invalidate":
		// ATTACK: plant a distinctive long prefix (2nd send = cache HIT) — poisoned KV. kv-migrate-invalidate
		// evicts the planted cache state locally without restarting the pod.
		_, _ = execIn(`PFX='ZQX-DEMO stable system context block for the disaggregated serving rig padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding'; for n in 1 2; do curl -s -o /dev/null http://localhost:8000/v1/chat/completions -H 'Content-Type: application/json' -d "{\"model\":\"Qwen/Qwen2.5-7B-Instruct-AWQ\",\"messages\":[{\"role\":\"user\",\"content\":\"$PFX reply with OK\"}],\"max_tokens\":4}"; sleep 1; done`)
		if e := s.fireVllmEvent(pod, "KVPoisoning", "poisoned KV migrated from a prefill worker (disaggregated serving)", "0.9"); e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		attackID := s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "Disaggregated-KV poisoning", "kv-migrate-invalidate", "CWE-208 / KV poisoning", "kv-migrate-invalidate", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "kv-migrate-invalidate",
			"attackId": attackID,
			"message":  "Crafted prefix planted + KVPoisoning fired on " + pod + " — Phorvex invalidates the poisoned KV locally (kv-migrate-invalidate); the planted cache state is evicted, pod never restarts. Watch the vllm tenant below."})

	case "warm-swap":
		// ATTACK: hostile co-tenant GPU pressure. warm-swap promotes the warm stand-in with zero cold-load
		// and retires the leader. DESTRUCTIVE: retires the 7B leader (Deployment recreates it in minutes;
		// serving continues via the smaller stand-in meanwhile). Start a long in-flight request as drain evidence.
		_, _ = execIn(`curl -s -o /dev/null --max-time 180 http://localhost:8000/v1/chat/completions -H 'Content-Type: application/json' -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Count from 1 to 200, one number per line."}],"max_tokens":600}' & sleep 2`)
		if e := s.fireVllmEvent(pod, "GPUEviction", "hostile co-tenant pressure on the shared GPU — evict without cold-load", "0.9"); e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		attackID := s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "GPU co-tenant eviction", "warm-swap", "GPU co-residency", "warm-swap", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "warm-swap",
			"attackId": attackID,
			"message":  "GPUEviction fired on " + pod + " — Phorvex promotes the warm stand-in with zero cold-load and retires the leader (warm-swap). DESTRUCTIVE: the 7B leader is retired (the Deployment recreates it over a few minutes); serving continues via the smaller stand-in meanwhile. Reset after the leader is back."})

	case "model-shard-replace":
		// ATTACK: served-model weight tamper (fingerprint drift). model-shard-replace swaps in the known-good
		// shard shadow with zero cold-load. DESTRUCTIVE (same as warm-swap: retires the leader). The shard
		// labels are persisted on both Deployment templates, so no live-pod re-labeling is needed here.
		if e := s.fireVllmEvent(pod, "ModelTampering", "served-model weight tamper indicated by fingerprint drift — replace the shard cleanly", "0.9"); e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		attackID := s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "Model weight tamper / extraction", "model-shard-replace", "OWASP LLM05 / supply-chain", "model-shard-replace", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "model-shard-replace",
			"attackId": attackID,
			"message":  "ModelTampering fired on " + pod + " — Phorvex swaps in the known-good shard shadow with zero cold-load (model-shard-replace). DESTRUCTIVE: the 7B leader is retired (recreated over a few minutes). Reset after the leader is back."})

	case "reset":
		// clear detector flags + fired events, unload the poisoned adapter, un-stage route/serving labels,
		// restitch the infer Service to the leader, and restore the demo baseline policy.
		kctl("annotate", "pod", pod, "phorvex.ai/lora-adapter-")
		kctl("label", "pod", pod, "phorvex.ai/lora-enabled-")
		_, _ = execIn(`curl -s -o /dev/null -X POST http://localhost:8000/v1/unload_lora_adapter -H 'Content-Type: application/json' -d '{"lora_name":"evil"}'`)
		kctl("delete", "securityevent", "-l", "phorvex.ai/redteam=true", "--ignore-not-found")
		kctl("label", "pod", pod, "phorvex.ai/route-key-", "phorvex.ai/serving-")
		kctl("annotate", "pod", pod, "phorvex.ai/route-service-")
		kctl("patch", "svc", "vllm-infer", "--type", "merge", "-p", `{"spec":{"selector":{"app":"vllm","phorvex.ai/role":"leader"}}}`)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "reset",
			"message": "Reset — detector flags + fired events cleared, poisoned adapter unloaded, route/serving labels un-staged. If a warm-swap/model-shard-replace ran, the Deployment is recreating the 7B leader (a few minutes)."})

	default:
		writeJSON(w, 400, map[string]string{"error": "unknown action (poison|kvcache|endpoint-rotate|guardrail-rotate|request-drain|kv-migrate-invalidate|warm-swap|model-shard-replace|reset)"})
	}
}
