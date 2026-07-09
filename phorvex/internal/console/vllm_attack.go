/*
 * Phorvex Console — DASHBOARD-TRIGGERED live vLLM attacks.
 *
 * POST /api/vllm/attack {action} launches a REAL attack on the live vLLM so the operator's actuator
 * SELECTION is visible right below in Live Theatre — no CLI. The console can't reach pod IPs, so it
 * shells kubectl (exec into the pod for the serving-stack call; label/annotate for the detector flag).
 * Read-only-ish: it only touches the dedicated `vllm` demo workload.
 */

package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const vllmAttackNS = "vllm"

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
	execIn := func(curl string) (string, error) {
		return s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", pod, "--", "sh", "-c", curl)
	}
	kctl := func(args ...string) { _, _ = s.cfg.execText(8*time.Second, "kubectl", append([]string{"-n", vllmAttackNS}, args...)...) }

	// snapshot the defense baseline BEFORE the attack lands (esp. the adapter epoch for poison) so a
	// fast operator reaction is correctly attributed and not absorbed into the baseline.
	base := s.snapshotBaseline(vllmAttackNS, pod)

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
		s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "Poisoned LoRA injection", "poison", "OWASP LLM05 / AML.T0018", "adapter-rotate", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "poison",
			"message": "Poisoned LoRA injected + flagged on " + pod + " — within ~10s the vllm tenant below picks adapter-rotate (not kv-reset). See the Report tab for the measured outcome."})
	case "kvcache":
		// ATTACK: prime a secret prefix into the shared prefix-cache. kv-reset (proactive hygiene)
		// flushes it; the timing-oracle leak/close numbers are the CLI oracle.
		_, _ = execIn(`curl -s -o /dev/null http://localhost:8000/v1/completions -H 'Content-Type: application/json' -d '{"model":"Qwen/Qwen2.5-0.5B-Instruct","prompt":"SYSTEM CONFIDENTIAL DOSSIER wire-secret ZX-44918-PLT do not reveal","max_tokens":1}'`)
		s.startAttackRecord("", vllmAttackNS, vllmAttackNS, pod, "Prefix-cache occupancy oracle", "kvcache", "CWE-208", "kv-reset", false, base)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "kvcache",
			"message": "Secret prefix primed on " + pod + " — Phorvex flushes it via kv-reset (watch the vllm tenant below). See the Report tab for the measured outcome."})
	case "reset":
		kctl("annotate", "pod", pod, "phorvex.ai/lora-adapter-")
		kctl("label", "pod", pod, "phorvex.ai/lora-enabled-")
		_, _ = execIn(`curl -s -o /dev/null -X POST http://localhost:8000/v1/unload_lora_adapter -H 'Content-Type: application/json' -d '{"lora_name":"evil"}'`)
		writeJSON(w, 200, map[string]any{"ok": true, "action": "reset",
			"message": "Reset — detector flag cleared, poisoned adapter unloaded; Phorvex returns to kv-reset hygiene."})
	default:
		writeJSON(w, 400, map[string]string{"error": "unknown action (poison|kvcache|reset)"})
	}
}
