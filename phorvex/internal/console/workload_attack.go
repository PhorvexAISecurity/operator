/*
 * Phorvex Console — DASHBOARD-TRIGGERED live attacks on REAL workloads (beyond vLLM).
 *
 * POST /api/workload/attack {namespace, action} fires a REAL detector signal (a SecurityEvent
 * CR — the same shape Falco/KubeArmor emit) at the live rotation-target pod of an armed demo
 * workload, so the in-cluster operator's actuator SELECTION is visible in Live Theatre. The
 * armed workloads run reactiveOnly policies, so they sit CALM (no proactive churn) until this
 * fires — making the response a clean, attributable reaction. The console can't reach pod IPs,
 * so it shells kubectl. vLLM keeps its own /api/vllm/attack (adapter/kv AI signals).
 */

package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// armedWorkloads are the reactiveOnly demo namespaces the dashboard may fire REAL attacks at.
var armedWorkloads = map[string]bool{
	"litellm":           true,
	"mock-rag-chatbot":  true,
	"phorvex-live-demo": true,
}

func (s *Server) workloadAttack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var body struct {
		Namespace string `json:"namespace"`
		Action    string `json:"action"` // foothold | clear
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ns := strings.TrimSpace(body.Namespace)
	if !armedWorkloads[ns] {
		writeJSON(w, 400, map[string]string{"error": "namespace not armed for live attack: " + ns + " (armed: litellm, mock-rag-chatbot, phorvex-live-demo)"})
		return
	}
	kctl := func(timeout time.Duration, args ...string) (string, error) {
		return s.cfg.execText(timeout, "kubectl", append([]string{"-n", ns}, args...)...)
	}
	evName := "redteam-" + ns

	if body.Action == "clear" {
		_, _ = kctl(8*time.Second, "delete", "securityevent", evName, "--ignore-not-found")
		writeJSON(w, 200, map[string]any{"ok": true, "action": "clear",
			"message": "Attack signal cleared in " + ns + " — Phorvex returns to a calm baseline (no proactive churn)."})
		return
	}
	if body.Action != "foothold" && body.Action != "" {
		writeJSON(w, 400, map[string]string{"error": "unknown action (foothold|clear)"})
		return
	}

	// Resolve the CURRENT rotation-target pod at fire-time — a SecurityEvent targets a pod NAME,
	// and the pod may have rotated since the page loaded.
	pod, err := kctl(8*time.Second, "get", "pod", "-l", "r6th.io/rotation-target=true", "-o", "jsonpath={.items[0].metadata.name}")
	pod = strings.TrimSpace(pod)
	if err != nil || pod == "" {
		writeJSON(w, 503, map[string]string{"error": "no rotation-target pod in " + ns + ": " + strings.TrimSpace(pod)})
		return
	}

	// stateful pods get quarantined (rotate vetoed, state preserved); stateless get rotated.
	ownerKind, _ := kctl(6*time.Second, "get", "pod", pod, "-o", "jsonpath={.metadata.ownerReferences[0].kind}")
	expect := "rotate"
	if k := strings.ToLower(strings.TrimSpace(ownerKind)); strings.Contains(k, "stateful") {
		expect = "quarantine (stateful — rotate vetoed, state preserved)"
	}

	yaml := fmt.Sprintf(`apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: %s
  namespace: %s
  labels:
    phorvex.ai/redteam: "true"
spec:
  description: "red-team (dashboard): container-escape foothold detected on %s"
  targets: ["%s/%s"]
  rule:
    type: "Panic"
    threatLevel: "critical"
    source: "ExternalDetector"
`, evName, ns, pod, ns, pod)

	f, ferr := os.CreateTemp("", "phorvex-se-*.yaml")
	if ferr != nil {
		writeJSON(w, 500, map[string]string{"error": "temp file: " + ferr.Error()})
		return
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(yaml)
	_ = f.Close()

	if out, e := kctl(10*time.Second, "apply", "-f", f.Name()); e != nil {
		writeJSON(w, 502, map[string]string{"error": "apply SecurityEvent failed: " + strings.TrimSpace(out)})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "action": "foothold", "pod": pod, "expect": expect,
		"message": "Real foothold signal fired at " + pod + " — within ~10s Phorvex selects " + expect + " on it (it was calm/noop before)."})
}
