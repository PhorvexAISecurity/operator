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
	"sort"
	"strconv"
	"strings"
	"time"
)

// armedWorkloads are the reactiveOnly demo namespaces the dashboard may fire REAL attacks at.
// The litellm / mock-rag-chatbot / phorvex-live-demo demo namespaces were retired from the
// cluster; voice (voice-bot Deployment) is the stateless rotate target that replaced them.
var armedWorkloads = map[string]bool{
	"voice": true, // voice-bot (Deployment) — stateless => Phorvex rotates
	"nats":  true, // NATS JetStream (StatefulSet) — stateful => Phorvex quarantines, not rotates
}

// armedList renders the allowlist for error messages, so a namespace added above can never
// drift out of what the API tells the caller is available.
func armedList() string {
	names := make([]string, 0, len(armedWorkloads))
	for ns := range armedWorkloads {
		names = append(names, ns)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
	// M-168's resettable stateless experiment path and the normal Fire control share
	// one typed producer. Other legacy demo actions keep their existing path below.
	if ns == "voice" && (body.Action == "" || body.Action == "foothold") {
		receipt, err := s.executeResettableFoothold(actorOf(r), ns, "redteam-"+ns)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "action": "foothold", "pod": receipt.Pod,
			"attackId": receipt.AttackID, "message": "Synthetic detector signal accepted; target response observation pending."})
		return
	}
	// Armed = Phorvex actually governs this namespace (it has a PhorvexPolicy). That is the
	// honest gate: a foothold at a namespace Phorvex does not watch just lands with no
	// defense — there is nothing to demonstrate. Any app with a policy is fair game, which
	// is what makes the launcher's Fire button light up across every governed app rather
	// than a hardcoded demo pair. The static allowlist stays as a fallback for a namespace
	// that is armed by intent but has no policy object yet.
	if !armedWorkloads[ns] && !s.namespaceHasPolicy(ns) {
		writeJSON(w, 400, map[string]string{"error": "namespace not armed: " + ns +
			" — it has no PhorvexPolicy, so Phorvex does not govern it and an attack would land " +
			"with no defense. Add a policy (Protect → Policy control) first."})
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
	// [TARGET-SELECTION FIX] Pick a LIVE, NOT-ALREADY-QUARANTINED rotation target. Taking
	// items[0] blindly aimed the attack at a pod Phorvex had already adopted into the AMTD CR in
	// an earlier demo (quarantine is sticky — one per reset): the pod is network-isolated and out
	// of the serving set, so there is nothing left to defend and the attack correctly does
	// NOTHING — which reads exactly like a broken actuator.
	// pickPod finds a Running, not-already-quarantined pod to attack. It returns the pod name
	// and a count of pods skipped because a previous run already quarantined them.
	pickPod := func(labelSel string) (string, int) {
		args := []string{"get", "pod"}
		if labelSel != "" {
			args = append(args, "-l", labelSel)
		}
		args = append(args, "-o",
			`jsonpath={range .items[*]}{.metadata.name}|{.metadata.ownerReferences[0].kind}|{.status.phase}{"\n"}{end}`)
		list, _ := kctl(8*time.Second, args...)
		skipped := 0
		for _, ln := range strings.Split(strings.TrimSpace(list), "\n") {
			f := strings.Split(strings.TrimSpace(ln), "|")
			if len(f) < 3 || f[0] == "" {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(f[1]), "AdaptiveMovingTargetDefense") {
				skipped++ // already quarantined by a previous run
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(f[2]), "Running") {
				continue
			}
			return strings.TrimSpace(f[0]), skipped
		}
		return "", skipped
	}
	// Prefer an explicit rotation-target pod (the original demo apps carry that label), but fall
	// back to ANY Running pod in the namespace. Every namespace that reaches here is armed —
	// i.e. governed by a PhorvexPolicy whose selector picks this app's own pods — so a foothold
	// at any Running pod lands on something Phorvex actually watches and will defend.
	pod, skippedQuarantined := pickPod("r6th.io/rotation-target=true")
	if pod == "" {
		pod, _ = pickPod("")
	}
	if pod == "" {
		msg := "no attackable pod in " + ns
		if skippedQuarantined > 0 {
			msg += fmt.Sprintf(" — %d pod(s) are ALREADY quarantined from an earlier run; quarantine is sticky (one per reset), so reset the workload before firing again", skippedQuarantined)
		}
		writeJSON(w, 503, map[string]string{"error": msg})
		return
	}

	// [STATEFULNESS FIX] Statefulness is a property of the WORKLOAD, not of whoever currently owns
	// the pod: an adopted (quarantined) pod reports ownerKind=AdaptiveMovingTargetDefense, so the
	// old ownerReferences check called a StatefulSet broker "stateless" and promised a rotate that
	// the statefulIntegrity law would then veto. Decide from what actually makes rotate
	// destructive — a mounted PVC — and fall back to the owner kind.
	stateful := false
	if pvc, _ := kctl(6*time.Second, "get", "pod", pod,
		"-o", "jsonpath={.spec.volumes[*].persistentVolumeClaim.claimName}"); strings.TrimSpace(pvc) != "" {
		stateful = true
	}
	ownerKind, _ := kctl(6*time.Second, "get", "pod", pod, "-o", "jsonpath={.metadata.ownerReferences[0].kind}")
	if k := strings.ToLower(strings.TrimSpace(ownerKind)); strings.Contains(k, "stateful") {
		stateful = true
	}
	if !stateful { // the workload may be a StatefulSet even when this pod was adopted away from it
		if ss, _ := kctl(6*time.Second, "get", "statefulset", "-o", "jsonpath={.items[*].metadata.name}"); strings.TrimSpace(ss) != "" {
			stateful = true
		}
	}
	expect := "rotate"
	if stateful {
		expect = "quarantine (stateful — rotate vetoed, state preserved)"
	}

	// [PRE-FLIGHT HEADROOM] Promising "Phorvex will act in ~10s" is a lie when the workload has no
	// availability headroom left: on a stateful workload rotate is vetoed by statefulIntegrity and
	// quarantine removes a replica, so if available == the policy's minAvailableReplicas floor every
	// candidate is INFEASIBLE and the tick correctly selects nothing. That reads as a broken
	// actuator unless we say so up front. Surfaced as a warning; the signal still fires so the
	// veto itself is visible in the audit.
	warning := ""
	if stateful {
		avail := 0
		if a, _ := kctl(6*time.Second, "get", "statefulset", "-o", "jsonpath={.items[0].status.availableReplicas}"); strings.TrimSpace(a) != "" {
			avail, _ = strconv.Atoi(strings.TrimSpace(a))
		}
		floor := 0
		if f, _ := kctl(6*time.Second, "get", "phorvexpolicy", "-o", "jsonpath={.items[0].spec.slo.minAvailableReplicas}"); strings.TrimSpace(f) != "" {
			floor, _ = strconv.Atoi(strings.TrimSpace(f))
		}
		if floor > 0 && avail > 0 && avail <= floor {
			warning = fmt.Sprintf("NO HEADROOM: %s has %d available replica(s) and the policy floor is %d, "+
				"so quarantine would breach the availability SLO and every move is correctly vetoed as infeasible. "+
				"A previous quarantine is likely still in place (it is sticky — one per reset). Reset the workload to restore full replicas, then fire again.",
				ns, avail, floor)
		}
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
	if _, ferr = f.WriteString(yaml); ferr == nil {
		ferr = f.Sync()
	}
	if cerr := f.Close(); ferr == nil {
		ferr = cerr
	}
	if ferr != nil {
		writeJSON(w, 500, map[string]string{"error": "write attack manifest: " + ferr.Error()})
		return
	}

	// snapshot the defense baseline BEFORE applying the attack — the operator can quarantine within ~1s,
	// so a post-apply snapshot would absorb this attack's own response and misreport it as LANDED.
	base := s.snapshotBaseline(ns, pod)
	if err := s.persistEffectIntent("/api/workload/attack", actorOf(r), ns, "foothold"); err != nil {
		writeJSON(w, 503, map[string]string{"error": "attack refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}

	if out, e := kctl(10*time.Second, "apply", "-f", f.Name()); e != nil {
		writeJSON(w, 502, map[string]string{"error": "apply SecurityEvent failed: " + strings.TrimSpace(out)})
		return
	}
	// reuse the workload-level statefulness decided above — recomputing it from ownerKind here
	// reintroduced the exact bug: an adopted pod reports AdaptiveMovingTargetDefense, so a
	// StatefulSet broker was recorded as "rotate expected" and every quarantine then looked like
	// the wrong actuator in the report.
	actuator := "rotate"
	if stateful {
		actuator = "quarantine"
	}
	// capture the REAL outcome (landed vs defended) + reasoning + uptime + cost for the Report tab.
	s.startAttackRecord("", ns, ns, pod, "Container-escape foothold", "foothold", "T1611", actuator, stateful, base)
	msg := "Real foothold signal fired at " + pod + " — within ~10s Phorvex selects " + expect + " on it (it was calm/noop before). See the Report tab for the measured outcome."
	if warning != "" {
		msg = "Real foothold signal fired at " + pod + ", but " + warning
	}
	writeJSON(w, 200, map[string]any{"ok": true, "action": "foothold", "pod": pod, "expect": expect,
		"warning": warning, "message": msg})
}
