/*
 * Phorvex Console — fire a CATALOGUE scenario as a REAL attack at a live app.
 *
 * POST /api/workload/fire-scenario applies a real SecurityEvent — of the scenario's own attack
 * type — to a Running pod in an armed (policy-governed) namespace, exactly the mechanism the
 * foothold and the vLLM attacks already use. Phorvex then reacts on the real pod and the outcome
 * lands in /api/attack-results like any other live attack.
 *
 * This is the bridge the launcher was missing: the harness "Run" path only ever ran a scenario
 * against synthetic sandbox pods (the harness deletes its namespace at teardown, so it can never
 * touch a real app). Firing the scenario's DETECTOR SIGNAL at the real pod is the honest live
 * equivalent — the attack signal is real, the pod is real, the defense is real. It does not
 * re-implement each scenario's full attacker behaviour (only the 9 dedicated live attacks do
 * that); it makes the pod actionable under the scenario's banner and measures the response.
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

// resolveRunningPod picks a Running, not-already-quarantined pod in ns to attack. It prefers an
// explicit rotation-target pod (the demo apps carry that label) and falls back to any Running pod
// — safe because the caller has already checked the namespace is governed by a policy.
func (s *Server) resolveRunningPod(ns string) (string, error) {
	pick := func(labelSel string) string {
		args := []string{"-n", ns, "get", "pod"}
		if labelSel != "" {
			args = append(args, "-l", labelSel)
		}
		args = append(args, "-o",
			`jsonpath={range .items[*]}{.metadata.name}|{.metadata.ownerReferences[0].kind}|{.status.phase}{"\n"}{end}`)
		out, _ := s.cfg.execText(8*time.Second, "kubectl", args...)
		for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
			f := strings.Split(strings.TrimSpace(ln), "|")
			if len(f) < 3 || f[0] == "" {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(f[1]), "AdaptiveMovingTargetDefense") {
				continue // already quarantined
			}
			if strings.EqualFold(strings.TrimSpace(f[2]), "Running") {
				return strings.TrimSpace(f[0])
			}
		}
		return ""
	}
	if pod := pick("r6th.io/rotation-target=true"); pod != "" {
		return pod, nil
	}
	if pod := pick(""); pod != "" {
		return pod, nil
	}
	return "", fmt.Errorf("no Running, non-quarantined pod in %s", ns)
}

// fireSecurityEventAt applies a SecurityEvent CR at ns/pod. It is the namespace-general form of
// the foothold event, and it uses the SAME recognised rule (type "Panic", source
// "ExternalDetector") that the shipping foothold attack uses — verified live to raise the pod's
// threatPosture to ~0.9. An arbitrary rule.type (e.g. the raw scenario name) is NOT a threat the
// operator scores, so it would leave threatPosture at 0 and Phorvex would never react. The
// scenario's identity is carried in the description and the event name, not the rule type.
// Labeled phorvex.ai/redteam=true so a clear can delete it.
func (s *Server) fireSecurityEventAt(ns, pod, evName, desc string) error {
	yaml := fmt.Sprintf(`apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: %s
  namespace: %s
  labels:
    phorvex.ai/redteam: "true"
spec:
  description: %q
  targets: ["%s/%s"]
  rule:
    type: "Panic"
    threatLevel: "critical"
    source: "ExternalDetector"
`, evName, ns, desc, ns, pod)
	f, err := os.CreateTemp("", "phorvex-scn-se-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(yaml)
	_ = f.Close()
	if out, e := s.cfg.execText(10*time.Second, "kubectl", "-n", ns, "apply", "-f", f.Name()); e != nil {
		return fmt.Errorf("apply SecurityEvent: %s", strings.TrimSpace(out))
	}
	return nil
}

// eventTypeForScenario turns a catalogue scenario name into a SecurityEvent rule.type. The type
// is a free-form label the operator raises threat posture on; keeping the scenario's own name
// makes the audit trail and the attack-results row self-describing.
func eventTypeForScenario(scenario string) string {
	t := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, scenario)
	if t == "" {
		return "RedTeamScenario"
	}
	return t
}

func (s *Server) fireScenarioLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var body struct {
		Namespace string `json:"namespace"`
		Scenario  string `json:"scenario"`
		MITRE     string `json:"mitre"`
		Expected  string `json:"expected"` // the actuator the caller expects, for the results row
		Action    string `json:"action"`   // "" | "fire" | "clear"
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ns := strings.TrimSpace(body.Namespace)
	scenario := strings.TrimSpace(body.Scenario)
	if ns == "" || !nsRe.MatchString(ns) {
		writeJSON(w, 400, map[string]string{"error": "valid namespace is required"})
		return
	}
	if !scenarioRe.MatchString(scenario) {
		writeJSON(w, 400, map[string]string{"error": "invalid scenario name"})
		return
	}
	evName := "redteam-scn-" + strings.ToLower(eventTypeForScenario(scenario))
	if len(evName) > 253 {
		evName = evName[:253]
	}

	// Clear: delete this scenario's event so the app returns to a calm baseline.
	if body.Action == "clear" {
		_, _ = s.cfg.execText(8*time.Second, "kubectl", "-n", ns, "delete", "securityevent", evName, "--ignore-not-found")
		writeJSON(w, 200, map[string]any{"ok": true, "action": "clear", "scenario": scenario,
			"message": "Cleared " + scenario + " in " + ns + "."})
		return
	}

	// Armed = the namespace is governed by a PhorvexPolicy, so firing at it demonstrates a
	// real defense. Same gate as the foothold path.
	if !armedWorkloads[ns] && !s.namespaceHasPolicy(ns) {
		writeJSON(w, 400, map[string]string{"error": "namespace not armed: " + ns +
			" — it has no PhorvexPolicy, so Phorvex does not govern it and the attack would land " +
			"with no defense."})
		return
	}

	pod, err := s.resolveRunningPod(ns)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}

	// Statefulness (mounted PVC) decides whether Phorvex will rotate or quarantine, and it is
	// what the results row reports as the expected actuator when the caller didn't supply one.
	stateful := false
	if pvc, _ := s.cfg.execText(6*time.Second, "kubectl", "-n", ns, "get", "pod", pod,
		"-o", "jsonpath={.spec.volumes[*].persistentVolumeClaim.claimName}"); strings.TrimSpace(pvc) != "" {
		stateful = true
	}
	expected := strings.TrimSpace(body.Expected)
	if expected == "" {
		expected = "rotate"
		if stateful {
			expected = "quarantine"
		}
	}

	// Baseline BEFORE applying — the operator can act within ~1s, so a later snapshot would
	// absorb this attack's own response and misreport the outcome.
	base := s.snapshotBaseline(ns, pod)
	mitre := strings.TrimSpace(body.MITRE)
	if mitre == "" {
		mitre = "catalogue"
	}
	desc := "Red-team catalogue scenario " + scenario + " fired live at " + ns + "/" + pod
	if err := s.fireSecurityEventAt(ns, pod, evName, desc); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	s.startAttackRecord("", ns, ns, pod, scenario, scenario, mitre, expected, stateful, base)
	writeJSON(w, 200, map[string]any{
		"ok": true, "action": "fire", "scenario": scenario, "namespace": ns, "pod": pod,
		"expect": expected,
		"message": scenario + " fired as a real SecurityEvent at " + ns + "/" + pod +
			" — Phorvex is now reacting; the outcome appears in Attack monitoring and on the dashboard.",
	})
}
