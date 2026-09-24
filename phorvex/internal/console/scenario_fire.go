/*
 * Phorvex Console — emit a server-authorized CATALOGUE detector signal at a live app.
 *
 * POST /api/workload/fire-scenario creates a unique SecurityEvent for an exact live Pod UID. It
 * observes the installed manager's temporally related decision and exact-target response, while
 * explicitly recording that the named scenario behavior was not executed. These observations are
 * diagnostic signals, never LANDED/DEFENDED results or evidence of attack mitigation.
 */

package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

var catalogueSignalSequence atomic.Uint64

type catalogueSignalCreateError struct {
	err        error
	dispatched bool
}

func (e *catalogueSignalCreateError) Error() string { return e.err.Error() }
func (e *catalogueSignalCreateError) Unwrap() error { return e.err }

// resolveRunningPod preserves the legacy namespace-only selection: it prefers a
// rotation-labeled Running Pod and otherwise takes another Running Pod. Namespace
// policy presence alone does not prove that the chosen Pod matches any policy.
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
// the foothold event, and source "ExternalDetector". The rule TYPE must be one the operator
// SCORES as a threat: "Panic" (the shipping foothold rule, verified to raise threatPosture ~0.9)
// or one of the model.AttackVector* types, which killchain.stageFromEvent now recognises as a
// persist-stage threat AND recon (ucw) uses to steer the surgical actuator. An arbitrary type
// (e.g. the raw scenario name) is NOT scored and would leave threatPosture at 0 — so ruleType is
// constrained to that set; "" falls back to "Panic". The scenario's identity is carried in the
// description and the event name. Each event is unique and retained for exact reconciliation;
// the legacy clear request has no UID authority and therefore refuses without deleting anything.
func (s *Server) prepareSecurityEventAt(targetUID, evName, ruleType string) (*attackStimulusEvidence, error) {
	if targetUID == "" {
		return nil, fmt.Errorf("target Pod UID is unavailable")
	}
	if ruleType == "" {
		ruleType = "Panic"
	}
	sequence := catalogueSignalSequence.Add(1)
	correlation := fmt.Sprintf("%x-%x", s.cfg.now().UnixNano(), sequence)
	suffix := "-" + correlation
	if len(evName)+len(suffix) > 253 {
		evName = strings.TrimRight(evName[:253-len(suffix)], "-")
	}
	evName += suffix
	candidate := &attackStimulusEvidence{Kind: "synthetic-catalogue-signal", TargetUID: targetUID, EventName: evName, EventRule: ruleType, Correlation: correlation, BehavioralExecuted: false, Limitation: "catalogue detector signal only; the named scenario behavior was not executed"}
	return candidate, nil
}

func (s *Server) firePreparedSecurityEventAt(ns, pod, desc string, candidate *attackStimulusEvidence) (*attackStimulusEvidence, error) {
	if candidate == nil || candidate.TargetUID == "" || candidate.EventName == "" || candidate.EventRule == "" || candidate.Correlation == "" || candidate.Observed || candidate.EventUID != "" {
		return candidate, fmt.Errorf("prepared SecurityEvent identity is incomplete or already used")
	}
	evName, ruleType, correlation := candidate.EventName, candidate.EventRule, candidate.Correlation
	yaml := fmt.Sprintf(`apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: %s
  labels:
    phorvex.ai/redteam: "true"
    phorvex.ai/console-catalogue: "true"
    phorvex.ai/attack-correlation: %q
  annotations:
    %s: %q
spec:
  description: %q
  targets: ["%s/%s"]
  rule:
    type: %q
    threatLevel: "critical"
    source: "ExternalDetector"
`, evName, correlation, model.ConsoleTargetPodUIDAnnotation, candidate.TargetUID, desc, ns, pod, ruleType)
	f, err := os.CreateTemp("", "phorvex-scn-se-*.yaml")
	if err != nil {
		return candidate, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0o600); err == nil {
		_, err = f.WriteString(yaml)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return candidate, fmt.Errorf("write SecurityEvent manifest: %w", err)
	}
	out, err := s.cfg.execText(10*time.Second, "kubectl", "create", "-f", f.Name(), "-o", "json")
	if err != nil {
		return candidate, &catalogueSignalCreateError{err: fmt.Errorf("create SecurityEvent %q correlation %q outcome unknown: %w (%s)", evName, correlation, err, strings.TrimSpace(out)), dispatched: true}
	}
	var event vllmSecurityEvent
	if err := json.Unmarshal([]byte(out), &event); err != nil {
		return candidate, &catalogueSignalCreateError{err: fmt.Errorf("created SecurityEvent reply is malformed; exact resource %q correlation %q requires reconciliation: %w", evName, correlation, err), dispatched: true}
	}
	if event.Metadata.Name != evName || event.Metadata.Namespace != "" || event.Metadata.UID == "" || event.Metadata.CreationTimestamp == "" ||
		event.Metadata.Labels["phorvex.ai/attack-correlation"] != correlation || event.Metadata.Labels["phorvex.ai/console-catalogue"] != "true" ||
		event.Metadata.Annotations[model.ConsoleTargetPodUIDAnnotation] != candidate.TargetUID ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != ns+"/"+pod || event.Spec.Rule.Type != ruleType || event.Spec.Rule.Source != "ExternalDetector" {
		return candidate, &catalogueSignalCreateError{err: fmt.Errorf("created SecurityEvent reply is incomplete or mismatched; exact resource %q correlation %q requires reconciliation", evName, correlation), dispatched: true}
	}
	candidate.Observed = true
	candidate.EventUID = event.Metadata.UID
	candidate.EventCreatedAt = event.Metadata.CreationTimestamp
	return candidate, nil
}

func (s *Server) fireSecurityEventAt(ns, pod, targetUID, evName, desc, ruleType string) (*attackStimulusEvidence, error) {
	candidate, err := s.prepareSecurityEventAt(targetUID, evName, ruleType)
	if err != nil {
		return candidate, err
	}
	return s.firePreparedSecurityEventAt(ns, pod, desc, candidate)
}

func (s *Server) catalogueSignalDefinition(name string) (CatalogItem, error) {
	for _, item := range s.cfg.Catalog() {
		if item.Name != name || item.LaunchKind != "harness-scenario" {
			continue
		}
		if item.BenignControl == nil {
			return CatalogItem{}, fmt.Errorf("scenario %q has legacy metadata without an authoritative attack/benign declaration", name)
		}
		if *item.BenignControl {
			return CatalogItem{}, fmt.Errorf("scenario %q is a benign functional control and cannot be emitted as a security signal", name)
		}
		if len(item.ExpectedActuators) == 0 || strings.TrimSpace(item.ExpectedActuators[0]) == "" {
			return CatalogItem{}, fmt.Errorf("scenario %q has no server-authoritative expected response", name)
		}
		return item, nil
	}
	return CatalogItem{}, fmt.Errorf("scenario %q is not present in the authoritative harness catalogue", name)
}

func (s *Server) writeCatalogueSignalFailure(w http.ResponseWriter, endpoint, actor, namespace, scenario, phase, targetUID string, candidate *attackStimulusEvidence, dispatched bool, cause error) {
	restoration := "not-needed"
	if dispatched {
		restoration = "reconciliation-required"
	}
	if err := s.persistCatalogueSignalFailure(endpoint, actor, namespace, scenario, phase, targetUID, candidate, dispatched, restoration, cause); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":         "catalogue signal failure evidence could not be persisted; unsafe to retry: " + err.Error(),
			"unsafeToRetry": true, "eventName": candidateEventName(candidate), "eventUID": candidateEventUID(candidate),
		})
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{
		"error": cause.Error(), "mutated": dispatched, "restoration": restoration,
		"eventName": candidateEventName(candidate), "eventUID": candidateEventUID(candidate), "correlation": candidateCorrelation(candidate),
	})
}

func candidateEventName(candidate *attackStimulusEvidence) string {
	if candidate == nil {
		return ""
	}
	return candidate.EventName
}

func candidateEventUID(candidate *attackStimulusEvidence) string {
	if candidate == nil {
		return ""
	}
	return candidate.EventUID
}

func candidateCorrelation(candidate *attackStimulusEvidence) string {
	if candidate == nil {
		return ""
	}
	return candidate.Correlation
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
	body, decodeErr := decodeScenarioFireRequest(r)
	if decodeErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": decodeErr.Error()})
		return
	}
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

	// A cluster-scoped SecurityEvent can only be deleted with the exact event UID that this
	// record created. The legacy request carries no such authority, so it must fail closed.
	if body.Action == "clear" {
		if err := s.persistEffectIntent("/api/workload/fire-scenario", actorOf(r), ns, "clear-refused:"+scenario); err != nil {
			writeJSON(w, 503, map[string]string{"error": "clear refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
			return
		}
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "action": "clear", "scenario": scenario,
			"verdict": "unsupported-restoration-authority", "error": "clear refused: exact record-owned SecurityEvent name and UID authority is required"})
		return
	}
	definition, err := s.catalogueSignalDefinition(scenario)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error(), "verdict": "unsupported-catalogue-signal"})
		return
	}
	expected := definition.ExpectedActuators[0]
	if requested := strings.TrimSpace(body.Expected); requested != "" && requested != expected {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "requested response does not match server-authoritative scenario metadata", "verdict": "metadata-mismatch"})
		return
	}

	// Legacy namespace selection remains compatible. Exact mode independently
	// verifies the one selected Pod, its owner and its matching active policy.
	if body.TargetPod == "" && !armedWorkloads[ns] && !s.namespaceHasPolicy(ns) {
		writeJSON(w, 400, map[string]string{"error": "namespace not armed: " + ns +
			" — it has no PhorvexPolicy for a catalogue signal."})
		return
	}

	pod := body.TargetPod
	var exact scenarioExactTarget
	if pod != "" {
		exact, err = s.resolveScenarioExactTarget(ns, pod, body.TargetUID)
	} else {
		pod, err = s.resolveRunningPod(ns)
	}
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}

	// Mounted-PVC state is recorded for the case. The brain's actual action is
	// independently observed; a catalogue name hint never forces selection.
	stateful := pod != "" && body.TargetPod != "" && scenarioHasPVC(&exact.pod)
	if body.TargetPod == "" {
		if pvc, _ := s.cfg.execText(6*time.Second, "kubectl", "-n", ns, "get", "pod", pod,
			"-o", "jsonpath={.spec.volumes[*].persistentVolumeClaim.claimName}"); strings.TrimSpace(pvc) != "" {
			stateful = true
		}
	}
	// Baseline BEFORE applying — the operator can act within ~1s, so a later snapshot would
	// absorb this attack's own response and misreport the outcome.
	base := defenseBaseline{}
	if body.TargetPod != "" {
		base = s.snapshotBaselineForOwner(ns, pod, exact.ownerName, exact.ownerUID, string(exact.pod.UID))
	} else {
		base = s.snapshotBaseline(ns, pod)
	}
	if base.uid == "" {
		writeJSON(w, 503, map[string]string{"error": "exact target Pod identity is unavailable"})
		return
	}
	// This is the final read before durable signal intent. The manager repeats
	// the UID check against its own decision Pod snapshot after event creation.
	if body.TargetPod != "" {
		if err := s.recheckScenarioExactTarget(ns, pod, base.uid, exact); err != nil {
			writeJSON(w, 503, map[string]string{"error": err.Error()})
			return
		}
	} else if liveUID, found, readErr := s.experimentCluster().PodUID(r.Context(), ns, pod); readErr != nil || !found || liveUID != base.uid {
		writeJSON(w, 503, map[string]string{"error": "selected Pod identity changed before catalogue signal intent"})
		return
	}
	mitre := strings.Join(definition.Techniques, ",")
	if mitre == "" {
		mitre = "catalogue"
	}
	desc := "Red-team catalogue scenario " + scenario + " fired live at " + ns + "/" + pod
	// Carry the attack's VECTOR when the expected actuator is a surgical serving move, so the brain
	// is steered to it (kv-reset/guardrail-rotate/request-drain/adapter-rotate) instead of the
	// cheapest generic cover; "" (e.g. rotate/quarantine) keeps the recognised "Panic" default.
	vector := model.AttackVectorForActuator(expected)
	stimulus, err := s.prepareSecurityEventAt(base.uid, evName, vector)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "prepare signal identity: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}
	if err := s.persistCatalogueSignalIntent("/api/workload/fire-scenario", actorOf(r), ns, scenario, base.uid, stimulus); err != nil {
		writeJSON(w, 503, map[string]string{"error": "signal refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}
	if err := s.persistEffectIntent("/api/workload/fire-scenario", actorOf(r), ns, "fire:"+scenario); err != nil {
		writeJSON(w, 503, map[string]string{"error": "attack refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}
	stimulus, err = s.firePreparedSecurityEventAt(ns, pod, desc, stimulus)
	if err != nil {
		dispatched := false
		var createErr *catalogueSignalCreateError
		if errors.As(err, &createErr) {
			dispatched = createErr.dispatched
		}
		s.writeCatalogueSignalFailure(w, "/api/workload/fire-scenario", actorOf(r), ns, scenario, "stimulus-create", base.uid, stimulus, dispatched, err)
		return
	}
	liveUID, found, readErr := s.experimentCluster().PodUID(r.Context(), ns, pod)
	if readErr != nil || !found || liveUID != base.uid {
		cause := fmt.Errorf("target Pod identity changed or became unavailable across catalogue signal creation")
		s.writeCatalogueSignalFailure(w, "/api/workload/fire-scenario", actorOf(r), ns, scenario, "post-create-target-identity", base.uid, stimulus, true, cause)
		return
	}
	base.stimulus = stimulus
	base.outcomeClass = "behavioral-oracle-unsupported"
	base.producerRoute = "/api/workload/fire-scenario"
	base.resultSchema = "catalogue-signal-v1"
	attackID := s.startCatalogueSignalRecord(ns, pod, scenario, mitre, expected, stateful, base)
	writeJSON(w, 200, map[string]any{
		"ok": true, "action": "fire", "scenario": scenario, "namespace": ns, "pod": pod,
		"expect": expected, "attackId": attackID,
		"message": scenario + " accepted as a synthetic catalogue SecurityEvent at " + ns + "/" + pod +
			"; the exact-ID observation reports temporal manager evidence and target response without a behavioral security verdict.",
	})
}
