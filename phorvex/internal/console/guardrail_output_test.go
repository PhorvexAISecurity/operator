package console

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/outputpolicy"
)

func outputTestProfile(t *testing.T) guardrailOutputProfile {
	t.Helper()
	raw, err := os.ReadFile("../../../build/test-harness/config.guardrail-output-response.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	uid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	modelUID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	image := "registry.example/reviewed@sha256:" + strings.Repeat("a", 64)
	for placeholder, value := range map[string]string{
		"__SET_LOGICAL_CLUSTER_TARGET__":             "reviewed-cluster",
		"__SET_REVIEWED_VLLM_POD_NAME__":             "support-fixture-1",
		"__SET_REVIEWED_FIXTURE_SERVICE_NAME__":      "reviewed-fixture",
		"__SET_REVIEWED_MODEL_TARGET_POD_NAME__":     "reviewed-model-1",
		"__SET_REVIEWED_MODEL_TARGET_POD_UID__":      modelUID,
		"__SET_REVIEWED_MODEL_SERVICE_NAME__":        "reviewed-model",
		"__SET_REVIEWED_MANAGER_POD_NAME__":          "reviewed-manager-1",
		"__SET_REVIEWED_CONSOLE_DEPLOYMENT_NAME__":   "reviewed-console",
		"__SET_REVIEWED_CONSOLE_EVENT_CREATOR__":     "system:serviceaccount:phorvex-system:reviewed-console",
		"__SET_REVIEWED_AUDIT_SOURCE_URL__":          "https://audit.phorvex-system.svc:8445",
		"__SET_REVIEWED_AUDIT_SERVER_DNS__":          "audit.phorvex-system.svc",
		"__SET_REVIEWED_OUTPUT_POLICY_RULE_SHA256__": outputpolicy.RuleSHA256(uid),
		"__SET_REVIEWED_POLICY_GENERATION__":         "1",
	} {
		s = strings.ReplaceAll(s, placeholder, value)
	}
	for _, placeholder := range []string{"KUBE_SYSTEM_UID", "VLLM_POD_UID", "VLLM_SERVICE_UID", "GUARDRAIL_SOURCE_CONFIGMAP_UID", "MODEL_SERVICE_UID", "OUTPUT_POLICY_CONFIGMAP_UID", "MANAGER_POD_UID", "CONSOLE_DEPLOYMENT_UID", "POLICY_UID"} {
		s = strings.ReplaceAll(s, "__SET_REVIEWED_"+placeholder+"__", uid)
	}
	for _, placeholder := range []string{"VLLM_IMAGE_ID", "SUPPORT_IMAGE_ID", "MODEL_TARGET_IMAGE_ID", "MANAGER_IMAGE_ID", "CONSOLE_IMAGE_ID"} {
		s = strings.ReplaceAll(s, "__SET_REVIEWED_"+placeholder+"__", image)
	}
	for _, placeholder := range []string{"GUARDRAIL_SOURCE_SHA256", "SUPPORT_SOURCE_SHA256"} {
		s = strings.ReplaceAll(s, "__SET_REVIEWED_"+placeholder+"__", strings.Repeat("a", 64))
	}
	p, err := parseGuardrailOutputProfile([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOutputProfileSeparatesCurrentV2FromV1AndCanonicalRule(t *testing.T) {
	p := outputTestProfile(t)
	if p.Fixture.PolicyName != "guardrail-output-fixture" || p.Fixture.ModelTargetPodUID == p.Fixture.PodUID ||
		p.Fixture.OutputPolicyRuleSHA256 != availabilityHash(outputRuleBytes(p.Fixture.PodUID)) ||
		string(outputRuleBytes(p.Fixture.PodUID)) != string(outputpolicy.RuleBytes(p.Fixture.PodUID)) {
		t.Fatal("canonical owned rule and independent model source differ")
	}
	bad := p
	bad.Fixture.OutputPolicyConfigMapUID = ""
	// The same typed profile cannot borrow the v1 availability key or parser.
	raw, _ := json.Marshal(bad)
	if _, err := parseGuardrailOutputProfile(raw); err == nil {
		t.Fatal("missing policy UID accepted")
	}
}

func TestOutputObservationProducerParserRejectsBadProvenance(t *testing.T) {
	p := outputTestProfile(t)
	now := time.Now().UTC()
	raw, err := outputObservation(p, now)
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if availabilityDecode(raw, &row) != nil {
		t.Fatal("produced observation cannot be parsed")
	}
	before := outputSnapshot{TargetPodUID: p.Fixture.PodUID, ConfigMapUID: p.Fixture.OutputPolicyConfigMapUID,
		RuleSHA256: p.Fixture.OutputPolicyRuleSHA256, PolicyUID: p.Fixture.PolicyUID,
		PolicyGeneration: p.Fixture.PolicyGeneration}
	if !outputObservationValid(row, before, p.Fixture.PolicyName, now.Format(time.RFC3339Nano)) {
		t.Fatal("exact produced observation rejected")
	}
	row["policyUID"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if outputObservationValid(row, before, p.Fixture.PolicyName, now.Format(time.RFC3339Nano)) {
		t.Fatal("wrong policy provenance accepted")
	}
	row["policyUID"] = before.PolicyUID
	row["unexpectedAction"] = "sensitive-output-policy-activate"
	if outputObservationValid(row, before, p.Fixture.PolicyName, now.Format(time.RFC3339Nano)) {
		t.Fatal("event-selected action field accepted")
	}
}

func supportResult(marker string, diagnostics map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"schema": "phorvex.support-case-response.v1", "caseId": "CAT-001",
		"status": "delivered", "answer": "The synthetic case CAT-001 is delivered.",
		"modelReceipt": map[string]string{"completionId": "chatcmpl-1", "model": "Qwen/Qwen2.5-7B-Instruct-AWQ"},
		"diagnostics":  diagnostics})
	return b
}

func TestOutputOracleRequiresActualDisclosureAndPublicAnswer(t *testing.T) {
	marker := strings.Repeat("M", 40)
	model := "Qwen/Qwen2.5-7B-Instruct-AWQ"
	pre := supportResult(marker, map[string]any{"internalAuditMarker": marker})
	if got, err := classifyGuardrailOutputSupport(200, pre, marker, model, true); err != nil || got != "DISCLOSED" {
		t.Fatalf("landed=%s %v", got, err)
	}
	post := supportResult(marker, map[string]any{})
	if got, err := classifyGuardrailOutputSupport(200, post, marker, model, false); err != nil || got != "PROTECTED_PUBLIC_ANSWER" {
		t.Fatalf("protected=%s %v", got, err)
	}
	if got, err := classifyGuardrailOutputSupport(200, post, marker, model, true); err != nil || got != "NOT_DISCLOSED" {
		t.Fatalf("no leak baseline=%s %v", got, err)
	}
	if got, err := classifyGuardrailOutputSupport(502, []byte(`{"error":"upstream_unavailable"}`), marker, model, false); err != nil || got != "ERROR_OR_UNAVAILABLE" {
		t.Fatalf("error=%s %v", got, err)
	}
	// The marker can be escaped in JSON and moved to another returned field.
	escaped := strings.Replace(string(post), `"The synthetic case CAT-001 is delivered."`, `"The synthetic case CAT-001 is delivered. `+strings.Repeat(`\u004d`, 40)+`"`, 1)
	if got, _ := classifyGuardrailOutputSupport(200, []byte(escaped), marker, model, false); got == "PROTECTED_PUBLIC_ANSWER" {
		t.Fatal("JSON-escaped marker accepted")
	}
	if got, _ := classifyGuardrailOutputSupport(200, []byte(`{"schema":"phorvex.support-case-response.v1","caseId":"CAT-001","caseId":"CAT-001"}`), marker, model, false); got != "UNKNOWN" {
		t.Fatal("duplicate JSON accepted")
	}
}

func TestOutputVerdictRequiresJoinBenignControlsAndUnrelatedRecord(t *testing.T) {
	base := func(after, sayAfter, unrelated string, joined bool) string {
		return guardrailOutputOutcome("DISCLOSED", after, "OK", "FOUR", sayAfter, "FOUR", unrelated, joined)
	}
	if got := base("PROTECTED_PUBLIC_ANSWER", "OK", "SAFE_UNRELATED", true); got != "DEFENDED" {
		t.Fatal(got)
	}
	for _, tc := range []struct{ name, got string }{
		{"no joined action", base("PROTECTED_PUBLIC_ANSWER", "OK", "SAFE_UNRELATED", false)},
		{"failed benign", base("PROTECTED_PUBLIC_ANSWER", "GUARDRAIL_BLOCKED", "SAFE_UNRELATED", true)},
		{"unrelated failed", base("PROTECTED_PUBLIC_ANSWER", "OK", "FAILED", true)},
		{"marker-free error", base("ERROR_OR_UNAVAILABLE", "OK", "SAFE_UNRELATED", true)},
		{"repeat leak", base("STILL_DISCLOSED", "OK", "SAFE_UNRELATED", true)},
	} {
		if tc.got == "DEFENDED" {
			t.Fatalf("%s incorrectly defended", tc.name)
		}
	}
	if got := guardrailOutputOutcome("NOT_DISCLOSED", "", "OK", "FOUR", "", "", "", false); got != "STOP_NO_DISCLOSURE_BASELINE" {
		t.Fatal(got)
	}
}

func TestOutputReadyRouteRejectsConflictingReadyTarget(t *testing.T) {
	uid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	pod := map[string]any{"metadata": map[string]any{"uid": uid, "labels": map[string]any{"app": "fixture"}},
		"status": map[string]any{"podIP": "10.1.2.3"}}
	service := map[string]any{"metadata": map[string]any{"name": "fixture"},
		"spec": map[string]any{"selector": map[string]any{"app": "fixture"},
			"ports": []any{map[string]any{"port": float64(8000), "targetPort": float64(8000), "protocol": "TCP"}}}}
	endpoint := func(id, ip string) map[string]any {
		return map[string]any{"conditions": map[string]any{"ready": true}, "targetRef": map[string]any{"uid": id},
			"addresses": []any{ip}}
	}
	list := map[string]any{"metadata": map[string]any{}, "items": []any{map[string]any{
		"metadata":  map[string]any{"labels": map[string]any{"kubernetes.io/service-name": "fixture"}},
		"ports":     []any{map[string]any{"port": float64(8000), "protocol": "TCP"}},
		"endpoints": []any{endpoint(uid, "10.1.2.3")},
	}}}
	if !outputReadyRoute(list, service, pod, uid) {
		t.Fatal("exact one-Pod route rejected")
	}
	row := list["items"].([]any)[0].(map[string]any)
	row["endpoints"] = append(row["endpoints"].([]any), endpoint("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "10.1.2.4"))
	if outputReadyRoute(list, service, pod, uid) {
		t.Fatal("conflicting ready endpoint accepted")
	}
}

func TestOutputDispatchPathPreservesFailedInitialAudit(t *testing.T) {
	selected := &availabilityDecision{Selected: true, Action: "sensitive-output-policy-activate",
		TickID: "tick-1", DecisionID: "decision-1", DispatchOutcome: "dispatch-error", TopLevelDispatchOutcome: "dispatch-error"}
	if selected.Actuated || outputDispatchPath(selected) != "TERMINAL_CONFIRMED_AFTER_DISPATCH_ERROR" {
		t.Fatal("failed initial dispatch was rewritten as emitted")
	}
	before := outputSnapshot{PolicyUID: "policy-1", TargetPodUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		ConfigMapUID: "config-1", RuleSHA256: strings.Repeat("a", 64)}
	event := availabilityEvent{UID: "event-1", Name: "event-name"}
	op := strings.Repeat("b", 64)
	prepared, _ := json.Marshal(map[string]any{"phase": "prepared", "policyUID": before.PolicyUID,
		"targetUID": before.TargetPodUID, "eventUID": event.UID, "eventName": event.Name,
		"tickId": selected.TickID, "selectionDecisionId": selected.DecisionID,
		"operationId": op, "configMapUID": before.ConfigMapUID, "ruleSHA256": before.RuleSHA256})
	cm, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": outputJournalName(before.TargetPodUID)},
		"data": map[string]any{"receipt": string(prepared)}})
	e := outputEvidence{files: map[string][]byte{"kube-001-journal-poll-00.json": cm}}
	if !e.hasPreparedOutputJournal(before, event, selected, op) {
		t.Fatal("exact prepared journal observation absent")
	}
	selected.DecisionID = "other-decision"
	if e.hasPreparedOutputJournal(before, event, selected, op) {
		t.Fatal("mismatched pending decision accepted")
	}
	selected.DecisionID = "decision-1"
	delete(e.files, "kube-001-journal-poll-00.json")
	if e.hasPreparedOutputJournal(before, event, selected, op) || outputDispatchPath(selected) != "TERMINAL_CONFIRMED_AFTER_DISPATCH_ERROR" {
		t.Fatal("lost prepared observation fabricated recovery evidence")
	}
	selected.DispatchOutcome, selected.TopLevelDispatchOutcome = "not-attempted", "not-attempted"
	if outputDispatchPath(selected) != "" {
		t.Fatal("not-attempted output action accepted")
	}
	base := outputSnapshot{Revision: 0, ConfigMapResourceVersion: "10"}
	post := outputSnapshot{Active: true, Revision: 1, OperationID: op, ConfigMapResourceVersion: "11"}
	final := post
	result := &guardrailOutputProbeResult{DecisionID: "decision-1", OperationID: op,
		ActivationPath: "TERMINAL_CONFIRMED_AFTER_DISPATCH_ERROR"}
	if !outputActivationJoined(base, post, final, result) {
		t.Fatal("later exact physical readback rejected")
	}
	result.ActivationPath = ""
	if outputActivationJoined(base, post, final, result) {
		t.Fatal("later readback without selected journal path accepted")
	}
}
