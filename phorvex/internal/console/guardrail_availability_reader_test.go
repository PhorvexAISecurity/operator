package console

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/phorvex/phorvex/internal/audittransport"
)

func availabilityEffectFixture(t *testing.T) (availabilityEvidence, availabilitySnapshot, availabilitySnapshot, *GuardrailAvailabilityResult) {
	t.Helper()
	e := availabilityEvidence{files: map[string][]byte{}, terminal: availabilityTerminal{RunID: "run-1", ConsolePOSTsAttempted: 1, CleanupVerified: true, ExactEventDeletesAttempted: 1}}
	e.p.Fixture.PodName = "target-pod"
	e.p.Fixture.PodUID = "target-uid"
	e.p.Fixture.PolicyName = "vllm-defense"
	e.p.Fixture.PolicyUID = "policy-uid"
	e.p.Fixture.EventCreator = "system:serviceaccount:phorvex-system:console-sa"
	put := func(name string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		e.files[name] = raw
	}
	start := availabilityAuditStart{Schema: "guardrail-availability-audit-start-v1", SourceIdentity: "audit|server", Segment: audittransport.Segment{ID: "live", Generation: "gen-1", Size: 0, Anchor: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, ManifestSHA256: availabilityHash([]byte(`{"segments":[]}`))}
	put("audit-start.json", start)
	e.files["audit-start-manifest.json"] = []byte(`{"segments":[]}`)
	put("post-intent.json", map[string]any{"runID": "run-1", "requestSHA256": availabilityHash([]byte(availabilityConsoleBody)), "auditStartSHA256": availabilityHash(mustAvailabilityJSON(start)), "baselineGate": "READY_FOR_ONE_INJECTED_RECOVERY", "maximumPOSTs": 1})
	postBody := []byte(`{"ok":true,"action":"guardrail-rotate","attackId":"atk-one"}`)
	put("console-1-0.json", availabilityConsoleHTTP{"POST", "/api/vllm/attack", 200, base64.StdEncoding.EncodeToString(postBody), availabilityHash(postBody), len(postBody)})
	resultBody := []byte(`{"attacks":[{"id":"atk-one","evidenceKind":"vllm-in-place-effect","attackId":"guardrail-rotate","targetUid":"target-uid","stimulusEvidence":{"observed":true,"eventName":"event-1","eventUid":"event-uid","correlation":"corr-1"}}]}`)
	put("console-1-1.json", availabilityConsoleHTTP{"GET", "/api/attack-results?id=atk-one&includeObservations=true&limit=1", 200, base64.StdEncoding.EncodeToString(resultBody), availabilityHash(resultBody), len(resultBody)})
	event := availabilityEvent{UID: "event-uid", Name: "event-1", ResourceVersion: "rv-1", CreatorIdentity: e.p.Fixture.EventCreator, Correlation: "corr-1", TargetPodUID: "target-uid", RuleType: "phorvex.attack.guardrail", Source: "redteam"}
	created := map[string]any{"metadata": map[string]any{"uid": event.UID, "name": event.Name, "resourceVersion": event.ResourceVersion, "labels": map[string]any{"phorvex.ai/attack-correlation": event.Correlation, "phorvex.ai/console-vllm": "true"}, "annotations": map[string]any{"phorvex.ai/creator-identity": event.CreatorIdentity}}, "spec": map[string]any{"targets": []string{"vllm/target-pod"}, "rule": map[string]any{"type": event.RuleType, "source": event.Source}}}
	put("kube-001-event.json", created)
	put("kube-002-before-target.json", map[string]any{"metadata": map[string]any{"name": "target-pod", "uid": "target-uid"}})
	put("kube-003-prepost-event-inventory.json", map[string]any{"metadata": map[string]any{"continue": ""}, "items": []any{}})
	put("created-event.json", event)
	put("event-predelete.json", created)
	put("delete-intent.json", event)
	put("delete-ack.json", map[string]any{"uid": event.UID, "resourceVersion": event.ResourceVersion, "acknowledged": true})
	put("event-absence.json", map[string]any{"name": event.Name, "uid": event.UID, "notFound": true})
	put("cleanup-cluster.json", map[string]any{"metadata": map[string]any{"uid": "cluster-uid"}})
	before := availabilitySnapshot{ClusterUID: "cluster-uid", TargetPodUID: "target-uid", PolicyUID: "policy-uid", ActiveVariant: "pgv1", PodVariant: "pgv1"}
	before.Receipt = json.RawMessage(`{"generation":7,"operationID":"old"}`)
	tick := "t09"
	op := availabilityOperationID(tick, "policy-uid", "vllm", "target-uid")
	after := before
	after.ActiveVariant = "pgv2"
	after.PodVariant = "pgv2"
	after.GuardrailEpoch = availabilityEpoch(op)
	after.Receipt = mustAvailabilityJSON(map[string]any{"version": 9, "kind": "guardrail-rotate", "effectDomain": "guardrail-variant-v1", "phase": "terminal-full", "generation": 8, "priorVariant": "pgv1", "nextVariant": "pgv2", "operationID": op, "tickID": tick, "policyNamespace": "vllm", "policyName": "vllm-defense", "policyUID": "policy-uid", "targetName": "target-pod", "targetUID": "target-uid", "expectedGuardrail": map[string]any{"present": true, "value": availabilityEpoch(op)}})
	var trace []byte
	for i := 0; i < 17; i++ {
		trace = append(trace, availabilityAuditLine(i, i == 9, i >= 9)...)
	}
	rows, unbound, err := availabilityProjectAudit(trace, before, "target-pod", &event)
	if err != nil || unbound != 0 {
		t.Fatalf("project real-shaped 17 rows: %d %v", unbound, err)
	}
	chunk := []byte("audit-interval")
	audit := availabilityAuditTerminal{Schema: "guardrail-availability-audit-terminal-v1", Status: "COMPLETE", CoverageComplete: true, SourceIdentity: start.SourceIdentity, StartSHA256: availabilityHash(mustAvailabilityJSON(start)), EndManifestSHA256: availabilityHash([]byte(`{"end":1}`)), TerminalManifestSHA256: availabilityHash([]byte(`{"final":1}`)), FrozenBytes: int64(len(chunk)), BytesRead: int64(len(chunk)), PayloadBytes: int64(len(chunk)), DataGETs: 1, ControlGETs: 2, AuditReadElapsedSeconds: 1, UnboundTargetRows: &unbound, TargetRows: rows, ChunkReceipts: []availabilityAuditChunk{{SegmentID: "live", Generation: "gen-1", Offset: 0, Bytes: len(chunk), SHA256: availabilityHash(chunk)}}}
	put("audit-terminal.json", audit)
	e.files["audit-end-manifest.json"] = []byte(`{"end":1}`)
	e.files["audit-terminal-manifest.json"] = []byte(`{"final":1}`)
	result := &GuardrailAvailabilityResult{Status: "UNKNOWN", EventMode: "INJECTED", NaturalDetector: "NOT_EVALUATED", SecurityEfficacy: "NOT_EVALUATED", SyntheticThreat: "NOT_EVALUATED", Route: "Pod-loopback-8000", Before: GuardrailAvailabilityControls{"GUARDRAIL_BLOCKED", "GUARDRAIL_BLOCKED", "FOUR"}, After: GuardrailAvailabilityControls{"GUARDRAIL_BLOCKED", "OK", "FOUR"}}
	return e, before, after, result
}

func TestGuardrailAvailabilityProducerProjectionToIndependentEffectReader(t *testing.T) {
	e, before, after, result := availabilityEffectFixture(t)
	got, err := e.projectEffect(result, before, after, "")
	if err != nil || !got.Accepted || got.Status != "INJECTED_GUARDRAIL_AVAILABILITY_RECOVERY_CONFIRMED" || got.Operation.EventUID != "event-uid" || !got.CleanupVerified {
		t.Fatalf("producer-shaped original projection failed: %+v %v", got, err)
	}
	soleEvidence, soleBefore, soleAfter, soleResult := availabilityEffectFixture(t)
	var soleAudit availabilityAuditTerminal
	if err := soleEvidence.decode("audit-terminal.json", &soleAudit); err != nil {
		t.Fatal(err)
	}
	soleAudit.TargetRows = soleAudit.TargetRows[9:10]
	soleEvidence.files["audit-terminal.json"] = mustAvailabilityJSON(soleAudit)
	soleGot, soleErr := soleEvidence.projectEffect(soleResult, soleBefore, soleAfter, "")
	if soleErr != nil || !soleGot.Accepted || soleGot.Status != "INJECTED_GUARDRAIL_AVAILABILITY_RECOVERY_CONFIRMED" {
		t.Fatalf("single exact selected observation refused: %+v %v", soleGot, soleErr)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*availabilityEvidence, *availabilitySnapshot)
	}{
		{"missing unbound count", func(e *availabilityEvidence, _ *availabilitySnapshot) {
			var a availabilityAuditTerminal
			_ = e.decode("audit-terminal.json", &a)
			a.UnboundTargetRows = nil
			e.files["audit-terminal.json"] = mustAvailabilityJSON(a)
		}},
		{"second selected action", func(e *availabilityEvidence, _ *availabilitySnapshot) {
			var a availabilityAuditTerminal
			_ = e.decode("audit-terminal.json", &a)
			a.TargetRows[10].Selected = true
			a.TargetRows[10].Actuated = true
			a.TargetRows[10].Action = "guardrail-rotate"
			a.TargetRows[10].DispatchOutcome = "emitted"
			a.TargetRows[10].TopLevelDispatchOutcome = "emitted"
			e.files["audit-terminal.json"] = mustAvailabilityJSON(a)
		}},
		{"missing exact cleanup", func(e *availabilityEvidence, _ *availabilitySnapshot) { delete(e.files, "event-absence.json") }},
		{"forged console 200", func(e *availabilityEvidence, _ *availabilitySnapshot) {
			var c availabilityConsoleHTTP
			_ = e.decode("console-1-0.json", &c)
			c.Status = 403
			e.files["console-1-0.json"] = mustAvailabilityJSON(c)
		}},
		{"wrong operation phase", func(_ *availabilityEvidence, a *availabilitySnapshot) {
			a.Receipt = bytes.Replace(a.Receipt, []byte("terminal-full"), []byte("dispatching"), 1)
		}},
		{"wrong event creator", func(e *availabilityEvidence, _ *availabilitySnapshot) {
			var v map[string]any
			_ = e.decode("kube-001-event.json", &v)
			availabilityMap(availabilityMeta(v)["annotations"])["phorvex.ai/creator-identity"] = "other"
			e.files["kube-001-event.json"] = mustAvailabilityJSON(v)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyEvidence, b, a, r := availabilityEffectFixture(t)
			tc.mutate(&copyEvidence, &a)
			got, err := copyEvidence.projectEffect(r, b, a, "")
			if err != nil {
				t.Fatal(err)
			}
			if got.Accepted || got.Status != "UNKNOWN" {
				t.Fatalf("tampered original earned credit: %+v", got)
			}
		})
	}
}
