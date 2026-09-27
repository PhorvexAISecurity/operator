package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func drainTestProfile() drainLiveProfile {
	h := strings.Repeat("a", 64)
	u := "11111111-1111-4111-8111-111111111111"
	return drainLiveProfile{Schema: "live-request-drain-v1", Context: "dev-test", ClusterUID: u,
		PodName: "vllm-0", PodUID: u, PodImageID: "repo.invalid/vllm@sha256:" + h, PodContainerID: "containerd://" + h,
		ProxyImageID: "repo.invalid/proxy@sha256:" + h, ProxyContainerID: "containerd://" + h,
		ServiceName: "vllm", ServiceUID: u, ServiceSelector: map[string]string{"app": "vllm", "phorvex.ai/serving": "true"},
		PolicyName: "vllm-defense", PolicyUID: u, PolicyGeneration: 2, ManagerPodName: "manager-0", ManagerPodUID: u,
		ManagerImageID: "repo.invalid/manager@sha256:" + h, ManagerContainerID: "containerd://" + h,
		ConsoleDeploymentName: "phorvex-phorvex-console", ConsoleDeploymentUID: u, ConsoleImageID: "repo.invalid/console@sha256:" + h,
		ModelID: "Qwen/Qwen2.5-7B-Instruct-AWQ", AuditSourceIdentity: "https://audit.invalid|audit.invalid",
		ServingCompletionSHA256: "30ed34497113131c2749b7091bc4a49b5dd374b23b15bc5c7981c3e90ede804a",
		ServingEngineSHA256:     "35e4419aeb3ca2c1c0153254ac0a179db454cae4a33f7d37b3b9020ebdcfa73e",
		DrainProxySourceSHA256:  h, DrainEngineSourceSHA256: h, MaxRunSeconds: 240}
}

func TestDrainPinnedContainerAllowsHistoricalRestartButRejectsCurrentDrift(t *testing.T) {
	var pod vllmPodState
	if err := json.Unmarshal([]byte(`{"status":{"containerStatuses":[{"name":"guardrail","ready":true,"restartCount":1,"imageID":"proxy@sha256:abc","containerID":"containerd://current"}]}}`), &pod); err != nil {
		t.Fatal(err)
	}
	if !drainPinnedContainer(pod, "guardrail", "proxy@sha256:abc", "containerd://current") {
		t.Fatal("current ready container refused only because it restarted earlier")
	}
	if drainPinnedContainer(pod, "guardrail", "proxy@sha256:abc", "containerd://old") ||
		drainPinnedContainer(pod, "guardrail", "proxy@sha256:other", "containerd://current") {
		t.Fatal("stale image or container incarnation accepted")
	}
	pod.Status.ContainerStatuses[0].RestartCount = -1
	if drainPinnedContainer(pod, "guardrail", "proxy@sha256:abc", "containerd://current") {
		t.Fatal("invalid negative restart count accepted")
	}
}

func TestDrainLiveProfilePinsRouteAndSource(t *testing.T) {
	p := drainTestProfile()
	encode := func(v drainLiveProfile) []byte { b, _ := json.Marshal(v); return b }
	if _, err := parseDrainLiveProfile(encode(p)); err != nil {
		t.Fatal(err)
	}
	bad := p
	bad.ServiceSelector = map[string]string{}
	if _, err := parseDrainLiveProfile(encode(bad)); err == nil {
		t.Fatal("empty selector accepted")
	}
	bad = p
	bad.ServingEngineSHA256 = strings.Repeat("b", 64)
	if _, err := parseDrainLiveProfile(encode(bad)); err == nil {
		t.Fatal("unreviewed engine source accepted")
	}
	bad = p
	bad.AuditSourceIdentity = ""
	if _, err := parseDrainLiveProfile(encode(bad)); err == nil {
		t.Fatal("unbound audit source accepted")
	}
}

func TestDrainOwnedIDRequiresSameSnapshotAndTerminalAbort(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	hash := sha256.Sum256([]byte("cmpl-" + nonce + "-0"))
	id := hex.EncodeToString(hash[:])
	e := &model.DrainOperationEvidence{OperationID: "operation", ReceiptSHA256: strings.Repeat("b", 64), Aborted: 1,
		Reopened: true, Restored: true, SnapshotRequests: []string{id}, Dispositions: []model.DrainRequestDisposition{{RequestSHA256: id, Disposition: "aborted"}}}
	if !drainOwnedDisposition(e, nonce) {
		t.Fatal("exact owned abort rejected")
	}
	for name, mutate := range map[string]func(*model.DrainOperationEvidence){
		"other snapshot": func(v *model.DrainOperationEvidence) { v.SnapshotRequests = []string{strings.Repeat("c", 64)} },
		"completed":      func(v *model.DrainOperationEvidence) { v.Dispositions[0].Disposition = "completed-before-abort" },
		"duplicate":      func(v *model.DrainOperationEvidence) { v.Dispositions = append(v.Dispositions, v.Dispositions[0]) },
		"closed":         func(v *model.DrainOperationEvidence) { v.Reopened = false },
	} {
		t.Run(name, func(t *testing.T) {
			v := model.CloneDrainOperationEvidence(e)
			mutate(v)
			if drainOwnedDisposition(v, nonce) {
				t.Fatal("non-owned or unconfirmed terminal credited")
			}
		})
	}
}

func TestDrainStrictAuditRowsRefuseGaps(t *testing.T) {
	row, _ := json.Marshal(audit.Record{Kind: "phorvex.decision", Time: time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC), Namespace: "vllm", Pod: "vllm-0"})
	good := append(append([]byte(nil), row...), '\n')
	if got, originals, err := parseStrictDrainRows(context.Background(), good); err != nil || len(got) != 1 || len(originals) != 1 || !bytes.Equal(originals[0], row) {
		t.Fatalf("valid original rejected: %v", err)
	}
	for name, body := range map[string][]byte{"partial": row, "corrupt": append(append([]byte(nil), good...), []byte("{bad}\n")...), "blank": append(append([]byte(nil), good...), '\n')} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseStrictDrainRows(context.Background(), body); err == nil {
				t.Fatal("audit gap accepted")
			}
		})
	}
}

func TestDrainFixedRequestUsesOneBoundedGeneration(t *testing.T) {
	var body map[string]any
	if err := json.Unmarshal(drainRequestBody("Qwen/Qwen2.5-7B-Instruct-AWQ", 1024, true), &body); err != nil {
		t.Fatal(err)
	}
	if body["max_tokens"] != float64(1024) || body["stream"] != true || body["n"] != float64(1) {
		t.Fatal("stream bound changed")
	}
	if !strings.Contains(body["prompt"].(string), "1 through 400") {
		t.Fatal("fixed long-enough prompt changed")
	}
}

func TestDrainTerminalAuditJoinsExactOwnedOperation(t *testing.T) {
	p := drainTestProfile()
	nonce := strings.Repeat("d", 32)
	hash := sha256.Sum256([]byte("cmpl-" + nonce + "-0"))
	ownedID := hex.EncodeToString(hash[:])
	created := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	r := &attackRecord{Namespace: "vllm", Pod: p.PodName, TargetUID: p.PodUID, AttackID: "request-drain", EvidenceKind: "vllm-drain-owned-observation",
		ObservationStart: created.Add(-time.Second).Format(time.RFC3339Nano), ObservationEnd: created.Add(time.Minute).Format(time.RFC3339Nano),
		StimulusEvidence: &attackStimulusEvidence{Observed: true, TargetUID: p.PodUID, EventName: "owned-drain", EventUID: "event-uid",
			EventRule: model.AttackVectorInflight, EventCreatedAt: created.Format(time.RFC3339Nano)}}
	trace := caseTraceValidTrace(created.Add(20*time.Second), true, false)
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = "vllm", p.PolicyName, p.PolicyUID
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = "vllm", p.PodName, p.PodUID
	trace.Candidates[1].Action = string(model.ActionRequestDrain)
	trace.SelectedAction = string(model.ActionRequestDrain)
	trace.DispatchOutcome = model.DispatchEmitted
	if err := trace.Validate(); err != nil {
		t.Fatalf("producer-shaped trace invalid: %v", err)
	}
	op := &model.DrainOperationEvidence{OperationID: "operation-1", Generation: "1", PolicyUID: p.PolicyUID, TargetUID: p.PodUID, ServiceUID: p.ServiceUID,
		ReceiptSHA256: strings.Repeat("e", 64), Aborted: 1, Reopened: true, Restored: true,
		SnapshotRequests: []string{ownedID}, Dispositions: []model.DrainRequestDisposition{{RequestSHA256: ownedID, Disposition: "aborted"}}}
	event := model.EventEvidence{Name: "owned-drain", EventUID: "event-uid", Type: model.AttackVectorInflight,
		TargetPodUID: p.PodUID, TargetsPod: true, TimestampPresent: true}
	row := audit.Record{Kind: "phorvex.decision", Time: created.Add(20 * time.Second), Namespace: "vllm", Pod: p.PodName,
		Action: "request-drain", Selected: true, Actuated: true, DispatchOutcome: model.DispatchEmitted,
		DecisionTrace: trace, DrainOperation: op, Events: []model.EventEvidence{event}}
	before := audit.Record{Kind: "phorvex.decision", Time: created.Add(-time.Second), Namespace: "vllm", Pod: p.PodName, Action: "noop"}
	selected, err := drainTerminalFromRecords(r, []audit.Record{before, row}, created.Add(30*time.Second), nonce)
	if err != nil || selected == nil || !drainTerminalMatchesProfile(selected, p) || !drainOwnedDisposition(selected.DrainOperation, nonce) {
		t.Fatalf("exact source-bound operation rejected: %+v %v", selected, err)
	}
	for name, mutate := range map[string]func(*audit.Record){
		"event":        func(v *audit.Record) { v.Events[0].EventUID = "other" },
		"policy":       func(v *audit.Record) { v.DecisionTrace.PolicyUID = "other" },
		"target":       func(v *audit.Record) { v.DrainOperation.TargetUID = "other" },
		"receipt":      func(v *audit.Record) { v.DrainOperation.ReceiptSHA256 = "" },
		"dispatch":     func(v *audit.Record) { v.DispatchOutcome = model.DispatchError },
		"trace-action": func(v *audit.Record) { v.DecisionTrace.SelectedAction = string(model.ActionNoop) },
		"trace-dispatch": func(v *audit.Record) {
			v.DecisionTrace.DispatchOutcome = model.DispatchError
			v.DecisionTrace.DispatchReason = "bounded dispatch error"
		},
		"terminal": func(v *audit.Record) { v.DrainOperation.Dispositions[0].Disposition = "completed-before-abort" },
	} {
		t.Run(name, func(t *testing.T) {
			v := row
			traceCopy := *row.DecisionTrace
			v.DecisionTrace = &traceCopy
			v.DrainOperation = model.CloneDrainOperationEvidence(row.DrainOperation)
			v.Events = append([]model.EventEvidence(nil), row.Events...)
			mutate(&v)
			got, _ := drainTerminalFromRecords(r, []audit.Record{before, v}, created.Add(30*time.Second), nonce)
			if got != nil && drainTerminalMatchesProfile(got, p) && drainOwnedDisposition(got.DrainOperation, nonce) {
				t.Fatal("mutated original credited")
			}
		})
	}
}

func TestDrainEventIntentPrecedesAmbiguousCreate(t *testing.T) {
	called := 0
	var intent []byte
	s := NewServer(Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		called++
		if bin != "kubectl" || strings.Contains(strings.Join(args, " "), "--context") {
			t.Errorf("in-Pod create used external context: %s %v", bin, args)
		}
		if len(intent) == 0 {
			t.Error("create dispatched before durable manifest")
		}
		return "", errors.New("lost create reply")
	}})
	_, err := s.createCorrelatedVLLMEventWithAdapterContext("arn:aws:eks:us-east-2:123456789012:cluster/reviewed", "vllm-0", "pod-uid", "DenialOfWallet", "fixed synthetic signal", "0.9", "", func(raw []byte) error { intent = append([]byte(nil), raw...); return nil })
	if err == nil || called != 1 || !bytes.Contains(intent, []byte("name: redteam-vllm-denialofwallet-")) {
		t.Fatalf("ambiguous create lost exact intent: calls=%d err=%v", called, err)
	}
	called = 0
	_, err = s.createCorrelatedVLLMEventWithAdapterContext("dev-test", "vllm-0", "pod-uid", "DenialOfWallet", "fixed synthetic signal", "0.9", "", func([]byte) error { return errors.New("durability failed") })
	if err == nil || called != 0 {
		t.Fatalf("create escaped failed intent persistence: calls=%d err=%v", called, err)
	}
}

func TestDrainSelfIncarnationBracketsProfileRollout(t *testing.T) {
	dir := t.TempDir()
	base := []byte(`{"metadata":{"name":"console-new","uid":"new-pod-uid"},"status":{"containerStatuses":[{"name":"console","containerID":"containerd://one","imageID":"repo.invalid/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ready":true}]}}`)
	for _, phase := range []string{"before", "after"} {
		if err := os.WriteFile(filepath.Join(dir, phase+"-console.json"), base, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := drainConsoleIncarnationStable(dir); err != nil {
		t.Fatal(err)
	}
	drift := bytes.Replace(base, []byte("containerd://one"), []byte("containerd://two"), 1)
	if err := os.WriteFile(filepath.Join(dir, "after-console.json"), drift, 0600); err != nil {
		t.Fatal(err)
	}
	if err := drainConsoleIncarnationStable(dir); err == nil {
		t.Fatal("same Pod UID container restart accepted")
	}
}

func TestDrainLiveVerdictCreditsOnlyCompleteOwnedChain(t *testing.T) {
	record := func(status string) *attackRecord {
		return &attackRecord{Pod: "vllm-0", DrainLiveProbe: &drainLiveProbeResult{Status: status},
			StimulusEvidence: &attackStimulusEvidence{EventCreatedAt: "2026-09-27T19:00:00Z"},
			DecisionEvidence: &decisionEvidence{Action: "request-drain", Time: "2026-09-27T19:00:07.5Z"}}
	}
	r := record("OWNED_ABORT_AND_CONTINUITY_OBSERVED")
	applyDrainLiveVerdict(r)
	if r.Status != "done" || r.Outcome != "DEFENDED" || !r.Actuated || r.Action != "request-drain" ||
		r.DefendedPod != "vllm-0" || r.Containment != "owned-inflight-request-aborted-service-reopened" ||
		r.OutcomeClass != "drain-owned_abort_and_continuity_observed" || r.TimeToDefendSec != 7.5 {
		t.Fatalf("complete owned chain was not credited: %+v", r)
	}
	for _, status := range []string{"MECHANISM_ONLY", "NO_DISCRIMINATING_OVERLAP", "UNKNOWN"} {
		r := record(status)
		applyDrainLiveVerdict(r)
		if r.Outcome != "" || r.Actuated || r.Containment != "" || r.DefendedPod != "" || r.TimeToDefendSec != 0 {
			t.Fatalf("%s earned credit: %+v", status, r)
		}
	}
	unknown := record("UNKNOWN")
	applyDrainLiveVerdict(unknown)
	if unknown.Status != "partial" || unknown.OutcomeClass != "drain-observation-unknown" {
		t.Fatalf("unknown drain was not partial: %+v", unknown)
	}
	missingDecision := record("OWNED_ABORT_AND_CONTINUITY_OBSERVED")
	missingDecision.DecisionEvidence = nil
	applyDrainLiveVerdict(missingDecision)
	if missingDecision.Outcome != "" || missingDecision.Actuated {
		t.Fatalf("credit without exact decision evidence: %+v", missingDecision)
	}
	reversed := record("OWNED_ABORT_AND_CONTINUITY_OBSERVED")
	reversed.DecisionEvidence.Time = "2026-09-27T18:59:59Z"
	applyDrainLiveVerdict(reversed)
	if reversed.Outcome != "DEFENDED" || reversed.TimeToDefendSec != 0 {
		t.Fatalf("decision before event must not produce a negative or fabricated time: %+v", reversed)
	}
}
