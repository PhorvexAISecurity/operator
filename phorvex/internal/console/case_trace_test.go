package console

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func caseTraceRecord(t *testing.T, now time.Time, records ...audit.Record) (*Server, *attackRecord) {
	t.Helper()
	for i := range records {
		if len(records[i].Events) > 0 && records[i].DecisionTrace == nil {
			records[i].DecisionTrace = caseTraceValidTrace(records[i].Time, records[i].Selected, false)
			if err := records[i].DecisionTrace.Validate(); err != nil {
				t.Fatalf("generated trace invalid: %v", err)
			}
		}
	}
	path := writeDecisionAudit(t, records...)
	s := NewServer(Config{AuditPath: path, Now: func() time.Time { return now.Add(10 * time.Second) }})
	r := &attackRecord{
		FiredAt: now.Format(time.RFC3339Nano), Namespace: "demo", Pod: "demo-0", TargetUID: "pod-uid",
		EvidenceKind: "catalogue-signal", ObservationStart: now.Format(time.RFC3339Nano),
		ObservationEnd: now.Add(8 * time.Second).Format(time.RFC3339Nano),
		StimulusEvidence: &attackStimulusEvidence{Observed: true, TargetUID: "pod-uid", EventName: "owned-signal",
			EventUID: "event-uid", EventCreatedAt: now.Add(time.Second).Format(time.RFC3339Nano), EventRule: "Panic"},
	}
	return s, r
}

func TestCaseTraceLegacyWorkloadSignalIsTypedAndClearRefusesWithoutUID(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &catalogueSignalExec{}
	cluster := &fakeExperimentCluster{podUID: "pod-uid", podFound: true}
	cfg := Config{StateDir: t.TempDir(), Exec: fx.run, AttackWatchDuration: 10 * time.Millisecond, AttackWatchInterval: time.Millisecond}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: cluster}
	// The fired attack's watcher writes to StateDir: it finishes before the directory goes.
	t.Cleanup(s.attackWatchers.Wait)

	req := httptest.NewRequest("POST", "/api/workload/attack", strings.NewReader(`{"namespace":"demo","action":"foothold"}`))
	rw := httptest.NewRecorder()
	s.workloadAttack(rw, req)
	if rw.Code != 200 {
		t.Fatalf("fire status=%d body=%s", rw.Code, rw.Body.String())
	}
	var response struct {
		AttackID string `json:"attackId"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &response); err != nil || response.AttackID == "" {
		t.Fatalf("fire response=%s err=%v", rw.Body.String(), err)
	}
	attackMu.Lock()
	var observed *attackRecord
	for _, record := range attackList {
		if record.ID == response.AttackID {
			observed = cloneAttackRecord(record)
		}
	}
	attackMu.Unlock()
	if observed == nil || observed.EvidenceKind != "synthetic-detector-signal" || observed.StimulusEvidence == nil ||
		!observed.StimulusEvidence.Observed || observed.StimulusEvidence.EventUID == "" || observed.StimulusEvidence.TargetUID != "pod-uid" ||
		observed.StimulusEvidence.BehavioralExecuted || observed.ProducerRoute != "/api/workload/attack" {
		t.Fatalf("legacy route did not produce an identity-bound unscored signal: %+v", observed)
	}

	clear := httptest.NewRequest("POST", "/api/workload/attack", strings.NewReader(`{"namespace":"demo","action":"clear"}`))
	clearRW := httptest.NewRecorder()
	s.workloadAttack(clearRW, clear)
	if clearRW.Code != 409 || fx.deleteCall {
		t.Fatalf("clear status=%d delete=%t body=%s", clearRW.Code, fx.deleteCall, clearRW.Body.String())
	}
}

func TestCaseTraceLegacyLostCreateAcknowledgementPersistsUnknownOutcome(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &catalogueSignalExec{createErr: errors.New("connection reset after create")}
	stateDir := t.TempDir()
	cfg := Config{StateDir: stateDir, Exec: fx.run, AttackWatchDuration: 10 * time.Millisecond, AttackWatchInterval: time.Millisecond}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: &fakeExperimentCluster{podUID: "pod-uid", podFound: true}}
	t.Cleanup(s.attackWatchers.Wait)
	rw := httptest.NewRecorder()
	s.workloadAttack(rw, httptest.NewRequest("POST", "/api/workload/attack", strings.NewReader(`{"namespace":"demo","action":"foothold"}`)))
	if rw.Code != 502 || !strings.Contains(rw.Body.String(), `"mutated":true`) || !strings.Contains(rw.Body.String(), `"restoration":"reconciliation-required"`) {
		t.Fatalf("lost acknowledgement response=%d %s", rw.Code, rw.Body.String())
	}
	b, err := os.ReadFile(cfg.statePath("effect-intents.jsonl"))
	if err != nil || !strings.Contains(string(b), `"endpoint":"/api/workload/attack"`) || !strings.Contains(string(b), `"mutated":true`) ||
		!strings.Contains(string(b), `"restoration":"reconciliation-required"`) {
		t.Fatalf("durable ambiguous failure missing: err=%v body=%s", err, b)
	}
}

func TestCaseTraceSignalIntentFailurePreventsCreate(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &catalogueSignalExec{}
	cfg := Config{StateDir: t.TempDir(), Exec: fx.run, StateAppend: func(string, []byte) error { return errors.New("intent sink unavailable") }}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: &fakeExperimentCluster{podUID: "pod-uid", podFound: true}}
	rw := httptest.NewRecorder()
	s.workloadAttack(rw, httptest.NewRequest("POST", "/api/workload/attack", strings.NewReader(`{"namespace":"demo","action":"foothold"}`)))
	if rw.Code != 503 || len(fx.created) != 0 || !strings.Contains(rw.Body.String(), "refused-evidence-unavailable") {
		t.Fatalf("intent failure did not refuse before create: code=%d creates=%v body=%s", rw.Code, fx.created, rw.Body.String())
	}
}

func TestCaseTraceLostAckAndFailureAppendRetainsPreSendLookupAuthority(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &catalogueSignalExec{createErr: errors.New("connection reset after create")}
	var writes [][]byte
	cfg := Config{StateDir: t.TempDir(), Exec: fx.run}
	cfg.StateAppend = func(_ string, record []byte) error {
		copyRecord := append([]byte(nil), record...)
		if len(writes) == 2 {
			return errors.New("post-effect evidence sink failed")
		}
		writes = append(writes, copyRecord)
		return nil
	}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: &fakeExperimentCluster{podUID: "pod-uid", podFound: true}}
	rw := httptest.NewRecorder()
	s.workloadAttack(rw, httptest.NewRequest("POST", "/api/workload/attack", strings.NewReader(`{"namespace":"demo","action":"foothold"}`)))
	if rw.Code != 503 || len(fx.created) != 1 || len(writes) != 2 || !strings.Contains(rw.Body.String(), `"unsafeToRetry":true`) {
		t.Fatalf("post-effect append control: code=%d creates=%v writes=%d body=%s", rw.Code, fx.created, len(writes), rw.Body.String())
	}
	var intent catalogueSignalFailureRecord
	if err := json.Unmarshal(writes[0], &intent); err != nil {
		t.Fatal(err)
	}
	if intent.Phase != "stimulus-create-intent" || intent.Endpoint != "/api/workload/attack" || intent.Namespace != "demo" ||
		intent.TargetUID != "pod-uid" || intent.EventName == "" || intent.Correlation == "" || intent.EventUID != "" || intent.Mutated || intent.Restoration != "pending-dispatch" {
		t.Fatalf("pre-send intent lacks exact lookup authority or invents UID/delete authority: %+v", intent)
	}
}

func genericCaseEvent(uid, target, trust string) model.EventEvidence {
	return model.EventEvidence{Name: "owned-signal", EventUID: uid, Type: "Panic", Source: "ExternalDetector",
		TrustVerdict: trust, CreatorIdentity: "system:serviceaccount:demo:detector", TargetPodUID: target,
		TargetsPod: true, TimestampPresent: true, Weight: 1}
}

func TestCaseTraceExactNoopOutranksUnrelatedSelected(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	unrelated := audit.Record{Kind: "phorvex.decision", Time: now.Add(2 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "rotate", Selected: true, Actuated: true, Reason: "unrelated selection"}
	exact := audit.Record{Kind: "phorvex.decision", Time: now.Add(3 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "noop", Reason: "exact event refused", DispatchOutcome: model.DispatchRefused, DispatchReason: "capacity floor", Events: []model.EventEvidence{genericCaseEvent("event-uid", "pod-uid", "trusted")}}
	s, result := caseTraceRecord(t, now, unrelated, exact)
	s.fillReasoning("", result)
	if result.DecisionEvidence == nil || result.DecisionEvidence.Correlation != "exact-event-uid" || result.DecisionEvidence.Source != "generic-event-evidence" || result.DecisionEvidence.Selected || result.DecisionEvidence.Reason != "exact event refused" || result.DecisionEvidence.DispatchOutcome != model.DispatchRefused {
		t.Fatalf("exact refusal did not outrank unrelated temporal selection: %+v", result.DecisionEvidence)
	}
	if result.TemporalDecisionEvidence == nil || result.TemporalDecisionEvidence.Reason != "unrelated selection" || len(result.DecisionTraceEvidence) != 1 {
		t.Fatalf("exact and temporal evidence were not kept separate: exact=%+v temporal=%+v", result.DecisionTraceEvidence, result.TemporalDecisionEvidence)
	}
}

func caseTraceValidTrace(now time.Time, selected, steered bool) *model.DecisionTraceV2 {
	facts := []model.DecisionFactV2{{FactKey: "z", FactType: "session", FinalWeight: 1}, {FactKey: "a", FactType: "podIdentity", FinalWeight: 2}}
	if steered {
		facts[0].SteeredBy = &model.VectorSteeringAttribution{RuleType: "Panic", AppliedMultiplier: 3, Events: []model.VectorSteeringEvent{{EventName: "owned-signal", EventUID: "event-uid", RuleType: "Panic", DeclaredSource: "ExternalDetector", TrustVerdict: "trusted", CreatorIdentity: "system:serviceaccount:demo:detector", TargetPodUID: "pod-uid"}}}
	}
	trace := &model.DecisionTraceV2{
		SchemaVersion: model.DecisionTraceSchemaV2, DecisionID: "decision-1", TickID: "tick-1", Timestamp: now.Format(time.RFC3339Nano),
		BrainImage: "registry/phorvex:sha-abc", GitSHA: "abcdef1234567890", DecisionEngine: "p1-coverage",
		PolicyNamespace: "demo", PolicyName: "policy", PolicyUID: "policy-uid", TenantName: "demo",
		AssetNamespace: "demo", AssetName: "demo-0", AssetUID: "pod-uid", Budget: 1, CandidateDemand: 1, MovesSpent: 1,
		LambdaConfiguredSeed: 0.6, LambdaRuntime: 0.6, LambdaConfiguredPolicy: 0.6, LambdaRuntimeLegacy: 0.6,
		SelectorComparator: model.SelectorStrictPositiveGain, NormWeight: 0.4, FlowWeight: 0.6,
		CFlowUnitStatus: model.CFlowUnitDimensionlessDisruptionLoss, CostRepresentationVersion: model.CostRepresentationWeightedDimensionlessV1,
		DualUpdate: model.DecisionDualUpdateV2{Applied: true, Demand: 1, Spent: 1, Budget: 1, LambdaBefore: 0.6, LambdaAfter: 0.6, UpdateReason: "exact_binding_no_update"},
		Facts:      facts,
		Candidates: []model.DecisionCandidateV2{
			{Action: string(model.ActionQuarantine), CandidateKey: "z", CoverKeys: []string{"z", "a"}, Feasible: model.OptionalBool{Present: true, Value: true}},
			{Action: string(model.ActionRotate), CandidateKey: "a", CoverKeys: []string{"b", "a"}, GrossFullValue: model.OptionalFloat{Present: true, Value: 2}, MarginalCoverage: model.OptionalFloat{Present: true, Value: 2}, Provenance: model.OptionalFloat{Present: true, Value: 0.5}, CNorm: model.OptionalFloat{Present: true, Value: 0.5}, CFlow: model.OptionalFloat{Present: true, Value: 0.5}, ExpectedCost: model.OptionalFloat{Present: true, Value: 0.5}, CostHigh: model.OptionalFloat{Present: true, Value: 0.6}, LambdaContribution: model.OptionalFloat{Present: true, Value: 0.3}, NetGain: model.OptionalFloat{Present: true, Value: 0.7}, Feasible: model.OptionalBool{Present: true, Value: true}, Selected: true, SelectionReason: "selected_strict_positive_gain"},
		},
		SelectedAction: string(model.ActionRotate), SelectedCandidateKey: "a", SelectionRound: model.OptionalInt{Present: true, Value: 1}, TieBreakReason: "strict-greater",
	}
	if !selected {
		trace.CandidateDemand, trace.MovesSpent = 0, 0
		trace.DualUpdate = model.DecisionDualUpdateV2{Applied: true, Demand: 0, Spent: 0, Budget: 1, RawExcess: -1, EffectiveExcess: -1, LambdaBefore: 0.6, LambdaAfter: 0.6, UpdateReason: "exact_binding_no_update"}
		trace.Candidates[1].Selected = false
		trace.Candidates[1].SelectionReason = ""
		trace.SelectedAction, trace.SelectedCandidateKey = string(model.ActionNoop), ""
		trace.SelectionRound = model.OptionalInt{}
		trace.TieBreakReason = "notApplicable"
		trace.NoopReason = "no feasible action"
	}
	return trace
}

func TestCaseTraceSteeredAndGenericDuplicatePrefersValidatedTrace(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	trace := caseTraceValidTrace(now.Add(2*time.Second), true, true)
	if err := trace.Validate(); err != nil {
		t.Fatalf("fixture trace invalid: %v", err)
	}
	row := audit.Record{Kind: "phorvex.decision", Time: now.Add(2 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "rotate", Selected: true,
		DecisionTrace: trace, Events: []model.EventEvidence{genericCaseEvent("event-uid", "pod-uid", "trusted")}}
	s, result := caseTraceRecord(t, now, row)
	s.fillReasoning("", result)
	if result.DecisionEvidence == nil || result.DecisionEvidence.Correlation != "exact-event-uid" ||
		result.DecisionEvidence.Source != "decision-trace-steered-event" || result.DecisionEvidence.DecisionID != "decision-1" || result.DecisionEvidence.TargetUID != "pod-uid" {
		t.Fatalf("validated steering identity was not preferred over duplicate generic evidence: %+v", result.DecisionEvidence)
	}
}

func TestCaseTraceGenericExactInputWithoutRichTraceKeepsRichIdentityUnavailable(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	row := audit.Record{Kind: "phorvex.decision", Time: now.Add(2 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "noop",
		Events: []model.EventEvidence{genericCaseEvent("event-uid", "pod-uid", "trusted")}}
	s := NewServer(Config{AuditPath: writeDecisionAudit(t, row), Now: func() time.Time { return now.Add(3 * time.Second) }})
	result := &attackRecord{FiredAt: now.Format(time.RFC3339Nano), ObservationStart: now.Format(time.RFC3339Nano), ObservationEnd: now.Add(8 * time.Second).Format(time.RFC3339Nano),
		Namespace: "demo", Pod: "demo-0", TargetUID: "pod-uid", EvidenceKind: "catalogue-signal",
		StimulusEvidence: &attackStimulusEvidence{Observed: true, TargetUID: "pod-uid", EventName: "owned-signal", EventUID: "event-uid", EventCreatedAt: now.Add(time.Second).Format(time.RFC3339Nano), EventRule: "Panic"}}
	s.fillReasoning("", result)
	if result.DecisionEvidence == nil || result.DecisionEvidence.Correlation != "exact-event-uid" || result.DecisionEvidence.Source != "generic-event-evidence" {
		t.Fatalf("generic immutable input identity was not retained: %+v", result.DecisionEvidence)
	}
	if result.DecisionEvidence.DecisionID != "" || result.DecisionEvidence.TickID != "" || result.DecisionEvidence.PolicyUID != "" || result.DecisionEvidence.BrainImage != "" || result.DecisionEvidence.GitSHA != "" {
		t.Fatalf("missing rich trace identity was invented: %+v", result.DecisionEvidence)
	}
}

func TestCaseTraceGenericEventCannotOverrideContradictoryRichTarget(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	trace := caseTraceValidTrace(now.Add(2*time.Second), false, false)
	trace.AssetUID = "other-pod-uid"
	row := audit.Record{Kind: "phorvex.decision", Time: now.Add(2 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "noop", DecisionTrace: trace,
		Events: []model.EventEvidence{genericCaseEvent("event-uid", "pod-uid", "trusted")}}
	s, result := caseTraceRecord(t, now, row)
	s.fillReasoning("", result)
	if result.DecisionEvidence != nil && result.DecisionEvidence.Correlation == "exact-event-uid" {
		t.Fatalf("generic input overrode contradictory trace target: %+v", result.DecisionEvidence)
	}
}

func TestCaseTraceIdentityAndBoundsControls(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		event  model.EventEvidence
		at     time.Time
		mutate func(*attackRecord)
		exact  bool
	}{
		{name: "untrusted exact identity remains diagnostic", event: genericCaseEvent("event-uid", "pod-uid", "untrusted-identity"), at: now.Add(2 * time.Second), exact: true},
		{name: "same name new UID", event: genericCaseEvent("other-uid", "pod-uid", "trusted"), at: now.Add(2 * time.Second)},
		{name: "wrong target", event: genericCaseEvent("event-uid", "other-pod-uid", "trusted"), at: now.Add(2 * time.Second)},
		{name: "neighbor", event: func() model.EventEvidence {
			e := genericCaseEvent("event-uid", "pod-uid", "trusted")
			e.TargetsPod = false
			return e
		}(), at: now.Add(2 * time.Second)},
		{name: "missing UID", event: genericCaseEvent("", "pod-uid", "trusted"), at: now.Add(2 * time.Second)},
		{name: "before event creation", event: genericCaseEvent("event-uid", "pod-uid", "trusted"), at: now.Add(500 * time.Millisecond)},
		{name: "after deadline", event: genericCaseEvent("event-uid", "pod-uid", "trusted"), at: now.Add(9 * time.Second)},
		{name: "missing stimulus UID", event: genericCaseEvent("event-uid", "pod-uid", "trusted"), at: now.Add(2 * time.Second), mutate: func(r *attackRecord) { r.StimulusEvidence.EventUID = "" }},
		{name: "stimulus target contradicts record", event: genericCaseEvent("event-uid", "pod-uid", "trusted"), at: now.Add(2 * time.Second), mutate: func(r *attackRecord) { r.StimulusEvidence.TargetUID = "other-pod-uid" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := audit.Record{Kind: "phorvex.decision", Time: tc.at, Namespace: "demo", Pod: "demo-0", Action: "noop", Reason: tc.name, Events: []model.EventEvidence{tc.event}}
			s, result := caseTraceRecord(t, now, row)
			if tc.mutate != nil {
				tc.mutate(result)
			}
			s.fillReasoning("", result)
			gotExact := result.DecisionEvidence != nil && result.DecisionEvidence.Correlation == "exact-event-uid"
			if gotExact != tc.exact {
				t.Fatalf("exact=%t want=%t evidence=%+v", gotExact, tc.exact, result.DecisionEvidence)
			}
			if tc.exact && result.DecisionEvidence.TrustVerdict != tc.event.TrustVerdict {
				t.Fatalf("trust verdict not retained separately: %+v", result.DecisionEvidence)
			}
		})
	}
}

func TestCaseTraceTemporalFallbackCannotExtendPersistedWindow(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	late := audit.Record{Kind: "phorvex.decision", Time: now.Add(9 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "rotate", Selected: true, Actuated: true}
	s, result := caseTraceRecord(t, now, late)
	s.fillReasoning("", result)
	if result.DecisionEvidence != nil || result.TemporalDecisionEvidence != nil {
		t.Fatalf("post-window temporal row was admitted: exact=%+v temporal=%+v", result.DecisionEvidence, result.TemporalDecisionEvidence)
	}
}

func TestCaseTraceSyntheticDetectorRetainsWeakTemporalNoop(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	row := audit.Record{Kind: "phorvex.decision", Time: now.Add(2 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "noop", Reason: "capacity refusal"}
	s, result := caseTraceRecord(t, now, row)
	result.EvidenceKind = "synthetic-detector-signal"
	result.StimulusEvidence.EventUID = "" // old manager/record: exact identity unavailable
	s.fillReasoning("", result)
	if result.DecisionEvidence == nil || result.DecisionEvidence.Correlation != "temporal-workload-noop" ||
		result.DecisionEvidence.Source != "temporal-candidate" || result.DecisionEvidence.Reason != "capacity refusal" || result.DecisionEvidence.Selected || result.DecisionEvidence.Actuated {
		t.Fatalf("weak temporal NOOP diagnostic missing or overstated: %+v", result.DecisionEvidence)
	}
}

func TestCaseTraceImmediateDecisionUsesVerifiedEventCreationBound(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	row := audit.Record{Kind: "phorvex.decision", Time: now.Add(1500 * time.Millisecond), Namespace: "demo", Pod: "demo-0", Action: "noop", Reason: "immediate", Events: []model.EventEvidence{genericCaseEvent("event-uid", "pod-uid", "trusted")}}
	s, result := caseTraceRecord(t, now, row)
	result.ObservationStart = now.Add(2 * time.Second).Format(time.RFC3339Nano)
	s.fillReasoning("", result)
	if result.DecisionEvidence == nil || result.DecisionEvidence.Correlation != "exact-event-uid" {
		t.Fatalf("decision after event creation but before record registration was lost: %+v", result.DecisionEvidence)
	}
}

func TestCaseTraceDuplicateIdentityDedupesButConflictRefusesExactMatch(t *testing.T) {
	now := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	e := genericCaseEvent("event-uid", "pod-uid", "trusted")
	row := audit.Record{Kind: "phorvex.decision", Time: now.Add(2 * time.Second), Namespace: "demo", Pod: "demo-0", Action: "noop", Events: []model.EventEvidence{e, e}}
	s, result := caseTraceRecord(t, now, row)
	s.fillReasoning("", result)
	if result.DecisionEvidence == nil || result.DecisionEvidence.Correlation != "exact-event-uid" {
		t.Fatalf("identical duplicate references lost exact identity: %+v", result.DecisionEvidence)
	}
	conflict := e
	conflict.TrustVerdict = "untrusted-identity"
	row.Events = []model.EventEvidence{e, conflict}
	s, result = caseTraceRecord(t, now, row)
	s.fillReasoning("", result)
	if result.DecisionEvidence != nil && result.DecisionEvidence.Correlation == "exact-event-uid" {
		t.Fatalf("conflicting identity metadata gained exact authority: %+v", result.DecisionEvidence)
	}
}
