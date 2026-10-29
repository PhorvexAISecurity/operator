package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

type fakeServingPreparation struct{ token string }

type fakeServingRuntime struct {
	mu             sync.Mutex
	preflightCalls int
	executeCalls   int
	cleanupCalls   int
	mutations      int
	preflightErr   error
	executeErr     error
	cleanup        servingCatalogueRuntimeCleanup
	outcome        func(AttackCatalogRunContext, servingCatalogueProfile) servingCatalogueRuntimeObservation
	waitForCancel  bool
}

func (f *fakeServingRuntime) Preflight(_ context.Context, profile servingCatalogueProfile) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.preflightCalls++
	if f.preflightErr != nil {
		return nil, f.preflightErr
	}
	return &fakeServingPreparation{token: profile.digest()}, nil
}

func (f *fakeServingRuntime) Execute(ctx context.Context, run AttackCatalogRunContext, profile servingCatalogueProfile, state any) (servingCatalogueRuntimeObservation, error) {
	f.mu.Lock()
	f.executeCalls++
	f.mutations++
	wait := f.waitForCancel
	f.mu.Unlock()
	if p, ok := state.(*fakeServingPreparation); !ok || p.token != profile.digest() {
		return servingCatalogueRuntimeObservation{}, errors.New("fake preparation changed")
	}
	if wait {
		<-ctx.Done()
		return servingCatalogueRuntimeObservation{MutationStarted: true, Reason: "cancelled"}, ctx.Err()
	}
	return f.outcome(run, profile), f.executeErr
}

func (f *fakeServingRuntime) Cleanup(_ context.Context, _ AttackCatalogRunContext, _ servingCatalogueProfile, _ any) servingCatalogueRuntimeCleanup {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanupCalls++
	return f.cleanup
}

func servingTestProfile(t *testing.T, id string) servingCatalogueProfile {
	t.Helper()
	for _, profile := range servingCatalogueProfiles() {
		if profile.CatalogueID == id {
			return profile
		}
	}
	t.Fatalf("missing serving test profile %s", id)
	return servingCatalogueProfile{}
}

func servingTestRun(t *testing.T, profile servingCatalogueProfile, runID string) AttackCatalogRunContext {
	t.Helper()
	entry, ok := attackcatalog.Lookup(profile.CatalogueID)
	if !ok {
		t.Fatalf("missing embedded entry %s", profile.CatalogueID)
	}
	return AttackCatalogRunContext{RunID: runID, CatalogueID: profile.CatalogueID,
		ExpectedAction: entry.ExpectedAction, ReactiveCompatible: entry.ReactiveCompatible}
}

func servingReceiptObjects(profile servingCatalogueProfile) []string {
	switch profile.Family {
	case servingRateFamily:
		return []string{"configmap/" + profile.Namespace + "/phorvex-serving-rate-budget"}
	case sensitiveOutputFamily:
		return []string{profile.Namespace + "/" + profile.ConfigMapName}
	default:
		return []string{"Pod/" + profile.Namespace + "/kv-serving-0"}
	}
}

func positiveServingOutcome(run AttackCatalogRunContext, profile servingCatalogueProfile) servingCatalogueRuntimeObservation {
	signalUID := "11111111-1111-4111-8111-111111111111"
	targetUID := "22222222-2222-4222-8222-222222222222"
	o := servingCatalogueRuntimeObservation{
		MutationStarted: true,
		Launched:        true,
		Signal: servingCatalogueSignal{Created: true, Observed: true, Name: "signal-" + run.RunID,
			UID: signalUID, Creator: "system:serviceaccount:test:detector", TargetUID: targetUID},
		Decision: servingCatalogueDecision{Observed: true, Selected: true, Feasible: true, Actuated: true,
			ID: "decision-" + run.RunID, Action: profile.ExpectedAction, DispatchOutcome: "emitted",
			Handler: profile.ExpectedAction, ObjectsTouched: servingReceiptObjects(profile)},
		Reason: "positive family oracle",
	}
	switch profile.Family {
	case servingRateFamily:
		o.Rate = &servingRatePhysical{OperationID: "op-rate", Baseline: 2, ElapsedSeconds: 10,
			AbusiveAttempted: 1000, AbusiveAdmitted: 5, AbusiveRejected: 995,
			LegitimateAttempted: 30, LegitimateAdmitted: 30, CapApplied: true, ProxyIdentityUnchanged: true}
	case sensitiveOutputFamily:
		digest := sha256.Sum256([]byte("test-only-private-marker-that-must-never-be-serialized"))
		benignDigest := sha256.Sum256([]byte("test-only-benign-response"))
		o.Sensitive = &sensitiveOutputPhysical{ConfigMapUID: "33333333-3333-4333-8333-333333333333",
			PolicyUID: "44444444-4444-4444-8444-444444444444", OperationID: "op-output",
			MarkerSHA256: hex.EncodeToString(digest[:]), PolicyGeneration: 1, Revision: 1,
			BenignSHA256Before: hex.EncodeToString(benignDigest[:]), BenignSHA256After: hex.EncodeToString(benignDigest[:]),
			BaselineLeaked: true, ConfigMapActive: true, ProxyActive: true, Redacted: true, PodRetained: true}
	case servingKVFamily:
		o.KV = &servingKVPhysical{BystanderUID: "55555555-5555-4555-8555-555555555555",
			BaselineResetCount: 2, AfterResetCount: 3, TargetImplantBefore: true,
			TargetRetained: true, BystanderImplantRetained: true, BystanderRetained: true,
			AvailableReplicas: 2, DesiredReplicas: 2}
	}
	return o
}

func newPositiveServingAdapter(t *testing.T, id string) (*servingCatalogueAdapter, *fakeServingRuntime, AttackCatalogRunContext) {
	t.Helper()
	profile := servingTestProfile(t, id)
	runtime := &fakeServingRuntime{outcome: positiveServingOutcome,
		cleanup: servingCatalogueRuntimeCleanup{Attempted: true, EventDeleted: true, MarkerDeleted: true,
			Restored: true, RetrySafe: true, Reason: "verified"}}
	adapter := newServingCatalogueAdapterForTest(profile, Config{}, runtime).(*servingCatalogueAdapter)
	return adapter, runtime, servingTestRun(t, profile, "cat-test-1")
}

func executeServingTestResult(t *testing.T, adapter *servingCatalogueAdapter, run AttackCatalogRunContext) AttackCatalogResult {
	t.Helper()
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	started := time.Now().UTC()
	observation, err := adapter.Execute(context.Background(), run, prepared)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	result := AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: run.CatalogueID,
		RunID: run.RunID, Visible: true, Available: true, Launched: observation.Launched,
		ReactiveOnly: true, ExecutionMode: prepared.ExecutionMode(), TriggerMode: prepared.TriggerMode(),
		ExpectedAction: run.ExpectedAction, StartedAt: started, Signal: observation.Signal,
		Decision: observation.Decision, Actuator: observation.Actuator,
		PhysicalValidation: observation.PhysicalValidation}
	result.Cleanup = adapter.Cleanup(context.Background(), run, prepared)
	result.finishVerdict(adapter, observation.Reason)
	return result
}

func servingDecisionAuditFixture(profile servingCatalogueProfile) (audit.Record, *servingCatalogueKubePreparation, servingCatalogueSignal) {
	now := time.Now().UTC()
	creator := eventtrust.Injector()
	if profile.Family == servingRateFamily {
		creator = "system:serviceaccount:" + profile.Namespace + ":rate-detector"
	}
	p := &servingCatalogueKubePreparation{
		policy:    servingPolicyPin{UID: "policy-uid", Generation: 1},
		target:    servingPodPin{Name: "target-0", UID: "target-uid"},
		runID:     "serving-decision-run",
		startedAt: now.Add(-time.Second),
	}
	signal := servingCatalogueSignal{
		Created:   true,
		Name:      "serving-signal",
		UID:       "signal-uid",
		Creator:   creator,
		TargetUID: p.target.UID,
		CreatedAt: now.Add(-500 * time.Millisecond),
	}
	row := audit.Record{
		Kind: "phorvex.decision", Time: now, Namespace: profile.Namespace, Pod: p.target.Name,
		Action: profile.ExpectedAction, Selected: true, Feasible: true, Actuated: true,
		DispatchOutcome: model.DispatchEmitted, Handler: profile.ExpectedAction,
		ObjectsTouched: servingReceiptObjects(profile),
		DecisionTrace: &model.DecisionTraceV2{
			DecisionID: "serving-decision", PolicyNamespace: profile.Namespace,
			PolicyName: profile.PolicyName, PolicyUID: p.policy.UID, AssetUID: p.target.UID,
			SelectedAction: profile.ExpectedAction, DispatchOutcome: model.DispatchEmitted,
		},
		Events: []model.EventEvidence{{
			Name: signal.Name, EventUID: signal.UID, Type: profile.EventType,
			CreatorIdentity: creator, TargetPodUID: p.target.UID, TrustVerdict: "trusted",
			TargetsPod: true, TimestampPresent: true, AgeSec: 0.5,
		}},
	}
	return row, p, signal
}

func TestServingCatalogueDecisionRequiresConsistentActiveEmittedReceipt(t *testing.T) {
	for _, profile := range servingCatalogueProfiles() {
		t.Run(profile.CatalogueID+"/strict-positive", func(t *testing.T) {
			row, prepared, signal := servingDecisionAuditFixture(profile)
			matchedSignal, decision, ok := matchServingDecision(row, profile, prepared, signal)
			if !ok || !matchedSignal.Observed || !decision.Actuated || decision.DispatchOutcome != model.DispatchEmitted {
				t.Fatalf("consistent active emitted decision rejected: signal=%+v decision=%+v matched=%t", matchedSignal, decision, ok)
			}
		})
	}

	profile := servingTestProfile(t, "AML.T0034")
	tests := []struct {
		name   string
		mutate func(*audit.Record)
	}{
		{
			name: "top-level-active-trace-dry-run",
			mutate: func(row *audit.Record) {
				row.DryRun = false
				row.DecisionTrace.DryRun = true
			},
		},
		{
			name: "top-level-dry-run-trace-active",
			mutate: func(row *audit.Record) {
				row.DryRun = true
				row.DecisionTrace.DryRun = false
			},
		},
		{
			name: "top-level-emitted-trace-non-emitted",
			mutate: func(row *audit.Record) {
				row.DispatchOutcome = model.DispatchEmitted
				row.DecisionTrace.DispatchOutcome = model.DispatchError
			},
		},
		{
			name: "top-level-non-emitted-trace-emitted",
			mutate: func(row *audit.Record) {
				row.DispatchOutcome = model.DispatchRefused
				row.DecisionTrace.DispatchOutcome = model.DispatchEmitted
			},
		},
		{
			name: "missing-dispatch",
			mutate: func(row *audit.Record) {
				row.DispatchOutcome = ""
				row.DecisionTrace.DispatchOutcome = ""
			},
		},
		{
			name: "accepted-receipt-contradicts-rejected-dispatch",
			mutate: func(row *audit.Record) {
				row.Actuated = true
				row.DispatchOutcome = model.DispatchRefused
				row.DecisionTrace.DispatchOutcome = model.DispatchRefused
			},
		},
		{
			name: "stale-decision",
			mutate: func(row *audit.Record) {
				row.Time = time.Time{}
			},
		},
		{
			name: "foreign-run-signal",
			mutate: func(row *audit.Record) {
				row.Events[0].Name = "other-run-signal"
				row.Events[0].EventUID = "other-run-uid"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row, prepared, signal := servingDecisionAuditFixture(profile)
			tt.mutate(&row)
			if matchedSignal, decision, ok := matchServingDecision(row, profile, prepared, signal); ok {
				t.Fatalf("inconsistent decision became receipt candidate: signal=%+v decision=%+v", matchedSignal, decision)
			}
		})
	}
}

func TestServingCatalogueAdapterRejectsContradictoryAcceptedReceipt(t *testing.T) {
	adapter, runtime, run := newPositiveServingAdapter(t, "AML.T0034")
	runtime.outcome = func(run AttackCatalogRunContext, profile servingCatalogueProfile) servingCatalogueRuntimeObservation {
		observation := positiveServingOutcome(run, profile)
		observation.Decision.Actuated = true
		observation.Decision.DispatchOutcome = model.DispatchRefused
		return observation
	}
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := adapter.Execute(context.Background(), run, prepared)
	if err == nil || observation.Actuator.ReceiptObserved || observation.Actuator.AcceptedAt != nil || observation.DefensiveChainComplete {
		t.Fatalf("contradictory rejected dispatch became accepted: observation=%+v err=%v", observation, err)
	}
}

func TestServingCatalogueExactCoverage(t *testing.T) {
	profiles := servingCatalogueProfiles()
	if len(profiles) != 26 {
		t.Fatalf("profile count=%d want 26", len(profiles))
	}
	wantFamilies := map[string]int{servingRateFamily: 20, sensitiveOutputFamily: 3, servingKVFamily: 3}
	gotFamilies := map[string]int{}
	gotIDs := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		if err := profile.validate(); err != nil {
			t.Fatalf("profile %s: %v", profile.CatalogueID, err)
		}
		gotFamilies[profile.Family]++
		gotIDs = append(gotIDs, profile.CatalogueID)
	}
	if !mapsEqual(gotFamilies, wantFamilies) {
		t.Fatalf("family counts=%v want=%v", gotFamilies, wantFamilies)
	}
	entries, err := attackcatalog.Entries()
	if err != nil {
		t.Fatalf("load embedded attack catalogue: %v", err)
	}
	wantIDs := []string{}
	for _, entry := range entries {
		if _, ok := wantFamilies[entry.Family]; ok {
			wantIDs = append(wantIDs, entry.ID)
		}
	}
	slices.Sort(gotIDs)
	slices.Sort(wantIDs)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("serving adapter IDs differ\ngot=%v\nwant=%v", gotIDs, wantIDs)
	}
	adapters := newServingCatalogueAdapters()
	if len(adapters) != len(profiles) {
		t.Fatalf("adapter count=%d want=%d", len(adapters), len(profiles))
	}
	for _, adapter := range adapters {
		if adapter.Availability().Available {
			t.Fatalf("unbound adapter %s unexpectedly available", adapter.CatalogueID())
		}
	}
}

func mapsEqual(got, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func TestServingCatalogueSensitiveEvidenceRedactsRawValue(t *testing.T) {
	adapter, _, run := newPositiveServingAdapter(t, "AML.T0069")
	result := executeServingTestResult(t, adapter, run)
	if result.Verdict != "DEFENDED" {
		t.Fatalf("verdict=%s reason=%s", result.Verdict, result.Reason)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	secret := "test-only-private-marker-that-must-never-be-serialized"
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "internalAuditMarker") {
		t.Fatalf("raw sensitive output escaped into result: %s", raw)
	}
	if !strings.Contains(string(raw), "markerSHA256") || !strings.Contains(string(raw), "redacted") {
		t.Fatalf("sanitized evidence missing: %s", raw)
	}
}

func TestServingCatalogueWrongIDIsolation(t *testing.T) {
	adapter, runtime, run := newPositiveServingAdapter(t, "AML.T0069")
	run.CatalogueID = "AML.T0069.001"
	if _, err := adapter.Preflight(context.Background(), run); err == nil {
		t.Fatal("wrong ID reached preflight runtime")
	}
	if runtime.preflightCalls != 0 {
		t.Fatalf("wrong ID invoked runtime %d times", runtime.preflightCalls)
	}

	adapterA, runtimeA, runA := newPositiveServingAdapter(t, "AML.T0080")
	prepared, err := adapterA.Preflight(context.Background(), runA)
	if err != nil {
		t.Fatal(err)
	}
	otherRun := runA
	otherRun.RunID = "cat-test-other-run"
	if _, err = adapterA.Execute(context.Background(), otherRun, prepared); err == nil {
		t.Fatal("preparation from another run of the same exact ID was accepted")
	}
	if runtimeA.executeCalls != 0 {
		t.Fatal("foreign run reached runtime")
	}
	adapterB, runtimeB, runB := newPositiveServingAdapter(t, "AML.T0080.001")
	if _, err = adapterB.Execute(context.Background(), runB, prepared); err == nil {
		t.Fatal("preparation from another exact ID was accepted")
	}
	if runtimeB.executeCalls != 0 {
		t.Fatal("foreign preparation reached runtime")
	}
}

func TestServingCataloguePreflightDoesNotMutateAndModesStayDistinct(t *testing.T) {
	adapter, runtime, run := newPositiveServingAdapter(t, "AML.T0034")
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.preflightCalls != 1 || runtime.executeCalls != 0 || runtime.mutations != 0 {
		t.Fatalf("preflight calls/mutations=%d/%d/%d", runtime.preflightCalls, runtime.executeCalls, runtime.mutations)
	}
	if prepared.ExecutionMode() != AttackCatalogExecutionActive || prepared.TriggerMode() != AttackCatalogTriggerReactive ||
		prepared.ExecutionMode() == AttackCatalogExecutionMode(prepared.TriggerMode()) {
		t.Fatalf("execution and trigger modes collapsed: %q/%q", prepared.ExecutionMode(), prepared.TriggerMode())
	}
}

func TestServingCatalogueFamilyOraclesPositiveAndNegative(t *testing.T) {
	for _, id := range []string{"AML.T0034", "AML.T0069", "AML.T0080"} {
		t.Run(id+"/positive", func(t *testing.T) {
			adapter, _, run := newPositiveServingAdapter(t, id)
			result := executeServingTestResult(t, adapter, run)
			if result.Verdict != "DEFENDED" || !result.PhysicalValidation.Validated {
				t.Fatalf("result=%+v", result)
			}
		})
		t.Run(id+"/negative", func(t *testing.T) {
			adapter, runtime, run := newPositiveServingAdapter(t, id)
			runtime.outcome = func(run AttackCatalogRunContext, profile servingCatalogueProfile) servingCatalogueRuntimeObservation {
				o := positiveServingOutcome(run, profile)
				switch profile.Family {
				case servingRateFamily:
					o.Rate.LegitimateRejected = 1
				case sensitiveOutputFamily:
					o.Sensitive.Redacted = false
				case servingKVFamily:
					o.KV.TargetImplantAfter = true
				}
				return o
			}
			prepared, err := adapter.Preflight(context.Background(), run)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := adapter.Execute(context.Background(), run, prepared)
			if err == nil || observation.PhysicalValidation.Validated || observation.DefensiveChainComplete {
				t.Fatalf("negative oracle was accepted: observation=%+v err=%v", observation, err)
			}
		})
	}
}

func TestServingCatalogueCleanupControlsRetrySafety(t *testing.T) {
	adapter, runtime, run := newPositiveServingAdapter(t, "AML.T0080")
	result := executeServingTestResult(t, adapter, run)
	if !result.Cleanup.Verified || result.UnsafeToRetry || runtime.cleanupCalls != 1 {
		t.Fatalf("verified cleanup result=%+v calls=%d", result, runtime.cleanupCalls)
	}

	adapter, runtime, run = newPositiveServingAdapter(t, "AML.T0080")
	runtime.cleanup.Restored = false
	result = executeServingTestResult(t, adapter, run)
	if result.Cleanup.Verified || !result.UnsafeToRetry || result.Verdict == "DEFENDED" {
		t.Fatalf("unverified cleanup result=%+v", result)
	}
}

func TestServingCatalogueCancellationStillAllowsExactCleanup(t *testing.T) {
	adapter, runtime, run := newPositiveServingAdapter(t, "AML.T0034")
	runtime.waitForCancel = true
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = adapter.Execute(ctx, run, prepared); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation err=%v", err)
	}
	cleanup := adapter.Cleanup(context.Background(), run, prepared)
	if !cleanup.Verified || runtime.cleanupCalls != 1 {
		t.Fatalf("post-cancel cleanup=%+v calls=%d", cleanup, runtime.cleanupCalls)
	}
}

func TestServingCatalogueStrictResultBinding(t *testing.T) {
	adapter, _, run := newPositiveServingAdapter(t, "AML.T0069.002")
	result := executeServingTestResult(t, adapter, run)
	if err := adapter.ValidateDefended(result); err != nil {
		t.Fatalf("positive result rejected: %v", err)
	}
	for name, mutate := range map[string]func(*AttackCatalogResult){
		"run":      func(r *AttackCatalogResult) { r.RunID = "other-run" },
		"signal":   func(r *AttackCatalogResult) { r.Signal.UID = "other-signal" },
		"decision": func(r *AttackCatalogResult) { r.Decision.ID = "other-decision" },
		"target":   func(r *AttackCatalogResult) { r.Signal.TargetUID = "other-target" },
		"handler":  func(r *AttackCatalogResult) { r.Actuator.Handler = "kv-reset" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := result
			mutate(&changed)
			if err := adapter.ValidateDefended(changed); err == nil {
				t.Fatal("substituted result binding accepted")
			}
		})
	}
	other, _, _ := newPositiveServingAdapter(t, "AML.T0069.001")
	if err := other.ValidateDefended(result); err == nil {
		t.Fatal("another exact-ID adapter accepted the result")
	}
}
