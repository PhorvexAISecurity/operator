package console

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

var infraExpectedIDs = map[string][]string{
	infraFamilyNetworkEdge: {
		"AML.T0096", "AML.T0108", "AML.T0114", "AML.T0132", "ASI07:2026",
		"MS-DI-access-kubelet-api", "MS-DI-instance-metadata-api", "MS-IN-exposed-sensitive-inte", "T1552.005",
	},
	infraFamilyDatastore: {
		"AML.T0070", "AML.T0080.000", "AML.T0099", "ASI06:2026", "LLM08:2025",
	},
	infraFamilyImage: {
		"registry-rollback", "aml.t0010", "aml.t0010.001", "aml.t0010.002", "aml.t0010.003", "aml.t0010.004",
		"aml.t0010.005", "aml.t0018", "aml.t0018.000", "aml.t0018.001", "aml.t0018.002", "aml.t0031", "aml.t0076",
		"aml.t0109", "aml.t0110.001", "aml.t0115", "aml.t0115.000", "aml.t0115.001", "aml.t0115.002",
		"asi04-2026", "llm03-2025", "llm04-2025", "mcp04-2025", "ms-in-compromised-image-in-r",
		"t1204.003", "t1204.005", "t1525",
	},
	infraFamilyNodeRecycle: {
		"AML.T0105", "AML.T0112", "AML.T0112.000", "AML.T0112.001", "MS-PE-static-pods",
		"MS-PE-writable-hostpath-moun", "MS-PR-privileged-container", "T1543.002", "T1611", "T1612", "T1685.004", "T1685.006",
	},
}

func TestInfraCatalogueCoverageAndExactMembership(t *testing.T) {
	profiles := infraCatalogueProfiles()
	if len(profiles) != 53 {
		t.Fatalf("profile count = %d, want 53", len(profiles))
	}
	adapters := newInfraCatalogueAdapters(nil, Config{})
	if len(adapters) != len(profiles) {
		t.Fatalf("adapter count = %d, want %d", len(adapters), len(profiles))
	}

	want := map[string]map[string]bool{}
	for family, ids := range infraExpectedIDs {
		want[family] = map[string]bool{}
		for _, id := range ids {
			want[family][id] = true
		}
	}
	seen := map[string]bool{}
	got := map[string]map[string]bool{}
	for _, profile := range profiles {
		if err := profile.validate(); err != nil {
			t.Fatalf("profile %q: %v", profile.ID, err)
		}
		if seen[profile.ID] {
			t.Fatalf("duplicate profile %q", profile.ID)
		}
		seen[profile.ID] = true
		if got[profile.Family] == nil {
			got[profile.Family] = map[string]bool{}
		}
		got[profile.Family][profile.ID] = true
	}
	for i, adapter := range adapters {
		if adapter.CatalogueID() != profiles[i].ID {
			t.Fatalf("adapter %d ID = %q, want %q", i, adapter.CatalogueID(), profiles[i].ID)
		}
	}
	registry := NewAttackCatalogAdapterRegistry()
	for _, adapter := range adapters {
		if err := registry.Register(adapter); err != nil {
			t.Fatalf("register %q: %v", adapter.CatalogueID(), err)
		}
	}
	for _, profile := range profiles {
		if adapter, ok := registry.Lookup(profile.ID); !ok || adapter.CatalogueID() != profile.ID {
			t.Fatalf("exact lookup failed for %q", profile.ID)
		}
		if _, ok := registry.Lookup(" " + profile.ID); ok {
			t.Fatalf("whitespace lookup alias accepted for %q", profile.ID)
		}
	}
	if _, ok := registry.Lookup("aml.t0096"); ok {
		t.Fatal("wrong-case lookup alias was accepted")
	}
	for family, ids := range want {
		if len(got[family]) != len(ids) {
			t.Fatalf("%s count = %d, want %d", family, len(got[family]), len(ids))
		}
		for id := range ids {
			if !got[family][id] {
				t.Errorf("%s is missing exact ID %q", family, id)
			}
		}
	}

	entries, err := attackcatalog.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		ids, isInfra := want[entry.Family]
		if isInfra != seen[entry.ID] || (isInfra && !ids[entry.ID]) {
			t.Errorf("catalogue membership mismatch for %s/%s", entry.Family, entry.ID)
		}
	}
}

func TestInfraCatalogueRejectsWrongIDAndFixedProfile(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyNetworkEdge)
	tampered := profile
	tampered.ForbiddenEdges = []string{"imds"}
	if err := tampered.validate(); err == nil {
		t.Fatal("tampered fixed profile was accepted")
	}
	tampered = profile
	tampered.ID = "aml.t0096"
	if err := tampered.validate(); err == nil {
		t.Fatal("wrong-case catalogue ID was accepted")
	}

	runtime := infraTestRuntimeFor(t, profile)
	adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: runtime}
	badRuns := []AttackCatalogRunContext{
		{CatalogueID: profile.ID, ExpectedAction: profile.ExpectedAction},
		{CatalogueID: "AML.T0108", ExpectedAction: profile.ExpectedAction},
		{CatalogueID: profile.ID, ExpectedAction: "registry-rollback"},
	}
	for _, run := range badRuns {
		if _, err := adapter.Preflight(context.Background(), run); err == nil {
			t.Fatalf("wrong run binding was accepted: %+v", run)
		}
	}
	if runtime.prepareCalls != 0 {
		t.Fatalf("wrong binding reached preflight runtime %d times", runtime.prepareCalls)
	}

	runtime.fixture.ReceiptObjects = []string{"NetworkPolicy/p2-demo/not-the-bound-target"}
	if _, err := adapter.Preflight(context.Background(), infraTestRun(profile)); err == nil {
		t.Fatal("wrong preflight receipt object was accepted")
	}
	runtime = infraTestRuntimeFor(t, profile)
	runtime.fixture.PolicyName = "different-policy"
	adapter.fixedRuntime = runtime
	if _, err := adapter.Preflight(context.Background(), infraTestRun(profile)); err == nil {
		t.Fatal("wrong fixed policy was accepted")
	}
}

func TestInfraCatalogueExecutionAndTriggerModesRemainSeparate(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyDatastore)
	for _, test := range []struct {
		name     string
		reactive bool
		trigger  AttackCatalogTriggerMode
	}{
		{name: "proactive-and-reactive", trigger: AttackCatalogTriggerProactiveReactive},
		{name: "reactive-only", reactive: true, trigger: AttackCatalogTriggerReactive},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := infraTestRuntimeFor(t, profile)
			runtime.fixture.ReactiveOnly = test.reactive
			adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: runtime}
			prepared, err := adapter.Preflight(context.Background(), infraTestRun(profile))
			if err != nil {
				t.Fatal(err)
			}
			if prepared.ExecutionMode() != AttackCatalogExecutionActive || prepared.TriggerMode() != test.trigger {
				t.Fatalf("modes = %s/%s, want active/%s", prepared.ExecutionMode(), prepared.TriggerMode(), test.trigger)
			}
		})
	}
}

func TestInfraCataloguePreflightDoesNotMutate(t *testing.T) {
	for family := range infraExpectedIDs {
		t.Run(family, func(t *testing.T) {
			profile := infraTestProfile(t, family)
			runtime := infraTestRuntimeFor(t, profile)
			adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: runtime}
			prepared, err := adapter.Preflight(context.Background(), infraTestRun(profile))
			if err != nil {
				t.Fatal(err)
			}
			if prepared.ExecutionMode() != AttackCatalogExecutionActive || prepared.EvidenceTenant() != profile.Namespace {
				t.Fatal("preflight returned changed execution mode or tenant")
			}
			if runtime.prepareCalls != 1 || runtime.armCalls != 0 || runtime.signalCalls != 0 || runtime.physicalCalls != 0 || runtime.cleanupCalls != 0 {
				t.Fatalf("preflight call counts show mutation: %+v", runtime)
			}
		})
	}
}

func TestInfraCatalogueFamilyOraclesPositiveAndNegative(t *testing.T) {
	for family := range infraExpectedIDs {
		t.Run(family, func(t *testing.T) {
			profile := infraTestProfile(t, family)
			positive := infraTestPhysical(profile)
			if err := validateInfraPhysicalEvidence(profile, positive); err != nil {
				t.Fatalf("positive oracle rejected: %v", err)
			}
			negative := infraTestNegativePhysical(profile)
			if err := validateInfraPhysicalEvidence(profile, negative); err == nil {
				t.Fatal("negative physical evidence was accepted")
			}
			wrongOracle := positive
			wrongOracle.Oracle = "synthetic-oracle"
			if err := validateInfraPhysicalEvidence(profile, wrongOracle); err == nil {
				t.Fatal("wrong oracle identity was accepted")
			}
		})
	}
}

func TestInfraCatalogueExecutionCompletesEachFamily(t *testing.T) {
	for family := range infraExpectedIDs {
		t.Run(family, func(t *testing.T) {
			profile := infraTestProfile(t, family)
			runtime := infraTestRuntimeFor(t, profile)
			runtime.physical = infraTestPhysical(profile)
			adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: runtime,
				cfg: Config{AttackCatalogPollInterval: time.Millisecond}}
			adapter.records = func(context.Context) ([]audit.Record, error) {
				return []audit.Record{infraTestDecisionRecord(profile, runtime.fixture, runtime.arm, runtime.signal)}, nil
			}
			prepared, err := adapter.Preflight(context.Background(), infraTestRun(profile))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			observation, err := adapter.Execute(ctx, infraTestRun(profile), prepared)
			if err != nil {
				t.Fatal(err)
			}
			if !observation.Launched || !observation.Signal.Observed || !observation.Actuator.ReceiptObserved ||
				!observation.PhysicalValidation.Validated || !observation.DefensiveChainComplete {
				t.Fatalf("defensive chain incomplete: %+v", observation)
			}
		})
	}
}

func TestInfraCatalogueCleanupIsDelegatedAndRetrySafe(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyDatastore)
	runtime := infraTestRuntimeFor(t, profile)
	adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: runtime}
	prepared, err := adapter.Preflight(context.Background(), infraTestRun(profile))
	if err != nil {
		t.Fatal(err)
	}
	state := prepared.(*infraCataloguePreparation)
	state.arm, state.signal = runtime.arm, runtime.signal
	for i := 0; i < 2; i++ {
		cleanup := adapter.Cleanup(context.Background(), infraTestRun(profile), prepared)
		if !cleanup.Attempted || !cleanup.EventDeleted || !cleanup.MarkerDeleted || !cleanup.Verified {
			t.Fatalf("cleanup attempt %d was not verified: %+v", i+1, cleanup)
		}
	}
	if runtime.cleanupCalls != 2 {
		t.Fatalf("cleanup calls = %d, want 2", runtime.cleanupCalls)
	}
}

func TestInfraCatalogueCleanupReconcilesLostEventCreateAcknowledgement(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyNetworkEdge)
	state := infraTestRuntimeFor(t, profile)
	newRuntime := func(correlation string) *kubernetesInfraCatalogueRuntime {
		event := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
			"metadata": map[string]any{"name": state.signal.Name,
				"labels": map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": profile.ID},
				"annotations": map[string]any{"phorvex.ai/creator-identity": profile.creator(),
					attackCatalogCorrelationAnnotation: correlation, model.ConsoleTargetPodUIDAnnotation: state.arm.TargetUID}},
			"spec": map[string]any{"targets": []any{state.fixture.Namespace + "/" + state.arm.TargetName},
				"rule": map[string]any{"type": profile.EventType}},
		}}
		event.SetUID(types.UID("event-uid"))
		return &kubernetesInfraCatalogueRuntime{dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), event)}
	}
	signal := infraCatalogueSignal{Name: state.signal.Name, RunID: state.signal.RunID}

	kubeRuntime := newRuntime(signal.RunID)
	if !kubeRuntime.cleanupEvent(context.Background(), profile, state.fixture, state.arm, signal) {
		t.Fatal("exact event from lost create acknowledgement was not cleaned")
	}
	if _, err := kubeRuntime.dynamic.Resource(securityEventGVR).Get(context.Background(), signal.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("event remained after cleanup: %v", err)
	}
	if !kubeRuntime.cleanupEvent(context.Background(), profile, state.fixture, state.arm, signal) {
		t.Fatal("idempotent event cleanup retry failed")
	}

	kubeRuntime = newRuntime("another-run")
	if kubeRuntime.cleanupEvent(context.Background(), profile, state.fixture, state.arm, signal) {
		t.Fatal("cleanup deleted an event with a different correlation")
	}
	if _, err := kubeRuntime.dynamic.Resource(securityEventGVR).Get(context.Background(), signal.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("differently bound event was not preserved: %v", err)
	}
}

func TestInfraCatalogueExecutionHonorsCancellation(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyNetworkEdge)
	t.Run("during-arm", func(t *testing.T) {
		runtime := infraTestRuntimeFor(t, profile)
		runtime.blockArm = true
		adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: runtime}
		prepared, err := adapter.Preflight(context.Background(), infraTestRun(profile))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = adapter.Execute(ctx, infraTestRun(profile), prepared)
		if !errors.Is(err, context.Canceled) || runtime.signalCalls != 0 {
			t.Fatalf("arm cancellation = %v, signal calls = %d", err, runtime.signalCalls)
		}
	})
	t.Run("while-observing", func(t *testing.T) {
		runtime := infraTestRuntimeFor(t, profile)
		adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: runtime,
			cfg: Config{AttackCatalogPollInterval: time.Millisecond}}
		adapter.records = func(context.Context) ([]audit.Record, error) { return nil, nil }
		prepared, err := adapter.Preflight(context.Background(), infraTestRun(profile))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		observation, err := adapter.Execute(ctx, infraTestRun(profile), prepared)
		if err != nil || !observation.Launched || observation.DefensiveChainComplete || observation.Signal.Observed {
			t.Fatalf("observation cancellation result = %+v, err = %v", observation, err)
		}
	})
}

func TestInfraCatalogueDecisionRequiresFreshExactBinding(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyImage)
	runtime := infraTestRuntimeFor(t, profile)
	record := func() audit.Record {
		return infraTestDecisionRecord(profile, runtime.fixture, runtime.arm, runtime.signal)
	}
	observed, _, actuator := infraCatalogueDecision(record(), profile, runtime.fixture, runtime.arm, runtime.signal)
	if !observed || !actuator.ReceiptObserved {
		t.Fatal("exact decision fixture was not accepted")
	}

	rejected := map[string]func(*audit.Record){
		"stale":            func(r *audit.Record) { r.Time = runtime.signal.CreatedAt.Add(-time.Nanosecond) },
		"wrong-pod":        func(r *audit.Record) { r.Pod = "other-pod" },
		"dry-run":          func(r *audit.Record) { r.DryRun = true },
		"wrong-policy":     func(r *audit.Record) { r.DecisionTrace.PolicyUID = "other-policy" },
		"wrong-target":     func(r *audit.Record) { r.DecisionTrace.AssetUID = "other-target" },
		"missing-dispatch": func(r *audit.Record) { r.DispatchOutcome = "" },
		"wrong-event-uid":  func(r *audit.Record) { r.Events[0].EventUID = "other-event" },
		"wrong-creator":    func(r *audit.Record) { r.Events[0].CreatorIdentity = "system:serviceaccount:other:other" },
		"duplicate-event":  func(r *audit.Record) { r.Events = append(r.Events, r.Events[0]) },
	}
	for name, mutate := range rejected {
		t.Run(name, func(t *testing.T) {
			row := record()
			mutate(&row)
			observed, _, actuator := infraCatalogueDecision(row, profile, runtime.fixture, runtime.arm, runtime.signal)
			if observed || actuator.ReceiptObserved {
				t.Fatalf("non-exact decision accepted: %+v", row)
			}
		})
	}
	noReceipt := map[string]func(*audit.Record){
		"wrong-handler": func(r *audit.Record) { r.Handler = "different-handler" },
		"wrong-object":  func(r *audit.Record) { r.ObjectsTouched = []string{"Deployment/p3-demo/other"} },
		"not-actuated":  func(r *audit.Record) { r.Actuated = false },
	}
	for name, mutate := range noReceipt {
		t.Run(name, func(t *testing.T) {
			row := record()
			mutate(&row)
			observed, _, actuator := infraCatalogueDecision(row, profile, runtime.fixture, runtime.arm, runtime.signal)
			if !observed || actuator.ReceiptObserved {
				t.Fatalf("receipt binding result observed=%t receipt=%t", observed, actuator.ReceiptObserved)
			}
		})
	}
}

func TestInfraCatalogueValidateDefendedIsStrict(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyImage)
	adapter := &infraAttackCatalogAdapter{profile: profile}
	result := AttackCatalogResult{
		CatalogueID: profile.ID, ExpectedAction: profile.ExpectedAction, ExecutionMode: AttackCatalogExecutionActive,
		Signal:             AttackCatalogSignalResult{TargetUID: "target-uid"},
		Actuator:           AttackCatalogActuatorResult{Handler: profile.ExpectedAction, ObjectsTouched: adapter.receiptObjects("target-uid")},
		PhysicalValidation: infraTestPhysical(profile),
		Cleanup:            AttackCatalogCleanupResult{EventDeleted: true, MarkerDeleted: true},
	}
	if err := adapter.ValidateDefended(result); err != nil {
		t.Fatalf("exact result rejected: %v", err)
	}
	cases := map[string]func(*AttackCatalogResult){
		"wrong-id":      func(r *AttackCatalogResult) { r.CatalogueID = "aml.t0010.001" },
		"dry-run":       func(r *AttackCatalogResult) { r.ExecutionMode = AttackCatalogExecutionDryRun },
		"wrong-handler": func(r *AttackCatalogResult) { r.Actuator.Handler = "other" },
		"wrong-receipt": func(r *AttackCatalogResult) { r.Actuator.ObjectsTouched = []string{"other"} },
		"bad-oracle":    func(r *AttackCatalogResult) { r.PhysicalValidation = infraTestNegativePhysical(profile) },
		"dirty-cleanup": func(r *AttackCatalogResult) { r.Cleanup.MarkerDeleted = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := result
			mutate(&changed)
			if err := adapter.ValidateDefended(changed); err == nil {
				t.Fatal("non-exact defended result was accepted")
			}
		})
	}
}

type infraTestRuntime struct {
	fixture  infraCatalogueFixture
	arm      infraCatalogueArm
	signal   infraCatalogueSignal
	physical AttackCatalogPhysicalResult
	cleanup  AttackCatalogCleanupResult

	prepareCalls, armCalls, signalCalls, physicalCalls, cleanupCalls int
	blockArm                                                         bool
}

func (f *infraTestRuntime) Prepare(context.Context, infraCatalogueProfile) (infraCatalogueFixture, error) {
	f.prepareCalls++
	return f.fixture, nil
}

func (f *infraTestRuntime) Arm(ctx context.Context, _ infraCatalogueProfile, _ infraCatalogueFixture) (infraCatalogueArm, error) {
	f.armCalls++
	if f.blockArm {
		<-ctx.Done()
		return infraCatalogueArm{}, ctx.Err()
	}
	return f.arm, nil
}

func (f *infraTestRuntime) CreateSignal(context.Context, infraCatalogueProfile, infraCatalogueFixture, infraCatalogueArm, string) (infraCatalogueSignal, error) {
	f.signalCalls++
	return f.signal, nil
}

func (f *infraTestRuntime) Physical(context.Context, infraCatalogueProfile, infraCatalogueFixture, infraCatalogueArm) (AttackCatalogPhysicalResult, error) {
	f.physicalCalls++
	return f.physical, nil
}

func (f *infraTestRuntime) Cleanup(context.Context, infraCatalogueProfile, infraCatalogueFixture, infraCatalogueArm, infraCatalogueSignal) AttackCatalogCleanupResult {
	f.cleanupCalls++
	return f.cleanup
}

func infraTestProfile(t *testing.T, family string) infraCatalogueProfile {
	t.Helper()
	for _, profile := range infraCatalogueProfiles() {
		if profile.Family == family {
			return profile
		}
	}
	t.Fatalf("family %q has no profile", family)
	return infraCatalogueProfile{}
}

func infraTestRuntimeFor(t *testing.T, profile infraCatalogueProfile) *infraTestRuntime {
	t.Helper()
	adapter := &infraAttackCatalogAdapter{profile: profile}
	policyName := profile.PolicyName
	if policyName == "" {
		policyName = "datastore-defense"
	}
	fixture := infraCatalogueFixture{Namespace: profile.Namespace, TargetName: "target-pod", TargetUID: "target-uid",
		PolicyName: policyName, PolicyUID: "policy-uid", PolicyGeneration: 3}
	fixture.ReceiptObjects = adapter.receiptObjects(fixture.TargetUID)
	return &infraTestRuntime{
		fixture: fixture,
		arm:     infraCatalogueArm{TargetName: fixture.TargetName, TargetUID: fixture.TargetUID, Mutated: true},
		signal: infraCatalogueSignal{Name: "catalogue-event", UID: "event-uid", Creator: profile.creator(), RunID: "run-1",
			CreatedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)},
		cleanup: AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, MarkerDeleted: true, Verified: true},
	}
}

func infraTestRun(profile infraCatalogueProfile) AttackCatalogRunContext {
	return AttackCatalogRunContext{RunID: "run-1", CatalogueID: profile.ID, ExpectedAction: profile.ExpectedAction, ReactiveCompatible: true}
}

func infraTestDecisionRecord(profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm, signal infraCatalogueSignal) audit.Record {
	return audit.Record{
		Kind: "phorvex.decision", Time: signal.CreatedAt.Add(time.Millisecond), Namespace: fixture.Namespace, Pod: arm.TargetName,
		Action: profile.ExpectedAction, Selected: true, Feasible: true, Actuated: true, DispatchOutcome: model.DispatchEmitted,
		Handler: profile.ExpectedAction, ObjectsTouched: slices.Clone(fixture.ReceiptObjects),
		Events: []model.EventEvidence{{Name: signal.Name, EventUID: signal.UID, Type: profile.EventType, TrustVerdict: "trusted",
			CreatorIdentity: signal.Creator, TargetPodUID: arm.TargetUID, TargetsPod: true, TimestampPresent: true}},
		DecisionTrace: &model.DecisionTraceV2{DecisionID: "decision-1", PolicyNamespace: fixture.Namespace,
			PolicyName: fixture.PolicyName, PolicyUID: fixture.PolicyUID, AssetUID: arm.TargetUID,
			SelectedAction: profile.ExpectedAction, DispatchOutcome: model.DispatchEmitted},
	}
}

func infraTestPhysical(profile infraCatalogueProfile) AttackCatalogPhysicalResult {
	trustedSHA := strings.Repeat("a", 64)
	trustedDigest := "sha256:" + trustedSHA
	switch profile.Family {
	case infraFamilyNetworkEdge:
		before, after := map[string]bool{}, map[string]bool{}
		for _, edge := range profile.ForbiddenEdges {
			before[edge], after[edge] = true, false
		}
		return AttackCatalogPhysicalResult{Validated: true, Oracle: infraNetworkOracle, Evidence: marshalInfraEvidence(infraNetworkEvidence{
			ForbiddenBefore: before, ForbiddenAfter: after,
			LegitimateBefore: true, LegitimateAfter: true, TargetSameUIDReady: true, PeerSameUIDUntouched: true,
			PeerEdgesReachable: true, Available: 2, MinimumAvailable: 2,
		})}
	case infraFamilyDatastore:
		return AttackCatalogPhysicalResult{Validated: true, Oracle: infraDatastoreOracle, Evidence: marshalInfraEvidence(infraDatastoreEvidence{
			TrustedSHA: trustedSHA, FinalSHA: trustedSHA, PoisonAbsent: true, BenignServed: true, AllPodsServed: true, TargetSameUID: true,
		})}
	case infraFamilyImage:
		return AttackCatalogPhysicalResult{Validated: true, Oracle: infraImageOracle, Evidence: marshalInfraEvidence(infraImageEvidence{
			TrustedDigest: trustedDigest, DeploymentImage: "example.invalid/demo@" + trustedDigest,
			RunningDigests: []string{trustedDigest, trustedDigest}, ReadyPods: 2, PoisonImageAbsent: true,
		})}
	case infraFamilyNodeRecycle:
		return AttackCatalogPhysicalResult{Validated: true, Oracle: infraNodeOracle, Evidence: marshalInfraEvidence(infraNodeEvidence{
			CompromisedNodeGone: true, TargetPodGone: true, ReplacementReady: true, HealthyNodeSameUID: true,
			HealthyPodsSameUID: true, Available: 2, MinimumAvailable: 2,
		})}
	default:
		return AttackCatalogPhysicalResult{}
	}
}

func infraTestNegativePhysical(profile infraCatalogueProfile) AttackCatalogPhysicalResult {
	physical := infraTestPhysical(profile)
	trustedSHA := strings.Repeat("a", 64)
	trustedDigest := "sha256:" + trustedSHA
	switch profile.Family {
	case infraFamilyNetworkEdge:
		before, after := map[string]bool{}, map[string]bool{}
		for _, edge := range profile.ForbiddenEdges {
			before[edge], after[edge] = true, false
		}
		after[profile.ForbiddenEdges[0]] = true
		physical.Evidence = marshalInfraEvidence(infraNetworkEvidence{
			ForbiddenBefore: before, ForbiddenAfter: after,
			LegitimateBefore: true, LegitimateAfter: true, TargetSameUIDReady: true, PeerSameUIDUntouched: true,
			PeerEdgesReachable: true, Available: 2, MinimumAvailable: 2,
		})
	case infraFamilyDatastore:
		physical.Evidence = marshalInfraEvidence(infraDatastoreEvidence{
			TrustedSHA: trustedSHA, FinalSHA: strings.Repeat("b", 64), PoisonAbsent: true, BenignServed: true, AllPodsServed: true, TargetSameUID: true,
		})
	case infraFamilyImage:
		physical.Evidence = marshalInfraEvidence(infraImageEvidence{
			TrustedDigest: trustedDigest, DeploymentImage: "example.invalid/demo@" + trustedDigest,
			RunningDigests: []string{"sha256:" + strings.Repeat("b", 64)}, ReadyPods: 1, PoisonImageAbsent: true,
		})
	case infraFamilyNodeRecycle:
		physical.Evidence = marshalInfraEvidence(infraNodeEvidence{
			CompromisedNodeGone: false, TargetPodGone: true, ReplacementReady: true, HealthyNodeSameUID: true,
			HealthyPodsSameUID: true, Available: 2, MinimumAvailable: 2,
		})
	}
	return physical
}
