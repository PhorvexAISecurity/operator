package console

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
)

var k8sCatalogueTestRepresentatives = map[string]string{
	k8sCatalogueFamilyQuarantine:     "AML.T0025",
	k8sCatalogueFamilyPodRotate:      "T1070.004",
	k8sCatalogueFamilyControllerStop: "T1610",
}

type fakeK8sCatalogueCluster struct {
	fixture       k8sCatalogueFixture
	signal        k8sCatalogueSignal
	physical      AttackCatalogPhysicalResult
	cleanup       AttackCatalogCleanupResult
	retry         AttackCatalogRetrySafety
	preflightErr  error
	signalErr     error
	retryErr      error
	preflightCall atomic.Int32
	signalCall    atomic.Int32
	physicalCall  atomic.Int32
	cleanupCall   atomic.Int32
	retryCall     atomic.Int32
}

func (f *fakeK8sCatalogueCluster) Preflight(context.Context, attackcatalog.Entry, k8sCatalogueProfile) (k8sCatalogueFixture, error) {
	f.preflightCall.Add(1)
	return f.fixture, f.preflightErr
}

func (f *fakeK8sCatalogueCluster) CreateSignal(context.Context, attackcatalog.Entry, k8sCatalogueProfile, k8sCatalogueFixture, string) (k8sCatalogueSignal, error) {
	f.signalCall.Add(1)
	return f.signal, f.signalErr
}

func (f *fakeK8sCatalogueCluster) Physical(context.Context, attackcatalog.Entry, k8sCatalogueProfile, k8sCatalogueFixture, k8sCatalogueSignal) (AttackCatalogPhysicalResult, error) {
	f.physicalCall.Add(1)
	return f.physical, nil
}

func (f *fakeK8sCatalogueCluster) Cleanup(context.Context, attackcatalog.Entry, k8sCatalogueProfile, k8sCatalogueFixture, k8sCatalogueSignal, string, string) AttackCatalogCleanupResult {
	f.cleanupCall.Add(1)
	return f.cleanup
}

func (f *fakeK8sCatalogueCluster) ReconcileRetrySafety(context.Context, attackcatalog.Entry, k8sCatalogueProfile, AttackCatalogResult) (AttackCatalogRetrySafety, error) {
	f.retryCall.Add(1)
	return f.retry, f.retryErr
}

func k8sCatalogueTestEntry(t *testing.T, id string) attackcatalog.Entry {
	t.Helper()
	entry, ok := attackcatalog.Lookup(id)
	if !ok {
		t.Fatalf("catalogue entry %q is missing", id)
	}
	return entry
}

func k8sCatalogueTestFixture(entry attackcatalog.Entry, profile k8sCatalogueProfile, execution AttackCatalogExecutionMode, reactive bool) k8sCatalogueFixture {
	start := time.Now().UTC().Add(-10 * time.Minute)
	target := k8sCataloguePodIdentity{Name: "demo-api-old", UID: "pod-old-uid", StartTime: start}
	return k8sCatalogueFixture{
		CatalogueID: entry.ID, ProfileKey: profile.Key, Namespace: profile.Namespace,
		NamespaceUID: "namespace-uid", DeploymentUID: "deployment-uid", ServiceUID: "service-uid",
		PolicyName: profile.PolicyName, PolicyUID: "policy-uid", PolicyGeneration: 7,
		ExecutionMode: execution, ReactiveOnly: reactive, Target: target,
		BaselineReadyPods: []k8sCataloguePodIdentity{
			target,
			{Name: "demo-api-sibling-a", UID: "pod-sibling-a", StartTime: start.Add(time.Second)},
			{Name: "demo-api-sibling-b", UID: "pod-sibling-b", StartTime: start.Add(2 * time.Second)},
		},
		SiblingUIDs:       []string{"pod-sibling-a", "pod-sibling-b"},
		NetworkPolicyName: k8sQuarantineNetworkPolicyName(target.UID),
	}
}

func k8sCatalogueTestPhysical(entry attackcatalog.Entry, profile k8sCatalogueProfile, fixture k8sCatalogueFixture, validated bool) AttackCatalogPhysicalResult {
	evidence := k8sCataloguePhysicalEvidence{
		Schema: k8sCataloguePhysicalSchema, CatalogueID: entry.ID, Profile: profile.Key, Family: profile.Family,
		Lane: profile.Lane, Namespace: profile.Namespace, LogicalAction: profile.ExpectedAction, NativeAction: profile.NativeAction,
		PolicyName: fixture.PolicyName, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration,
		DeploymentUID: fixture.DeploymentUID, ServiceUID: fixture.ServiceUID, TargetName: fixture.Target.Name,
		TargetUID: fixture.Target.UID, ReadyReplicas: 3, AvailableReplicas: 3,
		SiblingUIDs: slices.Clone(fixture.SiblingUIDs), ReplacementUIDs: []string{"pod-replacement"},
		EndpointUIDs: []string{"pod-replacement", "pod-sibling-a", "pod-sibling-b"}, AvailabilityHeld: true,
		SiblingsIntact: true, ReplacementReady: true, TargetEndpointAbsent: true,
	}
	if profile.Family == k8sCatalogueFamilyQuarantine {
		evidence.TargetQuarantined = true
		evidence.NetworkPolicyName = fixture.NetworkPolicyName
		evidence.NetworkPolicyUID = "network-policy-uid"
		evidence.NetworkPolicyValid = true
	} else {
		evidence.TargetGone = true
	}
	raw, _ := json.Marshal(evidence)
	return AttackCatalogPhysicalResult{Validated: validated, Oracle: profile.Oracle, Evidence: raw}
}

func k8sCatalogueTestCleanup(entry attackcatalog.Entry, profile k8sCatalogueProfile, fixture k8sCatalogueFixture, signal k8sCatalogueSignal, verified bool) AttackCatalogCleanupResult {
	evidence := k8sCatalogueCleanupEvidence{
		Schema: k8sCatalogueCleanupSchema, CatalogueID: entry.ID, RunID: "k8s-test-run", Profile: profile.Key,
		Family: profile.Family, TargetUID: fixture.Target.UID, SignalName: signal.Name, SignalUID: signal.UID,
		EventAbsent: true, FamilyArtifactsAbsent: true, CapacityRecordsAbsent: true, ReadyRestored: verified,
	}
	raw, _ := json.Marshal(evidence)
	return AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, MarkerDeleted: true, Verified: verified, Evidence: raw}
}

func k8sCatalogueTestAudit(entry attackcatalog.Entry, profile k8sCatalogueProfile, fixture k8sCatalogueFixture, signal k8sCatalogueSignal) audit.Record {
	podObject := "Pod/" + fixture.Namespace + "/" + fixture.Target.Name
	record := audit.Record{
		Kind: "phorvex.decision", Time: signal.CreatedAt.Add(time.Millisecond), Namespace: fixture.Namespace,
		Pod: fixture.Target.Name, Action: profile.NativeAction, Selected: true, Feasible: true,
		DryRun: fixture.ExecutionMode == AttackCatalogExecutionDryRun, Actuated: true,
		DispatchOutcome: model.DispatchEmitted, Handler: profile.NativeAction, ObjectsTouched: []string{podObject},
		DecisionTrace: &model.DecisionTraceV2{
			DecisionID: "decision-id", PolicyNamespace: fixture.Namespace, PolicyName: fixture.PolicyName,
			PolicyUID: fixture.PolicyUID, AssetNamespace: fixture.Namespace, AssetName: fixture.Target.Name,
			AssetUID: fixture.Target.UID, SelectedAction: profile.NativeAction, DispatchOutcome: model.DispatchEmitted,
			DryRun: fixture.ExecutionMode == AttackCatalogExecutionDryRun,
		},
		Events: []model.EventEvidence{{
			Name: signal.Name, EventUID: signal.UID, Source: profile.Lane + "-attacks", Type: entry.EventType,
			ThreatLevel: "critical", TrustVerdict: "trusted", CreatorIdentity: signal.Creator,
			TargetPodUID: fixture.Target.UID, TargetsPod: true, Weight: 1, TimestampPresent: true,
		}},
	}
	if profile.NativeAction == string(model.ActionRotate) {
		record.GracefulTermination = &model.GracefulTerminationReceipt{
			PolicyNamespace: fixture.Namespace, PolicyName: fixture.PolicyName, PolicyUID: fixture.PolicyUID,
			PolicyGeneration: fixture.PolicyGeneration, PolicyGraceCapSeconds: 30, WorkloadGraceSeconds: 30,
			EffectiveGracePeriodSeconds: 30, PodUID: fixture.Target.UID, PodResourceVersion: "17", TerminationStatus: "unconfirmed",
		}
	} else {
		record.ObjectsTouched = append(record.ObjectsTouched, "NetworkPolicy/"+fixture.Namespace+"/"+fixture.NetworkPolicyName)
	}
	return record
}

func completeFakeK8sCatalogue(t *testing.T, family string, execution AttackCatalogExecutionMode, reactive bool) (*k8sAttackCatalogAdapter, *fakeK8sCatalogueCluster, audit.Record) {
	t.Helper()
	entry := k8sCatalogueTestEntry(t, k8sCatalogueTestRepresentatives[family])
	profile, err := k8sCatalogueProfileForFamily(family)
	if err != nil {
		t.Fatal(err)
	}
	fixture := k8sCatalogueTestFixture(entry, profile, execution, reactive)
	signal := k8sCatalogueSignal{Name: "catalog-k8s-test", UID: "event-uid", Creator: profile.DetectorIdentity,
		CreatedAt: time.Now().UTC().Add(-time.Second)}
	cluster := &fakeK8sCatalogueCluster{fixture: fixture, signal: signal}
	cluster.physical = k8sCatalogueTestPhysical(entry, profile, fixture, true)
	cluster.cleanup = k8sCatalogueTestCleanup(entry, profile, fixture, signal, true)
	cfg := Config{Service: ServiceAttacks, AttackCatalogEnabled: true, AttackCatalogAuthorizationTenant: "phorvex-test",
		AttackCatalogPollInterval: time.Millisecond, AuditSource: &audittransport.Client{}}
	server := &Server{cfg: cfg}
	adapter := &k8sAttackCatalogAdapter{server: server, cfg: cfg, entry: entry, profile: profile,
		clusterFactory: func(k8sCatalogueProfile) (k8sCatalogueCluster, error) { return cluster, nil }}
	return adapter, cluster, k8sCatalogueTestAudit(entry, profile, fixture, signal)
}

func runFakeK8sCatalogue(t *testing.T, ctx context.Context, adapter *k8sAttackCatalogAdapter) AttackCatalogResult {
	t.Helper()
	run := AttackCatalogRunContext{RunID: "k8s-test-run", CatalogueID: adapter.entry.ID,
		ExpectedAction: adapter.entry.ExpectedAction, ReactiveCompatible: adapter.entry.ReactiveCompatible}
	prepared, err := adapter.Preflight(ctx, run)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	result := AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: adapter.entry.ID, RunID: run.RunID,
		Visible: true, Available: true, ExpectedAction: adapter.entry.ExpectedAction, StartedAt: time.Now().UTC(),
		ExecutionMode: prepared.ExecutionMode(), TriggerMode: prepared.TriggerMode(),
		ReactiveOnly: prepared.TriggerMode() == AttackCatalogTriggerReactive}
	return adapter.server.executePreparedAttackCatalogueRun(ctx, run, adapter, prepared, result)
}

func TestK8sCatalogueAdapterMembershipAndFixedProfiles(t *testing.T) {
	cfg := Config{Service: ServiceAttacks, AttackCatalogEnabled: true, AttackCatalogAuthorizationTenant: "phorvex-test",
		AuditSource: &audittransport.Client{}}
	server := &Server{cfg: cfg}
	adapters, err := newK8sCatalogueAdaptersWithFactory(server, cfg, func(k8sCatalogueProfile) (k8sCatalogueCluster, error) {
		return nil, errors.New("not invoked while constructing exact registry membership")
	})
	if err != nil {
		t.Fatal(err)
	}
	wantCounts := map[string]int{k8sCatalogueFamilyQuarantine: 33, k8sCatalogueFamilyPodRotate: 27, k8sCatalogueFamilyControllerStop: 10}
	gotCounts := map[string]int{}
	gotIDs := map[string]bool{}
	for _, raw := range adapters {
		adapter, ok := raw.(*k8sAttackCatalogAdapter)
		if !ok || validateK8sCatalogueBinding(adapter.entry, adapter.profile) != nil || gotIDs[adapter.entry.ID] {
			t.Fatalf("invalid or duplicate Kubernetes adapter: %#v", raw)
		}
		gotIDs[adapter.entry.ID] = true
		gotCounts[adapter.profile.Family]++
		if !adapter.Availability().Available {
			t.Fatalf("reviewed adapter %s is not available with its fixed server profile", adapter.entry.ID)
		}
	}
	if len(gotIDs) != 70 {
		t.Fatalf("adapter count=%d, want 70", len(gotIDs))
	}
	for family, want := range wantCounts {
		if gotCounts[family] != want {
			t.Fatalf("%s adapters=%d, want %d", family, gotCounts[family], want)
		}
	}
	entries, err := attackcatalog.Entries()
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := map[string]bool{}
	for _, entry := range entries {
		if _, supported := wantCounts[entry.Family]; supported {
			wantIDs[entry.ID] = true
		}
	}
	if len(wantIDs) != len(gotIDs) {
		t.Fatalf("authoritative family membership=%d, adapters=%d", len(wantIDs), len(gotIDs))
	}
	for id := range wantIDs {
		if !gotIDs[id] {
			t.Fatalf("authoritative family ID %q has no adapter", id)
		}
	}
	if gotIDs[attackcatalog.FirstID] {
		t.Fatalf("unrelated catalogue ID %q was registered by Kubernetes families", attackcatalog.FirstID)
	}
}

func TestK8sCatalogueRetryReconcileDelegatesOnlyExactBinding(t *testing.T) {
	adapter, cluster, _ := completeFakeK8sCatalogue(t, k8sCatalogueFamilyQuarantine, AttackCatalogExecutionActive, true)
	cluster.retry = AttackCatalogRetrySafety{Verified: true, RetrySafe: true, Reason: "clean"}
	persisted := AttackCatalogResult{CatalogueID: adapter.entry.ID, RunID: "cat-retry", Family: adapter.profile.Family}
	safety, err := adapter.ReconcileRetrySafety(context.Background(), persisted)
	if err != nil || !safety.RetrySafe || cluster.retryCall.Load() != 1 {
		t.Fatalf("exact retry reconciliation was not delegated: safety=%+v calls=%d err=%v", safety, cluster.retryCall.Load(), err)
	}
	persisted.CatalogueID = "AML.T0049"
	if _, err = adapter.ReconcileRetrySafety(context.Background(), persisted); err == nil || cluster.retryCall.Load() != 1 {
		t.Fatalf("foreign catalogue identity reached retry verifier: calls=%d err=%v", cluster.retryCall.Load(), err)
	}
}

func TestK8sCatalogueWrongIDAndProfileFailBeforePreflight(t *testing.T) {
	adapter, cluster, _ := completeFakeK8sCatalogue(t, k8sCatalogueFamilyQuarantine, AttackCatalogExecutionActive, true)
	base := AttackCatalogRunContext{RunID: "k8s-test-run", CatalogueID: adapter.entry.ID,
		ExpectedAction: adapter.entry.ExpectedAction, ReactiveCompatible: adapter.entry.ReactiveCompatible}
	tests := []struct {
		name string
		run  AttackCatalogRunContext
	}{
		{name: "wrong exact ID", run: func() AttackCatalogRunContext { r := base; r.CatalogueID = "AML.T0049"; return r }()},
		{name: "wrong action", run: func() AttackCatalogRunContext { r := base; r.ExpectedAction = "rotate"; return r }()},
		{name: "wrong reactive compatibility", run: func() AttackCatalogRunContext { r := base; r.ReactiveCompatible = !r.ReactiveCompatible; return r }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := adapter.Preflight(context.Background(), test.run); err == nil {
				t.Fatal("substituted run identity passed preflight")
			}
		})
	}
	badProfile := *adapter
	badProfile.profile.Namespace = "p2-demo"
	if _, err := badProfile.Preflight(context.Background(), base); err == nil {
		t.Fatal("substituted fixed profile passed preflight")
	}
	if cluster.preflightCall.Load() != 0 || cluster.signalCall.Load() != 0 {
		t.Fatalf("failed identity/profile validation reached cluster: preflight=%d signal=%d", cluster.preflightCall.Load(), cluster.signalCall.Load())
	}
}

func TestK8sCataloguePreflightIsNonMutatingForEveryFamily(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			adapter, cluster, _ := completeFakeK8sCatalogue(t, family, AttackCatalogExecutionActive, true)
			run := AttackCatalogRunContext{RunID: "k8s-test-run", CatalogueID: adapter.entry.ID,
				ExpectedAction: adapter.entry.ExpectedAction, ReactiveCompatible: adapter.entry.ReactiveCompatible}
			if _, err := adapter.Preflight(context.Background(), run); err != nil {
				t.Fatal(err)
			}
			if cluster.preflightCall.Load() != 1 || cluster.signalCall.Load() != 0 || cluster.cleanupCall.Load() != 0 {
				t.Fatalf("preflight mutated fixture: preflight=%d signal=%d cleanup=%d", cluster.preflightCall.Load(), cluster.signalCall.Load(), cluster.cleanupCall.Load())
			}
		})
	}
}

func TestK8sCatalogueStrictPositiveRecordsForEveryFamily(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			adapter, cluster, record := completeFakeK8sCatalogue(t, family, AttackCatalogExecutionActive, true)
			adapter.server.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
			result := runFakeK8sCatalogue(t, context.Background(), adapter)
			if result.Verdict != "DEFENDED" || result.Validate() != nil || adapter.ValidateDefended(result) != nil {
				t.Fatalf("strict family chain did not defend: %+v", result)
			}
			if !result.ReactiveOnly || result.TriggerMode != AttackCatalogTriggerReactive || result.ExecutionMode != AttackCatalogExecutionActive {
				t.Fatalf("execution and trigger modes were conflated: %+v", result)
			}
			if family == k8sCatalogueFamilyControllerStop && (result.Decision.Action != string(model.ActionControllerStop) || result.Actuator.Handler != string(model.ActionRotate)) {
				t.Fatalf("controller-stop logical/native mapping changed: %+v", result)
			}
			if cluster.signalCall.Load() != 1 || cluster.cleanupCall.Load() != 1 {
				t.Fatalf("unexpected family lifecycle calls: signal=%d cleanup=%d", cluster.signalCall.Load(), cluster.cleanupCall.Load())
			}
		})
	}
}

func TestK8sCatalogueOracleNegativeForEveryFamily(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			adapter, cluster, record := completeFakeK8sCatalogue(t, family, AttackCatalogExecutionActive, true)
			cluster.physical.Validated = false
			adapter.server.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			result := runFakeK8sCatalogue(t, ctx, adapter)
			if result.Verdict != "NOT_DEFENDED" || !result.Actuator.ReceiptObserved || result.PhysicalValidation.Validated || !result.Cleanup.Verified {
				t.Fatalf("negative physical oracle inferred defense: %+v", result)
			}
		})
	}
}

func TestK8sCatalogueCleanupNegativeForEveryFamily(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			adapter, cluster, record := completeFakeK8sCatalogue(t, family, AttackCatalogExecutionActive, true)
			cluster.cleanup.Verified = false
			adapter.server.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
			result := runFakeK8sCatalogue(t, context.Background(), adapter)
			if result.Verdict == "DEFENDED" || !result.UnsafeToRetry || result.Cleanup.Verified {
				t.Fatalf("negative cleanup inferred retry safety or defense: %+v", result)
			}
		})
	}
}

func TestK8sCatalogueCancellationStillRunsExactCleanup(t *testing.T) {
	adapter, cluster, _ := completeFakeK8sCatalogue(t, k8sCatalogueFamilyPodRotate, AttackCatalogExecutionActive, true)
	ctx, cancel := context.WithCancel(context.Background())
	adapter.server.attackCatalogRecords = func(context.Context) ([]audit.Record, error) {
		cancel()
		return nil, nil
	}
	result := runFakeK8sCatalogue(t, ctx, adapter)
	if result.Verdict == "DEFENDED" || !result.Launched || result.Signal.Observed || !result.Cleanup.Verified || cluster.cleanupCall.Load() != 1 {
		t.Fatalf("cancellation skipped cleanup or inferred defense: %+v", result)
	}
}

func TestK8sCatalogueRejectsForeignAndUnacceptedAuditRecords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*audit.Record)
	}{
		{name: "foreign event UID", mutate: func(r *audit.Record) { r.Events[0].EventUID = "foreign-event" }},
		{name: "unselected", mutate: func(r *audit.Record) { r.Selected = false }},
		{name: "infeasible", mutate: func(r *audit.Record) { r.Feasible = false }},
		{name: "unaccepted dispatch", mutate: func(r *audit.Record) { r.Actuated = false; r.DispatchOutcome = "failed" }},
		{name: "foreign target", mutate: func(r *audit.Record) { r.DecisionTrace.AssetUID = "foreign-pod" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _, record := completeFakeK8sCatalogue(t, k8sCatalogueFamilyQuarantine, AttackCatalogExecutionActive, true)
			test.mutate(&record)
			adapter.server.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			result := runFakeK8sCatalogue(t, ctx, adapter)
			if result.Verdict == "DEFENDED" || result.Actuator.ReceiptObserved {
				t.Fatalf("foreign or unaccepted audit record inferred receipt: %+v", result)
			}
		})
	}
}

func TestK8sCatalogueDryRunAndReactiveModesRemainSeparate(t *testing.T) {
	adapter, _, record := completeFakeK8sCatalogue(t, k8sCatalogueFamilyControllerStop, AttackCatalogExecutionDryRun, true)
	adapter.server.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
	result := runFakeK8sCatalogue(t, context.Background(), adapter)
	if result.ExecutionMode != AttackCatalogExecutionDryRun || result.TriggerMode != AttackCatalogTriggerReactive || !result.ReactiveOnly {
		t.Fatalf("dryRun execution and reactive trigger modes were conflated: %+v", result)
	}
	if result.Verdict == "DEFENDED" {
		t.Fatalf("dryRun result weakened the active-only DEFENDED contract: %+v", result)
	}
}
