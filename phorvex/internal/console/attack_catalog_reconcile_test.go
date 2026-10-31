package console

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audittransport"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// reconcileCatalogAdapter is a registry-registerable adapter whose read-only retry
// verdict is fully controllable, so the shared reconcile state machine can be
// exercised without a live cluster. Its mutation methods exist only to satisfy the
// interface; the reconcile tests seed terminal runs directly.
type reconcileCatalogAdapter struct {
	id        string
	tenant    string
	safety    AttackCatalogRetrySafety
	safetyErr error
	calls     atomic.Int32
}

func (a *reconcileCatalogAdapter) CatalogueID() string { return a.id }
func (a *reconcileCatalogAdapter) Availability() AttackCatalogAdapterAvailability {
	return AttackCatalogAdapterAvailability{Available: true, RuntimeContext: defaultTargetID, FixtureTenant: a.tenant}
}
func (a *reconcileCatalogAdapter) Destination() (runDestination, error) {
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{a.tenant},
		ScopeTarget: defaultTargetID, ScopeTenant: a.tenant}, nil
}
func (a *reconcileCatalogAdapter) Preflight(context.Context, AttackCatalogRunContext) (AttackCatalogPreparation, error) {
	return nil, errors.New("reconcile test adapter does not launch")
}
func (a *reconcileCatalogAdapter) Execute(context.Context, AttackCatalogRunContext, AttackCatalogPreparation) (AttackCatalogObservation, error) {
	return AttackCatalogObservation{}, errors.New("reconcile test adapter does not launch")
}
func (a *reconcileCatalogAdapter) Cleanup(context.Context, AttackCatalogRunContext, AttackCatalogPreparation) AttackCatalogCleanupResult {
	return AttackCatalogCleanupResult{Attempted: true}
}
func (a *reconcileCatalogAdapter) ValidateDefended(AttackCatalogResult) error {
	return errors.New("reconcile test adapter is never DEFENDED")
}
func (a *reconcileCatalogAdapter) DefendedReason() string { return "" }
func (a *reconcileCatalogAdapter) ReconcileRetrySafety(_ context.Context, _ AttackCatalogResult) (AttackCatalogRetrySafety, error) {
	a.calls.Add(1)
	return a.safety, a.safetyErr
}

var _ AttackCatalogAdapter = (*reconcileCatalogAdapter)(nil)
var _ AttackCatalogRetryReconciler = (*reconcileCatalogAdapter)(nil)

func newReconcileTestManager(t *testing.T, adapter AttackCatalogAdapter) *RunManager {
	t.Helper()
	cfg := Config{Service: ServiceAttacks, StateDir: t.TempDir()}
	rm := NewRunManager(cfg)
	rm.startupReconcile.Wait() // drain the functional reconcile goroutine
	registry := NewAttackCatalogAdapterRegistry()
	if adapter != nil {
		if err := registry.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	rm.attackCatalogAdapters = registry
	return rm
}

func seedTerminalCatalogueRun(t *testing.T, rm *RunManager, id, catalogueID, state string, unsafe bool) *RunStatus {
	t.Helper()
	st := &RunStatus{ID: id, Config: catalogueID, State: state, ExecutionKind: attackCatalogExecutionKind,
		Owner: "op", ScopeTarget: defaultTargetID, ScopeTenant: "phorvex-test", Outcome: "INCONCLUSIVE",
		CleanupStatus: "unverified", UnsafeToRetry: unsafe, Started: time.Now().UTC().Format(time.RFC3339Nano), Finished: tsNow()}
	rm.mu.Lock()
	rm.runs[id] = st
	rm.runOut[id] = id
	if err := rm.persistStatus(st, id); err != nil { // the original terminal record
		rm.mu.Unlock()
		t.Fatalf("persist seed status: %v", err)
	}
	rm.mu.Unlock()
	return st
}

func readRunEventStatuses(t *testing.T, cfg Config, id string) []RunStatus {
	t.Helper()
	raw, err := os.ReadFile(cfg.statePath("run-events.jsonl"))
	if err != nil {
		t.Fatalf("read run-events: %v", err)
	}
	var out []RunStatus
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 4096), consoleStateRecordLimit)
	for sc.Scan() {
		var p persistedRunStatus
		if json.Unmarshal(sc.Bytes(), &p) != nil || p.Phase != "status" || p.Run.ID != id {
			continue
		}
		out = append(out, p.Run)
	}
	return out
}

// TestAttackCatalogueSingleActiveRunSerialization proves the single-active-run lock
// rejects every concurrent launch while a prior catalogue run is running or is
// unsafe-to-retry, and that the shared run map survives concurrent access.
func TestAttackCatalogueSingleActiveRunSerialization(t *testing.T) {
	entry, ok := attackcatalog.Lookup("AML.T0024")
	if !ok {
		t.Fatal("metadata ID missing")
	}
	adapter := &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test"}
	for _, blocker := range []struct {
		name   string
		state  string
		unsafe bool
	}{{"running", "running", false}, {"unsafe-terminal", "error", true}} {
		t.Run(blocker.name, func(t *testing.T) {
			s := &Server{cfg: Config{Service: ServiceAttacks, StateDir: t.TempDir()}}
			s.runs = NewRunManager(s.cfg)
			s.runs.startupReconcile.Wait()
			s.attackCatalogAdapters = NewAttackCatalogAdapterRegistry()
			s.runs.attackCatalogAdapters = s.attackCatalogAdapters
			s.runs.mu.Lock()
			s.runs.runs["cat-1"] = &RunStatus{ID: "cat-1", Config: entry.ID, State: blocker.state,
				ExecutionKind: attackCatalogExecutionKind, UnsafeToRetry: blocker.unsafe}
			s.runs.runOut["cat-1"] = "cat-1"
			if blocker.state == "running" {
				s.runs.active = 1
			}
			s.runs.mu.Unlock()

			dest, _ := adapter.Destination()
			avail := adapter.Availability()
			const launches = 8
			var wg sync.WaitGroup
			var accepted, rejected atomic.Int32
			for i := 0; i < launches; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := s.startAttackCatalogueRun(entry, adapter, avail, dest, "op"); err != nil {
						if !strings.Contains(err.Error(), "active or requires cleanup reconciliation") {
							t.Errorf("unexpected rejection: %v", err)
						}
						rejected.Add(1)
					} else {
						accepted.Add(1)
					}
				}()
			}
			wg.Wait()
			if accepted.Load() != 0 || rejected.Load() != launches {
				t.Fatalf("serialization breached: accepted=%d rejected=%d", accepted.Load(), rejected.Load())
			}
		})
	}
}

// TestAttackCatalogueFinalizeDecouplesRetrySafety proves finalize derives the retry
// gate from retry-safety, not the full DEFENDED cleanup oracle: an environmental Pod
// rollout (Verified=false, RetrySafe=true) is terminal-but-retryable, while genuine
// contamination (RetrySafe=false) stays partial and unsafe.
func TestAttackCatalogueFinalizeDecouplesRetrySafety(t *testing.T) {
	entry, ok := attackcatalog.Lookup("AML.T0024")
	if !ok {
		t.Fatal("metadata ID missing")
	}
	adapter := &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test"}
	cases := []struct {
		name          string
		cleanup       AttackCatalogCleanupResult
		verdict       string
		wantState     string
		wantUnsafe    bool
		wantCleanupSt string
	}{
		{"environmental-rollout-retry-safe",
			AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, MarkerDeleted: false, Verified: false, RetrySafe: true},
			"INCONCLUSIVE", "error", false, "retry-safe"},
		{"leftover-artifacts-unsafe",
			AttackCatalogCleanupResult{Attempted: true, EventDeleted: false, MarkerDeleted: false, Verified: false, RetrySafe: false},
			"INCONCLUSIVE", "partial", true, "unverified"},
		{"full-oracle-verified-is-retry-safe",
			AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, MarkerDeleted: true, Verified: true, RetrySafe: false},
			"ERROR", "error", false, "verified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Service: ServiceAttacks, StateDir: t.TempDir()}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
			s.runs.startupReconcile.Wait()
			id := "cat-1"
			if err := os.MkdirAll(cfg.runOutputPath(id), 0o750); err != nil {
				t.Fatal(err)
			}
			start := time.Now().UTC().Add(-time.Second)
			s.runs.mu.Lock()
			s.runs.runs[id] = &RunStatus{ID: id, Config: entry.ID, State: "running",
				ExecutionKind: attackCatalogExecutionKind, Owner: "op"}
			s.runs.runOut[id] = id
			s.runs.active = 1
			s.runs.mu.Unlock()
			result := AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: entry.ID, RunID: id,
				Family: entry.Family, Visible: true, Available: true, Launched: true, ExpectedAction: entry.ExpectedAction,
				StartedAt: start, FinishedAt: time.Now().UTC(), Verdict: tc.verdict, Reason: "test finalize",
				Cleanup: tc.cleanup}
			s.finalizeAttackCatalogueRun(id, adapter, result, nil, nil)
			st, _ := s.runs.Status(id)
			if st == nil || st.State != tc.wantState || st.UnsafeToRetry != tc.wantUnsafe || st.CleanupStatus != tc.wantCleanupSt {
				t.Fatalf("state=%q unsafe=%v cleanup=%q; want %q/%v/%q", st.State, st.UnsafeToRetry, st.CleanupStatus,
					tc.wantState, tc.wantUnsafe, tc.wantCleanupSt)
			}
		})
	}
}

// TestAttackCatalogueReconcileClearsStaleUnsafe proves a stale unsafe run whose
// cluster the adapter re-verifies clean is cleared by appending a NEW status record
// (UnsafeToRetry=false) while every prior journal record is preserved, and that the
// superseding record is the one a restart loads.
func TestAttackCatalogueReconcileClearsStaleUnsafe(t *testing.T) {
	entry, _ := attackcatalog.Lookup("AML.T0024")
	adapter := &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test",
		safety: AttackCatalogRetrySafety{Verified: true, RetrySafe: true, Reason: "fixture clean"}}
	rm := newReconcileTestManager(t, adapter)
	seedTerminalCatalogueRun(t, rm, "cat-9", entry.ID, "partial", true)

	if err := rm.ReconcileAttackCatalogRun("cat-9", "op"); err != nil {
		t.Fatalf("reconcile refused a clean run: %v", err)
	}
	if adapter.calls.Load() != 1 {
		t.Fatalf("adapter reconcile calls=%d, want 1", adapter.calls.Load())
	}
	st, _ := rm.Status("cat-9")
	if st.UnsafeToRetry || st.CleanupStatus != "reconciled-read-only" || st.State != "partial" {
		t.Fatalf("cleared record wrong: unsafe=%v cleanup=%q state=%q", st.UnsafeToRetry, st.CleanupStatus, st.State)
	}

	// Append-only: the original unsafe record and the new safe record both survive,
	// in that order, and no record was rewritten in place.
	statuses := readRunEventStatuses(t, rm.cfg, "cat-9")
	if len(statuses) < 2 || !statuses[0].UnsafeToRetry || statuses[len(statuses)-1].UnsafeToRetry {
		t.Fatalf("append-only semantics broken: %d records first.unsafe=%v last.unsafe=%v",
			len(statuses), statuses[0].UnsafeToRetry, statuses[len(statuses)-1].UnsafeToRetry)
	}

	// A restart loads the LAST record — the run is no longer unsafe.
	reloaded := NewRunManager(rm.cfg)
	reloaded.startupReconcile.Wait()
	rel, ok := reloaded.Status("cat-9")
	if !ok || rel.UnsafeToRetry {
		t.Fatalf("restart loaded a stale unsafe record: ok=%v unsafe=%v", ok, rel.UnsafeToRetry)
	}
}

// TestAttackCatalogueReconcileRefusesContaminated proves the reconcile NEVER clears
// the retry gate when the adapter cannot prove the cluster clean (leftover artifacts
// or a verification error): the run stays unsafe and the refusal is recorded.
func TestAttackCatalogueReconcileRefusesContaminated(t *testing.T) {
	entry, _ := attackcatalog.Lookup("AML.T0024")
	for _, tc := range []struct {
		name      string
		safety    AttackCatalogRetrySafety
		safetyErr error
		wantErr   string
	}{
		{"leftover-artifact", AttackCatalogRetrySafety{RetrySafe: false, Reason: "run-owned SecurityEvent is still present"}, nil, "run-owned SecurityEvent is still present"},
		{"verification-error", AttackCatalogRetrySafety{}, errors.New("cluster unreachable"), "cluster unreachable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test", safety: tc.safety, safetyErr: tc.safetyErr}
			rm := newReconcileTestManager(t, adapter)
			seedTerminalCatalogueRun(t, rm, "cat-3", entry.ID, "partial", true)
			err := rm.ReconcileAttackCatalogRun("cat-3", "op")
			if err == nil {
				t.Fatal("reconcile cleared a contaminated run")
			}
			st, _ := rm.Status("cat-3")
			if !st.UnsafeToRetry || st.CleanupStatus != "unverified" || !strings.Contains(st.Error, tc.wantErr) {
				t.Fatalf("contaminated run not held unsafe: unsafe=%v cleanup=%q err=%q", st.UnsafeToRetry, st.CleanupStatus, st.Error)
			}
		})
	}
}

// TestAttackCatalogueReconcileCrashRestartRecovery proves a run interrupted mid-flight
// by a process restart (persisted while "running", with no terminal result file) is
// loaded as partial+unsafe and can then be reconciled clean read-only.
func TestAttackCatalogueReconcileCrashRestartRecovery(t *testing.T) {
	entry, _ := attackcatalog.Lookup("AML.T0024")
	cfg := Config{Service: ServiceAttacks, StateDir: t.TempDir()}
	// Simulate the pre-crash journal: a catalogue run persisted while running.
	seed := &RunManager{cfg: cfg}
	running := &RunStatus{ID: "cat-5", Config: entry.ID, State: "running", ExecutionKind: attackCatalogExecutionKind,
		Owner: "op", Started: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := seed.persistStatus(running, "cat-5"); err != nil {
		t.Fatal(err)
	}

	rm := NewRunManager(cfg)
	rm.startupReconcile.Wait()
	if rm.loadErr != nil {
		t.Fatalf("load: %v", rm.loadErr)
	}
	st, ok := rm.Status("cat-5")
	if !ok || st.State != "partial" || !st.UnsafeToRetry {
		t.Fatalf("interrupted run not recovered as partial+unsafe: ok=%v state=%q unsafe=%v", ok, st.State, st.UnsafeToRetry)
	}

	adapter := &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test",
		safety: AttackCatalogRetrySafety{Verified: true, RetrySafe: true}}
	registry := NewAttackCatalogAdapterRegistry()
	if err := registry.Register(adapter); err != nil {
		t.Fatal(err)
	}
	rm.attackCatalogAdapters = registry
	if err := rm.ReconcileAttackCatalogRun("cat-5", "op"); err != nil {
		t.Fatalf("reconcile after crash refused: %v", err)
	}
	st, _ = rm.Status("cat-5")
	if st.UnsafeToRetry {
		t.Fatal("crash-interrupted run stayed unsafe after clean reconciliation")
	}
}

// TestAttackCatalogueReconcileRejectsIneligible proves the reconcile only touches an
// interrupted unsafe catalogue run of a reconcilable family, authorized to its owner.
func TestAttackCatalogueReconcileRejectsIneligible(t *testing.T) {
	entry, _ := attackcatalog.Lookup("AML.T0024")

	t.Run("not-unsafe", func(t *testing.T) {
		rm := newReconcileTestManager(t, &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test", safety: AttackCatalogRetrySafety{RetrySafe: true}})
		seedTerminalCatalogueRun(t, rm, "cat-1", entry.ID, "done", false)
		if err := rm.ReconcileAttackCatalogRun("cat-1", "op"); err == nil {
			t.Fatal("reconciled a run that was not unsafe")
		}
	})
	t.Run("still-running", func(t *testing.T) {
		rm := newReconcileTestManager(t, &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test", safety: AttackCatalogRetrySafety{RetrySafe: true}})
		st := seedTerminalCatalogueRun(t, rm, "cat-1", entry.ID, "running", true)
		_ = st
		if err := rm.ReconcileAttackCatalogRun("cat-1", "op"); err == nil {
			t.Fatal("reconciled a still-running run")
		}
	})
	t.Run("wrong-owner", func(t *testing.T) {
		rm := newReconcileTestManager(t, &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test", safety: AttackCatalogRetrySafety{RetrySafe: true}})
		seedTerminalCatalogueRun(t, rm, "cat-1", entry.ID, "partial", true)
		if err := rm.ReconcileAttackCatalogRun("cat-1", "intruder"); err == nil {
			t.Fatal("reconciled under a non-owning identity")
		}
	})
	t.Run("unsupported-family", func(t *testing.T) {
		// A registered adapter that does NOT implement AttackCatalogRetryReconciler.
		plain := &testCatalogAdapter{id: entry.ID, tenant: "phorvex-test"}
		rm := newReconcileTestManager(t, plain)
		seedTerminalCatalogueRun(t, rm, "cat-1", entry.ID, "partial", true)
		if err := rm.ReconcileAttackCatalogRun("cat-1", "op"); err == nil {
			t.Fatal("reconciled an unsupported family")
		}
	})
}

// TestAttackCatalogueStartupReconcileClearsEligibleRuns proves the server-initiated
// startup pass re-verifies and clears every eligible stale unsafe run, and leaves
// contaminated ones unsafe, without an operator request.
func TestAttackCatalogueStartupReconcileClearsEligibleRuns(t *testing.T) {
	entry, _ := attackcatalog.Lookup("AML.T0024")
	adapter := &reconcileCatalogAdapter{id: entry.ID, tenant: "phorvex-test",
		safety: AttackCatalogRetrySafety{Verified: true, RetrySafe: true}}
	cfg := Config{Service: ServiceAttacks, StateDir: t.TempDir(), Sleep: func(time.Duration) {}}
	rm := NewRunManager(cfg)
	rm.startupReconcile.Wait()
	seedTerminalCatalogueRun(t, rm, "cat-2", entry.ID, "partial", true)
	registry := NewAttackCatalogAdapterRegistry()
	if err := registry.Register(adapter); err != nil {
		t.Fatal(err)
	}
	rm.attackCatalogAdapters = registry

	rm.reconcileInterruptedAttackCatalog()

	st, _ := rm.Status("cat-2")
	if st.UnsafeToRetry {
		t.Fatal("startup reconciliation did not clear an eligible clean run")
	}
	if adapter.calls.Load() != 1 {
		t.Fatalf("startup adapter reconcile calls=%d, want 1", adapter.calls.Load())
	}
}

// --- Cluster-level credential cleanup: the core pod-UID decoupling ---

func credentialCleanupTestCluster(t *testing.T, objects []runtime.Object, policy *v1alpha1.PhorvexPolicy) *kubernetesCredentialCatalogueCluster {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{securityEventGVR: "SecurityEventList"})
	ctrl := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	return &kubernetesCredentialCatalogueCluster{kube: kubernetesfake.NewSimpleClientset(objects...), dynamic: dyn, client: ctrl}
}

func credentialCleanupFixtureObjects(profile identityCredentialServerProfile, currentPodUID, rsUID, depUID string, available int32, extra ...runtime.Object) ([]runtime.Object, *v1alpha1.PhorvexPolicy) {
	controller := true
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: profile.Deployment, Namespace: profile.Namespace, UID: types.UID(depUID)},
		Status: appsv1.DeploymentStatus{AvailableReplicas: available}}
	replicaSet := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "demo-api-rs", Namespace: profile.Namespace, UID: types.UID(rsUID),
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: profile.Deployment, UID: types.UID(depUID), Controller: &controller}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: profile.PodPrefix + "0", Namespace: profile.Namespace, UID: types.UID(currentPodUID),
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "demo-api-rs", UID: types.UID(rsUID), Controller: &controller}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: profile.PolicyName, Namespace: profile.Namespace, UID: "policy-uid", Generation: 7}}
	objects := append([]runtime.Object{deployment, replicaSet, pod}, extra...)
	return objects, policy
}

func TestCredentialCleanupRetrySafeToleratesPodRollout(t *testing.T) {
	profile := credentialCatalogueServerProfiles["AML.T0035"]
	fixture := identityCredentialCatalogueFixture{Profile: profile, PodName: profile.PodPrefix + "0",
		PodUID: "prepare-time-pod-uid", ReplicaSetUID: "prepare-time-rs-uid", DeploymentUID: "deployment-uid",
		PolicyUID: "policy-uid", PolicyGeneration: 7, MinimumAvailableReplicas: 2}
	// The live Pod and ReplicaSet have rolled to fresh UIDs; the Deployment and
	// PhorvexPolicy identity are unchanged and the availability floor is met.
	objects, policy := credentialCleanupFixtureObjects(profile, "rolled-pod-uid", "rolled-rs-uid", "deployment-uid", 2)
	cluster := credentialCleanupTestCluster(t, objects, policy)
	state := &identityCredentialCatalogueRunState{}

	observation, err := cluster.Cleanup(context.Background(), fixture, state)
	if err == nil {
		t.Fatal("full cleanup oracle unexpectedly passed despite the rolled Pod identity")
	}
	if observation.FixtureRestored {
		t.Fatal("FixtureRestored must stay false when the prepare-time Pod identity changed")
	}
	if !observation.RetrySafe {
		t.Fatalf("a benign Pod rollout with absent artifacts must be retry-safe: %v", err)
	}
}

func TestCredentialCleanupRetryUnsafeOnLeftoverArtifact(t *testing.T) {
	profile := credentialCatalogueServerProfiles["AML.T0035"]
	fixture := identityCredentialCatalogueFixture{Profile: profile, PodName: profile.PodPrefix + "0",
		PodUID: "rolled-pod-uid", ReplicaSetUID: "rolled-rs-uid", DeploymentUID: "deployment-uid",
		PolicyUID: "policy-uid", PolicyGeneration: 7, MinimumAvailableReplicas: 2}
	// A run-owned token Secret that this run cannot prove it owns (foreign UID) still
	// exists: the fixture is NOT clean, so it is neither restored nor retry-safe.
	leftover := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: profile.TokenSecret, Namespace: profile.Namespace, UID: "foreign-uid"}}
	objects, policy := credentialCleanupFixtureObjects(profile, "rolled-pod-uid", "rolled-rs-uid", "deployment-uid", 2, leftover)
	cluster := credentialCleanupTestCluster(t, objects, policy)
	state := &identityCredentialCatalogueRunState{secretUID: "owned-uid"}

	observation, err := cluster.Cleanup(context.Background(), fixture, state)
	if err == nil {
		t.Fatal("cleanup accepted a leftover credential artifact")
	}
	if observation.FixtureRestored || observation.RetrySafe {
		t.Fatalf("leftover artifact must be neither restored nor retry-safe: restored=%v retrySafe=%v", observation.FixtureRestored, observation.RetrySafe)
	}
}

// TestCredentialBindingReconcileDelegatesToCluster proves the shared identity adapter
// routes retry reconciliation through the credential binding to its cluster verifier.
func TestCredentialBindingReconcileDelegatesToCluster(t *testing.T) {
	profile := identityTestProfile(t, identityCatalogueCredential)
	cfg := Config{Service: ServiceAttacks, AttackCatalogEnabled: true, AttackCatalogAuthorizationTenant: "phorvex-test",
		AuditSource: &audittransport.Client{}}
	cluster := &fakeCredentialRetryCluster{safety: AttackCatalogRetrySafety{Verified: true, RetrySafe: true, Reason: "clean"}}
	adapter := &identityFamilyCatalogueAdapter{profile: profile, cfg: cfg,
		binding: &identityCredentialCatalogueBinding{cfg: cfg, fixedCluster: cluster}}
	if _, ok := attackCatalogReconcilerFor(adapter); !ok {
		t.Fatal("credential family adapter was not recognised as reconcilable")
	}
	safety, err := adapter.ReconcileRetrySafety(context.Background(), AttackCatalogResult{CatalogueID: profile.ID,
		Signal: AttackCatalogSignalResult{Name: "catalog-credential-abc"}})
	if err != nil || !safety.RetrySafe || cluster.signalName != "catalog-credential-abc" {
		t.Fatalf("delegation failed: safety=%+v err=%v signalName=%q", safety, err, cluster.signalName)
	}
}

// fakeCredentialRetryCluster is an injectable credential cluster that implements the
// optional read-only retry verifier so the delegation chain can be tested without a
// live cluster or SelfSubjectAccessReviews.
type fakeCredentialRetryCluster struct {
	identityCredentialCatalogueCluster
	safety     AttackCatalogRetrySafety
	err        error
	signalName string
}

func (c *fakeCredentialRetryCluster) reconcileRetrySafety(_ context.Context, _ identityCredentialServerProfile, signalName string) (AttackCatalogRetrySafety, error) {
	c.signalName = signalName
	return c.safety, c.err
}
