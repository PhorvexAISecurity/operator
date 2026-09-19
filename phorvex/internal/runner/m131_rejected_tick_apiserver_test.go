package runner

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	metricspkg "github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
)

// m131StatusRaceClient replaces a policy after the updater's authoritative Get
// and immediately before its first status write. The real API server must reject
// the stale resourceVersion; RetryOnConflict then reads the replacement UID.
type m131StatusRaceClient struct {
	client.Client
	beforeFirstUpdate func(context.Context) error
	fired             bool
}

func (c *m131StatusRaceClient) Status() client.SubResourceWriter {
	return &m131StatusRaceWriter{SubResourceWriter: c.Client.Status(), parent: c}
}

type m131StatusRaceWriter struct {
	client.SubResourceWriter
	parent *m131StatusRaceClient
}

func (w *m131StatusRaceWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if !w.parent.fired {
		w.parent.fired = true
		if err := w.parent.beforeFirstUpdate(ctx); err != nil {
			return err
		}
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestM131RealAPIRejectedTickAndReplacementUIDBoundary(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	useExistingCluster := false
	env := &envtest.Environment{
		UseExistingCluster: &useExistingCluster, CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}); err != nil {
		t.Fatal(err)
	}
	p := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "m131-real-api", Generation: 1},
		Spec: v1alpha1.PhorvexPolicySpec{
			Tenant: "m131-real-api", Mode: v1alpha1.ModeDryRun, Selector: metav1.LabelSelector{},
			Budget: v1alpha1.BudgetSpec{
				TickInterval:           metav1.Duration{Duration: 20 * time.Second},
				AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
				ProactiveFloor:         metav1.Duration{Duration: time.Hour},
			},
			SLO: v1alpha1.SLOSpec{MinAvailableReplicas: 1},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{
				v1alpha1.ActionType(model.ActionRotate),
			}},
		},
	}
	if err := apiClient.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	oldTick := metav1.NewTime(time.Unix(1_700_000_000, 0).UTC())
	lastDecision := metav1.NewTime(oldTick.Add(-time.Hour))
	p.Status = v1alpha1.PhorvexPolicyStatus{
		SelectedPods: 31, LastTickTime: oldTick, LastDecisionTime: lastDecision, DecisionsTotal: 11,
		Conditions: []metav1.Condition{
			{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ticking"},
			{Type: "ValidationError", Status: metav1.ConditionTrue, Reason: "ControllerOwned", Message: "real API sentinel"},
		},
	}
	if err := apiClient.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(apiClient, logr.Discard())
	if err != nil {
		t.Fatal(err)
	}
	engine := decision.NewCoverageEngine()
	engine.Recon = m131Recon{collision: true}
	m.Optimizer = engine
	m.Calibration = nil
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	entry := m.policies[client.ObjectKeyFromObject(p).String()]
	m.processTenant(ctx, m131Snapshot(oldTick.Add(2*time.Hour)), entry, false)

	var rejected v1alpha1.PhorvexPolicy
	if err := apiClient.Get(ctx, client.ObjectKeyFromObject(p), &rejected); err != nil {
		t.Fatal(err)
	}
	ready := m131Condition(t, &rejected, "Ready")
	if ready.Status != metav1.ConditionFalse || ready.Reason != "ActionSetRejected" {
		t.Fatalf("real API rejected Ready condition = %+v", ready)
	}
	if rejected.SelectedPods != 2 || rejected.DecisionsTotal != 11 || !rejected.LastDecisionTime.Equal(&lastDecision) {
		t.Fatalf("real API rejection status = %+v", rejected.Status)
	}
	if validation := m131Condition(t, &rejected, "ValidationError"); validation.Message != "real API sentinel" {
		t.Fatalf("controller-owned validation changed: %+v", validation)
	}
	recorder := record.NewFakeRecorder(2)
	m.Recorder = recorder

	// Recreate the same object key with a server-assigned replacement UID exactly
	// between the shared status updater's authoritative Get and status write. The
	// stale write conflicts, the retry reads the replacement, and the UID guard
	// must stop operational evidence, its pending unsupported event, and the later
	// existential status transaction.
	stale := entry
	replacement := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name}, Spec: p.Spec,
	}
	raceClient := &m131StatusRaceClient{Client: apiClient}
	raceClient.beforeFirstUpdate = func(ctx context.Context) error {
		if err := apiClient.Delete(ctx, &rejected); err != nil {
			return err
		}
		if err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
			var deleted v1alpha1.PhorvexPolicy
			err := apiClient.Get(ctx, client.ObjectKeyFromObject(p), &deleted)
			return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
		}); err != nil {
			return err
		}
		if err := apiClient.Create(ctx, replacement); err != nil {
			return err
		}
		return m.Upsert(replacement)
	}
	m.Client = raceClient
	m.updateRejectedStatusObserved(ctx, stale, 2, legacyKillSwitchObservation(false), time.Now(),
		metricspkg.RejectCrossBlockCollision, actionsSupportStatus{
			status: metav1.ConditionFalse, reason: actionsUnsupportedReason, message: "predecessor unsupported action",
		})
	if !raceClient.fired {
		t.Fatal("replacement control never reached the between-Get-and-write boundary")
	}
	if replacement.UID == p.UID {
		t.Fatal("API server reused policy UID in replacement control")
	}
	select {
	case event := <-recorder.Events:
		t.Fatalf("predecessor emitted an unsupported-action event for replacement UID: %s", event)
	default:
	}
	m.updateExistentialStatus(ctx, stale, []model.Decision{{
		Namespace: stale.namespace, Pod: "predecessor-pod",
		Existential: &model.ExistentialDecision{Present: true, Result: "uncontainable"},
	}})

	var current v1alpha1.PhorvexPolicy
	if err := apiClient.Get(ctx, client.ObjectKeyFromObject(replacement), &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.ObservedGeneration != 0 || current.Status.SelectedPods != 0 ||
		current.Status.DecisionsTotal != 0 || len(current.Status.Conditions) != 0 {
		t.Fatalf("predecessor wrote rejected/existential status onto replacement UID: %+v", current.Status)
	}
}
