package scenarios

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestStatefulTrainingMetadataIsMarkerOnly(t *testing.T) {
	md := (&c2StatefulTraining{}).Metadata()
	if md.EffectiveRealism() != core.RealismMarkerSimulation {
		t.Fatalf("realism=%q", md.EffectiveRealism())
	}
	if md.BenignControl || len(md.AttackTechniqueIDs) == 0 || len(md.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("marker classification is dishonest: benign=%v declared=%v exercised=%v", md.BenignControl, md.AttackTechniqueIDs, md.ExercisedTechniqueIDs)
	}
	for _, limitation := range []string{"containment", "NetworkPolicy enforcement", "checkpoint durability", "application progress", "work preservation", "GPU training"} {
		if !strings.Contains(md.ClaimLimits, limitation) {
			t.Errorf("claim limits omit %q: %s", limitation, md.ClaimLimits)
		}
	}
}

func TestStatefulTrainingOracleIgnoresUnrelatedPolicyAndEvent(t *testing.T) {
	setFastStatefulObservation(t)
	for _, tc := range []struct {
		name       string
		addPolicy  bool
		denyPolicy bool
		addEvent   bool
	}{
		{name: "negative-no-unrelated-object"},
		{name: "unrelated-permitting-policy", addPolicy: true},
		{name: "targeted-deny-without-enforcement", addPolicy: true, denyPolicy: true},
		{name: "unrelated-cluster-event", addEvent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := statefulOracleEnv(t, "original", tc.addPolicy, tc.denyPolicy, tc.addEvent)
			core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
				return core.ExecResult{Stdout: BackdoorMarker, ExitCode: 0}
			})
			t.Cleanup(func() { core.SetExecer(nil) })
			got, err := observedStatefulScenario().SuccessOracle(context.Background(), env)
			if err != nil || !got.Achieved {
				t.Fatalf("marker result changed by unrelated object: achieved=%v err=%v evidence=%v", got.Achieved, err, got.Evidence)
			}
			if got.Evidence["containment"] != "unobserved" || got.Evidence["workPreserved"] != "unobserved" || got.Evidence["networkEffect"] != "unobserved" {
				t.Fatalf("unmeasured favorable effect was claimed: %v", got.Evidence)
			}
			if _, exists := got.Evidence["quarantined"]; exists {
				t.Fatalf("legacy favorable quarantine field survived correction: %v", got.Evidence)
			}
			if _, exists := got.Evidence[core.EvReactionSeconds]; exists {
				t.Fatalf("marker observation window was mislabeled as defense reaction: %v", got.Evidence)
			}
		})
	}
}

func TestStatefulTrainingOracleRequiresExactMarkerRead(t *testing.T) {
	setFastStatefulObservation(t)
	for _, tc := range []struct {
		name         string
		stdout       string
		execErr      error
		wantErr      bool
		wantAchieved bool
	}{
		{name: "explicit-marker-absent", stdout: observationAbsent},
		{name: "malformed-readback", stdout: "ambiguous", wantErr: true},
		{name: "failed-readback", execErr: context.DeadlineExceeded, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := statefulOracleEnv(t, "original", false, false, false)
			core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
				return core.ExecResult{Stdout: tc.stdout, ExitCode: 0, Err: tc.execErr}
			})
			t.Cleanup(func() { core.SetExecer(nil) })
			got, err := observedStatefulScenario().SuccessOracle(context.Background(), env)
			if (err != nil) != tc.wantErr || got.Achieved != tc.wantAchieved {
				t.Fatalf("result achieved=%v err=%v", got.Achieved, err)
			}
		})
	}
}

func TestStatefulTrainingOracleSeparatesIdentityRemovalFromContainment(t *testing.T) {
	setFastStatefulObservation(t)
	for _, tc := range []struct {
		name string
		uid  types.UID
	}{
		{name: "original-absent"},
		{name: "same-name-replacement", uid: "replacement"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := statefulOracleEnv(t, tc.uid, false, false, false)
			called := false
			core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
				called = true
				return core.ExecResult{Stdout: BackdoorMarker, ExitCode: 0}
			})
			t.Cleanup(func() { core.SetExecer(nil) })
			got, err := observedStatefulScenario().SuccessOracle(context.Background(), env)
			if err != nil || got.Achieved || got.Evidence["originalUIDAbsent"] != "true" {
				t.Fatalf("identity removal result=%+v err=%v", got, err)
			}
			if got.Evidence["containment"] != "unobserved" || got.Evidence["workPreserved"] != "unobserved" {
				t.Fatalf("identity removal became favorable stateful claim: %v", got.Evidence)
			}
			if called {
				t.Fatal("marker was read from a replacement identity")
			}
		})
	}
}

func TestStatefulTrainingExecutePreservesProducerFailureAndClearsStimulus(t *testing.T) {
	env := statefulOracleEnv(t, "original", false, false, false)
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		return core.ExecResult{ExitCode: -1, Err: errors.New("synthetic marker producer failed")}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedStatefulScenario()
	if _, err := s.Execute(context.Background(), env); err == nil || !strings.Contains(err.Error(), "producer failed") {
		t.Fatalf("producer failure error=%v", err)
	}
	if !s.markerPlantedAt.IsZero() {
		t.Fatalf("failed producer retained favorable prior stimulus time: %s", s.markerPlantedAt)
	}
}

func TestStatefulTrainingOraclePreservesObservationFailureAndCancellation(t *testing.T) {
	t.Run("pod read failure", func(t *testing.T) {
		setFastStatefulObservation(t)
		env := statefulOracleEnv(t, "original", false, false, false)
		env.Kube.(*k8sfake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver unavailable")
		})
		if _, err := observedStatefulScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "apiserver unavailable") {
			t.Fatalf("pod observation error=%v", err)
		}
	})
	t.Run("cancelled window", func(t *testing.T) {
		env := statefulOracleEnv(t, "original", false, false, false)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := observedStatefulScenario().SuccessOracle(ctx, env); err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("cancelled observation error=%v", err)
		}
	})
}

func TestStatefulTrainingSetupCollisionPreservesForeignPVC(t *testing.T) {
	env := fixtureObservationEnv()
	foreign := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "c2st-train-work", Namespace: "sandbox", UID: "foreign-pvc"}}
	if _, err := env.Kube.CoreV1().PersistentVolumeClaims("sandbox").Create(context.Background(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s := &c2StatefulTraining{targetName: "stale", targetUID: "stale", pvcUID: "stale", markerPlantedAt: time.Now()}
	if err := s.Setup(context.Background(), env); err == nil || !apierrors.IsAlreadyExists(errors.Unwrap(err)) {
		t.Fatalf("foreign PVC collision error=%v", err)
	}
	if s.targetUID != "" || s.pvcUID != "" || !s.markerPlantedAt.IsZero() {
		t.Fatalf("setup retained stale ownership/stimulus: %+v", s)
	}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	got, err := env.Kube.CoreV1().PersistentVolumeClaims("sandbox").Get(context.Background(), foreign.Name, metav1.GetOptions{})
	if err != nil || got.UID != foreign.UID {
		t.Fatalf("foreign PVC was deleted or replaced: pvc=%+v err=%v", got, err)
	}
}

func TestStatefulTrainingSetupBindsCreatedUIDsAndTeardownPreconditions(t *testing.T) {
	env := fixtureObservationEnv()
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("create", "persistentvolumeclaims", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*corev1.PersistentVolumeClaim).UID = "owned-pvc"
		return false, nil, nil
	})
	client.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pod := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		pod.UID = "owned-pod"
		pod.Status.Phase = corev1.PodRunning
		return false, nil, nil
	})
	var deleted []types.UID
	client.PrependReactor("delete", "pods", captureStatefulDeleteUID(t, &deleted))
	client.PrependReactor("delete", "persistentvolumeclaims", captureStatefulDeleteUID(t, &deleted))
	s := &c2StatefulTraining{}
	if err := s.Setup(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if s.targetName != "c2st-train" || s.targetUID != "owned-pod" || s.pvcUID != "owned-pvc" {
		t.Fatalf("create-response identities not retained: %+v", s)
	}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 || deleted[0] != "owned-pod" || deleted[1] != "owned-pvc" {
		t.Fatalf("cleanup UID preconditions=%v", deleted)
	}
}

func TestStatefulTrainingTeardownReportsUIDConflictAndPreservesReplacement(t *testing.T) {
	env := fixtureObservationEnv()
	replacement := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "c2st-train-work", Namespace: "sandbox", UID: "replacement-pvc"}}
	if _, err := env.Kube.CoreV1().PersistentVolumeClaims("sandbox").Create(context.Background(), replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("delete", "persistentvolumeclaims", func(action k8stesting.Action) (bool, runtime.Object, error) {
		opts := action.(k8stesting.DeleteAction).GetDeleteOptions()
		if opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != "owned-pvc" {
			t.Fatalf("wrong delete precondition: %+v", opts)
		}
		return true, nil, errors.New("UID precondition rejected replacement")
	})
	s := &c2StatefulTraining{pvc: replacement.Name, pvcUID: "owned-pvc"}
	if err := s.Teardown(context.Background(), env); err == nil {
		t.Fatal("cleanup failure was hidden")
	}
	got, err := env.Kube.CoreV1().PersistentVolumeClaims("sandbox").Get(context.Background(), replacement.Name, metav1.GetOptions{})
	if err != nil || got.UID != replacement.UID {
		t.Fatalf("replacement PVC was deleted: pvc=%+v err=%v", got, err)
	}
}

func statefulOracleEnv(t *testing.T, podUID types.UID, addPolicy, denyPolicy, addEvent bool) *core.Env {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := k8sfake.NewSimpleClientset()
	if podUID != "" {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "c2st-train", Namespace: "sandbox", UID: podUID, Labels: map[string]string{"app": "c2st-train"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "trainer"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
		if _, err := kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if addPolicy {
		np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-allow-all", Namespace: "sandbox", UID: "unrelated-policy"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "unrelated"}}, Ingress: []networkingv1.NetworkPolicyIngressRule{{}}}}
		if denyPolicy {
			np.Name = "targeted-deny-without-backend"
			np.Spec.PodSelector.MatchLabels["app"] = "c2st-train"
			np.Spec.Ingress = nil
			np.Spec.Egress = nil
			np.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
		}
		if _, err := kube.NetworkingV1().NetworkPolicies("sandbox").Create(context.Background(), np, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ctrlBuilder := ctrlfake.NewClientBuilder().WithScheme(scheme)
	if addEvent {
		ctrlBuilder = ctrlBuilder.WithObjects(&amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "other", UID: "unrelated-event"}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"other/unrelated"}, Rule: amtdv1beta1.Rule{Type: "phorvex.quarantine"}}})
	}
	return &core.Env{Kube: kube, Ctrl: ctrlBuilder.Build(), Rest: &rest.Config{}, Config: config.TargetConfig{Namespace: "sandbox"}, Log: &dpLogger{}, Guard: dpGuard{}}
}

func observedStatefulScenario() *c2StatefulTraining {
	return &c2StatefulTraining{app: "c2st-train", pvc: "c2st-train-work", targetName: "c2st-train", targetUID: "original", pvcUID: "owned-pvc", markerPlantedAt: time.Now().Add(-statefulMarkerObservationWindow)}
}

func setFastStatefulObservation(t *testing.T) {
	t.Helper()
	old := statefulMarkerObservationWait
	statefulMarkerObservationWait = func(ctx context.Context, interval time.Duration) (time.Time, time.Time, error) {
		start := time.Now()
		if err := ctx.Err(); err != nil {
			return start, start, err
		}
		return start, start.Add(interval), nil
	}
	t.Cleanup(func() { statefulMarkerObservationWait = old })
}

func captureStatefulDeleteUID(t *testing.T, got *[]types.UID) k8stesting.ReactionFunc {
	t.Helper()
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		opts := action.(k8stesting.DeleteAction).GetDeleteOptions()
		if opts.Preconditions == nil || opts.Preconditions.UID == nil {
			t.Fatal("delete omitted UID precondition")
		}
		*got = append(*got, *opts.Preconditions.UID)
		return true, nil, nil
	}
}
