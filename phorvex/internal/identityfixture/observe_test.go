package identityfixture

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// identityWorld is a fully valid, observable fixture. Tests mutate exactly one
// property and assert the single oracle binding that must then reject or bind.
type identityWorld struct {
	ns     *corev1.Namespace
	pod    *corev1.Pod
	sa     *corev1.ServiceAccount
	rs     *appsv1.ReplicaSet
	dep    *appsv1.Deployment
	policy *v1alpha1.PhorvexPolicy
	marker *corev1.ConfigMap
	extra  []client.Object
}

const (
	testNamespace = "console-identity-test"
	testNSUID     = "ns-uid-0001"
	testRun       = "console-id-fixture"
	testPolicyUID = "policy-uid-0001"
	testSAUID     = "sa-uid-old-0001"
	testPodName   = "console-id-fixture-5f9c7"
	testPodUID    = "pod-uid-0001"
)

func ptrBool(b bool) *bool    { return &b }
func ptrInt64(i int64) *int64 { return &i }

func newIdentityWorld() *identityWorld {
	controller := true
	saCreated := metav1.NewTime(time.Now().UTC().Add(-10 * time.Minute))
	podCreated := metav1.NewTime(time.Now().UTC().Add(-5 * time.Minute))
	w := &identityWorld{
		ns: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace, UID: testNSUID,
			Labels: map[string]string{Label: NamespaceOwnedLabelValue}}},
		sa: &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: testRun, Namespace: testNamespace,
			UID: testSAUID, CreationTimestamp: saCreated, Labels: map[string]string{Label: testRun}}},
		dep: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: testRun, Namespace: testNamespace, UID: "dep-uid-0001"},
			Spec: appsv1.DeploymentSpec{Replicas: ptrInt64Int32(1),
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: testRun}}}},
		rs: &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: testRun + "-5f9c7", Namespace: testNamespace, UID: "rs-uid-0001",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: testRun, UID: "dep-uid-0001", Controller: &controller}}}},
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: testPodName, Namespace: testNamespace, UID: testPodUID,
			CreationTimestamp: podCreated, Labels: map[string]string{Label: testRun},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: testRun + "-5f9c7", UID: "rs-uid-0001", Controller: &controller}}},
			Spec: corev1.PodSpec{ServiceAccountName: testRun,
				Containers: []corev1.Container{{Name: "workload", Image: Image, Command: Command,
					VolumeMounts: []corev1.VolumeMount{{Name: "api", MountPath: Mount, ReadOnly: true}}}},
				Volumes: []corev1.Volume{{Name: "api", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Path: "token", ExpirationSeconds: ptrInt64(TokenExpirationSeconds)}}}}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
				Name: "workload", Ready: true, Started: ptrBool(true), RestartCount: 0,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
		policy: &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: testRun, Namespace: testNamespace,
			UID: testPolicyUID, Generation: 3}, Status: v1alpha1.PhorvexPolicyStatus{ObservedGeneration: 3},
			Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{Label: testRun}},
				Triggers: v1alpha1.TriggersSpec{EventDriven: true},
				Actions:  v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionIdentityRotate)}}}},
		marker: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: testRun, Namespace: testNamespace}, Data: map[string]string{
			MarkerKeyPodUID: testPodUID, MarkerKeySAUID: testSAUID, MarkerKeyProducer: MarkerProducer,
			MarkerKeyLandedAt: time.Now().UTC().Format(time.RFC3339Nano)}},
	}
	return w
}

func ptrInt64Int32(i int32) *int32 { return &i }

func (w *identityWorld) profile() Profile {
	return Profile{JournalNamespace: "phorvex-journal", Namespace: testNamespace, NamespaceUID: testNSUID,
		PolicyName: testRun, PolicyUID: testPolicyUID, PolicyGeneration: 0, Cluster: "phorvex-dev-eks", Region: "us-east-2"}
}

// reader builds a fake client that, like a real API server, returns a non-empty
// ResourceVersion on List responses (the bare fake client leaves it empty).
func (w *identityWorld) reader(t *testing.T, withMarker bool) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	objs := []client.Object{w.ns, w.pod, w.sa, w.rs, w.dep, w.policy}
	if withMarker {
		objs = append(objs, w.marker)
	}
	objs = append(objs, w.extra...)
	base := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}
			list.SetResourceVersion("1000")
			return nil
		},
	})
}

func TestObserveKubernetesPositiveBindsLiveGeneration(t *testing.T) {
	w := newIdentityWorld()
	out, err := ObserveKubernetes(context.Background(), w.reader(t, false), w.profile(), testPodName, testPodUID, false)
	if err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	// Profile pins generation 0 (bind-to-live); the observation must carry the
	// live policy's generation, not the zero pin.
	if out.Observation == nil || out.Observation.PolicyGeneration != 3 {
		t.Fatalf("observation did not bind the live generation: %+v", out.Observation)
	}
	if out.Observation.ServiceAccountUID != testSAUID {
		t.Fatalf("unexpected SA binding: %+v", out.Observation)
	}
}

func TestObserveKubernetesActiveRequiresMarker(t *testing.T) {
	w := newIdentityWorld()
	if _, err := ObserveKubernetes(context.Background(), w.reader(t, false), w.profile(), testPodName, testPodUID, true); err == nil {
		t.Fatal("active observation admitted without the positive-control marker")
	}
	if _, err := ObserveKubernetes(context.Background(), w.reader(t, true), w.profile(), testPodName, testPodUID, true); err != nil {
		t.Fatalf("active observation rejected a valid marker: %v", err)
	}
}

// Regression: a workload that exits and is restarted (the old bounded-sleep bug)
// must never be accepted — restartCount drift is the blocker this fix removes at
// the source (non-terminating Command), but the oracle still rejects a drifted pod.
func TestObserveKubernetesRejectsRestartedPod(t *testing.T) {
	w := newIdentityWorld()
	w.pod.Status.ContainerStatuses[0].RestartCount = 101
	if _, err := ObserveKubernetes(context.Background(), w.reader(t, false), w.profile(), testPodName, testPodUID, false); err == nil {
		t.Fatal("restarted fixture pod (restartCount!=0) was accepted")
	}
}

// Regression: generation drift. A static profile pin that no longer matches the
// live policy must reject; binding to live (pin 0) must accept the live generation.
func TestObserveKubernetesStaticPinDriftVsBindToLive(t *testing.T) {
	w := newIdentityWorld() // live policy generation == 3, reconciled.
	stale := w.profile()
	stale.PolicyGeneration = 2 // the committed-vs-live drift observed in staging.
	if _, err := ObserveKubernetes(context.Background(), w.reader(t, false), stale, testPodName, testPodUID, false); err == nil {
		t.Fatal("stale static generation pin (2 vs live 3) was accepted")
	}
	live := w.profile() // generation 0 == bind-to-live.
	if _, err := ObserveKubernetes(context.Background(), w.reader(t, false), live, testPodName, testPodUID, false); err != nil {
		t.Fatalf("bind-to-live rejected the real policy generation: %v", err)
	}
}

// Regression: a policy caught mid-edit (metadata.generation ahead of the
// controller's status.observedGeneration) must never be observed.
func TestObserveKubernetesRejectsUnreconciledPolicy(t *testing.T) {
	w := newIdentityWorld()
	w.policy.Generation = 4
	w.policy.Status.ObservedGeneration = 3 // reconcile has not caught up.
	if _, err := ObserveKubernetes(context.Background(), w.reader(t, false), w.profile(), testPodName, testPodUID, false); err == nil {
		t.Fatal("unreconciled policy (observedGeneration<generation) was observed")
	}
}

// Regression: run-bound generation. Once preflight binds a run to one live
// generation, a later observation at a changed generation must invalidate the
// run (not silently re-bind), even though every other object is still valid.
func TestObserveKubernetesAtRunBoundGeneration(t *testing.T) {
	w := newIdentityWorld() // live reconciled generation == 3.
	if _, err := ObserveKubernetesAt(context.Background(), w.reader(t, false), w.profile(), testPodName, testPodUID, false, 3); err != nil {
		t.Fatalf("run-bound generation 3 rejected the matching live policy: %v", err)
	}
	// The policy advanced to a new, fully reconciled generation mid-run.
	w2 := newIdentityWorld()
	w2.policy.Generation = 4
	w2.policy.Status.ObservedGeneration = 4
	if _, err := ObserveKubernetesAt(context.Background(), w2.reader(t, false), w2.profile(), testPodName, testPodUID, false, 3); err == nil {
		t.Fatal("a mid-run policy generation change was silently re-bound instead of rejected")
	}
}

func TestObserveKubernetesRejectsStaleAndSubstitutedState(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC())
	cases := map[string]func(*identityWorld){
		"deleting-pod":        func(w *identityWorld) { w.pod.DeletionTimestamp = &now; w.pod.Finalizers = []string{"x"} },
		"pod-not-running":     func(w *identityWorld) { w.pod.Status.Phase = corev1.PodPending },
		"not-ready":           func(w *identityWorld) { w.pod.Status.ContainerStatuses[0].Ready = false },
		"wrong-pod-uid":       func(w *identityWorld) { w.pod.UID = "other-uid" },
		"wrong-namespace-uid": func(w *identityWorld) { w.ns.UID = "other-ns-uid" },
		"unowned-namespace":   func(w *identityWorld) { w.ns.Labels = map[string]string{} },
		"wrong-policy-uid":    func(w *identityWorld) { w.policy.UID = "other-policy-uid" },
		"dry-run-policy":      func(w *identityWorld) { w.policy.Spec.Mode = v1alpha1.ModeDryRun },
		"rotate-action-off": func(w *identityWorld) {
			w.policy.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionAgentActionDeny)}
		},
		"selector-misses": func(w *identityWorld) {
			w.policy.Spec.Selector = metav1.LabelSelector{MatchLabels: map[string]string{Label: "other"}}
		},
		"sa-after-pod": func(w *identityWorld) { w.sa.CreationTimestamp = metav1.NewTime(time.Now().UTC().Add(time.Hour)) },
		"federated-sa": func(w *identityWorld) {
			w.sa.Annotations = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/x"}
		},
		"second-consumer-pod": func(w *identityWorld) { w.extra = append(w.extra, secondConsumerPod()) },
		"mismatched-command":  func(w *identityWorld) { w.pod.Spec.Containers[0].Command = []string{"sh", "-c", "sleep 1800"} },
		"token-wrong-expiry": func(w *identityWorld) {
			w.pod.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.ExpirationSeconds = ptrInt64(3600)
		},
		"token-audience-scoped": func(w *identityWorld) {
			w.pod.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = "sts"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := newIdentityWorld()
			mutate(w)
			if _, err := ObserveKubernetes(context.Background(), w.reader(t, false), w.profile(), testPodName, testPodUID, false); err == nil {
				t.Fatalf("%s state was accepted", name)
			}
		})
	}
}

func secondConsumerPod() *corev1.Pod {
	controller := true
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: testPodName + "-dup", Namespace: testNamespace, UID: "pod-uid-dup",
		Labels:          map[string]string{Label: testRun},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: testRun + "-5f9c7", UID: "rs-uid-0001", Controller: &controller}}},
		Spec:   corev1.PodSpec{ServiceAccountName: testRun},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
}

func TestProfileValidateBindToLiveGeneration(t *testing.T) {
	base := (&identityWorld{}).profile()
	base.PolicyGeneration = 0
	if err := base.Validate(); err != nil {
		t.Fatalf("bind-to-live profile (generation 0) rejected: %v", err)
	}
	pinned := base
	pinned.PolicyGeneration = 7
	if err := pinned.Validate(); err != nil {
		t.Fatalf("explicit positive generation pin rejected: %v", err)
	}
	negative := base
	negative.PolicyGeneration = -1
	if err := negative.Validate(); err == nil {
		t.Fatal("negative generation accepted")
	}
}

// The source invariant behind the restartCount fix: the fixture workload must be
// non-terminating, so kubelet never restarts it under normal operation.
func TestFixtureCommandIsNonTerminating(t *testing.T) {
	joined := strings.Join(Command, " ")
	if strings.Contains(joined, "1800") {
		t.Fatalf("fixture command still uses a bounded sleep that self-terminates: %q", joined)
	}
	if !strings.Contains(joined, "time.sleep(2147483647)") {
		t.Fatalf("fixture command is not the expected non-terminating sleep: %q", joined)
	}
}
