package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	amtd "github.com/r6security/phoenix/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// configureActuationBoundary gives older focused dispatch tests explicit live
// Namespace/Pod authority. It also completes deliberately minimal tick views
// with the immutable identity the production boundary requires.
func configureActuationBoundary(t *testing.T, m *Manager, namespace string, views map[string]*model.WorkloadView) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	objects := make([]client.Object, 0, len(views)+1)
	namespaces := map[string]bool{}
	if namespace != "" {
		objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
		namespaces[namespace] = true
	}
	for key, view := range views {
		if view == nil {
			continue
		}
		ns, name, ok := strings.Cut(key, "/")
		if !ok {
			t.Fatalf("invalid tick view key %q", key)
		}
		if view.Pod.Namespace == "" {
			view.Pod.Namespace = ns
		}
		if view.Pod.Name == "" {
			view.Pod.Name = name
		}
		if view.Pod.UID == "" {
			view.Pod.UID = "test-uid-" + ns + "-" + name
		}
		if !namespaces[ns] {
			objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
			namespaces[ns] = true
		}
		objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(view.Pod.UID),
		}})
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()
	m.BoundaryReader = c
	return c
}

func actuateWithBoundary(t *testing.T, m *Manager, ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, views map[string]*model.WorkloadView) int {
	t.Helper()
	if e.namespace == "" {
		for key := range views {
			e.namespace, _, _ = strings.Cut(key, "/")
			break
		}
	}
	configureActuationBoundary(t, m, e.namespace, views)
	return m.actuate(ctx, e, pol, decisions, views)
}

func actuatePreparedWithBoundary(t *testing.T, m *Manager, ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, views map[string]*model.WorkloadView) (int, *actuator.RoutePreparation) {
	t.Helper()
	configureActuationBoundary(t, m, e.namespace, views)
	return m.actuatePrepared(ctx, e, pol, decisions, views)
}

func TestM124SnapshotOptOutExcludesWithoutCapabilityFailure(t *testing.T) {
	views := []*model.WorkloadView{
		{Pod: model.Pod{Name: "blocked", OptOut: model.ActuationBrakeObservation{Engaged: true, Cause: actuationbrake.PodOptOutEngaged}}},
		{Pod: model.Pod{Name: "peer"}},
	}
	wit := capability.BuildWitness(context.Background(), capability.Index{}, model.InstallSet{}, nil, &fakeActuator{})
	report := capabilityGaps(model.Policy{EnabledActions: map[model.Action]bool{model.ActionRotate: true}}, views, wit)
	if report.observed != 1 || len(report.gaps) != 0 {
		t.Fatalf("opt-out changed capability status: %+v", report)
	}
	got := codeExecAwareEligibility(wit, false, func(*model.WorkloadView) bool { return false }, views[0], model.ActionRotate, []string{model.VarPodIdentity})
	if got == nil || !got.Excluded || got.Kind != model.ExclusionOperatorOptOut {
		t.Fatalf("opt-out eligibility = %+v", got)
	}
	if got := codeExecAwareEligibility(wit, false, func(*model.WorkloadView) bool { return false }, views[1], model.ActionRotate, []string{model.VarPodIdentity}); got != nil {
		t.Fatalf("peer eligibility = %+v", got)
	}
}

func TestM124OptedOutPodConsumesNoBudgetAndPeerRemainsSelectable(t *testing.T) {
	_, pol, seedViews, _ := m019Scenario(t)
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	one := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "workload", UID: "deployment-uid"},
		Spec:       appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}}},
	}
	replicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "workload-rs", UID: "replicaset-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(deployment, appsv1.SchemeGroupVersion.WithKind("Deployment"))}},
		Spec:       appsv1.ReplicaSetSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}}},
	}
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	pod := func(name, uid, optOut string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: name, UID: types.UID(uid), Labels: map[string]string{"app": "workload"},
				Annotations:     map[string]string{actuationbrake.PodOptOutAnnotation: optOut},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(replicaSet, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "main", Image: "example.invalid/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
				Volumes:    []corev1.Volume{{Name: "creds", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "creds"}}}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: ready},
		}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", UID: "namespace-uid"}},
		deployment, replicaSet,
		pod("blocked", "uid-blocked", " yes "), pod("peer", "uid-peer", "false"),
	).Build()
	snapshot, err := ingest.CollectSnapshot(context.Background(), c, time.Now(), nil, c)
	if err != nil {
		t.Fatal(err)
	}
	blockedPod, peerPod := snapshot.PodByKey["ns/blocked"], snapshot.PodByKey["ns/peer"]
	if blockedPod == nil || peerPod == nil || !blockedPod.OptOut.Engaged || peerPod.OptOut.Engaged {
		t.Fatalf("snapshot opt-out projection = blocked %+v peer %+v", blockedPod, peerPod)
	}
	blockedValue := *seedViews[0]
	blockedValue.Pod = *blockedPod
	peerValue := *seedViews[0]
	peerValue.Pod = *peerPod
	ce := decision.NewCoverageEngine()
	witness := capability.BuildWitness(context.Background(), capability.Index{}, model.InstallSet{}, nil, &fakeActuator{})
	wireCapabilityGates(ce, witness, false, func(*model.WorkloadView) bool { return false })
	decisions, err := ce.DecideChecked([]*model.WorkloadView{&blockedValue, &peerValue}, pol)
	if err != nil {
		t.Fatal(err)
	}
	selected := ""
	var blocked *model.Decision
	for i := range decisions {
		if decisions[i].Selected {
			if selected != "" {
				t.Fatalf("budget 1 selected multiple targets: %+v", decisions)
			}
			selected = decisions[i].Pod
		}
		if decisions[i].Pod == "blocked" {
			blocked = &decisions[i]
		}
	}
	if selected != "peer" || blocked == nil || blocked.Selected || blocked.Trace == nil {
		t.Fatalf("opt-out consumed budget: selected=%q blocked=%+v all=%+v", selected, blocked, decisions)
	}
	var found bool
	for _, row := range blocked.Trace.ActionStatus {
		if row.ExclusionKind == model.ExclusionOperatorOptOut {
			found = true
		}
	}
	if !found {
		t.Fatalf("operator opt-out reason missing: %+v", blocked.Trace.ActionStatus)
	}
}

func m124BoundaryClient(t *testing.T, namespaceValue, podValue string) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	nsAnnotations := map[string]string{}
	if namespaceValue != "" {
		nsAnnotations[actuationbrake.NamespaceDryRunAnnotation] = namespaceValue
	}
	podAnnotations := map[string]string{}
	if podValue != "" {
		podAnnotations[actuationbrake.PodOptOutAnnotation] = podValue
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", Annotations: nsAnnotations}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1", UID: types.UID("uid-p1"), Annotations: podAnnotations}},
	).Build()
}

func m124SetAnnotation(t *testing.T, c client.Client, object client.Object, key, value string) {
	t.Helper()
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(object), object); err != nil {
		t.Fatal(err)
	}
	annotations := object.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	if value == "" {
		delete(annotations, key)
	} else {
		annotations[key] = value
	}
	object.SetAnnotations(annotations)
	if err := c.Update(context.Background(), object); err != nil {
		t.Fatal(err)
	}
}

func m124DecisionAndViews() ([]model.Decision, map[string]*model.WorkloadView) {
	decisions := tracedSelectedDecision()
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{
		Namespace: "ns", Name: "p1", UID: "uid-p1", Ready: true,
		DesiredReplicas: 3, ReadyReplicas: 3,
	}}}
	return decisions, views
}

func TestM124LateNamespaceAndPodFlipsRefuseDispatchThenResume(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flip  func(*testing.T, client.Client)
		cause string
	}{
		{
			name: "namespace",
			flip: func(t *testing.T, c client.Client) {
				m124SetAnnotation(t, c, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, actuationbrake.NamespaceDryRunAnnotation, " TRUE ")
			},
			cause: actuationbrake.NamespaceDryRunEngaged,
		},
		{
			name: "pod",
			flip: func(t *testing.T, c client.Client) {
				m124SetAnnotation(t, c, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1"}}, actuationbrake.PodOptOutAnnotation, " yes ")
			},
			cause: actuationbrake.PodOptOutEngaged,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := m124BoundaryClient(t, "false", "false")
			hands := &m127BoundaryActuator{}
			hands.ensure = func(context.Context) error {
				tc.flip(t, c)
				return nil
			}
			m := &Manager{Actuator: hands, BoundaryReader: c, Intents: exposure.NewIntents()}
			decisions, views := m124DecisionAndViews()
			decisions[0].Handler = "stale"
			decisions[0].RollbackRef = "stale"
			decisions[0].ObjectsTouched = []string{"stale"}
			pol := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
			if got := m.actuate(ctx, &policyEntry{namespace: "ns"}, pol, decisions, views); got != 0 {
				t.Fatalf("actuated after late flip: %d", got)
			}
			if hands.ensureCalls != 1 || hands.actuateCalls != 0 || decisions[0].ActuationBrakeCause != tc.cause ||
				decisions[0].Trace.DispatchOutcome != model.DispatchNotAttempted || decisions[0].Handler != "" || decisions[0].RollbackRef != "" || len(decisions[0].ObjectsTouched) != 0 {
				t.Fatalf("late refusal = calls %d/%d decision=%+v trace=%+v", hands.ensureCalls, hands.actuateCalls, decisions[0], decisions[0].Trace)
			}
			record := audit.ToRecord(decisions[0])
			if record.ActuationBrakeCause != tc.cause || (tc.name == "namespace" && record.DryRunCause != tc.cause) {
				t.Fatalf("audit cause drifted from dispatch: %+v", record)
			}

			m124SetAnnotation(t, c, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, actuationbrake.NamespaceDryRunAnnotation, "false")
			m124SetAnnotation(t, c, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1"}}, actuationbrake.PodOptOutAnnotation, "false")
			hands.ensure = nil
			allowed, allowedViews := m124DecisionAndViews()
			if got := m.actuate(ctx, &policyEntry{namespace: "ns"}, pol, allowed, allowedViews); got != 1 || hands.actuateCalls != 1 || !allowed[0].Actuated {
				t.Fatalf("explicit false did not resume: got=%d calls=%d decision=%+v", got, hands.actuateCalls, allowed[0])
			}
		})
	}
}

func TestM124MissingReaderAndEmptySnapshotUIDFailClosed(t *testing.T) {
	pol := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	t.Run("missing-reader", func(t *testing.T) {
		hands := &m127BoundaryActuator{}
		m := &Manager{Actuator: hands}
		decisions, views := m124DecisionAndViews()
		if got := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, decisions, views); got != 0 || hands.ensureCalls != 0 || hands.actuateCalls != 0 {
			t.Fatalf("missing reader reached route/dispatch: got=%d route=%d dispatch=%d", got, hands.ensureCalls, hands.actuateCalls)
		}
		if decisions[0].ActuationBrakeCause != actuationbrake.BoundaryReaderUnavailable {
			t.Fatalf("missing reader cause = %+v", decisions[0])
		}
	})
	t.Run("empty-snapshot-uid", func(t *testing.T) {
		c := m124BoundaryClient(t, "false", "false")
		hands := &m127BoundaryActuator{}
		m := &Manager{Actuator: hands, BoundaryReader: c}
		decisions, views := m124DecisionAndViews()
		views["ns/p1"].Pod.UID = ""
		if got := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, decisions, views); got != 0 || hands.ensureCalls != 1 || hands.actuateCalls != 0 {
			t.Fatalf("empty UID reached dispatch: got=%d route=%d dispatch=%d", got, hands.ensureCalls, hands.actuateCalls)
		}
		if decisions[0].ActuationBrakeCause != actuationbrake.PodUIDChanged {
			t.Fatalf("empty UID cause = %+v", decisions[0])
		}
	})
}

func TestM124NamespaceStatusCauseClearsOnLaterObservation(t *testing.T) {
	h := newStatusHarness(t, time.Minute)
	h.e.namespace = h.e.key.Namespace
	h.e.spec.Mode = v1alpha1.ModeActive
	engaged := model.ActuationBrakeObservation{Engaged: true, Cause: actuationbrake.NamespaceDryRunMalformed}
	h.m.updateStatusObserved(context.Background(), h.e, 1, 1, 0, legacyKillSwitchObservation(false), time.Now(), actionsSupportStatus{
		status: metav1.ConditionTrue, reason: actionsSupportedReason, message: "supported", namespaceDryRun: engaged,
	})
	var policy v1alpha1.PhorvexPolicy
	if err := h.m.Client.Get(context.Background(), h.e.key, &policy); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(policy.Status.Conditions, "DryRun")
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != engaged.Cause || !strings.Contains(condition.Message, "malformed") {
		t.Fatalf("engaged status = %+v", condition)
	}
	h.m.updateStatusObserved(context.Background(), h.e, 1, 0, 0, legacyKillSwitchObservation(false), time.Now().Add(time.Second), actionsSupportStatus{
		status: metav1.ConditionTrue, reason: actionsSupportedReason, message: "supported", namespaceDryRun: actuationbrake.Namespace(map[string]string{actuationbrake.NamespaceDryRunAnnotation: "false"}),
	})
	if err := h.m.Client.Get(context.Background(), h.e.key, &policy); err != nil {
		t.Fatal(err)
	}
	condition = meta.FindStatusCondition(policy.Status.Conditions, "DryRun")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "Active" {
		t.Fatalf("later disengagement did not resume status: %+v", condition)
	}
}

func TestM124LatePodOptOutSuppressesFailureLearningAndFallbackReservation(t *testing.T) {
	ctx := context.Background()
	ce, pol, views, decisions := m019Scenario(t)
	hands := &m127BoundaryActuator{}
	m := &Manager{Actuator: hands, Optimizer: ce, Intents: exposure.NewIntents()}
	viewMap := map[string]*model.WorkloadView{"ns/pod": views[0]}
	c := configureActuationBoundary(t, m, "ns", viewMap)
	hands.actuate = func(context.Context, actuator.Request) (actuator.Result, error) {
		m124SetAnnotation(t, c, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod"}}, actuationbrake.PodOptOutAnnotation, "true")
		return actuator.Result{}, actuator.RefusedWithoutEffect(errors.New("precondition unavailable"))
	}
	if got := m.actuate(ctx, &policyEntry{namespace: "ns"}, pol, decisions, viewMap); got != 0 {
		t.Fatalf("actuated = %d", got)
	}
	if hands.actuateCalls != 1 || len(m.fallbackDecisions) != 0 || len(m.Failures.at) != 0 {
		t.Fatalf("opt-out allowed learning/fallback: calls=%d fallbacks=%d failures=%v", hands.actuateCalls, len(m.fallbackDecisions), m.Failures.at)
	}
	if _, ok := ce.SelectAlternative(pol.Owner(), "ns/pod", decisions[0].Action); !ok {
		t.Fatal("opt-out path reserved the fallback slot")
	}
	if decisions[0].ActuationBrakeCause != actuationbrake.PodOptOutEngaged ||
		decisions[0].KillSwitch || decisions[0].KillSwitchCause != "" || decisions[0].Trace.KillSwitchEngaged ||
		!strings.Contains(decisions[0].Trace.DispatchReason, "fallback-refused-actuation-brake: "+actuationbrake.PodOptOutEngaged) {
		t.Fatalf("fallback refusal evidence = %+v trace=%+v", decisions[0], decisions[0].Trace)
	}
}
