package main

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidateNamespaceFailClosed(t *testing.T) {
	for _, ns := range []string{"", "default", "phorvex-system", "phorvex-cost-validate-"} {
		if err := validateNamespace(ns); err == nil {
			t.Fatalf("validateNamespace(%q) allowed a non-disposable target", ns)
		}
	}
	if err := validateNamespace("phorvex-cost-validate-task35"); err != nil {
		t.Fatalf("valid disposable namespace rejected: %v", err)
	}
}

func TestObservedCostUsesOnlyAvailableTerms(t *testing.T) {
	obs := observation{
		AvailabilityLoss: 0.2,
		P99BeforeMS:      nullableFloat{Value: 100, Valid: true},
		P99AfterMS:       nullableFloat{Value: 150, Valid: true},
		TimeToReadySec:   nullableFloat{Value: 40, Valid: true},
		StateOrKVLoss:    nullableFloat{Value: 1, Valid: true},
	}
	got, terms := observedCost(obs)
	// mean(0.2 availability, 0.5 p99 increase, 0.1 ready, 1 state loss)
	want := 0.45
	if !got.Valid || terms != 4 || math.Abs(got.Value-want) > 1e-12 {
		t.Fatalf("observedCost=%+v terms=%d, want %.3f/4", got, terms, want)
	}
}

func TestNullableMetricFieldsRemainExplicitNull(t *testing.T) {
	data, err := json.Marshal(observation{P99BeforeMS: nullableFloat{}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["p99_before_ms"] != nil {
		t.Fatalf("missing measurement serialized as %v, want null", decoded["p99_before_ms"])
	}
}

func TestFeatureComponentsAreActionSpecific(t *testing.T) {
	o := options{Stateful: true, GPU: true}
	m := metricSnapshot{GPUUtil: nullableFloat{Value: 0.7, Valid: true}}
	if got := stateFeature(model.ActionRotate, o); got != 1 {
		t.Fatalf("state feature for stateful rotate=%v", got)
	}
	if got := stateFeature(model.ActionQuarantine, o); got != 0 {
		t.Fatalf("state feature for quarantine=%v", got)
	}
	if got := gpuFeature(model.ActionRotate, o, m); !got.Valid || got.Value != 0.7 {
		t.Fatalf("gpu feature=%+v", got)
	}
	if got := availabilityFeature(model.ActionRotate, 4); got != 0.25 {
		t.Fatalf("availability feature=%v", got)
	}
}

func TestTerminatingPodIsNotReady(t *testing.T) {
	now := metav1.NewTime(time.Now())
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue,
		}}},
	}
	if podReady(pod) {
		t.Fatal("terminating pod counted as Ready")
	}
}

func TestRotateReplacementMustBeNewToWholeReplicaSet(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "old-target", UID: "uid-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "old-peer", UID: "uid-b"}},
	}
	before := map[string]bool{"uid-a": true, "uid-b": true}
	if got := newReplica(pods, before); got.Name != "" {
		t.Fatalf("pre-existing peer accepted as replacement: %s", got.Name)
	}
	pods = append(pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "new", UID: "uid-c"}})
	if got := newReplica(pods, before); got.Name != "new" {
		t.Fatalf("replacement=%q, want new", got.Name)
	}
}

func TestTargetDepartureUsesUIDNotPodCount(t *testing.T) {
	pods := []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "peer", UID: "uid-b"}}}
	if containsUID(pods, "uid-a") {
		t.Fatal("departed target UID reported present because another replica remained")
	}
	if !containsUID(pods, "uid-b") {
		t.Fatal("present UID reported departed")
	}
}

func TestM124CostProbeHonorsIdentityBoundNamespaceAndPodBrakes(t *testing.T) {
	const namespace = namespacePrefix + "m124"
	fixture := func(t *testing.T, namespaceValue, podValue string) (client.Client, corev1.Pod) {
		t.Helper()
		s := runtime.NewScheme()
		if err := corev1.AddToScheme(s); err != nil {
			t.Fatal(err)
		}
		if err := appsv1.AddToScheme(s); err != nil {
			t.Fatal(err)
		}
		nsAnnotations, podAnnotations := map[string]string{}, map[string]string{}
		if namespaceValue != "" {
			nsAnnotations[actuationbrake.NamespaceDryRunAnnotation] = namespaceValue
		}
		if podValue != "" {
			podAnnotations[actuationbrake.PodOptOutAnnotation] = podValue
		}
		two, controller := int32(2), true
		rs := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "workload", UID: "rs-uid", ResourceVersion: "1"},
			Spec:       appsv1.ReplicaSetSpec{Replicas: &two, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}}},
		}
		pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: "target", UID: types.UID("pod-uid"), ResourceVersion: "1",
			Labels: map[string]string{"app": "workload"}, Annotations: podAnnotations,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}},
		}}
		c := fake.NewClientBuilder().WithScheme(s).WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, UID: "namespace-uid", Annotations: nsAnnotations}},
			rs, &pod,
		).Build()
		return c, pod
	}
	o := options{Namespace: namespace, Pod: "target"}

	t.Run("explicit-false-allows-real-native-dispatch", func(t *testing.T) {
		c, target := fixture(t, "false", "no")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result, err := actuateNativeCostProbe(ctx, c, o, model.ActionRotate, target)
		if err != nil || !result.Emitted {
			t.Fatalf("allowed cost probe dispatch = %+v, %v", result, err)
		}
		var after corev1.Pod
		if err := c.Get(ctx, client.ObjectKeyFromObject(&target), &after); !apierrors.IsNotFound(err) {
			t.Fatalf("real native rotate did not delete the bound target: %v", err)
		}
	})

	for _, tc := range []struct {
		name, namespaceValue, podValue, cause string
	}{
		{"namespace", " TRUE ", "false", actuationbrake.NamespaceDryRunEngaged},
		{"pod", "false", " yes ", actuationbrake.PodOptOutEngaged},
	} {
		t.Run(tc.name+"-brake-refuses-without-effect", func(t *testing.T) {
			c, target := fixture(t, tc.namespaceValue, tc.podValue)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := actuateNativeCostProbe(ctx, c, o, model.ActionRotate, target)
			if err == nil || result.Emitted || !strings.Contains(err.Error(), tc.cause) {
				t.Fatalf("braked cost probe dispatch = %+v, %v; want cause %s", result, err, tc.cause)
			}
			var after corev1.Pod
			if err := c.Get(ctx, client.ObjectKeyFromObject(&target), &after); err != nil || after.UID != target.UID {
				t.Fatalf("brake changed target: uid=%s err=%v", after.UID, err)
			}
		})
	}
}
