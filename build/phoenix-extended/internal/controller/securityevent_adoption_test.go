package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func pendingPod(name string, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Annotations: annotations},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}},
	}
}

func deleteAMTD() *amtdv1beta1.AdaptiveMovingTargetDefense {
	amtd := timedRotateAMTD("default", "amtd-delete")
	amtd.Spec.Strategy[0].Action = amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}}
	return amtd
}

func adoptionReconciler(objects ...client.Object) (*SecurityEventReconciler, client.Client) {
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(objects...).Build()
	return &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}, cl
}

func TestSecurityEventReconciler_PendingAdoptionRetriesWithoutMutation(t *testing.T) {
	cases := map[string]map[string]string{
		"nil annotations":    nil,
		"missing annotation": {"unrelated": "value"},
		"empty annotation":   {AMTD_MANAGED_BY: ""},
		"json null":          {AMTD_MANAGED_BY: "null"},
		"empty list":         {AMTD_MANAGED_BY: "[]"},
	}
	for name, annotations := range cases {
		t.Run(name, func(t *testing.T) {
			pod := pendingPod("pending", annotations)
			ev := timedSecurityEvent("event", "default/pending")
			r, cl := adoptionReconciler(pod, ev)

			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}})
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if result.RequeueAfter != 2*time.Second {
				t.Fatalf("RequeueAfter = %v, want 2s", result.RequeueAfter)
			}
			var after corev1.Pod
			if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pod), &after); err != nil {
				t.Fatalf("pending pod was mutated or removed: %v", err)
			}
			if _, found := after.Annotations[AMTD_APPLIED_SECURITY_EVENTS]; found {
				t.Fatal("pending event was recorded as applied")
			}
		})
	}
}

func TestSecurityEventReconciler_AdoptionRetryThenExecutesOriginalEvent(t *testing.T) {
	pod := pendingPod("pending", nil)
	ev := timedSecurityEvent("event", "default/pending")
	amtd := deleteAMTD()
	r, cl := adoptionReconciler(pod, ev, amtd)

	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}})
	if err != nil || result.RequeueAfter != 2*time.Second {
		t.Fatalf("initial Reconcile = (%v, %v), want 2s retry and nil error", result, err)
	}

	var adopted corev1.Pod
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pod), &adopted); err != nil {
		t.Fatal(err)
	}
	adopted.Annotations = managedPod("pending", "default", "default", amtd.Name).Annotations
	if err := cl.Update(context.Background(), &adopted); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}}); err != nil {
		t.Fatalf("Reconcile after adoption: %v", err)
	}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err == nil {
		t.Fatal("original event did not execute after adoption")
	}
}

func TestSecurityEventReconciler_InvalidAdoptionMetadataFails(t *testing.T) {
	for name, raw := range map[string]string{
		"malformed json":  "not-json",
		"wrong json type": `{}`,
		"empty entry":     `[{}]`,
		"missing name":    `[{"amtd-namespace":"default"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			pod := pendingPod("invalid", map[string]string{AMTD_MANAGED_BY: raw})
			ev := timedSecurityEvent("event", "default/invalid")
			r, _ := adoptionReconciler(pod, ev)
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}}); err == nil {
				t.Fatal("Reconcile succeeded with invalid management metadata")
			}
		})
	}
}

func TestSecurityEventReconciler_PreflightValidatesTargetsAfterPendingOne(t *testing.T) {
	pending := pendingPod("pending", nil)
	invalid := pendingPod("invalid", map[string]string{AMTD_MANAGED_BY: "not-json"})
	ev := timedSecurityEvent("event", "default/pending")
	ev.Spec.Targets = []string{"default/pending", "default/invalid"}
	r, _ := adoptionReconciler(pending, invalid, ev)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}}); err == nil {
		t.Fatal("batch preflight stopped at pending target without validating the remaining target")
	}
}

func TestSecurityEventReconciler_InvalidTargetFailsWithoutPanic(t *testing.T) {
	for _, target := range []string{"", "pod", "/pod", "default/", "a/b/c"} {
		t.Run(target, func(t *testing.T) {
			ev := timedSecurityEvent("event", target)
			r, _ := adoptionReconciler(ev)
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}}); err == nil {
				t.Fatalf("Reconcile succeeded for target %q", target)
			}
		})
	}
}

func TestSecurityEventReconciler_PreflightsMixedTargetBatch(t *testing.T) {
	for _, targets := range [][]string{
		{"default/ready", "default/pending"},
		{"default/pending", "default/ready"},
	} {
		t.Run(targets[0], func(t *testing.T) {
			amtd := deleteAMTD()
			ready := managedPod("ready", "default", "default", amtd.Name)
			pending := pendingPod("pending", nil)
			ev := timedSecurityEvent("event", targets[0])
			ev.Spec.Targets = targets
			r, cl := adoptionReconciler(amtd, ready, pending, ev)

			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}})
			if err != nil || result.RequeueAfter != 2*time.Second {
				t.Fatalf("Reconcile = (%v, %v), want 2s retry", result, err)
			}
			var after corev1.Pod
			if err := cl.Get(context.Background(), client.ObjectKeyFromObject(ready), &after); err != nil {
				t.Fatalf("ready target was acted on before batch preflight completed: %v", err)
			}
			if _, found := after.Annotations[AMTD_APPLIED_SECURITY_EVENTS]; found {
				t.Fatal("ready target was recorded as applied before batch preflight completed")
			}
		})
	}
}

func TestSecurityEventReconciler_AbsentTargetPreventsEarlierMutation(t *testing.T) {
	for _, targets := range [][]string{
		{"default/ready", "default/absent"},
		{"default/absent", "default/ready"},
	} {
		t.Run(targets[0], func(t *testing.T) {
			amtd := deleteAMTD()
			ready := managedPod("ready", "default", "default", amtd.Name)
			ev := timedSecurityEvent("event", targets[0])
			ev.Spec.Targets = targets
			r, cl := adoptionReconciler(amtd, ready, ev)

			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}})
			if err != nil || result != (ctrl.Result{}) {
				t.Fatalf("Reconcile = (%v, %v), want absent-pod no-action outcome", result, err)
			}
			if err := cl.Get(context.Background(), client.ObjectKeyFromObject(ready), &corev1.Pod{}); err != nil {
				t.Fatalf("ready target was mutated before absent target was discovered: %v", err)
			}
		})
	}
}

type failingPodGetClient struct {
	client.Client
	err error
}

func (c failingPodGetClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Pod); ok {
		return c.err
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestSecurityEventReconciler_PropagatesTargetReadFailure(t *testing.T) {
	ev := timedSecurityEvent("event", "default/pod")
	_, cl := adoptionReconciler(ev)
	want := errors.New("pod API unavailable")
	r := &SecurityEventReconciler{Client: failingPodGetClient{Client: cl, err: want}, Scheme: seTestScheme}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}})
	if !errors.Is(err, want) {
		t.Fatalf("Reconcile error = %v, want %v", err, want)
	}
}

func TestSecurityEventReconciler_AdoptedNoMatchDoesNotInvokeAction(t *testing.T) {
	amtd := deleteAMTD()
	pod := managedPod("no-match", "default", "default", amtd.Name)
	ev := timedSecurityEvent("event", "default/no-match")
	ev.Spec.Rule.Type = "different"
	r, cl := adoptionReconciler(amtd, pod, ev)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: ev.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
		t.Fatalf("no-match target was acted on: %v", err)
	}
}
