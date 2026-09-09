/*
 * M-140: the coalesced delete+recreate, driven through the real reconciler.
 *
 * Reconcile reaches Manager.Remove ONLY when Get returns NotFound, and there is no
 * finalizer. controller-runtime dedupes its workqueue by NamespacedName, so a delete
 * immediately followed by a recreate is an admissible sequence in which one reconcile
 * observes the NEW object and Remove never runs at all. This is a deterministic
 * fake-client proof of that sequence, not a claim about how often it happens in a cluster.
 */

package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/runner"
)

func m140Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func m140PolicyObj(uid string) *v1alpha1.PhorvexPolicy {
	p := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "policy", UID: types.UID(uid), Generation: 1,
	}}
	p.Spec.Tenant = "pxv1t"
	return p
}

func TestM140_CoalescedRecreateThroughReconcileDoesNotInheritState(t *testing.T) {
	scheme := m140Scheme(t)
	engine := decision.NewCoverageEngine()
	mgr := runner.NewManager(fake.NewClientBuilder().WithScheme(scheme).Build(), logr.Discard())
	mgr.Optimizer = engine

	old := m140PolicyObj("uid-A")
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(old).Build()
	r := &PhorvexPolicyReconciler{Client: client, Manager: mgr}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "policy"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	oldOwner := model.OwnerKey(model.OwnerKindUID, "uid-A")
	engine.SetOwnerLive(oldOwner, true)
	for i := 0; i < 5; i++ {
		engine.ObserveRotation(oldOwner, &model.WorkloadView{
			Pod:   model.Pod{Namespace: "ns", Name: "crown", UID: "u-crown", ReadyReplicas: 3, Ready: true},
			Phase: model.PhaseWarm,
		}, 0.5)
	}
	if engine.CalibrationState()[oldOwner].Updates != 5 {
		t.Fatal("precondition: the original owner did not accumulate learned state")
	}

	// The gesture: delete and recreate. Only ONE reconcile runs, and by the time it calls
	// Get the new object already exists — so Get succeeds and Remove is never reached.
	if err := client.Delete(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := client.Create(context.Background(), m140PolicyObj("uid-B")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	mgr.DrainLifecycle()

	if got := engine.CalibrationState()[oldOwner].Updates; got != 0 {
		t.Fatalf("predecessor state leaked through a coalesced recreate: RLS updates = %d", got)
	}
	newOwner := model.OwnerKey(model.OwnerKindUID, "uid-B")
	if got := engine.CalibrationState()[newOwner].Updates; got != 0 {
		t.Fatalf("the recreated policy inherited learned state: RLS updates = %d", got)
	}
}

// A policy without a UID must not silently acquire name-keyed semantics. The reconciler
// surfaces the rejection as a ValidationError condition rather than returning an error,
// which is the existing contract for an unusable policy: report it on status instead of
// hot-looping the workqueue.
func TestM140_ReconcileSurfacesMissingUIDInsteadOfDowngrading(t *testing.T) {
	scheme := m140Scheme(t)
	mgr := runner.NewManager(fake.NewClientBuilder().WithScheme(scheme).Build(), logr.Discard())
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(m140PolicyObj("")).Build()
	r := &PhorvexPolicyReconciler{Client: client, Manager: mgr}
	key := types.NamespacedName{Namespace: "ns", Name: "policy"}

	var fetched v1alpha1.PhorvexPolicy
	if err := client.Get(context.Background(), key, &fetched); err != nil {
		t.Fatal(err)
	}
	if fetched.UID != "" {
		t.Skip("fake client assigned a UID; manager-level rejection is covered in internal/runner")
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile returned an error instead of recording a condition: %v", err)
	}

	if err := client.Get(context.Background(), key, &fetched); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(fetched.Status.Conditions, "ValidationError")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("no ValidationError condition for an unidentified policy: %+v", fetched.Status.Conditions)
	}
	if !strings.Contains(cond.Message, "UID") {
		t.Fatalf("condition does not explain the missing UID: %q", cond.Message)
	}
}

// R1.5 — TenantCollision is published and cleared through the REAL status path, so an
// operator can see that one display name has become two independent economic units. This is
// distinct from a rejected duplicate owner UID, which never reaches the registry at all.
func TestM140_TenantCollisionConditionIsPublishedAndCleared(t *testing.T) {
	scheme := m140Scheme(t)
	first := m140PolicyObj("uid-A")
	second := m140PolicyObj("uid-B")
	second.Name = "policy-two" // same spec.tenant, different policy and UID
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(first, second).Build()
	mgr := runner.NewManager(client, logr.Discard())
	mgr.Optimizer = decision.NewCoverageEngine()

	if err := mgr.Upsert(first); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Upsert(second); err != nil {
		t.Fatalf("two independent owners sharing a display name must be supported: %v", err)
	}
	mgr.PublishTenantCollisions(context.Background())

	for _, name := range []string{"policy", "policy-two"} {
		var obj v1alpha1.PhorvexPolicy
		if err := client.Get(context.Background(),
			types.NamespacedName{Namespace: "ns", Name: name}, &obj); err != nil {
			t.Fatal(err)
		}
		cond := meta.FindStatusCondition(obj.Status.Conditions, runner.TenantCollisionCondition)
		if cond == nil || cond.Status != metav1.ConditionTrue {
			t.Fatalf("%s has no TenantCollision condition: %+v", name, obj.Status.Conditions)
		}
		if !strings.Contains(cond.Message, "SEPARATE") {
			t.Fatalf("%s condition does not explain the split: %q", name, cond.Message)
		}
	}

	// Resolve the collision: the condition must CLEAR, not linger.
	mgr.Remove(types.NamespacedName{Namespace: "ns", Name: "policy-two"})
	mgr.DrainLifecycle()
	mgr.PublishTenantCollisions(context.Background())

	var survivor v1alpha1.PhorvexPolicy
	if err := client.Get(context.Background(),
		types.NamespacedName{Namespace: "ns", Name: "policy"}, &survivor); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(survivor.Status.Conditions, runner.TenantCollisionCondition)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("TenantCollision did not clear for the surviving unique owner: %+v", cond)
	}
}
