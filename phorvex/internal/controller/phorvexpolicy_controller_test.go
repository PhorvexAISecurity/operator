package controller

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

func TestSetConditionSkipsIdenticalStatusWrite(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "policy", Generation: 3},
		Status: v1alpha1.PhorvexPolicyStatus{
			Tenant: "tenant-a",
			Conditions: []metav1.Condition{{
				Type:               "ValidationError",
				Status:             metav1.ConditionFalse,
				Reason:             "Valid",
				Message:            "policy accepted",
				ObservedGeneration: 3,
			}},
		},
	}
	updates := 0
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).
		WithObjects(policy).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, delegate client.Client, subresource string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				updates++
				return delegate.SubResource(subresource).Update(ctx, obj, opts...)
			},
		}).Build()
	r := &PhorvexPolicyReconciler{Client: c}

	if err := r.setCondition(context.Background(), policy, "ValidationError", metav1.ConditionFalse, "Valid", "policy accepted"); err != nil {
		t.Fatal(err)
	}
	if updates != 0 {
		t.Fatalf("identical status condition caused %d writes; want 0", updates)
	}
}

func TestSetConditionRetriesConflictWithoutRevertingOperationalStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "policy", Generation: 4},
	}
	attempts := 0
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).
		WithObjects(policy).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, delegate client.Client, subresource string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				attempts++
				if attempts == 1 {
					// Simulate the runner winning the race after the reconciler's read.
					var concurrent v1alpha1.PhorvexPolicy
					if err := delegate.Get(ctx, client.ObjectKeyFromObject(obj), &concurrent); err != nil {
						return err
					}
					concurrent.Status.KillSwitchEngaged = true
					meta.SetStatusCondition(&concurrent.Status.Conditions, metav1.Condition{
						Type:               "KillSwitch",
						Status:             metav1.ConditionTrue,
						Reason:             "Engaged",
						Message:            "actuation suppressed globally",
						ObservedGeneration: concurrent.Generation,
					})
					if err := delegate.Status().Update(ctx, &concurrent); err != nil {
						return err
					}
					return apierrors.NewConflict(
						schema.GroupResource{Group: "phorvex.ai", Resource: "phorvexpolicies"},
						obj.GetName(), errors.New("injected concurrent status writer"),
					)
				}
				return delegate.SubResource(subresource).Update(ctx, obj, opts...)
			},
		}).Build()
	r := &PhorvexPolicyReconciler{Client: c}

	if err := r.setCondition(context.Background(), policy, "ValidationError", metav1.ConditionFalse, "Valid", "policy accepted"); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("status update attempts = %d, want 2 (one conflict and one retry)", attempts)
	}
	var got v1alpha1.PhorvexPolicy
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(policy), &got); err != nil {
		t.Fatal(err)
	}
	validation := meta.FindStatusCondition(got.Status.Conditions, "ValidationError")
	killSwitch := meta.FindStatusCondition(got.Status.Conditions, "KillSwitch")
	if validation == nil || validation.Status != metav1.ConditionFalse {
		t.Fatalf("validation condition was not written after retry: %+v", got.Status.Conditions)
	}
	if !got.Status.KillSwitchEngaged || killSwitch == nil || killSwitch.Status != metav1.ConditionTrue {
		t.Fatalf("reconciler retry reverted fresh runner status: %+v", got.Status)
	}
}
