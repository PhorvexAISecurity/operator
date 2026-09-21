package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m054EvictionObservation struct {
	calls              int
	deletes            int
	eviction           *policyv1.Eviction
	retain             bool
	forwardSubresource bool
	err                error
}

func (o *m054EvictionObservation) delete(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
	o.deletes++
	return errors.New("direct Pod DELETE fallback attempted")
}

func (o *m054EvictionObservation) create(ctx context.Context, c client.Client, name string, obj client.Object, sub client.Object, _ ...client.SubResourceCreateOption) error {
	o.calls++
	if name != "eviction" {
		return errors.New("unexpected subresource " + name)
	}
	eviction, ok := sub.(*policyv1.Eviction)
	if !ok || eviction.DeleteOptions == nil {
		return errors.New("unexpected eviction object")
	}
	o.eviction = eviction.DeepCopy()
	if o.err != nil {
		return o.err
	}
	if o.retain {
		// A nil Eviction response is only API acceptance. Keeping the object models a
		// finalizer or unreachable kubelet and proves the receipt stays unconfirmed.
		return nil
	}
	if o.forwardSubresource {
		return c.SubResource(name).Create(ctx, obj, sub)
	}
	return c.Delete(ctx, obj, &client.DeleteOptions{GracePeriodSeconds: eviction.DeleteOptions.GracePeriodSeconds, Preconditions: eviction.DeleteOptions.Preconditions})
}

func m054Int64(v int64) *int64 { return &v }

func m054Fixture(t *testing.T, policyCap, workloadGrace *int64, retain bool) (client.Client, *corev1.Pod, *v1alpha1.PhorvexPolicy, *m054EvictionObservation) {
	t.Helper()
	pod, rs := m47Pair()
	pod.Spec.TerminationGracePeriodSeconds = workloadGrace
	policy := m47Policy()
	policy.Spec.Budget.MaxGracePeriodSeconds = policyCap
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, rs, policy).Build()
	observation := &m054EvictionObservation{retain: retain}
	return interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{SubResourceCreate: observation.create, Delete: observation.delete}), pod, policy, observation
}

func m054Request(pod *corev1.Pod, policy *v1alpha1.PhorvexPolicy, cap int64) Request {
	return Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionRotate,
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation,
		MaxGracePeriodSeconds: cap,
	}
}

func TestM054NativeRotateBindsActualEvictionOptionsAndUnconfirmedReceipt(t *testing.T) {
	tests := []struct {
		name                    string
		policyCap, workload     *int64
		requestCap              int64
		wantWorkload, wantGrace int64
		wantExplicit            bool
	}{
		{name: "nil-policy-default-and-nil-workload", requestCap: 30, wantWorkload: 30, wantGrace: 30},
		{name: "explicit-short-policy", policyCap: m054Int64(7), workload: m054Int64(120), requestCap: 7, wantWorkload: 120, wantGrace: 7, wantExplicit: true},
		{name: "shorter-workload-wins", policyCap: m054Int64(60), workload: m054Int64(5), requestCap: 60, wantWorkload: 5, wantGrace: 5, wantExplicit: true},
		{name: "upper-policy-bound", policyCap: m054Int64(300), workload: m054Int64(301), requestCap: 300, wantWorkload: 301, wantGrace: 300, wantExplicit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, pod, policy, observed := m054Fixture(t, tt.policyCap, tt.workload, true)
			result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, m054Request(pod, policy, tt.requestCap))
			if err != nil || !result.Emitted || observed.calls != 1 {
				t.Fatalf("result=%+v calls=%d err=%v", result, observed.calls, err)
			}
			if observed.eviction == nil || observed.eviction.DeleteOptions == nil || observed.eviction.DeleteOptions.GracePeriodSeconds == nil || *observed.eviction.DeleteOptions.GracePeriodSeconds != tt.wantGrace {
				t.Fatalf("Eviction grace=%+v want %d", observed.eviction, tt.wantGrace)
			}
			pre := observed.eviction.DeleteOptions.Preconditions
			if pre == nil || pre.UID == nil || *pre.UID != pod.UID || pre.ResourceVersion == nil || *pre.ResourceVersion != pod.ResourceVersion {
				t.Fatalf("Eviction preconditions=%+v want UID=%s RV=%s", pre, pod.UID, pod.ResourceVersion)
			}
			receipt := result.GracefulTermination
			if receipt == nil || receipt.PolicyUID != string(policy.UID) || receipt.PolicyGeneration != policy.Generation || receipt.PolicyGraceCapSeconds != tt.requestCap || receipt.WorkloadGraceSeconds != tt.wantWorkload || receipt.WorkloadGraceExplicit != tt.wantExplicit || receipt.EffectiveGracePeriodSeconds != tt.wantGrace || receipt.PodUID != string(pod.UID) || receipt.PodResourceVersion != pod.ResourceVersion || receipt.TerminationStatus != "unconfirmed" {
				t.Fatalf("receipt=%+v", receipt)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
				t.Fatalf("API-accepted Eviction with unresolved termination must remain observable: %v", err)
			}
		})
	}
}

func TestM054NativeRotateOrdinaryCompletionAndBoundaryRefusals(t *testing.T) {
	c, pod, policy, observed := m054Fixture(t, m054Int64(12), m054Int64(90), false)
	result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, m054Request(pod, policy, 12))
	if err != nil || !result.Emitted || observed.calls != 1 || result.GracefulTermination == nil || result.GracefulTermination.TerminationStatus != "unconfirmed" {
		t.Fatalf("ordinary delete result=%+v calls=%d err=%v", result, observed.calls, err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err == nil {
		t.Fatal("ordinary fake-client deletion did not complete")
	}

	tests := []struct {
		name       string
		policyCap  *int64
		requestCap int64
		edit       func(*v1alpha1.PhorvexPolicy, *Request)
		want       string
	}{
		{name: "zero-policy", policyCap: m054Int64(0), want: "grace-cap-invalid"},
		{name: "negative-policy", policyCap: m054Int64(-1), requestCap: -1, want: "grace-cap-invalid"},
		{name: "oversized-policy", policyCap: m054Int64(301), requestCap: 301, want: "grace-cap-invalid"},
		{name: "request-does-not-match-authority", policyCap: m054Int64(10), requestCap: 11, want: "grace-cap-mismatch"},
		{name: "stale-policy-uid", policyCap: m054Int64(10), requestCap: 10, edit: func(_ *v1alpha1.PhorvexPolicy, req *Request) { req.PolicyUID = "old-policy" }, want: "policy-uid-mismatch"},
		{name: "stale-policy-generation", policyCap: m054Int64(10), requestCap: 10, edit: func(_ *v1alpha1.PhorvexPolicy, req *Request) { req.PolicyGeneration-- }, want: "policy-generation-mismatch"},
		{name: "policy-dry-run", policyCap: m054Int64(10), requestCap: 10, edit: func(policy *v1alpha1.PhorvexPolicy, _ *Request) { policy.Spec.Mode = v1alpha1.ModeDryRun }, want: "policy-not-authorized"},
		{name: "selector-drift", policyCap: m054Int64(10), requestCap: 10, edit: func(policy *v1alpha1.PhorvexPolicy, _ *Request) { policy.Spec.Selector.MatchLabels["app"] = "other" }, want: "policy-selector-mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, pod, policy, observed := m054Fixture(t, tt.policyCap, m054Int64(90), true)
			req := m054Request(pod, policy, tt.requestCap)
			if tt.edit != nil {
				authoritative := &v1alpha1.PhorvexPolicy{}
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(policy), authoritative); err != nil {
					t.Fatal(err)
				}
				tt.edit(authoritative, &req)
				if err := c.Update(t.Context(), authoritative); err != nil {
					t.Fatal(err)
				}
			}
			result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, req)
			if err != nil || result.Emitted || observed.calls != 0 || !strings.Contains(result.Note, tt.want) {
				t.Fatalf("result=%+v calls=%d err=%v want refusal %q", result, observed.calls, err, tt.want)
			}
		})
	}
}

func TestM054EvictionFailureAndPhoenixRefusalAreNoEffect(t *testing.T) {
	c, pod, policy, observed := m054Fixture(t, m054Int64(10), m054Int64(90), true)
	observed.err = errors.New("eviction transport failed")
	result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, m054Request(pod, policy, 10))
	if err == nil || result.Emitted || result.GracefulTermination != nil || observed.calls != 1 {
		t.Fatalf("failed Eviction result=%+v calls=%d err=%v", result, observed.calls, err)
	}

	phoenix := NewPhoenixActuator(fake.NewClientBuilder().WithScheme(newScheme(t)).Build())
	result, err = phoenix.Actuate(t.Context(), m054Request(pod, policy, 10))
	if !IsNoEffectRefusal(err) || result.Emitted || result.NoEffect != NoEffectRefused || !strings.Contains(err.Error(), detailGraceCapUnsupported) {
		t.Fatalf("Phoenix bounded rotate result=%+v err=%v", result, err)
	}
}

func TestM183EvictionDenialsNeverFallBackToPodDelete(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		want      string
		wantError bool
	}{
		{"pdb-closed", apierrors.NewTooManyRequests("pdb closed", 0), "pdb-eviction-admission-refused", false},
		{"rbac-denied", apierrors.NewForbidden(schema.GroupResource{Group: "policy", Resource: "pods/eviction"}, "p", errors.New("denied")), "eviction-permission-denied", false},
		{"precondition-conflict", apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, "p", errors.New("changed")), "target-changed-before-eviction", false},
		{"subresource-unavailable", apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "p"), "target-or-eviction-subresource-unavailable", false},
		{"deadline-ambiguous", context.DeadlineExceeded, "rotate eviction", true},
		{"ambiguous-transport", errors.New("transport response lost"), "rotate eviction", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, pod, policy, observed := m054Fixture(t, m054Int64(10), m054Int64(90), true)
			observed.err = tt.err
			result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, m054Request(pod, policy, 10))
			if observed.calls != 1 || observed.deletes != 0 || result.Emitted || result.GracefulTermination != nil {
				t.Fatalf("result=%+v calls=%d deletes=%d err=%v", result, observed.calls, observed.deletes, err)
			}
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("err=%v want %q", err, tt.want)
				}
			} else if err != nil || result.NoEffect != NoEffectRefused || !strings.Contains(result.Note, tt.want) {
				t.Fatalf("result=%+v err=%v want refusal %q", result, err, tt.want)
			}
			if getErr := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); getErr != nil {
				t.Fatalf("denied/ambiguous eviction changed target: %v", getErr)
			}
		})
	}
}
