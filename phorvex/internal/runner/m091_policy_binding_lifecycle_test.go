package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	phorvexv1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

type m091BoundarySpy struct {
	reads   int
	deletes int
}

func (s *m091BoundarySpy) reset() { s.reads, s.deletes = 0, 0 }

func m091OwnedPod(namespace, name, uid, app, owner string) *corev1.Pod {
	controller := true
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: name, UID: types.UID(uid), ResourceVersion: "7",
		Labels: map[string]string{"app": app}, OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "ReplicationController", Name: owner,
			UID: types.UID(owner + "-uid"), Controller: &controller,
		}},
	}}
}

func m091Owner(namespace, name, app string) *corev1.ReplicationController {
	replicas := int32(2)
	return &corev1.ReplicationController{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(name + "-uid"), ResourceVersion: "3"},
		Spec:       corev1.ReplicationControllerSpec{Replicas: &replicas, Selector: map[string]string{"app": app}},
		Status:     corev1.ReplicationControllerStatus{Replicas: replicas},
	}
}

type m091Fixture struct {
	native *actuator.NativeActuator
	spy    *m091BoundarySpy
}

func newM091Fixture(t *testing.T, objects ...client.Object) *m091Fixture {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := phorvexv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	spy := &m091BoundarySpy{}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			spy.reads++
			return inner.Get(ctx, key, obj, opts...)
		},
		Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			spy.deletes++
			return inner.Delete(ctx, obj, opts...)
		},
	}).Build()
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	return &m091Fixture{native: native, spy: spy}
}

func m091Policy(namespace, name, uid, tenant, app string) *phorvexv1alpha1.PhorvexPolicy {
	return &phorvexv1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid)},
		Spec:       phorvexv1alpha1.PhorvexPolicySpec{Tenant: tenant, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}},
	}
}

func m091Target(p *phorvexv1alpha1.PhorvexPolicy) actuator.TenantTarget {
	return actuator.TenantTarget{Tenant: p.EffectiveTenant(), Namespace: p.Namespace, PolicyName: p.Name, PolicyUID: string(p.UID), Selector: p.Spec.Selector.DeepCopy()}
}

func m091Request(p *phorvexv1alpha1.PhorvexPolicy, pod, uid string) actuator.Request {
	return actuator.Request{Tenant: p.EffectiveTenant(), Namespace: p.Namespace, Pod: pod, PolicyName: p.Name, PolicyUID: string(p.UID), TargetUID: uid, Action: model.ActionRotate}
}

func m091Manager(f *m091Fixture) *Manager {
	return &Manager{Actuator: f.native, policies: map[string]*policyEntry{}, emits: map[string]*emissionHistory{}, Log: logr.Discard()}
}

func TestM091ActuateRequiresExactOwnerBeforeBoundaryReads(t *testing.T) {
	cases := []struct {
		name string
		edit func(*actuator.Request)
		want bool
	}{
		{name: "exact", want: true},
		{name: "missing-owner", edit: func(r *actuator.Request) { r.PolicyUID = "" }},
		{name: "unknown-owner", edit: func(r *actuator.Request) { r.PolicyUID = "unknown" }},
		{name: "wrong-tenant", edit: func(r *actuator.Request) { r.Tenant = "other" }},
		{name: "wrong-namespace", edit: func(r *actuator.Request) { r.Namespace = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newM091Fixture(t,
				m091Owner("ns", "owner", "app"),
				m091OwnedPod("ns", "target", "target-uid", "app", "owner"),
			)
			policy := m091Policy("ns", "policy", "owner-uid", "tenant", "app")
			if err := f.native.EnsurePolicy(t.Context(), m091Target(policy)); err != nil {
				t.Fatal(err)
			}
			req := m091Request(policy, "target", "target-uid")
			if tc.edit != nil {
				tc.edit(&req)
			}
			result, err := f.native.Actuate(t.Context(), req)
			if tc.want {
				if err != nil || !result.Emitted || f.spy.reads == 0 || f.spy.deletes != 1 {
					t.Fatalf("exact owner result=%+v err=%v reads=%d deletes=%d", result, err, f.spy.reads, f.spy.deletes)
				}
				return
			}
			if err == nil || result.Emitted || f.spy.reads != 0 || f.spy.deletes != 0 {
				t.Fatalf("refused owner crossed boundary: result=%+v err=%v reads=%d deletes=%d", result, err, f.spy.reads, f.spy.deletes)
			}
		})
	}
}

func TestM091ManagerRemovalUsesDrainBoundaryAndPreservesSharedOwner(t *testing.T) {
	objects := []client.Object{
		m091Owner("ns-a", "owner-a", "a"), m091Owner("ns-b", "owner-b", "b"),
		m091OwnedPod("ns-a", "before", "before-uid", "a", "owner-a"),
		m091OwnedPod("ns-a", "pre-drain", "pre-drain-uid", "a", "owner-a"),
		m091OwnedPod("ns-a", "after", "after-uid", "a", "owner-a"),
		m091OwnedPod("ns-b", "survivor", "survivor-uid", "b", "owner-b"),
	}
	f := newM091Fixture(t, objects...)
	m := m091Manager(f)
	retired := m091Policy("ns-a", "policy-a", "policy-a-uid", "shared", "a")
	survivor := m091Policy("ns-b", "policy-b", "policy-b-uid", "shared", "b")
	for _, p := range []*phorvexv1alpha1.PhorvexPolicy{retired, survivor} {
		if err := m.Upsert(p); err != nil {
			t.Fatal(err)
		}
		if err := f.native.EnsurePolicy(t.Context(), m091Target(p)); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := f.native.Actuate(t.Context(), m091Request(retired, "before", "before-uid")); err != nil || !result.Emitted {
		t.Fatalf("current owner positive result=%+v err=%v", result, err)
	}
	m.Remove(types.NamespacedName{Namespace: retired.Namespace, Name: retired.Name})
	if result, err := f.native.Actuate(t.Context(), m091Request(retired, "pre-drain", "pre-drain-uid")); err != nil || !result.Emitted {
		t.Fatalf("enqueue incorrectly claimed completed retirement: result=%+v err=%v", result, err)
	}
	m.DrainLifecycle()
	f.spy.reset()
	if result, err := f.native.Actuate(t.Context(), m091Request(retired, "after", "after-uid")); err == nil || result.Emitted || f.spy.reads != 0 || f.spy.deletes != 0 {
		t.Fatalf("drained owner reached handler: result=%+v err=%v reads=%d deletes=%d", result, err, f.spy.reads, f.spy.deletes)
	}
	if result, err := f.native.Actuate(t.Context(), m091Request(survivor, "survivor", "survivor-uid")); err != nil || !result.Emitted || f.spy.deletes != 1 {
		t.Fatalf("shared-display survivor lost authority: result=%+v err=%v reads=%d deletes=%d", result, err, f.spy.reads, f.spy.deletes)
	}
}

func TestM091ManagerCoalescedReplacementRetiresOnlyOldUID(t *testing.T) {
	f := newM091Fixture(t,
		m091Owner("ns", "owner", "app"),
		m091OwnedPod("ns", "old-before", "old-before-uid", "app", "owner"),
		m091OwnedPod("ns", "old-after", "old-after-uid", "app", "owner"),
		m091OwnedPod("ns", "new-live", "new-live-uid", "app", "owner"),
	)
	m := m091Manager(f)
	old := m091Policy("ns", "policy", "old-uid", "shared", "app")
	next := m091Policy("ns", "policy", "new-uid", "shared", "app")
	if err := m.Upsert(old); err != nil {
		t.Fatal(err)
	}
	if err := f.native.EnsurePolicy(t.Context(), m091Target(old)); err != nil {
		t.Fatal(err)
	}
	if err := m.Upsert(next); err != nil {
		t.Fatal(err)
	}
	if result, err := f.native.Actuate(t.Context(), m091Request(old, "old-before", "old-before-uid")); err != nil || !result.Emitted {
		t.Fatalf("replacement enqueue moved completion boundary: result=%+v err=%v", result, err)
	}
	m.DrainLifecycle()
	f.spy.reset()
	if result, err := f.native.Actuate(t.Context(), m091Request(old, "old-after", "old-after-uid")); err == nil || result.Emitted || f.spy.reads != 0 || f.spy.deletes != 0 {
		t.Fatalf("replaced UID reached handler: result=%+v err=%v reads=%d deletes=%d", result, err, f.spy.reads, f.spy.deletes)
	}
	if err := f.native.EnsurePolicy(t.Context(), m091Target(next)); err != nil {
		t.Fatal(err)
	}
	if result, err := f.native.Actuate(t.Context(), m091Request(next, "new-live", "new-live-uid")); err != nil || !result.Emitted || f.spy.deletes != 1 {
		t.Fatalf("replacement owner unavailable after preparation: result=%+v err=%v", result, err)
	}
}

func TestM091SameUIDDisplayRenameIsNotOwnerRetirement(t *testing.T) {
	f := newM091Fixture(t,
		m091Owner("ns", "owner", "app"),
		m091OwnedPod("ns", "old-display", "old-display-uid", "app", "owner"),
		m091OwnedPod("ns", "new-display", "new-display-uid", "app", "owner"),
		m091OwnedPod("ns", "stale-display", "stale-display-uid", "app", "owner"),
	)
	m := m091Manager(f)
	old := m091Policy("ns", "policy", "same-uid", "before", "app")
	if err := m.Upsert(old); err != nil {
		t.Fatal(err)
	}
	if err := f.native.EnsurePolicy(t.Context(), m091Target(old)); err != nil {
		t.Fatal(err)
	}
	renamed := old.DeepCopy()
	renamed.Spec.Tenant = "after"
	renamed.Generation = 2
	if err := m.Upsert(renamed); err != nil {
		t.Fatal(err)
	}
	m.DrainLifecycle()
	if result, err := f.native.Actuate(t.Context(), m091Request(old, "old-display", "old-display-uid")); err != nil || !result.Emitted {
		t.Fatalf("metrics-only drain retired owner binding: result=%+v err=%v", result, err)
	}
	if err := f.native.EnsurePolicy(t.Context(), m091Target(renamed)); err != nil {
		t.Fatal(err)
	}
	if result, err := f.native.Actuate(t.Context(), m091Request(renamed, "new-display", "new-display-uid")); err != nil || !result.Emitted {
		t.Fatalf("renamed binding unavailable: result=%+v err=%v", result, err)
	}
	f.spy.reset()
	if result, err := f.native.Actuate(t.Context(), m091Request(old, "stale-display", "stale-display-uid")); err == nil || result.Emitted || f.spy.reads != 0 || f.spy.deletes != 0 {
		t.Fatalf("old display binding survived refresh: result=%+v err=%v reads=%d deletes=%d", result, err, f.spy.reads, f.spy.deletes)
	}
}

type m091LifecycleActuator struct{ retired []string }

func (*m091LifecycleActuator) Name() string                                              { return "m091-lifecycle" }
func (*m091LifecycleActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (*m091LifecycleActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{}, nil
}
func (*m091LifecycleActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (a *m091LifecycleActuator) RetirePolicyBinding(uid string) { a.retired = append(a.retired, uid) }

func TestM091DrainCountsOwnerBindingAndSkipsMetricsOnly(t *testing.T) {
	var lines []string
	log := funcr.New(func(prefix, args string) { lines = append(lines, prefix+" "+args) }, funcr.Options{})
	a := &m091LifecycleActuator{}
	m := &Manager{Actuator: a, policies: map[string]*policyEntry{}, emits: map[string]*emissionHistory{}, Audit: audit.New(log, nil), Log: logr.Discard()}
	p := m091Policy("ns", "policy", "uid", "before", "app")
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	renamed := p.DeepCopy()
	renamed.Spec.Tenant = "after"
	if err := m.Upsert(renamed); err != nil {
		t.Fatal(err)
	}
	m.DrainLifecycle()
	if len(a.retired) != 0 {
		t.Fatalf("metrics-only event retired binding: %v", a.retired)
	}
	m.Remove(types.NamespacedName{Namespace: "ns", Name: "policy"})
	m.DrainLifecycle()
	if len(a.retired) != 1 || a.retired[0] != "uid" {
		t.Fatalf("genuine removal did not retire exact UID: %v", a.retired)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `"storesPruned"=2`) {
		t.Fatalf("owner binding store missing from cleanup audit: %s", joined)
	}
}
