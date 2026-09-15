/*
 * Phorvex — M-87: NativeActuator.Rollback enforces the SAME boundary as Actuate (O7 tenant-namespace
 * assertion, then the central dry-run refusal) BEFORE any handler lookup or invocation.
 */

package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/internal/model"
)

// m087Spy counts every K8s call that crosses the actuation boundary. A refused rollback must
// leave both counters at zero: the assertion is on the absence of effects, not on error text.
type m087Spy struct{ reads, writes int }

func (s *m087Spy) reset() { s.reads, s.writes = 0, 0 }

func m087Client(spy *m087Spy, objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			spy.reads++
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			spy.reads++
			return c.List(ctx, list, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			spy.writes++
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			spy.writes++
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			spy.writes++
			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			spy.writes++
			return c.Delete(ctx, obj, opts...)
		},
	}).Build()
}

// m087Rotate performs a real route-rotate through Actuate on a permissive actuator.
// actuator so the pod carries the handler-produced snapshot + rollback ref. The actuator under test
// is then built separately with the case's bindings and DryRun.
func m087Rotate(t *testing.T, c client.Client, ns, pod string) (Request, string) {
	t.Helper()
	req := Request{Tenant: "t", Namespace: ns, Pod: pod, Action: model.ActionRouteRotate, TargetUID: "uid-" + pod}
	res, err := NewNativeActuator(c).Actuate(context.Background(), req)
	if err != nil || !res.Emitted || res.RollbackRef == "" {
		t.Fatalf("route-rotate setup: emitted=%v ref=%q err=%v", res.Emitted, res.RollbackRef, err)
	}
	return req, res.RollbackRef
}

func m087Pod(t *testing.T, c client.Client, ns, name string) corev1.Pod {
	t.Helper()
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// m087Rotated asserts the pod is still in its restitched route state.
func m087Rotated(t *testing.T, p corev1.Pod, what string) {
	t.Helper()
	if p.Labels[labelRouteKey] == "" || p.Labels[labelRouteKey] == "route-old" || p.Annotations[routeSnapAnno] == "" || p.Labels["app"] != "orig" {
		t.Fatalf("%s: pod %s/%s is no longer in its rotated state: labels=%v annotations=%v", what, p.Namespace, p.Name, p.Labels, p.Annotations)
	}
}

func TestM033IdentityDirectDispatchRefusesWithoutPodAccess(t *testing.T) {
	for _, backend := range []Backend{BackendNative, BackendHybrid} {
		t.Run(string(backend), func(t *testing.T) {
			spy := &m087Spy{}
			pod := aiPod("ns", "target", map[string]string{"app": "orig"})
			pod.UID = "stable-uid"
			pod.Spec.ServiceAccountName = "stable-sa"
			pod.Status.PodIP = "10.0.0.7"
			c := m087Client(spy, pod)
			act, err := New(backend, c)
			if err != nil {
				t.Fatal(err)
			}
			if ok, why := act.SupportsAction(t.Context(), model.ActionIdentityRotate, Target{Namespace: "ns", Pod: "target"}); ok || !strings.Contains(why, "declared-only") {
				t.Fatalf("identity support=%v why=%q, want declared-only refusal", ok, why)
			}
			spy.reset()
			res, err := act.Actuate(t.Context(), Request{Namespace: "ns", Pod: "target", Action: model.ActionIdentityRotate})
			if err == nil || !strings.Contains(err.Error(), "declared-only") || res.Emitted || spy.reads != 0 || spy.writes != 0 {
				t.Fatalf("identity dispatch result=%+v err=%v reads=%d writes=%d", res, err, spy.reads, spy.writes)
			}
			got := m087Pod(t, c, "ns", "target")
			if got.UID != "stable-uid" || got.Status.PodIP != "10.0.0.7" || got.Spec.ServiceAccountName != "stable-sa" || got.Labels["phorvex.ai/identity-epoch"] != "" {
				t.Fatalf("identity refusal changed pod identity: %+v", got)
			}
		})
	}
}

func TestM087RollbackEnforcesTenantAndDryRunBoundary(t *testing.T) {
	isDryRun := func(err error) bool { return errors.Is(err, errDryRunGuard) }
	isO7 := func(err error) bool {
		return err != nil && !isDryRun(err) && strings.Contains(err.Error(), "DENIED (O7)")
	}
	isO7Strict := func(err error) bool {
		return err != nil && !isDryRun(err) && strings.Contains(err.Error(), "DENIED (O7 strict)")
	}
	cases := []struct {
		name   string
		bind   string // namespace bound to tenant "t" ("" = no binding at all)
		strict bool
		dryRun bool
		refuse func(error) bool // nil = the rollback must proceed and restore
	}{
		{name: "dry-run only refuses", bind: "ns", dryRun: true, refuse: isDryRun},
		{name: "cross-namespace only refuses", bind: "elsewhere", refuse: isO7},
		{name: "both: tenant error takes precedence", bind: "elsewhere", dryRun: true, refuse: isO7},
		{name: "strict unbound refuses", strict: true, refuse: isO7Strict},
		{name: "legacy unbound proceeds", refuse: nil},
		{name: "same tenant non-dry-run restores", bind: "ns", refuse: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &m087Spy{}
			routeFixture := func(name, service string) *corev1.Pod {
				p := aiPod("ns", name, map[string]string{"app": "orig", labelRouteKey: "route-old", "route-group": service})
				p.Annotations[annoRouteService] = service
				return p
			}
			serviceFixture := func(name string) *corev1.Service {
				return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
					Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "orig", "route-group": name, labelRouteKey: "route-old"}}}
			}
			c := m087Client(spy,
				routeFixture("target", "target-route"), routeFixture("target-peer", "target-route"),
				routeFixture("bystander", "bystander-route"), routeFixture("bystander-peer", "bystander-route"),
				serviceFixture("target-route"), serviceFixture("bystander-route"))
			// Real producer: both pods are actually rotated, so a rollback that reaches the handler WRITES.
			req, ref := m087Rotate(t, c, "ns", "target")
			m087Rotate(t, c, "ns", "bystander")
			m087Rotated(t, m087Pod(t, c, "ns", "target"), "setup")

			n := NewNativeActuator(c)
			n.SetBoundaryReader(c)
			n.StrictTenantNamespace = tc.strict
			n.DryRun = tc.dryRun
			if tc.bind != "" {
				if err := n.EnsurePolicy(context.Background(), TenantTarget{Tenant: "t", Namespace: tc.bind}); err != nil {
					t.Fatal(err)
				}
			}

			spy.reset()
			err := n.Rollback(context.Background(), req, ref)
			if tc.refuse != nil {
				if !tc.refuse(err) {
					after := m087Pod(t, c, "ns", "target")
					t.Fatalf("rollback must be refused by the boundary guard, got err=%v; effects: reads=%d writes=%d; target labels=%v snapshot-present=%v",
						err, spy.reads, spy.writes, after.Labels, after.Annotations[routeSnapAnno] != "")
				}
				if spy.reads != 0 || spy.writes != 0 {
					t.Fatalf("refused rollback crossed the boundary: reads=%d writes=%d", spy.reads, spy.writes)
				}
				m087Rotated(t, m087Pod(t, c, "ns", "target"), "refused rollback")
				// Precedence parity: Actuate refuses the identical request with the identical error.
				spy.reset()
				_, aerr := n.Actuate(context.Background(), req)
				if aerr == nil || aerr.Error() != err.Error() {
					t.Fatalf("Actuate/Rollback precedence differs:\n actuate=%v\n rollback=%v", aerr, err)
				}
				if spy.reads != 0 || spy.writes != 0 {
					t.Fatalf("refused actuate crossed the boundary: reads=%d writes=%d", spy.reads, spy.writes)
				}
				return
			}
			if err != nil {
				t.Fatalf("allowed rollback refused: %v", err)
			}
			if spy.writes == 0 {
				t.Fatal("allowed rollback wrote nothing — the fixture does not mutate, so refusal assertions would be vacuous")
			}
			got := m087Pod(t, c, "ns", "target")
			if got.Labels[labelRouteKey] != "route-old" || got.Annotations[routeSnapAnno] != "" || got.Labels["app"] != "orig" {
				t.Fatalf("allowed rollback did not restore the snapshot: labels=%v annotations=%v", got.Labels, got.Annotations)
			}
			var restoredService corev1.Service
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "target-route"}, &restoredService); err != nil {
				t.Fatal(err)
			}
			if restoredService.Spec.Selector[labelRouteKey] != "route-old" {
				t.Fatalf("allowed rollback did not restore Service selector: %v", restoredService.Spec.Selector)
			}
			// Untouched-object control: the rollback restores only its own target.
			m087Rotated(t, m087Pod(t, c, "ns", "bystander"), "bystander")
		})
	}
}

// Unknown and non-Rollbacker actions keep their no-op nil result ONLY after the boundary guards;
// a dry-run or cross-tenant request is refused before the registry is even consulted.
func TestM087RollbackGuardsPrecedeHandlerLookup(t *testing.T) {
	rotate, ok := HandlerRegistry.Get(string(model.ActionRotate))
	if !ok {
		t.Fatal("fixture: rotate must be registered")
	}
	if _, ok := rotate.(Rollbacker); ok {
		t.Fatal("fixture: rotate is expected to be a non-Rollbacker (forward-only)")
	}
	if _, ok := HandlerRegistry.Get("no-such-action"); ok {
		t.Fatal("fixture: no-such-action must be unregistered")
	}
	for _, action := range []model.Action{model.ActionRotate, "no-such-action"} {
		t.Run(string(action), func(t *testing.T) {
			spy := &m087Spy{}
			c := m087Client(spy, aiPod("ns", "target", map[string]string{"app": "orig"}))
			req := Request{Tenant: "t", Namespace: "ns", Pod: "target", Action: action}

			allowed := NewNativeActuator(c)
			_ = allowed.EnsurePolicy(context.Background(), TenantTarget{Tenant: "t", Namespace: "ns"})
			if err := allowed.Rollback(context.Background(), req, ""); err != nil {
				t.Fatalf("unknown/non-Rollbacker after passing guards must stay a no-op nil, got %v", err)
			}

			dry := NewNativeActuator(c)
			_ = dry.EnsurePolicy(context.Background(), TenantTarget{Tenant: "t", Namespace: "ns"})
			dry.DryRun = true
			if err := dry.Rollback(context.Background(), req, ""); !errors.Is(err, errDryRunGuard) {
				t.Fatalf("dry-run must refuse before handler lookup, got %v", err)
			}

			cross := NewNativeActuator(c)
			_ = cross.EnsurePolicy(context.Background(), TenantTarget{Tenant: "t", Namespace: "elsewhere"})
			if err := cross.Rollback(context.Background(), req, ""); err == nil || !strings.Contains(err.Error(), "DENIED (O7)") {
				t.Fatalf("cross-namespace must refuse before handler lookup, got %v", err)
			}
			if spy.reads != 0 || spy.writes != 0 {
				t.Fatalf("no-op/refused rollbacks crossed the boundary: reads=%d writes=%d", spy.reads, spy.writes)
			}
		})
	}
}

// adapter-rotate's Rollback issues a serving-API call (LoadAdapter) after reading the pod. A refused
// rollback must reach neither. The tripwire fails the FIRST read, so a boundary crossing is observed as
// a different error and the real HTTP client is never reached from the test.
func TestM087RollbackRefusalPrecedesServingCall(t *testing.T) {
	errTripwire := errors.New("m087 tripwire: rollback crossed the boundary")
	pod := aiPod("ns", "llm", map[string]string{labelLoRAEnabled: "true"})
	snap, _ := json.Marshal(struct{ Adapter, Clean string }{"adapter-x", "s3://clean/adapter-x"})
	pod.Annotations[annoAdapterSnapshot] = string(snap)
	crossings := 0
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			crossings++
			return errTripwire
		},
	}).Build()
	req := Request{Tenant: "t", Namespace: "ns", Pod: "llm", Action: model.ActionAdapterRotate}

	// Positive control: with the guards satisfied the handler IS invoked and hits the tripwire.
	open := NewNativeActuator(c)
	_ = open.EnsurePolicy(context.Background(), TenantTarget{Tenant: "t", Namespace: "ns"})
	if err := open.Rollback(context.Background(), req, ""); !errors.Is(err, errTripwire) || crossings != 1 {
		t.Fatalf("control: allowed adapter-rotate rollback must reach the pod read (crossings=%d), got %v", crossings, err)
	}

	crossings = 0
	dry := NewNativeActuator(c)
	_ = dry.EnsurePolicy(context.Background(), TenantTarget{Tenant: "t", Namespace: "ns"})
	dry.DryRun = true
	if err := dry.Rollback(context.Background(), req, ""); !errors.Is(err, errDryRunGuard) {
		t.Fatalf("dry-run adapter-rotate rollback must refuse centrally, got %v", err)
	}
	cross := NewNativeActuator(c)
	_ = cross.EnsurePolicy(context.Background(), TenantTarget{Tenant: "t", Namespace: "elsewhere"})
	if err := cross.Rollback(context.Background(), req, ""); err == nil || !strings.Contains(err.Error(), "DENIED (O7)") {
		t.Fatalf("cross-namespace adapter-rotate rollback must refuse centrally, got %v", err)
	}
	if crossings != 0 {
		t.Fatalf("refused adapter-rotate rollback read the pod %d time(s) on its way to the serving call", crossings)
	}
}

// Retained control: quarantine's OWN dry-run refusal (quarantinePod) is unchanged and still holds
// when the handler is called directly, independent of the central NativeActuator guard.
func TestM087QuarantineDirectRollbackKeepsDryRunRefusal(t *testing.T) {
	spy := &m087Spy{}
	p := ownedPod("ns", "victim", map[string]string{"app": "a"}, ctrlRef("apps/v1", "ReplicaSet", "rs"))
	c := m087Client(spy, p)
	err := (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, DryRun: true},
		Request{Namespace: "ns", Pod: "victim", TargetUID: string(p.UID)}, "ns/victim@"+string(p.UID))
	if !errors.Is(err, errDryRunGuard) {
		t.Fatalf("quarantine direct rollback must keep its dry-run refusal, got %v", err)
	}
	if spy.reads != 0 || spy.writes != 0 {
		t.Fatalf("quarantine dry-run rollback crossed the boundary: reads=%d writes=%d", spy.reads, spy.writes)
	}
}
