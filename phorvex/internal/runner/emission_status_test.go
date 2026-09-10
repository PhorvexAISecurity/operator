package runner

import (
	"context"
	"errors"
	"github.com/phorvex/phorvex/internal/model"
	"testing"
	"time"

	v1 "github.com/phorvex/phorvex/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestM011QuietExpiryFreshnessAndNoExtraWrites(t *testing.T) {
	h := newStatusHarness(t, time.Minute)
	h.m.policies = map[string]*policyEntry{h.e.key.String(): h.e}
	writes, patches := 0, 0
	h.m.Client = interceptor.NewClient(h.m.Client.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, o client.Object, opts ...client.SubResourceUpdateOption) error {
			writes++
			return c.SubResource(sub).Update(ctx, o, opts...)
		},
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, o client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
			patches++
			return c.SubResource(sub).Patch(ctx, o, p, opts...)
		},
	})
	t0 := time.Unix(100000, 0)
	h.tick(t, 1, 1, t0)
	read := func() v1.PhorvexPolicy {
		var p v1.PhorvexPolicy
		if err := h.m.Client.Get(context.Background(), h.e.key, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := read()
	c := meta.FindStatusCondition(before.Status.Conditions, "EmissionHistory")
	if c == nil || c.Status != metav1.ConditionUnknown {
		t.Fatal("incomplete history must be explicit")
	}
	h.e.spec.Mode = v1.ModeDryRun // earlier active emissions survive mode changes.
	h.m.refreshEmissionStatus(context.Background(), t0.Add(30*time.Second))
	inside := read()
	if !inside.Status.Actuated || inside.Status.MovesThisWindow != 1 {
		t.Fatal("mode change erased recent emission")
	}
	count := writes
	h.m.refreshEmissionStatus(context.Background(), t0.Add(40*time.Second))
	if writes != count || patches != 0 {
		t.Fatal("unchanged reporting caused writes")
	}
	h.m.refreshEmissionStatus(context.Background(), t0.Add(time.Minute))
	after := read()
	if after.Status.Actuated || after.Status.MovesThisWindow != 0 {
		t.Fatal("quiet tick did not expire at boundary")
	}
	if !after.Status.LastTickTime.Equal(&before.Status.LastTickTime) || after.Status.DecisionsTotal != before.Status.DecisionsTotal {
		t.Fatal("expiry fabricated decision activity")
	}
	c = meta.FindStatusCondition(after.Status.Conditions, "EmissionHistory")
	if c == nil || c.Status != metav1.ConditionTrue {
		t.Fatal("complete observed window not recognized")
	}
	if writes != count+1 || patches != 0 {
		t.Fatal("unexpected expiry traffic")
	}
}

func TestM011RestartAndUIDIsolation(t *testing.T) {
	h := newStatusHarness(t, time.Minute)
	t0 := time.Unix(100000, 0)
	h.tick(t, 1, 1, t0)
	h.m.emits = nil
	h.tick(t, 0, 0, t0.Add(time.Second))
	var p v1.PhorvexPolicy
	_ = h.m.Client.Get(context.Background(), h.e.key, &p)
	if c := meta.FindStatusCondition(p.Status.Conditions, "EmissionHistory"); c == nil || c.Status != metav1.ConditionUnknown {
		t.Fatal("restart presented exact zero")
	}
	old := *h.e
	old.uid = "old"
	h.m.emissionWindow(&old, 1, t0)
	newer := *h.e
	newer.uid = "new"
	h.m.policies = map[string]*policyEntry{newer.key.String(): &newer}
	if n, _ := h.m.emissionWindow(&newer, 0, t0.Add(time.Second)); n != 0 {
		t.Fatal("new UID inherited old emissions")
	}
	h.m.emissionWindow(&old, 5, t0.Add(2*time.Second))
	if n, _ := h.m.emissionWindow(&newer, 0, t0.Add(3*time.Second)); n != 0 {
		t.Fatal("stale tick contaminated new UID")
	}
}

func TestM011ExpandedWindowAndClockRollbackRemainUnknown(t *testing.T) {
	h := newStatusHarness(t, time.Minute)
	t0 := time.Unix(100000, 0)
	h.m.emissionWindow(h.e, 0, t0)
	if _, ok := h.m.emissionWindow(h.e, 0, t0.Add(time.Minute)); !ok {
		t.Fatal("expected complete window")
	}
	h.e.spec.Budget.AntiOverRotationWindow = metav1.Duration{Duration: 2 * time.Minute}
	if _, ok := h.m.emissionWindow(h.e, 0, t0.Add(2*time.Minute)); ok {
		t.Fatal("expanded window fabricated retained history")
	}
	if _, ok := h.m.emissionWindow(h.e, 0, t0.Add(time.Minute)); ok {
		t.Fatal("clock rollback fabricated completeness")
	}
}

func TestM011EmittedErrorStillCountsOnceAtSource(t *testing.T) {
	h := newStatusHarness(t, time.Minute)
	fa := &dispatchFakeActuator{emit: true, actErr: errors.New("partial result")}
	h.m.Actuator = fa
	ds := tracedSelectedDecision()
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true}}}
	pol := model.Policy{Tenant: "t", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	h.m.actuate(context.Background(), h.e, pol, ds, views)
	if fa.calls != 1 {
		t.Fatal("positive control did not invoke handler")
	}
	if ds[0].Trace.DispatchOutcome != model.DispatchError || ds[0].Actuated {
		t.Fatal("reporting correction changed existing decision result")
	}
	now := time.Now()
	h.m.updateStatus(context.Background(), h.e, 1, 1, 0, false, now)
	h.m.updateStatus(context.Background(), h.e, 1, 0, 0, false, now.Add(time.Second))
	var p v1.PhorvexPolicy
	_ = h.m.Client.Get(context.Background(), h.e.key, &p)
	if p.Status.MovesThisWindow != 1 || !p.Status.Actuated || fa.calls != 1 {
		t.Fatal("lost or double counted emitted error")
	}
}
