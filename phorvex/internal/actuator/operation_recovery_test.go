package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/model"
)

type changingDrainVLLM struct {
	mockVLLM
	change func()
}

func (m *changingDrainVLLM) DrainRequests(ctx context.Context, ep servingEndpoint) (int, error) {
	if m.change != nil {
		m.change()
		m.change = nil
	}
	return m.mockVLLM.DrainRequests(ctx, ep)
}

// A real warmCutover producer is interrupted after promotion, then the restarted
// consumer uses the persisted pair rather than attacker-writable labels.
func interruptedWarmReceiptFixture(t *testing.T) (client.Client, *NativeActuator, *corev1.Pod, *corev1.Pod) {
	t.Helper()
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	newPod := aiPod("ns", "new", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	poolObjects := m066FakePool(old, newPod, labelSwapGroup)
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{labelSwapGroup: "g"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
	phaseError := true
	objects := append([]client.Object{old, newPod, pol, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}}, poolObjects...)
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("created-" + obj.GetName()))
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if cm, ok := obj.(*corev1.ConfigMap); ok && phaseError && cm.Data["receipt"] != "" && cm.Name == receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)}) {
				phaseError = false
				return errors.New("injected post-promotion journal outage")
			}
			if err := c.Update(ctx, obj, opts...); err != nil {
				return err
			}
			if _, ok := obj.(*corev1.Pod); ok {
				return m067SyncFakeRoute(ctx, c, old)
			}
			return nil
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := c.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			if _, ok := obj.(*corev1.Pod); ok {
				return m067SyncFakeRoute(ctx, c, old)
			}
			return nil
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			p, ok := obj.(*corev1.Pod)
			if !ok || p.Name != old.Name {
				return nil
			}
			// Synthetic controller event for journal unit tests. The local real
			// KCM test independently proves actual ReplicaSet behavior.
			replacement := newPod.DeepCopy()
			replacement.Name = "m066-controller-new"
			replacement.UID, replacement.ResourceVersion = "m066-controller-new-uid", ""
			replacement.Labels[labelRole] = roleShadow
			replacement.Labels[labelModelLoaded] = "true"
			return c.Create(ctx, replacement)
		},
	}).Build()
	req := boundReq(old, model.ActionWarmSwap)
	if _, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: &mockVLLM{loaded: true}}, req); err == nil {
		t.Fatal("fixture did not interrupt real producer after promotion")
	}
	var leaders corev1.PodList
	if err := c.List(ctx, &leaders, client.InNamespace("ns"), client.MatchingLabels{labelRole: roleLeader}); err != nil || len(leaders.Items) != 2 {
		t.Fatalf("fixture is not double-leader: %v %+v", err, leaders.Items)
	}
	n := NewNativeActuator(c)
	n.Reader = c
	n.JournalNamespace = "operator"
	n.RecoveryVLLM = &mockVLLM{loaded: true}
	return c, n, old, newPod
}

func TestOperationJournalWarmProducerRecovery(t *testing.T) {
	ctx := context.Background()
	c, n, _, newPod := interruptedWarmReceiptFixture(t)
	var leaders corev1.PodList
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err != nil || events[0].Effect == "" {
		t.Fatalf("recorded recovery failed: events=%+v err=%v", events, err)
	}
	if err := c.List(ctx, &leaders, client.InNamespace("ns"), client.MatchingLabels{labelRole: roleLeader}); err != nil || len(leaders.Items) != 1 || leaders.Items[0].UID != newPod.UID {
		t.Fatalf("wrong survivor: %v %+v", err, leaders.Items)
	}
	again, err := n.RecoverOperations(ctx, false)
	if err != nil || len(again) != 0 {
		t.Fatalf("retry was not idempotent: %+v %v", again, err)
	}
}

func TestOperationJournalProducerRefusesOldNameReplacementBeforeFlipDown(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	newPod := aiPod("ns", "new", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, newPod)
	replaced := false
	guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(*corev1.Pod); ok && key.Namespace == "ns" && key.Name == old.Name && !replaced {
			promoted := &corev1.Pod{}
			if err := inner.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil {
				return err
			}
			if promoted.Labels[labelRole] == roleLeader {
				replaced = true
				original := &corev1.Pod{}
				if err := inner.Get(ctx, key, original); err != nil {
					return err
				}
				if err := inner.Delete(ctx, original, uidPrecondition(original)); err != nil {
					return err
				}
				foreign := original.DeepCopy()
				foreign.ResourceVersion = ""
				foreign.UID = "foreign-old-uid"
				if err := inner.Create(ctx, foreign); err != nil {
					return err
				}
			}
		}
		return inner.Get(ctx, key, obj, opts...)
	}})
	_, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: &mockVLLM{loaded: true}}, boundReq(old, model.ActionWarmSwap))
	if err == nil || !replaced {
		t.Fatalf("same-name replacement did not refuse flip-down: replaced=%t err=%v", replaced, err)
	}
	foreign := &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, foreign); err != nil || foreign.UID != "foreign-old-uid" || foreign.Labels[labelRole] != roleLeader {
		t.Fatalf("foreign old Pod mutated: %v %+v", err, foreign)
	}
	promoted := &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil || promoted.UID != newPod.UID || promoted.Labels[labelRole] != roleLeader {
		t.Fatalf("only recorded survivor demoted: %v %+v", err, promoted)
	}
}

func TestOperationJournalProducerKeepsPromotedLeaderWhenOldDisappearsBeforeFlipDown(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	newPod := aiPod("ns", "new", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, newPod)
	disappeared := false
	guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(*corev1.Pod); ok && key.Namespace == "ns" && key.Name == old.Name && !disappeared {
			promoted := &corev1.Pod{}
			if err := inner.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil {
				return err
			}
			if promoted.Labels[labelRole] == roleLeader {
				disappeared = true
				original := &corev1.Pod{}
				if err := inner.Get(ctx, key, original); err != nil {
					return err
				}
				if err := inner.Delete(ctx, original, uidPrecondition(original)); err != nil {
					return err
				}
			}
		}
		return inner.Get(ctx, key, obj, opts...)
	}})
	_, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: &mockVLLM{loaded: true}}, boundReq(old, model.ActionWarmSwap))
	if err == nil || !disappeared {
		t.Fatalf("old disappearance not exercised/refused: disappeared=%t err=%v", disappeared, err)
	}
	promoted := &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil || promoted.UID != newPod.UID || promoted.Labels[labelRole] != roleLeader {
		t.Fatalf("only surviving leader demoted: %v %+v", err, promoted)
	}
}

func TestOperationJournalProducerRetiringPatchAppliedButErrorRetainsLeader(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	newPod := aiPod("ns", "new", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, newPod)
	modeled := m067ModeledRouteClient(base, old)
	applied := false
	guard := interceptor.NewClient(modeled.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if pod, ok := obj.(*corev1.Pod); ok && pod.Name == old.Name && pod.Labels[labelRole] == roleRetiring && !applied {
			applied = true
			if err := inner.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			return errors.New("retiring Patch response lost")
		}
		return inner.Patch(ctx, obj, patch, opts...)
	}})
	_, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: &mockVLLM{loaded: true}}, boundReq(old, model.ActionWarmSwap))
	if err == nil || !applied {
		t.Fatalf("ambiguous applied Patch not exercised/refused: applied=%t err=%v", applied, err)
	}
	oldAfter, promoted := &corev1.Pod{}, &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, oldAfter); err != nil || oldAfter.Labels[labelRole] != roleRetiring {
		t.Fatalf("applied old retiring mutation not retained: %v %+v", err, oldAfter)
	}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil || promoted.UID != newPod.UID || promoted.Labels[labelRole] != roleLeader {
		t.Fatalf("promoted survivor demoted after ambiguous Patch: %v %+v", err, promoted)
	}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("unresolved receipt not retained: %v", err)
	}
}

func TestOperationJournalProducerDrainFailureReportsPartialObjects(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	newPod := aiPod("ns", "new", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	c := fakeC(old, newPod)
	modeled := m067ModeledRouteClient(c, old)
	res, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: modeled, Reader: modeled, JournalNamespace: "operator", VLLM: &mockVLLM{loaded: true, drainErr: errors.New("drain failed")}}, boundReq(old, model.ActionWarmSwap))
	if err == nil || res.Emitted || res.MutationKind != "swap" || len(res.ObjectsTouched) != 2 || !strings.Contains(res.Note, "partial") {
		t.Fatalf("acknowledged partial cutover not reported: %+v %v", res, err)
	}
	oldAfter, promoted := &corev1.Pod{}, &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, oldAfter); err != nil || oldAfter.Labels[labelRole] != roleRetiring {
		t.Fatalf("old route effect missing: %v %+v", err, oldAfter)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil || promoted.Labels[labelRole] != roleLeader {
		t.Fatalf("promoted leader lost: %v %+v", err, promoted)
	}
	for _, ref := range []string{objRef("Pod", "ns", old.Name), objRef("Pod", "ns", newPod.Name)} {
		if !slices.Contains(res.ObjectsTouched, ref) {
			t.Fatalf("partial report omitted %s: %+v", ref, res)
		}
	}
}

func TestOperationJournalScheduledReplacementSpecValidation(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"scheduled-node-accepted", "workload-spec-drift-refused"} {
		t.Run(mode, func(t *testing.T) {
			c, n, old, _ := interruptedWarmReceiptFixture(t)
			guard := interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if err := inner.Delete(ctx, obj, opts...); err != nil {
					return err
				}
				p, ok := obj.(*corev1.Pod)
				if !ok || p.UID != old.UID {
					return nil
				}
				replacement := &corev1.Pod{}
				if err := inner.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "m066-controller-new"}, replacement); err != nil {
					return err
				}
				replacement.Spec.NodeName = "scheduled-node"
				if mode == "workload-spec-drift-refused" {
					replacement.Spec.Containers[0].Image = "different-workload:image"
				}
				return inner.Update(ctx, replacement)
			}})
			n.Client, n.Reader = guard, guard
			events, err := n.RecoverOperations(ctx, false)
			if err != nil || len(events) != 1 {
				t.Fatalf("scheduled replacement recovery not attempted: %+v %v", events, err)
			}
			if mode == "scheduled-node-accepted" && (events[0].Err != nil || events[0].Outcome != "confirmed") {
				t.Fatalf("scheduler NodeName falsely treated as workload drift: %+v", events)
			}
			if mode == "workload-spec-drift-refused" && (events[0].Err == nil || events[0].Outcome != "partial") {
				t.Fatalf("real workload spec drift accepted: %+v", events)
			}
		})
	}
}

func TestOperationJournalWarmRecoveryRefusalControls(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		mutate func(*testing.T, client.Client, *corev1.Pod)
	}{
		{"current-selector-edited", func(t *testing.T, c client.Client, _ *corev1.Pod) {
			p := &v1alpha1.PhorvexPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, p); err != nil {
				t.Fatal(err)
			}
			p.Spec.Selector.MatchLabels = map[string]string{"app": "outside"}
			if err := c.Update(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"current-selector-cleared", func(t *testing.T, c client.Client, _ *corev1.Pod) {
			p := &v1alpha1.PhorvexPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, p); err != nil {
				t.Fatal(err)
			}
			p.Spec.Selector = metav1.LabelSelector{}
			if err := c.Update(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"policy-uid-replaced", func(t *testing.T, c client.Client, _ *corev1.Pod) {
			p := &v1alpha1.PhorvexPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, p); err != nil {
				t.Fatal(err)
			}
			if err := c.Delete(ctx, p); err != nil {
				t.Fatal(err)
			}
			p.UID, p.ResourceVersion = "replacement-policy-uid", ""
			if err := c.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"policy-deleted", func(t *testing.T, c client.Client, _ *corev1.Pod) {
			p := &v1alpha1.PhorvexPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, p); err != nil {
				t.Fatal(err)
			}
			if err := c.Delete(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"policy-dry-run", func(t *testing.T, c client.Client, _ *corev1.Pod) {
			p := &v1alpha1.PhorvexPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, p); err != nil {
				t.Fatal(err)
			}
			p.Spec.Mode = v1alpha1.ModeDryRun
			if err := c.Update(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"policy-action-disabled", func(t *testing.T, c client.Client, _ *corev1.Pod) {
			p := &v1alpha1.PhorvexPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, p); err != nil {
				t.Fatal(err)
			}
			p.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRotate)}
			if err := c.Update(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"namespace-dry-run", func(t *testing.T, c client.Client, _ *corev1.Pod) {
			ns := &corev1.Namespace{}
			if err := c.Get(ctx, client.ObjectKey{Name: "ns"}, ns); err != nil {
				t.Fatal(err)
			}
			ns.Annotations = map[string]string{actuationbrake.NamespaceDryRunAnnotation: " TRUE "}
			if err := c.Update(ctx, ns); err != nil {
				t.Fatal(err)
			}
		}},
		{"promoted-unhealthy", func(t *testing.T, c client.Client, newPod *corev1.Pod) {
			p := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, p); err != nil {
				t.Fatal(err)
			}
			p.Status.Conditions[0].Status = corev1.ConditionFalse
			if err := c.Status().Update(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"promoted-name-recreated", func(t *testing.T, c client.Client, newPod *corev1.Pod) {
			p := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, p); err != nil {
				t.Fatal(err)
			}
			if err := c.Delete(ctx, p); err != nil {
				t.Fatal(err)
			}
			p.UID = "replacement-uid"
			p.ResourceVersion = ""
			if err := c.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, n, old, newPod := interruptedWarmReceiptFixture(t)
			tc.mutate(t, c, newPod)
			beforeOld, beforeNew := &corev1.Pod{}, &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, beforeOld); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, beforeNew); err != nil {
				t.Fatal(err)
			}
			cm := &corev1.ConfigMap{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}, cm); err != nil {
				t.Fatal(err)
			}
			events, err := n.RecoverOperations(ctx, false)
			if err != nil || len(events) != 1 || events[0].Err == nil || events[0].Effect != "" {
				t.Fatalf("refusal not reported: %+v %v", events, err)
			}
			afterOld, afterNew := &corev1.Pod{}, &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, afterOld); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, afterNew); err != nil {
				t.Fatal(err)
			}
			if beforeOld.ResourceVersion != afterOld.ResourceVersion || beforeNew.ResourceVersion != afterNew.ResourceVersion || beforeOld.UID != afterOld.UID || beforeNew.UID != afterNew.UID {
				t.Fatal("refusal mutated recorded pair")
			}
			afterCM := &corev1.ConfigMap{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(cm), afterCM); err != nil || afterCM.ResourceVersion != cm.ResourceVersion {
				t.Fatalf("refusal changed receipt: %v", err)
			}
		})
	}
}

func TestM124PodOptOutDoesNotAbandonStartedWarmRecovery(t *testing.T) {
	ctx := context.Background()
	c, n, old, _ := interruptedWarmReceiptFixture(t)
	current := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(old), current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations == nil {
		current.Annotations = map[string]string{}
	}
	current.Annotations[actuationbrake.PodOptOutAnnotation] = "true"
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err != nil || events[0].Outcome != "confirmed" {
		t.Fatalf("Pod opt-out abandoned required compensation: events=%+v err=%v", events, err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("retiring Pod was not converged after opt-out: %v", err)
	}
}

func TestOperationJournalGlobalAndNativeDryRunLeaveInterruptedPair(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"global-kill", "native-dry-run"} {
		t.Run(mode, func(t *testing.T) {
			c, n, old, newPod := interruptedWarmReceiptFixture(t)
			beforeOld, beforeNew, beforeCM := &corev1.Pod{}, &corev1.Pod{}, &corev1.ConfigMap{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, beforeOld); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, beforeNew); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}, beforeCM); err != nil {
				t.Fatal(err)
			}
			if mode == "native-dry-run" {
				n.DryRun = true
			}
			events, err := n.RecoverOperations(ctx, mode == "global-kill")
			if err != nil || len(events) != 0 {
				t.Fatalf("dry-run/kill attempted maintenance: %+v %v", events, err)
			}
			afterOld, afterNew, afterCM := &corev1.Pod{}, &corev1.Pod{}, &corev1.ConfigMap{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(beforeOld), afterOld); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(beforeNew), afterNew); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(beforeCM), afterCM); err != nil {
				t.Fatal(err)
			}
			if beforeOld.ResourceVersion != afterOld.ResourceVersion || beforeNew.ResourceVersion != afterNew.ResourceVersion || beforeCM.ResourceVersion != afterCM.ResourceVersion {
				t.Fatal("dry-run/kill changed Pod or receipt")
			}
		})
	}
}

func TestOperationJournalCurrentExpressionSelectorAllowsAuthorizedRecovery(t *testing.T) {
	ctx := context.Background()
	c, n, old, newPod := interruptedWarmReceiptFixture(t)
	pol := &v1alpha1.PhorvexPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, pol); err != nil {
		t.Fatal(err)
	}
	pol.Spec.Selector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: labelSwapGroup, Operator: metav1.LabelSelectorOpIn, Values: []string{"g"}}}}
	if err := c.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err != nil || events[0].Outcome != "confirmed" {
		t.Fatalf("valid expression selector refused real recovery: %+v %v", events, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("old leader not retired under expression selector: %v", err)
	}
	promoted := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil || promoted.UID != newPod.UID || promoted.Labels[labelRole] != roleLeader {
		t.Fatalf("wrong expression-selector survivor: %v %+v", err, promoted)
	}
}

func TestOperationJournalWarmDrainAndCollisionOutcomes(t *testing.T) {
	ctx := context.Background()
	t.Run("stack-unreachable-honest", func(t *testing.T) {
		c, n, old, _ := interruptedWarmReceiptFixture(t)
		vllm := &mockVLLM{drainErr: errStackUnreachable}
		n.RecoveryVLLM = vllm
		events, err := n.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Err == nil || events[0].Outcome != "partial" || !strings.Contains(events[0].Err.Error(), "possibly sent") {
			t.Fatalf("unreachable drain overclaimed: %+v %v", events, err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Name}, &corev1.Pod{}); err != nil {
			t.Fatalf("old UID deleted without durable drain confirmation: %v", err)
		}
		again, err := n.RecoverOperations(ctx, false)
		if err != nil || len(again) != 1 || again[0].Err == nil || !strings.Contains(again[0].Err.Error(), "without replay") {
			t.Fatalf("possible-send receipt replayed or disappeared: %+v %v", again, err)
		}
		if vllm.drainCalls != 1 {
			t.Fatalf("possible-send drain replayed: calls=%d", vllm.drainCalls)
		}
	})
	t.Run("drain-failure-retains-old", func(t *testing.T) {
		c, n, old, _ := interruptedWarmReceiptFixture(t)
		n.RecoveryVLLM = &mockVLLM{drainErr: errors.New("abort failed")}
		events, err := n.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Err == nil || events[0].Outcome != "partial" {
			t.Fatalf("drain failure not retained: %+v %v", events, err)
		}
		p := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, p); err != nil {
			t.Fatalf("old deleted despite failed drain: %v", err)
		}
	})
	t.Run("promoted-leader-loses-readiness-during-drain", func(t *testing.T) {
		c, n, old, newPod := interruptedWarmReceiptFixture(t)
		n.RecoveryVLLM = &changingDrainVLLM{change: func() {
			promoted := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil {
				t.Fatal(err)
			}
			promoted.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
			if err := c.Status().Update(ctx, promoted); err != nil {
				t.Fatal(err)
			}
		}}
		events, err := n.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Err == nil || events[0].Outcome != "partial" {
			t.Fatalf("readiness transition retired old: %+v %v", events, err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, &corev1.Pod{}); err != nil {
			t.Fatalf("old deleted after promoted leader became unhealthy: %v", err)
		}
	})
	t.Run("foreign-rewarm-name-collision", func(t *testing.T) {
		c, n, _, newPod := interruptedWarmReceiptFixture(t)
		promoted := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, promoted); err != nil {
			t.Fatal(err)
		}
		name := "legacy-rewarm-name-collision"
		foreign := aiPod("ns", name, map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "false"})
		foreign.UID = "foreign-uid"
		foreign.ResourceVersion = ""
		if err := c.Create(ctx, foreign); err != nil {
			t.Fatal(err)
		}
		events, err := n.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Err != nil || events[0].Outcome != "confirmed" {
			t.Fatalf("unrelated legacy clone name affected controller recovery: %+v %v", events, err)
		}
		got := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, got); err != nil || got.UID != foreign.UID {
			t.Fatalf("foreign shadow adopted/replaced: %v %+v", err, got)
		}
	})
}

func TestM067DefinitelyUnsentRestoresOldFirstWithoutZeroRoute(t *testing.T) {
	ctx := context.Background()
	c, n, old, newPod := interruptedWarmReceiptFixture(t)
	observed := []int{}
	controller := interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if err := inner.Patch(ctx, obj, patch, opts...); err != nil {
			return err
		}
		pod, ok := obj.(*corev1.Pod)
		if !ok || (pod.Name != old.Name && pod.Name != newPod.Name) {
			return nil
		}
		oldNow, newNow := &corev1.Pod{}, &corev1.Pod{}
		if err := inner.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Name}, oldNow); err != nil {
			return err
		}
		if err := inner.Get(ctx, client.ObjectKey{Namespace: newPod.Namespace, Name: newPod.Name}, newNow); err != nil {
			return err
		}
		slice := &discoveryv1.EndpointSlice{}
		if err := inner.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: "m066-serving-1"}, slice); err != nil {
			return err
		}
		ready := true
		slice.Endpoints = nil
		for _, current := range []*corev1.Pod{oldNow, newNow} {
			if current.Labels[labelRole] == roleLeader {
				slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{current.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: current.Namespace, Name: current.Name, UID: current.UID}})
			}
		}
		observed = append(observed, len(slice.Endpoints))
		return inner.Update(ctx, slice)
	}})
	n.Client = controller
	vllm := &mockVLLM{drainErr: &definiteServingUnreachableError{cause: errors.New("dial refused")}}
	n.RecoveryVLLM = vllm
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err != nil || !strings.Contains(events[0].Effect, "routing roles restored") {
		t.Fatalf("definitely-unsent recovery did not restore routing: events=%+v err=%v", events, err)
	}
	oldAfter, newAfter := &corev1.Pod{}, &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Name}, oldAfter); err != nil || oldAfter.Labels[labelRole] != roleLeader {
		t.Fatalf("old leader was not restored: %v %+v", err, oldAfter)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: newPod.Namespace, Name: newPod.Name}, newAfter); err != nil || newAfter.Labels[labelRole] != roleShadow {
		t.Fatalf("new leader was not restored to shadow: %v %+v", err, newAfter)
	}
	if vllm.drainCalls != 1 {
		t.Fatalf("definitely-unsent operation sent %d drains", vllm.drainCalls)
	}
	if !slices.Equal(observed, []int{1, 2, 1}) {
		t.Fatalf("route order was not new-only -> old+new -> old-only: %v", observed)
	}
}

func TestM067LegacyRetiringReceiptNeverPostsDeletesOrRestores(t *testing.T) {
	ctx := context.Background()
	c, n, old, newPod := interruptedWarmReceiptFixture(t)
	oldNow := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Name}, oldNow); err != nil {
		t.Fatal(err)
	}
	oldNow.Labels[labelRole] = roleRetiring
	if err := c.Update(ctx, oldNow); err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}
	if err := c.Get(ctx, key, cm); err != nil {
		t.Fatal(err)
	}
	var receipt operationReceipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Version, receipt.Phase = 2, "retiring"
	receipt.DrainAttempts, receipt.Aborted = 0, 0
	receipt.AdmittedFloor = 0
	receipt.WarmSelectedUIDs, receipt.EndpointConfigSHA256 = nil, ""
	receipt.ServingBindingSHA256, receipt.ServingServiceAccount, receipt.ServingLegacy = "", "", false
	b, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	cm.Data["receipt"] = string(b)
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	vllm := &mockVLLM{}
	n.RecoveryVLLM = vllm
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Err.Error(), "ambiguous drain history") {
		t.Fatalf("legacy ambiguity was not retained: events=%+v err=%v", events, err)
	}
	if vllm.drainCalls != 0 {
		t.Fatalf("legacy retiring receipt replayed drain: calls=%d", vllm.drainCalls)
	}
	for _, expected := range []struct {
		name string
		role string
	}{{old.Name, roleRetiring}, {newPod.Name, roleLeader}} {
		pod := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: expected.name}, pod); err != nil || pod.Labels[labelRole] != expected.role {
			t.Fatalf("legacy receipt mutated %s: %v %+v", expected.name, err, pod)
		}
	}
}

func TestM067ConfirmedReceiptPrecedesExactOldDelete(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, next)
	modeled := m067ModeledRouteClient(base, old)
	deletes := 0
	guard := interceptor.NewClient(modeled.(client.WithWatch), interceptor.Funcs{Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		pod, ok := obj.(*corev1.Pod)
		if !ok || pod.Name != old.Name {
			return inner.Delete(ctx, obj, opts...)
		}
		cm := &corev1.ConfigMap{}
		key := client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}
		if err := inner.Get(ctx, key, cm); err != nil {
			return err
		}
		var receipt operationReceipt
		if err := json.Unmarshal([]byte(cm.Data["receipt"]), &receipt); err != nil {
			return err
		}
		if receipt.Phase != "drain-confirmed" || receipt.Aborted != 3 || receipt.DrainAttempts != 1 || receipt.AdmittedFloor != 1 {
			return fmt.Errorf("delete observed without exact durable drain confirmation: %+v", receipt)
		}
		deletes++
		return inner.Delete(ctx, obj, opts...)
	}})
	vllm := &mockVLLM{loaded: true, drained: 3}
	result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
	if err == nil || result.MutationKind != "swap" {
		t.Fatalf("fake controller did not leave expected replenishment partial: result=%+v err=%v", result, err)
	}
	if vllm.drainCalls != 1 || deletes != 1 {
		t.Fatalf("confirmed flow calls: drain=%d delete=%d", vllm.drainCalls, deletes)
	}
	if err := base.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Name}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("confirmed old UID was not deleted: %v", err)
	}
}

func TestM067LostDispatchClaimAcknowledgementSendsNothing(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, next)
	modeled := m067ModeledRouteClient(base, old)
	lost := false
	guard := interceptor.NewClient(modeled.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		cm, ok := obj.(*corev1.ConfigMap)
		if ok && !lost && strings.Contains(cm.Data["receipt"], `"phase":"drain-dispatching"`) {
			lost = true
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			return errors.New("dispatch claim acknowledgement lost")
		}
		return inner.Update(ctx, obj, opts...)
	}})
	vllm := &mockVLLM{loaded: true, drained: 1}
	result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
	if err == nil || result.MutationKind != "swap" || !lost {
		t.Fatalf("lost dispatch acknowledgement not exercised: result=%+v err=%v", result, err)
	}
	if vllm.drainCalls != 0 {
		t.Fatalf("unacknowledged dispatch claim sent a drain: calls=%d", vllm.drainCalls)
	}
	n := NewNativeActuator(base)
	n.Reader, n.JournalNamespace, n.RecoveryVLLM = base, "operator", vllm
	events, recoverErr := n.RecoverOperations(ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Err.Error(), "without replay") {
		t.Fatalf("durable dispatching receipt was not retained: events=%+v err=%v", events, recoverErr)
	}
	if vllm.drainCalls != 0 {
		t.Fatalf("recovery replayed an unacknowledged dispatch claim: calls=%d", vllm.drainCalls)
	}
}

func TestM067PostDispatchClaimAuthorityDriftRetainsWithoutEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(context.Context, client.Client, *corev1.Pod) error
	}{
		{name: "policy-action", mutate: func(ctx context.Context, c client.Client, _ *corev1.Pod) error {
			policy := &v1alpha1.PhorvexPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, policy); err != nil {
				return err
			}
			policy.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRotate)}
			return c.Update(ctx, policy)
		}},
		{name: "namespace-brake", mutate: func(ctx context.Context, c client.Client, _ *corev1.Pod) error {
			ns := &corev1.Namespace{}
			if err := c.Get(ctx, client.ObjectKey{Name: "ns"}, ns); err != nil {
				return err
			}
			ns.Annotations = map[string]string{actuationbrake.NamespaceDryRunAnnotation: "true"}
			return c.Update(ctx, ns)
		}},
		{name: "promoted-role", mutate: func(ctx context.Context, c client.Client, next *corev1.Pod) error {
			current := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(next), current); err != nil {
				return err
			}
			current.Labels[labelRole] = roleShadow
			return c.Update(ctx, current)
		}},
		{name: "service-selector", mutate: func(ctx context.Context, c client.Client, _ *corev1.Pod) error {
			service := &corev1.Service{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "m066-serving"}, service); err != nil {
				return err
			}
			service.Spec.Selector["authority-drift"] = "true"
			return c.Update(ctx, service)
		}},
		{name: "replicaset-generation", mutate: func(ctx context.Context, c client.Client, _ *corev1.Pod) error {
			rs := &appsv1.ReplicaSet{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "m066-rs"}, rs); err != nil {
				return err
			}
			rs.Generation++
			return c.Update(ctx, rs)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
			base := fakeC(old, next)
			modeled := m067ModeledRouteClient(base, old)
			claimed, deletes := false, 0
			guard := interceptor.NewClient(modeled.(client.WithWatch), interceptor.Funcs{
				Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					cm, ok := obj.(*corev1.ConfigMap)
					if !ok || claimed || !strings.Contains(cm.Data["receipt"], `"phase":"drain-dispatching"`) {
						return inner.Update(ctx, obj, opts...)
					}
					if err := inner.Update(ctx, obj, opts...); err != nil {
						return err
					}
					claimed = true
					return tc.mutate(ctx, inner, next)
				},
				Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					if pod, ok := obj.(*corev1.Pod); ok && pod.Name == old.Name {
						deletes++
					}
					return inner.Delete(ctx, obj, opts...)
				},
			})
			vllm := &mockVLLM{loaded: true, drained: 1}
			result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
			if err == nil || result.MutationKind != "swap" || !claimed {
				t.Fatalf("post-claim authority drift not exercised: result=%+v err=%v claimed=%t", result, err, claimed)
			}
			if vllm.drainCalls != 0 || deletes != 0 {
				t.Fatalf("post-claim authority drift crossed effect boundary: posts=%d deletes=%d", vllm.drainCalls, deletes)
			}
			cm := &corev1.ConfigMap{}
			key := client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}
			if err := base.Get(ctx, key, cm); err != nil {
				t.Fatal(err)
			}
			var receipt operationReceipt
			if err := json.Unmarshal([]byte(cm.Data["receipt"]), &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.Phase != "drain-dispatching" || receipt.DrainAttempts != 1 {
				t.Fatalf("post-claim drift changed conservative receipt: %+v", receipt)
			}
			oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
			if err := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); err != nil || oldCurrent.Labels[labelRole] != roleRetiring {
				t.Fatalf("post-claim drift removed or compensated old UID: %v %+v", err, oldCurrent)
			}
			wantNextRole := roleLeader
			if tc.name == "promoted-role" {
				wantNextRole = roleShadow
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); err != nil || nextCurrent.Labels[labelRole] != wantNextRole {
				t.Fatalf("post-claim drift compensated promoted UID: want role=%s err=%v pod=%+v", wantNextRole, err, nextCurrent)
			}
		})
	}
}

func m067ThreeMemberPool(t *testing.T) (client.Client, *corev1.Pod, *corev1.Pod, *corev1.Pod) {
	return m067ThreeMemberPoolWithThirdRole(t, roleLeader)
}

func m067ThreeMemberPoolWithThirdRole(t *testing.T, thirdRole string) (client.Client, *corev1.Pod, *corev1.Pod, *corev1.Pod) {
	t.Helper()
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, next)
	rs := &appsv1.ReplicaSet{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "m066-rs"}, rs); err != nil {
		t.Fatal(err)
	}
	desired := int32(3)
	rs.Spec.Replicas, rs.Status.Replicas = &desired, desired
	if err := base.Update(ctx, rs); err != nil {
		t.Fatal(err)
	}
	third := aiPod("ns", "third", map[string]string{"app": "m066-pool", labelSwapGroup: "g", labelRole: thirdRole, labelModelLoaded: "true"})
	third.ResourceVersion = ""
	third.Annotations[annoRouteService] = "m066-serving"
	third.OwnerReferences = append([]metav1.OwnerReference(nil), old.OwnerReferences...)
	if err := base.Create(ctx, third); err != nil {
		t.Fatal(err)
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "m066-serving-1"}, slice); err != nil {
		t.Fatal(err)
	}
	if thirdRole == roleLeader {
		ready := true
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{third.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: third.Namespace, Name: third.Name, UID: third.UID}})
	}
	if err := base.Update(ctx, slice); err != nil {
		t.Fatal(err)
	}
	return base, old, next, third
}

func m067SetPolicyFloor(ctx context.Context, c client.Client, floor int) error {
	policy := &v1alpha1.PhorvexPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "policy"}, policy); err != nil {
		return err
	}
	policy.Spec.SLO.MinAvailableReplicas = floor
	return c.Update(ctx, policy)
}

func m067SetPodReady(ctx context.Context, c client.Client, pod *corev1.Pod, ready bool) error {
	current := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), current); err != nil {
		return err
	}
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	current.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}
	return c.Status().Update(ctx, current)
}

func m067ReadReceipt(t *testing.T, ctx context.Context, c client.Client, old *corev1.Pod) operationReceipt {
	t.Helper()
	cm := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}
	if err := c.Get(ctx, key, cm); err != nil {
		t.Fatal(err)
	}
	var receipt operationReceipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func m067SyncFakeRoute(ctx context.Context, c client.Client, old *corev1.Pod) error {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(old.Namespace), client.MatchingLabels{"app": "m066-pool", labelSwapGroup: "g"}); err != nil {
		return err
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: "m066-serving-1"}, slice); err != nil {
		return err
	}
	ready := true
	slice.Endpoints = nil
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Labels[labelRole] != roleLeader || !podReady(pod) || pod.DeletionTimestamp != nil {
			continue
		}
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{pod.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}})
	}
	return c.Update(ctx, slice)
}

// m067ModeledRouteClient is an explicit per-fixture EndpointSlice controller.
// It is intentionally not part of fakeC: tests that need delayed or stale
// convergence must continue to model those states themselves.
func m067ModeledRouteClient(base client.Client, old *corev1.Pod) client.Client {
	return interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			if _, ok := obj.(*corev1.Pod); ok {
				return m067SyncFakeRoute(ctx, inner, old)
			}
			return nil
		},
		Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := inner.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			if _, ok := obj.(*corev1.Pod); ok {
				return m067SyncFakeRoute(ctx, inner, old)
			}
			return nil
		},
	})
}

func m067WriteFakeRoute(ctx context.Context, c client.Client, old *corev1.Pod, members ...*corev1.Pod) error {
	slice := &discoveryv1.EndpointSlice{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: "m066-serving-1"}, slice); err != nil {
		return err
	}
	ready := true
	slice.Endpoints = nil
	for _, pod := range members {
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{pod.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}})
	}
	return c.Update(ctx, slice)
}

func TestM067ForwardRouteBarriersProtectDrainAndDeletion(t *testing.T) {
	ctx := context.Background()
	t.Run("stale-original-after-promotion", func(t *testing.T) {
		base, old, next, _ := m067ThreeMemberPool(t)
		vllm := &mockVLLM{loaded: true, drained: 2}
		result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: base, Reader: base, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 15 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap))
		if err == nil || result.MutationKind == "swap" || vllm.drainCalls != 0 {
			t.Fatalf("stale promotion route crossed old removal: result=%+v err=%v calls=%d", result, err, vllm.drainCalls)
		}
		oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
		if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); getErr != nil || oldCurrent.Labels[labelRole] != roleLeader {
			t.Fatalf("stale promotion route changed old leader: %v %+v", getErr, oldCurrent)
		}
		if getErr := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); getErr != nil || nextCurrent.Labels[labelRole] != roleShadow {
			t.Fatalf("stale promotion route did not preserve/restore shadow: %v %+v", getErr, nextCurrent)
		}
	})

	t.Run("old-remains-selected-after-retirement", func(t *testing.T) {
		base, old, _, _ := m067ThreeMemberPool(t)
		guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
			Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if err := inner.Update(ctx, obj, opts...); err != nil {
					return err
				}
				if _, ok := obj.(*corev1.Pod); ok {
					return m067SyncFakeRoute(ctx, inner, old)
				}
				return nil
			},
		})
		vllm := &mockVLLM{loaded: true, drained: 2}
		result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 15 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap))
		if err == nil || result.MutationKind != "swap" || vllm.drainCalls != 0 {
			t.Fatalf("stale retired route crossed dispatch claim: result=%+v err=%v calls=%d", result, err, vllm.drainCalls)
		}
		receipt := m067ReadReceipt(t, ctx, base, old)
		if receipt.Phase != "retiring" || receipt.DrainAttempts != 0 {
			t.Fatalf("stale preclaim route changed send ownership: %+v", receipt)
		}
	})

	for _, routeDrift := range []string{"stale-old", "foreign", "duplicate"} {
		t.Run("after-dispatch-claim-"+routeDrift, func(t *testing.T) {
			base, old, next, third := m067ThreeMemberPool(t)
			mutated := false
			guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
				Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if err := inner.Update(ctx, obj, opts...); err != nil {
						return err
					}
					if _, ok := obj.(*corev1.Pod); ok {
						return m067SyncFakeRoute(ctx, inner, old)
					}
					cm, ok := obj.(*corev1.ConfigMap)
					if !ok || mutated || !strings.Contains(cm.Data["receipt"], `"phase":"drain-dispatching"`) {
						return nil
					}
					mutated = true
					switch routeDrift {
					case "stale-old":
						return m067WriteFakeRoute(ctx, inner, old, old, next, third)
					case "foreign":
						foreign := next.DeepCopy()
						foreign.Name, foreign.UID = "foreign", "foreign-uid"
						return m067WriteFakeRoute(ctx, inner, old, foreign, third)
					default:
						return m067WriteFakeRoute(ctx, inner, old, next, next, third)
					}
				},
				Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					if err := inner.Patch(ctx, obj, patch, opts...); err != nil {
						return err
					}
					if _, ok := obj.(*corev1.Pod); ok {
						return m067SyncFakeRoute(ctx, inner, old)
					}
					return nil
				},
			})
			vllm := &mockVLLM{loaded: true, drained: 2}
			result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 15 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap))
			if err == nil || result.MutationKind != "swap" || !mutated || vllm.drainCalls != 0 {
				t.Fatalf("postclaim route drift crossed POST: drift=%s result=%+v err=%v mutated=%t calls=%d", routeDrift, result, err, mutated, vllm.drainCalls)
			}
			receipt := m067ReadReceipt(t, ctx, base, old)
			if receipt.Phase != "drain-dispatching" || receipt.DrainAttempts != 1 {
				t.Fatalf("postclaim route drift lost conservative claim: %+v", receipt)
			}
			if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); getErr != nil {
				t.Fatalf("postclaim route drift deleted old UID: %v", getErr)
			}
		})
	}

	t.Run("route-regression-after-confirmation", func(t *testing.T) {
		base, old, next, third := m067ThreeMemberPool(t)
		guard := m067ModeledRouteClient(base, old)
		vllm := &changingDrainVLLM{mockVLLM: mockVLLM{loaded: true, drained: 2}, change: func() {
			if err := m067WriteFakeRoute(ctx, base, old, old, next, third); err != nil {
				t.Errorf("regress route after POST: %v", err)
			}
		}}
		result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 15 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap))
		if err == nil || result.MutationKind != "swap" || vllm.drainCalls != 1 {
			t.Fatalf("confirmed route regression fixture: result=%+v err=%v calls=%d", result, err, vllm.drainCalls)
		}
		receipt := m067ReadReceipt(t, ctx, base, old)
		if receipt.Phase != "drain-confirmed" || receipt.DrainAttempts != 1 {
			t.Fatalf("confirmed route regression lost durable result: %+v", receipt)
		}
		if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); getErr != nil {
			t.Fatalf("confirmed route regression deleted old UID: %v", getErr)
		}
		events, recoverErr := (&NativeActuator{Client: guard, Reader: guard, JournalNamespace: "operator", RecoveryVLLM: vllm, RouteObservationTimeout: 15 * time.Millisecond, RouteObservationInterval: time.Millisecond}).RecoverOperations(ctx, false)
		if recoverErr != nil || len(events) != 1 || events[0].Err == nil || vllm.drainCalls != 1 {
			t.Fatalf("confirmed route regression replayed or vanished: events=%+v err=%v calls=%d", events, recoverErr, vllm.drainCalls)
		}
		if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); getErr != nil {
			t.Fatalf("confirmed route regression recovery deleted old UID: %v", getErr)
		}
	})

	t.Run("converged", func(t *testing.T) {
		base, old, _, _ := m067ThreeMemberPool(t)
		guard := m067ModeledRouteClient(base, old)
		vllm := &mockVLLM{loaded: true, drained: 2}
		result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 50 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap))
		if err == nil || result.MutationKind != "swap" || vllm.drainCalls != 1 {
			t.Fatalf("converged route did not reach confirmed retirement: result=%+v err=%v calls=%d", result, err, vllm.drainCalls)
		}
		if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); !apierrors.IsNotFound(getErr) {
			t.Fatalf("converged route did not delete exact old UID: %v", getErr)
		}
	})
}

func TestM067ForwardRouteObservationRechecksAuthorityAndReadiness(t *testing.T) {
	for _, drift := range []string{"promoted-readiness", "service-authority"} {
		t.Run(drift, func(t *testing.T) {
			ctx := context.Background()
			base, old, next, _ := m067ThreeMemberPool(t)
			producer, lost := m067PhaseLossClient(base, old, next, "retiring")
			vllm := &mockVLLM{loaded: true, drained: 2}
			if _, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: producer, Reader: producer, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap)); err == nil || !*lost || vllm.drainCalls != 0 {
				t.Fatalf("retiring producer fixture failed: err=%v lost=%t calls=%d", err, *lost, vllm.drainCalls)
			}
			receipt := m067ReadReceipt(t, ctx, base, old)
			mutated := false
			reader := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
				List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if err := inner.List(ctx, list, opts...); err != nil {
						return err
					}
					if mutated {
						return nil
					}
					if _, ok := list.(*discoveryv1.EndpointSliceList); !ok {
						return nil
					}
					mutated = true
					if drift == "promoted-readiness" {
						return m067SetPodReady(ctx, inner, next, false)
					}
					service := &corev1.Service{}
					if err := inner.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Annotations[annoRouteService]}, service); err != nil {
						return err
					}
					service.Spec.Selector["observed-authority-drift"] = "true"
					return inner.Update(ctx, service)
				},
			})
			err := observeWarmRecordedRoute(ctx, EnactCtx{Reader: reader, RouteObservationTimeout: 15 * time.Millisecond, RouteObservationInterval: time.Millisecond}, receipt, warmProspectiveRoute)
			if err == nil || !mutated {
				t.Fatalf("route observation accepted %s drift: mutated=%t err=%v", drift, mutated, err)
			}
		})
	}
}

func m067CompensationBoundaryClient(base client.Client, old, next, third *corev1.Pod, mutate func(context.Context, client.WithWatch) error) (client.Client, *bool) {
	mutated := false
	return interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if pod, ok := obj.(*corev1.Pod); ok {
				if err := inner.Update(ctx, pod, opts...); err != nil {
					return err
				}
				if pod.UID == old.UID || pod.UID == next.UID || (third != nil && pod.UID == third.UID) {
					return m067SyncFakeRoute(ctx, inner, old)
				}
				return nil
			}
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || mutate == nil || mutated || !strings.Contains(cm.Data["receipt"], `"phase":"drain-unsent"`) {
				return inner.Update(ctx, obj, opts...)
			}
			if err := inner.Update(ctx, cm, opts...); err != nil {
				return err
			}
			if err := mutate(ctx, inner); err != nil {
				return err
			}
			mutated = true
			return m067SyncFakeRoute(ctx, inner, old)
		},
		Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := inner.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			pod, ok := obj.(*corev1.Pod)
			if !ok || (pod.UID != old.UID && pod.UID != next.UID && (third == nil || pod.UID != third.UID)) {
				return nil
			}
			return m067SyncFakeRoute(ctx, inner, old)
		},
	}), &mutated
}

func m067AssertFakeRouteUIDs(t *testing.T, ctx context.Context, c client.Client, old *corev1.Pod, want ...*corev1.Pod) {
	t.Helper()
	service := &corev1.Service{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Annotations[annoRouteService]}, service); err != nil {
		t.Fatal(err)
	}
	members, err := routeEndpointMembers(ctx, c, service)
	if err != nil {
		t.Fatal(err)
	}
	wantUIDs := make([]string, 0, len(want))
	for _, pod := range want {
		wantUIDs = append(wantUIDs, string(pod.UID))
	}
	sort.Strings(wantUIDs)
	if !reflect.DeepEqual(members, wantUIDs) {
		t.Fatalf("active route members=%v want exact recorded Ready leaders=%v", members, wantUIDs)
	}
}

func m067AssertNoFakeReceipt(t *testing.T, ctx context.Context, c client.Client) {
	t.Helper()
	var receipts corev1.ConfigMapList
	if err := c.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 0 {
		t.Fatalf("completed compensation retained receipt: count=%d err=%v", len(receipts.Items), err)
	}
}

func TestM067AvailabilityAdmissionUsesOnlyProspectiveServingUIDs(t *testing.T) {
	t.Run("equal-floor-two", func(t *testing.T) {
		ctx := context.Background()
		base, old, _, _ := m067ThreeMemberPool(t)
		if err := m067SetPolicyFloor(ctx, base, 2); err != nil {
			t.Fatal(err)
		}
		modeled := m067ModeledRouteClient(base, old)
		vllm := &mockVLLM{loaded: true, drained: 2}
		result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: modeled, Reader: modeled, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
		if err == nil || result.MutationKind != "swap" || vllm.drainCalls != 1 {
			t.Fatalf("equal floor two did not reach the fake-controller terminal boundary: result=%+v err=%v calls=%d", result, err, vllm.drainCalls)
		}
		if err := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); !apierrors.IsNotFound(err) {
			t.Fatalf("equal floor two did not permit confirmed exact old retirement: %v", err)
		}
		receipt := m067ReadReceipt(t, ctx, base, old)
		if receipt.AdmittedFloor != 2 || !receipt.valid() {
			t.Fatalf("admitted floor missing or invalid: %+v", receipt)
		}
		missing := receipt
		missing.AdmittedFloor = 0
		tooHigh := receipt
		tooHigh.AdmittedFloor = len(receipt.WarmSelectedUIDs) + 1
		duplicate := receipt
		duplicate.Pool = &warmPoolIntent{}
		*duplicate.Pool = *receipt.Pool
		duplicate.Pool.Members = append([]string(nil), receipt.Pool.Members...)
		duplicate.Pool.Members[1] = duplicate.Pool.Members[0]
		if missing.valid() || tooHigh.valid() || duplicate.valid() {
			t.Fatalf("invalid availability provenance accepted: missing=%t high=%t duplicate=%t", missing.valid(), tooHigh.valid(), duplicate.valid())
		}
	})

	for _, tc := range []struct {
		name      string
		thirdRole string
		floor     int
	}{
		{name: "impossible-floor-before-first-mutation", thirdRole: roleLeader, floor: 4},
		{name: "ready-unrelated-shadow-has-no-credit", thirdRole: roleShadow, floor: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base, old, next, third := m067ThreeMemberPoolWithThirdRole(t, tc.thirdRole)
			if err := m067SetPolicyFloor(ctx, base, tc.floor); err != nil {
				t.Fatal(err)
			}
			vllm := &mockVLLM{loaded: true, drained: 2}
			result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: base, Reader: base, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
			if err == nil || result.MutationKind != "" || vllm.drainCalls != 0 {
				t.Fatalf("availability admission crossed mutation boundary: result=%+v err=%v calls=%d", result, err, vllm.drainCalls)
			}
			for pod, wantRole := range map[*corev1.Pod]string{old: roleLeader, next: roleShadow, third: tc.thirdRole} {
				current := &corev1.Pod{}
				if getErr := base.Get(ctx, client.ObjectKeyFromObject(pod), current); getErr != nil || current.Labels[labelRole] != wantRole {
					t.Fatalf("availability refusal mutated %s: err=%v role=%q want=%q", pod.Name, getErr, current.Labels[labelRole], wantRole)
				}
			}
			var receipts corev1.ConfigMapList
			if listErr := base.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 0 {
				t.Fatalf("availability refusal retained pre-mutation receipt: count=%d err=%v", len(receipts.Items), listErr)
			}
		})
	}
}

func TestM067AvailabilityDriftAtReducingBoundariesRetainsExactState(t *testing.T) {
	for _, boundary := range []string{"promoted", "drain-dispatching", "drain-confirmed"} {
		drifts := []string{"third-not-ready", "floor-increase"}
		if boundary == "promoted" {
			drifts = append(drifts, "floor-relaxation-with-third-not-ready")
		}
		for _, drift := range drifts {
			t.Run(boundary+"/"+drift, func(t *testing.T) {
				ctx := context.Background()
				base, old, next, third := m067ThreeMemberPool(t)
				if err := m067SetPolicyFloor(ctx, base, 2); err != nil {
					t.Fatal(err)
				}
				mutated := false
				mutate := func(c client.Client) error {
					if mutated {
						return nil
					}
					mutated = true
					if drift == "third-not-ready" {
						return m067SetPodReady(ctx, c, third, false)
					}
					if drift == "floor-relaxation-with-third-not-ready" {
						if err := m067SetPodReady(ctx, c, third, false); err != nil {
							return err
						}
						return m067SetPolicyFloor(ctx, c, 1)
					}
					return m067SetPolicyFloor(ctx, c, 3)
				}
				modeled := m067ModeledRouteClient(base, old)
				var enactClient client.Client = modeled
				vllm := &changingDrainVLLM{mockVLLM: mockVLLM{loaded: true, drained: 2}}
				if boundary == "drain-confirmed" {
					vllm.change = func() {
						if err := mutate(base); err != nil {
							t.Errorf("apply confirmed-boundary drift: %v", err)
						}
					}
				} else {
					enactClient = interceptor.NewClient(modeled.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
						cm, ok := obj.(*corev1.ConfigMap)
						if !ok || mutated || !strings.Contains(cm.Data["receipt"], `"phase":"`+boundary+`"`) {
							return inner.Update(ctx, obj, opts...)
						}
						if err := inner.Update(ctx, obj, opts...); err != nil {
							return err
						}
						return mutate(inner)
					}})
				}
				result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: enactClient, Reader: enactClient, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
				if err == nil || result.MutationKind != "swap" || !mutated {
					t.Fatalf("availability boundary not exercised: result=%+v err=%v mutated=%t", result, err, mutated)
				}
				wantCalls, wantOldRole := 0, roleLeader
				if boundary == "drain-dispatching" {
					wantOldRole = roleRetiring
				}
				if boundary == "drain-confirmed" {
					wantCalls, wantOldRole = 1, roleRetiring
				}
				if vllm.drainCalls != wantCalls {
					t.Fatalf("availability boundary POST calls=%d want=%d", vllm.drainCalls, wantCalls)
				}
				oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
				if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); getErr != nil || oldCurrent.UID != old.UID || oldCurrent.Labels[labelRole] != wantOldRole {
					t.Fatalf("availability boundary changed old: %v %+v", getErr, oldCurrent)
				}
				if getErr := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); getErr != nil || nextCurrent.UID != next.UID || nextCurrent.Labels[labelRole] != roleLeader {
					t.Fatalf("availability boundary compensated promoted Pod: %v %+v", getErr, nextCurrent)
				}
				receipt := m067ReadReceipt(t, ctx, base, old)
				if receipt.Phase != boundary || receipt.AdmittedFloor != 2 {
					t.Fatalf("availability boundary receipt=%+v want phase=%s admittedFloor=2", receipt, boundary)
				}
			})
		}
	}
}

func TestM067AvailabilityFailureBeforeDispatchClaimPreservesRetryableReceipt(t *testing.T) {
	ctx := context.Background()
	base, old, next, third := m067ThreeMemberPool(t)
	if err := m067SetPolicyFloor(ctx, base, 2); err != nil {
		t.Fatal(err)
	}
	modeled := m067ModeledRouteClient(base, old)
	readinessDropped := false
	guard := interceptor.NewClient(modeled.(client.WithWatch), interceptor.Funcs{
		Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || readinessDropped || !strings.Contains(cm.Data["receipt"], `"phase":"retiring"`) {
				return inner.Update(ctx, obj, opts...)
			}
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			readinessDropped = true
			return m067SetPodReady(ctx, inner, third, false)
		},
	})
	vllm := &mockVLLM{loaded: true, drained: 2}
	result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
	if err == nil || result.MutationKind != "swap" || !readinessDropped || vllm.drainCalls != 0 {
		t.Fatalf("preclaim availability drift crossed send boundary: result=%+v err=%v dropped=%t calls=%d", result, err, readinessDropped, vllm.drainCalls)
	}
	receipt := m067ReadReceipt(t, ctx, base, old)
	if receipt.Phase != "retiring" || receipt.DrainAttempts != 0 || receipt.AdmittedFloor != 2 {
		t.Fatalf("preclaim availability drift changed retryable receipt: %+v", receipt)
	}
	oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
	if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); getErr != nil || oldCurrent.UID != old.UID || oldCurrent.Labels[labelRole] != roleRetiring {
		t.Fatalf("preclaim availability drift changed old route identity: %v %+v", getErr, oldCurrent)
	}
	if getErr := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); getErr != nil || nextCurrent.UID != next.UID || nextCurrent.Labels[labelRole] != roleLeader {
		t.Fatalf("preclaim availability drift changed promoted route identity: %v %+v", getErr, nextCurrent)
	}

	if err := m067SetPodReady(ctx, base, third, true); err != nil {
		t.Fatal(err)
	}
	n := NewNativeActuator(guard)
	n.Reader, n.JournalNamespace, n.RecoveryVLLM = guard, "operator", vllm
	events, recoverErr := n.RecoverOperations(ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Effect, "old leader retired") {
		t.Fatalf("restored availability did not resume confirmed drain: events=%+v err=%v", events, recoverErr)
	}
	if vllm.drainCalls != 1 {
		t.Fatalf("restored availability drain calls=%d want=1", vllm.drainCalls)
	}
	if err := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("restored availability did not retire exact old UID: %v", err)
	}
	receipt = m067ReadReceipt(t, ctx, base, old)
	if receipt.Phase != "retired-awaiting-controller" || receipt.DrainAttempts != 1 {
		t.Fatalf("restored availability recovery receipt=%+v", receipt)
	}
}

func TestM067AvailabilityInventoryDriftAndFailedFlipPreservePromotedMember(t *testing.T) {
	for _, drift := range []string{"member-deleted", "member-replaced", "failed-old-flip-low-original-capacity"} {
		t.Run(drift, func(t *testing.T) {
			ctx := context.Background()
			base, old, next, third := m067ThreeMemberPool(t)
			if err := m067SetPolicyFloor(ctx, base, 2); err != nil {
				t.Fatal(err)
			}
			modeled := m067ModeledRouteClient(base, old)
			mutated := false
			guard := interceptor.NewClient(modeled.(client.WithWatch), interceptor.Funcs{
				Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					cm, ok := obj.(*corev1.ConfigMap)
					if !ok || mutated || drift == "failed-old-flip-low-original-capacity" || !strings.Contains(cm.Data["receipt"], `"phase":"promoted"`) {
						return inner.Update(ctx, obj, opts...)
					}
					if err := inner.Update(ctx, obj, opts...); err != nil {
						return err
					}
					mutated = true
					if err := inner.Delete(ctx, third); err != nil {
						return err
					}
					if drift == "member-replaced" {
						replacement := third.DeepCopy()
						replacement.ResourceVersion, replacement.UID = "", "replacement-third-uid"
						return inner.Create(ctx, replacement)
					}
					return nil
				},
				Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					pod, ok := obj.(*corev1.Pod)
					if !ok || mutated || drift != "failed-old-flip-low-original-capacity" || pod.Name != old.Name || pod.Labels[labelRole] != roleRetiring {
						return inner.Patch(ctx, obj, patch, opts...)
					}
					mutated = true
					if err := m067SetPodReady(ctx, inner, third, false); err != nil {
						return err
					}
					return errors.New("old route patch refused")
				},
			})
			vllm := &mockVLLM{loaded: true, drained: 2}
			result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
			if err == nil || result.MutationKind != "swap" || !mutated || vllm.drainCalls != 0 {
				t.Fatalf("availability inventory/rollback drift not retained: result=%+v err=%v mutated=%t calls=%d", result, err, mutated, vllm.drainCalls)
			}
			oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
			if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); getErr != nil || oldCurrent.UID != old.UID || oldCurrent.Labels[labelRole] != roleLeader {
				t.Fatalf("availability drift changed original leader: %v %+v", getErr, oldCurrent)
			}
			if getErr := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); getErr != nil || nextCurrent.UID != next.UID || nextCurrent.Labels[labelRole] != roleLeader {
				t.Fatalf("availability drift rolled back promoted capacity: %v %+v", getErr, nextCurrent)
			}
			receipt := m067ReadReceipt(t, ctx, base, old)
			if receipt.Phase != "promoted" || receipt.AdmittedFloor != 2 {
				t.Fatalf("availability inventory/rollback receipt changed: %+v", receipt)
			}
		})
	}
}

func TestM067DefinitelyUnsentRestoresOldBeforeAvailabilityCanBlockNewDemotion(t *testing.T) {
	ctx := context.Background()
	base, old, next, third := m067ThreeMemberPool(t)
	if err := m067SetPolicyFloor(ctx, base, 2); err != nil {
		t.Fatal(err)
	}
	readinessDropped := false
	guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := inner.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			pod, ok := obj.(*corev1.Pod)
			if !ok || (pod.Name != old.Name && pod.Name != next.Name) {
				return nil
			}
			return m067SyncFakeRoute(ctx, inner, old)
		},
		Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if pod, ok := obj.(*corev1.Pod); ok {
				if err := inner.Update(ctx, pod, opts...); err != nil {
					return err
				}
				return m067SyncFakeRoute(ctx, inner, old)
			}
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || readinessDropped || !strings.Contains(cm.Data["receipt"], `"phase":"old-route-observed"`) {
				return inner.Update(ctx, obj, opts...)
			}
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			readinessDropped = true
			return m067SetPodReady(ctx, inner, third, false)
		},
	})
	vllm := &mockVLLM{loaded: true, drainErr: &definiteServingUnreachableError{cause: errors.New("dial refused")}}
	ec := EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 50 * time.Millisecond, RouteObservationInterval: time.Millisecond}
	result, err := (warmSwapHandler{}).Enact(ctx, ec, boundReq(old, model.ActionWarmSwap))
	if err == nil || result.MutationKind != "swap" || !readinessDropped || vllm.drainCalls != 1 {
		t.Fatalf("direction-sensitive unsent restoration not exercised: result=%+v err=%v dropped=%t calls=%d", result, err, readinessDropped, vllm.drainCalls)
	}
	oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
	if getErr := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); getErr != nil || oldCurrent.UID != old.UID || oldCurrent.Labels[labelRole] != roleLeader {
		t.Fatalf("low capacity blocked capacity-adding old restoration: %v %+v", getErr, oldCurrent)
	}
	if getErr := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); getErr != nil || nextCurrent.UID != next.UID || nextCurrent.Labels[labelRole] != roleLeader {
		t.Fatalf("low original capacity demoted promoted member: %v %+v", getErr, nextCurrent)
	}
	receipt := m067ReadReceipt(t, ctx, base, old)
	if receipt.Phase != "restore-shadow-claimed" || receipt.DrainAttempts != 1 {
		t.Fatalf("direction-sensitive restoration receipt=%+v", receipt)
	}
	if err := m067SetPodReady(ctx, base, third, true); err != nil {
		t.Fatal(err)
	}
	n := NewNativeActuator(guard)
	n.Reader, n.JournalNamespace, n.RecoveryVLLM = guard, "operator", vllm
	n.RouteObservationTimeout, n.RouteObservationInterval = 50*time.Millisecond, time.Millisecond
	events, recoverErr := n.RecoverOperations(ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Err != nil || !strings.Contains(events[0].Effect, "routing roles restored") {
		t.Fatalf("restored third readiness did not resume exact compensation: events=%+v err=%v", events, recoverErr)
	}
	if vllm.drainCalls != 1 {
		t.Fatalf("availability recovery replayed definitely-unsent drain: calls=%d", vllm.drainCalls)
	}
	if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); err != nil || nextCurrent.Labels[labelRole] != roleShadow {
		t.Fatalf("restored original capacity did not permit exact new demotion: %v %+v", err, nextCurrent)
	}
	var receipts corev1.ConfigMapList
	if err := base.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 0 {
		t.Fatalf("completed availability recovery retained receipt: count=%d err=%v", len(receipts.Items), err)
	}
}

func TestM067DefinitelyUnsentCompensationTreatsPromotedReadinessDirectionally(t *testing.T) {
	for _, tc := range []struct {
		name                string
		dropNext, dropThird bool
		wantFinished        bool
	}{
		{name: "unchanged-ready-positive", wantFinished: true},
		{name: "promoted-not-ready-original-floor-met", dropNext: true, wantFinished: true},
		{name: "promoted-and-third-not-ready-retained", dropNext: true, dropThird: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base, old, next, third := m067ThreeMemberPool(t)
			if err := m067SetPolicyFloor(ctx, base, 2); err != nil {
				t.Fatal(err)
			}
			var mutate func(context.Context, client.WithWatch) error
			if tc.dropNext || tc.dropThird {
				mutate = func(ctx context.Context, inner client.WithWatch) error {
					if tc.dropNext {
						if err := m067SetPodReady(ctx, inner, next, false); err != nil {
							return err
						}
					}
					if tc.dropThird {
						return m067SetPodReady(ctx, inner, third, false)
					}
					return nil
				}
			}
			guard, changed := m067CompensationBoundaryClient(base, old, next, third, mutate)
			vllm := &mockVLLM{loaded: true, drainErr: &definiteServingUnreachableError{cause: errors.New("dial refused")}}
			ec := EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 50 * time.Millisecond, RouteObservationInterval: time.Millisecond}
			result, enactErr := (warmSwapHandler{}).Enact(ctx, ec, boundReq(old, model.ActionWarmSwap))
			if enactErr == nil || result.MutationKind != "swap" || vllm.drainCalls != 1 || *changed != (tc.dropNext || tc.dropThird) {
				t.Fatalf("directional compensation producer not exercised: result=%+v err=%v calls=%d changed=%t", result, enactErr, vllm.drainCalls, *changed)
			}
			oldCurrent, nextCurrent, thirdCurrent := &corev1.Pod{}, &corev1.Pod{}, &corev1.Pod{}
			if err := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); err != nil || oldCurrent.UID != old.UID || oldCurrent.Labels[labelRole] != roleLeader || !podReady(oldCurrent) {
				t.Fatalf("healthy old capacity was not restored first: %v %+v", err, oldCurrent)
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(third), thirdCurrent); err != nil || thirdCurrent.UID != third.UID || thirdCurrent.Labels[labelRole] != roleLeader || podReady(thirdCurrent) == tc.dropThird {
				t.Fatalf("third recorded member changed unexpectedly: %v %+v", err, thirdCurrent)
			}
			if tc.wantFinished {
				if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); err != nil || nextCurrent.UID != next.UID || nextCurrent.Labels[labelRole] != roleShadow || podReady(nextCurrent) == tc.dropNext {
					t.Fatalf("promoted member did not return to exact shadow state: %v %+v", err, nextCurrent)
				}
				m067AssertFakeRouteUIDs(t, ctx, base, old, old, third)
				m067AssertNoFakeReceipt(t, ctx, base)
				return
			}

			if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); err != nil || nextCurrent.UID != next.UID || nextCurrent.Labels[labelRole] != roleLeader || podReady(nextCurrent) {
				t.Fatalf("below-floor compensation reduced the promoted member: %v %+v", err, nextCurrent)
			}
			m067AssertFakeRouteUIDs(t, ctx, base, old, old)
			receipt := m067ReadReceipt(t, ctx, base, old)
			if receipt.Phase != "restore-shadow-claimed" || receipt.DrainAttempts != 1 {
				t.Fatalf("below-floor compensation did not retain the exact obligation: %+v", receipt)
			}
			if err := m067SetPodReady(ctx, base, third, true); err != nil {
				t.Fatal(err)
			}
			if err := m067SyncFakeRoute(ctx, base, old); err != nil {
				t.Fatal(err)
			}
			native := NewNativeActuator(guard)
			native.Reader, native.JournalNamespace, native.RecoveryVLLM = guard, "operator", vllm
			native.RouteObservationTimeout, native.RouteObservationInterval = 50*time.Millisecond, time.Millisecond
			events, recoverErr := native.RecoverOperations(ctx, false)
			if recoverErr != nil || len(events) != 1 || events[0].Err != nil || !strings.Contains(events[0].Effect, "routing roles restored") {
				t.Fatalf("restored original floor did not finish compensation: events=%+v err=%v", events, recoverErr)
			}
			if vllm.drainCalls != 1 {
				t.Fatalf("retained compensation replayed the definitely-unsent drain: calls=%d", vllm.drainCalls)
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); err != nil || nextCurrent.Labels[labelRole] != roleShadow || podReady(nextCurrent) {
				t.Fatalf("recovered compensation did not demote exact inactive promoted UID: %v %+v", err, nextCurrent)
			}
			m067AssertFakeRouteUIDs(t, ctx, base, old, old, third)
			m067AssertNoFakeReceipt(t, ctx, base)
		})
	}
}

func TestM067CompensationReadinessExceptionPreservesHealthAndAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(context.Context, client.WithWatch, *corev1.Pod, *corev1.Pod) error
	}{
		{name: "old-not-ready", mutate: func(ctx context.Context, c client.WithWatch, old, _ *corev1.Pod) error {
			return m067SetPodReady(ctx, c, old, false)
		}},
		{name: "next-uid", mutate: func(ctx context.Context, c client.WithWatch, _, next *corev1.Pod) error {
			if err := m067SetPodReady(ctx, c, next, false); err != nil {
				return err
			}
			current := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(next), current); err != nil {
				return err
			}
			if err := c.Delete(ctx, current); err != nil {
				return err
			}
			replacement := current.DeepCopy()
			replacement.UID, replacement.ResourceVersion = "foreign-next-uid", ""
			return c.Create(ctx, replacement)
		}},
		{name: "next-role", mutate: func(ctx context.Context, c client.WithWatch, _, next *corev1.Pod) error {
			if err := m067SetPodReady(ctx, c, next, false); err != nil {
				return err
			}
			current := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(next), current); err != nil {
				return err
			}
			current.Labels[labelRole] = roleShadow
			return c.Update(ctx, current)
		}},
		{name: "next-profile", mutate: func(ctx context.Context, c client.WithWatch, _, next *corev1.Pod) error {
			if err := m067SetPodReady(ctx, c, next, false); err != nil {
				return err
			}
			current := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(next), current); err != nil {
				return err
			}
			current.Spec.ServiceAccountName = "foreign-profile"
			return c.Update(ctx, current)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base, old, next, third := m067ThreeMemberPool(t)
			if err := m067SetPolicyFloor(ctx, base, 2); err != nil {
				t.Fatal(err)
			}
			guard, changed := m067CompensationBoundaryClient(base, old, next, third, func(ctx context.Context, c client.WithWatch) error {
				return tc.mutate(ctx, c, old, next)
			})
			vllm := &mockVLLM{loaded: true, drainErr: &definiteServingUnreachableError{cause: errors.New("dial refused")}}
			result, enactErr := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 50 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap))
			if enactErr == nil || result.MutationKind != "swap" || !*changed || vllm.drainCalls != 1 {
				t.Fatalf("compensation authority boundary not exercised: result=%+v err=%v changed=%t calls=%d", result, enactErr, *changed, vllm.drainCalls)
			}
			oldCurrent := &corev1.Pod{}
			if err := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); err != nil || oldCurrent.UID != old.UID || oldCurrent.Labels[labelRole] != roleRetiring {
				t.Fatalf("invalid compensation authority restored old route: %v %+v", err, oldCurrent)
			}
			receipt := m067ReadReceipt(t, ctx, base, old)
			if receipt.Phase != "restore-old-claimed" || receipt.DrainAttempts != 1 {
				t.Fatalf("invalid compensation authority changed retained claim: %+v", receipt)
			}
		})
	}
}

func TestM067ConfirmedDrainRechecksUnrelatedRecordedRolesBeforeDelete(t *testing.T) {
	for _, drift := range []bool{false, true} {
		name := "roles-current"
		if drift {
			name = "third-leader-demoted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			base, old, next, third := m067ThreeMemberPool(t)
			modeled := m067ModeledRouteClient(base, old)
			vllm := &changingDrainVLLM{mockVLLM: mockVLLM{loaded: true, drained: 2}}
			if drift {
				vllm.change = func() {
					current := &corev1.Pod{}
					if err := base.Get(ctx, client.ObjectKeyFromObject(third), current); err != nil {
						t.Errorf("get third member: %v", err)
						return
					}
					current.Labels[labelRole] = roleShadow
					if err := base.Update(ctx, current); err != nil {
						t.Errorf("demote third member: %v", err)
					}
				}
			}
			result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: modeled, Reader: modeled, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
			if err == nil || result.MutationKind != "swap" || vllm.drainCalls != 1 {
				t.Fatalf("confirmed drain fixture result=%+v err=%v calls=%d", result, err, vllm.drainCalls)
			}
			oldCurrent, nextCurrent, thirdCurrent := &corev1.Pod{}, &corev1.Pod{}, &corev1.Pod{}
			oldErr := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent)
			if drift && oldErr != nil {
				t.Fatalf("third-member drift deleted confirmed old UID: %v", oldErr)
			}
			if !drift && !apierrors.IsNotFound(oldErr) {
				t.Fatalf("unchanged recorded roles did not permit exact old delete: %v", oldErr)
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); err != nil || nextCurrent.Labels[labelRole] != roleLeader {
				t.Fatalf("confirmed drain changed promoted route: %v %+v", err, nextCurrent)
			}
			wantThirdRole := roleLeader
			if drift {
				wantThirdRole = roleShadow
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(third), thirdCurrent); err != nil || thirdCurrent.Labels[labelRole] != wantThirdRole {
				t.Fatalf("confirmed drain changed unrelated role beyond fixture drift: want=%s err=%v pod=%+v", wantThirdRole, err, thirdCurrent)
			}
			if drift {
				if oldCurrent.Labels[labelRole] != roleRetiring {
					t.Fatalf("third-member drift compensated old route: %+v", oldCurrent)
				}
				cm := &corev1.ConfigMap{}
				key := client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}
				if err := base.Get(ctx, key, cm); err != nil || !strings.Contains(cm.Data["receipt"], `"phase":"drain-confirmed"`) {
					t.Fatalf("third-member drift did not retain durable confirmation: err=%v receipt=%s", err, cm.Data["receipt"])
				}
				n := NewNativeActuator(modeled)
				n.Reader, n.JournalNamespace, n.RecoveryVLLM = modeled, "operator", vllm
				_, _ = n.RecoverOperations(ctx, false)
				if vllm.drainCalls != 1 {
					t.Fatalf("retained confirmation replayed drain: calls=%d", vllm.drainCalls)
				}
			}
		})
	}
}

type m067DrainOutcome struct {
	aborted int
	err     error
}

type m067SequencedDrainVLLM struct {
	mockVLLM
	outcomes []m067DrainOutcome
}

func (m *m067SequencedDrainVLLM) DrainRequests(_ context.Context, _ servingEndpoint) (int, error) {
	m.drainCalls++
	if len(m.outcomes) == 0 {
		return 0, errors.New("unexpected extra drain request")
	}
	outcome := m.outcomes[0]
	m.outcomes = m.outcomes[1:]
	return outcome.aborted, outcome.err
}

func TestM067SecondClaimDistinguishesConfirmedAndUnknownWithoutThirdPost(t *testing.T) {
	for _, tc := range []struct {
		name         string
		second       m067DrainOutcome
		wantPhase    string
		wantOldAlive bool
	}{
		{name: "unsent-then-confirmed", second: m067DrainOutcome{aborted: 2}, wantPhase: "retired-awaiting-controller"},
		{name: "unsent-then-unknown", second: m067DrainOutcome{err: errors.New("response lost after send")}, wantPhase: "drain-dispatching", wantOldAlive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
			base := fakeC(old, next)
			guard, lost := m067PhaseLossClient(base, old, next, "drain-unsent")
			vllm := &m067SequencedDrainVLLM{mockVLLM: mockVLLM{loaded: true}, outcomes: []m067DrainOutcome{{err: &definiteServingUnreachableError{cause: errors.New("dial refused")}}, tc.second}}
			if _, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap)); err == nil || !*lost || vllm.drainCalls != 1 {
				t.Fatalf("first definitely-unsent claim not retained: err=%v lost=%t calls=%d", err, *lost, vllm.drainCalls)
			}
			n := NewNativeActuator(guard)
			n.Reader, n.JournalNamespace, n.RecoveryVLLM = guard, "operator", vllm
			_, _ = n.RecoverOperations(ctx, false)
			if vllm.drainCalls != 2 {
				t.Fatalf("second admitted attempt calls=%d want=2", vllm.drainCalls)
			}
			_, _ = n.RecoverOperations(ctx, false)
			if vllm.drainCalls != 2 {
				t.Fatalf("terminal/unknown second attempt admitted a third POST: calls=%d", vllm.drainCalls)
			}
			cm := &corev1.ConfigMap{}
			key := client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}
			if err := base.Get(ctx, key, cm); err != nil {
				t.Fatal(err)
			}
			var receipt operationReceipt
			if err := json.Unmarshal([]byte(cm.Data["receipt"]), &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.Phase != tc.wantPhase || receipt.DrainAttempts != 2 {
				t.Fatalf("second attempt state=%+v want phase=%s attempts=2", receipt, tc.wantPhase)
			}
			oldErr := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{})
			if tc.wantOldAlive && oldErr != nil {
				t.Fatalf("unknown second attempt removed old UID: %v", oldErr)
			}
			if !tc.wantOldAlive && !apierrors.IsNotFound(oldErr) {
				t.Fatalf("confirmed second attempt did not delete exact old UID: %v", oldErr)
			}
			if tc.wantOldAlive {
				oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
				if err := base.Get(ctx, client.ObjectKeyFromObject(old), oldCurrent); err != nil || oldCurrent.Labels[labelRole] != roleRetiring {
					t.Fatalf("unknown second attempt compensated old route: %v %+v", err, oldCurrent)
				}
				if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextCurrent); err != nil || nextCurrent.Labels[labelRole] != roleLeader {
					t.Fatalf("unknown second attempt compensated promoted route: %v %+v", err, nextCurrent)
				}
			}
		})
	}
}

func TestM067WarmRouteObservationRequiresConsecutiveReads(t *testing.T) {
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "serving", UID: "service-uid", ResourceVersion: "3"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "model", labelRole: roleLeader}}}
	ready := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: service.Namespace, Name: "serving-a", UID: "slice-uid", ResourceVersion: "4", Labels: map[string]string{discoveryv1.LabelServiceName: service.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.9"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: service.Namespace, Name: "old", UID: "old-uid"}}}}
	receipt := operationReceipt{PolicyNamespace: service.Namespace, Pool: &warmPoolIntent{ServiceName: service.Name, ServiceUID: string(service.UID), ServiceSelectorHash: hashWarmObject(service.Spec.Selector)}}
	for _, source := range []string{"service-get", "endpoint-list"} {
		for _, tc := range []struct {
			name      string
			afterGap  bool
			wantError bool
		}{
			{name: "error-breaks-sequence", afterGap: false, wantError: true},
			{name: "two-successes-after-error", afterGap: true},
		} {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				base := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(service.DeepCopy(), slice.DeepCopy()).Build()
				calls := 0
				failRead := func() error {
					calls++
					if calls == 2 || (!tc.afterGap && calls > 3) {
						return errors.New("transient " + source + " failure")
					}
					return nil
				}
				reader := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
					Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if source == "service-get" && key.Namespace == service.Namespace && key.Name == service.Name {
							if err := failRead(); err != nil {
								return err
							}
						}
						return inner.Get(ctx, key, obj, opts...)
					},
					List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if source == "endpoint-list" {
							if _, ok := list.(*discoveryv1.EndpointSliceList); ok {
								if err := failRead(); err != nil {
									return err
								}
							}
						}
						return inner.List(ctx, list, opts...)
					},
				})
				err := waitWarmRouteMembers(context.Background(), EnactCtx{Reader: reader, RouteObservationTimeout: 15 * time.Millisecond, RouteObservationInterval: time.Millisecond}, receipt, []string{"old-uid"})
				if tc.wantError && err == nil {
					t.Fatalf("separated successes were treated as consecutive after %d reads", calls)
				}
				if !tc.wantError && (err != nil || calls < 4) {
					t.Fatalf("two post-error successes did not converge: calls=%d err=%v", calls, err)
				}
			})
		}
	}
}

func m067PhaseLossClient(base client.Client, old, next *corev1.Pod, lostPhase string) (client.Client, *bool) {
	lost := false
	return interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := inner.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			pod, ok := obj.(*corev1.Pod)
			if !ok || (pod.Name != old.Name && pod.Name != next.Name) {
				return nil
			}
			oldNow, nextNow := &corev1.Pod{}, &corev1.Pod{}
			if err := inner.Get(ctx, client.ObjectKeyFromObject(old), oldNow); err != nil {
				return err
			}
			if err := inner.Get(ctx, client.ObjectKeyFromObject(next), nextNow); err != nil {
				return err
			}
			slice := &discoveryv1.EndpointSlice{}
			if err := inner.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: "m066-serving-1"}, slice); err != nil {
				return err
			}
			ready := true
			slice.Endpoints = nil
			for _, current := range []*corev1.Pod{oldNow, nextNow} {
				if current.Labels[labelRole] == roleLeader {
					slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{current.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: current.Namespace, Name: current.Name, UID: current.UID}})
				}
			}
			return inner.Update(ctx, slice)
		},
		Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if pod, ok := obj.(*corev1.Pod); ok {
				if err := inner.Update(ctx, pod, opts...); err != nil {
					return err
				}
				return m067SyncFakeRoute(ctx, inner, old)
			}
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || lost || !strings.Contains(cm.Data["receipt"], `"phase":"`+lostPhase+`"`) {
				return inner.Update(ctx, obj, opts...)
			}
			lost = true
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			return errors.New("persisted phase acknowledgement lost")
		},
	}), &lost
}

func TestM067CompensationPhaseAcknowledgementLossRecoversWithoutExtraSend(t *testing.T) {
	for _, phase := range []string{"drain-unsent", "restore-old-claimed", "old-route-observed", "restore-shadow-claimed", "routing-restored"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
			base := fakeC(old, next)
			guard, lost := m067PhaseLossClient(base, old, next, phase)
			vllm := &mockVLLM{loaded: true, drainErr: &definiteServingUnreachableError{cause: errors.New("dial refused")}}
			result, enactErr := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 50 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap))
			if enactErr == nil || result.MutationKind != "swap" || !*lost {
				t.Fatalf("phase acknowledgement loss not exercised: result=%+v err=%v lost=%t", result, enactErr, *lost)
			}
			cm := &corev1.ConfigMap{}
			key := client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "warm-swap", PolicyUID: "policy-uid", TargetUID: string(old.UID)})}
			if err := base.Get(ctx, key, cm); err != nil || !strings.Contains(cm.Data["receipt"], `"phase":"`+phase+`"`) {
				t.Fatalf("lost acknowledgement did not persist %s: err=%v receipt=%s", phase, err, cm.Data["receipt"])
			}
			n := NewNativeActuator(guard)
			n.Reader, n.JournalNamespace, n.RecoveryVLLM = guard, "operator", vllm
			n.RouteObservationTimeout, n.RouteObservationInterval = 50*time.Millisecond, time.Millisecond
			events, recoverErr := n.RecoverOperations(ctx, false)
			if recoverErr != nil || len(events) != 1 || events[0].Err != nil || !strings.Contains(events[0].Effect, "routing roles restored") {
				t.Fatalf("phase %s did not resume compensation: events=%+v err=%v", phase, events, recoverErr)
			}
			wantCalls := 1
			if phase == "drain-unsent" {
				wantCalls = warmDrainMaxAttempts
			}
			if vllm.drainCalls != wantCalls {
				t.Fatalf("phase %s drain calls=%d want=%d", phase, vllm.drainCalls, wantCalls)
			}
			oldAfter, nextAfter := &corev1.Pod{}, &corev1.Pod{}
			if err := base.Get(ctx, client.ObjectKeyFromObject(old), oldAfter); err != nil || oldAfter.Labels[labelRole] != roleLeader {
				t.Fatalf("phase %s old route not restored: %v %+v", phase, err, oldAfter)
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextAfter); err != nil || nextAfter.Labels[labelRole] != roleShadow {
				t.Fatalf("phase %s new shadow not restored: %v %+v", phase, err, nextAfter)
			}
			if err := base.Get(ctx, key, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
				t.Fatalf("phase %s completed receipt retained: %v", phase, err)
			}
		})
	}
}

func TestM067ConfirmedPhaseAcknowledgementLossRecoversWithoutReplay(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, next)
	guard, lost := m067PhaseLossClient(base, old, next, "drain-confirmed")
	vllm := &mockVLLM{loaded: true, drained: 4}
	result, enactErr := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
	if enactErr == nil || result.MutationKind != "swap" || !*lost || vllm.drainCalls != 1 {
		t.Fatalf("confirmed acknowledgement loss not exercised: result=%+v err=%v lost=%t calls=%d", result, enactErr, *lost, vllm.drainCalls)
	}
	if err := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); err != nil {
		t.Fatalf("process-local 200 deleted old before durable confirmation acknowledgement: %v", err)
	}
	n := NewNativeActuator(guard)
	n.Reader, n.JournalNamespace, n.RecoveryVLLM = guard, "operator", vllm
	events, recoverErr := n.RecoverOperations(ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Effect, "old leader retired") {
		t.Fatalf("durable confirmed phase did not retire without replay: events=%+v err=%v", events, recoverErr)
	}
	if vllm.drainCalls != 1 {
		t.Fatalf("confirmed recovery replayed drain: calls=%d", vllm.drainCalls)
	}
	if err := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("durably confirmed old UID not retired: %v", err)
	}
}

func TestM067PromotionAndRetiringAcknowledgementLossRecoverOnce(t *testing.T) {
	for _, phase := range []string{"promoted", "retiring"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
			base := fakeC(old, next)
			guard, lost := m067PhaseLossClient(base, old, next, phase)
			vllm := &mockVLLM{loaded: true, drained: 1}
			result, enactErr := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
			if enactErr == nil || result.MutationKind != "swap" || !*lost || vllm.drainCalls != 0 {
				t.Fatalf("phase %s acknowledgement loss crossed send boundary: result=%+v err=%v lost=%t calls=%d", phase, result, enactErr, *lost, vllm.drainCalls)
			}
			n := NewNativeActuator(guard)
			n.Reader, n.JournalNamespace, n.RecoveryVLLM = guard, "operator", vllm
			events, recoverErr := n.RecoverOperations(ctx, false)
			if recoverErr != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Effect, "old leader retired") {
				t.Fatalf("phase %s did not continue its one confirmed send: events=%+v err=%v", phase, events, recoverErr)
			}
			if vllm.drainCalls != 1 {
				t.Fatalf("phase %s recovery drain calls=%d want=1", phase, vllm.drainCalls)
			}
			if err := base.Get(ctx, client.ObjectKeyFromObject(old), &corev1.Pod{}); !apierrors.IsNotFound(err) {
				t.Fatalf("phase %s confirmed old UID not retired: %v", phase, err)
			}
		})
	}
}

func TestM067PersistedCreateAcknowledgementLossMutatesNothing(t *testing.T) {
	ctx := context.Background()
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(old, next)
	lost := false
	guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Create: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Labels[journalLabel] == "v1" && !lost {
			lost = true
			if err := inner.Create(ctx, obj, opts...); err != nil {
				return err
			}
			return errors.New("journal create acknowledgement lost")
		}
		return inner.Create(ctx, obj, opts...)
	}})
	vllm := &mockVLLM{loaded: true, drained: 1}
	result, enactErr := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
	if enactErr == nil || result.Emitted || !lost || vllm.drainCalls != 0 {
		t.Fatalf("lost receipt create acknowledgement crossed mutation boundary: result=%+v err=%v lost=%t calls=%d", result, enactErr, lost, vllm.drainCalls)
	}
	oldAfter, nextAfter := &corev1.Pod{}, &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKeyFromObject(old), oldAfter); err != nil || oldAfter.Labels[labelRole] != roleLeader {
		t.Fatalf("old changed after unacknowledged receipt create: %v %+v", err, oldAfter)
	}
	if err := base.Get(ctx, client.ObjectKeyFromObject(next), nextAfter); err != nil || nextAfter.Labels[labelRole] != roleShadow {
		t.Fatalf("shadow changed after unacknowledged receipt create: %v %+v", err, nextAfter)
	}
	n := NewNativeActuator(base)
	n.Reader, n.JournalNamespace, n.RecoveryVLLM = base, "operator", vllm
	events, recoverErr := n.RecoverOperations(ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Err != nil || !strings.Contains(events[0].Effect, "unpromoted") {
		t.Fatalf("persisted prepared receipt did not cleanly recover: events=%+v err=%v", events, recoverErr)
	}
	if vllm.drainCalls != 0 {
		t.Fatalf("prepared receipt recovery sent drain: calls=%d", vllm.drainCalls)
	}
}

func TestM067CompensationAuthorityDriftRetainsWithoutPost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(context.Context, client.Client, *corev1.Pod, *corev1.Pod) error
	}{
		{name: "old-uid", mutate: func(ctx context.Context, c client.Client, old, _ *corev1.Pod) error {
			current := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(old), current); err != nil {
				return err
			}
			if err := c.Delete(ctx, current, uidPrecondition(current)); err != nil {
				return err
			}
			replacement := current.DeepCopy()
			replacement.UID, replacement.ResourceVersion = "foreign-old-uid", ""
			return c.Create(ctx, replacement)
		}},
		{name: "new-role", mutate: func(ctx context.Context, c client.Client, _, next *corev1.Pod) error {
			current := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(next), current); err != nil {
				return err
			}
			current.Labels[labelRole] = roleShadow
			return c.Update(ctx, current)
		}},
		{name: "service-uid", mutate: func(ctx context.Context, c client.Client, old, _ *corev1.Pod) error {
			service := &corev1.Service{}
			key := client.ObjectKey{Namespace: old.Namespace, Name: "m066-serving"}
			if err := c.Get(ctx, key, service); err != nil {
				return err
			}
			if err := c.Delete(ctx, service); err != nil {
				return err
			}
			service.UID, service.ResourceVersion = "foreign-service-uid", ""
			return c.Create(ctx, service)
		}},
		{name: "service-account-profile", mutate: func(ctx context.Context, c client.Client, old, _ *corev1.Pod) error {
			current := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(old), current); err != nil {
				return err
			}
			current.Spec.ServiceAccountName = "foreign-profile"
			return c.Update(ctx, current)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
			base := fakeC(old, next)
			guard, lost := m067PhaseLossClient(base, old, next, "restore-old-claimed")
			vllm := &mockVLLM{loaded: true, drainErr: &definiteServingUnreachableError{cause: errors.New("dial refused")}}
			if _, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: guard, JournalNamespace: "operator", VLLM: vllm, RouteObservationTimeout: 50 * time.Millisecond, RouteObservationInterval: time.Millisecond}, boundReq(old, model.ActionWarmSwap)); err == nil || !*lost {
				t.Fatalf("restoration claim fixture failed: err=%v lost=%t", err, *lost)
			}
			if err := tc.mutate(ctx, base, old, next); err != nil {
				t.Fatal(err)
			}
			n := NewNativeActuator(guard)
			n.Reader, n.JournalNamespace, n.RecoveryVLLM = guard, "operator", vllm
			events, recoverErr := n.RecoverOperations(ctx, false)
			if recoverErr != nil || len(events) != 1 || events[0].Err == nil {
				t.Fatalf("authority drift was not retained: events=%+v err=%v", events, recoverErr)
			}
			if vllm.drainCalls != 1 {
				t.Fatalf("authority drift triggered another POST: calls=%d", vllm.drainCalls)
			}
			var receipts corev1.ConfigMapList
			if err := base.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 1 {
				t.Fatalf("authority drift lost retained obligation: count=%d err=%v", len(receipts.Items), err)
			}
		})
	}
}

func TestOperationJournalWarmFailedPhaseAndRollbackCleanup(t *testing.T) {
	ctx := context.Background()
	t.Run("retire-phase-write-lost", func(t *testing.T) {
		c, n, old, _ := interruptedWarmReceiptFixture(t)
		block := interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if cm, ok := obj.(*corev1.ConfigMap); ok && strings.Contains(cm.Data["receipt"], `"phase":"retired"`) {
				return errors.New("retire phase response lost")
			}
			return inner.Update(ctx, obj, opts...)
		}})
		n.Client = block
		first, err := n.RecoverOperations(ctx, false)
		if err != nil || len(first) != 1 || first[0].Err != nil || first[0].Outcome != "confirmed" {
			t.Fatalf("obsolete retired-phase interceptor affected v2 observation: %+v %v", first, err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
			t.Fatalf("old retirement did not happen: %v", err)
		}
		n.Client = c
		second, err := n.RecoverOperations(ctx, false)
		if err != nil || len(second) != 0 {
			t.Fatalf("completed receipt unexpectedly retried: %+v %v", second, err)
		}
	})
	t.Run("successful-rollback-cleanup-lost", func(t *testing.T) {
		c, n, old, newPod := interruptedWarmReceiptFixture(t)
		shadow := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, shadow); err != nil {
			t.Fatal(err)
		}
		shadow.Labels[labelRole] = roleShadow
		if err := c.Update(ctx, shadow); err != nil {
			t.Fatal(err)
		}
		events, err := n.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Err != nil || !strings.Contains(events[0].Effect, "rolled-back") {
			t.Fatalf("safe rollback cleanup failed: %+v %v", events, err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, &corev1.Pod{}); err != nil {
			t.Fatalf("old serving leader deleted: %v", err)
		}
	})
}

func TestOperationJournalWarmReadDeleteAndStoreFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("producer-store-unavailable-before-promotion", func(t *testing.T) {
		old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
		newPod := aiPod("ns", "new", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
		c := fakeC(old, newPod)
		if _, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: c, Reader: c, VLLM: &mockVLLM{loaded: true}}, boundReq(old, model.ActionWarmSwap)); err == nil {
			t.Fatal("missing administrative store promoted shadow")
		}
		got := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: newPod.Name}, got); err != nil || got.Labels[labelRole] != roleShadow {
			t.Fatalf("missing store changed serving role: %v %+v", err, got.Labels)
		}
	})
	t.Run("journal-list-error-no-retirement", func(t *testing.T) {
		c, n, old, _ := interruptedWarmReceiptFixture(t)
		n.Reader = interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.ConfigMapList); ok {
				return errors.New("journal read forbidden")
			}
			return inner.List(ctx, list, opts...)
		}})
		if events, err := n.RecoverOperations(ctx, false); err == nil || len(events) != 0 {
			t.Fatalf("journal read failure crossed mutation boundary: %+v %v", events, err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, &corev1.Pod{}); err != nil {
			t.Fatalf("old deleted on uncertain journal read: %v", err)
		}
	})
	t.Run("malformed-journal-record-refused", func(t *testing.T) {
		c, n, old, _ := interruptedWarmReceiptFixture(t)
		bad := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "phorvex-operation-invalid", Labels: map[string]string{journalLabel: "v1"}}, Data: map[string]string{"receipt": "not-json"}}
		if err := c.Create(ctx, bad); err != nil {
			t.Fatal(err)
		}
		if events, err := n.RecoverOperations(ctx, false); err == nil || len(events) != 0 {
			t.Fatalf("malformed record caused unsafe batch: %+v %v", events, err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, &corev1.Pod{}); err != nil {
			t.Fatalf("old deleted despite malformed journal: %v", err)
		}
	})
	t.Run("delete-error-reported-and-retryable", func(t *testing.T) {
		c, n, old, _ := interruptedWarmReceiptFixture(t)
		n.Client = interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1.Pod); ok {
				return errors.New("delete denied")
			}
			return inner.Delete(ctx, obj, opts...)
		}})
		first, err := n.RecoverOperations(ctx, false)
		if err != nil || len(first) != 1 || first[0].Err == nil || first[0].Outcome != "partial" {
			t.Fatalf("delete failure swallowed: %+v %v", first, err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: old.Name}, &corev1.Pod{}); err != nil {
			t.Fatalf("old deleted despite denied Delete: %v", err)
		}
		n.Client = c
		second, err := n.RecoverOperations(ctx, false)
		if err != nil || len(second) != 1 || second[0].Err != nil {
			t.Fatalf("safe delete retry failed: %+v %v", second, err)
		}
	})
}

func TestOperationJournalQuarantineProducerGC(t *testing.T) {
	ctx := context.Background()
	pod := aiPod("ns", "victim", map[string]string{"app": "victim"})
	c := qtnClient(pod)
	_, _ = enactQuarantine(t, c, "ns", pod.Name)
	if err := c.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	n := NewNativeActuator(c)
	n.Reader = c
	n.JournalNamespace = "operator"
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err != nil || events[0].Effect != "NP deleted" {
		t.Fatalf("canonical producer GC failed: %+v %v", events, err)
	}
	var np corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "quarantine", PolicyUID: "policy-uid", TargetUID: string(pod.UID)})}, &np); !apierrors.IsNotFound(err) {
		t.Fatalf("receipt not completed: %v", err)
	}
}

func TestOperationJournalQuarantineGCRefusesIdentityAndSpecDrift(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"canonical-uid-replaced", "canonical-spec-drift", "target-name-recreated"} {
		t.Run(mode, func(t *testing.T) {
			pod := aiPod("ns", "victim", map[string]string{"app": "victim"})
			c := qtnClient(pod)
			_, current := enactQuarantine(t, c, "ns", pod.Name)
			canonical := &networkingv1.NetworkPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: quarantinePolicy(pod).Name}, canonical); err != nil {
				t.Fatal(err)
			}
			if err := c.Delete(ctx, current); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "canonical-uid-replaced":
				if err := c.Delete(ctx, canonical); err != nil {
					t.Fatal(err)
				}
				canonical.UID, canonical.ResourceVersion = "foreign-policy-uid", ""
				if err := c.Create(ctx, canonical); err != nil {
					t.Fatal(err)
				}
			case "canonical-spec-drift":
				canonical.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}}
				if err := c.Update(ctx, canonical); err != nil {
					t.Fatal(err)
				}
			case "target-name-recreated":
				recreated := pod.DeepCopy()
				recreated.UID, recreated.ResourceVersion = "replacement-target-uid", ""
				if err := c.Create(ctx, recreated); err != nil {
					t.Fatal(err)
				}
			}
			beforeNP, beforeCM := &networkingv1.NetworkPolicy{}, &corev1.ConfigMap{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(canonical), beforeNP); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "quarantine", PolicyUID: "policy-uid", TargetUID: string(pod.UID)})}, beforeCM); err != nil {
				t.Fatal(err)
			}
			n := NewNativeActuator(c)
			n.Reader, n.JournalNamespace = c, "operator"
			events, err := n.RecoverOperations(ctx, false)
			if err != nil || len(events) != 1 || events[0].Err == nil || events[0].Outcome != "refused" {
				t.Fatalf("GC accepted ambiguous operation scope: %+v %v", events, err)
			}
			afterNP, afterCM := &networkingv1.NetworkPolicy{}, &corev1.ConfigMap{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(beforeNP), afterNP); err != nil || afterNP.UID != beforeNP.UID || afterNP.ResourceVersion != beforeNP.ResourceVersion {
				t.Fatalf("GC changed canonical NP on refusal: %v %+v", err, afterNP)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(beforeCM), afterCM); err != nil || afterCM.ResourceVersion != beforeCM.ResourceVersion {
				t.Fatalf("GC changed receipt on refusal: %v %+v", err, afterCM)
			}
			if mode == "target-name-recreated" {
				replacement := &corev1.Pod{}
				if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: pod.Name}, replacement); err != nil || replacement.UID != "replacement-target-uid" {
					t.Fatalf("GC changed recreated target: %v %+v", err, replacement)
				}
			} else if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: pod.Name}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
				t.Fatalf("GC recreated old target: %v", err)
			}
		})
	}
}

func TestOperationJournalActiveQuarantineReportsRetained(t *testing.T) {
	ctx := context.Background()
	pod := aiPod("ns", "victim", map[string]string{"app": "victim"})
	c := qtnClient(pod)
	_, _ = enactQuarantine(t, c, "ns", pod.Name)
	n := NewNativeActuator(c)
	n.Reader = c
	n.JournalNamespace = "operator"
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err != nil || events[0].Outcome != "retained" || !strings.Contains(events[0].Effect, string(pod.UID)) {
		t.Fatalf("active quarantine overclaimed maintenance: %+v %v", events, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: pod.Name}, &corev1.Pod{}); err != nil {
		t.Fatalf("retained target deleted: %v", err)
	}
}

func TestOperationJournalQuarantineRetryBindsCanonicalReceipt(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"intact", "edited-legacy-fields", "canonical-name-replaced", "missing-canonical-recreated"} {
		t.Run(mode, func(t *testing.T) {
			pod := aiPod("ns", "victim", map[string]string{"app": "victim"})
			c := qtnClient(pod)
			_, current := enactQuarantine(t, c, "ns", pod.Name)
			canonical := &networkingv1.NetworkPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: quarantinePolicy(pod).Name}, canonical); err != nil {
				t.Fatal(err)
			}
			originalUID := canonical.UID
			var legacy *networkingv1.NetworkPolicy
			switch mode {
			case "edited-legacy-fields":
				legacy = quarantinePolicy(pod)
				legacy.Name = "phorvex-quarantine-" + pod.Name
				legacy.UID = "tenant-legacy-uid"
				legacy.OwnerReferences = nil
				if err := c.Create(ctx, legacy); err != nil {
					t.Fatal(err)
				}
				s := m048Snapshot(t, current)
				s.LegacyName, s.LegacyUID = legacy.Name, legacy.UID
				m048PutSnapshot(t, c, current, s)
			case "canonical-name-replaced", "missing-canonical-recreated":
				if err := c.Delete(ctx, canonical); err != nil {
					t.Fatal(err)
				}
				if mode == "canonical-name-replaced" {
					foreign := canonical.DeepCopy()
					foreign.UID, foreign.ResourceVersion = "foreign-canonical-uid", ""
					if err := c.Create(ctx, foreign); err != nil {
						t.Fatal(err)
					}
				}
			}
			res, err := m048Dispatch(c, pod)
			if mode == "canonical-name-replaced" {
				if err == nil || res.Emitted {
					t.Fatalf("foreign canonical policy adopted: %+v %v", res, err)
				}
				got := &networkingv1.NetworkPolicy{}
				if e := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: canonical.Name}, got); e != nil || got.UID != "foreign-canonical-uid" {
					t.Fatalf("foreign policy changed: %v %+v", e, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("authorized retry failed: %+v %v", res, err)
			}
			if mode == "intact" && res.Emitted {
				t.Fatalf("intact retry duplicated mutation: %+v", res)
			}
			if mode == "edited-legacy-fields" {
				got := &networkingv1.NetworkPolicy{}
				if e := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: legacy.Name}, got); e != nil || got.UID != legacy.UID || !strings.Contains(res.Note, "retained") {
					t.Fatalf("mutable legacy fields authorized cleanup: %+v %v %+v", res, e, got)
				}
			}
			if mode == "missing-canonical-recreated" {
				got := &networkingv1.NetworkPolicy{}
				if e := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: canonical.Name}, got); e != nil || got.UID == originalUID || got.UID == "" || !res.Emitted {
					t.Fatalf("missing canonical not recreated with new UID: %+v %v %+v", res, e, got)
				}
				receipt := &corev1.ConfigMap{}
				if e := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: receiptName(operationReceipt{Kind: "quarantine", PolicyUID: "policy-uid", TargetUID: string(pod.UID)})}, receipt); e != nil || !strings.Contains(receipt.Data["receipt"], string(got.UID)) {
					t.Fatalf("new canonical UID not bound administratively: %v %+v", e, receipt)
				}
			}
		})
	}
}

func TestOperationJournalQuarantineAlreadyGCedAndHybridRoute(t *testing.T) {
	ctx := context.Background()
	for _, route := range []string{"native-already-absent", "hybrid-phoenix-refusal"} {
		t.Run(route, func(t *testing.T) {
			pod := aiPod("ns", "victim", map[string]string{"app": "victim"})
			c := qtnClient(pod)
			enactQuarantine(t, c, "ns", pod.Name)
			if err := c.Delete(ctx, pod); err != nil {
				t.Fatal(err)
			}
			np := &networkingv1.NetworkPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: quarantinePolicy(pod).Name}, np); err != nil {
				t.Fatal(err)
			}
			if route == "native-already-absent" {
				if err := c.Delete(ctx, np); err != nil {
					t.Fatal(err)
				}
			}
			var events []RecoveryEvent
			var err error
			if route == "native-already-absent" {
				n := NewNativeActuator(c)
				n.Reader = c
				n.JournalNamespace = "operator"
				events, err = n.RecoverOperations(ctx, false)
			} else {
				h := NewHybridActuator(c)
				h.ConfigureNativeJournal(c, "operator")
				events, err = h.RecoverOperations(ctx, false)
			}
			if err != nil || len(events) != 1 {
				t.Fatalf("route attempt missing: %+v %v", events, err)
			}
			if route == "native-already-absent" {
				if events[0].Err != nil || events[0].Effect != "NP already absent; receipt finished" {
					t.Fatalf("prior GC overclaimed delete: %+v", events[0])
				}
			} else {
				if events[0].Err == nil || events[0].Effect != "" {
					t.Fatalf("Phoenix-routed quarantine entered native GC: %+v", events[0])
				}
				if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: np.Name}, &networkingv1.NetworkPolicy{}); err != nil {
					t.Fatalf("hybrid route deleted NP: %v", err)
				}
			}
		})
	}
}

func TestOperationJournalPreparedQuarantineNoEffectCleanup(t *testing.T) {
	ctx := context.Background()
	pod := aiPod("ns", "victim", map[string]string{"app": "victim"})
	c := qtnClient(pod)
	block := interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{Create: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*networkingv1.NetworkPolicy); ok {
			return errors.New("network policy create blocked")
		}
		return inner.Create(ctx, obj, opts...)
	}})
	req := Request{Namespace: "ns", Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionQuarantine, PolicyName: "policy", PolicyUID: "policy-uid"}
	if _, err := (quarantineHandler{}).Enact(ctx, EnactCtx{Client: block, Reader: c, JournalNamespace: "operator"}, req); err == nil {
		t.Fatal("fixture did not interrupt before NP effect")
	}
	n := NewNativeActuator(c)
	n.Reader = c
	n.JournalNamespace = "operator"
	events, err := n.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Err != nil || !strings.Contains(events[0].Effect, "no quarantine mutation") {
		t.Fatalf("prepared no-effect receipt stranded: %+v %v", events, err)
	}
}

func TestOperationJournalQuarantineRollbackRequarantine(t *testing.T) {
	ctx := context.Background()
	pod := aiPod("ns", "victim", map[string]string{"app": "victim"})
	c := qtnClient(pod)
	result, _ := enactQuarantine(t, c, "ns", pod.Name)
	req := Request{Namespace: "ns", Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionQuarantine, PolicyName: "policy", PolicyUID: "policy-uid"}
	if err := (quarantineHandler{}).Rollback(ctx, EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, req, result.RollbackRef); err != nil {
		t.Fatalf("explicit rollback failed: %v", err)
	}
	enactQuarantine(t, c, "ns", pod.Name)
}

func TestOperationJournalLegacySnapshotWithoutReceiptRefused(t *testing.T) {
	ctx := context.Background()
	c, p, _ := m048Legacy(t)
	name := receiptName(operationReceipt{Kind: "quarantine", PolicyUID: "policy-uid", TargetUID: string(p.UID)})
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: name}, cm); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, cm); err != nil {
		t.Fatal(err)
	}
	before := m048GetPod(t, c, p).DeepCopy()
	result, err := m048Dispatch(c, p)
	if err == nil || result.Emitted {
		t.Fatalf("legacy Pod snapshot minted mutation authority: %+v %v", result, err)
	}
	after := m048GetPod(t, c, p)
	if after.ResourceVersion != before.ResourceVersion || after.Labels[quarantineLabel] != before.Labels[quarantineLabel] {
		t.Fatal("missing receipt refusal mutated target")
	}
}
