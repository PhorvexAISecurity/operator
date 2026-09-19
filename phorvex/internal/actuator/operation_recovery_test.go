package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
			return c.Update(ctx, obj, opts...)
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
	applied := false
	guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, inner client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
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
	res, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: &mockVLLM{loaded: true, drainErr: errors.New("drain failed")}}, boundReq(old, model.ActionWarmSwap))
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
		name := truncName(promoted.Name + "-rw-" + promoted.ResourceVersion)
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
	deletes := 0
	guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
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
		if receipt.Phase != "drain-confirmed" || receipt.Aborted != 3 || receipt.DrainAttempts != 1 {
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
	lost := false
	guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
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
			claimed, deletes := false, 0
			guard := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
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
	third := aiPod("ns", "third", map[string]string{"app": "m066-pool", labelSwapGroup: "g", labelRole: roleLeader, labelModelLoaded: "true"})
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
	ready := true
	slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{third.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: third.Namespace, Name: third.Name, UID: third.UID}})
	if err := base.Update(ctx, slice); err != nil {
		t.Fatal(err)
	}
	return base, old, next, third
}

func TestM067ConfirmedDrainRechecksUnrelatedRecordedRolesBeforeDelete(t *testing.T) {
	for _, drift := range []bool{false, true} {
		name := "roles-current"
		if drift {
			name = "third-leader-demoted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			base, old, _, third := m067ThreeMemberPool(t)
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
			result, err := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: base, Reader: base, JournalNamespace: "operator", VLLM: vllm}, boundReq(old, model.ActionWarmSwap))
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
				n := NewNativeActuator(base)
				n.Reader, n.JournalNamespace, n.RecoveryVLLM = base, "operator", vllm
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
