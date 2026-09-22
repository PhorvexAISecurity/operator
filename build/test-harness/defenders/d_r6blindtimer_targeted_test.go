package defenders

import (
	"context"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestTargetedBlindTimerDeletesOnlyExactUIDRVWithRequestedGrace(t *testing.T) {
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-0", Namespace: "owned", UID: "11111111-2222-4333-8444-555555555555", ResourceVersion: "91", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "session-rs", UID: "22222222-3333-4444-8555-666666666666", Controller: &controller}}}}
	pdb := exactTargetedTestPDB()
	kube := fake.NewSimpleClientset(pod, pdb)
	deletes := 0
	kube.PrependReactor("update", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updated := action.(k8stesting.UpdateAction).GetObject().(*corev1.Pod)
		updated.ResourceVersion = "92"
		return false, nil, nil
	})
	kube.PrependReactor("delete", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deletes++
		deleteAction := action.(k8stesting.DeleteAction)
		opts := deleteAction.GetDeleteOptions()
		if deleteAction.GetName() != pod.Name || opts.GracePeriodSeconds == nil || *opts.GracePeriodSeconds != 30 || opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != pod.UID || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != "92" {
			t.Fatalf("timer delete was not exact UID/RV/grace: name=%s opts=%+v", deleteAction.GetName(), opts)
		}
		return true, nil, nil
	})
	kube.PrependReactor("update", "poddisruptionbudgets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updated := action.(k8stesting.UpdateAction).GetObject().(*policyv1.PodDisruptionBudget)
		updated.ResourceVersion = "12"
		updated.Generation = 2
		updated.Status = policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 2, ExpectedPods: 2, CurrentHealthy: 2, DesiredHealthy: 1, DisruptionsAllowed: 1}
		return false, nil, nil
	})
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "owned"}, Guard: allowGuard{allow: "owned"}, Log: &nopLogger{}, ScenarioName: "c2-installed-manager-session"}
	oldInterval := targetedBlindRotationInterval
	targetedBlindRotationInterval = time.Millisecond
	t.Cleanup(func() { targetedBlindRotationInterval = oldInterval })
	request := exactTargetedTestRequest(env.ScenarioName, pod)
	request.DeadlineUTC = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
	defender := &blindTimer{}
	result, err := defender.CoordinateTargetedAction(context.Background(), env, request)
	if err != nil || result.Disposition != "dispatched-unconfirmed" || !result.AttributionComplete || result.ActionAtUTC == "" || result.AvailabilityPolicyResourceVersion != "12" || deletes != 1 {
		t.Fatalf("exact timer result=%+v deletes=%d err=%v", result, deletes, err)
	}
	updated, err := kube.CoreV1().Pods("owned").Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil || updated.UID != pod.UID || updated.ResourceVersion != "92" || updated.Labels[RotationTargetLabel] != "true" {
		t.Fatalf("target label identity not retained before exact delete: pod=%+v err=%v", updated, err)
	}
	count, _, err := defender.DefensiveActions(context.Background(), env)
	if err != nil || count != 1 {
		t.Fatalf("exact timer action not observed: count=%d err=%v", count, err)
	}
}

func TestTargetedBlindTimerRefusesChangedIdentityBeforeDelete(t *testing.T) {
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-0", Namespace: "owned", UID: "11111111-2222-4333-8444-555555555555", ResourceVersion: "91", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "session-rs", UID: "22222222-3333-4444-8555-666666666666", Controller: &controller}}}}
	kube := fake.NewSimpleClientset(pod)
	deletes := 0
	kube.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		deletes++
		return true, nil, nil
	})
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "owned"}, Guard: allowGuard{allow: "owned"}, Log: &nopLogger{}, ScenarioName: "c2-installed-manager-session"}
	request := exactTargetedTestRequest(env.ScenarioName, pod)
	request.TargetUID = string(types.UID("99999999-9999-4999-8999-999999999999"))
	request.DeadlineUTC = time.Now().Add(BlindRotationInterval + time.Second).UTC().Format(time.RFC3339Nano)
	result, err := (&blindTimer{}).CoordinateTargetedAction(context.Background(), env, request)
	if err == nil || result.Disposition != "refused" || result.AttributionComplete || deletes != 0 {
		t.Fatalf("changed target identity not refused before delete: result=%+v deletes=%d err=%v", result, deletes, err)
	}
}

func exactTargetedTestPDB() *policyv1.PodDisruptionBudget {
	minimum := intstr.FromInt(2)
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "owned", UID: "33333333-4444-4555-8666-777777777777", ResourceVersion: "11", Generation: 1},
		Spec:       policyv1.PodDisruptionBudgetSpec{MinAvailable: &minimum, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "session"}}},
		Status:     policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 1, ExpectedPods: 2, CurrentHealthy: 2, DesiredHealthy: 2, DisruptionsAllowed: 0},
	}
}

func exactTargetedTestRequest(scenario string, pod *corev1.Pod) core.TargetedActionRequest {
	return core.TargetedActionRequest{
		Objective: scenario, Namespace: "owned", TargetKind: "Pod", TargetName: pod.Name, TargetUID: string(pod.UID), TargetResourceVersion: pod.ResourceVersion,
		OwnerKind: "ReplicaSet", OwnerName: "session-rs", OwnerUID: "22222222-3333-4444-8555-666666666666", TargetLabelKey: RotationTargetLabel, TargetLabelValue: "true", RequestedGraceSeconds: 30,
		AvailabilityPolicyName: "session", AvailabilityPolicyUID: "33333333-4444-4555-8666-777777777777", AvailabilityPolicyResourceVersion: "11", AvailabilitySelectorKey: "app", AvailabilitySelectorValue: "session", InitialMinAvailable: 2, EligibleMinAvailable: 1,
	}
}

func TestTargetedBlindTimerRefusesDriftedAvailabilityFloorBeforeDelete(t *testing.T) {
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-0", Namespace: "owned", UID: "11111111-2222-4333-8444-555555555555", ResourceVersion: "91", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "session-rs", UID: "22222222-3333-4444-8555-666666666666", Controller: &controller}}}}
	pdb := exactTargetedTestPDB()
	pdb.Status.CurrentHealthy = 1
	kube := fake.NewSimpleClientset(pod, pdb)
	deletes := 0
	kube.PrependReactor("update", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updated := action.(k8stesting.UpdateAction).GetObject().(*corev1.Pod)
		updated.ResourceVersion = "92"
		return false, nil, nil
	})
	kube.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		deletes++
		return true, nil, nil
	})
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "owned"}, Guard: allowGuard{allow: "owned"}, Log: &nopLogger{}, ScenarioName: "c2-installed-manager-session"}
	request := exactTargetedTestRequest(env.ScenarioName, pod)
	request.DeadlineUTC = time.Now().Add(BlindRotationInterval + time.Second).UTC().Format(time.RFC3339Nano)
	result, err := (&blindTimer{}).CoordinateTargetedAction(context.Background(), env, request)
	if err == nil || result.Disposition != "refused" || result.AttributionComplete || deletes != 0 {
		t.Fatalf("drifted PDB was not refused before delete: result=%+v deletes=%d err=%v", result, deletes, err)
	}
}

func TestTargetAvailabilityTransitionRefusesIdentitySelectorAndStatusDrift(t *testing.T) {
	base := exactTargetedTestPDB()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-0", Namespace: "owned", UID: "11111111-2222-4333-8444-555555555555", ResourceVersion: "91"}}
	request := exactTargetedTestRequest("c2-installed-manager-session", pod)
	for name, mutate := range map[string]func(*policyv1.PodDisruptionBudget){
		"uid":      func(pdb *policyv1.PodDisruptionBudget) { pdb.UID = "99999999-9999-4999-8999-999999999999" },
		"rv":       func(pdb *policyv1.PodDisruptionBudget) { pdb.ResourceVersion = "changed" },
		"selector": func(pdb *policyv1.PodDisruptionBudget) { pdb.Spec.Selector.MatchLabels["app"] = "foreign" },
		"floor": func(pdb *policyv1.PodDisruptionBudget) {
			minimum := intstr.FromInt(1)
			pdb.Spec.MinAvailable = &minimum
		},
		"health": func(pdb *policyv1.PodDisruptionBudget) { pdb.Status.CurrentHealthy = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			pdb := base.DeepCopy()
			mutate(pdb)
			kube := fake.NewSimpleClientset(pdb)
			updates := 0
			kube.PrependReactor("update", "poddisruptionbudgets", func(k8stesting.Action) (bool, runtime.Object, error) {
				updates++
				return true, nil, nil
			})
			env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "owned"}, Guard: allowGuard{allow: "owned"}, Log: &nopLogger{}}
			if got, err := transitionTargetAvailabilityGuard(context.Background(), env, request); err == nil || got != "" || updates != 0 {
				t.Fatalf("drifted availability state reached mutation: rv=%q updates=%d err=%v", got, updates, err)
			}
		})
	}
}
