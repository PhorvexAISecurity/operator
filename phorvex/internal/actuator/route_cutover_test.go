package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type routeUnitClient struct {
	client.Client
	serviceUpdates     int
	podPatches         int
	failPodPatchAt     int
	lostPodAckAt       int
	lostServiceAckAt   int
	failServiceAt      int
	configMapCreates   int
	configMapUpdates   int
	configMapDeletes   int
	lostCreateAckAt    int
	lostJournalAckAt   int
	lostDeleteAckAt    int
	failJournalAt      int
	replacePodAt       int
	replaceServiceAt   int
	replacementUID     types.UID
	membershipHistory  []int
	afterPodPatch      func(context.Context, *routeUnitClient, *corev1.Pod)
	afterServiceUpdate func(context.Context, *routeUnitClient, *corev1.Service)
}

func (c *routeUnitClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		c.configMapCreates++
	}
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	if _, ok := obj.(*corev1.ConfigMap); ok && c.lostCreateAckAt == c.configMapCreates {
		return errors.New("injected accepted ConfigMap create with lost acknowledgement")
	}
	return nil
}

func (c *routeUnitClient) reconcile(ctx context.Context, namespace, service string) error {
	svc := &corev1.Service{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: service}, svc); err != nil {
		return err
	}
	var pods corev1.PodList
	if err := c.Client.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return err
	}
	endpoints := []discoveryv1.Endpoint{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !routeReady(pod) || !selectorMatchesPod(svc.Spec.Selector, pod.Labels) {
			continue
		}
		ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: namespace, Name: pod.Name, UID: pod.UID}
		ready := true
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{pod.Status.PodIP}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
	}
	slice := &discoveryv1.EndpointSlice{}
	key := client.ObjectKey{Namespace: namespace, Name: service + "-slice"}
	if err := c.Client.Get(ctx, key, slice); err != nil {
		return err
	}
	slice.Endpoints = endpoints
	c.membershipHistory = append(c.membershipHistory, len(endpoints))
	return c.Client.Update(ctx, slice)
}

func (c *routeUnitClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if _, ok := obj.(*corev1.Pod); ok {
		c.podPatches++
		if c.failPodPatchAt == c.podPatches {
			return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, obj.GetName(), errors.New("injected Pod patch refusal"))
		}
		if c.replacePodAt == c.podPatches {
			stored := &corev1.Pod{}
			if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
				return err
			}
			if err := c.Client.Delete(ctx, stored); err != nil {
				return err
			}
			replacement := stored.DeepCopy()
			replacement.UID, replacement.ResourceVersion = "", ""
			replacement.CreationTimestamp = metav1.Time{}
			if err := c.Client.Create(ctx, replacement); err != nil {
				return err
			}
			c.replacementUID = replacement.UID
		}
	}
	if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	if pod, ok := obj.(*corev1.Pod); ok {
		if err := c.reconcile(ctx, pod.Namespace, pod.Annotations[annoRouteService]); err != nil {
			return err
		}
		if c.afterPodPatch != nil {
			c.afterPodPatch(ctx, c, pod)
		}
		if c.lostPodAckAt == c.podPatches {
			return errors.New("injected accepted Pod patch with lost acknowledgement")
		}
	}
	return nil
}

func (c *routeUnitClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if svc, ok := obj.(*corev1.Service); ok {
		c.serviceUpdates++
		if c.failServiceAt == c.serviceUpdates {
			return apierrors.NewConflict(schema.GroupResource{Resource: "services"}, obj.GetName(), errors.New("injected Service update refusal"))
		}
		if c.replaceServiceAt == c.serviceUpdates {
			stored := &corev1.Service{}
			if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
				return err
			}
			if err := c.Client.Delete(ctx, stored); err != nil {
				return err
			}
			replacement := stored.DeepCopy()
			replacement.UID, replacement.ResourceVersion = "", ""
			replacement.CreationTimestamp = metav1.Time{}
			if err := c.Client.Create(ctx, replacement); err != nil {
				return err
			}
			c.replacementUID = replacement.UID
		}
		if err := c.Client.Update(ctx, obj, opts...); err != nil {
			return err
		}
		if err := c.reconcile(ctx, svc.Namespace, svc.Name); err != nil {
			return err
		}
		if c.afterServiceUpdate != nil {
			c.afterServiceUpdate(ctx, c, svc)
		}
		if c.lostServiceAckAt == c.serviceUpdates {
			return errors.New("injected accepted Service update with lost acknowledgement")
		}
		return nil
	}
	if _, ok := obj.(*corev1.ConfigMap); ok {
		c.configMapUpdates++
		if c.failJournalAt == c.configMapUpdates {
			return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, obj.GetName(), errors.New("injected journal phase conflict"))
		}
		if err := c.Client.Update(ctx, obj, opts...); err != nil {
			return err
		}
		if c.lostJournalAckAt == c.configMapUpdates {
			return errors.New("injected accepted ConfigMap update with lost acknowledgement")
		}
		return nil
	}
	return c.Client.Update(ctx, obj, opts...)
}

func (c *routeUnitClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		c.configMapDeletes++
	}
	if err := c.Client.Delete(ctx, obj, opts...); err != nil {
		return err
	}
	if _, ok := obj.(*corev1.ConfigMap); ok && c.lostDeleteAckAt == c.configMapDeletes {
		return errors.New("injected accepted ConfigMap delete with lost acknowledgement")
	}
	return nil
}

type routeUnitFixture struct {
	ctx       context.Context
	client    *routeUnitClient
	native    *NativeActuator
	policy    *v1alpha1.PhorvexPolicy
	pod       *corev1.Pod
	sibling   *corev1.Pod
	service   *corev1.Service
	request   Request
	originalP map[string]string
	originalS map[string]string
}

func newRouteUnitFixture(t *testing.T, action model.Action, floor int) routeUnitFixture {
	t.Helper()
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-unit", UID: "uid-route-unit"}}
	op := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-operator", UID: "uid-route-operator"}}
	pod := aiPod(ns.Name, "target", map[string]string{"app": "route", labelRouteKey: "old", "foreign": "keep", "foreign-selector": "keep"})
	pod.Status.PodIP = "10.0.0.10"
	pod.Annotations[annoRouteService] = "route"
	pod.Annotations["foreign"] = "keep"
	sibling := aiPod(ns.Name, "sibling", map[string]string{"app": "route", labelRouteKey: "old", "foreign-selector": "keep"})
	sibling.Status.PodIP = "10.0.0.11"
	sibling.Annotations[annoRouteService] = "route"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "route", UID: "uid-route-service", ResourceVersion: "5"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "route", labelRouteKey: "old", "foreign-selector": "keep"}}}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy", UID: "uid-route-policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "route"}}, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: floor}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(action)}}}}
	refs := []discoveryv1.Endpoint{}
	for _, p := range []*corev1.Pod{pod, sibling} {
		ready := true
		ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: p.Name, UID: p.UID}
		refs = append(refs, discoveryv1.Endpoint{Addresses: []string{p.Status.PodIP}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
	}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "route-slice", UID: "uid-route-slice", ResourceVersion: "6", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: refs}
	base := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(ns, op, pod, sibling, svc, pol, slice).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if obj.GetUID() == "" {
			obj.SetUID(types.UID("created-" + obj.GetName()))
		}
		return c.Create(ctx, obj, opts...)
	}}).Build()
	writer := &routeUnitClient{Client: base}
	native := &NativeActuator{Client: writer, Reader: writer, JournalNamespace: op.Name, RouteObservationTimeout: 100 * time.Millisecond, RouteObservationInterval: time.Millisecond}
	req := Request{Namespace: ns.Name, Pod: pod.Name, TargetUID: string(pod.UID), Action: action, PolicyName: pol.Name, PolicyUID: string(pol.UID), OperationID: strings.Repeat("a", 40)}
	return routeUnitFixture{ctx: ctx, client: writer, native: native, policy: pol, pod: pod, sibling: sibling, service: svc, request: req, originalP: copyLabels(pod.Labels), originalS: copyLabels(svc.Spec.Selector)}
}

func TestRouteCutoverSharedEngineCompletesAndRollbackRestoresOwnedFields(t *testing.T) {
	for _, action := range []model.Action{model.ActionRouteRotate, model.ActionEndpointRotate} {
		t.Run(string(action), func(t *testing.T) {
			f := newRouteUnitFixture(t, action, 1)
			result, err := f.native.Actuate(f.ctx, f.request)
			if err != nil || !result.Emitted || result.MutationKind != "reversible" || result.RollbackRef == "" {
				t.Fatalf("cutover result=%+v err=%v", result, err)
			}
			gotPod, gotSvc := &corev1.Pod{}, &corev1.Service{}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), gotPod); err != nil {
				t.Fatal(err)
			}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), gotSvc); err != nil {
				t.Fatal(err)
			}
			if gotPod.Labels[labelRouteKey] == "old" || gotSvc.Spec.Selector[labelRouteKey] != gotPod.Labels[labelRouteKey] || gotPod.Labels[routeBridgeLabel] != "" || gotPod.Labels["foreign"] != "keep" || gotPod.Annotations["foreign"] != "keep" || gotSvc.Spec.Selector["foreign-selector"] != "keep" {
				t.Fatalf("final owned/unrelated state Pod=%v/%v Service=%v", gotPod.Labels, gotPod.Annotations, gotSvc.Spec.Selector)
			}
			repeated, err := f.native.Actuate(f.ctx, f.request)
			if err != nil || repeated.Emitted || repeated.NoEffect != NoEffectReconciled || repeated.MutationKind != "none" ||
				repeated.RollbackRef != result.RollbackRef || len(repeated.ObjectsTouched) != 3 || !strings.Contains(repeated.Note, "already applied") {
				t.Fatalf("same operation retried result=%+v err=%v", repeated, err)
			}
			if err := f.native.Rollback(f.ctx, f.request, result.RollbackRef); err != nil {
				t.Fatalf("rollback: %v", err)
			}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), gotPod); err != nil {
				t.Fatal(err)
			}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), gotSvc); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotPod.Labels, f.originalP) || !reflect.DeepEqual(gotSvc.Spec.Selector, f.originalS) || gotPod.Annotations["foreign"] != "keep" {
				t.Fatalf("rollback clobbered or missed fields Pod=%v Service=%v", gotPod.Labels, gotSvc.Spec.Selector)
			}
		})
	}
}

func TestRouteCutoverFloorTwoRefusesBeforeProtectedOrTenantWrites(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 2)
	result, err := f.native.Actuate(f.ctx, f.request)
	if !IsNoEffectRefusal(err) || result.Emitted || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
		t.Fatalf("floor2 result=%+v err=%v patches=%d updates=%d", result, err, f.client.podPatches, f.client.serviceUpdates)
	}
	var journals corev1.ConfigMapList
	if err := f.client.List(f.ctx, &journals, client.InNamespace("route-operator")); err != nil || len(journals.Items) != 0 {
		t.Fatalf("floor2 created protected state: %v err=%v", journals.Items, err)
	}
}

func TestRouteCutoverPolicyDisableAfterPartialRestoresThroughRecovery(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
	f.client.failPodPatchAt = 2
	result, err := f.native.Actuate(f.ctx, f.request)
	if err == nil || !result.Emitted || result.MutationKind != "partial" {
		t.Fatalf("partial result=%+v err=%v", result, err)
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.policy), pol); err != nil {
		t.Fatal(err)
	}
	pol.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionRotate}
	if err := f.client.Update(f.ctx, pol); err != nil {
		t.Fatal(err)
	}
	f.client.failPodPatchAt = 0
	events, recoverErr := f.native.RecoverOperations(f.ctx, false)
	if recoverErr != nil {
		t.Fatalf("recovery: %v events=%+v", recoverErr, events)
	}
	gotPod, gotSvc := &corev1.Pod{}, &corev1.Service{}
	_ = f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), gotPod)
	_ = f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), gotSvc)
	if !reflect.DeepEqual(gotPod.Labels, f.originalP) || !reflect.DeepEqual(gotSvc.Spec.Selector, f.originalS) {
		t.Fatalf("disabled-policy compensation failed Pod=%v Service=%v events=%+v", gotPod.Labels, gotSvc.Spec.Selector, events)
	}
}

func TestRouteCutoverPolicyDeletionAfterPartialRestoresThroughRecovery(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	f.client.failPodPatchAt = 2
	result, err := f.native.Actuate(f.ctx, f.request)
	if err == nil || !result.Emitted || result.MutationKind != "partial" {
		t.Fatalf("partial result=%+v err=%v", result, err)
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.policy), policy); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(f.ctx, policy); err != nil {
		t.Fatal(err)
	}
	f.client.failPodPatchAt = 0
	events, recoverErr := f.native.RecoverOperations(f.ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("deleted-policy recovery events=%+v err=%v", events, recoverErr)
	}
	pod, svc := &corev1.Pod{}, &corev1.Service{}
	_ = f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod)
	_ = f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc)
	if !reflect.DeepEqual(pod.Labels, f.originalP) || !reflect.DeepEqual(svc.Spec.Selector, f.originalS) {
		t.Fatalf("deleted-policy compensation failed Pod=%v Service=%v", pod.Labels, svc.Spec.Selector)
	}
}

func TestRouteCutoverAcceptedLostAcknowledgementsUseAuthoritativeState(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*routeUnitClient)
	}{
		{name: "first-pod-patch", configure: func(c *routeUnitClient) { c.lostPodAckAt = 1 }},
		{name: "bridge-service-update", configure: func(c *routeUnitClient) { c.lostServiceAckAt = 1 }},
		{name: "final-service-update", configure: func(c *routeUnitClient) { c.lostServiceAckAt = 2 }},
		{name: "bridge-cleanup-pod-patch", configure: func(c *routeUnitClient) { c.lostPodAckAt = 3 }},
		{name: "target-guard-create", configure: func(c *routeUnitClient) { c.lostCreateAckAt = 1 }},
		{name: "service-receipt-create", configure: func(c *routeUnitClient) { c.lostCreateAckAt = 2 }},
		{name: "guard-binding", configure: func(c *routeUnitClient) { c.lostJournalAckAt = 1 }},
		{name: "first-journal-advance", configure: func(c *routeUnitClient) { c.lostJournalAckAt = 2 }},
		{name: "guard-delete", configure: func(c *routeUnitClient) { c.lostDeleteAckAt = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
			tc.configure(f.client)
			result, err := f.native.Actuate(f.ctx, f.request)
			if err != nil || !result.Emitted || result.MutationKind != "reversible" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestRouteCutoverRestartDerivesEveryForwardPhaseFromOwnedState(t *testing.T) {
	for journalUpdate := 2; journalUpdate <= 6; journalUpdate++ {
		t.Run(fmt.Sprintf("journal-update-%d", journalUpdate), func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
			f.client.failJournalAt = journalUpdate
			result, err := f.native.Actuate(f.ctx, f.request)
			if err == nil || !result.Emitted || result.MutationKind != "partial" {
				t.Fatalf("interrupted result=%+v err=%v", result, err)
			}
			restarted := &NativeActuator{Client: f.client, Reader: f.client, JournalNamespace: "route-operator"}
			events, recoverErr := restarted.RecoverOperations(f.ctx, false)
			if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" || events[0].Err != nil {
				t.Fatalf("recovery events=%+v err=%v", events, recoverErr)
			}
			pod, svc := &corev1.Pod{}, &corev1.Service{}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil {
				t.Fatal(err)
			}
			if pod.Labels[labelRouteKey] == "old" || svc.Spec.Selector[labelRouteKey] != pod.Labels[labelRouteKey] || pod.Labels[routeBridgeLabel] != "" {
				t.Fatalf("recovery did not derive terminal state: Pod=%v Service=%v", pod.Labels, svc.Spec.Selector)
			}
		})
	}
}

func TestRouteCutoverSameIDEnactResumesEveryForwardPhase(t *testing.T) {
	for journalUpdate := 2; journalUpdate <= 6; journalUpdate++ {
		t.Run(fmt.Sprintf("journal-update-%d", journalUpdate), func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
			f.client.failJournalAt = journalUpdate
			partial, err := f.native.Actuate(f.ctx, f.request)
			if err == nil || !partial.Emitted || partial.MutationKind != "partial" {
				t.Fatalf("interrupted result=%+v err=%v", partial, err)
			}
			resumed, resumeErr := f.native.Actuate(f.ctx, f.request)
			if resumeErr != nil || !resumed.Emitted || resumed.MutationKind != "reversible" || resumed.RollbackRef == "" {
				t.Fatalf("same-ID resume result=%+v err=%v", resumed, resumeErr)
			}
			terminal, terminalErr := f.native.Actuate(f.ctx, f.request)
			if terminalErr != nil || terminal.Emitted || !strings.Contains(terminal.Note, "already applied") {
				t.Fatalf("terminal same-ID result=%+v err=%v", terminal, terminalErr)
			}
		})
	}
}

func TestRouteCutoverPreparedRecoveryCleansLocksWithoutClaimingTenantEffect(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	f.client.failPodPatchAt = 1
	result, err := f.native.Actuate(f.ctx, f.request)
	if err == nil || result.Emitted || result.MutationKind != "partial" || f.client.podPatches != 1 || f.client.serviceUpdates != 0 {
		t.Fatalf("rejected first write result=%+v err=%v patches=%d updates=%d", result, err, f.client.podPatches, f.client.serviceUpdates)
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.policy), pol); err != nil {
		t.Fatal(err)
	}
	pol.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionRotate}
	if err := f.client.Update(f.ctx, pol); err != nil {
		t.Fatal(err)
	}
	f.client.failPodPatchAt = 0
	events, recoverErr := f.native.RecoverOperations(f.ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" || events[0].Err != nil {
		t.Fatalf("prepared recovery events=%+v err=%v", events, recoverErr)
	}
	if f.client.podPatches != 1 || f.client.serviceUpdates != 0 {
		t.Fatalf("prepared recovery mutated tenant objects: patches=%d updates=%d", f.client.podPatches, f.client.serviceUpdates)
	}
	var protected corev1.ConfigMapList
	if err := f.client.List(f.ctx, &protected, client.InNamespace("route-operator")); err != nil || len(protected.Items) != 0 {
		t.Fatalf("prepared recovery retained protected state=%v err=%v", protected.Items, err)
	}
}

func TestRouteCutoverAcceptedFirstPatchLostPhaseThenUnreadyRestoresOwnedBridge(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
	// ConfigMap update one binds the target guard to the Service receipt. Update
	// two is the first phase advance, after the bridge Pod patch was accepted.
	f.client.failJournalAt = 2
	result, err := f.native.Actuate(f.ctx, f.request)
	if err == nil || !result.Emitted || result.MutationKind != "partial" {
		t.Fatalf("lost phase result=%+v err=%v", result, err)
	}
	pod := &corev1.Pod{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	if pod.Labels[routeBridgeLabel] == "" {
		t.Fatal("accepted first tenant patch was not present")
	}
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == corev1.PodReady {
			pod.Status.Conditions[i].Status = corev1.ConditionFalse
		}
	}
	if err := f.client.Client.Status().Update(f.ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := f.client.reconcile(f.ctx, f.service.Namespace, f.service.Name); err != nil {
		t.Fatal(err)
	}
	var protectedBefore corev1.ConfigMapList
	if err := f.client.List(f.ctx, &protectedBefore, client.InNamespace("route-operator")); err != nil {
		t.Fatal(err)
	}
	var recorded operationReceipt
	for i := range protectedBefore.Items {
		if protectedBefore.Items[i].Labels[journalLabel] == "v1" {
			var err error
			recorded, err = readRouteReceipt(&protectedBefore.Items[i])
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if recorded.BeforePodRoute != ownedValue(f.originalP, labelRouteKey) || !routePodState(pod, recorded, recorded.BeforePodRoute, recorded.BeforePodEpoch, routeAppliedValue(recorded.BridgeValue)) {
		t.Fatalf("accepted first patch was not bound to the original Pod state: receipt=%+v Pod=%v/%v", recorded, pod.Labels, pod.Annotations)
	}
	events, recoverErr := f.native.RecoverOperations(f.ctx, false)
	if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("unready recovery events=%+v err=%v", events, recoverErr)
	}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pod.Labels, f.originalP) || pod.Labels[routeBridgeLabel] != "" {
		t.Fatalf("prepared receipt compensation failed: labels=%v original=%v events=%+v", pod.Labels, f.originalP, events)
	}
	var protected corev1.ConfigMapList
	if err := f.client.List(f.ctx, &protected, client.InNamespace("route-operator")); err != nil || len(protected.Items) != 0 {
		t.Fatalf("successful compensation retained records=%v err=%v", protected.Items, err)
	}
}

func TestRouteCutoverUnavailableTargetRetainsImpossibleMixedOwnedState(t *testing.T) {
	for _, mutate := range []string{"Pod", "Service"} {
		t.Run(mutate, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
			result, err := f.native.Actuate(f.ctx, f.request)
			if err != nil || !result.Emitted {
				t.Fatalf("initial cutover result=%+v err=%v", result, err)
			}
			pod := &corev1.Pod{}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			for i := range pod.Status.Conditions {
				if pod.Status.Conditions[i].Type == corev1.PodReady {
					pod.Status.Conditions[i].Status = corev1.ConditionFalse
				}
			}
			if err := f.client.Client.Status().Update(f.ctx, pod); err != nil {
				t.Fatal(err)
			}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			var mixedPodLabels, mixedPodAnnotations map[string]string
			var mixedServiceSelector map[string]string
			switch mutate {
			case "Pod":
				pod.Annotations = copyLabels(pod.Annotations)
				delete(pod.Annotations, routeEpochKey(model.ActionRouteRotate))
				if err := f.client.Client.Update(f.ctx, pod); err != nil {
					t.Fatal(err)
				}
				mixedPodLabels, mixedPodAnnotations = copyLabels(pod.Labels), copyLabels(pod.Annotations)
			case "Service":
				svc := &corev1.Service{}
				if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil {
					t.Fatal(err)
				}
				var protected corev1.ConfigMapList
				if err := f.client.List(f.ctx, &protected, client.InNamespace("route-operator")); err != nil {
					t.Fatal(err)
				}
				foundReceipt := false
				for i := range protected.Items {
					if protected.Items[i].Labels[journalLabel] != "v1" {
						continue
					}
					recorded, readErr := readRouteReceipt(&protected.Items[i])
					if readErr != nil {
						t.Fatal(readErr)
					}
					svc.Spec.Selector = copyLabels(svc.Spec.Selector)
					svc.Spec.Selector[routeBridgeLabel] = recorded.BridgeValue
					foundReceipt = true
				}
				if !foundReceipt {
					t.Fatal("terminal route receipt missing")
				}
				if err := f.client.Client.Update(f.ctx, svc); err != nil {
					t.Fatal(err)
				}
				mixedServiceSelector = copyLabels(svc.Spec.Selector)
			}

			events, recoverErr := f.native.RecoverOperations(f.ctx, false)
			if recoverErr == nil || len(events) == 0 {
				t.Fatalf("impossible mixed %s state was accepted: events=%+v err=%v", mutate, events, recoverErr)
			}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			if mutate == "Pod" && (!reflect.DeepEqual(pod.Labels, mixedPodLabels) || !reflect.DeepEqual(pod.Annotations, mixedPodAnnotations)) {
				t.Fatalf("mixed Pod owned fields were overwritten: labels=%v annotations=%v", pod.Labels, pod.Annotations)
			}
			if mutate == "Service" {
				svc := &corev1.Service{}
				if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(svc.Spec.Selector, mixedServiceSelector) {
					t.Fatalf("mixed Service owned fields were overwritten: %v", svc.Spec.Selector)
				}
			}
			var retained corev1.ConfigMapList
			if err := f.client.List(f.ctx, &retained, client.InNamespace("route-operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(retained.Items) != 1 {
				t.Fatalf("unresolved receipt count=%d err=%v", len(retained.Items), err)
			}
		})
	}
}

func TestRouteCutoverNewOperationSupersedesTerminalAndOldRollbackRefuses(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	first, err := f.native.Actuate(f.ctx, f.request)
	if err != nil || !first.Emitted {
		t.Fatalf("first result=%+v err=%v", first, err)
	}
	secondRequest := f.request
	secondRequest.OperationID = strings.Repeat("b", 40)
	second, err := f.native.Actuate(f.ctx, secondRequest)
	if err != nil || !second.Emitted || second.RollbackRef == first.RollbackRef {
		t.Fatalf("second result=%+v err=%v firstRef=%q", second, err, first.RollbackRef)
	}
	if err := f.native.Rollback(f.ctx, f.request, first.RollbackRef); err == nil {
		t.Fatal("superseded rollback authority was accepted")
	}
	if err := f.native.Rollback(f.ctx, secondRequest, second.RollbackRef); err != nil {
		t.Fatalf("current rollback: %v", err)
	}
}

func TestRouteCutoverRollbackUsesReverseBridgeWithoutZeroMembership(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	if err := f.client.Delete(f.ctx, f.sibling); err != nil {
		t.Fatal(err)
	}
	if err := f.client.reconcile(f.ctx, f.service.Namespace, f.service.Name); err != nil {
		t.Fatal(err)
	}
	result, err := f.native.Actuate(f.ctx, f.request)
	if err != nil || !result.Emitted {
		t.Fatalf("single-target cutover result=%+v err=%v", result, err)
	}
	f.client.membershipHistory = nil
	if err := f.native.Rollback(f.ctx, f.request, result.RollbackRef); err != nil {
		t.Fatalf("single-target rollback: %v", err)
	}
	if len(f.client.membershipHistory) == 0 {
		t.Fatal("rollback made no observable EndpointSlice transitions")
	}
	for i, members := range f.client.membershipHistory {
		if members < 1 {
			t.Fatalf("rollback transition %d selected zero active Pods: history=%v", i, f.client.membershipHistory)
		}
	}
}

func TestRouteCutoverForeignTargetGuardBlocksWithoutTenantWrite(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	foreign := operationReceipt{
		Kind: string(model.ActionEndpointRotate), PolicyNamespace: f.request.Namespace, PolicyUID: "foreign-policy",
		ServiceUID: "foreign-service", TargetUID: f.request.TargetUID, OperationToken: "foreign-operation",
	}
	foreign.ReceiptID = routeReceiptID(foreign.PolicyUID, foreign.TargetUID, model.ActionEndpointRotate, foreign.OperationToken)
	guardData, err := json.Marshal(routeGuardFor(foreign))
	if err != nil {
		t.Fatal(err)
	}
	guard := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "route-operator", Name: routeGuardName(f.request.TargetUID), Labels: map[string]string{routeTargetGuardLabel: "v1"}}, Data: map[string]string{"guard": string(guardData)}}
	if err := f.client.Create(f.ctx, guard); err != nil {
		t.Fatal(err)
	}
	result, enactErr := f.native.Actuate(f.ctx, f.request)
	if enactErr == nil || result.Emitted || result.MutationKind != "partial" || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
		t.Fatalf("foreign guard result=%+v err=%v patches=%d updates=%d", result, enactErr, f.client.podPatches, f.client.serviceUpdates)
	}
}

func TestRouteCutoverServiceUIDLockSerializesOverlappingPolicies(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	f.client.failPodPatchAt = 1
	first, firstErr := f.native.Actuate(f.ctx, f.request)
	if firstErr == nil || first.Emitted {
		t.Fatalf("first unresolved operation result=%+v err=%v", first, firstErr)
	}
	secondPolicy := f.policy.DeepCopy()
	secondPolicy.Name = "policy-two"
	secondPolicy.UID = "uid-route-policy-two"
	secondPolicy.ResourceVersion = ""
	if err := f.client.Client.Create(f.ctx, secondPolicy); err != nil {
		t.Fatal(err)
	}
	f.client.failPodPatchAt = 0
	second := f.request
	second.Pod = f.sibling.Name
	second.TargetUID = string(f.sibling.UID)
	second.PolicyName = secondPolicy.Name
	second.PolicyUID = string(secondPolicy.UID)
	second.OperationID = strings.Repeat("c", 40)
	result, err := f.native.Actuate(f.ctx, second)
	if err == nil || result.Emitted || result.MutationKind != "partial" || f.client.podPatches != 1 || f.client.serviceUpdates != 0 {
		t.Fatalf("overlapping policy result=%+v err=%v patches=%d updates=%d", result, err, f.client.podPatches, f.client.serviceUpdates)
	}
	var protected corev1.ConfigMapList
	if err := f.client.List(f.ctx, &protected, client.InNamespace("route-operator")); err != nil || len(protected.Items) != 2 {
		t.Fatalf("losing target guard leaked or active lock vanished: records=%d err=%v", len(protected.Items), err)
	}
}

func TestRouteCutoverTargetLossRestoresSiblingRouteAndRetainsWhenFloorUnprovable(t *testing.T) {
	for _, tc := range []struct {
		name          string
		removeSibling bool
		wantProtected int
	}{
		{name: "surviving-sibling", wantProtected: 0},
		{name: "single-backend", removeSibling: true, wantProtected: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
			f.native.RouteObservationTimeout = 15 * time.Millisecond
			f.native.RouteObservationInterval = time.Millisecond
			if tc.removeSibling {
				if err := f.client.Delete(f.ctx, f.sibling); err != nil {
					t.Fatal(err)
				}
				if err := f.client.reconcile(f.ctx, f.service.Namespace, f.service.Name); err != nil {
					t.Fatal(err)
				}
			}
			f.client.afterServiceUpdate = func(ctx context.Context, c *routeUnitClient, svc *corev1.Service) {
				if c.serviceUpdates != 1 {
					return
				}
				victim := &corev1.Pod{}
				if err := c.Client.Get(ctx, client.ObjectKey{Namespace: f.request.Namespace, Name: f.request.Pod}, victim); err != nil {
					t.Fatal(err)
				}
				if err := c.Client.Delete(ctx, victim); err != nil {
					t.Fatal(err)
				}
				if err := c.reconcile(ctx, svc.Namespace, svc.Name); err != nil {
					t.Fatal(err)
				}
			}
			result, enactErr := f.native.Actuate(f.ctx, f.request)
			if enactErr == nil || !result.Emitted || result.MutationKind != "partial" {
				t.Fatalf("target loss result=%+v err=%v", result, enactErr)
			}
			gotSvc := &corev1.Service{}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), gotSvc); err != nil || !reflect.DeepEqual(gotSvc.Spec.Selector, f.originalS) {
				t.Fatalf("original Service route not restored: selector=%v err=%v", gotSvc.Spec.Selector, err)
			}
			var protected corev1.ConfigMapList
			if err := f.client.List(f.ctx, &protected, client.InNamespace("route-operator")); err != nil || len(protected.Items) != tc.wantProtected {
				t.Fatalf("protected records=%d want=%d err=%v: %+v", len(protected.Items), tc.wantProtected, err, protected.Items)
			}
		})
	}
}

func TestRouteCutoverAppliedRecoveryRestoresOnTargetLossAndRaisedFloor(t *testing.T) {
	t.Run("terminal-target-loss-restores-sibling", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
		result, err := f.native.Actuate(f.ctx, f.request)
		if err != nil || !result.Emitted {
			t.Fatalf("cutover result=%+v err=%v", result, err)
		}
		target := &corev1.Pod{}
		if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), target); err != nil {
			t.Fatal(err)
		}
		if err := f.client.Delete(f.ctx, target); err != nil {
			t.Fatal(err)
		}
		if err := f.client.reconcile(f.ctx, f.service.Namespace, f.service.Name); err != nil {
			t.Fatal(err)
		}
		events, recoverErr := f.native.RecoverOperations(f.ctx, false)
		if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
			t.Fatalf("target-loss recovery events=%+v err=%v", events, recoverErr)
		}
		svc := &corev1.Service{}
		if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil || !reflect.DeepEqual(svc.Spec.Selector, f.originalS) {
			t.Fatalf("target-loss recovery selector=%v err=%v", svc.Spec.Selector, err)
		}
	})

	for _, tc := range []struct {
		name          string
		removeSibling bool
		wantOutcome   string
		wantProtected int
	}{
		{name: "raised-floor-proved", wantOutcome: "confirmed", wantProtected: 0},
		{name: "raised-floor-unprovable", removeSibling: true, wantOutcome: "partial", wantProtected: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
			f.native.RouteObservationTimeout = 15 * time.Millisecond
			f.native.RouteObservationInterval = time.Millisecond
			if tc.removeSibling {
				if err := f.client.Delete(f.ctx, f.sibling); err != nil {
					t.Fatal(err)
				}
				if err := f.client.reconcile(f.ctx, f.service.Namespace, f.service.Name); err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.native.Actuate(f.ctx, f.request)
			if err != nil || !result.Emitted {
				t.Fatalf("cutover result=%+v err=%v", result, err)
			}
			policy := &v1alpha1.PhorvexPolicy{}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.policy), policy); err != nil {
				t.Fatal(err)
			}
			policy.Spec.SLO.MinAvailableReplicas = 2
			if err := f.client.Update(f.ctx, policy); err != nil {
				t.Fatal(err)
			}
			events, recoverErr := f.native.RecoverOperations(f.ctx, false)
			if recoverErr != nil || len(events) != 1 || events[0].Outcome != tc.wantOutcome {
				t.Fatalf("raised-floor recovery events=%+v err=%v", events, recoverErr)
			}
			var protected corev1.ConfigMapList
			if err := f.client.List(f.ctx, &protected, client.InNamespace("route-operator")); err != nil || len(protected.Items) != tc.wantProtected {
				t.Fatalf("protected records=%d want=%d err=%v", len(protected.Items), tc.wantProtected, err)
			}
		})
	}
}

func TestRouteCutoverRefusesDuplicateInactiveAndWrongOwnerEndpointEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*discoveryv1.EndpointSlice)
	}{
		{name: "duplicate-target", mutate: func(slice *discoveryv1.EndpointSlice) { slice.Endpoints = append(slice.Endpoints, slice.Endpoints[0]) }},
		{name: "inactive-target", mutate: func(slice *discoveryv1.EndpointSlice) {
			inactive := false
			slice.Endpoints[0].Conditions.Ready = &inactive
		}},
		{name: "wrong-owner", mutate: func(slice *discoveryv1.EndpointSlice) { slice.OwnerReferences[0].UID = "other-service" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
			slice := &discoveryv1.EndpointSlice{}
			if err := f.client.Get(f.ctx, client.ObjectKey{Namespace: f.request.Namespace, Name: "route-slice"}, slice); err != nil {
				t.Fatal(err)
			}
			tc.mutate(slice)
			if err := f.client.Client.Update(f.ctx, slice); err != nil {
				t.Fatal(err)
			}
			result, err := f.native.Actuate(f.ctx, f.request)
			if !IsNoEffectRefusal(err) || result.Emitted || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
				t.Fatalf("invalid endpoints result=%+v err=%v patches=%d updates=%d", result, err, f.client.podPatches, f.client.serviceUpdates)
			}
		})
	}
}

func TestRouteCutoverNeverMutatesSameNameSuccessors(t *testing.T) {
	t.Run("Pod-replaced-before-first-patch", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
		f.client.replacePodAt = 1
		result, err := f.native.Actuate(f.ctx, f.request)
		if err == nil || result.Emitted || result.MutationKind != "partial" || f.client.replacementUID == "" || f.client.replacementUID == f.pod.UID {
			t.Fatalf("Pod replacement result=%+v err=%v replacement=%s", result, err, f.client.replacementUID)
		}
		successor := &corev1.Pod{}
		if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), successor); err != nil {
			t.Fatal(err)
		}
		if successor.UID != f.client.replacementUID || !reflect.DeepEqual(successor.Labels, f.originalP) {
			t.Fatalf("same-name Pod successor was mutated: uid=%s labels=%v", successor.UID, successor.Labels)
		}
	})

	t.Run("Service-replaced-after-Pod-bridge", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
		f.client.replaceServiceAt = 1
		result, err := f.native.Actuate(f.ctx, f.request)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || f.client.replacementUID == "" || f.client.replacementUID == f.service.UID {
			t.Fatalf("Service replacement result=%+v err=%v replacement=%s", result, err, f.client.replacementUID)
		}
		successor := &corev1.Service{}
		if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), successor); err != nil {
			t.Fatal(err)
		}
		if successor.UID != f.client.replacementUID || !reflect.DeepEqual(successor.Spec.Selector, f.originalS) {
			t.Fatalf("same-name Service successor was mutated: uid=%s selector=%v", successor.UID, successor.Spec.Selector)
		}
	})
}

func TestRouteReceiptRejectsForgedAndLegacyAuthority(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	receipt, err := routeInitialReceipt(f.ctx, EnactCtx{Client: f.client, Reader: f.client, JournalNamespace: "route-operator"}, f.request)
	if err != nil {
		t.Fatal(err)
	}
	receipt.TargetGuardUID = "guard-uid"
	if !receipt.valid() {
		t.Fatal("valid route receipt rejected")
	}
	for _, mutate := range []func(*operationReceipt){
		func(r *operationReceipt) { r.Version = 1 },
		func(r *operationReceipt) { r.ReceiptID = strings.Repeat("0", 40) },
		func(r *operationReceipt) { r.RouteValue = "forged" },
		func(r *operationReceipt) { r.OriginalServiceSelector[labelRouteKey] = "foreign" },
		func(r *operationReceipt) { r.RouteEpochKey = "phorvex.ai/foreign" },
	} {
		forged := receipt
		forged.TargetLabels = copyLabels(receipt.TargetLabels)
		forged.OriginalServiceSelector = copyLabels(receipt.OriginalServiceSelector)
		mutate(&forged)
		if forged.valid() {
			t.Fatalf("forged route receipt accepted: %+v", forged)
		}
	}
}

func TestRouteGuardBindingFencesStaleOrphanCleanup(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	ec := EnactCtx{Client: f.client, Reader: f.client, JournalNamespace: "route-operator"}
	receipt, err := routeInitialReceipt(f.ctx, ec, f.request)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := acquireRouteGuard(f.ctx, ec, receipt)
	if err != nil {
		t.Fatal(err)
	}
	stale := guard.DeepCopy()
	receipt.TargetGuardUID = string(guard.UID)
	journal, err := journalWrite(f.ctx, ec, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindRouteGuard(f.ctx, ec, guard, journal, receipt); err != nil {
		t.Fatal(err)
	}
	if err := finishRouteGuard(f.ctx, ec, stale); err == nil {
		t.Fatal("stale orphan cleanup deleted a guard after Service receipt binding")
	}
	if err := requireRouteGuard(f.ctx, ec, guard, journal, receipt); err != nil {
		t.Fatalf("bound guard lost after stale cleanup attempt: %v", err)
	}
}

func TestRouteCutoverTerminatingProtectedClaimsRemainBusy(t *testing.T) {
	t.Run("target-guard", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
		ec := EnactCtx{Client: f.client, Reader: f.client, JournalNamespace: "route-operator"}
		receipt, err := routeInitialReceipt(f.ctx, ec, f.request)
		if err != nil {
			t.Fatal(err)
		}
		guard, err := acquireRouteGuard(f.ctx, ec, receipt)
		if err != nil {
			t.Fatal(err)
		}
		guard.Finalizers = []string{"tests.phorvex.ai/retain"}
		if err := f.client.Client.Update(f.ctx, guard); err != nil {
			t.Fatal(err)
		}
		if err := f.client.Client.Delete(f.ctx, guard); err != nil {
			t.Fatal(err)
		}
		result, enactErr := f.native.Actuate(f.ctx, f.request)
		if enactErr == nil || result.Emitted || result.MutationKind != "partial" || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
			t.Fatalf("terminating guard result=%+v err=%v", result, enactErr)
		}
	})

	t.Run("Service-receipt", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
		ec := EnactCtx{Client: f.client, Reader: f.client, JournalNamespace: "route-operator"}
		receipt, err := routeInitialReceipt(f.ctx, ec, f.request)
		if err != nil {
			t.Fatal(err)
		}
		guard, err := acquireRouteGuard(f.ctx, ec, receipt)
		if err != nil {
			t.Fatal(err)
		}
		receipt.TargetGuardUID = string(guard.UID)
		journal, err := journalWrite(f.ctx, ec, receipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := bindRouteGuard(f.ctx, ec, guard, journal, receipt); err != nil {
			t.Fatal(err)
		}
		journal.Finalizers = []string{"tests.phorvex.ai/retain"}
		if err := f.client.Client.Update(f.ctx, journal); err != nil {
			t.Fatal(err)
		}
		if err := f.client.Client.Delete(f.ctx, journal); err != nil {
			t.Fatal(err)
		}
		result, enactErr := f.native.Actuate(f.ctx, f.request)
		if enactErr == nil || result.Emitted || result.MutationKind != "partial" || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
			t.Fatalf("terminating receipt result=%+v err=%v", result, enactErr)
		}
	})
}
