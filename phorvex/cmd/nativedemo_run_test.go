package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type demoUIDClient struct {
	client.Client
	next          int
	suppressReady bool
}

func (c *demoUIDClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.next++
	obj.SetUID(types.UID("owned-" + string(rune('a'+c.next))))
	if p, ok := obj.(*corev1.Pod); ok && !c.suppressReady {
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	return c.syncRouteSlices(ctx)
}

func (c *demoUIDClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	return c.syncRouteSlices(ctx)
}

func (c *demoUIDClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	return c.syncRouteSlices(ctx)
}

func (c *demoUIDClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if err := c.Client.Delete(ctx, obj, opts...); err != nil {
		return err
	}
	return c.syncRouteSlices(ctx)
}

// syncRouteSlices is the test boundary for the EndpointSlice controller. The
// production demo relies on Kubernetes; these fake-client controls still feed
// the real handler current Service-owned membership after every Pod/Service write.
func (c *demoUIDClient) syncRouteSlices(ctx context.Context) error {
	var services corev1.ServiceList
	if err := c.Client.List(ctx, &services); err != nil {
		return err
	}
	var pods corev1.PodList
	if err := c.Client.List(ctx, &pods); err != nil {
		return err
	}
	for i := range services.Items {
		svc := &services.Items[i]
		if svc.UID == "" || len(svc.Spec.Selector) == 0 {
			continue
		}
		ready := true
		endpoints := make([]discoveryv1.Endpoint, 0)
		selector := labels.SelectorFromSet(svc.Spec.Selector)
		for j := range pods.Items {
			pod := &pods.Items[j]
			if pod.Namespace != svc.Namespace || !selector.Matches(labels.Set(pod.Labels)) {
				continue
			}
			isReady := false
			for _, condition := range pod.Status.Conditions {
				isReady = isReady || condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue
			}
			if !isReady || pod.UID == "" {
				continue
			}
			ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
			endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
		}
		key := client.ObjectKey{Namespace: svc.Namespace, Name: "demo-" + svc.Name}
		var slice discoveryv1.EndpointSlice
		err := c.Client.Get(ctx, key, &slice)
		if runtime.IsNotRegisteredError(err) {
			return nil
		}
		if apierrors.IsNotFound(err) {
			slice = discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: svc.Namespace, Name: key.Name, UID: types.UID("slice-" + svc.Name), Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: endpoints}
			if err := c.Client.Create(ctx, &slice); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		slice.Labels = map[string]string{discoveryv1.LabelServiceName: svc.Name}
		slice.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}}
		slice.Endpoints = endpoints
		if err := c.Client.Update(ctx, &slice); err != nil {
			return err
		}
	}
	return nil
}

func demoRouteAuthority(t *testing.T, ctx context.Context, c client.Client, action model.Action) (*actuator.NativeActuator, *v1alpha1.PhorvexPolicy) {
	t.Helper()
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "route-policy", Namespace: "demo"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/native-demo": "true"}}, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: 1}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(action)}}}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	native := newDemoActuator(c)
	native.JournalNamespace = "operator"
	native.RouteObservationTimeout = 100 * time.Millisecond
	native.RouteObservationInterval = time.Millisecond
	return native, policy
}

type demoRouteReadFault struct {
	*demoUIDClient
	fault bool
}

func (c *demoRouteReadFault) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	err := c.demoUIDClient.Update(ctx, obj, opts...)
	if _, ok := obj.(*corev1.Service); ok && err == nil {
		c.fault = true
	}
	return err
}
func (c *demoRouteReadFault) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Service); ok && c.fault {
		return errors.New("injected postcondition Service read failure")
	}
	return c.demoUIDClient.Get(ctx, key, obj, opts...)
}

// The native Service update succeeds, then the API boundary replaces that
// Service under the same name and selector before independent demo readback.
type demoRouteReplacementClient struct {
	*demoUIDClient
	replacementUID types.UID
}

func (c *demoRouteReplacementClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.demoUIDClient.Update(ctx, obj, opts...); err != nil {
		return err
	}
	svc, ok := obj.(*corev1.Service)
	if !ok || c.replacementUID != "" {
		return nil
	}
	var current corev1.Service
	if err := c.demoUIDClient.Get(ctx, client.ObjectKeyFromObject(svc), &current); err != nil {
		return err
	}
	replacement := current.DeepCopy()
	if err := c.demoUIDClient.Delete(ctx, &current); err != nil {
		return err
	}
	replacement.UID = ""
	replacement.ResourceVersion = ""
	replacement.CreationTimestamp = metav1.Time{}
	if err := c.demoUIDClient.Create(ctx, replacement); err != nil {
		return err
	}
	c.replacementUID = replacement.UID
	return nil
}

// This controlled Kubernetes boundary materializes Deployment-owned Pods and
// garbage collection. NativeActuator itself remains the real implementation.
type demoControllerClient struct{ *demoUIDClient }

type demoEphemeralBoundary struct {
	client.SubResourceClient
	c *demoControllerClient
}

func (b *demoEphemeralBoundary) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return b.SubResourceClient.Update(ctx, obj, opts...)
	}
	var current corev1.Pod
	if err := b.c.demoUIDClient.Get(ctx, client.ObjectKeyFromObject(p), &current); err != nil {
		return err
	}
	if current.UID != p.UID {
		return errors.New("ephemeral boundary target UID changed")
	}
	current.Spec.EphemeralContainers = append([]corev1.EphemeralContainer(nil), p.Spec.EphemeralContainers...)
	return b.c.demoUIDClient.Update(ctx, &current)
}
func (c *demoControllerClient) SubResource(name string) client.SubResourceClient {
	base := c.demoUIDClient.SubResource(name)
	if name == "ephemeralcontainers" {
		return &demoEphemeralBoundary{SubResourceClient: base, c: c}
	}
	return base
}

func (c *demoControllerClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.demoUIDClient.Create(ctx, obj, opts...); err != nil {
		return err
	}
	dep, ok := obj.(*appsv1.Deployment)
	if !ok {
		return nil
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: dep.Name + "-rs", Namespace: dep.Namespace, Labels: dep.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Spec: appsv1.ReplicaSetSpec{Replicas: ptr32(1), Selector: dep.Spec.Selector, Template: dep.Spec.Template}}
	if err := c.demoUIDClient.Create(ctx, rs); err != nil {
		return err
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: dep.Name + "-pod", Namespace: dep.Namespace, Labels: dep.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}, Spec: dep.Spec.Template.Spec}
	return c.demoUIDClient.Create(ctx, pod)
}

func (c *demoControllerClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if dep, ok := obj.(*appsv1.Deployment); ok {
		var sets appsv1.ReplicaSetList
		if err := c.List(ctx, &sets, client.InNamespace(dep.Namespace)); err != nil {
			return err
		}
		for i := range sets.Items {
			rs := &sets.Items[i]
			if len(rs.OwnerReferences) == 1 && rs.OwnerReferences[0].UID == dep.UID {
				if err := c.demoUIDClient.Delete(ctx, rs); err != nil && !apierrors.IsNotFound(err) {
					return err
				}
			}
		}
	}
	return c.demoUIDClient.Delete(ctx, obj, opts...)
}

func TestDemoRouteCaseUsesNativeActuatorAndServiceReadback(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = discoveryv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "demo-uid"}}
	c := &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(namespace).Build()}
	run := &demoRun{client: c, token: "route-run"}
	ctx := context.Background()
	native, policy := demoRouteAuthority(t, ctx, c, model.ActionRouteRotate)
	row := runDemoRouteCase(ctx, run, native, "demo", policy, model.ActionRouteRotate)
	if row.verdict != demoConfirmed {
		t.Fatalf("route control: %+v", row)
	}
	if !strings.Contains(row.observed, "beforeReady=2") || !strings.Contains(row.observed, "restitched=true") {
		t.Fatalf("route observation lacks actual controls: %+v", row)
	}
}

func TestDemoRouteMissingReadyFixtureIsVisible(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = discoveryv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	c := &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).Build(), suppressReady: true}
	run := &demoRun{client: c, token: "missing-run"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}}); err != nil {
		t.Fatal(err)
	}
	native, policy := demoRouteAuthority(t, ctx, c, model.ActionRouteRotate)
	row := runDemoRouteCase(ctx, run, native, "demo", policy, model.ActionRouteRotate)
	if row.verdict != demoSetupFailure || row.observed == "" {
		t.Fatalf("missing fixture vanished: %+v", row)
	}
}

func TestDemoRouteFailedIndependentServiceReadNeverPasses(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = discoveryv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "demo-uid"}}
	c := &demoRouteReadFault{demoUIDClient: &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(namespace).Build()}}
	run := &demoRun{client: c, token: "read-fault-run"}
	ctx := context.Background()
	native, policy := demoRouteAuthority(t, ctx, c, model.ActionRouteRotate)
	row := runDemoRouteCase(ctx, run, native, "demo", policy, model.ActionRouteRotate)
	if row.verdict != demoObservationFailure || !strings.Contains(row.observed, "injected postcondition") {
		t.Fatalf("read failure credited: %+v", row)
	}
}

func TestDemoRouteSameNameServiceReplacementIsNotCreditedOrCleaned(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = discoveryv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "demo-uid"}}
	c := &demoRouteReplacementClient{demoUIDClient: &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(namespace).Build()}}
	run := &demoRun{client: c, token: "replacement-run"}
	ctx := context.Background()
	native, policy := demoRouteAuthority(t, ctx, c, model.ActionRouteRotate)
	row := runDemoRouteCase(ctx, run, native, "demo", policy, model.ActionRouteRotate)
	if c.replacementUID == "" || row.verdict != demoObservationFailure || !strings.Contains(row.observed, "restitched=false") {
		t.Fatalf("same-name replacement credited: replacement=%s row=%+v", c.replacementUID, row)
	}
	if errs := run.cleanup(ctx); len(errs) == 0 {
		t.Fatal("cleanup did not report replaced owned Service")
	}
	var foreign corev1.Service
	if err := c.Get(ctx, client.ObjectKey{Namespace: "demo", Name: "svc-route-rotate"}, &foreign); err != nil || foreign.UID != c.replacementUID {
		t.Fatalf("cleanup touched foreign Service uid=%s want=%s err=%v", foreign.UID, c.replacementUID, err)
	}
}

func TestDemoWarmCaseBuildsConfiguredPoolScaffoldWithoutClaimingCutover(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	admin := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "operator-uid"}}
	tenant := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "demo-uid"}}
	c := &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(admin, tenant).Build()}
	run := &demoRun{client: c, token: "warm-run"}
	ctx := context.Background()
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "demo"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/native-demo-run": run.token}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionWarmSwap}}}}
	if err := run.create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	n := newDemoActuator(&demoTrackingClient{Client: c, run: run})
	n.JournalNamespace = "operator"
	row := runDemoWarmCase(ctx, run, n, "demo", policy)
	if row.verdict != demoUnavailable {
		t.Fatalf("controller replenishment pending control: %+v", row)
	}
	if !strings.Contains(row.observed, "configuredPool=true") || !strings.Contains(row.observed, "cutover not submitted") {
		t.Fatalf("warm prerequisite result overclaims cutover/capacity: %+v", row)
	}
}

func TestDemoQuarantineCanonicalPredicateAndMissingJournalControl(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	ctx := context.Background()
	for _, tc := range []struct {
		name, journal string
		confirmed     bool
	}{{"protected", "operator", true}, {"missing", "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			c := &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "tenant-uid"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "admin-uid"}}).Build()}
			run := &demoRun{client: c, token: "qtn-" + tc.name}
			policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "demo"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/native-demo-run": run.token}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionQuarantine}}}}
			if err := run.create(ctx, policy); err != nil {
				t.Fatal(err)
			}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: "demo", Labels: map[string]string{"app": "victim"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:1.36"}}}}
			if err := run.create(ctx, pod); err != nil {
				t.Fatal(err)
			}
			n := newDemoActuator(&demoTrackingClient{Client: c, run: run})
			n.JournalNamespace = tc.journal
			req := actuator.Request{Namespace: "demo", Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionQuarantine, PolicyName: policy.Name, PolicyUID: string(policy.UID)}
			res, err := demoActuate(ctx, n, req)
			if !tc.confirmed {
				if err == nil || res.Emitted {
					t.Fatalf("missing journal mutated: %+v %v", res, err)
				}
				return
			}
			if err != nil || !res.Emitted {
				t.Fatalf("quarantine control: %+v %v", res, err)
			}
			observed, readErr := demoQuarantine(ctx, c, pod)
			if readErr != nil || !observed {
				t.Fatalf("canonical policy/Pod readback: %v %v", observed, readErr)
			}
			if err := n.Rollback(ctx, req, res.RollbackRef); err != nil {
				t.Fatal(err)
			}
			restored, readErr := demoQuarantineRolledBack(ctx, c, pod)
			if readErr != nil || !restored {
				t.Fatalf("rollback readback: %v %v", restored, readErr)
			}
		})
	}
}

func TestDemoRouteRefusesZeroSingleAndUnreadyAlternativesWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name                                             string
		targetReady, alternativeReady, createAlternative bool
	}{{"zero", false, false, true}, {"single", true, false, false}, {"unready-alternative", true, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s := runtime.NewScheme()
			_ = corev1.AddToScheme(s)
			_ = discoveryv1.AddToScheme(s)
			_ = v1alpha1.AddToScheme(s)
			namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "demo-uid"}}
			c := &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(namespace).Build()}
			run := &demoRun{client: c, token: "refuse-" + tc.name}
			ctx := context.Background()
			native, policy := demoRouteAuthority(t, ctx, c, model.ActionRouteRotate)
			mk := func(name string, ready bool, annotated bool) *corev1.Pod {
				c.suppressReady = !ready
				p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo", Labels: map[string]string{"app": "route-group", demoRouteKey: "route-initial"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:1.36"}}}}
				if annotated {
					p.Annotations = map[string]string{"phorvex.ai/route-service": "route-svc"}
				}
				if err := run.create(ctx, p); err != nil {
					t.Fatal(err)
				}
				return p
			}
			target := mk("target", tc.targetReady, true)
			if tc.createAlternative {
				_ = mk("alternative", tc.alternativeReady, false)
			}
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "route-svc", Namespace: "demo"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "route-group", demoRouteKey: "route-initial"}, Ports: []corev1.ServicePort{{Port: 80}}}}
			if err := run.create(ctx, svc); err != nil {
				t.Fatal(err)
			}
			res, err := demoActuate(ctx, native, actuator.Request{Namespace: "demo", Pod: target.Name, TargetUID: string(target.UID), Action: model.ActionRouteRotate, PolicyName: policy.Name, PolicyUID: string(policy.UID), OperationID: "refuse-" + tc.name})
			if err == nil && res.Emitted {
				t.Fatalf("%s unexpectedly emitted: %+v", tc.name, res)
			}
			var after corev1.Pod
			if e := c.Get(ctx, client.ObjectKeyFromObject(target), &after); e != nil || after.UID != target.UID || after.Labels[demoRouteKey] != "route-initial" {
				t.Fatalf("%s changed selected Pod: %v %+v", tc.name, e, after.Labels)
			}
			var afterSvc corev1.Service
			if e := c.Get(ctx, client.ObjectKeyFromObject(svc), &afterSvc); e != nil || !reflect.DeepEqual(afterSvc.Spec.Selector, svc.Spec.Selector) {
				t.Fatalf("%s changed Service selector: %v %+v", tc.name, e, afterSvc.Spec.Selector)
			}
		})
	}
}

func TestDemoReportSeparatesUnavailableAndFailure(t *testing.T) {
	r := &demoReport{}
	r.add("kv-reset", "busybox refused", "no flush", demoRefused)
	r.add("identity-rotate", "declared-only", "no credential effect", demoUnavailable)
	r.add("rotate", "UID gone", "read denied", demoObservationFailure)
	var out bytes.Buffer
	if err := r.write(&out); err == nil {
		t.Fatal("incomplete report returned success")
	}
	for _, want := range []string{"REFUSED", "UNAVAILABLE", "OBSERVE-FAIL", "1 refused / 1 unavailable"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report missing %q: %s", want, out.String())
		}
	}
}

func TestNativeDemoMissingNamespaceStopsBeforeEffectsWithVisibleRow(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	c := &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).Build()}
	var out bytes.Buffer
	if err := runNativeDemo(context.Background(), c, "missing-demo", "operator", &out); err == nil {
		t.Fatal("missing namespace returned success")
	}
	if c.next != 0 || !strings.Contains(out.String(), "namespace") || !strings.Contains(out.String(), "SETUP-FAIL") {
		t.Fatalf("missing namespace hidden or effects attempted: creates=%d report=%s", c.next, out.String())
	}
}

func TestNativeDemoFullRunReportsEffectsQualificationsAndOwnedCleanup(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = discoveryv1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	tenant := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "tenant-uid"}}
	admin := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "operator-uid"}}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(tenant, admin).Build()
	c := &demoControllerClient{demoUIDClient: &demoUIDClient{Client: base}}
	var out bytes.Buffer
	if err := runNativeDemo(context.Background(), c, "demo", "operator", &out); err == nil {
		t.Fatal("qualified unavailable cases returned full success")
	}
	output := out.String()
	for _, control := range []string{"rotate", "quarantine", "route-rotate", "endpoint-rotate", "warm-swap", "identity-rotate", "kv-reset", "cleanup", "receiptFinished=true", "UNAVAILABLE", "REFUSED"} {
		if !strings.Contains(output, control) {
			t.Fatalf("full run missing %s: %s", control, output)
		}
	}
	for _, bad := range []string{"SETUP-FAIL", "OBSERVE-FAIL", "CLEANUP-FAIL", "12 handlers + rollback + dry-run"} {
		if strings.Contains(output, bad) {
			t.Fatalf("full run credited bad/misleading summary %s: %s", bad, output)
		}
	}
	var pods corev1.PodList
	if err := c.List(context.Background(), &pods, client.InNamespace("demo")); err != nil || len(pods.Items) != 0 {
		t.Fatalf("owned Pods remained: %v count=%d", err, len(pods.Items))
	}
}

func TestDemoCollisionAndCleanupBoundToAcknowledgedUID(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	foreign := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "collision", Namespace: "demo", UID: "foreign", Labels: map[string]string{"phorvex.ai/native-demo-run": "old"}}}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(foreign).Build()
	c := &demoUIDClient{Client: base}
	run := &demoRun{client: c, token: "run-one"}
	ctx := context.Background()
	if err := run.create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "collision", Namespace: "demo"}}); err == nil {
		t.Fatal("name collision adopted")
	}
	var after corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: "demo", Name: "collision"}, &after); err != nil || after.UID != "foreign" {
		t.Fatalf("foreign collision touched: %v uid=%s", err, after.UID)
	}
	owned := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "owned", Namespace: "demo"}}
	if err := run.create(ctx, owned); err != nil {
		t.Fatal(err)
	}
	if errs := run.cleanup(ctx); len(errs) != 0 {
		t.Fatalf("owned cleanup: %v", errs)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(owned), &after); !apierrors.IsNotFound(err) {
		t.Fatalf("owned UID remains: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "demo", Name: "collision"}, &after); err != nil || after.UID != "foreign" {
		t.Fatalf("collision removed: %v uid=%s", err, after.UID)
	}
}

func TestDemoCleanupRefusesRecreatedSameNameEvenWithCopiedRunLabel(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	c := &demoUIDClient{Client: fake.NewClientBuilder().WithScheme(s).Build()}
	ctx := context.Background()
	run := &demoRun{client: c, token: "same-name-run"}
	owned := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: "demo"}}
	if err := run.create(ctx, owned); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, owned); err != nil {
		t.Fatal(err)
	}
	replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: owned.Name, Namespace: owned.Namespace, Labels: map[string]string{"phorvex.ai/native-demo-run": run.token}}}
	if err := c.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.UID == owned.UID {
		t.Fatal("test replacement UID did not change")
	}
	if errs := run.cleanup(ctx); len(errs) == 0 {
		t.Fatal("recreated name cleanup falsely succeeded")
	}
	var observed corev1.Pod
	if err := c.Get(ctx, client.ObjectKeyFromObject(replacement), &observed); err != nil || observed.UID != replacement.UID {
		t.Fatalf("same-name replacement deleted: %v uid=%s", err, observed.UID)
	}
}
