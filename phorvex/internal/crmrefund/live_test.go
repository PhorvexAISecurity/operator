package crmrefund

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func crmLiveFixture(t *testing.T) client.Client {
	t.Helper()
	return crmLiveFixtureInNamespace(t, Namespace)
}

func crmLiveFixtureInNamespace(t *testing.T, namespace string) client.Client {
	t.Helper()
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: namespace, UID: "svc-uid"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "crm"},
			Ports: []corev1.ServicePort{{Port: 8080, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt(8080)}}}}
	guard := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: GuardConfigMapName, Namespace: namespace, UID: "guard-uid"},
		Data: map[string]string{GuardKey: `{"denied_order_ids":[]}`}}
	objects := []client.Object{svc, guard}
	ready := true
	var endpoints []discoveryv1.Endpoint
	for i, name := range []string{"crm-a", "crm-b"} {
		guardVol := corev1.Volume{Name: "crm-guard", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: GuardConfigMapName}}}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID("pod-" + string(rune('a'+i))), Labels: map[string]string{"app": "crm"}},
			Spec: corev1.PodSpec{Volumes: []corev1.Volume{guardVol},
				Containers: []corev1.Container{{Name: "crm", VolumeMounts: []corev1.VolumeMount{{Name: "crm-guard", ReadOnly: true, MountPath: GuardMountPath}}}}},
			Status: corev1.PodStatus{PodIP: "10.2.0." + string(rune('1'+i)), ContainerStatuses: []corev1.ContainerStatus{{Name: "crm", Ready: true}}}}
		objects = append(objects, pod)
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{pod.Status.PodIP},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: name, UID: pod.UID}})
	}
	port := int32(8080)
	objects = append(objects, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "crm-slice", Namespace: namespace,
		Labels: map[string]string{discoveryv1.LabelServiceName: ServiceName}},
		Ports: []discoveryv1.EndpointPort{{Port: &port}}, Endpoints: endpoints})
	if namespace == StagingNamespace {
		for _, object := range objects {
			labels := object.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}
			labels[StagingFixtureLabel] = StagingFixtureValue
			object.SetLabels(labels)
		}
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme} {
		if e := add(scheme); e != nil {
			t.Fatal(e)
		}
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func TestCRMValidateLiveExactGuardAndPodGraph(t *testing.T) {
	ctx := context.Background()
	c := crmLiveFixture(t)
	got, e := ValidateLive(ctx, c, "pod-a", "pod-b")
	if e != nil || len(got.Pods) != 2 || got.GuardUID != "guard-uid" || got.ServiceUID != "svc-uid" || len(got.State.Entries) != 0 {
		t.Fatalf("valid guard graph rejected: %+v %v", got, e)
	}

	for _, tc := range []struct {
		name   string
		mutate func(client.Client)
	}{
		{"app-ledger-disagree", func(c client.Client) {
			o := &corev1.ConfigMap{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: GuardConfigMapName}, o)
			o.Data[GuardKey] = `{"denied_order_ids":["OR-9999"]}` // app guard disagrees with the empty ledger
			_ = c.Update(ctx, o)
		}},
		{"pod-unmounts-guard", func(c client.Client) {
			o := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "crm-a"}, o)
			o.Spec.Containers[0].VolumeMounts = nil
			_ = c.Update(ctx, o)
		}},
		{"pod-not-ready", func(c client.Client) {
			o := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "crm-a"}, o)
			o.Status.ContainerStatuses[0].Ready = false
			_ = c.Status().Update(ctx, o)
		}},
		{"service-port-drift", func(c client.Client) {
			o := &corev1.Service{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ServiceName}, o)
			o.Spec.Ports[0].Port = 9090
			_ = c.Update(ctx, o)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := crmLiveFixture(t)
			tc.mutate(c)
			if _, e := ValidateLive(ctx, c, "pod-a", "pod-b"); e == nil {
				t.Fatalf("%s: ValidateLive accepted a drifted guard graph", tc.name)
			}
		})
	}
}

// A revoke already recorded in the ledger must round-trip through state <-> app-facing bytes
// so ValidateLive accepts a guard the actuator has previously written.
func TestCRMValidateLiveAcceptsWrittenLedger(t *testing.T) {
	ctx := context.Background()
	c := crmLiveFixture(t)
	next, e := (Guard{Version: 2, Entries: []Entry{}}).Append("OR-5002", "op-1")
	if e != nil {
		t.Fatal(e)
	}
	stateRaw, e := EncodeState(next)
	if e != nil {
		t.Fatal(e)
	}
	o := &corev1.ConfigMap{}
	if e = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: GuardConfigMapName}, o); e != nil {
		t.Fatal(e)
	}
	o.Data[StateKey] = stateRaw
	o.Data[GuardKey] = next.EncodeAppGuard()
	if e = c.Update(ctx, o); e != nil {
		t.Fatal(e)
	}
	got, e := ValidateLive(ctx, c, "pod-a", "pod-b")
	if e != nil || len(got.State.Entries) != 1 || got.State.Entries[0].OrderID != "OR-5002" {
		t.Fatalf("written ledger not read back: %+v %v", got, e)
	}
}

func TestCRMStagingNamespaceRequiresExplicitOptIn(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, configured, namespace string
		want                        bool
	}{
		{"legacy-default", "", Namespace, true},
		{"staging-default-off", "", StagingNamespace, false},
		{"staging-explicit", StagingNamespace, StagingNamespace, true},
		{"legacy-still-pinned", StagingNamespace, Namespace, true},
		{"arbitrary-config", "other", StagingNamespace, false},
		{"arbitrary-namespace", StagingNamespace, "other", false},
		{"empty-namespace", StagingNamespace, "", false},
		{"no-trimming", StagingNamespace + " ", StagingNamespace, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(NamespaceEnv, tc.configured)
			c := crmLiveFixtureInNamespace(t, tc.namespace)
			_, err := ValidateLiveInNamespace(ctx, c, tc.namespace, "pod-a", "pod-b")
			if (err == nil) != tc.want {
				t.Fatalf("namespace %q configured %q: err=%v want admitted=%v", tc.namespace, tc.configured, err, tc.want)
			}
		})
	}
	t.Setenv(NamespaceEnv, StagingNamespace)
	if _, err := ValidateLive(ctx, crmLiveFixtureInNamespace(t, StagingNamespace), "pod-a", "pod-b"); err == nil {
		t.Fatal("legacy ValidateLive changed namespace under staging configuration")
	}
}

func TestCRMStagingRejectsMissingFixtureMarkersAndGuardDrift(t *testing.T) {
	t.Setenv(NamespaceEnv, StagingNamespace)
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		object client.Object
	}{
		{"service", &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName}}},
		{"guard", &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: GuardConfigMapName}}},
		{"target", &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "crm-a"}}},
		{"peer", &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "crm-b"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := crmLiveFixtureInNamespace(t, StagingNamespace)
			if err := c.Get(ctx, client.ObjectKey{Namespace: StagingNamespace, Name: tc.object.GetName()}, tc.object); err != nil {
				t.Fatal(err)
			}
			delete(tc.object.GetLabels(), StagingFixtureLabel)
			if err := c.Update(ctx, tc.object); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateLiveInNamespace(ctx, c, StagingNamespace, "pod-a", "pod-b"); err == nil {
				t.Fatal("unmarked staging object admitted")
			}
		})
	}
	c := crmLiveFixtureInNamespace(t, StagingNamespace)
	guard := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: StagingNamespace, Name: GuardConfigMapName}, guard); err != nil {
		t.Fatal(err)
	}
	guard.Data[GuardKey] = `{"denied_order_ids":["OR-9999"]}`
	if err := c.Update(ctx, guard); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateLiveInNamespace(ctx, c, StagingNamespace, "pod-a", "pod-b"); err == nil {
		t.Fatal("staging bypassed app/ledger agreement")
	}
}
