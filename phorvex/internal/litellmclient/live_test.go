package litellmclient

import (
	"context"
	"os"
	"strings"
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

func liveFixture(t *testing.T) (client.Client, string) {
	t.Helper()
	code, e := os.ReadFile("../../../build/test-harness/fixtures/litellm-live/gateway.py")
	if e != nil {
		t.Fatal(e)
	}
	hash := SHA256(code)
	if hash != ApprovedSourceSHA256 {
		t.Fatalf("reviewed gateway source drift: %s", hash)
	}
	immutable := true
	attacker := strings.Repeat("a", 64)
	control := strings.Repeat("b", 64)
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: Namespace, UID: types.UID("service-uid")},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "litellm"}, Ports: []corev1.ServicePort{{Port: 4000, TargetPort: intstr.FromInt32(4001)}}}}
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: SourceConfigMapName, Namespace: Namespace, UID: types.UID("source-uid")},
		Immutable: &immutable, Data: map[string]string{SourceKey: string(code)}}
	clients := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ClientsConfigMapName, Namespace: Namespace, UID: types.UID("clients-uid")},
		Immutable: &immutable, Data: map[string]string{ClientsKey: `{"attackerSHA256":"` + attacker + `","controlSHA256":"` + control + `","modelAlias":"gpt-4o-mini","version":1}`}}
	policy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: PolicyConfigMapName, Namespace: Namespace, UID: types.UID("policy-cm-uid"), ResourceVersion: "1"},
		Data: map[string]string{PolicyKey: `{"active":false,"clientSHA256":"` + attacker + `","operationId":"","revision":0,"version":1}`}}
	objects := []client.Object{svc, source, clients, policy}
	for i, name := range []string{"litellm-a", "litellm-b"} {
		gatewayImage := "gateway@sha256:" + strings.Repeat("c", 64)
		uid := types.UID("pod-" + string(rune('a'+i)))
		ip := "10.1.0." + string(rune('1'+i))
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: Namespace, UID: uid,
			Labels: map[string]string{"app": "litellm"}, Annotations: map[string]string{
				SourceSHAAnnotation: hash, GatewayImageAnnotation: gatewayImage, PolicyUIDAnnotation: "policy-cm-uid", ServiceUIDAnnotation: "service-uid", ClientSHAAnnotation: attacker}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "litellm", Image: "backend@sha256:" + strings.Repeat(string(rune('d'+i)), 64)},
				{Name: GatewayContainerName, Image: gatewayImage, Command: []string{"python", "-B", "/opt/phorvex/gateway.py"},
					Env: []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
						{Name: "PHORVEX_LITELLM_CLIENTS_FILE", Value: "/etc/phorvex-litellm/clients.json"},
						{Name: "PHORVEX_LITELLM_POLICY_FILE", Value: "/etc/phorvex-litellm-policy/state.json"},
						{Name: "PHORVEX_LITELLM_STATUS_TOKEN_FILE", Value: "/etc/phorvex-litellm-status/token"},
						{Name: "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", Value: "policy-cm-uid"},
						{Name: "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", Value: hash}},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "litellm-live-gateway-source", MountPath: "/opt/phorvex", ReadOnly: true},
						{Name: "litellm-live-clients", MountPath: "/etc/phorvex-litellm", ReadOnly: true},
						{Name: "litellm-live-policy", MountPath: "/etc/phorvex-litellm-policy", ReadOnly: true},
						{Name: "litellm-live-status", MountPath: "/etc/phorvex-litellm-status", ReadOnly: true}}}},
				Volumes: []corev1.Volume{{Name: "litellm-live-gateway-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: SourceConfigMapName}}}},
					{Name: "litellm-live-clients", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: ClientsConfigMapName}}}},
					{Name: "litellm-live-policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: PolicyConfigMapName}}}},
					{Name: "litellm-live-status", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "status-secret"}}}}},
			Status: corev1.PodStatus{PodIP: ip, ContainerStatuses: []corev1.ContainerStatus{
				{Name: "litellm", ImageID: "backend@sha256:" + strings.Repeat(string(rune('d'+i)), 64), Ready: true},
				{Name: GatewayContainerName, ImageID: gatewayImage, Ready: true}}}}
		objects = append(objects, p)
	}
	ready := true
	port := int32(4001)
	endpoints := []discoveryv1.Endpoint{}
	for i, name := range []string{"litellm-a", "litellm-b"} {
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{"10.1.0." + string(rune('1'+i))},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: name, UID: types.UID("pod-" + string(rune('a'+i)))}})
	}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "litellm-slice", Namespace: Namespace,
		Labels: map[string]string{discoveryv1.LabelServiceName: ServiceName}},
		Ports: []discoveryv1.EndpointPort{{Port: &port}}, Endpoints: endpoints}
	objects = append(objects, slice)
	scheme := runtime.NewScheme()
	if e = corev1.AddToScheme(scheme); e != nil {
		t.Fatal(e)
	}
	if e = discoveryv1.AddToScheme(scheme); e != nil {
		t.Fatal(e)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(), attacker
}

func TestOwnedClientLiveExactGatewayAndEndpointGraph(t *testing.T) {
	ctx := context.Background()
	c, attacker := liveFixture(t)
	approvedGatewayImage := "gateway@sha256:" + strings.Repeat("c", 64)
	if _, e := ValidateLive(ctx, c, "pod-a", "pod-b"); e == nil {
		t.Fatal("unreviewed gateway image accepted")
	}
	got, e := validateLive(ctx, c, "pod-a", "pod-b", approvedGatewayImage)
	if e != nil || len(got.Pods) != 2 || got.ClientSHA256 != attacker || got.State.Active {
		t.Fatalf("valid graph: %+v %v", got, e)
	}
	for _, tc := range []struct {
		name   string
		mutate func(client.Client)
	}{
		{"source-change", func(c client.Client) {
			o := &corev1.ConfigMap{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: SourceConfigMapName}, o)
			o.Data[SourceKey] += "\n"
			_ = c.Update(ctx, o)
		}},
		{"policy-other-client", func(c client.Client) {
			o := &corev1.ConfigMap{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: PolicyConfigMapName}, o)
			o.Data[PolicyKey] = strings.Replace(o.Data[PolicyKey], attacker, strings.Repeat("c", 64), 1)
			_ = c.Update(ctx, o)
		}},
		{"sidecar-not-ready", func(c client.Client) {
			o := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, o)
			o.Status.ContainerStatuses[1].Ready = false
			_ = c.Status().Update(ctx, o)
		}},
		{"sidecar-image-drift", func(c client.Client) {
			o := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, o)
			o.Spec.Containers[1].Image = "gateway@sha256:" + strings.Repeat("e", 64)
			_ = c.Update(ctx, o)
		}},
		{"sidecar-runtime-drift", func(c client.Client) {
			o := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, o)
			o.Status.ContainerStatuses[1].ImageID = "gateway@sha256:" + strings.Repeat("e", 64)
			_ = c.Status().Update(ctx, o)
		}},
		{"sidecar-annotation-drift", func(c client.Client) {
			o := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, o)
			o.Annotations[GatewayImageAnnotation] = "gateway@sha256:" + strings.Repeat("e", 64)
			_ = c.Update(ctx, o)
		}},
		{"endpoint-wrong-ip", func(c client.Client) {
			o := &discoveryv1.EndpointSlice{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-slice"}, o)
			o.Endpoints[0].Addresses = []string{"10.9.9.9"}
			_ = c.Update(ctx, o)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := liveFixture(t)
			tc.mutate(c)
			if _, e := validateLive(ctx, c, "pod-a", "pod-b", approvedGatewayImage); e == nil {
				t.Fatal("drift accepted")
			}
		})
	}
	if _, e := validateLive(ctx, c, "pod-a", "wrong-peer", approvedGatewayImage); e == nil {
		t.Fatal("wrong peer accepted")
	}
}
