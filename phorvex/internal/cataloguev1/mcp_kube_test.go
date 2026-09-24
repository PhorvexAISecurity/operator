package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func mcpSnapshotFixture(t *testing.T) (mcpKubeTransport, MCPSessionRuntime) {
	t.Helper()
	cfg := mcpTestConfig()
	source := "fixed synthetic MCP source\n"
	sum := sha256.Sum256([]byte(source))
	cfg.ExpectedSourceSHA256 = hex.EncodeToString(sum[:])
	one := int32(1)
	port := int32(8000)
	yes := true
	no := false
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: cfg.Deployment, Namespace: cfg.Namespace, UID: types.UID("deploy-uid"), Generation: 3},
		Spec:   appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "mcp-server"}}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 3, ReadyReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "mcp-server-rs", Namespace: cfg.Namespace, UID: types.UID("rs-uid"), OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: cfg.Deployment, UID: deploy.UID, Controller: &yes}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mcp-server-pod", Namespace: cfg.Namespace, UID: types.UID("pod-uid"), Labels: map[string]string{"app": "mcp-server"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: cfg.Container, VolumeMounts: []corev1.VolumeMount{{Name: "code", MountPath: "/app"}}}}, Volumes: []corev1.Volume{{Name: "code", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cfg.SourceConfigMap}}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.7", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: cfg.Container, Ready: true, ImageID: cfg.ExpectedImageID, ContainerID: "containerd://fixed", RestartCount: 0}}}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: cfg.Service, Namespace: cfg.Namespace, UID: types.UID("service-uid")}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "mcp-server"}, Ports: []corev1.ServicePort{{Port: port, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(port)}}}}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "mcp-server-a", Namespace: cfg.Namespace, UID: types.UID("slice-uid"), Labels: map[string]string{discoveryv1.LabelServiceName: cfg.Service}, OwnerReferences: []metav1.OwnerReference{{Kind: "Service", Name: cfg.Service, UID: service.UID, Controller: &yes}}},
		Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: ptrProtocol(corev1.ProtocolTCP)}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{pod.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes, Terminating: &no}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: cfg.Namespace, Name: pod.Name, UID: pod.UID}}}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cfg.SourceConfigMap, Namespace: cfg.Namespace, UID: types.UID("source-uid"), ResourceVersion: "7"}, Data: map[string]string{cfg.SourceKey: source}}
	client := fake.NewSimpleClientset(deploy, rs, pod, service, slice, cm)
	return mcpKubeTransport{runtime: Runtime{Kube: client}}, cfg
}

func TestMCPSnapshotBindsRealKubernetesOwnerRouteAndSource(t *testing.T) {
	ctx := context.Background()
	f, cfg := mcpSnapshotFixture(t)
	before, err := f.snapshot(ctx, cfg)
	if err != nil || before.PodUID != "pod-uid" || before.SourceSHA != cfg.ExpectedSourceSHA256 || before.ServiceUID != "service-uid" {
		t.Fatalf("fixed source/route rejected: %+v %v", before, err)
	}
	cm, err := f.runtime.Kube.CoreV1().ConfigMaps(cfg.Namespace).Get(ctx, cfg.SourceConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data[cfg.SourceKey] = "changed"
	if _, err = f.runtime.Kube.CoreV1().ConfigMaps(cfg.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.snapshot(ctx, cfg); err == nil {
		t.Fatal("source drift admitted")
	}
}

func TestMCPSnapshotRejectsWrongEndpointAndImage(t *testing.T) {
	ctx := context.Background()
	f, cfg := mcpSnapshotFixture(t)
	slice, err := f.runtime.Kube.DiscoveryV1().EndpointSlices(cfg.Namespace).Get(ctx, "mcp-server-a", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	slice.Endpoints[0].TargetRef.UID = types.UID("foreign")
	if _, err = f.runtime.Kube.DiscoveryV1().EndpointSlices(cfg.Namespace).Update(ctx, slice, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.snapshot(ctx, cfg); err == nil {
		t.Fatal("foreign endpoint admitted")
	}
	f, cfg = mcpSnapshotFixture(t)
	pod, err := f.runtime.Kube.CoreV1().Pods(cfg.Namespace).Get(ctx, "mcp-server-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Status.ContainerStatuses[0].ImageID = "foreign-image"
	if _, err = f.runtime.Kube.CoreV1().Pods(cfg.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.snapshot(ctx, cfg); err == nil {
		t.Fatal("foreign image admitted")
	}
}

func TestMCPProxyUsesOnlyPinnedPodPathAndDoesNotFollowRedirect(t *testing.T) {
	cfg := mcpTestConfig()
	a := mcpAuthority{PodName: "mcp-server-pod", PodUID: "pod-uid"}
	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.URL.Path != "/api/v1/namespaces/mcp/pods/http:mcp-server-pod:8000/proxy/mcp" || r.Method != http.MethodPost ||
			r.Header.Get("MCP-Protocol-Version") != mcpProtocolVersion || r.Header.Get("Mcp-Session-Id") != "0123456789abcdef0123456789abcdef" {
			t.Errorf("proxy path/headers widened: %s %s %+v", r.Method, r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "0123456789abcdef0123456789abcdef")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`))
	}))
	defer server.Close()
	transport := mcpKubeTransport{runtime: Runtime{RESTConfig: &rest.Config{Host: server.URL}}}
	r, e := transport.call(context.Background(), cfg, a, http.MethodPost, mcpRPC(2, "tools/list", map[string]any{}), "0123456789abcdef0123456789abcdef")
	if e != nil || seen != 1 || r.Status != 200 || r.ContentType != "application/json" {
		t.Fatalf("fixed Pod proxy refused: %+v %v calls=%d", r, e, seen)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/foreign", 302)
	}))
	defer redirect.Close()
	transport.runtime.RESTConfig.Host = redirect.URL
	if _, e = transport.call(context.Background(), cfg, a, http.MethodPost, mcpRPC(2, "tools/list", map[string]any{}), ""); e == nil || !strings.Contains(e.Error(), "ambiguous") {
		t.Fatalf("redirect accepted or misclassified: %v", e)
	}
	if _, e = transport.call(context.Background(), cfg, a, http.MethodGet, nil, ""); e == nil {
		t.Fatal("arbitrary proxy verb accepted")
	}
}
