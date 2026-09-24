package cataloguev1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func chromaKubeFixture() (chromaKubeTransport, ChromaRuntime) {
	c := ChromaRuntime{Enabled: true, Namespace: "document-store", Deployment: "chroma", Service: "chroma", Container: "chroma", Port: 8000, ExpectedImageID: chromaImageID, ExpectedVersionSourceSHA256: chromaVersionSHA, ExpectedServerSourceSHA256: chromaServerSHA, ExpectedSchemaSourceSHA256: chromaSchemaSHA}
	one, port := int32(1), int32(8000)
	yes, no := true, false
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: c.Deployment, Namespace: c.Namespace, UID: types.UID("deployment-uid"), Generation: 2}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "chroma"}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 2, ReadyReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "chroma-rs", Namespace: c.Namespace, UID: types.UID("rs-uid"), OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: &yes}}}}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "chroma-pod", Namespace: c.Namespace, UID: types.UID("pod-uid"), Labels: map[string]string{"app": "chroma"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: c.Container}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.8", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: c.Container, Ready: true, ImageID: chromaImageID, ContainerID: "containerd://one"}}}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: c.Service, Namespace: c.Namespace, UID: types.UID("service-uid")}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "chroma"}, Ports: []corev1.ServicePort{{Port: port, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(port)}}}}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "chroma-slice", Namespace: c.Namespace, UID: types.UID("slice-uid"), Labels: map[string]string{discoveryv1.LabelServiceName: c.Service}, OwnerReferences: []metav1.OwnerReference{{Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: &yes}}}, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: ptrProtocol(corev1.ProtocolTCP)}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{p.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes, Terminating: &no}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: c.Namespace, Name: p.Name, UID: p.UID}}}}
	return chromaKubeTransport{runtime: Runtime{Kube: fake.NewSimpleClientset(d, rs, p, svc, slice)}}, c
}

func TestChromaKubeAuthorityRejectsRouteAndIdentityDrift(t *testing.T) {
	ctx := context.Background()
	transport, c := chromaKubeFixture()
	a, err := transport.snapshot(ctx, c)
	if err != nil || a.PodUID != "pod-uid" || a.ServiceUID != "service-uid" {
		t.Fatalf("valid producer rejected: %+v %v", a, err)
	}
	slice, err := transport.runtime.Kube.DiscoveryV1().EndpointSlices(c.Namespace).Get(ctx, "chroma-slice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	slice.Endpoints[0].TargetRef.UID = types.UID("foreign")
	if _, err = transport.runtime.Kube.DiscoveryV1().EndpointSlices(c.Namespace).Update(ctx, slice, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = transport.snapshot(ctx, c); err == nil {
		t.Fatal("foreign EndpointSlice Pod admitted")
	}
	transport, c = chromaKubeFixture()
	p, err := transport.runtime.Kube.CoreV1().Pods(c.Namespace).Get(ctx, "chroma-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Status.ContainerStatuses[0].ImageID = "foreign-image"
	if _, err = transport.runtime.Kube.CoreV1().Pods(c.Namespace).UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = transport.snapshot(ctx, c); err == nil {
		t.Fatal("foreign container image admitted")
	}
}

func TestChromaExecLoopbackDoesNotForwardKubernetesBearer(t *testing.T) {
	seen := 0
	redirect := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.URL.Path != "/api/v2/version" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			t.Errorf("loopback route or auth header differs: %s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		if redirect {
			http.Redirect(w, r, "http://example.invalid/foreign", 302)
			return
		}
		w.Write([]byte(`"0.5.23"`))
	}))
	defer s.Close()
	command, err := chromaExecCommand(http.MethodGet, "/api/v2/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Replace(command[2], ",8000,timeout=5", ","+u.Port()+",timeout=5", 1)
	output, err := exec.CommandContext(context.Background(), "python3", command[1], script, command[3]).Output()
	if err != nil {
		t.Fatalf("loopback producer failed: %v", err)
	}
	var receipt struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if json.Unmarshal(output, &receipt) != nil {
		t.Fatalf("malformed producer receipt: %q", output)
	}
	body, err := base64.StdEncoding.DecodeString(receipt.Body)
	if err != nil || receipt.Status != 200 || string(body) != `"0.5.23"` || seen != 1 {
		t.Fatalf("producer response differs: status=%d body=%q calls=%d err=%v", receipt.Status, body, seen, err)
	}
	redirect = true
	output, err = exec.CommandContext(context.Background(), "python3", command[1], script, command[3]).Output()
	if err != nil || json.Unmarshal(output, &receipt) != nil || receipt.Status != 302 || seen != 2 {
		t.Fatalf("redirect followed or response lost: status=%d calls=%d err=%v", receipt.Status, seen, err)
	}
	if _, err = chromaExecCommand(http.MethodGet, chromaBase, nil); err == nil {
		t.Fatal("collection listing accepted")
	}
	if _, err = chromaExecCommand(http.MethodPost, "https://foreign.invalid/", nil); err == nil {
		t.Fatal("foreign route accepted")
	}
	if strings.Contains(script, "Authorization") || strings.Contains(command[3], "Bearer") {
		t.Fatal("authorization reached application request")
	}
}
