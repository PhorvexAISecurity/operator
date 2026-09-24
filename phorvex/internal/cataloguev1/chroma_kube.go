package cataloguev1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

type chromaKubeTransport struct{ runtime Runtime }

func newChromaKubeTransport(r Runtime) (chromaTransport, error) {
	if r.Kube == nil || r.RESTConfig == nil {
		return nil, errors.New("Chroma Kubernetes transport unavailable")
	}
	return chromaKubeTransport{runtime: r}, nil
}

func (t chromaKubeTransport) snapshot(ctx context.Context, c ChromaRuntime) (chromaAuthority, error) {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ctx = bounded
	k := t.runtime.Kube
	d, err := k.AppsV1().Deployments(c.Namespace).Get(ctx, c.Deployment, metav1.GetOptions{})
	if err != nil {
		return chromaAuthority{}, err
	}
	if d.UID == "" || d.DeletionTimestamp != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || d.Status.ObservedGeneration != d.Generation || d.Status.ReadyReplicas != 1 || d.Spec.Selector == nil || len(d.Spec.Selector.MatchLabels) != 1 || d.Spec.Selector.MatchLabels["app"] != "chroma" || len(d.Spec.Selector.MatchExpressions) != 0 {
		return chromaAuthority{}, errors.New("Chroma Deployment authority differs")
	}
	pods, err := k.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=chroma"})
	if err != nil {
		return chromaAuthority{}, err
	}
	if len(pods.Items) != 1 {
		return chromaAuthority{}, errors.New("Chroma serving Pod cardinality differs")
	}
	p := &pods.Items[0]
	if p.UID == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || len(p.Spec.Containers) != 1 || len(p.Status.ContainerStatuses) != 1 || p.Spec.Containers[0].Name != c.Container {
		return chromaAuthority{}, errors.New("Chroma Pod identity differs")
	}
	ready := false
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	s := p.Status.ContainerStatuses[0]
	if !ready || s.Name != c.Container || !s.Ready || s.ContainerID == "" || s.ImageID != c.ExpectedImageID {
		return chromaAuthority{}, errors.New("Chroma Pod container differs")
	}
	if len(p.OwnerReferences) != 1 || p.OwnerReferences[0].Kind != "ReplicaSet" || p.OwnerReferences[0].UID == "" || p.OwnerReferences[0].Controller == nil || !*p.OwnerReferences[0].Controller {
		return chromaAuthority{}, errors.New("Chroma Pod owner differs")
	}
	rs, err := k.AppsV1().ReplicaSets(c.Namespace).Get(ctx, p.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return chromaAuthority{}, err
	}
	if rs.UID != p.OwnerReferences[0].UID || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].Kind != "Deployment" || rs.OwnerReferences[0].Name != c.Deployment || rs.OwnerReferences[0].UID != d.UID || rs.OwnerReferences[0].Controller == nil || !*rs.OwnerReferences[0].Controller {
		return chromaAuthority{}, errors.New("Chroma ReplicaSet owner differs")
	}
	svc, err := k.CoreV1().Services(c.Namespace).Get(ctx, c.Service, metav1.GetOptions{})
	if err != nil {
		return chromaAuthority{}, err
	}
	if svc.UID == "" || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) != 1 || svc.Spec.Selector["app"] != "chroma" || len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != c.Port || svc.Spec.Ports[0].Protocol != corev1.ProtocolTCP || svc.Spec.Ports[0].TargetPort.IntVal != c.Port {
		return chromaAuthority{}, errors.New("Chroma Service route differs")
	}
	slices, err := k.DiscoveryV1().EndpointSlices(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + c.Service})
	if err != nil {
		return chromaAuthority{}, err
	}
	if len(slices.Items) != 1 {
		return chromaAuthority{}, errors.New("Chroma EndpointSlice cardinality differs")
	}
	slice := &slices.Items[0]
	if slice.UID == "" || slice.DeletionTimestamp != nil || slice.Labels[discoveryv1.LabelServiceName] != c.Service || len(slice.Ports) != 1 || slice.Ports[0].Port == nil || *slice.Ports[0].Port != c.Port || slice.Ports[0].Protocol == nil || *slice.Ports[0].Protocol != corev1.ProtocolTCP || len(slice.Endpoints) != 1 {
		return chromaAuthority{}, errors.New("Chroma EndpointSlice route differs")
	}
	owned := false
	for _, owner := range slice.OwnerReferences {
		if owner.Kind == "Service" && owner.Name == c.Service && owner.UID == svc.UID && owner.Controller != nil && *owner.Controller {
			owned = true
		}
	}
	ep := slice.Endpoints[0]
	if !owned || ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.Namespace != c.Namespace || ep.TargetRef.Name != p.Name || ep.TargetRef.UID != p.UID || ep.Conditions.Ready == nil || !*ep.Conditions.Ready || ep.Conditions.Terminating != nil && *ep.Conditions.Terminating || len(ep.Addresses) != 1 || ep.Addresses[0] != p.Status.PodIP {
		return chromaAuthority{}, errors.New("Chroma EndpointSlice target differs")
	}
	return chromaAuthority{PodName: p.Name, PodUID: string(p.UID), ContainerID: s.ContainerID, ImageID: s.ImageID, RestartCount: s.RestartCount, DeploymentUID: string(d.UID), ReplicaSetUID: string(rs.UID), ServiceUID: string(svc.UID), SliceUID: string(slice.UID), PodIP: p.Status.PodIP, DeploymentGeneration: d.Generation}, nil
}

const chromaPinScript = `import hashlib,pathlib
r=pathlib.Path('/chroma/chromadb')
p=[('__init__.py','5458a79347d19a5d15966a76a3a5e02bdac384ef670ff0612cc93fc788c41f44'),('server/fastapi/__init__.py','8dae4ea1f3357edf75ac446bbe0e3973151a542dc6de184c7be3b6be82925c41'),('server/fastapi/types.py','2b6ec7c5796309be91f9af97e3bb4379a42652550146b2dda226c801894570b1')]
print('PIN_OK' if all(hashlib.sha256((r/f).read_bytes()).hexdigest()==h for f,h in p) else 'PIN_DIFF')`

func (t chromaKubeTransport) sourcePin(ctx context.Context, c ChromaRuntime, a chromaAuthority) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req := t.runtime.Kube.CoreV1().RESTClient().Post().Resource("pods").Name(a.PodName).Namespace(c.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: c.Container, Command: []string{"python", "-c", chromaPinScript}, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(t.runtime.RESTConfig, http.MethodPost, req.URL())
	if err != nil {
		return errors.New("Chroma source pin exec unavailable")
	}
	var stdout, stderr limitedVoiceBuffer
	stdout.limit, stderr.limit = 64, 64
	if executor.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}) != nil || stdout.String() != "PIN_OK\n" {
		return errors.New("Chroma installed source changed")
	}
	return nil
}

// This script runs only in the exact serving Pod and sends application HTTP to
// localhost. Kubernetes credentials stay on the SPDY exec control connection.
// http.client never follows redirects; each invocation makes one request.
const chromaRequestScript = `import base64,http.client,json,signal,sys
def expired(_s,_f): raise TimeoutError('absolute deadline')
signal.signal(signal.SIGALRM,expired);signal.alarm(10)
q=json.loads(sys.argv[1]);body=base64.b64decode(q['body']) if q['body'] else None
c=http.client.HTTPConnection('127.0.0.1',8000,timeout=5)
try:
 c.request(q['method'],q['path'],body=body,headers={'Content-Type':'application/json'} if body is not None else {})
 r=c.getresponse();raw=r.read(8193)
 if len(raw)>8192: raise ValueError('response bound')
 print(json.dumps({'status':r.status,'body':base64.b64encode(raw).decode('ascii')},separators=(',',':')))
finally:c.close()`

func chromaExecCommand(method, path string, body []byte) ([]string, error) {
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete || len(body) > 2048 || !chromaAllowedRoute(method, path) {
		return nil, errors.New("Chroma request outside fixed route set")
	}
	arg, err := json.Marshal(map[string]string{"method": method, "path": path, "body": base64.StdEncoding.EncodeToString(body)})
	if err != nil {
		return nil, err
	}
	return []string{"python", "-c", chromaRequestScript, string(arg)}, nil
}

func (t chromaKubeTransport) call(ctx context.Context, c ChromaRuntime, a chromaAuthority, method, path string, body []byte) (chromaResponse, error) {
	command, err := chromaExecCommand(method, path, body)
	if err != nil {
		return chromaResponse{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req := t.runtime.Kube.CoreV1().RESTClient().Post().Resource("pods").Name(a.PodName).Namespace(c.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: c.Container, Command: command, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(t.runtime.RESTConfig, http.MethodPost, req.URL())
	if err != nil {
		return chromaResponse{}, errors.New("Chroma exec transport unavailable")
	}
	var stdout, stderr limitedVoiceBuffer
	stdout.limit, stderr.limit = 12000, 256
	if executor.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}) != nil {
		return chromaResponse{}, errors.New("Chroma request outcome unknown")
	}
	var receipt struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if json.Unmarshal([]byte(stdout.String()), &receipt) != nil || receipt.Status < 100 || receipt.Status > 599 {
		return chromaResponse{}, errors.New("Chroma request receipt malformed")
	}
	raw, err := base64.StdEncoding.DecodeString(receipt.Body)
	if err != nil || len(raw) > 8192 {
		return chromaResponse{}, errors.New("Chroma request response bound exceeded")
	}
	if receipt.Status >= 300 && receipt.Status < 400 {
		return chromaResponse{}, errors.New("Chroma redirect refused")
	}
	return chromaResponse{Status: receipt.Status, Body: raw}, nil
}

func chromaAllowedRoute(method, path string) bool {
	if method == http.MethodGet && path == "/api/v2/version" {
		return true
	}
	if method == http.MethodPost && path == chromaBase {
		return true
	}
	if !strings.HasPrefix(path, chromaBase+"/") {
		return false
	}
	part := strings.TrimPrefix(path, chromaBase+"/")
	if strings.HasPrefix(part, "cat-chroma-") && len(part) == len("cat-chroma-")+24 && strings.Trim(part[len("cat-chroma-"):], "0123456789abcdef") == "" {
		return method == http.MethodGet || method == http.MethodDelete
	}
	if len(part) < 36 || !chromaUUID.MatchString(part[:36]) {
		return false
	}
	suffix := part[36:]
	return method == http.MethodPost && (suffix == "/add" || suffix == "/get" || suffix == "/query")
}
