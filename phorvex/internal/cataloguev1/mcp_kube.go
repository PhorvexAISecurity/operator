package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type mcpKubeTransport struct{ runtime Runtime }

func newMCPKubeTransport(r Runtime) (mcpTransport, error) {
	if r.Kube == nil || r.RESTConfig == nil {
		return nil, errors.New("Kubernetes MCP runtime unavailable")
	}
	return mcpKubeTransport{runtime: r}, nil
}

func (t mcpKubeTransport) snapshot(ctx context.Context, c MCPSessionRuntime) (mcpAuthority, error) {
	k := t.runtime.Kube
	deploy, err := k.AppsV1().Deployments(c.Namespace).Get(ctx, c.Deployment, metav1.GetOptions{})
	if err != nil {
		return mcpAuthority{}, err
	}
	if deploy.UID == "" || deploy.DeletionTimestamp != nil || deploy.Spec.Replicas == nil || *deploy.Spec.Replicas != 1 || deploy.Status.ObservedGeneration != deploy.Generation || deploy.Status.ReadyReplicas != 1 ||
		deploy.Spec.Selector == nil || len(deploy.Spec.Selector.MatchLabels) != 1 || deploy.Spec.Selector.MatchLabels["app"] != "mcp-server" || len(deploy.Spec.Selector.MatchExpressions) != 0 {
		return mcpAuthority{}, errors.New("MCP Deployment authority differs")
	}
	selector := "app=mcp-server"
	pods, err := k.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return mcpAuthority{}, err
	}
	if len(pods.Items) != 1 {
		return mcpAuthority{}, errors.New("MCP Pod cardinality differs")
	}
	p := &pods.Items[0]
	if p.UID == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || len(p.Status.ContainerStatuses) != 1 || len(p.Spec.Containers) != 1 || p.Spec.Containers[0].Name != c.Container {
		return mcpAuthority{}, errors.New("MCP Pod identity differs")
	}
	ready := false
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	s := p.Status.ContainerStatuses[0]
	if !ready || s.Name != c.Container || !s.Ready || s.ContainerID == "" || s.ImageID != c.ExpectedImageID {
		return mcpAuthority{}, errors.New("MCP Pod readiness or image differs")
	}
	if len(p.OwnerReferences) != 1 || p.OwnerReferences[0].Kind != "ReplicaSet" || p.OwnerReferences[0].UID == "" || p.OwnerReferences[0].Controller == nil || !*p.OwnerReferences[0].Controller {
		return mcpAuthority{}, errors.New("MCP Pod ReplicaSet owner differs")
	}
	rs, err := k.AppsV1().ReplicaSets(c.Namespace).Get(ctx, p.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return mcpAuthority{}, err
	}
	if rs.UID != p.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].Kind != "Deployment" || rs.OwnerReferences[0].Name != c.Deployment || rs.OwnerReferences[0].UID != deploy.UID || rs.DeletionTimestamp != nil {
		return mcpAuthority{}, errors.New("MCP ReplicaSet Deployment owner differs")
	}
	service, err := k.CoreV1().Services(c.Namespace).Get(ctx, c.Service, metav1.GetOptions{})
	if err != nil {
		return mcpAuthority{}, err
	}
	if service.UID == "" || service.DeletionTimestamp != nil || len(service.Spec.Selector) != 1 || service.Spec.Selector["app"] != "mcp-server" || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != c.Port || service.Spec.Ports[0].Protocol != corev1.ProtocolTCP || service.Spec.Ports[0].TargetPort.IntVal != c.Port {
		return mcpAuthority{}, errors.New("MCP Service route differs")
	}
	slices, err := k.DiscoveryV1().EndpointSlices(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + c.Service})
	if err != nil {
		return mcpAuthority{}, err
	}
	if len(slices.Items) != 1 {
		return mcpAuthority{}, errors.New("MCP EndpointSlice cardinality differs")
	}
	slice := &slices.Items[0]
	if slice.UID == "" || slice.DeletionTimestamp != nil || slice.Labels[discoveryv1.LabelServiceName] != c.Service || len(slice.Ports) != 1 || slice.Ports[0].Port == nil || *slice.Ports[0].Port != c.Port || slice.Ports[0].Protocol == nil || *slice.Ports[0].Protocol != corev1.ProtocolTCP || len(slice.Endpoints) != 1 {
		return mcpAuthority{}, errors.New("MCP EndpointSlice route differs")
	}
	owned := false
	for _, ref := range slice.OwnerReferences {
		if ref.Kind == "Service" && ref.Name == c.Service && ref.UID == service.UID && ref.Controller != nil && *ref.Controller {
			owned = true
		}
	}
	ep := slice.Endpoints[0]
	if !owned || ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.Namespace != c.Namespace || ep.TargetRef.Name != p.Name || ep.TargetRef.UID != p.UID || ep.Conditions.Ready == nil || !*ep.Conditions.Ready || ep.Conditions.Terminating != nil && *ep.Conditions.Terminating || len(ep.Addresses) != 1 || ep.Addresses[0] != p.Status.PodIP {
		return mcpAuthority{}, errors.New("MCP EndpointSlice target differs")
	}
	container := p.Spec.Containers[0]
	volumeName := ""
	for _, mount := range container.VolumeMounts {
		if mount.MountPath == "/app" && mount.SubPath == "" && mount.SubPathExpr == "" {
			volumeName = mount.Name
		}
		if mount.MountPath == "/app/server.py" || strings.HasPrefix(mount.MountPath, "/app/server.py/") {
			return mcpAuthority{}, errors.New("MCP source path shadowed")
		}
	}
	if volumeName == "" {
		return mcpAuthority{}, errors.New("MCP source mount absent")
	}
	volumeOK := false
	for _, v := range p.Spec.Volumes {
		if v.Name == volumeName && v.ConfigMap != nil && v.ConfigMap.Name == c.SourceConfigMap {
			if len(v.ConfigMap.Items) > 0 {
				projected := false
				for _, item := range v.ConfigMap.Items {
					if item.Key == c.SourceKey && item.Path == c.SourceKey {
						projected = true
					}
				}
				if !projected {
					return mcpAuthority{}, errors.New("MCP source key is not projected at the serving path")
				}
			}
			volumeOK = true
		}
	}
	if !volumeOK {
		return mcpAuthority{}, errors.New("MCP source mount authority differs")
	}
	cm, err := k.CoreV1().ConfigMaps(c.Namespace).Get(ctx, c.SourceConfigMap, metav1.GetOptions{})
	if err != nil {
		return mcpAuthority{}, err
	}
	source, ok := cm.Data[c.SourceKey]
	if !ok || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
		return mcpAuthority{}, errors.New("MCP source ConfigMap unavailable")
	}
	hash := sha256.Sum256([]byte(source))
	if hex.EncodeToString(hash[:]) != c.ExpectedSourceSHA256 {
		return mcpAuthority{}, errors.New("MCP source ConfigMap hash differs")
	}
	return mcpAuthority{PodName: p.Name, PodUID: string(p.UID), ContainerID: s.ContainerID, ImageID: s.ImageID, RestartCount: s.RestartCount,
		DeployUID: string(deploy.UID), DeployGeneration: deploy.Generation, ServiceUID: string(service.UID), SliceUID: string(slice.UID),
		SourceUID: string(cm.UID), SourceRV: cm.ResourceVersion, SourceSHA: hex.EncodeToString(hash[:])}, nil
}

// This fixed read-only process check hashes installed files and package versions.
// It emits one constant word; no application source, environment or credentials.
const mcpPinScript = `import hashlib,importlib.metadata,pathlib
root=pathlib.Path('/usr/local/lib/python3.11/site-packages')
files=[('/app/server.py','483009cd01640e9f604a21f16aa890539566f53a25fd7dc478bc43c1831212c5'),(str(root/'fastmcp/server/http.py'),'62fcacc9e3cb440132176a723dee224a879247223954b53f462244f90bdacce8'),(str(root/'fastmcp/settings.py'),'59780d8e9be7b3185d726c604378ce482a9bc80ab0eb86b8918a4aeef81c3954'),(str(root/'mcp/server/streamable_http.py'),'b184f85a99c9bd3aacc8232f6ccd2cc24cbfd3964ecb23ab2c9565d9aa38b225')]
ok=all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==s for p,s in files)
ok=ok and importlib.metadata.version('fastmcp')=='3.4.7' and importlib.metadata.version('mcp')=='1.29.0'
print('PIN_OK' if ok else 'PIN_DIFF')`

func (t mcpKubeTransport) installedSourcePin(ctx context.Context, c MCPSessionRuntime, a mcpAuthority) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req := t.runtime.Kube.CoreV1().RESTClient().Post().Resource("pods").Name(a.PodName).Namespace(c.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: c.Container, Command: []string{"python", "-c", mcpPinScript}, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(t.runtime.RESTConfig, http.MethodPost, req.URL())
	if err != nil {
		return errors.New("MCP source pin exec unavailable")
	}
	var stdout, stderr limitedVoiceBuffer
	stdout.limit, stderr.limit = 64, 64
	if executor.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}) != nil || stdout.String() != "PIN_OK\n" {
		return errors.New("MCP installed source or protocol pin differs")
	}
	return nil
}

func (t mcpKubeTransport) call(ctx context.Context, c MCPSessionRuntime, a mcpAuthority, method string, body []byte, session string) (mcpWireResponse, error) {
	if method != http.MethodPost && method != http.MethodDelete {
		return mcpWireResponse{}, errors.New("unsupported MCP proxy method")
	}
	if session != "" && !mcpSessionPattern.MatchString(session) {
		return mcpWireResponse{}, errors.New("MCP session header invalid")
	}
	if len(body) > 2048 {
		return mcpWireResponse{}, errors.New("MCP request bound")
	}
	base, err := url.Parse(t.runtime.RESTConfig.Host)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return mcpWireResponse{}, errors.New("Kubernetes API origin invalid")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/namespaces/" + c.Namespace + "/pods/http:" + a.PodName + ":" + strconv.Itoa(int(c.Port)) + "/proxy/mcp"
	requestCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, base.String(), bytes.NewReader(body))
	if err != nil {
		return mcpWireResponse{}, errors.New("MCP proxy request invalid")
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	client, err := rest.HTTPClientFor(t.runtime.RESTConfig)
	if err != nil {
		return mcpWireResponse{}, errors.New("Kubernetes proxy transport unavailable")
	}
	client.Timeout = 4 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("MCP proxy redirect refused") }
	resp, err := client.Do(req)
	if err != nil {
		return mcpWireResponse{}, errors.New("MCP proxy outcome ambiguous")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, mcpMaxResponse+1))
	if err != nil || len(data) > mcpMaxResponse {
		return mcpWireResponse{}, errors.New("MCP proxy response bound exceeded")
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	return mcpWireResponse{Status: resp.StatusCode, ContentType: contentType, SessionID: resp.Header.Get("Mcp-Session-Id"), Body: data}, nil
}
