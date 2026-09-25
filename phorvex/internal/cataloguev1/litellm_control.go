package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// LiteLLMRuntime is deployment-owned authority. None of these values comes
// from a launch request. The expected config digest is the reviewed round 7/9
// config, whose master-key reference is never exported by this control.
type LiteLLMRuntime struct {
	Enabled              bool   `json:"enabled"`
	Namespace            string `json:"namespace"`
	Deployment           string `json:"deployment"`
	Service              string `json:"service"`
	Container            string `json:"container"`
	Port                 int32  `json:"port"`
	ConfigMap            string `json:"configMap"`
	ConfigKey            string `json:"configKey"`
	ExpectedConfigSHA256 string `json:"expectedConfigSHA256"`
	InferenceEnabled     bool   `json:"inferenceEnabled,omitempty"`
	ModelAlias           string `json:"modelAlias,omitempty"`
}

const (
	liteConfigSHA   = "14ebebce3b18a492a7aadb5c011bfcd71d8d16d8e8745e305b4f2336664daafb"
	liteHealthPath  = "/health/liveliness"
	liteAuthPath    = "/v1/models"
	liteMaxBody     = 4096
	liteCallTimeout = 5 * time.Second
	liteHealthySHA  = "531eb97e0a03229b5b063cd6be4449bb5231ecbd28402be9186d8b8c84956d04"
)

type liteSource struct{ image, version, healthSHA, modelsSHA, authSHA string }

var liteSources = []liteSource{
	{"ghcr.io/berriai/litellm@sha256:af806882b7a6ced41658db5b6a7e98ed7b9b51d03b935e0417bf1c8552d688af", "1.95.0", "911e0f091249d8604ccddbb5b207e45a9b8da5fc6637fa3f0d0e4dcd5d104273", "3e4310c798ed86221bcd9b81336b04a1fca9bc128459d34c082a4042afe9f813", "ebd9d5a669689852f9c3ffe9cd90d25559051aa8ab9d313fe55ca003adb76842"},
	{"ghcr.io/berriai/litellm@sha256:20b5044b619055374061a6d5b7b08754cad75aeabbf82ddf4f69cc0cf80ddaf4", "1.98.0", "8bcd1f09bd847cadb01f83c0896d7857a8a111ff46a418c8b63deeabf95e7ddd", "14b954201801f7ef19df1f328dda37f489a03315b856f0dc43da8827d07669ec", "530269db4e3b1d8cf4a47529b3ede5d2c713fb7d3e8dc16bc4be48005586b1af"},
}

func ValidateLiteLLMRuntime(c LiteLLMRuntime) error {
	if !c.Enabled || c.Namespace != "litellm" || c.Deployment != "litellm" || c.Service != "litellm" || c.Container != "litellm" || c.Port != 4000 || c.ConfigMap != "litellm-config" || c.ConfigKey != "config.yaml" || c.ExpectedConfigSHA256 != liteConfigSHA {
		return errors.New("LiteLLM control disabled or differs from reviewed installed contract")
	}
	return nil
}

type liteHandler struct {
	profile   ProfileID
	transport liteTransport
}

func NewLiteLLMHealthHandler() Handler       { return liteHandler{profile: LiteLLMHealth} }
func NewLiteLLMCredentialHandler() Handler   { return liteHandler{profile: LiteLLMCredential} }
func (h liteHandler) Definition() Definition { d, _ := DefinitionFor(h.profile); return d }
func (h liteHandler) Validate(r Runtime) error {
	if err := ValidateLiteLLMRuntime(r.LiteLLM); err != nil {
		return err
	}
	if r.Kube == nil || r.RESTConfig == nil {
		return errors.New("LiteLLM Kubernetes transport unavailable")
	}
	return nil
}
func (h liteHandler) Reconcile(_ context.Context, _ JobContext, _ Journal) Cleanup {
	return Cleanup{Verified: true, Status: "no-mutation"}
}

type litePod struct {
	Name              string `json:"name"`
	UID               string `json:"uid"`
	ResourceVersion   string `json:"resourceVersion"`
	IP                string `json:"ip"`
	RSUID             string `json:"replicaSetUID"`
	ContainerID       string `json:"containerID"`
	ImageID           string `json:"imageID"`
	RestartCount      int32  `json:"restartCount"`
	MasterKeyDeclared bool   `json:"masterKeyDeclared"`
}
type liteAuthority struct {
	DeploymentUID        string    `json:"deploymentUID"`
	DeploymentRV         string    `json:"deploymentRV"`
	DeploymentGeneration int64     `json:"deploymentGeneration"`
	ServiceUID           string    `json:"serviceUID"`
	ServiceRV            string    `json:"serviceRV"`
	SliceUID             string    `json:"sliceUID"`
	SliceRV              string    `json:"sliceRV"`
	ConfigUID            string    `json:"configUID"`
	ConfigRV             string    `json:"configRV"`
	ConfigSHA            string    `json:"configSHA"`
	Pods                 []litePod `json:"pods"`
}

func (a liteAuthority) fingerprint() string {
	b, _ := json.Marshal(a)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type liteResponse struct {
	Status         int    `json:"status"`
	ContentType    string `json:"contentType"`
	BodySHA256     string `json:"bodySHA256"`
	BodyBytes      int    `json:"bodyBytes"`
	Reason         string `json:"reason"`
	ErrorClass     string `json:"errorClass"`
	ModelListShape bool   `json:"modelListShape"`
	BoundExceeded  bool   `json:"boundExceeded"`
}
type liteLimitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *liteLimitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		b.overflow = true
	}
	if remaining > 0 {
		_, _ = b.Buffer.Write(p[:min(len(p), remaining)])
	}
	return len(p), nil
}

type liteTransport interface {
	snapshot(context.Context, LiteLLMRuntime) (liteAuthority, error)
	sourcePin(context.Context, LiteLLMRuntime, litePod) error
	get(context.Context, LiteLLMRuntime, litePod, string, string) (liteResponse, error)
}
type liteKubeTransport struct{ runtime Runtime }

func (t liteKubeTransport) snapshot(ctx context.Context, c LiteLLMRuntime) (liteAuthority, error) {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ctx = bounded
	k := t.runtime.Kube
	d, e := k.AppsV1().Deployments(c.Namespace).Get(ctx, c.Deployment, metav1.GetOptions{})
	if e != nil {
		return liteAuthority{}, e
	}
	if d.UID == "" || d.ResourceVersion == "" || d.DeletionTimestamp != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 2 || d.Status.ObservedGeneration != d.Generation || d.Status.ReadyReplicas != 2 || d.Spec.Selector == nil || len(d.Spec.Selector.MatchLabels) != 1 || d.Spec.Selector.MatchLabels["app"] != "litellm" || len(d.Spec.Selector.MatchExpressions) != 0 {
		return liteAuthority{}, errors.New("LiteLLM Deployment authority differs")
	}
	svc, e := k.CoreV1().Services(c.Namespace).Get(ctx, c.Service, metav1.GetOptions{})
	if e != nil {
		return liteAuthority{}, e
	}
	if svc.UID == "" || svc.ResourceVersion == "" || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) != 1 || svc.Spec.Selector["app"] != "litellm" || len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != c.Port || svc.Spec.Ports[0].Protocol != corev1.ProtocolTCP || svc.Spec.Ports[0].TargetPort.IntVal != c.Port {
		return liteAuthority{}, errors.New("LiteLLM Service route differs")
	}
	cm, e := k.CoreV1().ConfigMaps(c.Namespace).Get(ctx, c.ConfigMap, metav1.GetOptions{})
	if e != nil {
		return liteAuthority{}, e
	}
	source, ok := cm.Data[c.ConfigKey]
	sum := sha256.Sum256([]byte(source))
	if !ok || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || hex.EncodeToString(sum[:]) != c.ExpectedConfigSHA256 {
		return liteAuthority{}, errors.New("LiteLLM ConfigMap identity, shape or digest differs")
	}
	pods, e := k.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=litellm"})
	if e != nil {
		return liteAuthority{}, e
	}
	if len(pods.Items) != 2 {
		return liteAuthority{}, errors.New("LiteLLM serving Pod cardinality differs")
	}
	slices, e := k.DiscoveryV1().EndpointSlices(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + c.Service})
	if e != nil {
		return liteAuthority{}, e
	}
	if len(slices.Items) != 1 {
		return liteAuthority{}, errors.New("LiteLLM EndpointSlice cardinality differs")
	}
	sl := &slices.Items[0]
	if sl.UID == "" || sl.ResourceVersion == "" || sl.DeletionTimestamp != nil || sl.Labels[discoveryv1.LabelServiceName] != c.Service || len(sl.Ports) != 1 || sl.Ports[0].Port == nil || *sl.Ports[0].Port != c.Port || sl.Ports[0].Protocol == nil || *sl.Ports[0].Protocol != corev1.ProtocolTCP || len(sl.Endpoints) != 2 {
		return liteAuthority{}, errors.New("LiteLLM EndpointSlice route differs")
	}
	if !liteOwned(sl.OwnerReferences, "Service", c.Service, string(svc.UID)) {
		return liteAuthority{}, errors.New("LiteLLM EndpointSlice Service owner differs")
	}
	a := liteAuthority{DeploymentUID: string(d.UID), DeploymentRV: d.ResourceVersion, DeploymentGeneration: d.Generation, ServiceUID: string(svc.UID), ServiceRV: svc.ResourceVersion, SliceUID: string(sl.UID), SliceRV: sl.ResourceVersion, ConfigUID: string(cm.UID), ConfigRV: cm.ResourceVersion, ConfigSHA: hex.EncodeToString(sum[:])}
	for _, p := range pods.Items {
		if p.UID == "" || p.ResourceVersion == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || len(p.Status.ContainerStatuses) != 1 || len(p.Spec.Containers) != 1 || p.Spec.Containers[0].Name != c.Container || !liteOwnedKind(p.OwnerReferences, "ReplicaSet") {
			return liteAuthority{}, errors.New("LiteLLM Pod identity or owner differs")
		}
		ready := false
		for _, condition := range p.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		status := p.Status.ContainerStatuses[0]
		if !ready || status.Name != c.Container || !status.Ready || status.ContainerID == "" || status.RestartCount < 0 || liteSourceFor(status.ImageID) == nil {
			return liteAuthority{}, errors.New("LiteLLM container readiness or installed image differs")
		}
		container := p.Spec.Containers[0]
		if len(container.Args) != 4 || container.Args[0] != "--config" || container.Args[1] != "/etc/litellm/config.yaml" || container.Args[2] != "--port" || container.Args[3] != "4000" {
			return liteAuthority{}, errors.New("LiteLLM process route arguments differ")
		}
		portOK := false
		for _, port := range container.Ports {
			if port.ContainerPort == c.Port && port.Protocol == corev1.ProtocolTCP {
				portOK = true
			}
		}
		if !portOK || !liteConfigMount(p.Spec, container, c.ConfigMap) {
			return liteAuthority{}, errors.New("LiteLLM container port or config mount differs")
		}
		owner := p.OwnerReferences[0]
		rs, e := k.AppsV1().ReplicaSets(c.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if e != nil {
			return liteAuthority{}, e
		}
		if rs.UID != owner.UID || rs.DeletionTimestamp != nil || !liteOwned(rs.OwnerReferences, "Deployment", c.Deployment, string(d.UID)) {
			return liteAuthority{}, errors.New("LiteLLM ReplicaSet owner differs")
		}
		epCount := 0
		for _, ep := range sl.Endpoints {
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" && ep.TargetRef.Namespace == c.Namespace && ep.TargetRef.Name == p.Name && ep.TargetRef.UID == p.UID && ep.Conditions.Ready != nil && *ep.Conditions.Ready && (ep.Conditions.Terminating == nil || !*ep.Conditions.Terminating) && len(ep.Addresses) == 1 && ep.Addresses[0] == p.Status.PodIP {
				epCount++
			}
		}
		if epCount != 1 {
			return liteAuthority{}, errors.New("LiteLLM Pod endpoint differs")
		}
		masterCount := 0
		for _, env := range container.Env {
			if env.Name == "LITELLM_MASTER_KEY" && env.ValueFrom == nil && env.Value != "" {
				masterCount++
			}
		}
		a.Pods = append(a.Pods, litePod{Name: p.Name, UID: string(p.UID), ResourceVersion: p.ResourceVersion, IP: p.Status.PodIP, RSUID: string(rs.UID), ContainerID: status.ContainerID, ImageID: status.ImageID, RestartCount: status.RestartCount, MasterKeyDeclared: len(p.Spec.Containers[0].EnvFrom) == 0 && masterCount == 1})
	}
	sort.Slice(a.Pods, func(i, j int) bool { return a.Pods[i].Name < a.Pods[j].Name })
	if a.Pods[0].Name == a.Pods[1].Name {
		return liteAuthority{}, errors.New("duplicate LiteLLM Pod")
	}
	return a, nil
}
func liteSourceFor(image string) *liteSource {
	for i := range liteSources {
		if liteSources[i].image == image {
			return &liteSources[i]
		}
	}
	return nil
}
func liteOwned(refs []metav1.OwnerReference, kind, name, uid string) bool {
	for _, r := range refs {
		if r.Kind == kind && r.Name == name && string(r.UID) == uid && r.Controller != nil && *r.Controller {
			return true
		}
	}
	return false
}
func liteOwnedKind(refs []metav1.OwnerReference, kind string) bool {
	return len(refs) == 1 && refs[0].Kind == kind && refs[0].UID != "" && refs[0].Controller != nil && *refs[0].Controller
}
func liteConfigMount(spec corev1.PodSpec, c corev1.Container, cm string) bool {
	mount := ""
	for _, m := range c.VolumeMounts {
		if m.MountPath == "/etc/litellm" && m.SubPath == "" && m.SubPathExpr == "" {
			mount = m.Name
		}
		if m.MountPath == "/" || m.MountPath == "/etc" || strings.HasPrefix(m.MountPath, "/etc/litellm/") {
			return false
		}
	}
	if mount == "" {
		return false
	}
	for _, v := range spec.Volumes {
		if v.Name == mount && v.ConfigMap != nil && v.ConfigMap.Name == cm {
			if len(v.ConfigMap.Items) == 0 {
				return true
			}
			return len(v.ConfigMap.Items) == 1 && v.ConfigMap.Items[0].Key == "config.yaml" && v.ConfigMap.Items[0].Path == "config.yaml"
		}
	}
	return false
}

// The script hashes only fixed mounted and installed files; it emits no source,
// config, environment, model name or bearer material.
const litePinScript = `import hashlib,importlib.metadata,pathlib,sys
expected=sys.argv[1:]
root=pathlib.Path(importlib.metadata.distribution('litellm').locate_file('litellm'))
files=[pathlib.Path('/etc/litellm/config.yaml'),root/'proxy/health_endpoints/_health_endpoints.py',root/'proxy/proxy_server.py',root/'proxy/auth/user_api_key_auth.py']
ok=importlib.metadata.version('litellm')==expected[0] and all(hashlib.sha256(p.read_bytes()).hexdigest()==e for p,e in zip(files,expected[1:]))
print('PIN_OK' if ok else 'PIN_DIFF')`

func (t liteKubeTransport) sourcePin(ctx context.Context, c LiteLLMRuntime, p litePod) error {
	s := liteSourceFor(p.ImageID)
	if s == nil {
		return errors.New("LiteLLM image pin missing")
	}
	bounded, cancel := context.WithTimeout(ctx, liteCallTimeout)
	defer cancel()
	command := []string{"python", "-c", litePinScript, s.version, c.ExpectedConfigSHA256, s.healthSHA, s.modelsSHA, s.authSHA}
	req := t.runtime.Kube.CoreV1().RESTClient().Post().Resource("pods").Name(p.Name).Namespace(c.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: c.Container, Command: command, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, e := remotecommand.NewSPDYExecutor(t.runtime.RESTConfig, http.MethodPost, req.URL())
	if e != nil {
		return errors.New("LiteLLM source pin exec unavailable")
	}
	var stdout, stderr liteLimitedBuffer
	stdout.limit, stderr.limit = 64, 64
	if executor.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}) != nil || stdout.overflow || stderr.overflow || stdout.String() != "PIN_OK\n" {
		return errors.New("LiteLLM installed source or mounted config differs")
	}
	return nil
}

// liteProbeScript opens one loopback application connection inside the exact
// selected Pod. Kubernetes credentials authenticate only the exec transport.
// The installed master key is read only inside that Pod for the positive arm;
// neither it, the generated invalid bearer, nor a response body is emitted.
const liteProbeScript = `import hashlib,http.client,json,os,secrets,signal,sys
path,mode,port=sys.argv[1:]
if path not in ('/health/liveliness','/v1/models') or mode not in ('health','master','missing','invalid') or (mode=='health')!=(path=='/health/liveliness'):
 raise ValueError('unsupported fixed GET')
headers={'Accept':'application/json'}
if mode=='invalid':headers['Authorization']='Bearer sk-catalogue-'+secrets.token_hex(16)
if mode=='master':
 key=os.environ.get('LITELLM_MASTER_KEY','')
 if not key:raise RuntimeError('declared master credential unavailable')
 headers['Authorization']='Bearer '+key
conn=http.client.HTTPConnection('127.0.0.1',int(port),timeout=4)
def timeout_handler(_signum,_frame):raise TimeoutError('bounded GET elapsed')
old_handler=signal.signal(signal.SIGALRM,timeout_handler)
signal.setitimer(signal.ITIMER_REAL,4)
try:
 conn.request('GET',path,headers=headers)
 response=conn.getresponse()
 body=response.read(4097)
 ct=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
 reason='NOT_CLASSIFIED'
 model_shape=False
 if mode=='master' and response.status==200 and ct=='application/json' and len(body)<=4096:
  try:
   def unique_pairs(pairs):
    value={}
    for name,item in pairs:
     if name in value:raise ValueError('duplicate JSON field')
     value[name]=item
    return value
   value=json.loads(body,object_pairs_hook=unique_pairs)
   model_shape=isinstance(value,dict) and value.get('object')=='list' and isinstance(value.get('data'),list)
  except (ValueError,UnicodeDecodeError):pass
 if response.status==400 and ct=='application/json' and len(body)<=4096:
  try:
   value=json.loads(body)
   message=value.get('error') if isinstance(value,dict) else None
   if isinstance(message,dict):message=message.get('message')
   reason='NO_CONNECTED_DB' if isinstance(message,str) and 'no connected db' in message.lower() else 'OTHER_REDACTED'
  except (ValueError,UnicodeDecodeError):reason='UNPARSEABLE'
 print(json.dumps({'status':response.status,'contentType':ct,'bodySHA256':hashlib.sha256(body).hexdigest(),'bodyBytes':len(body),'reason':reason,'modelListShape':model_shape,'boundExceeded':len(body)>4096},sort_keys=True))
finally:
 signal.setitimer(signal.ITIMER_REAL,0)
 signal.signal(signal.SIGALRM,old_handler)
 conn.close()`

func (t liteKubeTransport) get(ctx context.Context, c LiteLLMRuntime, p litePod, path, mode string) (liteResponse, error) {
	if (path != liteHealthPath && path != liteAuthPath) || (mode != "health" && mode != "master" && mode != "missing" && mode != "invalid") || (mode == "health") != (path == liteHealthPath) {
		return liteResponse{}, errors.New("LiteLLM route or mode not allowed")
	}
	bounded, cancel := context.WithTimeout(ctx, liteCallTimeout)
	defer cancel()
	command := []string{"python", "-c", liteProbeScript, path, mode, strconv.Itoa(int(c.Port))}
	req := t.runtime.Kube.CoreV1().RESTClient().Post().Resource("pods").Name(p.Name).Namespace(c.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: c.Container, Command: command, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, e := remotecommand.NewSPDYExecutor(t.runtime.RESTConfig, http.MethodPost, req.URL())
	if e != nil {
		return liteResponse{}, errors.New("LiteLLM loopback exec unavailable")
	}
	var stdout, stderr liteLimitedBuffer
	stdout.limit, stderr.limit = 1024, 128
	if executor.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}) != nil || stdout.overflow || stderr.overflow {
		return liteResponse{}, errors.New("LiteLLM loopback GET outcome ambiguous")
	}
	var response liteResponse
	if json.Unmarshal([]byte(stdout.String()), &response) != nil || response.Status < 100 || response.Status > 599 || response.BodyBytes < 0 || response.BodyBytes > liteMaxBody || response.BoundExceeded || len(response.BodySHA256) != 64 || response.ErrorClass != "" {
		return liteResponse{}, errors.New("LiteLLM loopback GET receipt invalid or over bound")
	}
	return response, nil
}

func (h liteHandler) Run(ctx context.Context, jc JobContext) (out Result) {
	out = Result{Outcome: OutcomeInconclusive, Summary: "LiteLLM control incomplete", StartedAt: time.Now().UTC(), Evidence: map[string]string{"securityOutcome": "NOT_EVALUATED", "installedDefense": "NOT_EVALUATED", "brain": "NOT_EVALUATED", "actuator": "NOT_EVALUATED", "securityEvent": "NOT_REQUIRED", "eventMode": "none", "sourceType": "direct-exact-pod-loopback", "requestCount": "0"}, Limits: []string{h.Definition().ClaimLimits}, Cleanup: Cleanup{Verified: true, Status: "no-mutation"}}
	defer func() { out.FinishedAt = time.Now().UTC() }()
	if h.Validate(jc.Runtime) != nil || jc.Recorder == nil {
		out.Summary = "LiteLLM runtime or recorder unavailable"
		return
	}
	t := h.transport
	if t == nil {
		t = liteKubeTransport{runtime: jc.Runtime}
	}
	c := jc.Runtime.LiteLLM
	initial, e := t.snapshot(ctx, c)
	if e != nil {
		out.Summary = "LiteLLM target preflight unavailable"
		return
	}
	initialHash := initial.fingerprint()
	out.Evidence["authorityBeforeSHA256"] = initialHash
	out.Evidence["configSHA256"] = initial.ConfigSHA
	out.Evidence["sourcePin"] = "mounted-config-and-installed-package-hashes"
	out.Evidence["targetPodCount"] = strconv.Itoa(len(initial.Pods))
	requests := 0
	healthPass := true
	masterPass := true
	authPass := true
	configLimited := false
	denialFailure := false
	for i, p := range initial.Pods {
		prefix := "pod" + strconv.Itoa(i+1) + "."
		out.Evidence[prefix+"name"] = p.Name
		out.Evidence[prefix+"uid"] = p.UID
		out.Evidence[prefix+"imageID"] = p.ImageID
		s := liteSourceFor(p.ImageID)
		out.Evidence[prefix+"version"] = s.version
		steps := []struct{ name, path, mode string }{{"health", liteHealthPath, "health"}}
		if h.profile == LiteLLMCredential {
			if !p.MasterKeyDeclared {
				out.Summary = "LiteLLM master credential declaration unavailable"
				return
			}
			steps = append(steps, struct{ name, path, mode string }{"masterBearer", liteAuthPath, "master"}, struct{ name, path, mode string }{"missingBearer", liteAuthPath, "missing"}, struct{ name, path, mode string }{"invalidBearer", liteAuthPath, "invalid"})
		}
		for _, step := range steps {
			current, readErr := t.snapshot(ctx, c)
			if readErr != nil || current.fingerprint() != initialHash {
				out.Summary = "LiteLLM authority changed before GET"
				return
			}
			if e = t.sourcePin(ctx, c, p); e != nil {
				out.Summary = "LiteLLM installed source changed before GET"
				return
			}
			identity := map[string]string{"podUID": p.UID, "podName": p.Name, "route": step.path}
			if e = jc.Recorder.Intent(Intent{Step: "litellm." + step.name, At: time.Now().UTC(), Identity: identity}); e != nil {
				out.Summary = "LiteLLM GET intent unavailable"
				return
			}
			response, callErr := t.get(ctx, c, p, step.path, step.mode)
			requests++
			out.Evidence["requestCount"] = strconv.Itoa(requests)
			if callErr != nil {
				out.Summary = "LiteLLM GET outcome ambiguous"
				return
			}
			out.Evidence[prefix+step.name+".status"] = strconv.Itoa(response.Status)
			out.Evidence[prefix+step.name+".bodySHA256"] = response.BodySHA256
			out.Evidence[prefix+step.name+".bodyBytes"] = strconv.Itoa(response.BodyBytes)
			reason := response.Reason
			if step.name == "masterBearer" {
				out.Evidence[prefix+step.name+".listShape"] = strconv.FormatBool(response.ModelListShape)
			}
			if step.name == "invalidBearer" {
				out.Evidence[prefix+step.name+".reason"] = reason
			}
			if e = jc.Recorder.Event(Event{Step: "litellm." + step.name, Status: "observed", At: time.Now().UTC(), Identity: map[string]string{"podUID": p.UID, "httpStatus": strconv.Itoa(response.Status), "reason": reason}}); e != nil {
				out.Summary = "LiteLLM GET receipt unavailable"
				return
			}
			after, readErr := t.snapshot(ctx, c)
			if readErr != nil || after.fingerprint() != initialHash || t.sourcePin(ctx, c, p) != nil {
				out.Summary = "LiteLLM authority or source changed after GET"
				return
			}
			if step.name == "health" {
				if response.Status != 200 || response.ContentType != "application/json" || response.BodyBytes != 12 || response.BodySHA256 != liteHealthySHA {
					healthPass = false
				}
			}
			if step.name == "masterBearer" {
				if response.Status != 200 || response.ContentType != "application/json" || !response.ModelListShape {
					masterPass = false
				}
			}
			if step.name == "missingBearer" || step.name == "invalidBearer" {
				if response.Status == 400 && reason == "NO_CONNECTED_DB" {
					configLimited = true
				} else if response.Status == 200 || response.Status == 201 || response.Status == 204 {
					denialFailure = true
				} else if response.Status != 401 && response.Status != 403 {
					authPass = false
				}
			}
		}
	}
	final, e := t.snapshot(ctx, c)
	if e != nil || final.fingerprint() != initialHash {
		out.Summary = "LiteLLM final authority changed"
		return
	}
	out.Evidence["authorityAfterSHA256"] = final.fingerprint()
	if !healthPass {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "one or more exact LiteLLM Pods failed listener health"
		return
	}
	if h.profile == LiteLLMHealth {
		out.Outcome = OutcomeFunctionalPass
		out.Summary = "each exact serving LiteLLM Pod returned bounded liveness 200"
		return
	}
	if masterPass {
		out.Evidence["masterPathState"] = "AVAILABLE"
	} else {
		out.Evidence["masterPathState"] = "UNVERIFIED"
	}
	if denialFailure {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "one or more negative auth GETs returned success"
		out.Evidence["authBoundaryState"] = "NEGATIVE_GET_ACCEPTED"
		return
	}
	if !masterPass {
		out.Summary = "LiteLLM master-key model-list path did not return reviewed shape on every Pod"
		return
	}
	if configLimited {
		out.Summary = "LiteLLM master-key model listing available; nonmaster bearer reached NO_CONNECTED_DB and virtual-key denial remains unverified"
		out.Evidence["authBoundaryState"] = "UNKNOWN_CONFIGURATION_LIMITED"
		out.Evidence["nonmasterPathState"] = "DB_FEATURE_UNAVAILABLE"
		return
	}
	if !authPass {
		out.Summary = "LiteLLM auth response differed from reviewed denial statuses"
		return
	}
	out.Outcome = OutcomeFunctionalPass
	out.Summary = "each exact LiteLLM Pod refused missing and generated invalid bearers"
	out.Evidence["authBoundaryState"] = "NEGATIVE_GET_REFUSAL_ONLY"
	out.Evidence["nonmasterPathState"] = "REFUSED"
	return
}
