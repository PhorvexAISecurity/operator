package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c2CheckpointContinuity{}) }

const (
	checkpointApp               = "c2-checkpoint-target"
	checkpointPVC               = "c2-checkpoint-state"
	checkpointService           = "c2-checkpoint-target"
	checkpointProducer          = "c2-checkpoint-producer"
	checkpointPort              = 8081
	checkpointImage             = sessionPythonImage
	checkpointObservationWindow = 20 * time.Second
	checkpointSampleInterval    = 2 * time.Second
	checkpointLocalHolder       = "checkpoint-local-holder"
	checkpointLocalCampaign     = "post25-checkpoint-local-r1"
	checkpointLocalOwnerLabel   = "fixture.phorvex.ai/external-owner"
	checkpointLocalOwnerValue   = "checkpoint-local-holder"
	checkpointLocalMarker       = ".phorvex-holder.json"
	checkpointLocalCapacity     = "64Mi"
	checkpointMaxIncarnations   = 16
)

var checkpointObservationWait = waitCheckpointObservation

const checkpointServerSource = `import hashlib,json,os,tempfile,threading,time,uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
state_dir=os.environ.get("STATE_DIR","/state"); path=os.path.join(state_dir,"checkpoint.json")
pod_uid=os.environ["POD_UID"]; pvc_uid=os.environ["PVC_UID"]; incarnation=str(uuid.uuid4()); lock=threading.Lock()
state={"ready":False,"error":"","sequence":-1,"payload":"","checksum":"","bootSequence":-1,"bootChecksum":"","initializedFresh":False}
def strict_object(pairs):
 out={}
 for key,value in pairs:
  if key in out: raise ValueError("duplicate checkpoint field")
  out[key]=value
 return out
def payload(seq): return "synthetic-sequence-%020d"%seq
def digest(seq,data): return hashlib.sha256(("v1\n%d\n%s"%(seq,data)).encode()).hexdigest()
def validate(obj):
 if type(obj) is not dict or set(obj)!={"version","sequence","payload","checksum"}: raise ValueError("checkpoint shape")
 if type(obj["version"]) is not int or obj["version"]!=1 or type(obj["sequence"]) is not int or obj["sequence"]<0 or obj["sequence"]>1000000000: raise ValueError("checkpoint version/sequence")
 if obj["payload"]!=payload(obj["sequence"]) or obj["checksum"]!=digest(obj["sequence"],obj["payload"]): raise ValueError("checkpoint checksum")
 return obj
def persist(seq):
 data=payload(seq); obj={"version":1,"sequence":seq,"payload":data,"checksum":digest(seq,data)}
 raw=json.dumps(obj,sort_keys=True,separators=(",",":")).encode(); fd,tmp=tempfile.mkstemp(prefix="checkpoint.",dir=state_dir)
 try:
  with os.fdopen(fd,"wb") as f:
   f.write(raw); f.flush()
   if os.environ.get("CHECKPOINT_FAULT")=="before-file-fsync": raise OSError("injected before file fsync")
   os.fsync(f.fileno())
  if os.environ.get("CHECKPOINT_FAULT")=="before-replace": raise OSError("injected before replace")
  os.replace(tmp,path)
  dfd=os.open(state_dir,os.O_RDONLY)
  try: os.fsync(dfd)
  finally: os.close(dfd)
 finally:
  try: os.unlink(tmp)
  except FileNotFoundError: pass
 return obj
def boot():
 os.makedirs(state_dir,exist_ok=True)
 fresh=not os.path.exists(path)
 if fresh: obj=persist(0)
 else:
  with open(path,"rb") as f: raw=f.read(8193)
  if len(raw)>8192: raise ValueError("checkpoint too large")
  obj=validate(json.loads(raw,object_pairs_hook=strict_object))
 with lock: state.update(ready=True,error="",sequence=obj["sequence"],payload=obj["payload"],checksum=obj["checksum"],bootSequence=obj["sequence"],bootChecksum=obj["checksum"],initializedFresh=fresh)
def advance():
 while True:
  time.sleep(float(os.environ.get("INTERVAL_MS","400"))/1000.0)
  with lock:
   if not state["ready"]: continue
   seq=state["sequence"]+1
  try: obj=persist(seq)
  except Exception as e:
   with lock: state.update(ready=False,error=type(e).__name__+":"+str(e))
   continue
  with lock: state.update(sequence=obj["sequence"],payload=obj["payload"],checksum=obj["checksum"])
try: boot()
except Exception as e:
 with lock: state.update(ready=False,error=type(e).__name__+":"+str(e))
threading.Thread(target=advance,daemon=True).start()
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path!="/progress": self.send(404,{"error":"not-found"}); return
  with lock: body=dict(state)
  body.update(version=1,podUID=pod_uid,pvcUID=pvc_uid,incarnation=incarnation)
  self.send(200 if body["ready"] else 503,body)
 def send(self,status,body):
  raw=json.dumps(body,sort_keys=True,separators=(",",":")).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
 def log_message(self,*args): pass
ThreadingHTTPServer(("0.0.0.0",int(os.environ.get("PORT","8081"))),H).serve_forever()
`

const checkpointClientSource = `import base64,sys,urllib.error,urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
try:
 r=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(urllib.request.Request(sys.argv[1],method="GET"),timeout=3); status=r.status; body=r.read(8193)
except urllib.error.HTTPError as e: status=e.code; body=e.read(8193)
except Exception as e: print(type(e).__name__+":"+str(e),file=sys.stderr); sys.exit(17)
if len(body)>8192: print("body-too-large",file=sys.stderr); sys.exit(18)
sys.stdout.write(str(status)+"\n"+base64.b64encode(body).decode("ascii"))
`

const checkpointMarkerInitSource = `import json,os,stat
path=os.path.join(os.environ.get("STATE_DIR","/state"),".phorvex-holder.json"); maximum=1024
def strict_object(pairs):
 out={}
 for key,value in pairs:
  if key in out: raise ValueError("duplicate marker field")
  out[key]=value
 return out
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_size<=0 or info.st_size>maximum: raise ValueError("marker is not a bounded regular file")
 raw=os.read(fd,maximum+1)
 if len(raw)!=info.st_size or len(raw)>maximum: raise ValueError("marker size changed or exceeds bound")
 if os.fstat(fd).st_ino!=info.st_ino or os.fstat(fd).st_dev!=info.st_dev: raise ValueError("marker descriptor changed")
finally: os.close(fd)
value=json.loads(raw,object_pairs_hook=strict_object)
expected={"schema":"post25-checkpoint-local-holder-marker-v1","holderPodUID":os.environ["EXPECTED_HOLDER_UID"],"nodeName":os.environ["EXPECTED_NODE_NAME"],"campaignNonce":os.environ["EXPECTED_NONCE"],"slot":int(os.environ["EXPECTED_SLOT"])}
if type(value) is not dict or type(value.get("schema")) is not str or type(value.get("holderPodUID")) is not str or type(value.get("nodeName")) is not str or type(value.get("campaignNonce")) is not str or type(value.get("slot")) is not int or value!=expected: raise ValueError("marker identity differs")
canonical=(json.dumps(expected,sort_keys=True,separators=(",",":"))+"\n").encode()
if raw!=canonical: raise ValueError("marker bytes are not canonical")
print(json.dumps({"status":"VERIFIED","markerSHA256":__import__("hashlib").sha256(raw).hexdigest()},sort_keys=True,separators=(",",":")))
`

func checkpointSourceSHA256() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(checkpointServerSource)))
}

func checkpointMarkerInitSourceSHA256() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(checkpointMarkerInitSource)))
}

type c2CheckpointContinuity struct {
	deploymentUID, serviceUID, producerUID, pvcUID types.UID
	targetName, replicaSetName                     string
	targetUID, replicaSetUID                       types.UID
	originalIncarnation                            string
	lastOriginal                                   checkpointBody
	windowStarted, windowEnded                     time.Time
	unavailableReason                              string
	pvName, storageClassName, storageProvisioner   string
	pvUID, storageClassUID                         types.UID
	incarnationChain                               []checkpointIncarnationObservation
	localFixture                                   bool
	localSlot                                      int
	localHolderUID, localNodeUID                   types.UID
	localNodeName, localNonce, localPath           string
}

type checkpointIncarnationObservation struct {
	PodName              string `json:"podName"`
	PodUID               string `json:"podUID"`
	Incarnation          string `json:"incarnation"`
	BootSequence         int64  `json:"bootSequence"`
	BootChecksum         string `json:"bootChecksum"`
	AcknowledgedSequence int64  `json:"acknowledgedSequence"`
	AcknowledgedChecksum string `json:"acknowledgedChecksum"`
	PreviousUIDAbsent    bool   `json:"previousUIDAbsent"`
	PostBootAdvance      bool   `json:"postBootAdvance"`
}

func (s *c2CheckpointContinuity) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{Name: "c2-checkpoint-continuity", Category: core.CategoryR6Claimed, Source: "Post25 benign stateful checkpoint continuity control", R6ResponseTag: core.R6Partial, BenignControl: true, Realism: core.RealismExecutable,
		Mechanism:          fmt.Sprintf("PVC-mounted Python CPU counter with atomic fsync+replace+directory-fsync checkpoints and ordinary HTTP observation; image=%s sourceSHA256=%s", checkpointImage, checkpointSourceSHA256()),
		ClaimLimits:        "benign functional control only; zero ATT&CK techniques; no attack, detection, containment, network-isolation, continuous-availability, GPU-training, mitigation, security-coverage, or ROI claim",
		OracleDescription:  "same identity must continue acknowledged progress; every bounded successive replacement must prove its predecessor UID absent, retain the same owner/storage/service authority, use a new Pod UID and process incarnation, boot at or above its predecessor's latest acknowledgement, and preserve monotonic progress through the final incarnation",
		CleanupDescription: "UID-preconditioned deletion of only the successfully created Deployment, ReplicaSet/target Pod identities, Service, producer Pod, and PVC",
		R6Justification:    "Measures only acknowledged synthetic checkpoint continuity across Pod replacement through a real application protocol."}
}

func checkpointLocalAssignment(defender string, trial int) (int, error) {
	if trial < 0 || trial >= 3 {
		return 0, fmt.Errorf("checkpoint local fixture trial %d is outside the six-slot contract", trial)
	}
	switch defender {
	case "d-nomtd":
		return trial, nil
	case "d-r6blindtimer":
		return 3 + trial, nil
	default:
		return 0, fmt.Errorf("checkpoint local fixture defender %q has no owned slot", defender)
	}
}

func checkpointLocalSelector(defender string, trial, slot int) map[string]string {
	return map[string]string{
		"r6th.io/owned":               "true",
		"r6th.io/scenario":            "c2-checkpoint-continuity",
		"r6th.io/defender":            defender,
		"r6th.io/trial":               strconv.Itoa(trial),
		"fixture.phorvex.ai/campaign": checkpointLocalCampaign,
		"fixture.phorvex.ai/slot":     strconv.Itoa(slot),
	}
}

func checkpointLocalPath(holderUID types.UID, slot int) string {
	return fmt.Sprintf("/var/lib/kubelet/pods/%s/volumes/kubernetes.io~empty-dir/slot-%d", holderUID, slot)
}

func checkpointNodeReady(node *corev1.Node) bool {
	if node == nil || node.DeletionTimestamp != nil || node.Spec.Unschedulable || len(node.Spec.Taints) != 0 {
		return false
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func validateCheckpointLocalStorageClass(sc *storagev1.StorageClass, uid types.UID, nonce string) error {
	if sc == nil || sc.UID == "" || uid != "" && sc.UID != uid || sc.DeletionTimestamp != nil || sc.Provisioner != "kubernetes.io/no-provisioner" || sc.VolumeBindingMode == nil || *sc.VolumeBindingMode != storagev1.VolumeBindingImmediate || sc.ReclaimPolicy == nil || *sc.ReclaimPolicy != corev1.PersistentVolumeReclaimRetain || sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion || len(sc.Parameters) != 0 || len(sc.MountOptions) != 0 || len(sc.AllowedTopologies) != 0 {
		return errors.New("checkpoint local StorageClass must be exact non-expanding no-provisioner Immediate Retain")
	}
	if sc.Labels[core.OwnedLabelKey] != core.OwnedLabelValue || sc.Labels["fixture.phorvex.ai/campaign"] != checkpointLocalCampaign || sc.Annotations["fixture.phorvex.ai/nonce"] != nonce {
		return errors.New("checkpoint local StorageClass ownership/nonce differs")
	}
	return nil
}

func (s *c2CheckpointContinuity) validateCheckpointLocalHolder(ctx context.Context, env *core.Env) error {
	if !s.localFixture || s.localHolderUID == "" || s.localNodeUID == "" || s.localNodeName == "" || s.localNonce == "" || s.localSlot < 0 || s.localSlot >= 6 {
		return errors.New("checkpoint local holder provenance missing")
	}
	holderPod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, checkpointLocalHolder, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read checkpoint local holder: %w", err)
	}
	if holderPod.UID != s.localHolderUID || holderPod.DeletionTimestamp != nil || holderPod.Spec.NodeName != s.localNodeName || holderPod.Status.Phase != corev1.PodRunning || !podReady(holderPod) {
		return fmt.Errorf("checkpoint local holder identity/readiness differs: name=%s uid=%s node=%s phase=%s", holderPod.Name, holderPod.UID, holderPod.Spec.NodeName, holderPod.Status.Phase)
	}
	if _, genericOwned := holderPod.Labels[core.OwnedLabelKey]; genericOwned || holderPod.Labels[checkpointLocalOwnerLabel] != checkpointLocalOwnerValue || holderPod.Labels["fixture.phorvex.ai/campaign"] != checkpointLocalCampaign || holderPod.Annotations["fixture.phorvex.ai/nonce"] != s.localNonce {
		return errors.New("checkpoint local holder ownership/nonce differs")
	}
	if holderPod.Spec.AutomountServiceAccountToken == nil || *holderPod.Spec.AutomountServiceAccountToken || holderPod.Spec.RestartPolicy != corev1.RestartPolicyNever || len(holderPod.Spec.Containers) != 1 || len(holderPod.Spec.NodeSelector) != 1 || holderPod.Spec.NodeSelector["kubernetes.io/hostname"] != s.localNodeName {
		return errors.New("checkpoint local holder token/container boundary differs")
	}
	volumes := map[string]bool{}
	for _, volume := range holderPod.Spec.Volumes {
		if volume.EmptyDir == nil || volume.EmptyDir.SizeLimit == nil || volume.EmptyDir.SizeLimit.Cmp(resource.MustParse(checkpointLocalCapacity)) != 0 {
			return errors.New("checkpoint local holder volume contract differs")
		}
		volumes[volume.Name] = true
	}
	mounts := map[string]string{}
	for _, mount := range holderPod.Spec.Containers[0].VolumeMounts {
		if mount.ReadOnly {
			return errors.New("checkpoint local holder mount unexpectedly read-only")
		}
		mounts[mount.Name] = mount.MountPath
	}
	if len(volumes) != 6 || len(mounts) != 6 {
		return errors.New("checkpoint local holder must expose exactly six slots")
	}
	for slot := 0; slot < 6; slot++ {
		name := fmt.Sprintf("slot-%d", slot)
		if !volumes[name] || mounts[name] != fmt.Sprintf("/checkpoint/slot-%d", slot) {
			return fmt.Errorf("checkpoint local holder slot %d differs", slot)
		}
	}
	security := holderPod.Spec.Containers[0].SecurityContext
	podSecurity := holderPod.Spec.SecurityContext
	if holderPod.Spec.Containers[0].Image != checkpointImage || security == nil || security.RunAsNonRoot == nil || !*security.RunAsNonRoot || security.RunAsUser == nil || *security.RunAsUser != 65532 || security.RunAsGroup == nil || *security.RunAsGroup != 65532 || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem || security.Privileged != nil && *security.Privileged || security.Capabilities == nil || len(security.Capabilities.Drop) != 1 || security.Capabilities.Drop[0] != "ALL" || podSecurity == nil || podSecurity.RunAsNonRoot == nil || !*podSecurity.RunAsNonRoot || podSecurity.RunAsUser == nil || *podSecurity.RunAsUser != 65532 || podSecurity.RunAsGroup == nil || *podSecurity.RunAsGroup != 65532 || podSecurity.FSGroup == nil || *podSecurity.FSGroup != 65532 {
		return errors.New("checkpoint local holder volume/image/nonroot contract differs")
	}
	node, err := env.Kube.CoreV1().Nodes().Get(ctx, s.localNodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read checkpoint local node: %w", err)
	}
	gpu := node.Status.Allocatable[corev1.ResourceName("nvidia.com/gpu")]
	if node.UID != s.localNodeUID || !checkpointNodeReady(node) || !gpu.IsZero() {
		return fmt.Errorf("checkpoint local node identity/readiness/GPU differs: uid=%s", node.UID)
	}
	return nil
}

func checkpointLocalNodeAffinityMatches(pv *corev1.PersistentVolume, nodeName string) bool {
	if pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil || len(pv.Spec.NodeAffinity.Required.NodeSelectorTerms) != 1 {
		return false
	}
	term := pv.Spec.NodeAffinity.Required.NodeSelectorTerms[0]
	if len(term.MatchFields) != 0 || len(term.MatchExpressions) != 1 {
		return false
	}
	expression := term.MatchExpressions[0]
	return expression.Key == "kubernetes.io/hostname" && expression.Operator == corev1.NodeSelectorOpIn && len(expression.Values) == 1 && expression.Values[0] == nodeName
}

func checkpointLocalLabelSelectorMatches(selector *metav1.LabelSelector, expected map[string]string) bool {
	if selector == nil || len(selector.MatchExpressions) != 0 || len(selector.MatchLabels) != len(expected) {
		return false
	}
	for key, value := range expected {
		if selector.MatchLabels[key] != value {
			return false
		}
	}
	return true
}

func (s *c2CheckpointContinuity) validateCheckpointLocalPVC(pvc *corev1.PersistentVolumeClaim, expectedPV string, selector map[string]string) error {
	if pvc == nil {
		return errors.New("checkpoint local PVC identity/prebinding contract differs")
	}
	capacity := pvc.Spec.Resources.Requests.Storage()
	if pvc.UID != s.pvcUID || pvc.DeletionTimestamp != nil || pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName != expectedPV || pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != s.storageClassName || len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteOnce || capacity == nil || capacity.Cmp(resource.MustParse(checkpointLocalCapacity)) != 0 || !checkpointLocalLabelSelectorMatches(pvc.Spec.Selector, selector) {
		return errors.New("checkpoint local PVC identity/prebinding contract differs")
	}
	return nil
}

func (s *c2CheckpointContinuity) validateCheckpointLocalPV(pv *corev1.PersistentVolume, selector map[string]string, requireAvailable bool) error {
	if pv == nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.StorageClassName != s.storageClassName || pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain || pv.Spec.VolumeMode == nil || *pv.Spec.VolumeMode != corev1.PersistentVolumeFilesystem || len(pv.Spec.AccessModes) != 1 || pv.Spec.AccessModes[0] != corev1.ReadWriteOnce || len(pv.Spec.MountOptions) != 0 {
		return errors.New("checkpoint local PV identity/storage contract differs")
	}
	capacity := pv.Spec.Capacity.Storage()
	if capacity == nil || capacity.Cmp(resource.MustParse(checkpointLocalCapacity)) != 0 || pv.Spec.Local == nil || pv.Spec.Local.Path != s.localPath || pv.Spec.Local.FSType != nil || !checkpointLocalNodeAffinityMatches(pv, s.localNodeName) {
		return errors.New("checkpoint local PV capacity/path/node affinity differs")
	}
	if requireAvailable && (pv.Status.Phase != corev1.VolumeAvailable || pv.Spec.ClaimRef != nil) {
		return errors.New("checkpoint local PV is not unused and Available")
	}
	if !requireAvailable && pv.Status.Phase != corev1.VolumeBound {
		return errors.New("checkpoint local PV is not Bound")
	}
	for key, value := range selector {
		if pv.Labels[key] != value {
			return fmt.Errorf("checkpoint local PV label %q differs", key)
		}
	}
	expectedAnnotations := map[string]string{
		"fixture.phorvex.ai/holder-uid":        string(s.localHolderUID),
		"fixture.phorvex.ai/node-uid":          string(s.localNodeUID),
		"fixture.phorvex.ai/nonce":             s.localNonce,
		"fixture.phorvex.ai/slot":              strconv.Itoa(s.localSlot),
		"fixture.phorvex.ai/local-path-sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(s.localPath))),
	}
	for key, value := range expectedAnnotations {
		if pv.Annotations[key] != value {
			return fmt.Errorf("checkpoint local PV annotation %q differs", key)
		}
	}
	return nil
}

func (s *c2CheckpointContinuity) prepareCheckpointLocalFixture(ctx context.Context, env *core.Env, sc *storagev1.StorageClass) (*corev1.PersistentVolume, map[string]string, error) {
	if err := validateCheckpointLocalStorageClass(sc, "", env.Config.BenignCheckpointLocalNonce); err != nil {
		return nil, nil, err
	}
	slot, err := checkpointLocalAssignment(env.DefenderName, env.Trial)
	if err != nil {
		return nil, nil, err
	}
	s.localFixture = true
	s.localSlot = slot
	s.localHolderUID = types.UID(env.Config.BenignCheckpointLocalHolderUID)
	s.localNodeUID = types.UID(env.Config.BenignCheckpointLocalNodeUID)
	s.localNodeName = env.Config.BenignCheckpointNodeSelector["kubernetes.io/hostname"]
	s.localNonce = env.Config.BenignCheckpointLocalNonce
	s.storageClassUID = sc.UID
	s.localPath = checkpointLocalPath(s.localHolderUID, slot)
	if err := s.validateCheckpointLocalHolder(ctx, env); err != nil {
		return nil, nil, err
	}
	selector := checkpointLocalSelector(env.DefenderName, env.Trial, slot)
	items, err := env.Kube.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{LabelSelector: labels.Set(selector).String()})
	if err != nil {
		return nil, nil, fmt.Errorf("list checkpoint local PV candidate: %w", err)
	}
	if len(items.Items) != 1 {
		return nil, nil, fmt.Errorf("checkpoint local fixture requires exactly one PV candidate, got %d", len(items.Items))
	}
	pv := items.Items[0].DeepCopy()
	if err := s.validateCheckpointLocalPV(pv, selector, true); err != nil {
		return nil, nil, err
	}
	return pv, selector, nil
}

func waitCheckpointLocalBinding(ctx context.Context, env *core.Env, pvcUID types.UID, pvName string) (*corev1.PersistentVolumeClaim, error) {
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		pvc, err := env.Kube.CoreV1().PersistentVolumeClaims(env.Config.Namespace).Get(deadline, checkpointPVC, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("read checkpoint local PVC binding: %w", err)
		}
		if pvc.UID != pvcUID {
			return nil, errors.New("checkpoint local PVC UID changed while binding")
		}
		if pvc.Status.Phase == corev1.ClaimBound {
			if pvc.Spec.VolumeName != pvName {
				return nil, fmt.Errorf("checkpoint local PVC bound unexpected PV %q", pvc.Spec.VolumeName)
			}
			return pvc, nil
		}
		select {
		case <-deadline.Done():
			return nil, fmt.Errorf("wait checkpoint local PVC Bound: %w", deadline.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (s *c2CheckpointContinuity) Setup(ctx context.Context, env *core.Env) error {
	*s = c2CheckpointContinuity{}
	storageClass := strings.TrimSpace(env.Config.BenignCheckpointStorageClass)
	if storageClass == "" {
		s.unavailableReason = "benign checkpoint storage unavailable: benignCheckpointStorageClass is not explicitly pinned"
		return nil
	}
	sc, err := env.Kube.StorageV1().StorageClasses().Get(ctx, storageClass, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		s.unavailableReason = fmt.Sprintf("benign checkpoint storage unavailable: StorageClass %q does not exist", storageClass)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read checkpoint StorageClass %q: %w", storageClass, err)
	}
	s.storageProvisioner = sc.Provisioner
	s.storageClassName = storageClass
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	labels := env.OwnedLabels(map[string]string{"app": checkpointApp})
	selector := cloneStringMap(env.Config.BenignSessionNodeSelector)
	var localPV *corev1.PersistentVolume
	var localSelector map[string]string
	if env.Config.BenignCheckpointLocalFixture {
		selector = cloneStringMap(env.Config.BenignCheckpointNodeSelector)
		localPV, localSelector, err = s.prepareCheckpointLocalFixture(ctx, env, sc)
		if err != nil {
			return err
		}
	}
	pvcSpec := corev1.PersistentVolumeClaimSpec{StorageClassName: &storageClass, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(checkpointLocalCapacity)}}}
	if s.localFixture {
		pvcSpec.VolumeName = localPV.Name
		pvcSpec.Selector = &metav1.LabelSelector{MatchLabels: cloneStringMap(localSelector)}
	}
	pvc, err := env.Kube.CoreV1().PersistentVolumeClaims(ns).Create(ctx, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: checkpointPVC, Namespace: ns, Labels: labels}, Spec: pvcSpec}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create checkpoint PVC: %w", err)
	}
	if pvc.UID == "" {
		return errors.New("checkpoint PVC create returned empty UID")
	}
	s.pvcUID = pvc.UID
	if s.localFixture {
		boundPVC, bindErr := waitCheckpointLocalBinding(ctx, env, s.pvcUID, localPV.Name)
		if bindErr != nil {
			return bindErr
		}
		if err := s.validateCheckpointLocalPVC(boundPVC, localPV.Name, localSelector); err != nil {
			return err
		}
		boundPV, getErr := env.Kube.CoreV1().PersistentVolumes().Get(ctx, localPV.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("read bound checkpoint local PV: %w", getErr)
		}
		if boundPV.UID != localPV.UID || !checkpointPVClaimsPVC(boundPV, boundPVC) {
			return errors.New("checkpoint local PV UID/claimRef changed before workload creation")
		}
		if err := s.validateCheckpointLocalPV(boundPV, localSelector, false); err != nil {
			return err
		}
		if err := s.validateCheckpointLocalHolder(ctx, env); err != nil {
			return err
		}
		s.pvName, s.pvUID = boundPV.Name, boundPV.UID
	}
	one := int32(1)
	noToken := false
	nonroot := true
	uid := int64(65532)
	ro := true
	noEsc := false
	fsGroupPolicy := corev1.FSGroupChangeOnRootMismatch
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: checkpointApp, Namespace: ns, Labels: labels}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": checkpointApp}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: env.OwnedLabels(map[string]string{"app": checkpointApp, defenders.RotationTargetLabel: "true"})}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &noToken, NodeSelector: selector, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid}, Containers: []corev1.Container{{Name: "checkpoint", Image: checkpointImage, Command: []string{"python3", "-B", "-c", checkpointServerSource}, Env: []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}, {Name: "PVC_UID", Value: string(s.pvcUID)}}, Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: checkpointPort}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("96Mi")}}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEsc, ReadOnlyRootFilesystem: &ro, RunAsNonRoot: &nonroot, RunAsUser: &uid}, VolumeMounts: []corev1.VolumeMount{{Name: "state", MountPath: "/state"}}}}, Volumes: []corev1.Volume{{Name: "state", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: checkpointPVC}}}}}}}}
	if s.localFixture {
		seccomp := corev1.SeccompProfileTypeRuntimeDefault
		dep.Spec.Template.Spec.InitContainers = []corev1.Container{{
			Name:    "verify-local-marker",
			Image:   checkpointImage,
			Command: []string{"python3", "-B", "-c", checkpointMarkerInitSource},
			Env: []corev1.EnvVar{
				{Name: "EXPECTED_HOLDER_UID", Value: string(s.localHolderUID)},
				{Name: "EXPECTED_NODE_NAME", Value: s.localNodeName},
				{Name: "EXPECTED_NONCE", Value: s.localNonce},
				{Name: "EXPECTED_SLOT", Value: strconv.Itoa(s.localSlot)},
			},
			Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("5m"), corev1.ResourceMemory: resource.MustParse("8Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("32Mi")}},
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEsc, ReadOnlyRootFilesystem: &ro, RunAsNonRoot: &nonroot, RunAsUser: &uid, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &corev1.SeccompProfile{Type: seccomp}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "state", MountPath: "/state", ReadOnly: true}},
		}}
	}
	dep.Spec.Template.Spec.SecurityContext.FSGroup = &uid
	dep.Spec.Template.Spec.SecurityContext.FSGroupChangePolicy = &fsGroupPolicy
	dep.Spec.Template.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/progress", Port: intstr.FromInt(checkpointPort)}}, InitialDelaySeconds: 1, PeriodSeconds: 1, TimeoutSeconds: 2, FailureThreshold: 10}
	createdDep, err := env.Kube.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create checkpoint Deployment: %w", err)
	}
	if createdDep.UID == "" {
		return errors.New("checkpoint Deployment create returned empty UID")
	}
	s.deploymentUID = createdDep.UID
	svc, err := env.Kube.CoreV1().Services(ns).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: checkpointService, Namespace: ns, Labels: labels}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": checkpointApp}, Ports: []corev1.ServicePort{{Name: "http", Port: checkpointPort, TargetPort: intstr.FromInt(checkpointPort)}}}}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create checkpoint Service: %w", err)
	}
	if svc.UID == "" {
		return errors.New("checkpoint Service create returned empty UID")
	}
	s.serviceUID = svc.UID
	producer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: checkpointProducer, Namespace: ns, Labels: env.OwnedLabels(map[string]string{"app": checkpointProducer})}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &noToken, NodeSelector: cloneStringMap(selector), RestartPolicy: corev1.RestartPolicyNever, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid}, Containers: []corev1.Container{{Name: "producer", Image: checkpointImage, Command: []string{"sh", "-c", "while true; do sleep 3600; done"}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEsc, ReadOnlyRootFilesystem: &ro, RunAsNonRoot: &nonroot, RunAsUser: &uid}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}}}}}}
	createdProducer, err := env.Kube.CoreV1().Pods(ns).Create(ctx, producer, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create checkpoint producer: %w", err)
	}
	if createdProducer.UID == "" {
		return errors.New("checkpoint producer create returned empty UID")
	}
	s.producerUID = createdProducer.UID
	if err := env.WaitForPodRunning(ctx, checkpointProducer, 60*time.Second); err != nil {
		return err
	}
	target, err := runningPodByApp(ctx, env, checkpointApp)
	if err != nil {
		return err
	}
	if err := env.WaitForPodRunning(ctx, target.Name, 60*time.Second); err != nil {
		return fmt.Errorf("wait for checkpoint HTTP readiness: %w", err)
	}
	targetAfterReady, err := env.Kube.CoreV1().Pods(ns).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil || targetAfterReady.UID != target.UID || !podReady(targetAfterReady) {
		return fmt.Errorf("checkpoint target identity/readiness changed: pod=%v err=%v", targetAfterReady, err)
	}
	target = targetAfterReady
	s.targetName, s.targetUID = target.Name, target.UID
	for _, o := range target.OwnerReferences {
		if o.Kind == "ReplicaSet" && o.Controller != nil && *o.Controller {
			if s.replicaSetUID != "" {
				return errors.New("checkpoint target Pod has multiple controller ReplicaSets")
			}
			s.replicaSetName, s.replicaSetUID = o.Name, o.UID
		}
	}
	if s.targetUID == "" || s.replicaSetName == "" || s.replicaSetUID == "" {
		return errors.New("checkpoint target Pod/ReplicaSet identity missing")
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(ns).Get(ctx, s.replicaSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read checkpoint ReplicaSet: %w", err)
	}
	if rs.UID != s.replicaSetUID {
		return errors.New("checkpoint ReplicaSet UID changed")
	}
	owned := false
	for _, o := range rs.OwnerReferences {
		if o.Kind == "Deployment" && o.Name == checkpointApp && o.UID == s.deploymentUID && o.Controller != nil && *o.Controller {
			owned = true
		}
	}
	if !owned {
		return errors.New("checkpoint ReplicaSet is not owned by exact Deployment UID")
	}
	bound, err := env.Kube.CoreV1().PersistentVolumeClaims(ns).Get(ctx, checkpointPVC, metav1.GetOptions{})
	if err != nil || bound.UID != s.pvcUID || bound.Status.Phase != corev1.ClaimBound || bound.Spec.VolumeName == "" {
		return fmt.Errorf("checkpoint PVC is not exact and Bound: pvc=%v err=%v", bound, err)
	}
	pv, err := env.Kube.CoreV1().PersistentVolumes().Get(ctx, bound.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || pv.UID == "" {
		return fmt.Errorf("read bound checkpoint PV %q: %v", bound.Spec.VolumeName, err)
	}
	if bound.Spec.StorageClassName == nil || *bound.Spec.StorageClassName != s.storageClassName || pv.Spec.StorageClassName != s.storageClassName || !checkpointPVClaimsPVC(pv, bound) {
		return errors.New("checkpoint PVC/PV storage class or claimRef binding mismatch")
	}
	if s.localFixture && (pv.Name != s.pvName || pv.UID != s.pvUID) {
		return errors.New("checkpoint local bound PV changed after workload readiness")
	}
	if s.localFixture {
		if err := s.validateCheckpointLocalPVC(bound, s.pvName, checkpointLocalSelector(env.DefenderName, env.Trial, s.localSlot)); err != nil {
			return err
		}
		sc, err := env.Kube.StorageV1().StorageClasses().Get(ctx, s.storageClassName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read checkpoint local StorageClass identity: %w", err)
		}
		if err := validateCheckpointLocalStorageClass(sc, s.storageClassUID, s.localNonce); err != nil {
			return err
		}
		if err := s.validateCheckpointLocalPV(pv, checkpointLocalSelector(env.DefenderName, env.Trial, s.localSlot), false); err != nil {
			return err
		}
		if err := s.validateCheckpointLocalHolder(ctx, env); err != nil {
			return err
		}
	}
	s.pvName, s.pvUID = pv.Name, pv.UID
	return nil
}

func (s *c2CheckpointContinuity) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if s.unavailableReason != "" {
		return core.AttackResult{Skipped: true, SkipReason: s.unavailableReason}, nil
	}
	s.originalIncarnation = ""
	s.lastOriginal = checkpointBody{}
	s.windowStarted = time.Time{}
	s.windowEnded = time.Time{}
	s.incarnationChain = nil
	original, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.targetName, metav1.GetOptions{})
	if err != nil || original.UID != s.targetUID || !podReady(original) || original.DeletionTimestamp != nil {
		return core.AttackResult{}, fmt.Errorf("checkpoint original identity/readiness unavailable: pod=%v err=%v", original, err)
	}
	if err := s.validateObservedCheckpointWorkload(ctx, env, original); err != nil {
		return core.AttackResult{}, err
	}
	first, err := s.request(ctx, env)
	if err != nil {
		return core.AttackResult{}, err
	}
	if err = validateCheckpointIdentity(first, s.targetUID, s.pvcUID); err != nil {
		return core.AttackResult{}, err
	}
	if first.InitializedFresh == nil || !*first.InitializedFresh || first.BootSequence != 0 {
		return core.AttackResult{}, errors.New("owned volume did not prove one fresh initial initialization")
	}
	var second checkpointBody
	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return core.AttackResult{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		second, err = s.request(ctx, env)
		if err == nil && second.Sequence > first.Sequence {
			break
		}
	}
	if err != nil {
		return core.AttackResult{}, err
	}
	if second.Sequence <= first.Sequence {
		return core.AttackResult{}, errors.New("original checkpoint writer did not advance twice")
	}
	if err = validateCheckpointIdentity(second, s.targetUID, s.pvcUID); err != nil {
		return core.AttackResult{}, err
	}
	if second.Incarnation != first.Incarnation {
		return core.AttackResult{}, errors.New("original incarnation changed during establishment")
	}
	if second.InitializedFresh == nil || !*second.InitializedFresh || second.BootSequence != first.BootSequence || second.BootChecksum != first.BootChecksum {
		return core.AttackResult{}, errors.New("original initialization/boot provenance changed during establishment")
	}
	s.originalIncarnation = second.Incarnation
	s.lastOriginal = second
	s.incarnationChain = []checkpointIncarnationObservation{checkpointIncarnationFrom(s.targetName, s.targetUID, second, false)}
	var integrityErr error
	start, end, samples, sampleFailures, err := checkpointObservationWait(ctx, checkpointObservationWindow, checkpointSampleInterval, func() (checkpointBody, error) {
		body, requestErr := s.request(ctx, env)
		if requestErr != nil {
			return body, requestErr
		}
		if sampleErr := s.observeCheckpointSample(ctx, env, body); sampleErr != nil {
			if integrityErr == nil {
				integrityErr = sampleErr
			}
			return body, sampleErr
		}
		return body, nil
	})
	s.windowStarted, s.windowEnded = start, end
	notes := map[string]string{"classification": "benign functional-effect control", "originalPodUID": string(s.targetUID), "pvcUID": string(s.pvcUID), "originalIncarnation": s.originalIncarnation, "lastOriginalSequence": strconv.FormatInt(s.lastOriginal.Sequence, 10), "lastOriginalChecksum": s.lastOriginal.Checksum, "fixtureImage": checkpointImage, "serverSourceSHA256": checkpointSourceSHA256(), "storageClass": s.storageClassName, "storageProvisioner": s.storageProvisioner, "boundPV": s.pvName, "boundPVUID": string(s.pvUID), "observationSamples": strconv.Itoa(samples), "observationFailures": strconv.Itoa(sampleFailures), "observationWindowStartedAtUTC": start.UTC().Format(time.RFC3339Nano), "observationWindowEndedAtUTC": end.UTC().Format(time.RFC3339Nano), "incarnationChain": s.checkpointIncarnationChainJSON()}
	s.addCheckpointLocalEvidence(notes)
	if err != nil {
		return core.AttackResult{Stages: []string{"establish two durable original acknowledgements", "sample checkpoint Service during bounded observation window"}, Notes: notes}, err
	}
	if integrityErr != nil {
		return core.AttackResult{Stages: []string{"establish two durable original acknowledgements", "sample checkpoint Service during bounded observation window"}, Notes: notes}, fmt.Errorf("checkpoint observation integrity failed: %w", integrityErr)
	}
	if samples == 0 || sampleFailures == samples {
		return core.AttackResult{Stages: []string{"establish two durable original acknowledgements", "sample checkpoint Service during bounded observation window"}, Notes: notes}, errors.New("checkpoint observation window had no successful Service sample")
	}
	return core.AttackResult{Stages: []string{"establish two durable original acknowledgements", "sample checkpoint Service during bounded observation window"}, Notes: notes}, nil
}

func (s *c2CheckpointContinuity) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	if s.targetName == "" || s.targetUID == "" || s.pvcUID == "" || s.originalIncarnation == "" || s.lastOriginal.Sequence < 0 || s.windowEnded.Sub(s.windowStarted) < checkpointObservationWindow {
		return core.OracleResult{}, errors.New("checkpoint stimulus/window provenance missing")
	}
	if err := s.verifyStorageIdentity(ctx, env); err != nil {
		return core.OracleResult{}, err
	}
	reply, err := s.request(ctx, env)
	if err != nil {
		return core.OracleResult{}, err
	}
	pod, transitioned, err := s.observeCheckpointReply(ctx, env, reply, true)
	if err != nil {
		return core.OracleResult{}, err
	}
	ev := map[string]string{"originalPodUID": string(s.targetUID), "observedPodUID": string(pod.UID), "pvcUID": string(s.pvcUID), "pvName": s.pvName, "pvUID": string(s.pvUID), "storageClass": s.storageClassName, "originalUIDAbsent": strconv.FormatBool(len(s.incarnationChain) > 1), "previousUIDAbsent": strconv.FormatBool(transitioned), "bootSequence": strconv.FormatInt(reply.BootSequence, 10), "sequence": strconv.FormatInt(reply.Sequence, 10), "bootChecksum": reply.BootChecksum, "checksum": reply.Checksum, "incarnation": reply.Incarnation, "incarnationChain": s.checkpointIncarnationChainJSON(), "classification": "benign functional-effect control"}
	s.addCheckpointLocalEvidence(ev)
	if len(s.incarnationChain) == 1 {
		return core.OracleResult{Achieved: true, ObservedState: "benign checkpoint control: exact original Pod and process continued acknowledged durable progress", Evidence: ev}, nil
	}
	return core.OracleResult{Achieved: true, ObservedState: "benign checkpoint control: exact successive Pod incarnations loaded retained checkpoints and produced a later durable acknowledgement", Evidence: ev}, nil
}

func (s *c2CheckpointContinuity) observeCheckpointSample(ctx context.Context, env *core.Env, reply checkpointBody) error {
	_, _, err := s.observeCheckpointReply(ctx, env, reply, false)
	return err
}

func checkpointIncarnationFrom(name string, uid types.UID, body checkpointBody, previousAbsent bool) checkpointIncarnationObservation {
	return checkpointIncarnationObservation{PodName: name, PodUID: string(uid), Incarnation: body.Incarnation, BootSequence: body.BootSequence, BootChecksum: body.BootChecksum, AcknowledgedSequence: body.Sequence, AcknowledgedChecksum: body.Checksum, PreviousUIDAbsent: previousAbsent, PostBootAdvance: body.Sequence > body.BootSequence}
}

func (s *c2CheckpointContinuity) ensureCheckpointIncarnationChain() error {
	if len(s.incarnationChain) > 0 {
		return nil
	}
	if s.targetName == "" || s.targetUID == "" || s.originalIncarnation == "" || s.lastOriginal.Sequence < 0 {
		return errors.New("checkpoint incarnation chain provenance missing")
	}
	s.incarnationChain = []checkpointIncarnationObservation{checkpointIncarnationFrom(s.targetName, s.targetUID, s.lastOriginal, false)}
	return nil
}

func (s *c2CheckpointContinuity) observeCheckpointReply(ctx context.Context, env *core.Env, reply checkpointBody, final bool) (*corev1.Pod, bool, error) {
	if err := s.ensureCheckpointIncarnationChain(); err != nil {
		return nil, false, err
	}
	current := &s.incarnationChain[len(s.incarnationChain)-1]
	pod, absent, err := c2DwellObservationTarget(ctx, env, checkpointApp, current.PodName, types.UID(current.PodUID))
	if err != nil {
		return nil, false, err
	}
	if !podReady(pod) || pod.DeletionTimestamp != nil {
		return nil, false, errors.New("checkpoint observation target is unavailable")
	}
	if err = s.validateObservedCheckpointWorkload(ctx, env, pod); err != nil {
		return nil, false, err
	}
	if err = validateCheckpointIdentity(reply, pod.UID, s.pvcUID); err != nil {
		return nil, false, err
	}
	if !absent {
		if string(pod.UID) != current.PodUID || reply.Incarnation != current.Incarnation {
			return nil, false, errors.New("checkpoint reply changed current Pod/process identity")
		}
		if reply.BootSequence != current.BootSequence || reply.BootChecksum != current.BootChecksum || reply.InitializedFresh == nil || (*reply.InitializedFresh) != (len(s.incarnationChain) == 1) {
			return nil, false, errors.New("checkpoint boot provenance changed within incarnation")
		}
		if reply.Sequence < current.AcknowledgedSequence {
			return nil, false, errors.New("checkpoint sequence moved backwards within incarnation")
		}
		if final && len(s.incarnationChain) == 1 && reply.Sequence == current.AcknowledgedSequence {
			return nil, false, errors.New("same-Pod checkpoint progress stalled")
		}
		current.AcknowledgedSequence, current.AcknowledgedChecksum = reply.Sequence, reply.Checksum
		current.PostBootAdvance = current.PostBootAdvance || reply.Sequence > reply.BootSequence
		if len(s.incarnationChain) == 1 {
			s.lastOriginal = reply
		}
		if final && !current.PostBootAdvance {
			return nil, false, errors.New("final checkpoint incarnation did not advance beyond boot")
		}
		return pod, false, nil
	}
	for _, seen := range s.incarnationChain {
		if string(pod.UID) == seen.PodUID || reply.Incarnation == seen.Incarnation {
			return nil, false, errors.New("checkpoint replacement reused a prior Pod UID or process incarnation")
		}
	}
	if len(s.incarnationChain) >= checkpointMaxIncarnations {
		return nil, false, errors.New("checkpoint incarnation chain exceeds bounded capacity")
	}
	high := checkpointBody{Sequence: current.AcknowledgedSequence, Checksum: current.AcknowledgedChecksum}
	if err = validateCheckpointReplacement(reply, high, current.Incarnation, final); err != nil {
		return nil, false, err
	}
	s.incarnationChain = append(s.incarnationChain, checkpointIncarnationFrom(pod.Name, pod.UID, reply, true))
	return pod, true, nil
}

func (s *c2CheckpointContinuity) checkpointIncarnationChainJSON() string {
	raw, _ := json.Marshal(s.incarnationChain)
	return string(raw)
}

func (s *c2CheckpointContinuity) validateObservedCheckpointWorkload(ctx context.Context, env *core.Env, pod *corev1.Pod) error {
	if pod == nil || pod.UID == "" || s.deploymentUID == "" || s.replicaSetUID == "" || s.serviceUID == "" {
		return errors.New("checkpoint workload identity provenance missing")
	}
	ownedByReplicaSet := false
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "ReplicaSet" && owner.Name == s.replicaSetName && owner.UID == s.replicaSetUID && owner.Controller != nil && *owner.Controller {
			ownedByReplicaSet = true
		}
	}
	if !ownedByReplicaSet {
		return errors.New("checkpoint Pod is not owned by exact ReplicaSet UID")
	}
	mounted := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == "state" && volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == checkpointPVC {
			mounted = true
		}
	}
	if !mounted {
		return errors.New("checkpoint Pod does not mount exact owned PVC")
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, s.replicaSetName, metav1.GetOptions{})
	if err != nil || rs.UID != s.replicaSetUID {
		return fmt.Errorf("checkpoint ReplicaSet identity changed: rs=%v err=%v", rs, err)
	}
	rsOwned := false
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" && owner.Name == checkpointApp && owner.UID == s.deploymentUID && owner.Controller != nil && *owner.Controller {
			rsOwned = true
		}
	}
	if !rsOwned {
		return errors.New("checkpoint ReplicaSet is not owned by exact Deployment UID")
	}
	dep, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Get(ctx, checkpointApp, metav1.GetOptions{})
	if err != nil || dep.UID != s.deploymentUID {
		return fmt.Errorf("checkpoint Deployment identity changed: deployment=%v err=%v", dep, err)
	}
	svc, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, checkpointService, metav1.GetOptions{})
	if err != nil || svc.UID != s.serviceUID {
		return fmt.Errorf("checkpoint Service identity changed: service=%v err=%v", svc, err)
	}
	if len(svc.Spec.Selector) != 1 || svc.Spec.Selector["app"] != checkpointApp {
		return fmt.Errorf("checkpoint Service selector changed: %v", svc.Spec.Selector)
	}
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + checkpointService})
	if err != nil {
		return fmt.Errorf("list checkpoint EndpointSlices: %w", err)
	}
	readyTargets := 0
	for i := range slices.Items {
		slice := &slices.Items[i]
		ownedByService := false
		for _, owner := range slice.OwnerReferences {
			if owner.Kind == "Service" && owner.Name == checkpointService && owner.UID == s.serviceUID && owner.Controller != nil && *owner.Controller {
				ownedByService = true
			}
		}
		if !ownedByService {
			return fmt.Errorf("checkpoint EndpointSlice %q is not owned by exact Service UID", slice.Name)
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			readyTargets++
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != env.Config.Namespace || endpoint.TargetRef.Name != pod.Name || endpoint.TargetRef.UID != pod.UID {
				return fmt.Errorf("checkpoint ready endpoint is not exact observed Pod UID %s", pod.UID)
			}
		}
	}
	if readyTargets != 1 {
		return fmt.Errorf("checkpoint Service has %d ready endpoint targets; require exactly one", readyTargets)
	}
	return nil
}

func validateCheckpointReplacement(reply, highWater checkpointBody, originalIncarnation string, requirePostBootAdvance bool) error {
	if reply.Incarnation == originalIncarnation {
		return errors.New("replacement reused original process incarnation")
	}
	if reply.InitializedFresh == nil || *reply.InitializedFresh {
		return errors.New("replacement reported fresh-volume initialization")
	}
	if reply.BootSequence < highWater.Sequence {
		return errors.New("replacement boot checkpoint predates highest original acknowledgement")
	}
	if reply.BootSequence == highWater.Sequence && reply.BootChecksum != highWater.Checksum {
		return errors.New("replacement boot checksum differs at retained sequence")
	}
	if reply.Sequence < reply.BootSequence || requirePostBootAdvance && reply.Sequence == reply.BootSequence {
		return errors.New("replacement did not advance beyond boot-loaded checkpoint")
	}
	return nil
}

func (s *c2CheckpointContinuity) Teardown(ctx context.Context, env *core.Env) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	var errs []error
	deletes := []struct {
		name string
		uid  types.UID
		fn   func(metav1.DeleteOptions) error
	}{{checkpointApp, s.deploymentUID, func(o metav1.DeleteOptions) error {
		return env.Kube.AppsV1().Deployments(ns).Delete(ctx, checkpointApp, o)
	}}, {s.targetName, s.targetUID, func(o metav1.DeleteOptions) error { return env.Kube.CoreV1().Pods(ns).Delete(ctx, s.targetName, o) }}, {s.replicaSetName, s.replicaSetUID, func(o metav1.DeleteOptions) error {
		return env.Kube.AppsV1().ReplicaSets(ns).Delete(ctx, s.replicaSetName, o)
	}}, {checkpointService, s.serviceUID, func(o metav1.DeleteOptions) error {
		return env.Kube.CoreV1().Services(ns).Delete(ctx, checkpointService, o)
	}}, {checkpointProducer, s.producerUID, func(o metav1.DeleteOptions) error {
		return env.Kube.CoreV1().Pods(ns).Delete(ctx, checkpointProducer, o)
	}}, {checkpointPVC, s.pvcUID, func(o metav1.DeleteOptions) error {
		return env.Kube.CoreV1().PersistentVolumeClaims(ns).Delete(ctx, checkpointPVC, o)
	}}}
	for _, d := range deletes {
		if d.uid == "" || d.name == "" {
			continue
		}
		if err := d.fn(sessionDeleteOptions(d.uid)); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete %s uid=%s: %w", d.name, d.uid, err))
		}
	}
	return errors.Join(errs...)
}

func (s *c2CheckpointContinuity) verifyStorageIdentity(ctx context.Context, env *core.Env) error {
	pvc, err := env.Kube.CoreV1().PersistentVolumeClaims(env.Config.Namespace).Get(ctx, checkpointPVC, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read checkpoint PVC identity: %w", err)
	}
	if pvc.UID != s.pvcUID || pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName != s.pvName || pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != s.storageClassName {
		return fmt.Errorf("checkpoint PVC identity/binding changed: uid=%s volume=%q", pvc.UID, pvc.Spec.VolumeName)
	}
	pv, err := env.Kube.CoreV1().PersistentVolumes().Get(ctx, s.pvName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read checkpoint PV identity: %w", err)
	}
	if pv.UID != s.pvUID || pv.Spec.StorageClassName != s.storageClassName || !checkpointPVClaimsPVC(pv, pvc) {
		return fmt.Errorf("checkpoint PV identity/binding changed: observedUID=%s expectedUID=%s", pv.UID, s.pvUID)
	}
	if s.localFixture {
		if err := s.validateCheckpointLocalPVC(pvc, s.pvName, checkpointLocalSelector(env.DefenderName, env.Trial, s.localSlot)); err != nil {
			return err
		}
		sc, err := env.Kube.StorageV1().StorageClasses().Get(ctx, s.storageClassName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read checkpoint local StorageClass identity: %w", err)
		}
		if err := validateCheckpointLocalStorageClass(sc, s.storageClassUID, s.localNonce); err != nil {
			return err
		}
		if err := s.validateCheckpointLocalPV(pv, checkpointLocalSelector(env.DefenderName, env.Trial, s.localSlot), false); err != nil {
			return err
		}
		if err := s.validateCheckpointLocalHolder(ctx, env); err != nil {
			return err
		}
	}
	return nil
}

func (s *c2CheckpointContinuity) addCheckpointLocalEvidence(out map[string]string) {
	if !s.localFixture {
		return
	}
	out["checkpointStorageMode"] = "owned node-local fixture"
	out["checkpointLocalHolderUID"] = string(s.localHolderUID)
	out["checkpointLocalNodeUID"] = string(s.localNodeUID)
	out["checkpointLocalNodeName"] = s.localNodeName
	out["checkpointLocalSlot"] = strconv.Itoa(s.localSlot)
	out["checkpointLocalNonce"] = s.localNonce
	out["checkpointLocalPathSHA256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(s.localPath)))
	out["checkpointLocalMarkerInitSourceSHA256"] = checkpointMarkerInitSourceSHA256()
}

func checkpointPVClaimsPVC(pv *corev1.PersistentVolume, pvc *corev1.PersistentVolumeClaim) bool {
	return pv.Spec.ClaimRef != nil && pv.Spec.ClaimRef.Namespace == pvc.Namespace && pv.Spec.ClaimRef.Name == pvc.Name && pv.Spec.ClaimRef.UID == pvc.UID
}

type checkpointBody struct {
	Version          int64  `json:"version"`
	PodUID           string `json:"podUID"`
	PVCUID           string `json:"pvcUID"`
	Incarnation      string `json:"incarnation"`
	Sequence         int64  `json:"sequence"`
	Payload          string `json:"payload"`
	Checksum         string `json:"checksum"`
	BootSequence     int64  `json:"bootSequence"`
	BootChecksum     string `json:"bootChecksum"`
	Ready            *bool  `json:"ready"`
	InitializedFresh *bool  `json:"initializedFresh"`
	Error            string `json:"error"`
}
type checkpointReply struct {
	HTTPStatus int
	Body       checkpointBody
}
type checkpointReceipt struct {
	URL                 string `json:"url"`
	ProducerUID         string `json:"producerUID"`
	ObservedProducerUID string `json:"observedProducerUID,omitempty"`
	ExitCode            int    `json:"exitCode"`
	Stdout              string `json:"stdout"`
	StdoutBytes         int    `json:"stdoutBytes"`
	StdoutSHA256        string `json:"stdoutSHA256"`
	StdoutTruncated     bool   `json:"stdoutTruncated"`
	Stderr              string `json:"stderr"`
	StderrBytes         int    `json:"stderrBytes"`
	StderrSHA256        string `json:"stderrSHA256"`
	StderrTruncated     bool   `json:"stderrTruncated"`
	ExecError           string `json:"execError,omitempty"`
	ContextError        string `json:"contextError,omitempty"`
	IdentityError       string `json:"identityError,omitempty"`
	RequestStartedAtUTC string `json:"requestStartedAtUTC,omitempty"`
	RequestEndedAtUTC   string `json:"requestEndedAtUTC,omitempty"`
	DurationMillis      int64  `json:"durationMillis,omitempty"`
}

func (s *c2CheckpointContinuity) request(ctx context.Context, env *core.Env) (checkpointBody, error) {
	url := fmt.Sprintf("http://%s:%d/progress", checkpointService, checkpointPort)
	rec := checkpointReceipt{URL: url, ProducerUID: string(s.producerUID), ExitCode: -1}
	p, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, checkpointProducer, metav1.GetOptions{})
	if err != nil {
		rec.IdentityError = err.Error()
		recordCheckpointReceipt(env, rec)
		return checkpointBody{}, err
	}
	rec.ObservedProducerUID = string(p.UID)
	if s.producerUID == "" || p.UID != s.producerUID {
		rec.IdentityError = "producer UID mismatch"
		recordCheckpointReceipt(env, rec)
		return checkpointBody{}, errors.New(rec.IdentityError)
	}
	started := time.Now()
	res := env.Exec(ctx, checkpointProducer, "producer", []string{"python3", "-B", "-c", checkpointClientSource, url})
	ended := time.Now()
	rec.RequestStartedAtUTC = started.UTC().Format(time.RFC3339Nano)
	rec.RequestEndedAtUTC = ended.UTC().Format(time.RFC3339Nano)
	rec.DurationMillis = ended.Sub(started).Milliseconds()
	rec.ExitCode = res.ExitCode
	rec.Stdout, rec.StdoutBytes, rec.StdoutSHA256, rec.StdoutTruncated = boundedSessionReceipt(res.Stdout, 8192)
	rec.Stderr, rec.StderrBytes, rec.StderrSHA256, rec.StderrTruncated = boundedSessionReceipt(res.Stderr, 1024)
	if res.Err != nil {
		rec.ExecError = res.Err.Error()
	}
	if err := ctx.Err(); err != nil {
		rec.ContextError = err.Error()
	}
	recordCheckpointReceipt(env, rec)
	if res.Err != nil {
		return checkpointBody{}, res.Err
	}
	if err := ctx.Err(); err != nil {
		return checkpointBody{}, err
	}
	if res.ExitCode != 0 {
		return checkpointBody{}, fmt.Errorf("checkpoint HTTP producer exit=%d: %s", res.ExitCode, rec.Stderr)
	}
	reply, err := parseCheckpointReply(res.Stdout)
	if err != nil {
		return checkpointBody{}, err
	}
	if reply.HTTPStatus != 200 {
		return checkpointBody{}, fmt.Errorf("checkpoint HTTP status=%d error=%q", reply.HTTPStatus, reply.Body.Error)
	}
	return reply.Body, nil
}
func recordCheckpointReceipt(env *core.Env, r checkpointReceipt) {
	raw, _ := json.Marshal(r)
	env.Log.Logf("c2-checkpoint-continuity http-receipt=%s", raw)
}

func parseCheckpointReply(out string) (checkpointReply, error) {
	parts := strings.Split(out, "\n")
	if len(parts) != 2 {
		return checkpointReply{}, errors.New("malformed checkpoint HTTP envelope")
	}
	status, err := strconv.Atoi(parts[0])
	if err != nil {
		return checkpointReply{}, err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return checkpointReply{}, err
	}
	body, err := parseCheckpointBody(raw)
	return checkpointReply{HTTPStatus: status, Body: body}, err
}
func parseCheckpointBody(raw []byte) (checkpointBody, error) {
	var b checkpointBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return b, errors.New("malformed checkpoint JSON")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return b, err
		}
		k, ok := t.(string)
		if !ok || seen[k] {
			return b, fmt.Errorf("duplicate/malformed checkpoint field %q", k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return b, err
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return b, fmt.Errorf("null checkpoint field %q", k)
		}
		switch k {
		case "version":
			err = json.Unmarshal(v, &b.Version)
		case "podUID":
			err = json.Unmarshal(v, &b.PodUID)
		case "pvcUID":
			err = json.Unmarshal(v, &b.PVCUID)
		case "incarnation":
			err = json.Unmarshal(v, &b.Incarnation)
		case "sequence":
			err = json.Unmarshal(v, &b.Sequence)
		case "payload":
			err = json.Unmarshal(v, &b.Payload)
		case "checksum":
			err = json.Unmarshal(v, &b.Checksum)
		case "bootSequence":
			err = json.Unmarshal(v, &b.BootSequence)
		case "bootChecksum":
			err = json.Unmarshal(v, &b.BootChecksum)
		case "ready":
			err = json.Unmarshal(v, &b.Ready)
		case "initializedFresh":
			err = json.Unmarshal(v, &b.InitializedFresh)
		case "error":
			err = json.Unmarshal(v, &b.Error)
		default:
			return b, fmt.Errorf("unknown checkpoint field %q", k)
		}
		if err != nil {
			return b, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return b, err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return b, err
	}
	for _, k := range []string{"version", "podUID", "pvcUID", "incarnation", "sequence", "payload", "checksum", "bootSequence", "bootChecksum", "ready", "initializedFresh", "error"} {
		if !seen[k] {
			return b, fmt.Errorf("required checkpoint field %q absent", k)
		}
	}
	return b, nil
}
func validateCheckpointIdentity(b checkpointBody, pod, pvc types.UID) error {
	if b.Ready == nil || !*b.Ready {
		return errors.New("checkpoint reply not explicitly ready")
	}
	if b.Version != 1 || b.PodUID == "" || b.PodUID != string(pod) || b.PVCUID == "" || b.PVCUID != string(pvc) || b.Incarnation == "" || b.Sequence < 0 || b.BootSequence < 0 {
		return errors.New("checkpoint reply identity/version invalid")
	}
	wantPayload := fmt.Sprintf("synthetic-sequence-%020d", b.Sequence)
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("v1\n%d\n%s", b.Sequence, wantPayload))))
	if b.Payload != wantPayload || b.Checksum != want {
		return errors.New("checkpoint reply payload/checksum invalid")
	}
	bootPayload := fmt.Sprintf("synthetic-sequence-%020d", b.BootSequence)
	bootChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("v1\n%d\n%s", b.BootSequence, bootPayload))))
	if b.BootChecksum != bootChecksum {
		return errors.New("checkpoint reply boot checksum invalid")
	}
	return nil
}
func waitCheckpointObservation(ctx context.Context, window, interval time.Duration, sample func() (checkpointBody, error)) (time.Time, time.Time, int, int, error) {
	start := time.Now()
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	n := 0
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return start, time.Now(), n, failures, ctx.Err()
		case <-deadline.C:
			return start, time.Now(), n, failures, nil
		case <-ticker.C:
			n++
			if _, err := sample(); err != nil {
				failures++
			}
		}
	}
}
