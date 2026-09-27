package console

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

var drainLiveInFlight atomic.Bool

func (s *Server) drainReadKube(ctx context.Context, out, label string, allowEmpty bool, args ...string) ([]byte, error) {
	return s.drainReadKubeInput(ctx, out, label, allowEmpty, nil, args...)
}

func (s *Server) drainReadKubeInput(ctx context.Context, out, label string, allowEmpty bool, input []byte, args ...string) ([]byte, error) {
	c, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	cmd := exec.CommandContext(c, "kubectl", args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	stdout, stderr := &availabilityCappedWriter{max: 1 << 20}, &availabilityCappedWriter{max: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil || stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("bounded request-drain GET unavailable: %s", label)
	}
	raw := append([]byte(nil), stdout.Bytes()...)
	if len(raw) == 0 && !allowEmpty {
		return nil, fmt.Errorf("empty request-drain GET: %s", label)
	}
	if len(raw) > 0 {
		saved := raw
		if strings.HasSuffix(label, "-target") || strings.HasSuffix(label, "-manager") || strings.HasSuffix(label, "-console") {
			var pod vllmPodState
			if json.Unmarshal(raw, &pod) != nil {
				return nil, errors.New("Pod source JSON malformed")
			}
			labels := map[string]string{}
			if pod.Metadata.Labels != nil {
				labels = *pod.Metadata.Labels
			}
			annotations := map[string]string{}
			if pod.Metadata.Annotations != nil {
				for _, key := range []string{"phorvex.ai/drain-proxy-source", "phorvex.ai/drain-engine-source"} {
					if value, ok := (*pod.Metadata.Annotations)[key]; ok {
						annotations[key] = value
					}
				}
			}
			saved = drainJSON(map[string]any{"rawSHA256": availabilityHash(raw), "metadata": map[string]any{"name": pod.Metadata.Name, "uid": pod.Metadata.UID, "labels": labels, "annotations": annotations, "ownerReferences": pod.Metadata.OwnerReferences},
				"status": map[string]any{"containerStatuses": pod.Status.ContainerStatuses}})
		} else if strings.HasSuffix(label, "-console-replicaset") || strings.HasSuffix(label, "-console-deployment") {
			var owner vllmPodState
			if json.Unmarshal(raw, &owner) != nil {
				return nil, errors.New("console owner JSON malformed")
			}
			saved = drainJSON(map[string]any{"rawSHA256": availabilityHash(raw), "metadata": map[string]any{"name": owner.Metadata.Name, "uid": owner.Metadata.UID, "ownerReferences": owner.Metadata.OwnerReferences}})
		} else if strings.HasSuffix(label, "-journal") {
			var cm struct {
				Metadata struct {
					Name string `json:"name"`
					UID  string `json:"uid"`
				} `json:"metadata"`
			}
			if json.Unmarshal(raw, &cm) != nil {
				return nil, errors.New("journal metadata malformed")
			}
			saved = drainJSON(map[string]any{"rawSHA256": availabilityHash(raw), "metadata": cm.Metadata, "dataIncluded": false})
		}
		if err := publishMongoAuditFile(out, label+".json", saved, 1<<20); err != nil {
			return nil, err
		}
	} else {
		if err := publishMongoAuditFile(out, label+"-absence.json", drainJSON(map[string]any{"schema": "exact-get-absence-v1", "name": label, "stdoutSHA256": availabilityHash(nil)}), 4096); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

const drainInstalledSourcePython = `import hashlib,json,pathlib,sysconfig
base=pathlib.Path(sysconfig.get_paths()["purelib"])/"vllm"/"entrypoints"/"openai"
names=("serving_completion.py","serving_engine.py")
print(json.dumps({name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in names},sort_keys=True))`

const drainModelPython = `import json,urllib.request
expected="Qwen/Qwen2.5-7B-Instruct-AWQ"
with urllib.request.urlopen("http://vllm.vllm.svc.cluster.local:8000/v1/models",timeout=8) as response:
 raw=response.read(8193)
 if len(raw)>8192 or response.status!=200:raise RuntimeError("model_inventory")
 value=json.loads(raw)
 rows=value.get("data")
 if not isinstance(rows,list) or len(rows)<1 or len(rows)>16:raise RuntimeError("model_rows")
 ids=[row.get("id") for row in rows if isinstance(row,dict)]
 print(json.dumps({"exact":ids.count(expected)==1,"count":len(rows)}))`

const drainRetainedModelPython = `import http.client,json,signal,sys
signal.alarm(12)
key=sys.stdin.buffer.read(257)
if len(key)<32 or len(key)>256 or any(c<33 or c>126 for c in key):raise RuntimeError("caller_bound")
conn=http.client.HTTPConnection("vllm.vllm.svc.cluster.local",8000,timeout=8)
try:
 conn.request("GET","/v1/models",headers={"Authorization":"Bearer "+key.decode("ascii")})
 response=conn.getresponse();raw=response.read(8193)
 if response.status!=200 or len(raw)>8192:raise RuntimeError("authenticated_model_inventory")
 rows=json.loads(raw).get("data")
 if not isinstance(rows,list) or len(rows)<1 or len(rows)>16:raise RuntimeError("model_rows")
 ids=[row.get("id") for row in rows if isinstance(row,dict)]
 print(json.dumps({"exact":ids.count("Qwen/Qwen2.5-7B-Instruct-AWQ")==1,"count":len(rows)}))
finally:conn.close()
`

func (s *Server) drainInstalledSource(ctx context.Context, out, phase string, p drainLiveProfile) error {
	args := []string{"-n", "vllm", "exec", p.PodName, "-c", "vllm", "--", "python3", "-B", "-c", drainInstalledSourcePython}
	raw, err := s.drainReadKube(ctx, out, phase+"-installed-source", false, args...)
	if err != nil {
		return err
	}
	var hashes map[string]string
	if json.Unmarshal(raw, &hashes) != nil || len(hashes) != 2 || hashes["serving_completion.py"] != p.ServingCompletionSHA256 || hashes["serving_engine.py"] != p.ServingEngineSHA256 {
		return errors.New("installed serving source drift")
	}
	return nil
}

func (s *Server) drainModelInventory(ctx context.Context, out, phase string, p drainLiveProfile) error {
	code := drainModelPython
	if p.retainedCaller != nil {
		code = drainRetainedModelPython
	}
	raw, err := s.drainReadKubeInput(ctx, out, phase+"-model-inventory", false, p.retainedCaller.bearer(), "-n", "vllm", "exec", "-i", p.PodName, "-c", "guardrail", "--", "python3", "-B", "-c", code)
	if err != nil {
		return err
	}
	var row struct {
		Exact bool `json:"exact"`
		Count int  `json:"count"`
	}
	if json.Unmarshal(raw, &row) != nil || !row.Exact || row.Count < 1 || row.Count > 16 {
		return errors.New("fixed model identity unavailable")
	}
	return nil
}

func (s *Server) drainLivePreflight(ctx context.Context, out string, p drainLiveProfile, phase string) error {
	if err := p.retainedCaller.check(ctx); err != nil {
		return err
	}
	read := func(label string, allowEmpty bool, args ...string) ([]byte, error) {
		return s.drainReadKube(ctx, out, phase+"-"+label, allowEmpty, args...)
	}
	raw, err := read("cluster", false, "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return err
	}
	var cluster struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &cluster) != nil || cluster.Metadata.UID != p.ClusterUID {
		return errors.New("cluster UID drift")
	}
	raw, err = read("target", false, "-n", "vllm", "get", "pod", p.PodName, "-o", "json")
	if err != nil {
		return err
	}
	var pod vllmPodState
	if json.Unmarshal(raw, &pod) != nil || pod.Metadata.UID != p.PodUID || pod.Metadata.Name != p.PodName || pod.Metadata.Labels == nil ||
		(*pod.Metadata.Labels)["phorvex.ai/serving"] != "true" || pod.Metadata.Annotations == nil ||
		(*pod.Metadata.Annotations)["phorvex.ai/drain-proxy-source"] != p.DrainProxySourceSHA256 ||
		(*pod.Metadata.Annotations)["phorvex.ai/drain-engine-source"] != p.DrainEngineSourceSHA256 {
		return errors.New("target Pod/source drift")
	}
	_, leaseSource := (*pod.Metadata.Annotations)["phorvex.ai/endpoint-lease-source-sha256"]
	if leaseSource != (p.retainedCaller != nil) {
		return errors.New("drain source and retained caller authority differ")
	}
	if !drainPinnedContainer(pod, "vllm", p.PodImageID, p.PodContainerID) ||
		!drainPinnedContainer(pod, "guardrail", p.ProxyImageID, p.ProxyContainerID) {
		return errors.New("target vLLM container identity drift")
	}
	if err = s.drainInstalledSource(ctx, out, phase, p); err != nil {
		return err
	}
	if phase == "before" {
		if err = s.drainModelInventory(ctx, out, phase, p); err != nil {
			return err
		}
	}
	raw, err = read("service", false, "-n", "vllm", "get", "service", p.ServiceName, "-o", "json")
	if err != nil {
		return err
	}
	var svc vllmServiceState
	if json.Unmarshal(raw, &svc) != nil || svc.Metadata.UID != p.ServiceUID || svc.Metadata.Name != p.ServiceName || svc.Spec.Selector == nil || !maps.Equal(*svc.Spec.Selector, p.ServiceSelector) ||
		len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 8000 || svc.Spec.Ports[0].Protocol != "TCP" || string(svc.Spec.Ports[0].TargetPort) != "8000" {
		return errors.New("route Service identity drift")
	}
	for key, value := range *svc.Spec.Selector {
		actual, exists := (*pod.Metadata.Labels)[key]
		if !exists || actual != value {
			return errors.New("route Service no longer selects exact target")
		}
	}
	raw, err = read("services", false, "-n", "vllm", "get", "services", "-o", "json")
	if err != nil {
		return err
	}
	var services vllmServiceList
	if json.Unmarshal(raw, &services) != nil || len(services.Items) > 64 {
		return errors.New("route Service inventory malformed")
	}
	selecting := 0
	for _, candidate := range services.Items {
		if candidate.Spec.Selector == nil || len(*candidate.Spec.Selector) == 0 {
			continue
		}
		match := true
		for key, value := range *candidate.Spec.Selector {
			actual, exists := (*pod.Metadata.Labels)[key]
			if !exists || actual != value {
				match = false
				break
			}
		}
		if match {
			selecting++
			if candidate.Metadata.UID != p.ServiceUID || candidate.Metadata.Name != p.ServiceName {
				return errors.New("alternate selecting Service present")
			}
		}
	}
	if selecting != 1 {
		return errors.New("route Service cardinality drift")
	}
	raw, err = read("endpointslices", false, "-n", "vllm", "get", "endpointslices", "-l", "kubernetes.io/service-name="+p.ServiceName, "-o", "json")
	if err != nil {
		return err
	}
	var slices vllmEndpointSliceList
	if json.Unmarshal(raw, &slices) != nil || len(slices.Items) < 1 || len(slices.Items) > 8 {
		return errors.New("route EndpointSlice inventory drift")
	}
	readyTarget := 0
	for _, slice := range slices.Items {
		if slice.Metadata.Labels["kubernetes.io/service-name"] != p.ServiceName {
			return errors.New("route EndpointSlice label drift")
		}
		owner := 0
		for _, ref := range slice.Metadata.OwnerReferences {
			if ref.Kind == "Service" && ref.Name == p.ServiceName && ref.UID == p.ServiceUID {
				owner++
			}
		}
		if owner != 1 {
			return errors.New("route EndpointSlice owner drift")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready && (endpoint.Conditions.Terminating == nil || !*endpoint.Conditions.Terminating) {
				if endpoint.TargetRef == nil || endpoint.TargetRef.UID != p.PodUID {
					return errors.New("route has alternate Ready target")
				}
				readyTarget++
			}
		}
	}
	if readyTarget != 1 {
		return errors.New("route Ready target cardinality drift")
	}
	raw, err = read("policy", false, "-n", "vllm", "get", "phorvexpolicy", p.PolicyName, "-o", "json")
	if err != nil {
		return err
	}
	var policy struct {
		Metadata struct {
			UID        string `json:"uid"`
			Generation int64  `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Mode     string `json:"mode"`
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
			Actions struct {
				Enabled []string `json:"enabled"`
			} `json:"actions"`
		} `json:"spec"`
	}
	if json.Unmarshal(raw, &policy) != nil || policy.Metadata.UID != p.PolicyUID || policy.Metadata.Generation != p.PolicyGeneration || policy.Spec.Mode != "active" || len(policy.Spec.Selector.MatchLabels) == 0 {
		return errors.New("policy identity drift")
	}
	for key, value := range policy.Spec.Selector.MatchLabels {
		actual, exists := (*pod.Metadata.Labels)[key]
		if !exists || actual != value {
			return errors.New("policy no longer selects target")
		}
	}
	allowed := false
	for _, a := range policy.Spec.Actions.Enabled {
		allowed = allowed || a == "request-drain"
	}
	if !allowed {
		return errors.New("policy does not enable request-drain")
	}
	raw, err = read("manager", false, "-n", "phorvex-system", "get", "pod", p.ManagerPodName, "-o", "json")
	if err != nil {
		return err
	}
	var manager vllmPodState
	if json.Unmarshal(raw, &manager) != nil || manager.Metadata.UID != p.ManagerPodUID {
		return errors.New("manager Pod identity drift")
	}
	managerReady := false
	for _, c := range manager.Status.ContainerStatuses {
		if c.Name == "manager" && c.Ready && c.ImageID == p.ManagerImageID && c.ContainerID == p.ManagerContainerID {
			managerReady = true
		}
	}
	if !managerReady {
		return errors.New("manager image drift")
	}
	consoleName := os.Getenv("PHORVEX_CONSOLE_POD_NAME")
	if consoleName == "" {
		return errors.New("console self identity unavailable")
	}
	raw, err = read("console", false, "-n", "phorvex-system", "get", "pod", consoleName, "-o", "json")
	if err != nil {
		return err
	}
	var self vllmPodState
	if json.Unmarshal(raw, &self) != nil || self.Metadata.UID == "" || self.Metadata.UID != os.Getenv("PHORVEX_CONSOLE_POD_UID") || self.Metadata.Name != consoleName {
		return errors.New("console Pod identity drift")
	}
	consoleReady := false
	for _, c := range self.Status.ContainerStatuses {
		if c.Name == "console" && c.Ready && c.ImageID == p.ConsoleImageID && c.ContainerID != "" {
			consoleReady = true
		}
	}
	if !consoleReady {
		return errors.New("console image drift")
	}
	rsName, rsUID, ownerOK := soleControllerOwner(self.Metadata.OwnerReferences, "ReplicaSet")
	if !ownerOK {
		return errors.New("console ReplicaSet owner unavailable")
	}
	raw, err = read("console-replicaset", false, "-n", "phorvex-system", "get", "replicaset", rsName, "-o", "json")
	if err != nil {
		return err
	}
	var rs vllmPodState
	if json.Unmarshal(raw, &rs) != nil || rs.Metadata.UID != rsUID {
		return errors.New("console ReplicaSet identity drift")
	}
	depName, depUID, ownerOK := soleControllerOwner(rs.Metadata.OwnerReferences, "Deployment")
	if !ownerOK || depName != p.ConsoleDeploymentName || depUID != p.ConsoleDeploymentUID {
		return errors.New("console Deployment owner drift")
	}
	raw, err = read("console-deployment", false, "-n", "phorvex-system", "get", "deployment", depName, "-o", "json")
	if err != nil {
		return err
	}
	var dep vllmPodState
	if json.Unmarshal(raw, &dep) != nil || dep.Metadata.UID != p.ConsoleDeploymentUID {
		return errors.New("console Deployment identity drift")
	}
	journalName := drainJournalName(p.PolicyUID, p.PodUID)
	raw, err = read("journal", true, "-n", "phorvex-system", "get", "configmap", journalName, "-o", "json", "--ignore-not-found=true")
	if err != nil {
		return err
	}
	if len(raw) != 0 {
		return errors.New("protected request-drain journal occupied")
	}
	return p.retainedCaller.check(ctx)
}

func drainPinnedContainer(pod vllmPodState, name, imageID, containerID string) bool {
	if imageID == "" || containerID == "" {
		return false
	}
	matches := 0
	for _, c := range pod.Status.ContainerStatuses {
		if c.Name == name && c.Ready && c.RestartCount >= 0 &&
			c.ImageID == imageID && c.ContainerID == containerID {
			matches++
		}
	}
	return matches == 1
}

func soleControllerOwner(refs []struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller"`
}, kind string) (string, string, bool) {
	name, uid, count := "", "", 0
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller {
			count++
			name, uid = ref.Name, ref.UID
			if ref.Kind != kind || name == "" || uid == "" {
				return "", "", false
			}
		}
	}
	return name, uid, count == 1
}

func drainConsoleIncarnationStable(out string) error {
	var previous string
	for _, phase := range []string{"before", "after"} {
		path := filepath.Join(out, phase+"-console.json")
		info, err := os.Stat(path)
		if err != nil || info.Size() < 1 || info.Size() > 1<<20 {
			return errors.New("console original unavailable")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var pod vllmPodState
		if json.Unmarshal(raw, &pod) != nil {
			return errors.New("console original malformed")
		}
		container := ""
		for _, c := range pod.Status.ContainerStatuses {
			if c.Name == "console" {
				container = c.ContainerID
			}
		}
		identity := pod.Metadata.UID + "|" + container
		if pod.Metadata.UID == "" || container == "" || (previous != "" && identity != previous) {
			return errors.New("console self incarnation changed during run")
		}
		previous = identity
	}
	return nil
}

func drainJournalName(policyUID, podUID string) string {
	hash := sha256.Sum256([]byte("request-drain/" + policyUID + "/" + podUID))
	return fmt.Sprintf("phorvex-operation-%x", hash[:20])
}

func (s *Server) drainBenign(ctx context.Context, p drainLiveProfile, body []byte) (int, bool, error) {
	if err := p.retainedCaller.check(ctx); err != nil {
		return 0, false, err
	}
	c, stop := context.WithTimeout(ctx, 25*time.Second)
	defer stop()
	cmd := exec.CommandContext(c, "kubectl", "-n", "vllm", "exec", "-i", p.PodName, "-c", "guardrail", "--", "python3", "-B", "-c", drainBenignPython)
	input := []byte(base64Body(body))
	if p.retainedCaller != nil {
		input, _ = json.Marshal(map[string]string{"body": base64Body(body), "bearer": base64Body(p.retainedCaller.bearer())})
	}
	cmd.Stdin = bytes.NewReader(input)
	stdout, stderr := &availabilityCappedWriter{max: 4096}, &availabilityCappedWriter{max: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil || stdout.overflow || stderr.overflow {
		return 0, false, errors.New("bounded benign completion unavailable")
	}
	var row struct {
		Status     int    `json:"status"`
		Valid      bool   `json:"valid"`
		BodySHA256 string `json:"bodySHA256"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&row) != nil || decoder.Decode(&struct{}{}) != io.EOF || !staticSHA256.MatchString(row.BodySHA256) {
		return 0, false, errors.New("benign completion projection malformed")
	}
	if err := p.retainedCaller.check(ctx); err != nil {
		return 0, false, err
	}
	return row.Status, row.Valid, nil
}

// This case measures one owned generation, one synthetic event, the native
// operation and one benign completion. It does not measure wallet depletion.
type drainLiveProbeResult struct {
	Schema          string `json:"schema"`
	Status          string `json:"status"`
	ProfileSHA256   string `json:"profileSHA256"`
	RequestSHA256   string `json:"requestSHA256,omitempty"`
	SchedulerIDHash string `json:"schedulerIDHash,omitempty"`
	FirstFrameAt    string `json:"firstFrameAt,omitempty"`
	StreamFrames    int    `json:"streamFrames,omitempty"`
	StreamEnded     string `json:"streamEnded,omitempty"`
	EventUID        string `json:"eventUID,omitempty"`
	DecisionID      string `json:"decisionID,omitempty"`
	OperationID     string `json:"operationID,omitempty"`
	Aborted         int    `json:"aborted,omitempty"`
	BenignStatus    int    `json:"benignStatus,omitempty"`
	Issue           string `json:"issue,omitempty"`
}

const drainStreamPython = `import base64,hashlib,http.client,json,signal,sys,time
signal.alarm(215)
v=json.loads(sys.stdin.buffer.read(9217))
body=base64.b64decode(v["body"],validate=True)
if len(body)>8192 or len(v["nonce"])!=32 or any(c not in "0123456789abcdef" for c in v["nonce"]):raise RuntimeError("input")
key=base64.b64decode(v.get("bearer",""),validate=True)
if len(key)>256 or any(c<33 or c>126 for c in key):raise RuntimeError("caller_bound")
expected="cmpl-"+v["nonce"]
conn=http.client.HTTPConnection("vllm.vllm.svc.cluster.local",8000,timeout=210)
frames=0; complete=False; status=0; first=False; digest=hashlib.sha256()
try:
 headers={"Content-Type":"application/json","Accept":"text/event-stream","X-Request-Id":v["nonce"]}
 if key:headers["Authorization"]="Bearer "+key.decode("ascii")
 conn.request("POST","/v1/completions",body=body,headers=headers)
 response=conn.getresponse();status=response.status
 if status!=200:raise RuntimeError("http")
 while frames<512:
  line=response.fp.readline(4097)
  if len(line)>4096:raise RuntimeError("frame_bound")
  if not line:break
  digest.update(line)
  if not line.startswith(b"data: "):continue
  payload=line[6:].strip()
  if payload==b"[DONE]":complete=True;break
  frame=json.loads(payload)
  if not isinstance(frame,dict) or frame.get("id")!=expected:raise RuntimeError("frame_id")
  frames+=1
  if not first:
   print(json.dumps({"stage":"first","status":status,"id":expected,"at":time.time_ns()}),flush=True)
   first=True
 print(json.dumps({"stage":"final","status":status,"frames":frames,"done":complete,"bodySHA256":digest.hexdigest()}),flush=True)
except Exception as exc:
 print(json.dumps({"stage":"final","status":status,"frames":frames,"done":False,"errorClass":type(exc).__name__,"bodySHA256":digest.hexdigest()}),flush=True)
finally:conn.close()
`

const drainBenignPython = `import base64,hashlib,http.client,json,signal,sys
signal.alarm(20)
input=sys.stdin.buffer.read(6145)
v=json.loads(input) if input.startswith(b"{") else {"body":input.decode("ascii")}
body=base64.b64decode(v["body"],validate=True)
key=base64.b64decode(v.get("bearer",""),validate=True)
if len(key)>256 or any(c<33 or c>126 for c in key):raise RuntimeError("caller_bound")
if len(body)>4096:raise RuntimeError("body")
conn=http.client.HTTPConnection("vllm.vllm.svc.cluster.local",8000,timeout=15)
try:
 headers={"Content-Type":"application/json"}
 if key:headers["Authorization"]="Bearer "+key.decode("ascii")
 conn.request("POST","/v1/completions",body=body,headers=headers)
 response=conn.getresponse();raw=response.read(8193)
 if len(raw)>8192:raise RuntimeError("reply_bound")
 valid=False
 if response.status==200:
  value=json.loads(raw)
  valid=(isinstance(value,dict) and isinstance(value.get("choices"),list) and len(value["choices"])==1 and value["choices"][0].get("finish_reason") in ("stop","length"))
 print(json.dumps({"status":response.status,"valid":valid,"bodySHA256":hashlib.sha256(raw).hexdigest()}))
finally:conn.close()
`

type drainStreamRow struct {
	Original   []byte `json:"-"`
	Stage      string `json:"stage"`
	Status     int    `json:"status"`
	ID         string `json:"id,omitempty"`
	At         int64  `json:"at,omitempty"`
	Frames     int    `json:"frames,omitempty"`
	Done       bool   `json:"done,omitempty"`
	ErrorClass string `json:"errorClass,omitempty"`
	BodySHA256 string `json:"bodySHA256,omitempty"`
}
type drainStreamRun struct {
	first  chan drainStreamRow
	done   chan error
	final  chan drainStreamRow
	cancel context.CancelFunc
}

func drainRequestBody(modelID string, maxTokens int, stream bool) []byte {
	prompt := "Reply with one ordinary sentence about clouds."
	if stream {
		prompt = "Write integers from 1 through 400, separated by spaces. Keep writing until 400. No introduction."
	}
	body, _ := json.Marshal(map[string]any{"model": modelID, "prompt": prompt, "max_tokens": maxTokens, "temperature": 0, "stream": stream, "n": 1})
	return body
}
func drainNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// startDrainStream keeps kubectl exec attached. Its only stdout is a bounded
// typed projection; the Python process never prints model text or credentials.
func startDrainStream(parent context.Context, p drainLiveProfile, body []byte, nonce string) (*drainStreamRun, error) {
	if err := p.retainedCaller.check(parent); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	input, _ := json.Marshal(map[string]string{"body": base64Body(body), "nonce": nonce})
	if p.retainedCaller != nil {
		input, _ = json.Marshal(map[string]string{"body": base64Body(body), "nonce": nonce,
			"bearer": base64Body(p.retainedCaller.bearer())})
	}
	cmd := exec.CommandContext(ctx, "kubectl", "-n", "vllm", "exec", "-i", p.PodName, "-c", "guardrail", "--", "python3", "-B", "-c", drainStreamPython)
	cmd.Stdin = bytes.NewReader(input)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr := &availabilityCappedWriter{max: 4096}
	cmd.Stderr = stderr
	if err = cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	run := &drainStreamRun{first: make(chan drainStreamRow, 1), done: make(chan error, 1), final: make(chan drainStreamRow, 1), cancel: cancel}
	go func() {
		defer close(run.first)
		defer close(run.final)
		scanner := bufio.NewScanner(io.LimitReader(stdout, 16385))
		scanner.Buffer(make([]byte, 1024), 4096)
		lines := 0
		firstSeen := false
		finalSeen := false
		var final drainStreamRow
		var parseErr error
		for scanner.Scan() {
			lines++
			if lines > 2 {
				parseErr = errors.New("too many stream projection rows")
				break
			}
			var row drainStreamRow
			dec := json.NewDecoder(strings.NewReader(scanner.Text()))
			dec.DisallowUnknownFields()
			if dec.Decode(&row) != nil || dec.Decode(&struct{}{}) != io.EOF {
				parseErr = errors.New("malformed stream projection")
				break
			}
			row.Original = append([]byte(nil), scanner.Bytes()...)
			switch row.Stage {
			case "first":
				if firstSeen || finalSeen || row.Status != 200 || row.ID != "cmpl-"+nonce || row.At <= 0 {
					parseErr = errors.New("stream first identity mismatch")
					break
				}
				firstSeen = true
				run.first <- row
			case "final":
				if finalSeen || row.Frames < 0 || row.Frames > 512 || !staticSHA256.MatchString(row.BodySHA256) || row.Status < 0 || row.Status > 599 {
					parseErr = errors.New("stream final malformed")
					break
				}
				finalSeen = true
				final = row
			default:
				parseErr = errors.New("unknown stream projection stage")
			}
			if parseErr != nil {
				break
			}
		}
		if parseErr != nil {
			cancel()
		}
		if err := scanner.Err(); err != nil && parseErr == nil {
			parseErr = err
		}
		waitErr := cmd.Wait()
		if parseErr == nil && (waitErr != nil || !finalSeen || (firstSeen && final.Frames < 1) || (!firstSeen && final.Frames != 0)) {
			parseErr = errors.New("stream execution incomplete")
		}
		if stderr.overflow && parseErr == nil {
			parseErr = errors.New("stream stderr bound exceeded")
		}
		if finalSeen {
			run.final <- final
		}
		run.done <- parseErr
	}()
	return run, nil
}

func base64Body(body []byte) string { return base64.StdEncoding.EncodeToString(body) }

func drainOwnedDisposition(e *model.DrainOperationEvidence, nonce string) bool {
	if e == nil || !e.Reopened || !e.Restored || e.Aborted < 1 || e.OperationID == "" || e.ReceiptSHA256 == "" {
		return false
	}
	id := sha256.Sum256([]byte("cmpl-" + nonce + "-0"))
	want := hex.EncodeToString(id[:])
	snapshotSeen := 0
	for _, digest := range e.SnapshotRequests {
		if digest == want {
			snapshotSeen++
		}
	}
	seen := 0
	for _, row := range e.Dispositions {
		if row.RequestSHA256 == want {
			seen++
			if row.Disposition != "aborted" {
				return false
			}
		}
	}
	return snapshotSeen == 1 && seen == 1
}

func drainTerminalMatchesProfile(d *decisionEvidence, p drainLiveProfile) bool {
	if d == nil || d.DrainOperation == nil {
		return false
	}
	e := d.DrainOperation
	return d.PolicyNamespace == "vllm" && d.PolicyName == p.PolicyName && d.PolicyUID == p.PolicyUID &&
		d.TargetUID == p.PodUID && e.PolicyUID == p.PolicyUID && e.TargetUID == p.PodUID && e.ServiceUID == p.ServiceUID &&
		e.OperationID != "" && e.Generation != "" && e.ReceiptSHA256 != ""
}

// Select the exact owned operation if present. Unrelated later operations do
// not erase its native disposition; contradictory claims for this owned ID do.
func drainTerminalFromRecords(r *attackRecord, records []audit.Record, collectedAt time.Time, nonce string) (*decisionEvidence, error) {
	created, err := time.Parse(time.RFC3339Nano, r.StimulusEvidence.EventCreatedAt)
	if err != nil || len(records) == 0 || records[0].Time.After(created) {
		return nil, errors.New("audit interval does not cover event creation")
	}
	var selected *decisionEvidence
	var owned *decisionEvidence
	for i := range records {
		projected, ok := exactDecisionEvidence(r, &records[i], collectedAt)
		if !ok || !projected.Selected {
			continue
		}
		if projected.Action != "request-drain" || projected.PolicyUID == "" || projected.DecisionID == "" || projected.TickID == "" ||
			!projected.Actuated || projected.DispatchOutcome != model.DispatchEmitted || projected.DrainOperation == nil {
			continue
		}
		if selected == nil {
			copy := projected
			selected = &copy
		}
		if drainOwnedDisposition(projected.DrainOperation, nonce) {
			if owned != nil && (owned.DrainOperation.OperationID != projected.DrainOperation.OperationID || owned.DecisionID != projected.DecisionID) {
				return nil, errors.New("conflicting owned terminal operations")
			}
			copy := projected
			owned = &copy
		}
	}
	if owned != nil {
		return owned, nil
	}
	return selected, nil
}

type drainAuditWindow struct {
	Records      []audit.Record
	Originals    [][]byte
	Generation   string
	Start        int64
	End          int64
	WindowSHA256 string
}

func (s *Server) drainTerminalAudit(ctx context.Context, out, phase string, r *attackRecord, nonce string) (*decisionEvidence, error) {
	window, err := s.readStrictDrainAudit(ctx)
	if err != nil {
		return nil, err
	}
	selected, err := drainTerminalFromRecords(r, window.Records, s.cfg.now(), nonce)
	if err != nil || selected == nil {
		return selected, err
	}
	var original []byte
	for i := range window.Records {
		projected, ok := exactDecisionEvidence(r, &window.Records[i], s.cfg.now())
		if ok && projected.Selected && projected.DecisionID == selected.DecisionID && projected.TickID == selected.TickID {
			if original != nil {
				return nil, errors.New("duplicate terminal original")
			}
			original = window.Originals[i]
		}
	}
	if len(original) == 0 {
		return nil, errors.New("terminal original missing")
	}
	if err = publishMongoAuditFile(out, phase+"-audit-original.jsonl", append(append([]byte(nil), original...), '\n'), liveRecordBytes+1); err != nil {
		return nil, err
	}
	commit := map[string]any{"schema": "authenticated-audit-window-v1", "sourceIdentity": s.cfg.AuditSourceIdentity,
		"generation": window.Generation, "start": window.Start, "end": window.End, "windowSHA256": window.WindowSHA256,
		"terminalOriginalSHA256": availabilityHash(original), "selectedDecisionID": selected.DecisionID,
		"operationID": selected.DrainOperation.OperationID, "operationGeneration": selected.DrainOperation.Generation}
	if err = publishMongoAuditFile(out, phase+"-audit-source-commitment.json", drainJSON(commit), 4096); err != nil {
		return nil, err
	}
	return selected, nil
}

// Unlike the generic UI history reader, a positive terminal proof cannot
// silently skip any malformed, oversized or unfinished audit row. A verified
// source snapshot is read twice by anchor/hash when the source is local.
func (s *Server) readStrictDrainAudit(ctx context.Context) (drainAuditWindow, error) {
	var window drainAuditWindow
	f, err := openDecisionSource(ctx, s.cfg.auditPathForContext(""), s.cfg.AuditSource)
	if err != nil {
		return window, err
	}
	defer f.Close()
	generation, err := auditGeneration(f)
	if err != nil {
		return window, err
	}
	st, err := f.Stat()
	if err != nil {
		return window, err
	}
	const maxWindow = int64(16 << 20)
	start := max(int64(0), st.Size()-maxWindow)
	startAnchor, err := auditAnchor(f, start)
	if err != nil {
		return window, err
	}
	endAnchor, err := auditAnchor(f, st.Size())
	if err != nil {
		return window, err
	}
	b := make([]byte, st.Size()-start)
	if len(b) > 0 {
		if _, err = f.ReadAt(b, start); err != nil {
			return window, err
		}
	}
	if remote, ok := f.(interface{ Verify() error }); ok {
		if err = remote.Verify(); err != nil {
			return window, err
		}
	} else {
		check, openErr := openDecisionSource(ctx, s.cfg.auditPathForContext(""), s.cfg.AuditSource)
		if openErr != nil {
			return window, errAuditChanged
		}
		defer check.Close()
		checkGeneration, checkErr := auditGeneration(check)
		if checkErr != nil || checkGeneration != generation {
			return window, errAuditChanged
		}
		if anchor, anchorErr := auditAnchor(check, start); anchorErr != nil || anchor != startAnchor {
			return window, errAuditChanged
		}
		if anchor, anchorErr := auditAnchor(check, st.Size()); anchorErr != nil || anchor != endAnchor {
			return window, errAuditChanged
		}
		want := sha256.Sum256(b)
		got, hashErr := auditRangeHash(check, uint64(start), uint64(len(b)))
		if hashErr != nil || got != want {
			return window, errAuditChanged
		}
	}
	window.Generation, window.Start, window.End, window.WindowSHA256 = generation, start, st.Size(), availabilityHash(b)
	if start > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return window, errors.New("audit window has no complete leading row")
		}
		b = b[i+1:]
	}
	window.Records, window.Originals, err = parseStrictDrainRows(ctx, b)
	return window, err
}

func parseStrictDrainRows(ctx context.Context, b []byte) ([]audit.Record, [][]byte, error) {
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return nil, nil, errors.New("audit window ends in incomplete row")
	}
	var records []audit.Record
	var originals [][]byte
	for len(b) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		i := bytes.IndexByte(b, '\n')
		if i < 0 || i == 0 || i > liveRecordBytes {
			return nil, nil, errors.New("audit window has invalid row boundary")
		}
		var rec audit.Record
		if json.Unmarshal(b[:i], &rec) != nil || rec.Kind == "" || rec.Time.IsZero() {
			return nil, nil, errors.New("audit window has malformed row")
		}
		if rec.Kind == "phorvex.decision" {
			records = append(records, rec)
			originals = append(originals, append([]byte(nil), b[:i]...))
		}
		b = b[i+1:]
	}
	return records, originals, nil
}

func drainLiveSafeIssue(err error) string {
	if err == nil {
		return ""
	}
	// Never echo transport stderr, model output or remote response details.
	return "bounded request-drain step unavailable"
}

func (s *Server) startDrainLive(p drainLiveProfile, profileRaw []byte) string {
	now := s.cfg.now()
	id := fmt.Sprintf("atk-%x%x", now.UnixNano(), vllmEventSequence.Add(1))
	record := &attackRecord{ID: id, FiredAt: now.UTC().Format(time.RFC3339Nano), Service: "vllm", Namespace: "vllm",
		Pod: p.PodName, TargetUID: p.PodUID, Attack: "Bounded request-drain behavior", AttackID: "request-drain",
		Expected: "request-drain", EvidenceKind: "vllm-drain-owned-observation", OutcomeClass: "drain-observation-pending",
		Status: "running", ObservationStart: now.UTC().Format(time.RFC3339Nano),
		ObservationEnd: now.Add(240 * time.Second).UTC().Format(time.RFC3339Nano),
		DrainLiveProbe: &drainLiveProbeResult{Schema: "live-request-drain-result-v1", Status: "UNKNOWN", ProfileSHA256: s.cfg.DrainLiveProfileSHA256},
		started:        now, accepted: now}
	publishAttack(record)
	go s.runDrainLive(record, p, profileRaw)
	return id
}

func (s *Server) runDrainLive(r *attackRecord, p drainLiveProfile, raw []byte) {
	defer drainLiveInFlight.Store(false)
	ctx, cancel := context.WithDeadline(context.Background(), r.started.Add(240*time.Second))
	defer cancel()
	out := s.cfg.statePath(filepath.Join("request-drain", r.ID))
	var err error
	if out == "" {
		err = errors.New("private state unavailable")
	} else if err = os.MkdirAll(out, 0700); err == nil {
		err = publishMongoAuditFile(out, "profile-original.json", raw, 16<<10)
		if err == nil {
			p.retainedCaller, err = newRetainedCallerAuthority(s.cfg, p.RetainedCallerLeaseProfileSHA256,
				p.ServiceUID, p.PolicyUID, "", p.PodUID)
		}
		if err == nil {
			err = s.executeDrainLive(ctx, out, r, p)
		}
	}
	if err != nil {
		r.DrainLiveProbe.Issue = drainLiveSafeIssue(err)
	}
	applyDrainLiveVerdict(r)
	// Persist before the one terminal publish: followers stop at the first
	// terminal record, so credit must never be visible before it is durable.
	if e := s.persistAttack(r); e != nil {
		r.Status, r.OutcomeClass = "partial", "drain-observation-unknown"
		r.Outcome, r.Action, r.DefendedPod, r.Containment = "", "", "", ""
		r.Actuated, r.TimeToDefendSec = false, 0
		r.PersistenceError = "request-drain evidence persistence unavailable; unsafe to retry"
	}
	publishAttack(r)
}

// applyDrainLiveVerdict grants credit only for the complete owned chain: the
// exact event's selected request-drain natively aborted the owned in-flight
// completion, and the same audited operation reopened to a benign completion.
func applyDrainLiveVerdict(r *attackRecord) {
	if r.DrainLiveProbe.Status == "UNKNOWN" {
		r.Status = "partial"
		r.OutcomeClass = "drain-observation-unknown"
	} else {
		r.Status = "done"
		r.OutcomeClass = "drain-" + strings.ToLower(r.DrainLiveProbe.Status)
	}
	r.Outcome, r.DefendedPod, r.Containment = "", "", ""
	r.Actuated, r.DwellOngoing = false, false
	r.TimeToDefendSec, r.DwellSec = 0, 0
	d, stimulus := r.DecisionEvidence, r.StimulusEvidence
	if r.DrainLiveProbe.Status != "OWNED_ABORT_AND_CONTINUITY_OBSERVED" || d == nil || stimulus == nil ||
		!d.Selected || d.Correlation != "exact-event-uid" || d.EventUID == "" || d.EventUID != stimulus.EventUID ||
		d.Action != "request-drain" || d.DrainOperation == nil {
		return
	}
	created, createdErr := time.Parse(time.RFC3339Nano, stimulus.EventCreatedAt)
	decided, decidedErr := time.Parse(time.RFC3339Nano, d.Time)
	if createdErr != nil || decidedErr != nil || decided.Before(created) {
		return
	}
	r.Outcome, r.DefendedPod, r.Containment = "DEFENDED", r.Pod, "owned-inflight-request-aborted-service-reopened"
	r.Action, r.Actuated = d.Action, true
	r.TimeToDefendSec = round2(decided.Sub(created).Seconds())
}

func (s *Server) executeDrainLive(ctx context.Context, out string, r *attackRecord, p drainLiveProfile) error {
	if err := s.drainLivePreflight(ctx, out, p, "before"); err != nil {
		return err
	}
	if p.retainedCaller != nil {
		body := drainRequestBody(p.ModelID, 8, false)
		status, valid, err := s.drainBenign(ctx, p, body)
		if err != nil || status != 200 || !valid {
			return errors.New("authenticated retained-B benign baseline unavailable; no event")
		}
		if err := publishMongoAuditFile(out, "retained-b-before-benign.json", drainJSON(map[string]any{
			"status": status, "valid": valid, "requestSHA256": availabilityHash(body),
			"callerSHA256": p.retainedCaller.profile.ClientBSHA256}), 4096); err != nil {
			return err
		}
	}
	nonce, err := drainNonce()
	if err != nil {
		return err
	}
	body := drainRequestBody(p.ModelID, 1024, true)
	r.DrainLiveProbe.RequestSHA256 = availabilityHash(body)
	hash := sha256.Sum256([]byte("cmpl-" + nonce + "-0"))
	r.DrainLiveProbe.SchedulerIDHash = hex.EncodeToString(hash[:])
	if err = publishMongoAuditFile(out, "stream-intent.json", drainJSON(map[string]any{"requestSHA256": availabilityHash(body), "nonce": nonce,
		"expectedSSEID": "cmpl-" + nonce, "schedulerIDHash": r.DrainLiveProbe.SchedulerIDHash,
		"streamScriptSHA256": availabilityHash([]byte(drainStreamPython)), "maxRequests": 1, "maxTokens": 1024}), 4096); err != nil {
		return err
	}
	stream, err := startDrainStream(ctx, p, body, nonce)
	if err != nil {
		return err
	}
	defer stream.cancel()
	var first drainStreamRow
	select {
	case row, ok := <-stream.first:
		if !ok {
			return errors.New("stream completed before first frame")
		}
		first = row
	case <-ctx.Done():
		return ctx.Err()
	}
	r.DrainLiveProbe.FirstFrameAt = time.Unix(0, first.At).UTC().Format(time.RFC3339Nano)
	if err = publishMongoAuditFile(out, "stream-first-original.json", first.Original, 4096); err != nil {
		return err
	}
	if first.Status != 200 {
		return errors.New("retained caller stream was not authenticated by model")
	}
	if err = p.retainedCaller.check(ctx); err != nil {
		return err
	}
	// A completed stream before the event has no discriminating overlap.
	select {
	case streamErr := <-stream.done:
		final := <-stream.final
		if len(final.Original) > 0 {
			if err = publishMongoAuditFile(out, "stream-final-original.json", final.Original, 4096); err != nil {
				return err
			}
		}
		if streamErr != nil || final.ErrorClass != "" || len(final.Original) == 0 {
			return errors.New("owned stream failed before event")
		}
		r.DrainLiveProbe.Status = "NO_DISCRIMINATING_OVERLAP"
		return nil
	default:
	}
	stimulus, eventErr := s.createCorrelatedVLLMEventWithAdapterContext(p.Context, p.PodName, p.PodUID, "DenialOfWallet", "one owned fixed completion admitted before synthetic request-drain signal", "0.9", "", func(raw []byte) error { return publishMongoAuditFile(out, "event-manifest.yaml", raw, 4096) })
	if stimulus != nil {
		r.StimulusEvidence = stimulus
		r.DrainLiveProbe.EventUID = stimulus.EventUID
		if len(stimulus.createReply) > 0 {
			if err = publishMongoAuditFile(out, "event-create-original.json", stimulus.createReply, 64<<10); err != nil {
				return err
			}
		}
	}
	if eventErr != nil {
		return eventErr
	}
	publishAttack(r)
	for time.Until(r.started.Add(240*time.Second)) > 10*time.Second {
		d, auditErr := s.drainTerminalAudit(ctx, out, "terminal", r, nonce)
		if auditErr != nil {
			return auditErr
		}
		if d != nil && d.Correlation == "exact-event-uid" && d.EventUID == stimulus.EventUID && d.DrainOperation != nil {
			r.DecisionEvidence = d
			if err = publishMongoAuditFile(out, "terminal-audit-projection.json", drainJSON(d), 64<<10); err != nil {
				return err
			}
			e := d.DrainOperation
			if !drainTerminalMatchesProfile(d, p) {
				return errors.New("drain operation identity mismatch")
			}
			r.DrainLiveProbe.DecisionID = d.DecisionID
			r.DrainLiveProbe.OperationID = e.OperationID
			r.DrainLiveProbe.Aborted = e.Aborted
			if !drainOwnedDisposition(e, nonce) {
				r.DrainLiveProbe.Status = "MECHANISM_ONLY"
				return nil
			}
			var streamErr error
			select {
			case streamErr = <-stream.done:
			case <-time.After(min(time.Until(r.started.Add(240*time.Second)), 15*time.Second)):
				return errors.New("owned stream termination unconfirmed")
			}
			final := <-stream.final
			if len(final.Original) > 0 {
				if err = publishMongoAuditFile(out, "stream-final-original.json", final.Original, 4096); err != nil {
					return err
				}
			}
			if streamErr != nil {
				return errors.New("owned stream transport failed after dispatch")
			}
			r.DrainLiveProbe.StreamFrames = final.Frames
			if final.ErrorClass != "" || final.Status != 200 || final.Done || final.Frames < 1 {
				return errors.New("owned stream ended inconsistently with native abort")
			}
			r.DrainLiveProbe.StreamEnded = "aborted-compatible"
			if err = s.drainLivePreflight(ctx, out, p, "after"); err != nil {
				return err
			}
			if err = drainConsoleIncarnationStable(out); err != nil {
				return err
			}
			benign := drainRequestBody(p.ModelID, 8, false)
			status, valid, benignErr := s.drainBenign(ctx, p, benign)
			if benignErr != nil {
				return benignErr
			}
			r.DrainLiveProbe.BenignStatus = status
			if status != 200 || !valid {
				return errors.New("benign completion after reopen unconfirmed")
			}
			closing, closeErr := s.drainTerminalAudit(ctx, out, "closing", r, nonce)
			if closeErr != nil || closing == nil || closing.DecisionID != d.DecisionID || closing.DrainOperation == nil ||
				closing.DrainOperation.OperationID != e.OperationID || closing.DrainOperation.ReceiptSHA256 != e.ReceiptSHA256 {
				return errors.New("closing audit interval or native receipt changed")
			}
			if err = publishMongoAuditFile(out, "closing-audit-projection.json", drainJSON(closing), 64<<10); err != nil {
				return err
			}
			r.DrainLiveProbe.Status = "OWNED_ABORT_AND_CONTINUITY_OBSERVED"
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("exact selected terminal drain audit unavailable")
}

func drainJSON(v any) []byte { b, _ := json.Marshal(v); return b }
