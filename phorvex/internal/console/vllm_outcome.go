package console

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/servingcontext"
)

var vllmEventSequence atomic.Uint64

type vllmSecurityEvent struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		UID               string            `json:"uid"`
		CreationTimestamp string            `json:"creationTimestamp"`
		Labels            map[string]string `json:"labels"`
		Annotations       map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Targets []string `json:"targets"`
		Rule    struct {
			Type   string `json:"type"`
			Source string `json:"source"`
		} `json:"rule"`
	} `json:"spec"`
}

func (s *Server) createCorrelatedVLLMEvent(pod, targetUID, evType, desc, anomaly string) (*attackStimulusEvidence, error) {
	return s.createCorrelatedVLLMEventWithAdapter(pod, targetUID, evType, desc, anomaly, "")
}

func (s *Server) createCorrelatedVLLMEventWithAdapter(pod, targetUID, evType, desc, anomaly, adapter string) (*attackStimulusEvidence, error) {
	return s.createCorrelatedVLLMEventWithAdapterContext("", pod, targetUID, evType, desc, anomaly, adapter, nil)
}

func (s *Server) createCorrelatedVLLMEventWithAdapterContext(kubeContext, pod, targetUID, evType, desc, anomaly, adapter string, precreate func([]byte) error) (*attackStimulusEvidence, error) {
	if targetUID == "" {
		return nil, fmt.Errorf("target Pod UID is unavailable")
	}
	if adapter != "" && (!validVLLMIdentity(adapter) || vllmRuleType(evType) != model.AttackVectorAdapter) {
		return nil, fmt.Errorf("adapter event identity is invalid")
	}
	sequence := vllmEventSequence.Add(1)
	correlation := fmt.Sprintf("%x-%x", s.cfg.now().UnixNano(), sequence)
	name := "redteam-vllm-" + strings.ToLower(evType) + "-" + correlation
	ruleType := vllmRuleType(evType)
	candidate := &attackStimulusEvidence{Kind: "synthetic-security-event", Observed: false, TargetUID: targetUID, EventName: name, EventRule: ruleType, Correlation: correlation, BehavioralExecuted: false, Limitation: "SecurityEvent create outcome is unknown and requires exact reconciliation"}
	annotations := ""
	if adapter != "" {
		annotations = fmt.Sprintf("  annotations:\n    phorvex.ai/adapter-name: %q\n    phorvex.ai/target-pod-uid: %q\n", adapter, targetUID)
	}
	manifest := fmt.Sprintf(`apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: %s
%s  labels:
    phorvex.ai/redteam: "true"
    phorvex.ai/console-vllm: "true"
    phorvex.ai/attack-correlation: %q
spec:
  description: %q
  targets: ["%s/%s"]
  rule:
    type: %q
    threatLevel: "critical"
    source: "redteam"
  anomalyScore: %q
`, name, annotations, correlation, desc, vllmAttackNS, pod, ruleType, anomaly)
	if evType == "GuardrailBypass" || kubeContext != "" {
		candidate.createManifest = []byte(manifest)
	}
	if precreate != nil {
		if err := precreate([]byte(manifest)); err != nil {
			return candidate, fmt.Errorf("durable event intent unavailable: %w", err)
		}
	}
	f, err := os.CreateTemp("", "phorvex-vllm-event-*.yaml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0o600); err == nil {
		_, err = f.WriteString(manifest)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("write SecurityEvent manifest: %w", err)
	}
	createArgs := []string{"create", "-f", f.Name(), "-o", "json"}
	if kubeContext != "" {
		createArgs = append([]string{"--context=" + kubeContext}, createArgs...)
	}
	out, err := s.cfg.execText(10*time.Second, "kubectl", createArgs...)
	if (evType == "GuardrailBypass" || kubeContext != "") && len(out) > 0 && len(out) <= 64<<10 {
		candidate.createReply = []byte(out)
	}
	if len(out) > 64<<10 {
		return candidate, fmt.Errorf("created SecurityEvent reply exceeded fixed bound; exact resource %q correlation %q requires reconciliation", name, correlation)
	}
	if err != nil {
		return candidate, fmt.Errorf("create SecurityEvent %q correlation %q outcome unknown: %w (%s)", name, correlation, err, strings.TrimSpace(out))
	}
	var event vllmSecurityEvent
	if err := json.Unmarshal([]byte(out), &event); err != nil {
		return candidate, fmt.Errorf("created SecurityEvent reply is malformed; exact resource %q correlation %q requires reconciliation: %w", name, correlation, err)
	}
	if event.Metadata.Name != name || event.Metadata.Namespace != "" || event.Metadata.UID == "" || event.Metadata.CreationTimestamp == "" ||
		event.Metadata.Labels["phorvex.ai/attack-correlation"] != correlation || event.Metadata.Labels["phorvex.ai/console-vllm"] != "true" || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != vllmAttackNS+"/"+pod ||
		event.Spec.Rule.Type != ruleType || event.Spec.Rule.Source != "redteam" {
		return candidate, fmt.Errorf("created SecurityEvent reply is incomplete or mismatched; exact resource %q correlation %q requires reconciliation", name, correlation)
	}
	if adapter != "" && (event.Metadata.Annotations["phorvex.ai/adapter-name"] != adapter || event.Metadata.Annotations["phorvex.ai/target-pod-uid"] != targetUID) {
		return candidate, fmt.Errorf("created adapter SecurityEvent reply is incomplete or mismatched; exact resource %q correlation %q requires reconciliation", name, correlation)
	}
	return &attackStimulusEvidence{Kind: "synthetic-security-event", Observed: true, TargetUID: targetUID, EventName: name, EventUID: event.Metadata.UID, EventCreatedAt: event.Metadata.CreationTimestamp, EventRule: ruleType, Correlation: correlation, BehavioralExecuted: false, Limitation: "detector stimulus is not a demonstrated exploit", createManifest: candidate.createManifest, createReply: candidate.createReply}, nil
}

const (
	vllmGuardrailURL = "http://localhost:8000"
)

type guardrailState struct {
	Ready  bool   `json:"ready"`
	Active string `json:"active"`
}

type guardrailReload struct {
	Active  string `json:"active"`
	Applied bool   `json:"applied"`
}

type vllmHTTPResponse struct {
	Status int
	Body   []byte
}

const vllmHTTPMaxBytes = 64 << 10

func validVLLMIdentity(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validVLLMModelID(value string) bool {
	if strings.TrimSpace(value) != value || value == "" || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func boundedVLLMHTTP(execIn func(string) (string, error), method, path, body, purpose string, allowed map[string]bool) (vllmHTTPResponse, error) {
	if (method != http.MethodGet && method != http.MethodPost) || !allowed[method+" "+path] {
		return vllmHTTPResponse{}, fmt.Errorf("unsupported %s request %q %q", purpose, method, path)
	}
	if strings.ContainsAny(path, "' \t\r\n") || strings.Contains(body, "'") {
		return vllmHTTPResponse{}, fmt.Errorf("%s request is not shell-safe", purpose)
	}
	data := ""
	if body != "" {
		data = " -H 'Content-Type: application/json' --data-binary '" + body + "'"
	}
	const begin, status = "__PHORVEX_HTTP_BEGIN__", "__PHORVEX_HTTP_STATUS__"
	cmd := "printf '" + begin + "\\n'; curl --silent --show-error --max-time 15 --max-filesize " + strconv.Itoa(vllmHTTPMaxBytes) + " -X " + method + data +
		" -w '\\n" + status + "%{http_code}\\n' '" + vllmGuardrailURL + path + "'"
	out, err := execIn(cmd)
	if err != nil {
		return vllmHTTPResponse{}, fmt.Errorf("%s HTTP command: %w (%s)", purpose, err, strings.TrimSpace(out))
	}
	return parseVLLMHTTPOutput(out, purpose)
}

func parseVLLMHTTPOutput(out, purpose string) (vllmHTTPResponse, error) {
	const begin, status = "__PHORVEX_HTTP_BEGIN__", "__PHORVEX_HTTP_STATUS__"
	start := strings.LastIndex(out, begin+"\n")
	end := strings.LastIndex(out, "\n"+status)
	if start < 0 || end < start {
		return vllmHTTPResponse{}, fmt.Errorf("%s HTTP response framing unavailable", purpose)
	}
	bodyBytes := []byte(out[start+len(begin)+1 : end])
	if len(bodyBytes) > vllmHTTPMaxBytes {
		return vllmHTTPResponse{}, fmt.Errorf("%s HTTP response exceeds %d bytes", purpose, vllmHTTPMaxBytes)
	}
	codeText := strings.TrimSpace(out[end+1+len(status):])
	code, err := strconv.Atoi(codeText)
	if err != nil || code < 100 || code > 599 {
		return vllmHTTPResponse{}, fmt.Errorf("%s HTTP status is invalid", purpose)
	}
	return vllmHTTPResponse{Status: code, Body: bodyBytes}, nil
}

// The workload API key exists only in the target vLLM container environment. A
// fixed local Python client reads it in-process; no credential is put in kubectl
// argv, the shell command, stdout, or a console-side environment variable.
const vllmLocalHTTPPython = `import base64,http.client,os,sys
host,port,method,path,body=sys.argv[1:6]
headers={"Content-Type":"application/json"}
key=os.environ.get("VLLM_API_KEY","")
if key:headers["Authorization"]="Bearer "+key
connection=http.client.HTTPConnection(host,int(port),timeout=15)
try:
 connection.request(method,path,base64.b64decode(body),headers)
 response=connection.getresponse()
 data=response.read(65537)
 if len(data)>65536:raise RuntimeError("vLLM response exceeds bound")
 sys.stdout.buffer.write(b"__PHORVEX_HTTP_BEGIN__\n"+data+b"\n__PHORVEX_HTTP_STATUS__"+str(response.status).encode()+b"\n")
finally:connection.close()
`

func boundedVLLMLocalHTTP(execIn func(string) (string, error), method, path, body string, allowed map[string]bool) (vllmHTTPResponse, error) {
	if !allowed[method+" "+path] || (method != http.MethodGet && method != http.MethodPost) ||
		len(body) > 8192 || strings.ContainsAny(path, "' \t\r\n") {
		return vllmHTTPResponse{}, fmt.Errorf("unsupported vLLM workload request")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	cmd := "python3 -c '" + vllmLocalHTTPPython + "' '127.0.0.1' '8001' '" + method + "' '" + path + "' '" + encoded + "'"
	out, err := execIn(cmd)
	if err != nil {
		return vllmHTTPResponse{}, fmt.Errorf("local vLLM HTTP command: %w (%s)", err, strings.TrimSpace(out))
	}
	return parseVLLMHTTPOutput(out, "local vLLM workload")
}

// vllmHTTP executes the real serving-stack HTTP producer from the target Pod. Markers isolate
// stdout from kubectl's default-container warnings, and every caller validates status and schema.
func vllmHTTP(execIn func(string) (string, error), method, path, body string) (vllmHTTPResponse, error) {
	allowed := map[string]bool{http.MethodGet + " /v1/guardrail/state": true, http.MethodPost + " /v1/guardrail/reload": true}
	return boundedVLLMHTTP(execIn, method, path, body, "guardrail", allowed)
}

func vllmWorkloadHTTP(execIn func(string) (string, error), method, path, body string) (vllmHTTPResponse, error) {
	allowed := map[string]bool{
		http.MethodGet + " /v1/models":               true,
		http.MethodPost + " /v1/load_lora_adapter":   true,
		http.MethodPost + " /v1/unload_lora_adapter": true,
		http.MethodPost + " /v1/completions":         true,
		http.MethodPost + " /v1/chat/completions":    true,
	}
	return boundedVLLMLocalHTTP(execIn, method, path, body, allowed)
}

func decodeOneJSON(data []byte, dst any) error {
	if len(data) == 0 || len(data) > vllmHTTPMaxBytes {
		return fmt.Errorf("response size must be 1..%d bytes", vllmHTTPMaxBytes)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("response contains trailing JSON")
		}
		return fmt.Errorf("response has invalid trailing data: %w", err)
	}
	return nil
}

func loadVLLMAdapter(execIn func(string) (string, error), name, source string) error {
	if !validVLLMIdentity(name) || source == "" || strings.ContainsAny(source, "'\r\n") {
		return fmt.Errorf("adapter identity or source is invalid")
	}
	payload, _ := json.Marshal(map[string]string{"lora_name": name, "lora_path": source})
	response, err := vllmWorkloadHTTP(execIn, http.MethodPost, "/v1/load_lora_adapter", string(payload))
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK {
		return fmt.Errorf("load adapter returned HTTP %d", response.Status)
	}
	models, err := readVLLMModels(execIn)
	if err != nil {
		return err
	}
	for _, model := range models {
		if model == name {
			return nil
		}
	}
	return fmt.Errorf("adapter inventory does not contain %q", name)
}

func readVLLMModels(execIn func(string) (string, error)) ([]string, error) {
	response, err := vllmWorkloadHTTP(execIn, http.MethodGet, "/v1/models", "")
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, fmt.Errorf("model inventory returned HTTP %d", response.Status)
	}
	var inventory struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := decodeOneJSON(response.Body, &inventory); err != nil {
		return nil, fmt.Errorf("model inventory is malformed: %w", err)
	}
	if len(inventory.Data) == 0 {
		return nil, fmt.Errorf("model inventory is empty")
	}
	models := make([]string, 0, len(inventory.Data))
	seen := map[string]bool{}
	for _, item := range inventory.Data {
		if !validVLLMModelID(item.ID) || seen[item.ID] {
			return nil, fmt.Errorf("model inventory contains an invalid or duplicate identity")
		}
		seen[item.ID] = true
		models = append(models, item.ID)
	}
	return models, nil
}

func runVLLMCompletion(execIn func(string) (string, error), chat bool, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	path := "/v1/completions"
	if chat {
		path = "/v1/chat/completions"
	}
	response, err := vllmWorkloadHTTP(execIn, http.MethodPost, path, string(body))
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK {
		if response.Status == http.StatusForbidden {
			var refusal struct {
				Error struct {
					Type string `json:"type"`
				} `json:"error"`
			}
			if decodeOneJSON(response.Body, &refusal) == nil && refusal.Error.Type == "guardrail_blocked" {
				return fmt.Errorf("completion blocked by the guardrail (HTTP 403); the KV observation was not started")
			}
		}
		return fmt.Errorf("completion returned HTTP %d; the KV observation was not started", response.Status)
	}
	var completion struct {
		ID      string            `json:"id"`
		Choices []json.RawMessage `json:"choices"`
	}
	if err := decodeOneJSON(response.Body, &completion); err != nil || completion.ID == "" || len(completion.Choices) == 0 {
		return fmt.Errorf("completion acknowledgement is malformed")
	}
	return nil
}

func readGuardrailState(execIn func(string) (string, error)) (guardrailState, error) {
	response, err := vllmHTTP(execIn, http.MethodGet, "/v1/guardrail/state", "")
	if err != nil {
		return guardrailState{}, err
	}
	if response.Status != http.StatusOK {
		return guardrailState{}, fmt.Errorf("guardrail state returned HTTP %d", response.Status)
	}
	var state guardrailState
	if err := json.Unmarshal(response.Body, &state); err != nil || !state.Ready || state.Active == "" {
		return guardrailState{}, fmt.Errorf("guardrail state response is malformed or not ready")
	}
	return state, nil
}

func reloadGuardrail(execIn func(string) (string, error), variant string) (guardrailState, error) {
	payload, _ := json.Marshal(map[string]string{"variant": variant})
	response, err := vllmHTTP(execIn, http.MethodPost, "/v1/guardrail/reload", string(payload))
	if err != nil {
		return guardrailState{}, err
	}
	if response.Status != http.StatusOK {
		return guardrailState{}, fmt.Errorf("guardrail reload returned HTTP %d", response.Status)
	}
	var applied guardrailReload
	if err := json.Unmarshal(response.Body, &applied); err != nil || !applied.Applied || applied.Active != variant {
		return guardrailState{}, fmt.Errorf("guardrail reload acknowledgement is malformed or mismatched")
	}
	state, err := readGuardrailState(execIn)
	if err != nil {
		return guardrailState{}, fmt.Errorf("guardrail reload readback: %w", err)
	}
	if state.Active != variant {
		return guardrailState{}, fmt.Errorf("guardrail reload readback active=%q, want %q", state.Active, variant)
	}
	return state, nil
}

type vllmPodState struct {
	Metadata struct {
		Name            string             `json:"name"`
		UID             string             `json:"uid"`
		ResourceVersion string             `json:"resourceVersion"`
		Labels          *map[string]string `json:"labels"`
		Annotations     *map[string]string `json:"annotations"`
		OwnerReferences []struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			UID        string `json:"uid"`
			Controller *bool  `json:"controller"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Name string   `json:"name"`
			Args []string `json:"args"`
			Env  []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"env"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses []struct {
			Name         string `json:"name"`
			ContainerID  string `json:"containerID"`
			ImageID      string `json:"imageID"`
			Ready        bool   `json:"ready"`
			RestartCount int32  `json:"restartCount"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

type vllmServiceState struct {
	Metadata struct {
		Name            string `json:"name"`
		UID             string `json:"uid"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		Selector *map[string]string `json:"selector"`
	} `json:"spec"`
}

type vllmServiceList struct {
	Items []vllmServiceState `json:"items"`
}

type vllmEndpointSliceList struct {
	Items []struct {
		Metadata struct {
			Labels          map[string]string `json:"labels"`
			OwnerReferences []struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
		Endpoints []struct {
			TargetRef *struct {
				UID string `json:"uid"`
			} `json:"targetRef"`
			Conditions struct {
				Ready       *bool `json:"ready"`
				Terminating *bool `json:"terminating"`
			} `json:"conditions"`
		} `json:"endpoints"`
	} `json:"items"`
}

type endpointSetupAuthority struct {
	pod                 string
	targetUID           string
	serviceName         string
	serviceUID          string
	originalLabels      *map[string]string
	originalAnnotations *map[string]string
	originalSelector    *map[string]string
	stagedLabels        *map[string]string
	stagedAnnotations   *map[string]string
	stagedSelector      *map[string]string
	podStaged           bool
	serviceStaged       bool
	restoration         string
}

type guardrailSetupAuthority struct {
	pod             string
	targetUID       string
	originalRuntime guardrailState
	restoration     string
}

type jsonPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

func copyOptionalStringMap(source *map[string]string) *map[string]string {
	if source == nil {
		return nil
	}
	copyMap := make(map[string]string, len(*source))
	for key, value := range *source {
		copyMap[key] = value
	}
	return &copyMap
}

func stringMapValue(source *map[string]string, key string) string {
	if source == nil {
		return ""
	}
	return (*source)[key]
}

func stringMapsEqual(left, right *map[string]string) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func replaceOptionalMapPatch(path string, before, after *map[string]string) []jsonPatchOperation {
	ops := []jsonPatchOperation{}
	if before != nil {
		ops = append(ops, jsonPatchOperation{Op: "test", Path: path, Value: before})
	}
	switch {
	case before == nil && after != nil:
		ops = append(ops, jsonPatchOperation{Op: "add", Path: path, Value: after})
	case before != nil && after == nil:
		ops = append(ops, jsonPatchOperation{Op: "remove", Path: path})
	default:
		ops = append(ops, jsonPatchOperation{Op: "replace", Path: path, Value: after})
	}
	return ops
}

func (s *Server) exactJSONPatch(kind, name, uid, resourceVersion string, operations ...jsonPatchOperation) error {
	if uid == "" || resourceVersion == "" {
		return fmt.Errorf("%s patch identity authority is unavailable", kind)
	}
	prefix := []jsonPatchOperation{{Op: "test", Path: "/metadata/uid", Value: uid}, {Op: "test", Path: "/metadata/resourceVersion", Value: resourceVersion}}
	payload, err := json.Marshal(append(prefix, operations...))
	if err != nil {
		return fmt.Errorf("encode %s JSON patch: %w", kind, err)
	}
	return s.checkedVLLMKubectl("patch", kind, name, "--type", "json", "-p", string(payload))
}

func (s *Server) checkedVLLMKubectl(args ...string) error {
	out, err := s.cfg.execText(8*time.Second, "kubectl", append([]string{"-n", vllmAttackNS}, args...)...)
	if err != nil {
		return fmt.Errorf("kubectl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

func (s *Server) prepareEndpointEffect(podName, targetUID string) (*endpointSetupAuthority, error) {
	pod, err := s.readVLLMPod(podName)
	if err != nil {
		return nil, err
	}
	if pod.Metadata.UID != targetUID {
		return nil, fmt.Errorf("target Pod UID changed before endpoint setup")
	}
	service, err := s.resolveVLLMService(pod)
	if err != nil {
		return nil, err
	}
	if pod.Metadata.ResourceVersion == "" || service.Metadata.ResourceVersion == "" || service.Spec.Selector == nil {
		return nil, fmt.Errorf("endpoint setup resourceVersion or selector authority is unavailable")
	}
	authority := &endpointSetupAuthority{pod: podName, targetUID: targetUID, serviceName: service.Metadata.Name, serviceUID: service.Metadata.UID, originalLabels: copyOptionalStringMap(pod.Metadata.Labels), originalAnnotations: copyOptionalStringMap(pod.Metadata.Annotations), originalSelector: copyOptionalStringMap(service.Spec.Selector)}
	authority.stagedLabels = copyOptionalStringMap(authority.originalLabels)
	if authority.stagedLabels == nil {
		labels := map[string]string{}
		authority.stagedLabels = &labels
	}
	(*authority.stagedLabels)["phorvex.ai/route-key"] = "ep-old"
	authority.stagedAnnotations = copyOptionalStringMap(authority.originalAnnotations)
	if authority.stagedAnnotations == nil {
		annotations := map[string]string{}
		authority.stagedAnnotations = &annotations
	}
	(*authority.stagedAnnotations)["phorvex.ai/route-service"] = authority.serviceName
	authority.stagedSelector = copyOptionalStringMap(authority.originalSelector)
	(*authority.stagedSelector)["phorvex.ai/route-key"] = "ep-old"
	fail := func(cause error) (*endpointSetupAuthority, error) {
		if restoreErr := s.restoreEndpointSetup(authority); restoreErr != nil {
			authority.restoration = "required: " + restoreErr.Error()
			return authority, fmt.Errorf("%w; exact setup restoration required: %v", cause, restoreErr)
		}
		authority.restoration = "restored"
		return authority, fmt.Errorf("%w; partial setup was restored", cause)
	}
	podOps := replaceOptionalMapPatch("/metadata/labels", authority.originalLabels, authority.stagedLabels)
	podOps = append(podOps, replaceOptionalMapPatch("/metadata/annotations", authority.originalAnnotations, authority.stagedAnnotations)...)
	if err := s.exactJSONPatch("pod", podName, targetUID, pod.Metadata.ResourceVersion, podOps...); err != nil {
		return fail(err)
	}
	authority.podStaged = true
	stagedPod, err := s.readVLLMPod(podName)
	if err != nil || stagedPod.Metadata.UID != targetUID || !stringMapsEqual(stagedPod.Metadata.Labels, authority.stagedLabels) || !stringMapsEqual(stagedPod.Metadata.Annotations, authority.stagedAnnotations) {
		return fail(fmt.Errorf("endpoint Pod setup acknowledgement or readback is incomplete"))
	}
	serviceOps := replaceOptionalMapPatch("/spec/selector", authority.originalSelector, authority.stagedSelector)
	if err := s.exactJSONPatch("service", authority.serviceName, authority.serviceUID, service.Metadata.ResourceVersion, serviceOps...); err != nil {
		return fail(err)
	}
	authority.serviceStaged = true
	for attempt := 0; attempt < 12; attempt++ {
		currentPod, podErr := s.readVLLMPod(podName)
		currentService, serviceErr := s.readVLLMService(authority.serviceName)
		if podErr == nil && serviceErr == nil && currentPod.Metadata.UID == targetUID && currentService.Metadata.UID == authority.serviceUID &&
			stringMapsEqual(currentPod.Metadata.Labels, authority.stagedLabels) && stringMapsEqual(currentPod.Metadata.Annotations, authority.stagedAnnotations) &&
			stringMapsEqual(currentService.Spec.Selector, authority.stagedSelector) {
			ready, endpointErr := s.targetReadyInRoute(authority.serviceName, authority.serviceUID, targetUID)
			if endpointErr == nil && ready {
				return authority, nil
			}
		}
		if attempt < 11 {
			s.cfg.sleep(500 * time.Millisecond)
		}
	}
	return fail(fmt.Errorf("endpoint setup readback did not converge on the exact target and route"))
}

func (s *Server) restoreEndpointSetup(authority *endpointSetupAuthority) error {
	if authority == nil {
		return fmt.Errorf("endpoint restoration authority is unavailable")
	}
	pod, err := s.readVLLMPod(authority.pod)
	if err != nil || pod.Metadata.UID != authority.targetUID {
		return fmt.Errorf("target Pod identity changed; refusing restoration")
	}
	service, err := s.readVLLMService(authority.serviceName)
	if err != nil || service.Metadata.UID != authority.serviceUID {
		return fmt.Errorf("route Service identity changed; refusing restoration")
	}
	if authority.serviceStaged && !stringMapsEqual(service.Spec.Selector, authority.stagedSelector) {
		return fmt.Errorf("route Service selector changed; refusing restoration")
	}
	if !authority.serviceStaged && !stringMapsEqual(service.Spec.Selector, authority.originalSelector) {
		return fmt.Errorf("route Service changed before restoration")
	}
	if authority.podStaged && (!stringMapsEqual(pod.Metadata.Labels, authority.stagedLabels) || !stringMapsEqual(pod.Metadata.Annotations, authority.stagedAnnotations)) {
		return fmt.Errorf("target Pod metadata changed; refusing restoration")
	}
	if !authority.podStaged && (!stringMapsEqual(pod.Metadata.Labels, authority.originalLabels) || !stringMapsEqual(pod.Metadata.Annotations, authority.originalAnnotations)) {
		return fmt.Errorf("target Pod changed before restoration")
	}
	if authority.serviceStaged {
		ops := replaceOptionalMapPatch("/spec/selector", authority.stagedSelector, authority.originalSelector)
		if err := s.exactJSONPatch("service", authority.serviceName, authority.serviceUID, service.Metadata.ResourceVersion, ops...); err != nil {
			return err
		}
	}
	if authority.podStaged {
		ops := replaceOptionalMapPatch("/metadata/labels", authority.stagedLabels, authority.originalLabels)
		ops = append(ops, replaceOptionalMapPatch("/metadata/annotations", authority.stagedAnnotations, authority.originalAnnotations)...)
		if err := s.exactJSONPatch("pod", authority.pod, authority.targetUID, pod.Metadata.ResourceVersion, ops...); err != nil {
			return err
		}
	}
	restoredPod, podErr := s.readVLLMPod(authority.pod)
	restoredService, serviceErr := s.readVLLMService(authority.serviceName)
	if podErr != nil || serviceErr != nil || restoredPod.Metadata.UID != authority.targetUID || restoredService.Metadata.UID != authority.serviceUID ||
		!stringMapsEqual(restoredPod.Metadata.Labels, authority.originalLabels) || !stringMapsEqual(restoredPod.Metadata.Annotations, authority.originalAnnotations) || !stringMapsEqual(restoredService.Spec.Selector, authority.originalSelector) {
		return fmt.Errorf("endpoint setup restoration readback is incomplete")
	}
	return nil
}

func (s *Server) prepareGuardrailEffect(podName, targetUID string, execIn func(string) (string, error)) (*guardrailSetupAuthority, error) {
	firstPod, err := s.readVLLMPod(podName)
	if err != nil || firstPod.Metadata.UID != targetUID || firstPod.Metadata.ResourceVersion == "" {
		return nil, fmt.Errorf("target Pod identity authority changed before guardrail setup")
	}
	firstRuntime, err := readGuardrailState(execIn)
	if err != nil {
		return nil, fmt.Errorf("read guardrail setup baseline: %w", err)
	}
	secondPod, podErr := s.readVLLMPod(podName)
	secondRuntime, runtimeErr := readGuardrailState(execIn)
	if podErr != nil || runtimeErr != nil || secondPod.Metadata.UID != targetUID || secondPod.Metadata.ResourceVersion == "" {
		return nil, fmt.Errorf("guardrail coherent setup readback is unavailable")
	}
	firstCurrent := stringMapValue(firstPod.Metadata.Annotations, "phorvex.ai/guardrail-variant")
	firstRoster := stringMapValue(firstPod.Metadata.Annotations, "phorvex.ai/guardrail-variants")
	secondCurrent := stringMapValue(secondPod.Metadata.Annotations, "phorvex.ai/guardrail-variant")
	secondRoster := stringMapValue(secondPod.Metadata.Annotations, "phorvex.ai/guardrail-variants")
	if firstCurrent != secondCurrent || firstRoster != secondRoster || firstRuntime != secondRuntime {
		return nil, fmt.Errorf("guardrail runtime or Pod roster changed during setup observation")
	}
	roster, err := servingcontext.ParseGuardrailRoster(firstCurrent, firstRoster)
	if err != nil {
		return nil, fmt.Errorf("guardrail Pod roster is invalid: %w", err)
	}
	if !firstRuntime.Ready || firstRuntime.Active != roster.Current {
		return nil, fmt.Errorf("guardrail runtime and Pod roster are incoherent")
	}
	return &guardrailSetupAuthority{pod: podName, targetUID: targetUID, originalRuntime: firstRuntime, restoration: "not-needed"}, nil
}

func decodeKubectlJSON(s *Server, ns string, dst any, args ...string) error {
	out, err := s.cfg.execText(8*time.Second, "kubectl", append([]string{"-n", ns}, args...)...)
	if err != nil {
		return fmt.Errorf("kubectl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	if err := json.Unmarshal([]byte(out), dst); err != nil {
		return fmt.Errorf("kubectl %s returned malformed JSON: %w", strings.Join(args, " "), err)
	}
	return nil
}

func decodeClusterKubectlJSON(s *Server, dst any, args ...string) error {
	out, err := s.cfg.execText(8*time.Second, "kubectl", args...)
	if err != nil {
		return fmt.Errorf("kubectl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	if err := json.Unmarshal([]byte(out), dst); err != nil {
		return fmt.Errorf("kubectl %s returned malformed JSON: %w", strings.Join(args, " "), err)
	}
	return nil
}

func (s *Server) readVLLMPod(pod string) (vllmPodState, error) {
	var state vllmPodState
	err := decodeKubectlJSON(s, vllmAttackNS, &state, "get", "pod", pod, "-o", "json")
	if err == nil && (state.Metadata.Name != pod || state.Metadata.UID == "") {
		err = fmt.Errorf("target Pod identity is absent or mismatched")
	}
	return state, err
}

func (s *Server) readVLLMService(name string) (vllmServiceState, error) {
	var state vllmServiceState
	if !validVLLMIdentity(name) {
		return state, fmt.Errorf("route Service name is invalid")
	}
	err := decodeKubectlJSON(s, vllmAttackNS, &state, "get", "service", name, "-o", "json")
	if err == nil && (state.Metadata.Name != name || state.Metadata.UID == "") {
		err = fmt.Errorf("route Service identity is absent or mismatched")
	}
	return state, err
}

// Resolve exactly one existing Service whose full selector selects the target.
// A Pod route annotation may narrow identity, but never overrides ambiguity.
func (s *Server) resolveVLLMService(pod vllmPodState) (vllmServiceState, error) {
	var list vllmServiceList
	if err := decodeKubectlJSON(s, vllmAttackNS, &list, "get", "services", "-o", "json"); err != nil {
		return vllmServiceState{}, err
	}
	var selected *vllmServiceState
	for i := range list.Items {
		item := &list.Items[i]
		if item.Metadata.Name == "" || item.Metadata.UID == "" || item.Spec.Selector == nil || len(*item.Spec.Selector) == 0 || pod.Metadata.Labels == nil {
			continue
		}
		matches := true
		for key, value := range *item.Spec.Selector {
			actual, exists := (*pod.Metadata.Labels)[key]
			if !exists || actual != value {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if selected != nil {
			return vllmServiceState{}, fmt.Errorf("multiple Services select the exact target Pod")
		}
		selected = item
	}
	if selected == nil {
		return vllmServiceState{}, fmt.Errorf("no Service selects the exact target Pod")
	}
	if annotated := stringMapValue(pod.Metadata.Annotations, "phorvex.ai/route-service"); annotated != "" && annotated != selected.Metadata.Name {
		return vllmServiceState{}, fmt.Errorf("target Pod route annotation differs from selecting Service")
	}
	state, err := s.readVLLMService(selected.Metadata.Name)
	if err != nil || state.Metadata.UID != selected.Metadata.UID || !stringMapsEqual(state.Spec.Selector, selected.Spec.Selector) {
		return vllmServiceState{}, fmt.Errorf("selecting Service identity or selector changed during resolution: %v", err)
	}
	return state, nil
}

func (s *Server) targetReadyInRoute(serviceName, serviceUID, targetUID string) (bool, error) {
	var slices vllmEndpointSliceList
	if err := decodeKubectlJSON(s, vllmAttackNS, &slices, "get", "endpointslice", "-l", "kubernetes.io/service-name="+serviceName, "-o", "json"); err != nil {
		return false, err
	}
	for _, slice := range slices.Items {
		if slice.Metadata.Labels["kubernetes.io/service-name"] != serviceName {
			return false, fmt.Errorf("EndpointSlice service label is mismatched")
		}
		owned := false
		for _, owner := range slice.Metadata.OwnerReferences {
			if owner.Kind == "Service" && owner.Name == serviceName && owner.UID == serviceUID {
				owned = true
			}
		}
		if !owned {
			return false, fmt.Errorf("EndpointSlice is not owned by the exact route Service")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef == nil || endpoint.TargetRef.UID != targetUID {
				continue
			}
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				return false, nil
			}
			if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				return false, nil
			}
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) observeVLLMInPlaceEffect(r *attackRecord) (*attackEffectEvidence, error) {
	if r.vllmEffect == nil || r.TargetUID == "" || r.StimulusEvidence == nil || !r.StimulusEvidence.Observed {
		return nil, fmt.Errorf("effect observation authority is unavailable")
	}
	pod, err := s.readVLLMPod(r.Pod)
	if err != nil {
		return nil, err
	}
	if pod.Metadata.UID != r.TargetUID {
		return nil, fmt.Errorf("target Pod UID changed")
	}
	if err := s.validateVLLMEvent(r); err != nil {
		return nil, err
	}
	switch r.vllmEffect.kind {
	case "adapter-epoch":
		if !validRunOwnedLoRA(r.vllmEffect.adapterName) {
			return nil, fmt.Errorf("run-owned adapter identity is unavailable")
		}
		afterAnnotation := stringMapValue(pod.Metadata.Annotations, "phorvex.ai/adapter-epoch")
		afterLabel := stringMapValue(pod.Metadata.Labels, "phorvex.ai/adapter-epoch")
		if afterAnnotation == "" || afterAnnotation == r.vllmEffect.before {
			return nil, nil
		}
		if afterAnnotation != afterLabel || afterAnnotation != r.StimulusEvidence.EventUID {
			return nil, fmt.Errorf("adapter epoch is not bound to the exact stimulus event")
		}
		postPod, err := s.readVLLMPod(r.Pod)
		if err != nil || postPod.Metadata.UID != r.TargetUID || stringMapValue(postPod.Metadata.Annotations, "phorvex.ai/adapter-epoch") != afterAnnotation || stringMapValue(postPod.Metadata.Labels, "phorvex.ai/adapter-epoch") != afterLabel {
			return nil, fmt.Errorf("target identity or adapter epoch changed across observation")
		}
		execIn := func(sh string) (string, error) {
			return s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", r.Pod, "-c", "vllm", "--", "sh", "-c", sh)
		}
		models, err := readVLLMModels(execIn)
		if err != nil {
			return nil, fmt.Errorf("adapter removal inventory: %w", err)
		}
		basePresent, adapterPresent := false, false
		for _, model := range models {
			basePresent = basePresent || model == liveLoRABaseModel
			adapterPresent = adapterPresent || model == r.vllmEffect.adapterName
		}
		if !basePresent || adapterPresent {
			return nil, nil
		}
		if err := probeLoRARoute(execIn, r.vllmEffect.adapterName, false); err != nil {
			return nil, fmt.Errorf("adapter route still available: %w", err)
		}
		if err := probeLoRARoute(execIn, liveLoRABaseModel, true); err != nil {
			return nil, fmt.Errorf("base-model continuity: %w", err)
		}
		lastPod, err := s.readVLLMPod(r.Pod)
		if err != nil || lastPod.Metadata.UID != r.TargetUID || stringMapValue(lastPod.Metadata.Annotations, "phorvex.ai/adapter-epoch") != afterAnnotation {
			return nil, fmt.Errorf("target identity changed across adapter route checks")
		}
		return &attackEffectEvidence{Kind: r.vllmEffect.kind, Observed: true, ObservedAt: s.cfg.now().UTC().Format(time.RFC3339Nano), TargetUID: r.TargetUID, Before: r.vllmEffect.before, After: afterAnnotation, Correlation: "exact-security-event-uid-target-and-adapter-route", Limitation: "run-owned adapter disappeared from inventory and its route returned 404 while the base model still served; no model answer corruption is claimed"}, nil
	case "kv-reset-epoch":
		after := stringMapValue(pod.Metadata.Annotations, "phorvex.ai/kv-reset-epoch")
		if after == "" || after == r.vllmEffect.before {
			return nil, nil
		}
		postPod, err := s.readVLLMPod(r.Pod)
		if err != nil || postPod.Metadata.UID != r.TargetUID || stringMapValue(postPod.Metadata.Annotations, "phorvex.ai/kv-reset-epoch") != after {
			return nil, fmt.Errorf("target identity or KV reset epoch changed across observation")
		}
		return &attackEffectEvidence{Kind: r.vllmEffect.kind, Observed: true, ObservedAt: s.cfg.now().UTC().Format(time.RFC3339Nano), TargetUID: r.TargetUID, Before: r.vllmEffect.before, After: after, Correlation: "temporal-event-and-exact-target", Limitation: "protected reset epoch is an in-place mechanism effect; no same-request cache hit/miss change was measured"}, nil
	case "kv-migrate-epoch":
		afterMigrate := stringMapValue(pod.Metadata.Annotations, "phorvex.ai/kv-migrate-epoch")
		afterLocal := stringMapValue(pod.Metadata.Annotations, "phorvex.ai/kv-local-effect-epoch")
		after := afterMigrate + "|" + afterLocal
		if after == "|" || after == r.vllmEffect.before {
			return nil, nil
		}
		postPod, err := s.readVLLMPod(r.Pod)
		if err != nil || postPod.Metadata.UID != r.TargetUID || stringMapValue(postPod.Metadata.Annotations, "phorvex.ai/kv-migrate-epoch")+"|"+stringMapValue(postPod.Metadata.Annotations, "phorvex.ai/kv-local-effect-epoch") != after {
			return nil, fmt.Errorf("target identity or KV migration epoch changed across observation")
		}
		return &attackEffectEvidence{Kind: r.vllmEffect.kind, Observed: true, ObservedAt: s.cfg.now().UTC().Format(time.RFC3339Nano), TargetUID: r.TargetUID, Before: r.vllmEffect.before, After: after, Correlation: "temporal-event-and-exact-target", Limitation: "local/remote completion metadata is a mechanism effect and may represent a partial remote outcome; no same-request cache eviction was measured"}, nil
	case "guardrail-runtime-state":
		execIn := func(sh string) (string, error) {
			return s.cfg.execText(20*time.Second, "kubectl", "-n", r.Namespace, "exec", r.Pod, "--", "sh", "-c", sh)
		}
		state, err := readGuardrailState(execIn)
		if err != nil {
			return nil, err
		}
		postPod, err := s.readVLLMPod(r.Pod)
		if err != nil || postPod.Metadata.UID != r.TargetUID {
			return nil, fmt.Errorf("target Pod UID changed across guardrail observation")
		}
		if state.Active == r.vllmEffect.before {
			return nil, nil
		}
		return &attackEffectEvidence{Kind: r.vllmEffect.kind, Observed: true, ObservedAt: s.cfg.now().UTC().Format(time.RFC3339Nano), TargetUID: r.TargetUID, Before: r.vllmEffect.before, After: state.Active, Correlation: "temporal-event-and-exact-target", Limitation: "runtime variant transition is an in-place effect; no discriminating behavioral bypass/mitigation probe was available"}, nil
	case "endpoint-route-state":
		after := stringMapValue(pod.Metadata.Labels, "phorvex.ai/route-key")
		if after == "" || after == r.vllmEffect.before {
			return nil, nil
		}
		if stringMapValue(pod.Metadata.Annotations, "phorvex.ai/route-service") != r.vllmEffect.serviceName {
			return nil, fmt.Errorf("route Service annotation changed across endpoint observation")
		}
		service, err := s.readVLLMService(r.vllmEffect.serviceName)
		if err != nil {
			return nil, err
		}
		if service.Metadata.UID != r.vllmEffect.serviceUID || stringMapValue(service.Spec.Selector, "phorvex.ai/route-key") != after {
			return nil, nil
		}
		ready, err := s.targetReadyInRoute(r.vllmEffect.serviceName, service.Metadata.UID, r.TargetUID)
		if err != nil {
			return nil, err
		}
		if !ready {
			return nil, nil
		}
		postPod, podErr := s.readVLLMPod(r.Pod)
		postService, serviceErr := s.readVLLMService(r.vllmEffect.serviceName)
		if podErr != nil || serviceErr != nil || postPod.Metadata.UID != r.TargetUID || postService.Metadata.UID != r.vllmEffect.serviceUID ||
			stringMapValue(postPod.Metadata.Labels, "phorvex.ai/route-key") != after || stringMapValue(postService.Spec.Selector, "phorvex.ai/route-key") != after {
			return nil, fmt.Errorf("target or route identity changed across endpoint observation")
		}
		return &attackEffectEvidence{Kind: r.vllmEffect.kind, Observed: true, ObservedAt: s.cfg.now().UTC().Format(time.RFC3339Nano), TargetUID: r.TargetUID, Before: r.vllmEffect.before, After: after, ServiceUID: service.Metadata.UID, Correlation: "temporal-event-and-exact-target", Limitation: "selector restitch preserves stable Service and Pod locators; no SSRF/model-extraction mitigation is established"}, nil
	default:
		return nil, fmt.Errorf("unknown in-place effect kind %q", r.vllmEffect.kind)
	}
}

func (s *Server) validateVLLMEvent(r *attackRecord) error {
	var event vllmSecurityEvent
	if err := decodeClusterKubectlJSON(s, &event, "get", "securityevent", r.StimulusEvidence.EventName, "-o", "json"); err != nil {
		return err
	}
	if event.Metadata.Name != r.StimulusEvidence.EventName || event.Metadata.Namespace != "" || event.Metadata.UID != r.StimulusEvidence.EventUID ||
		event.Metadata.CreationTimestamp != r.StimulusEvidence.EventCreatedAt || event.Metadata.Labels["phorvex.ai/attack-correlation"] != r.StimulusEvidence.Correlation || event.Metadata.Labels["phorvex.ai/console-vllm"] != "true" ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != r.Namespace+"/"+r.Pod || event.Spec.Rule.Type != r.StimulusEvidence.EventRule || event.Spec.Rule.Source != "redteam" {
		return fmt.Errorf("correlated SecurityEvent identity or target changed")
	}
	if r.vllmEffect != nil && r.vllmEffect.kind == "adapter-epoch" &&
		(event.Metadata.Annotations["phorvex.ai/adapter-name"] != r.vllmEffect.adapterName || event.Metadata.Annotations["phorvex.ai/target-pod-uid"] != r.TargetUID) {
		return fmt.Errorf("correlated adapter SecurityEvent identity changed")
	}
	return nil
}
