package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var vllmEventSequence atomic.Uint64

type vllmSecurityEvent struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		UID               string            `json:"uid"`
		CreationTimestamp string            `json:"creationTimestamp"`
		Labels            map[string]string `json:"labels"`
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
	if targetUID == "" {
		return nil, fmt.Errorf("target Pod UID is unavailable")
	}
	sequence := vllmEventSequence.Add(1)
	correlation := fmt.Sprintf("%x-%x", s.cfg.now().UnixNano(), sequence)
	name := "redteam-vllm-" + strings.ToLower(evType) + "-" + correlation
	ruleType := vllmRuleType(evType)
	manifest := fmt.Sprintf(`apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: %s
  labels:
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
`, name, correlation, desc, vllmAttackNS, pod, ruleType, anomaly)
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
	out, err := s.cfg.execText(10*time.Second, "kubectl", "create", "-f", f.Name(), "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("create SecurityEvent: %w (%s)", err, strings.TrimSpace(out))
	}
	var event vllmSecurityEvent
	if err := json.Unmarshal([]byte(out), &event); err != nil {
		return nil, fmt.Errorf("created SecurityEvent reply is malformed; exact resource %q requires reconciliation: %w", name, err)
	}
	if event.Metadata.Name != name || event.Metadata.Namespace != "" || event.Metadata.UID == "" || event.Metadata.CreationTimestamp == "" ||
		event.Metadata.Labels["phorvex.ai/attack-correlation"] != correlation || event.Metadata.Labels["phorvex.ai/console-vllm"] != "true" || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != vllmAttackNS+"/"+pod ||
		event.Spec.Rule.Type != ruleType || event.Spec.Rule.Source != "redteam" {
		return nil, fmt.Errorf("created SecurityEvent reply is incomplete or mismatched; exact resource %q requires reconciliation", name)
	}
	return &attackStimulusEvidence{Kind: "synthetic-security-event", Observed: true, TargetUID: targetUID, EventName: name, EventUID: event.Metadata.UID, EventCreatedAt: event.Metadata.CreationTimestamp, EventRule: ruleType, Correlation: correlation, BehavioralExecuted: false, Limitation: "detector stimulus is not a demonstrated exploit"}, nil
}

const (
	vllmGuardrailURL = "http://localhost:8000"
	vllmRouteService = "vllm-infer"
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

// vllmHTTP executes the real serving-stack HTTP producer from the target Pod. Markers isolate
// stdout from kubectl's default-container warnings, and every caller validates status and schema.
func vllmHTTP(execIn func(string) (string, error), method, path, body string) (vllmHTTPResponse, error) {
	if method != http.MethodGet && method != http.MethodPost {
		return vllmHTTPResponse{}, fmt.Errorf("unsupported HTTP method %q", method)
	}
	if !strings.HasPrefix(path, "/v1/guardrail/") || strings.ContainsAny(path, "' \t\r\n") {
		return vllmHTTPResponse{}, fmt.Errorf("unsupported guardrail path %q", path)
	}
	if strings.Contains(body, "'") {
		return vllmHTTPResponse{}, fmt.Errorf("guardrail request body is not shell-safe")
	}
	data := ""
	if body != "" {
		data = " -H 'Content-Type: application/json' --data-binary '" + body + "'"
	}
	const begin, status = "__PHORVEX_HTTP_BEGIN__", "__PHORVEX_HTTP_STATUS__"
	cmd := "printf '" + begin + "\\n'; curl --silent --show-error --max-time 10 -X " + method + data +
		" -w '\\n" + status + "%{http_code}\\n' '" + vllmGuardrailURL + path + "'"
	out, err := execIn(cmd)
	if err != nil {
		return vllmHTTPResponse{}, fmt.Errorf("guardrail HTTP command: %w (%s)", err, strings.TrimSpace(out))
	}
	start := strings.LastIndex(out, begin+"\n")
	end := strings.LastIndex(out, "\n"+status)
	if start < 0 || end < start {
		return vllmHTTPResponse{}, fmt.Errorf("guardrail HTTP response framing unavailable")
	}
	codeText := strings.TrimSpace(out[end+1+len(status):])
	code, err := strconv.Atoi(codeText)
	if err != nil || code < 100 || code > 599 {
		return vllmHTTPResponse{}, fmt.Errorf("guardrail HTTP status is invalid")
	}
	return vllmHTTPResponse{Status: code, Body: []byte(out[start+len(begin)+1 : end])}, nil
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
	} `json:"metadata"`
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
	pod                 string
	targetUID           string
	originalRuntime     guardrailState
	originalAnnotations *map[string]string
	stagedAnnotations   *map[string]string
	runtimeStaged       bool
	metadataStaged      bool
	restoration         string
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
	service, err := s.readVLLMService()
	if err != nil {
		return nil, err
	}
	if pod.Metadata.ResourceVersion == "" || service.Metadata.ResourceVersion == "" || service.Spec.Selector == nil {
		return nil, fmt.Errorf("endpoint setup resourceVersion or selector authority is unavailable")
	}
	authority := &endpointSetupAuthority{pod: podName, targetUID: targetUID, serviceUID: service.Metadata.UID, originalLabels: copyOptionalStringMap(pod.Metadata.Labels), originalAnnotations: copyOptionalStringMap(pod.Metadata.Annotations), originalSelector: copyOptionalStringMap(service.Spec.Selector)}
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
	(*authority.stagedAnnotations)["phorvex.ai/route-service"] = vllmRouteService
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
	if err := s.exactJSONPatch("service", vllmRouteService, authority.serviceUID, service.Metadata.ResourceVersion, serviceOps...); err != nil {
		return fail(err)
	}
	authority.serviceStaged = true
	for attempt := 0; attempt < 12; attempt++ {
		currentPod, podErr := s.readVLLMPod(podName)
		currentService, serviceErr := s.readVLLMService()
		if podErr == nil && serviceErr == nil && currentPod.Metadata.UID == targetUID && currentService.Metadata.UID == authority.serviceUID &&
			stringMapsEqual(currentPod.Metadata.Labels, authority.stagedLabels) && stringMapsEqual(currentPod.Metadata.Annotations, authority.stagedAnnotations) &&
			stringMapsEqual(currentService.Spec.Selector, authority.stagedSelector) {
			ready, endpointErr := s.targetReadyInRoute(authority.serviceUID, targetUID)
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
	service, err := s.readVLLMService()
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
		if err := s.exactJSONPatch("service", vllmRouteService, authority.serviceUID, service.Metadata.ResourceVersion, ops...); err != nil {
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
	restoredService, serviceErr := s.readVLLMService()
	if podErr != nil || serviceErr != nil || restoredPod.Metadata.UID != authority.targetUID || restoredService.Metadata.UID != authority.serviceUID ||
		!stringMapsEqual(restoredPod.Metadata.Labels, authority.originalLabels) || !stringMapsEqual(restoredPod.Metadata.Annotations, authority.originalAnnotations) || !stringMapsEqual(restoredService.Spec.Selector, authority.originalSelector) {
		return fmt.Errorf("endpoint setup restoration readback is incomplete")
	}
	return nil
}

func (s *Server) prepareGuardrailEffect(podName, targetUID string, execIn func(string) (string, error)) (*guardrailSetupAuthority, error) {
	pod, err := s.readVLLMPod(podName)
	if err != nil || pod.Metadata.UID != targetUID || pod.Metadata.ResourceVersion == "" {
		return nil, fmt.Errorf("target Pod identity authority changed before guardrail setup")
	}
	before, err := readGuardrailState(execIn)
	if err != nil {
		return nil, fmt.Errorf("read guardrail setup baseline: %w", err)
	}
	authority := &guardrailSetupAuthority{pod: podName, targetUID: targetUID, originalRuntime: before, originalAnnotations: copyOptionalStringMap(pod.Metadata.Annotations)}
	if _, err := reloadGuardrail(execIn, "pgv1"); err != nil {
		return authority, fmt.Errorf("set guardrail stimulus variant: %w", err)
	}
	authority.runtimeStaged = true
	pod, err = s.readVLLMPod(podName)
	if err != nil || pod.Metadata.UID != targetUID || pod.Metadata.ResourceVersion == "" {
		return authority, fmt.Errorf("target Pod identity changed after guardrail runtime setup; restoration required")
	}
	// Bind the manager-visible metadata to the actual runtime baseline. The live failure that led to
	// this code had pgv1 in memory and stale pgv2 metadata, so the manager acknowledged another pgv1.
	authority.originalAnnotations = copyOptionalStringMap(pod.Metadata.Annotations)
	authority.stagedAnnotations = copyOptionalStringMap(authority.originalAnnotations)
	if authority.stagedAnnotations == nil {
		annotations := map[string]string{}
		authority.stagedAnnotations = &annotations
	}
	(*authority.stagedAnnotations)["phorvex.ai/guardrail-variant"] = "pgv1"
	ops := replaceOptionalMapPatch("/metadata/annotations", authority.originalAnnotations, authority.stagedAnnotations)
	if err := s.exactJSONPatch("pod", podName, targetUID, pod.Metadata.ResourceVersion, ops...); err != nil {
		if restoreErr := s.restoreGuardrailEffect(authority, execIn); restoreErr != nil {
			authority.restoration = "required: " + restoreErr.Error()
			return authority, fmt.Errorf("synchronize guardrail metadata: %w; exact restoration required: %v", err, restoreErr)
		}
		return authority, fmt.Errorf("synchronize guardrail metadata: %w; partial setup was restored", err)
	}
	authority.metadataStaged = true
	readback, readErr := s.readVLLMPod(podName)
	runtime, runtimeErr := readGuardrailState(execIn)
	finalPod, finalErr := s.readVLLMPod(podName)
	if readErr != nil || runtimeErr != nil || finalErr != nil || readback.Metadata.UID != targetUID || finalPod.Metadata.UID != targetUID ||
		!stringMapsEqual(readback.Metadata.Annotations, authority.stagedAnnotations) || runtime.Active != "pgv1" {
		if restoreErr := s.restoreGuardrailEffect(authority, execIn); restoreErr != nil {
			authority.restoration = "required: " + restoreErr.Error()
			return authority, fmt.Errorf("guardrail coherent setup readback failed; exact restoration required: %v", restoreErr)
		}
		return authority, fmt.Errorf("guardrail coherent setup readback failed; partial setup was restored")
	}
	return authority, nil
}

func (s *Server) restoreGuardrailEffect(authority *guardrailSetupAuthority, execIn func(string) (string, error)) error {
	if authority == nil {
		return fmt.Errorf("guardrail restoration authority is unavailable")
	}
	pod, err := s.readVLLMPod(authority.pod)
	if err != nil || pod.Metadata.UID != authority.targetUID || pod.Metadata.ResourceVersion == "" {
		return fmt.Errorf("target Pod identity changed; refusing guardrail restoration")
	}
	if authority.originalRuntime.Active == "" {
		return fmt.Errorf("original guardrail runtime state is unavailable")
	}
	if authority.metadataStaged {
		if !stringMapsEqual(pod.Metadata.Annotations, authority.stagedAnnotations) {
			return fmt.Errorf("guardrail Pod annotations changed; refusing restoration")
		}
		ops := replaceOptionalMapPatch("/metadata/annotations", authority.stagedAnnotations, authority.originalAnnotations)
		if err := s.exactJSONPatch("pod", authority.pod, authority.targetUID, pod.Metadata.ResourceVersion, ops...); err != nil {
			return err
		}
	} else if !stringMapsEqual(pod.Metadata.Annotations, authority.originalAnnotations) {
		return fmt.Errorf("guardrail Pod annotations changed before restoration")
	}
	if authority.runtimeStaged {
		if _, err := reloadGuardrail(execIn, authority.originalRuntime.Active); err != nil {
			return err
		}
	}
	restoredPod, podErr := s.readVLLMPod(authority.pod)
	restoredRuntime, runtimeErr := readGuardrailState(execIn)
	finalPod, finalErr := s.readVLLMPod(authority.pod)
	if podErr != nil || runtimeErr != nil || finalErr != nil || restoredPod.Metadata.UID != authority.targetUID || finalPod.Metadata.UID != authority.targetUID ||
		!stringMapsEqual(restoredPod.Metadata.Annotations, authority.originalAnnotations) || restoredRuntime.Active != authority.originalRuntime.Active {
		return fmt.Errorf("guardrail setup restoration readback is incomplete")
	}
	authority.restoration = "restored"
	return nil
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

func (s *Server) readVLLMService() (vllmServiceState, error) {
	var state vllmServiceState
	err := decodeKubectlJSON(s, vllmAttackNS, &state, "get", "service", vllmRouteService, "-o", "json")
	if err == nil && (state.Metadata.Name != vllmRouteService || state.Metadata.UID == "") {
		err = fmt.Errorf("route Service identity is absent or mismatched")
	}
	return state, err
}

func (s *Server) targetReadyInRoute(serviceUID, targetUID string) (bool, error) {
	var slices vllmEndpointSliceList
	if err := decodeKubectlJSON(s, vllmAttackNS, &slices, "get", "endpointslice", "-l", "kubernetes.io/service-name="+vllmRouteService, "-o", "json"); err != nil {
		return false, err
	}
	for _, slice := range slices.Items {
		if slice.Metadata.Labels["kubernetes.io/service-name"] != vllmRouteService {
			return false, fmt.Errorf("EndpointSlice service label is mismatched")
		}
		owned := false
		for _, owner := range slice.Metadata.OwnerReferences {
			if owner.Kind == "Service" && owner.Name == vllmRouteService && owner.UID == serviceUID {
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
		service, err := s.readVLLMService()
		if err != nil {
			return nil, err
		}
		if service.Metadata.UID != r.vllmEffect.serviceUID || stringMapValue(service.Spec.Selector, "phorvex.ai/route-key") != after {
			return nil, nil
		}
		ready, err := s.targetReadyInRoute(service.Metadata.UID, r.TargetUID)
		if err != nil {
			return nil, err
		}
		if !ready {
			return nil, nil
		}
		postPod, podErr := s.readVLLMPod(r.Pod)
		postService, serviceErr := s.readVLLMService()
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
	return nil
}
