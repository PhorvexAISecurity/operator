package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
)

const (
	guardrailSayOK          = "Say OK"
	guardrailArithmetic     = "What is two plus two? Reply with the number only."
	guardrailMaxBody        = 16 << 10
	guardrailRequestTimeout = 12 * time.Second
)

type guardrailCalibrationHandler struct{}

func NewGuardrailCalibrationHandler() Handler { return guardrailCalibrationHandler{} }

func (guardrailCalibrationHandler) Definition() Definition {
	d, _ := DefinitionFor(GuardrailCalibration)
	return d
}

// ValidateGuardrailCalibrationRuntime deliberately accepts only the reviewed
// installed route shape. It does not probe availability or grant permissions.
func ValidateGuardrailCalibrationRuntime(c GuardrailCalibrationRuntime) error {
	if !c.Enabled {
		return errors.New("guardrail calibration is disabled")
	}
	if c.Namespace != "vllm" || c.Service != "vllm" || c.Port != 8000 || c.Container != "guardrail" ||
		c.SourceConfigMap != "guardrail-proxy" || c.SourceKey != "guardrail_proxy.py" {
		return errors.New("guardrail calibration route differs from the reviewed installed contract")
	}
	decoded, err := hex.DecodeString(c.ExpectedSourceSHA256)
	if err != nil || len(decoded) != sha256.Size || c.ExpectedSourceSHA256 != strings.ToLower(c.ExpectedSourceSHA256) {
		return errors.New("guardrail calibration expected source digest is invalid")
	}
	return nil
}

func (guardrailCalibrationHandler) Validate(r Runtime) error {
	if err := ValidateGuardrailCalibrationRuntime(r.Guardrail); err != nil {
		return err
	}
	if r.Kube == nil || r.RESTConfig == nil {
		return errors.New("guardrail Kubernetes read clients are unavailable")
	}
	return nil
}

type guardrailAuthority struct {
	PodName          string               `json:"podName"`
	PodUID           string               `json:"podUID"`
	PodRV            string               `json:"podRV"`
	PodIP            string               `json:"podIP"`
	ServiceUID       string               `json:"serviceUID"`
	ServiceRV        string               `json:"serviceRV"`
	SliceUID         string               `json:"sliceUID"`
	SliceRV          string               `json:"sliceRV"`
	SourceUID        string               `json:"sourceUID"`
	SourceRV         string               `json:"sourceRV"`
	SourceSHA256     string               `json:"sourceSHA256"`
	ActiveAnnotation string               `json:"activeAnnotation"`
	Roster           string               `json:"roster"`
	Containers       []guardrailContainer `json:"containers"`
}

type guardrailContainer struct {
	Name         string `json:"name"`
	ContainerID  string `json:"containerID"`
	ImageID      string `json:"imageID"`
	RestartCount int32  `json:"restartCount"`
}

func guardrailFingerprint(a guardrailAuthority) string {
	b, _ := json.Marshal(a)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func captureGuardrailAuthority(ctx context.Context, r Runtime) (guardrailAuthority, error) {
	c := r.Guardrail
	svc, err := r.Kube.CoreV1().Services(c.Namespace).Get(ctx, c.Service, metav1.GetOptions{})
	if err != nil {
		return guardrailAuthority{}, fmt.Errorf("read fixed Service: %w", err)
	}
	if svc.UID == "" || svc.ResourceVersion == "" || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) != 1 || svc.Spec.Selector["phorvex.ai/role"] != "leader" || len(svc.Spec.Ports) != 1 ||
		svc.Spec.Ports[0].Port != c.Port || svc.Spec.Ports[0].Protocol != corev1.ProtocolTCP || svc.Spec.Ports[0].TargetPort.IntVal != c.Port {
		return guardrailAuthority{}, errors.New("fixed Service selector, port or identity is unsupported")
	}
	pods, err := r.Kube.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(svc.Spec.Selector).String()})
	if err != nil {
		return guardrailAuthority{}, fmt.Errorf("list fixed Service Pods: %w", err)
	}
	if len(pods.Items) != 1 {
		return guardrailAuthority{}, errors.New("fixed Service must select exactly one Pod")
	}
	p := &pods.Items[0]
	if p.UID == "" || p.ResourceVersion == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" ||
		p.Labels["phorvex.ai/role"] != "leader" || p.Annotations["phorvex.ai/guardrail-variants"] != "pgv2,pgv1" {
		return guardrailAuthority{}, errors.New("selected Pod identity, readiness or guardrail roster is unsupported")
	}
	podReady := false
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			podReady = true
		}
	}
	if !podReady {
		return guardrailAuthority{}, errors.New("selected Pod Ready condition is false or absent")
	}
	active := p.Annotations["phorvex.ai/guardrail-variant"]
	if active != "pgv1" && active != "pgv2" {
		return guardrailAuthority{}, errors.New("selected Pod active guardrail annotation is unsupported")
	}
	if len(p.Spec.Containers) != 2 || len(p.Status.ContainerStatuses) != 2 {
		return guardrailAuthority{}, errors.New("selected Pod container population differs")
	}
	statuses := map[string]corev1.ContainerStatus{}
	for _, s := range p.Status.ContainerStatuses {
		if s.Name == "" || !s.Ready || s.ContainerID == "" || s.ImageID == "" {
			return guardrailAuthority{}, errors.New("selected Pod container is not ready or identifiable")
		}
		statuses[s.Name] = s
	}
	a := guardrailAuthority{PodName: p.Name, PodUID: string(p.UID), PodRV: p.ResourceVersion, PodIP: p.Status.PodIP,
		ServiceUID: string(svc.UID), ServiceRV: svc.ResourceVersion, ActiveAnnotation: active, Roster: p.Annotations["phorvex.ai/guardrail-variants"]}
	for _, name := range []string{"guardrail", "vllm"} {
		s, ok := statuses[name]
		if !ok {
			return guardrailAuthority{}, errors.New("selected Pod lacks an expected ready container")
		}
		a.Containers = append(a.Containers, guardrailContainer{Name: name, ContainerID: s.ContainerID, ImageID: s.ImageID, RestartCount: s.RestartCount})
	}
	guardrailContainerPresent, mountName := false, ""
	for _, container := range p.Spec.Containers {
		if container.Name != c.Container {
			continue
		}
		guardrailContainerPresent = true
		portFound := false
		for _, port := range container.Ports {
			if port.ContainerPort == c.Port && port.Protocol == corev1.ProtocolTCP {
				portFound = true
			}
		}
		if !portFound {
			return guardrailAuthority{}, errors.New("guardrail container does not expose the fixed port")
		}
		for _, m := range container.VolumeMounts {
			mountPath := path.Clean(m.MountPath)
			if mountPath == "/src" {
				if m.SubPath != "" || m.SubPathExpr != "" || mountName != "" {
					return guardrailAuthority{}, errors.New("guardrail source mount is shadowed or uses a subpath")
				}
				mountName = m.Name
			} else if mountPath == "/" || strings.HasPrefix(mountPath, "/src/") {
				return guardrailAuthority{}, errors.New("guardrail source path is shadowed by another mount")
			}
		}
	}
	if !guardrailContainerPresent || mountName == "" {
		return guardrailAuthority{}, errors.New("guardrail source mount is absent")
	}
	volumeFound := false
	for _, volume := range p.Spec.Volumes {
		if volume.Name == mountName && volume.ConfigMap != nil && volume.ConfigMap.Name == c.SourceConfigMap {
			if len(volume.ConfigMap.Items) > 0 {
				keyProjected := false
				for _, item := range volume.ConfigMap.Items {
					if item.Key == c.SourceKey && item.Path == c.SourceKey {
						keyProjected = true
					} else if path.Clean(item.Path) == c.SourceKey {
						return guardrailAuthority{}, errors.New("another ConfigMap key shadows the guardrail source path")
					}
				}
				if !keyProjected {
					return guardrailAuthority{}, errors.New("guardrail source key is not projected at the expected path")
				}
			}
			volumeFound = true
		}
	}
	if !volumeFound {
		return guardrailAuthority{}, errors.New("guardrail source mount does not select fixed ConfigMap")
	}
	cm, err := r.Kube.CoreV1().ConfigMaps(c.Namespace).Get(ctx, c.SourceConfigMap, metav1.GetOptions{})
	if err != nil {
		return guardrailAuthority{}, fmt.Errorf("read guardrail source ConfigMap: %w", err)
	}
	source, ok := cm.Data[c.SourceKey]
	if !ok || source == "" || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
		return guardrailAuthority{}, errors.New("guardrail source ConfigMap identity or key is unavailable")
	}
	sum := sha256.Sum256([]byte(source))
	a.SourceSHA256 = hex.EncodeToString(sum[:])
	if a.SourceSHA256 != c.ExpectedSourceSHA256 {
		return guardrailAuthority{}, errors.New("guardrail source digest differs from configured authority")
	}
	a.SourceUID, a.SourceRV = string(cm.UID), cm.ResourceVersion
	slices, err := r.Kube.DiscoveryV1().EndpointSlices(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + c.Service})
	if err != nil {
		return guardrailAuthority{}, fmt.Errorf("list fixed EndpointSlices: %w", err)
	}
	if len(slices.Items) != 1 {
		return guardrailAuthority{}, errors.New("fixed Service EndpointSlice population differs")
	}
	slice := &slices.Items[0]
	if slice.UID == "" || slice.ResourceVersion == "" || slice.DeletionTimestamp != nil || slice.Labels[discoveryv1.LabelServiceName] != c.Service || len(slice.Ports) != 1 ||
		slice.Ports[0].Port == nil || *slice.Ports[0].Port != c.Port || slice.Ports[0].Protocol == nil || *slice.Ports[0].Protocol != corev1.ProtocolTCP || len(slice.Endpoints) != 1 {
		return guardrailAuthority{}, errors.New("fixed EndpointSlice port or identity differs")
	}
	ownerOK := false
	for _, owner := range slice.OwnerReferences {
		if owner.Kind == "Service" && owner.Name == c.Service && owner.UID == svc.UID && owner.Controller != nil && *owner.Controller {
			ownerOK = true
		}
	}
	if !ownerOK {
		return guardrailAuthority{}, errors.New("fixed EndpointSlice is not owned by the exact Service UID")
	}
	ep := slice.Endpoints[0]
	if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.Name != p.Name || ep.TargetRef.Namespace != c.Namespace || ep.TargetRef.UID != p.UID ||
		ep.Conditions.Ready == nil || !*ep.Conditions.Ready || ep.Conditions.Terminating != nil && *ep.Conditions.Terminating ||
		len(ep.Addresses) != 1 || ep.Addresses[0] != p.Status.PodIP {
		return guardrailAuthority{}, errors.New("fixed EndpointSlice routes to an unsupported target")
	}
	a.SliceUID, a.SliceRV = string(slice.UID), slice.ResourceVersion
	return a, nil
}

// guardrailProxyCall uses a Kubernetes-authenticated HTTP client without the
// REST request retry loop. POST is dispatched once, with a fixed path and body.
func guardrailProxyCall(ctx context.Context, r Runtime, a guardrailAuthority, method, path, text string) ([]byte, error) {
	base, err := url.Parse(r.RESTConfig.Host)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("Kubernetes API origin is invalid")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/namespaces/" + r.Guardrail.Namespace + "/pods/http:" + a.PodName + ":" + strconv.Itoa(int(r.Guardrail.Port)) + "/proxy" + path
	var body io.Reader
	if method == http.MethodPost {
		raw, _ := json.Marshal(map[string]string{"text": text})
		body = bytes.NewReader(raw)
	}
	requestCtx, cancel := context.WithTimeout(ctx, guardrailRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, base.String(), body)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	client, err := rest.HTTPClientFor(r.RESTConfig)
	if err != nil {
		return nil, fmt.Errorf("Kubernetes authenticated HTTP client: %w", err)
	}
	client.Timeout = guardrailRequestTimeout
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return errors.New("Kubernetes proxy redirect refused") }
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fixed Pod proxy request: %w", err)
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, guardrailMaxBody+1))
	if err != nil || len(limited) > guardrailMaxBody {
		return nil, errors.New("fixed Pod proxy response is unreadable or exceeds bound")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fixed Pod proxy returned HTTP %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return nil, errors.New("fixed Pod proxy response is not JSON")
	}
	return limited, nil
}

type guardrailRuntimeState struct {
	Ready      bool               `json:"ready"`
	Active     string             `json:"active"`
	Loaded     []string           `json:"loaded"`
	Thresholds map[string]float64 `json:"thresholds"`
}

func parseGuardrailState(raw []byte, annotation string) (guardrailRuntimeState, error) {
	var s guardrailRuntimeState
	fields, err := uniqueGuardrailObject(raw)
	if err != nil || len(fields) != 4 {
		return s, errors.New("guardrail state object has missing, duplicate or unsupported fields")
	}
	for key := range fields {
		if key != "ready" && key != "active" && key != "loaded" && key != "thresholds" {
			return s, errors.New("guardrail state has an unsupported field")
		}
	}
	thresholdFields, err := uniqueGuardrailObject(fields["thresholds"])
	if err != nil || len(thresholdFields) != 2 || thresholdFields["pgv1"] == nil || thresholdFields["pgv2"] == nil {
		return s, errors.New("guardrail state thresholds are missing or ambiguous")
	}
	if err := json.Unmarshal(fields["ready"], &s.Ready); err != nil {
		return s, err
	}
	if err := json.Unmarshal(fields["active"], &s.Active); err != nil {
		return s, err
	}
	if err := json.Unmarshal(fields["loaded"], &s.Loaded); err != nil {
		return s, err
	}
	s.Thresholds = make(map[string]float64, 2)
	for key, value := range thresholdFields {
		var threshold float64
		if err := json.Unmarshal(value, &threshold); err != nil {
			return s, err
		}
		s.Thresholds[key] = threshold
	}
	if !s.Ready || s.Active != annotation || len(s.Loaded) != 2 || len(s.Thresholds) != 2 || s.Thresholds["pgv1"] <= 0 || s.Thresholds["pgv2"] <= 0 ||
		s.Thresholds["pgv1"] > 1 || s.Thresholds["pgv2"] > 1 || math.IsNaN(s.Thresholds["pgv1"]) || math.IsNaN(s.Thresholds["pgv2"]) {
		return s, errors.New("guardrail runtime state is unavailable or incoherent")
	}
	loaded := map[string]bool{}
	for _, v := range s.Loaded {
		loaded[v] = true
	}
	if len(loaded) != 2 || !loaded["pgv1"] || !loaded["pgv2"] {
		return s, errors.New("guardrail loaded variant roster differs")
	}
	return s, nil
}

func uniqueGuardrailObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("non-string object key")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("duplicate object key")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("unterminated JSON object")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return fields, nil
}

func parseGuardrailScores(raw []byte) (map[string]float64, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("classifier response is not an object")
	}
	scores := map[string]float64{}
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return nil, errors.New("classifier response key is malformed")
		}
		key, ok := keyToken.(string)
		if !ok || key != "pgv1" && key != "pgv2" {
			return nil, errors.New("classifier response has an unsupported variant")
		}
		if _, duplicate := scores[key]; duplicate {
			return nil, errors.New("classifier response duplicates a variant")
		}
		var field json.RawMessage
		if err := d.Decode(&field); err != nil {
			return nil, errors.New("classifier response value is malformed")
		}
		field = bytes.TrimSpace(field)
		if len(field) == 0 || field[0] == 'n' || field[0] == '"' {
			return nil, errors.New("classifier score is not a JSON number")
		}
		var n float64
		if err := json.Unmarshal(field, &n); err != nil {
			return nil, errors.New("classifier score is not a JSON number")
		}
		scores[key] = n
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') {
		return nil, errors.New("classifier response object is unterminated")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("classifier response has trailing JSON")
	}
	if len(scores) != 2 {
		return nil, errors.New("classifier response variant population differs")
	}
	for _, v := range []string{"pgv1", "pgv2"} {
		n, ok := scores[v]
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1 {
			return nil, errors.New("classifier score is missing or outside probability bounds")
		}
	}
	return scores, nil
}

func (guardrailCalibrationHandler) Run(ctx context.Context, jc JobContext) (result Result) {
	started := time.Now().UTC()
	result = Result{Outcome: OutcomeInconclusive, Summary: "benign guardrail calibration did not complete", StartedAt: started,
		Limits: []string{GuardrailCalibrationClaimLimits()}, Cleanup: Cleanup{Attempted: true, Status: "read-only-incomplete"},
		Evidence: map[string]string{"classifierOnly": "true", "servingOutcome": "NOT_MEASURED", "injectedResponse": "NOT_RUN", "securityEfficacy": "NOT_EVALUATED", "classifierRequests": "0"}}
	defer func() { result.FinishedAt = time.Now().UTC() }()
	if err := ValidateGuardrailCalibrationRuntime(jc.Runtime.Guardrail); err != nil {
		result.Summary = err.Error()
		return result
	}
	if jc.Runtime.Kube == nil || jc.Runtime.RESTConfig == nil || jc.Recorder == nil {
		result.Summary = "guardrail read runtime or recorder is unavailable"
		return result
	}
	before, err := captureGuardrailAuthority(ctx, jc.Runtime)
	if err != nil {
		result.Summary = "guardrail route/source preflight inconclusive: " + err.Error()
		return result
	}
	result.Evidence["targetPodUID"] = before.PodUID
	result.Evidence["serviceUID"] = before.ServiceUID
	result.Evidence["sourceConfigMapUID"] = before.SourceUID
	result.Evidence["sourceConfigMapRV"] = before.SourceRV
	result.Evidence["sourceSHA256"] = before.SourceSHA256
	result.Evidence["sourceEvidence"] = "configmap-mount-declaration"
	result.Evidence["loadedSource"] = "NOT_ATTESTED"
	result.Evidence["modelRevision"] = "NOT_ATTESTED"
	result.Evidence["authorityBeforeSHA256"] = guardrailFingerprint(before)
	stateRaw, err := guardrailProxyCall(ctx, jc.Runtime, before, http.MethodGet, "/v1/guardrail/state", "")
	if err != nil {
		result.Summary = "guardrail initial state unavailable: " + err.Error()
		return result
	}
	stateBefore, err := parseGuardrailState(stateRaw, before.ActiveAnnotation)
	if err != nil {
		result.Summary = "guardrail initial state unsupported: " + err.Error()
		return result
	}
	result.Evidence["activeVariant"] = stateBefore.Active
	texts := []struct{ label, text string }{{"sayOK", guardrailSayOK}, {"arithmetic", guardrailArithmetic}}
	scores := make(map[string]map[string]float64, 2)
	for _, fixed := range texts {
		current, currentErr := captureGuardrailAuthority(ctx, jc.Runtime)
		if currentErr != nil || guardrailFingerprint(current) != guardrailFingerprint(before) {
			result.Summary = "guardrail authority changed before a fixed classifier request"
			return result
		}
		if err = jc.Recorder.Intent(Intent{Step: "classify-" + fixed.label, Mutation: false, At: time.Now().UTC(), Identity: map[string]string{"path": "/v1/guardrail/classify", "textSHA256": shaGuardrailText(fixed.text)}}); err != nil {
			result.Summary = "classifier intent could not be recorded"
			return result
		}
		raw, callErr := guardrailProxyCall(ctx, jc.Runtime, before, http.MethodPost, "/v1/guardrail/classify", fixed.text)
		count, _ := strconv.Atoi(result.Evidence["classifierRequests"])
		result.Evidence["classifierRequests"] = strconv.Itoa(count + 1)
		if callErr != nil {
			result.Summary = "fixed classifier request outcome is ambiguous: " + callErr.Error()
			return result
		}
		parsed, parseErr := parseGuardrailScores(raw)
		if parseErr != nil {
			result.Summary = "fixed classifier response unsupported: " + parseErr.Error()
			return result
		}
		if err = jc.Recorder.Event(Event{Step: "classify-" + fixed.label, Status: "observed", At: time.Now().UTC(), Identity: map[string]string{"bodySHA256": shaGuardrailBytes(raw)}}); err != nil {
			result.Summary = "classifier observation could not be recorded"
			return result
		}
		scores[fixed.label] = parsed
	}
	stateAfterRaw, err := guardrailProxyCall(ctx, jc.Runtime, before, http.MethodGet, "/v1/guardrail/state", "")
	if err != nil {
		result.Summary = "guardrail final state unavailable: " + err.Error()
		return result
	}
	stateAfter, err := parseGuardrailState(stateAfterRaw, before.ActiveAnnotation)
	if err != nil || !sameGuardrailState(stateBefore, stateAfter) {
		result.Summary = "guardrail runtime state changed during calibration"
		return result
	}
	after, err := captureGuardrailAuthority(ctx, jc.Runtime)
	if err != nil || guardrailFingerprint(before) != guardrailFingerprint(after) {
		result.Summary = "guardrail target, route or source changed during calibration"
		return result
	}
	result.Evidence["authorityAfterSHA256"] = guardrailFingerprint(after)
	falsePositive := []string{}
	for _, variant := range []string{"pgv1", "pgv2"} {
		threshold := stateBefore.Thresholds[variant]
		result.Evidence[variant+"Threshold"] = strconv.FormatFloat(threshold, 'g', -1, 64)
		for _, fixed := range texts {
			score := scores[fixed.label][variant]
			result.Evidence[variant+fixed.label+"Score"] = strconv.FormatFloat(score, 'g', -1, 64)
			result.Evidence[variant+fixed.label+"ExpectedLabel"] = "benign"
			result.Evidence[variant+fixed.label+"FalsePositive"] = strconv.FormatBool(score >= threshold)
			if score >= threshold {
				falsePositive = append(falsePositive, variant+":"+fixed.label)
			}
		}
	}
	result.Evidence["falsePositiveFindings"] = strings.Join(falsePositive, ",")
	result.Evidence["calibrationQuality"] = "no-fixed-benign-false-positive"
	if len(falsePositive) > 0 {
		result.Evidence["calibrationQuality"] = "fixed-benign-false-positive-observed"
	}
	result.Outcome = OutcomeFunctionalPass
	result.Summary = "two fixed benign classifier reads completed with coherent installed authority; calibration quality is reported separately"
	result.Cleanup = Cleanup{Attempted: true, Verified: true, Status: "PASS", Details: map[string]string{"clientWritesEventsChats": "none", "serverSideEffects": "NOT_ATTESTED", "authoritySHA256": guardrailFingerprint(after)}}
	return result
}

func GuardrailCalibrationClaimLimits() string {
	d, _ := DefinitionFor(GuardrailCalibration)
	return d.ClaimLimits
}
func shaGuardrailText(s string) string  { return shaGuardrailBytes([]byte(s)) }
func shaGuardrailBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func sameGuardrailState(a, b guardrailRuntimeState) bool {
	return a.Ready == b.Ready && a.Active == b.Active && a.Thresholds["pgv1"] == b.Thresholds["pgv1"] && a.Thresholds["pgv2"] == b.Thresholds["pgv2"] &&
		len(a.Loaded) == len(b.Loaded) && strings.Join(a.Loaded, ",") == strings.Join(b.Loaded, ",")
}

func (guardrailCalibrationHandler) Reconcile(_ context.Context, _ JobContext, j Journal) Cleanup {
	for _, r := range j.Records {
		if r.Intent != nil && r.Intent.Mutation {
			return Cleanup{Attempted: true, Status: "foreign-mutation-intent", UnsafeToRetry: true}
		}
	}
	return Cleanup{Attempted: true, Verified: true, Status: "PASS", Details: map[string]string{"clientWritesEventsChats": "none", "serverSideEffects": "NOT_ATTESTED", "classifierReplay": "none"}}
}
