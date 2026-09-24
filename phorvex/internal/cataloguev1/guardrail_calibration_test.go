package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type guardrailTestRecorder struct {
	intents []Intent
	events  []Event
}

func (r *guardrailTestRecorder) Intent(x Intent) error         { r.intents = append(r.intents, x); return nil }
func (r *guardrailTestRecorder) Event(x Event) error           { r.events = append(r.events, x); return nil }
func (*guardrailTestRecorder) Metric(Metric) error             { return nil }
func (*guardrailTestRecorder) MetricRaw(json.RawMessage) error { return nil }
func (*guardrailTestRecorder) Result(Result) error             { return nil }

type guardrailFixture struct {
	mu             sync.Mutex
	active         string
	wrongTarget    bool
	wrongOwner     bool
	unreadyPod     bool
	shadowSource   bool
	wrongProtocol  bool
	drift          bool
	malformedScore bool
	oversizeBody   bool
	denyService    bool
	classifyTexts  []string
	proxyState     int
	mutatingCalls  int
	serviceReads   int
	requestPaths   []string
	stateRaw       []byte
	stateAfterRaw  []byte
}

func (f *guardrailFixture) setup(t *testing.T) (Runtime, *guardrailTestRecorder, func()) {
	t.Helper()
	if f.active == "" {
		f.active = "pgv2"
	}
	content := "fixed installed guardrail source\n"
	digest := sha256.Sum256([]byte(content))
	cfg := GuardrailCalibrationRuntime{Enabled: true, Namespace: "vllm", Service: "vllm", Port: 8000, Container: "guardrail", SourceConfigMap: "guardrail-proxy", SourceKey: "guardrail_proxy.py", ExpectedSourceSHA256: hex.EncodeToString(digest[:])}
	ready := true
	falseValue := false
	port := int32(8000)
	pod := corev1.Pod{TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "vllm-1", Namespace: "vllm", UID: types.UID("pod-uid"), ResourceVersion: "10", Labels: map[string]string{"phorvex.ai/role": "leader"}, Annotations: map[string]string{"phorvex.ai/guardrail-variants": "pgv2,pgv1", "phorvex.ai/guardrail-variant": f.active}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "guardrail", Ports: []corev1.ContainerPort{{ContainerPort: 8000, Protocol: corev1.ProtocolTCP}}, VolumeMounts: []corev1.VolumeMount{{Name: "source", MountPath: "/src"}}}, {Name: "vllm"}}, Volumes: []corev1.Volume{{Name: "source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "guardrail-proxy"}}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.7", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "guardrail", Ready: true, ContainerID: "containerd://guardrail", ImageID: "image-guardrail"}, {Name: "vllm", Ready: true, ContainerID: "containerd://vllm", ImageID: "image-vllm"}}}}
	service := corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "vllm", Namespace: "vllm", UID: types.UID("service-uid"), ResourceVersion: "11"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"phorvex.ai/role": "leader"}, Ports: []corev1.ServicePort{{Port: 8000, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8000)}}}}
	slice := discoveryv1.EndpointSlice{TypeMeta: metav1.TypeMeta{Kind: "EndpointSlice", APIVersion: "discovery.k8s.io/v1"}, ObjectMeta: metav1.ObjectMeta{Name: "vllm-a", Namespace: "vllm", UID: types.UID("slice-uid"), ResourceVersion: "12", Labels: map[string]string{discoveryv1.LabelServiceName: "vllm"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: "vllm", UID: types.UID("service-uid"), Controller: &ready}}}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: ptrProtocol(corev1.ProtocolTCP)}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.7"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready, Terminating: &falseValue}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "vllm-1", Namespace: "vllm", UID: types.UID("pod-uid")}}}}
	cm := corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "guardrail-proxy", Namespace: "vllm", UID: types.UID("cm-uid"), ResourceVersion: "13"}, Data: map[string]string{"guardrail_proxy.py": content}}
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requestPaths = append(f.requestPaths, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			f.mutatingCalls++
			http.Error(w, "unexpected", 500)
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/vllm/services/vllm":
			f.serviceReads++
			if f.denyService {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			write(w, service)
		case "/api/v1/namespaces/vllm/pods":
			copyPod := pod.DeepCopy()
			if f.drift && f.serviceReads >= 2 {
				copyPod.ResourceVersion = "changed"
			}
			if f.unreadyPod {
				copyPod.Status.Conditions[0].Status = corev1.ConditionFalse
			}
			if f.shadowSource {
				copyPod.Spec.Containers[0].VolumeMounts = append(copyPod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: "/src/guardrail_proxy.py"})
			}
			write(w, corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: []corev1.Pod{*copyPod}})
		case "/api/v1/namespaces/vllm/configmaps/guardrail-proxy":
			write(w, cm)
		case "/apis/discovery.k8s.io/v1/namespaces/vllm/endpointslices":
			copySlice := slice.DeepCopy()
			if f.wrongTarget {
				copySlice.Endpoints[0].TargetRef.UID = types.UID("unrelated-pod")
			}
			if f.wrongOwner {
				copySlice.OwnerReferences[0].UID = types.UID("unrelated-service")
			}
			if f.wrongProtocol {
				protocol := corev1.ProtocolUDP
				copySlice.Ports[0].Protocol = &protocol
			}
			write(w, discoveryv1.EndpointSliceList{TypeMeta: metav1.TypeMeta{Kind: "EndpointSliceList", APIVersion: "discovery.k8s.io/v1"}, Items: []discoveryv1.EndpointSlice{*copySlice}})
		case "/api/v1/namespaces/vllm/pods/http:vllm-1:8000/proxy/v1/guardrail/state":
			if r.Method != http.MethodGet {
				f.mutatingCalls++
				http.Error(w, "wrong method", 500)
				return
			}
			f.proxyState++
			if len(f.stateRaw) > 0 {
				state := f.stateRaw
				if f.proxyState > 1 && len(f.stateAfterRaw) > 0 {
					state = f.stateAfterRaw
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(state)
				return
			}
			write(w, map[string]any{"ready": true, "active": f.active, "loaded": []string{"pgv1", "pgv2"}, "thresholds": map[string]float64{"pgv1": 0.5, "pgv2": 0.5}})
		case "/api/v1/namespaces/vllm/pods/http:vllm-1:8000/proxy/v1/guardrail/classify":
			if r.Method != http.MethodPost {
				f.mutatingCalls++
				http.Error(w, "wrong method", 500)
				return
			}
			var body struct {
				Text string `json:"text"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, "bad body", 400)
				return
			}
			f.classifyTexts = append(f.classifyTexts, body.Text)
			if f.oversizeBody {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(strings.Repeat("x", guardrailMaxBody+1)))
				return
			}
			if f.malformedScore {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"pgv1":"invalid","pgv2":0.1}`))
				return
			}
			if body.Text == guardrailSayOK {
				write(w, map[string]float64{"pgv1": 0.999, "pgv2": 0.03})
				return
			}
			if body.Text == guardrailArithmetic {
				write(w, map[string]float64{"pgv1": 0.000001, "pgv2": 0.00005})
				return
			}
			f.mutatingCalls++
			http.Error(w, "unexpected text", 500)
		default:
			f.mutatingCalls++
			http.Error(w, "unexpected API path", 500)
		}
	}))
	restConfig := &rest.Config{Host: server.URL, Timeout: guardrailRequestTimeout}
	kube, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	recorder := &guardrailTestRecorder{}
	return Runtime{Kube: kube, RESTConfig: restConfig, Guardrail: cfg}, recorder, server.Close
}

func ptrProtocol(p corev1.Protocol) *corev1.Protocol { return &p }

func TestGuardrailCalibrationBenignFindingAndExactRequests(t *testing.T) {
	for _, active := range []string{"pgv1", "pgv2"} {
		t.Run(active, func(t *testing.T) {
			fixture := &guardrailFixture{active: active}
			runtime, recorder, closeServer := fixture.setup(t)
			defer closeServer()
			result := NewGuardrailCalibrationHandler().Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
			if result.Outcome != OutcomeFunctionalPass || !result.Cleanup.Verified || result.FinishedAt.Before(result.StartedAt) {
				t.Fatalf("valid benign measurement rejected: %+v", result)
			}
			if result.Evidence["calibrationQuality"] != "fixed-benign-false-positive-observed" || result.Evidence["falsePositiveFindings"] != "pgv1:sayOK" || result.Evidence["pgv1sayOKFalsePositive"] != "true" || result.Evidence["pgv2sayOKFalsePositive"] != "false" {
				t.Fatalf("benign false positive not separated from test pass: %+v", result.Evidence)
			}
			if result.Evidence["activeVariant"] != active || result.Evidence["servingOutcome"] != "NOT_MEASURED" || result.Evidence["injectedResponse"] != "NOT_RUN" || result.Evidence["securityEfficacy"] != "NOT_EVALUATED" {
				t.Fatalf("calibration claim crossed boundary: %+v", result.Evidence)
			}
			if result.Evidence["stateShape"] != "legacy" || result.Evidence["declaredMode"] != "UNREPORTED" || result.Evidence["declaredProvenance"] != "UNREPORTED" {
				t.Fatalf("legacy state invented a mode or provenance: %+v", result.Evidence)
			}
			if strings.Join(fixture.classifyTexts, "|") != guardrailSayOK+"|"+guardrailArithmetic || fixture.proxyState != 2 || fixture.mutatingCalls != 0 || len(recorder.intents) != 2 || len(recorder.events) != 2 {
				t.Fatalf("unexpected requests or journal: texts=%v state=%d mutations=%d intents=%d events=%d", fixture.classifyTexts, fixture.proxyState, fixture.mutatingCalls, len(recorder.intents), len(recorder.events))
			}
			for _, intent := range recorder.intents {
				if intent.Mutation {
					t.Fatal("classifier intent marked mutation")
				}
			}
		})
	}
}

func TestGuardrailCalibrationRefusesBeforeClassifierOnAuthorityFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*guardrailFixture, *Runtime)
	}{
		{"wrong endpoint UID", func(f *guardrailFixture, _ *Runtime) { f.wrongTarget = true }},
		{"wrong Service owner UID", func(f *guardrailFixture, _ *Runtime) { f.wrongOwner = true }},
		{"Pod Ready false", func(f *guardrailFixture, _ *Runtime) { f.unreadyPod = true }},
		{"source shadow mount", func(f *guardrailFixture, _ *Runtime) { f.shadowSource = true }},
		{"wrong endpoint protocol", func(f *guardrailFixture, _ *Runtime) { f.wrongProtocol = true }},
		{"source digest", func(_ *guardrailFixture, r *Runtime) { r.Guardrail.ExpectedSourceSHA256 = strings.Repeat("0", 64) }},
		{"read permission", func(f *guardrailFixture, _ *Runtime) { f.denyService = true }},
		{"Pod drift", func(f *guardrailFixture, _ *Runtime) { f.drift = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &guardrailFixture{}
			runtime, recorder, closeServer := fixture.setup(t)
			defer closeServer()
			tc.set(fixture, &runtime)
			result := NewGuardrailCalibrationHandler().Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
			if result.Outcome != OutcomeInconclusive || result.Cleanup.Verified || len(fixture.classifyTexts) != 0 || fixture.mutatingCalls != 0 || len(recorder.intents) != 0 {
				t.Fatalf("authority failure permitted classifier request: %+v texts=%v mutations=%d", result, fixture.classifyTexts, fixture.mutatingCalls)
			}
		})
	}
}

func TestGuardrailCalibrationMalformedScoreStopsWithoutSecondDispatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture *guardrailFixture
	}{
		{"malformed score", &guardrailFixture{malformedScore: true}},
		{"oversize response", &guardrailFixture{oversizeBody: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := tc.fixture
			runtime, recorder, closeServer := fixture.setup(t)
			defer closeServer()
			result := NewGuardrailCalibrationHandler().Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
			if result.Outcome != OutcomeInconclusive || result.Evidence["classifierRequests"] != "1" || len(fixture.classifyTexts) != 1 || len(recorder.intents) != 1 || len(recorder.events) != 0 || fixture.mutatingCalls != 0 {
				t.Fatalf("unsupported response did not stop after one dispatch: %+v texts=%v", result, fixture.classifyTexts)
			}
		})
	}
}

func TestGuardrailCalibrationReconcileNeverReplays(t *testing.T) {
	cleanup := NewGuardrailCalibrationHandler().Reconcile(context.Background(), JobContext{}, Journal{Records: []JournalRecord{{Intent: &Intent{Step: "classify-sayOK", Mutation: false, At: time.Now()}}}})
	if !cleanup.Verified || cleanup.Details["classifierReplay"] != "none" {
		t.Fatalf("read-only reconcile differs: %+v", cleanup)
	}
}

func TestGuardrailCalibrationScoreParserRejectsUnsupportedValues(t *testing.T) {
	for _, raw := range []string{
		`{"pgv1":null,"pgv2":0.1}`,
		`{"pgv1":0.1}`,
		`{"pgv1":0.1,"pgv1":0.2,"pgv2":0.3}`,
		`{"pgv1":NaN,"pgv2":0.1}`,
		`{"pgv1":1.1,"pgv2":0.1}`,
		`{"pgv1":0.1,"pgv2":0.2} {}`,
		`{"pgv1":"0.1","pgv2":0.2}`,
	} {
		if scores, err := parseGuardrailScores([]byte(raw)); err == nil {
			t.Fatalf("accepted %q as %v", raw, scores)
		}
	}
}

func TestGuardrailCalibrationStateParserRejectsAmbiguousJSON(t *testing.T) {
	valid := `{"ready":true,"active":"pgv2","loaded":["pgv1","pgv2"],"thresholds":{"pgv1":0.5,"pgv2":0.5}}`
	if _, err := parseGuardrailState([]byte(valid), "pgv2"); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	for _, raw := range []string{
		`{"ready":true,"ready":false,"active":"pgv2","loaded":["pgv1","pgv2"],"thresholds":{"pgv1":0.5,"pgv2":0.5}}`,
		`{"ready":true,"active":"pgv1","active":"pgv2","loaded":["pgv1","pgv2"],"thresholds":{"pgv1":0.5,"pgv2":0.5}}`,
		`{"ready":true,"active":"pgv2","loaded":["pgv1","pgv2"],"thresholds":{"pgv1":0.5,"pgv1":0.9,"pgv2":0.5}}`,
		`{"ready":true,"active":"pgv2","loaded":["pgv1","pgv2"],"thresholds":{"pgv1":0.5,"pgv2":0.5}} {}`,
	} {
		if state, err := parseGuardrailState([]byte(raw), "pgv2"); err == nil {
			t.Fatalf("ambiguous state accepted: %+v", state)
		}
	}
}

// These exact JSON bytes are emitted by tools/guardrail_state_fixture.py from
// the checked-in Python GuardrailRuntime.public_state with classifier doubles.
func guardrailProducerFixture(t *testing.T, mode string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/guardrail_state_" + mode + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func editGuardrailState(t *testing.T, raw []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	edit(state)
	changed, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestGuardrailCalibrationActualProducerStateAndHandler(t *testing.T) {
	for _, mode := range []string{"enforce", "observe"} {
		t.Run(mode, func(t *testing.T) {
			raw := guardrailProducerFixture(t, mode)
			state, err := parseGuardrailState(raw, "pgv2")
			if err != nil || state.Shape != "current" || state.Mode != mode ||
				state.Models["pgv1"].Model != guardrailModelPGV1 || state.Models["pgv2"].Model != guardrailModelPGV2 ||
				state.Models["pgv1"].Revision != "unknown" || state.Models["pgv2"].Revision != "fixture-revision-2" ||
				state.Runtime.Python == "" || len(state.Runtime.Packages) != 5 {
				t.Fatalf("actual producer state rejected or misread: %+v err=%v", state, err)
			}
			if mode == "enforce" && (state.Thresholds["pgv1"] != 0 || state.Thresholds["pgv2"] != 1) {
				t.Fatalf("producer's zero/one threshold boundaries differ: %+v", state.Thresholds)
			}
			fixture := &guardrailFixture{stateRaw: raw}
			runtime, recorder, closeServer := fixture.setup(t)
			defer closeServer()
			result := NewGuardrailCalibrationHandler().Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
			if result.Outcome != OutcomeFunctionalPass || !result.Cleanup.Verified || fixture.proxyState != 2 || len(fixture.classifyTexts) != 2 || len(recorder.events) != 2 {
				t.Fatalf("actual producer response failed real handler: %+v", result)
			}
			e := result.Evidence
			if e["stateShape"] != "current" || e["declaredMode"] != mode || e["declaredProvenance"] != "PROXY_RESPONSE_NOT_ATTESTED" ||
				e["pgv1DeclaredModel"] != guardrailModelPGV1 || e["pgv2DeclaredRevision"] != "fixture-revision-2" ||
				e["declaredPythonVersion"] != state.Runtime.Python || e["declaredPackageVersion.fastapi"] != state.Runtime.Packages["fastapi"] ||
				e["loadedSource"] != "NOT_ATTESTED" || e["modelRevision"] != "NOT_ATTESTED" ||
				e["classifierOnly"] != "true" || e["servingOutcome"] != "NOT_MEASURED" || e["securityEfficacy"] != "NOT_EVALUATED" {
				t.Fatalf("declared provenance or classifier-only limit differs: %+v", e)
			}
		})
	}
}

func TestGuardrailCalibrationCurrentStateClosedMetadataAndThresholds(t *testing.T) {
	base := guardrailProducerFixture(t, "enforce")
	tests := []struct {
		name string
		edit func(map[string]any)
	}{
		{"missing mode", func(s map[string]any) { delete(s, "mode") }},
		{"missing models", func(s map[string]any) { delete(s, "models") }},
		{"missing runtime", func(s map[string]any) { delete(s, "runtime") }},
		{"unknown top field", func(s map[string]any) { s["extra"] = "x" }},
		{"load error", func(s map[string]any) { s["load_error"] = "unavailable" }},
		{"unready", func(s map[string]any) { s["ready"] = false }},
		{"null ready", func(s map[string]any) { s["ready"] = nil }},
		{"unknown active", func(s map[string]any) { s["active"] = "pgv3" }},
		{"bad roster", func(s map[string]any) { s["loaded"] = []string{"pgv1", "pgv1"} }},
		{"unknown mode", func(s map[string]any) { s["mode"] = "audit" }},
		{"null mode", func(s map[string]any) { s["mode"] = nil }},
		{"missing model", func(s map[string]any) { delete(s["models"].(map[string]any), "pgv1") }},
		{"wrong model name", func(s map[string]any) { s["models"].(map[string]any)["pgv1"].(map[string]any)["model"] = "other/model" }},
		{"null model revision", func(s map[string]any) { s["models"].(map[string]any)["pgv2"].(map[string]any)["revision"] = nil }},
		{"extra model field", func(s map[string]any) { s["models"].(map[string]any)["pgv1"].(map[string]any)["loaded"] = true }},
		{"missing python", func(s map[string]any) { delete(s["runtime"].(map[string]any), "python") }},
		{"null python", func(s map[string]any) { s["runtime"].(map[string]any)["python"] = nil }},
		{"missing package", func(s map[string]any) { delete(s["runtime"].(map[string]any)["packages"].(map[string]any), "torch") }},
		{"null package version", func(s map[string]any) { s["runtime"].(map[string]any)["packages"].(map[string]any)["torch"] = nil }},
		{"extra package", func(s map[string]any) { s["runtime"].(map[string]any)["packages"].(map[string]any)["numpy"] = "1" }},
		{"null zero threshold", func(s map[string]any) { s["thresholds"].(map[string]any)["pgv1"] = nil }},
		{"bool zero threshold", func(s map[string]any) { s["thresholds"].(map[string]any)["pgv1"] = false }},
		{"negative threshold", func(s map[string]any) { s["thresholds"].(map[string]any)["pgv1"] = -0.1 }},
		{"above one threshold", func(s map[string]any) { s["thresholds"].(map[string]any)["pgv2"] = 1.1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if state, err := parseGuardrailState(editGuardrailState(t, base, tc.edit), "pgv2"); err == nil {
				t.Fatalf("unsupported current state accepted: %+v", state)
			}
		})
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"duplicate models key", `"models":{"pgv1":`, `"models":{"pgv1":null,"pgv1":`},
		{"duplicate revision", `"revision":"unknown"`, `"revision":"unknown","revision":"other"`},
		{"duplicate runtime key", `"runtime":{"packages":`, `"runtime":{"packages":{},"packages":`},
		{"duplicate package", `"fastapi":`, `"fastapi":"other","fastapi":`},
		{"nonfinite threshold", `"pgv2":1.0`, `"pgv2":NaN`},
		{"overflow threshold", `"pgv2":1.0`, `"pgv2":1e999`},
		{"trailing JSON", "}\n", `} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(string(base), tc.old) {
				t.Fatalf("producer fixture no longer contains %q", tc.old)
			}
			raw := []byte(strings.Replace(string(base), tc.old, tc.replacement, 1))
			if state, err := parseGuardrailState(raw, "pgv2"); err == nil {
				t.Fatalf("ambiguous current state accepted: %+v", state)
			}
		})
	}
}

func TestGuardrailCalibrationDeclaredStateDriftStopsResult(t *testing.T) {
	base := guardrailProducerFixture(t, "enforce")
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"mode", func(s map[string]any) { s["mode"] = "observe" }},
		{"model revision", func(s map[string]any) { s["models"].(map[string]any)["pgv2"].(map[string]any)["revision"] = "changed" }},
		{"runtime version", func(s map[string]any) {
			s["runtime"].(map[string]any)["packages"].(map[string]any)["fastapi"] = "changed"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &guardrailFixture{stateRaw: base, stateAfterRaw: editGuardrailState(t, base, tc.edit)}
			runtime, recorder, closeServer := fixture.setup(t)
			defer closeServer()
			result := NewGuardrailCalibrationHandler().Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
			if result.Outcome != OutcomeInconclusive || result.Cleanup.Verified || result.Summary != "guardrail runtime state changed during calibration" ||
				fixture.proxyState != 2 || len(fixture.classifyTexts) != 2 || len(recorder.events) != 2 || fixture.mutatingCalls != 0 {
				t.Fatalf("metadata drift completed calibration: %+v", result)
			}
		})
	}
}
