package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

type liteRecorder struct {
	intents []Intent
	events  []Event
}

func (r *liteRecorder) Intent(v Intent) error         { r.intents = append(r.intents, v); return nil }
func (r *liteRecorder) Event(v Event) error           { r.events = append(r.events, v); return nil }
func (*liteRecorder) Metric(Metric) error             { return nil }
func (*liteRecorder) MetricRaw(json.RawMessage) error { return nil }
func (*liteRecorder) Result(Result) error             { return nil }

type liteFixtureTransport struct {
	liteKubeTransport
	fixtureConfigSHA string
	port             string
	pinFail          bool
	override         func(litePod, string, string, liteResponse) liteResponse
	afterGet         func(litePod)
}

const liteSyntheticMaster = "sk-local-master-never-retain"

func (t *liteFixtureTransport) snapshot(ctx context.Context, c LiteLLMRuntime) (liteAuthority, error) {
	c.ExpectedConfigSHA256 = t.fixtureConfigSHA
	return t.liteKubeTransport.snapshot(ctx, c)
}
func (t *liteFixtureTransport) sourcePin(_ context.Context, _ LiteLLMRuntime, _ litePod) error {
	if t.pinFail {
		return context.DeadlineExceeded
	}
	return nil
}
func (t *liteFixtureTransport) get(ctx context.Context, _ LiteLLMRuntime, p litePod, path, mode string) (liteResponse, error) {
	if (path != liteHealthPath && path != liteAuthPath) || (mode != "health" && mode != "master" && mode != "missing" && mode != "invalid") || (mode == "health") != (path == liteHealthPath) {
		return liteResponse{}, errors.New("unsupported fixed route")
	}
	command := exec.CommandContext(ctx, "python3", "-c", liteProbeScript, path, mode, t.port)
	command.Env = append(os.Environ(), "LITELLM_MASTER_KEY="+liteSyntheticMaster)
	raw, e := command.Output()
	if e != nil {
		return liteResponse{}, e
	}
	var response liteResponse
	if e = json.Unmarshal(raw, &response); e != nil {
		return liteResponse{}, e
	}
	if response.BoundExceeded {
		return liteResponse{}, errors.New("body bound")
	}
	if t.override != nil {
		response = t.override(p, path, mode, response)
	}
	if t.afterGet != nil {
		t.afterGet(p)
	}
	return response, nil
}

func liteFixture(t *testing.T) (Runtime, *liteFixtureTransport, *liteRecorder, *httptest.Server) {
	return liteFixtureWithAuth(t, nil)
}

func liteFixtureWithAuth(t *testing.T, masterReply func(http.ResponseWriter, *http.Request)) (Runtime, *liteFixtureTransport, *liteRecorder, *httptest.Server) {
	return liteFixtureWithAuthReplies(t, masterReply, nil)
}

func liteFixtureWithAuthReplies(t *testing.T, masterReply, invalidReply func(http.ResponseWriter, *http.Request)) (Runtime, *liteFixtureTransport, *liteRecorder, *httptest.Server) {
	t.Helper()
	yes, no := true, false
	two := int32(2)
	port := int32(4000)
	config := "synthetic fixture config"
	sum := sha256.Sum256([]byte(config))
	cfg := LiteLLMRuntime{Enabled: true, Namespace: "litellm", Deployment: "litellm", Service: "litellm", Container: "litellm", Port: port, ConfigMap: "litellm-config", ConfigKey: "config.yaml", ExpectedConfigSHA256: liteConfigSHA}
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "litellm", Namespace: "litellm", UID: types.UID("deploy"), ResourceVersion: "1", Generation: 4}, Spec: appsv1.DeploymentSpec{Replicas: &two, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "litellm"}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 4, ReadyReplicas: 2}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "litellm-rs", Namespace: "litellm", UID: types.UID("rs"), OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "litellm", UID: d.UID, Controller: &yes}}}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "litellm", Namespace: "litellm", UID: types.UID("service"), ResourceVersion: "2"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "litellm"}, Ports: []corev1.ServicePort{{Port: port, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(port)}}}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "litellm-config", Namespace: "litellm", UID: types.UID("config"), ResourceVersion: "3"}, Data: map[string]string{"config.yaml": config}}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "litellm-slice", Namespace: "litellm", UID: types.UID("slice"), ResourceVersion: "4", Labels: map[string]string{discoveryv1.LabelServiceName: "litellm"}, OwnerReferences: []metav1.OwnerReference{{Kind: "Service", Name: "litellm", UID: svc.UID, Controller: &yes}}}, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: ptrProtocol(corev1.ProtocolTCP)}}}
	p1 := liteFixturePod("litellm-rs-a", "pod-a", "10.1.0.1", liteSources[0].image, rs.UID, yes)
	p2 := liteFixturePod("litellm-rs-b", "pod-b", "10.1.0.2", liteSources[1].image, rs.UID, yes)
	for _, p := range []*corev1.Pod{p1, p2} {
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{p.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes, Terminating: &no}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: p.Name, Namespace: p.Namespace, UID: p.UID}})
	}
	client := fake.NewSimpleClientset(d, rs, svc, cm, slice, p1, p2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected HTTP request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, liteHealthPath) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`"I'm alive!"`))
			return
		}
		if strings.HasSuffix(r.URL.Path, liteAuthPath) {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer "+liteSyntheticMaster {
				if masterReply != nil {
					masterReply(w, r)
					return
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"reviewed-model"}]}`))
				return
			}
			if auth == "" {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"error":"missing bearer"}`))
				return
			}
			if !strings.HasPrefix(auth, "Bearer sk-catalogue-") {
				t.Errorf("unexpected bearer shape")
			}
			if invalidReply != nil {
				invalidReply(w, r)
				return
			}
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"message":"No connected db."}}`))
			return
		}
		t.Errorf("unexpected route %s", r.URL.Path)
		w.WriteHeader(404)
	}))
	runtime := Runtime{LiteLLM: cfg, Kube: client, RESTConfig: &rest.Config{Host: server.URL}}
	parsed, e := url.Parse(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	transport := &liteFixtureTransport{liteKubeTransport: liteKubeTransport{runtime: runtime}, fixtureConfigSHA: hex.EncodeToString(sum[:]), port: parsed.Port()}
	return runtime, transport, &liteRecorder{}, server
}

func liteFixturePod(name, uid, ip, image string, rsUID types.UID, yes bool) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "litellm", UID: types.UID(uid), ResourceVersion: "5", Labels: map[string]string{"app": "litellm"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "litellm-rs", UID: rsUID, Controller: &yes}}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "litellm", Args: []string{"--config", "/etc/litellm/config.yaml", "--port", "4000"}, Env: []corev1.EnvVar{{Name: "LITELLM_MASTER_KEY", Value: liteSyntheticMaster}}, Ports: []corev1.ContainerPort{{ContainerPort: 4000, Protocol: corev1.ProtocolTCP}}, VolumeMounts: []corev1.VolumeMount{{Name: "cfg", MountPath: "/etc/litellm"}}}}, Volumes: []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "litellm-config"}}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "litellm", Ready: true, ImageID: image, ContainerID: "containerd://" + uid}}}}
}

func TestLiteLLMKubernetesAuthorityBindsEachMixedPod(t *testing.T) {
	runtime, transport, _, server := liteFixture(t)
	defer server.Close()
	a, e := transport.snapshot(context.Background(), runtime.LiteLLM)
	if e != nil {
		t.Fatal(e)
	}
	if len(a.Pods) != 2 || a.Pods[0].ImageID == a.Pods[1].ImageID || a.ConfigUID != "config" {
		t.Fatalf("mixed Pod authority lost: %+v", a)
	}
	client := runtime.Kube
	p, e := client.CoreV1().Pods("litellm").Get(context.Background(), a.Pods[0].Name, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	p.Status.ContainerStatuses[0].ImageID = "unexpected-image"
	if _, e = client.CoreV1().Pods("litellm").Update(context.Background(), p, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = transport.snapshot(context.Background(), runtime.LiteLLM); e == nil {
		t.Fatal("unknown installed image admitted")
	}
}

func TestLiteLLMKubernetesAuthorityRejectsWrongEndpointAndConfig(t *testing.T) {
	runtime, transport, _, server := liteFixture(t)
	defer server.Close()
	sl, e := runtime.Kube.DiscoveryV1().EndpointSlices("litellm").Get(context.Background(), "litellm-slice", metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	sl.Endpoints[0].TargetRef.UID = types.UID("other-pod")
	if _, e = runtime.Kube.DiscoveryV1().EndpointSlices("litellm").Update(context.Background(), sl, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = transport.snapshot(context.Background(), runtime.LiteLLM); e == nil {
		t.Fatal("wrong endpoint target admitted")
	}
	sl.Endpoints[0].TargetRef.UID = types.UID("pod-a")
	if _, e = runtime.Kube.DiscoveryV1().EndpointSlices("litellm").Update(context.Background(), sl, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	cm, e := runtime.Kube.CoreV1().ConfigMaps("litellm").Get(context.Background(), "litellm-config", metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	cm.Data["config.yaml"] = "changed configuration"
	if _, e = runtime.Kube.CoreV1().ConfigMaps("litellm").Update(context.Background(), cm, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = transport.snapshot(context.Background(), runtime.LiteLLM); e == nil {
		t.Fatal("changed config admitted")
	}
}

func TestLiteLLMExactPodHTTPAndConfigurationLimitedAuth(t *testing.T) {
	runtime, transport, recorder, server := liteFixture(t)
	defer server.Close()
	if ValidateLiteLLMRuntime(runtime.LiteLLM) != nil {
		t.Fatal("reviewed runtime rejected")
	}
	h := liteHandler{profile: LiteLLMCredential, transport: transport}
	result := h.Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["authBoundaryState"] != "UNKNOWN_CONFIGURATION_LIMITED" || result.Evidence["masterPathState"] != "AVAILABLE" || result.Evidence["nonmasterPathState"] != "DB_FEATURE_UNAVAILABLE" || result.Evidence["requestCount"] != "8" || len(recorder.intents) != 8 || len(recorder.events) != 8 {
		t.Fatalf("configuration-limited outcome was misclassified: %+v, intents=%d, events=%d", result, len(recorder.intents), len(recorder.events))
	}
	if result.Evidence["pod1.version"] == result.Evidence["pod2.version"] {
		t.Fatal("mixed versions collapsed")
	}
	if result.Evidence["pod1.masterBearer.status"] != "200" || result.Evidence["pod2.masterBearer.status"] != "200" || result.Evidence["pod1.masterBearer.listShape"] != "true" || result.Evidence["pod2.masterBearer.listShape"] != "true" {
		t.Fatalf("per-Pod master positive was not independently observed: %+v", result.Evidence)
	}
	if e := ValidateResult(liteJobForTest(t, runtime, LiteLLMCredential), normalizeResult(liteJobForTest(t, runtime, LiteLLMCredential), h.Definition(), result, result.StartedAt)); e != nil {
		t.Fatalf("shared result consumer rejected control: %v", e)
	}
}

func TestLiteLLMMasterMalformedAndDeniedStayInconclusive(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"malformed-list", `{"object":"error","data":[]}`, 200},
		{"denied-master", `{"error":"rejected"}`, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, transport, recorder, server := liteFixtureWithAuth(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			defer server.Close()
			result := (liteHandler{profile: LiteLLMCredential, transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
			if result.Outcome != OutcomeInconclusive || result.Evidence["masterPathState"] != "UNVERIFIED" || result.Evidence["authBoundaryState"] == "NEGATIVE_GET_REFUSAL_ONLY" {
				t.Fatalf("bad master positive was credited: %+v", result)
			}
		})
	}
}

func TestLiteLLMNegativeAcceptanceIsNotMaskedByMasterFailure(t *testing.T) {
	masterRequests, invalidRequests := 0, 0
	runtime, transport, _, server := liteFixtureWithAuthReplies(t,
		func(w http.ResponseWriter, _ *http.Request) {
			masterRequests++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"master path unavailable"}`))
		},
		func(w http.ResponseWriter, _ *http.Request) {
			invalidRequests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
		})
	defer server.Close()
	runtime.StateDir = t.TempDir()
	runtime.ConfigSHA256 = strings.Repeat("b", 64)
	runner, err := New(runtime, liteHandler{profile: LiteLLMCredential, transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	job := liteJobForTest(t, runtime, LiteLLMCredential)
	result := runner.Execute(context.Background(), job)
	if masterRequests != 2 || invalidRequests != 2 || result.Outcome != OutcomeFunctionalFail || result.Evidence["masterPathState"] != "UNVERIFIED" || result.Evidence["authBoundaryState"] != "NEGATIVE_GET_ACCEPTED" || result.Evidence["pod1.invalidBearer.status"] != "200" || result.Evidence["pod2.invalidBearer.status"] != "200" {
		t.Fatalf("observed negative acceptance was masked: master=%d invalid=%d result=%+v", masterRequests, invalidRequests, result)
	}
	if err = ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err != nil {
		t.Fatal(err)
	}
}

func TestLiteLLMMasterSecretEchoIsNeverRetained(t *testing.T) {
	runtime, transport, _, server := liteFixtureWithAuth(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"` + liteSyntheticMaster + `"}]}`))
	})
	defer server.Close()
	runtime.StateDir = t.TempDir()
	runtime.ConfigSHA256 = strings.Repeat("b", 64)
	runner, err := New(runtime, liteHandler{profile: LiteLLMCredential, transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	job := liteJobForTest(t, runtime, LiteLLMCredential)
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeInconclusive || result.Evidence["masterPathState"] != "AVAILABLE" || result.Evidence["authBoundaryState"] != "UNKNOWN_CONFIGURATION_LIMITED" || result.Evidence["requestCount"] != "8" {
		t.Fatalf("master positive and DB-limited negative not preserved: %+v", result)
	}
	if err = ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"result.json", "journal.jsonl", "metrics.jsonl"} {
		body, err := os.ReadFile(filepath.Join(job.OutputDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), liteSyntheticMaster) {
			t.Fatalf("master secret appeared in persisted %s", name)
		}
	}
}

func TestLiteLLMMasterPostRequestDriftCannotEarnPositive(t *testing.T) {
	runtime, transport, recorder, server := liteFixture(t)
	defer server.Close()
	requests := 0
	transport.afterGet = func(p litePod) {
		requests++
		if requests != 2 { // health, then master bearer on the first exact Pod
			return
		}
		pod, err := runtime.Kube.CoreV1().Pods("litellm").Get(context.Background(), p.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pod.ResourceVersion = "changed-after-master"
		if _, err = runtime.Kube.CoreV1().Pods("litellm").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	result := (liteHandler{profile: LiteLLMCredential, transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "2" || result.Evidence["masterPathState"] == "AVAILABLE" || !strings.Contains(result.Summary, "changed after GET") {
		t.Fatalf("master response crossed changed authority: %+v", result)
	}
}

func TestLiteLLMHealthPositiveControl(t *testing.T) {
	runtime, transport, recorder, server := liteFixture(t)
	defer server.Close()
	result := (liteHandler{profile: LiteLLMHealth, transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeFunctionalPass || result.Evidence["requestCount"] != "2" || len(recorder.events) != 2 {
		t.Fatalf("health positive control: %+v", result)
	}
	job := liteJobForTest(t, runtime, LiteLLMHealth)
	if e := ValidateResult(job, normalizeResult(job, (liteHandler{profile: LiteLLMHealth}).Definition(), result, result.StartedAt)); e != nil {
		t.Fatalf("shared result consumer rejected health: %v", e)
	}
}

func TestLiteLLMCredentialCannotMixPodOutcomes(t *testing.T) {
	runtime, transport, recorder, server := liteFixture(t)
	defer server.Close()
	transport.override = func(p litePod, _ string, mode string, r liteResponse) liteResponse {
		if p.UID == "pod-a" && mode == "invalid" {
			r.Status = 401
			r.Reason = "NOT_CLASSIFIED"
		}
		if p.UID == "pod-b" && mode == "missing" {
			r.Status = 200
			r.Reason = "NOT_CLASSIFIED"
		}
		return r
	}
	result := (liteHandler{profile: LiteLLMCredential, transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeFunctionalFail || result.Evidence["pod2.missingBearer.status"] != "200" || result.Evidence["pod1.invalidBearer.status"] != "401" {
		t.Fatalf("mixed Pod outcome incorrectly passed: %+v", result)
	}
}

func TestLiteLLMCredentialOnePodNoDBRemainsUnknown(t *testing.T) {
	runtime, transport, recorder, server := liteFixture(t)
	defer server.Close()
	transport.override = func(p litePod, _ string, mode string, r liteResponse) liteResponse {
		if p.UID == "pod-a" && mode == "invalid" {
			r.Status = 401
			r.Reason = "NOT_CLASSIFIED"
		}
		return r
	}
	result := (liteHandler{profile: LiteLLMCredential, transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["authBoundaryState"] != "UNKNOWN_CONFIGURATION_LIMITED" || result.Evidence["masterPathState"] != "AVAILABLE" || result.Evidence["pod2.invalidBearer.reason"] != "NO_CONNECTED_DB" {
		t.Fatalf("one Pod's no-DB branch incorrectly passed: %+v", result)
	}
}

func TestLiteLLMPostRequestPodDriftIsInconclusive(t *testing.T) {
	runtime, transport, recorder, server := liteFixture(t)
	defer server.Close()
	changed := false
	transport.afterGet = func(p litePod) {
		if changed {
			return
		}
		changed = true
		pod, e := runtime.Kube.CoreV1().Pods("litellm").Get(context.Background(), p.Name, metav1.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		pod.ResourceVersion = "changed"
		if _, e = runtime.Kube.CoreV1().Pods("litellm").Update(context.Background(), pod, metav1.UpdateOptions{}); e != nil {
			t.Fatal(e)
		}
	}
	result := (liteHandler{profile: LiteLLMHealth, transport: transport}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "1" || !strings.Contains(result.Summary, "changed after GET") {
		t.Fatalf("identity drift incorrectly passed: %+v", result)
	}
}

func liteJobForTest(t *testing.T, runtime Runtime, profile ProfileID) Job {
	t.Helper()
	def, e := DefinitionFor(profile)
	if e != nil {
		t.Fatal(e)
	}
	sum, e := DefinitionSHA256(def)
	if e != nil {
		t.Fatal(e)
	}
	root := runtime.StateDir
	if root == "" {
		root = t.TempDir()
	}
	dir := filepath.Join(root, "runs", "v1run-1")
	if e = os.MkdirAll(dir, 0750); e != nil {
		t.Fatal(e)
	}
	return Job{Version: JobVersion, RunID: "v1run-1", Profile: profile, OutputDir: dir, DefinitionSHA256: sum, OwnerDigest: strings.Repeat("a", 64), ResolvedTarget: "default", ResolvedTenant: "litellm", RuntimeConfigSHA256: strings.Repeat("b", 64), CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(time.Minute)}
}

func TestLiteLLMHTTPRefusesRedirectAndUnsupportedRoute(t *testing.T) {
	followed := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/other" {
			followed = true
			return
		}
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer s.Close()
	parsed, e := url.Parse(s.URL)
	if e != nil {
		t.Fatal(e)
	}
	transport := &liteFixtureTransport{port: parsed.Port()}
	c := LiteLLMRuntime{Namespace: "litellm", Port: 4000}
	p := litePod{Name: "litellm-rs-a"}
	response, e := transport.get(context.Background(), c, p, liteHealthPath, "health")
	if e != nil || response.Status != 302 || followed {
		t.Fatalf("redirect followed or not observed: %+v %v", response, e)
	}
	if _, e := transport.get(context.Background(), c, p, "/v1/chat/completions", "missing"); e == nil {
		t.Fatal("inference route admitted")
	}
}

func TestLiteLLMRunnerPersistsBoundedHealth(t *testing.T) {
	runtime, transport, _, server := liteFixture(t)
	defer server.Close()
	runtime.StateDir = t.TempDir()
	runtime.ConfigSHA256 = strings.Repeat("b", 64)
	h := liteHandler{profile: LiteLLMHealth, transport: transport}
	runner, e := New(runtime, h)
	if e != nil {
		t.Fatal(e)
	}
	job := liteJobForTest(t, runtime, LiteLLMHealth)
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeFunctionalPass {
		t.Fatalf("runner outcome %s: %s", result.Outcome, result.Summary)
	}
	if e = ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); e != nil {
		t.Fatal(e)
	}
	journal, e := os.ReadFile(filepath.Join(job.OutputDir, "journal.jsonl"))
	if e != nil || strings.Count(string(journal), "litellm.health") != 4 {
		t.Fatalf("journal missing exact-Pod intents and events: %v %s", e, journal)
	}
	if n, e := strconv.Atoi(result.Evidence["requestCount"]); e != nil || n != 2 {
		t.Fatalf("wrong request bound %q", result.Evidence["requestCount"])
	}
}

func TestLiteLLMRunnerPersistsConfigurationLimitedCredential(t *testing.T) {
	runtime, transport, _, server := liteFixture(t)
	defer server.Close()
	runtime.StateDir = t.TempDir()
	runtime.ConfigSHA256 = strings.Repeat("b", 64)
	h := liteHandler{profile: LiteLLMCredential, transport: transport}
	runner, e := New(runtime, h)
	if e != nil {
		t.Fatal(e)
	}
	job := liteJobForTest(t, runtime, LiteLLMCredential)
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeInconclusive || result.Evidence["authBoundaryState"] != "UNKNOWN_CONFIGURATION_LIMITED" || result.Evidence["masterPathState"] != "AVAILABLE" || result.Evidence["requestCount"] != "8" {
		t.Fatalf("runner auth outcome: %+v", result)
	}
	if e = ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); e != nil {
		t.Fatal(e)
	}
}

func TestLiteLLMDisabledAndUnreviewedConfigurationRejected(t *testing.T) {
	runtime, _, _, server := liteFixture(t)
	defer server.Close()
	runtime.LiteLLM.Enabled = false
	if e := NewLiteLLMHealthHandler().Validate(runtime); e == nil {
		t.Fatal("disabled control admitted")
	}
	runtime.LiteLLM.Enabled = true
	runtime.LiteLLM.ExpectedConfigSHA256 = strings.Repeat("0", 64)
	if e := NewLiteLLMCredentialHandler().Validate(runtime); e == nil {
		t.Fatal("unreviewed config admitted")
	}
}
