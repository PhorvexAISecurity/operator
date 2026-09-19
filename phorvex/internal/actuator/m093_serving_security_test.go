package actuator

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func legacyServingSecurityForTest(t testing.TB) *ServingSecurityConfig {
	t.Helper()
	c, err := LoadServingSecurityFile("", ServingSecurityLegacyPlaintext, "operator")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeServingSecurityConfig(t testing.TB, mode ServingSecurityMode, operatorNamespace string, bindings []ServingSecurityBinding) *ServingSecurityConfig {
	t.Helper()
	payload, err := json.Marshal(struct {
		Version  int                      `json:"version"`
		Bindings []ServingSecurityBinding `json:"bindings"`
	}{Version: servingSecurityVersion, Bindings: bindings})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "serving-security.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadServingSecurityFile(path, mode, operatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

type m093Fixture struct {
	server  *httptest.Server
	client  client.Client
	config  *ServingSecurityConfig
	policy  *v1alpha1.PhorvexPolicy
	pod     *corev1.Pod
	binding ServingSecurityBinding
	mu      sync.Mutex
	tokens  []string
}

func newM093Fixture(t *testing.T, handler http.Handler) *m093Fixture {
	t.Helper()
	f := &m093Fixture{}
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.tokens = append(f.tokens, r.Header.Get("Authorization"))
			f.mu.Unlock()
			if r.URL.Path == "/v1/models" {
				_, _ = w.Write([]byte(`{"data":[{"id":"base"}]}`))
				return
			}
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.URL.Path == "/drain" {
				_, _ = w.Write([]byte(`{"aborted":1}`))
				return
			}
			if r.URL.Path == defaultResetPath || r.URL.Path == "/reset" {
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	f.server = httptest.NewTLSServer(handler)
	t.Cleanup(f.server.Close)
	u, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cert := f.server.Certificate()
	serverName := host
	if len(cert.DNSNames) != 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) != 0 {
		serverName = cert.IPAddresses[0].String()
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	f.binding = ServingSecurityBinding{Namespace: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: "model-sa", ProfileID: "model-admin-v1", SecretName: "model-admin", BearerKey: "bearer", CAKey: "ca.crt", ServerName: serverName}
	f.policy = &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "policy", UID: types.UID("policy-uid"), ResourceVersion: "11"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "model"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionKVReset), v1alpha1.ActionType(model.ActionAdapterRotate), v1alpha1.ActionType(model.ActionRequestDrain), v1alpha1.ActionType(model.ActionWarmSwap), v1alpha1.ActionType(model.ActionModelShardReplace), v1alpha1.ActionType(model.ActionMIGRebind), v1alpha1.ActionType(model.ActionGuardrailRotate), v1alpha1.ActionType(model.ActionKVMigrateInvalidate)}}}}
	f.pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "model-0", UID: types.UID("pod-uid"), ResourceVersion: "12", Labels: map[string]string{"app": "model"}, Annotations: map[string]string{annoServingPort: strconv.Itoa(port), annoServingTok: "tenant-controlled-token"}}, Spec: corev1.PodSpec{ServiceAccountName: "model-sa", Containers: []corev1.Container{{Name: "model", Image: "model:test"}}}, Status: corev1.PodStatus{PodIP: host, Phase: corev1.PodRunning}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "model-admin", UID: types.UID("secret-uid"), ResourceVersion: "13"}, Data: map[string][]byte{"bearer": []byte("trusted-token-1"), "ca.crt": caPEM}}
	f.client = fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(f.policy, f.pod, secret,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("created-" + obj.GetName()))
			}
			return c.Create(ctx, obj, opts...)
		}}).Build()
	f.config = writeServingSecurityConfig(t, ServingSecuritySecureRequired, "operator", []ServingSecurityBinding{f.binding})
	return f
}

func (f *m093Fixture) request(action model.Action) Request {
	current := &corev1.Pod{}
	if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(f.pod), current); err != nil {
		panic(err)
	}
	req := boundReq(current, action)
	req.Tenant, req.PolicyName, req.PolicyUID = "tenant", f.policy.Name, string(f.policy.UID)
	req.TickID = fmt.Sprintf("m093-%d", time.Now().UnixNano())
	return req
}

func (f *m093Fixture) native(t *testing.T) *NativeActuator {
	t.Helper()
	n := NewNativeActuator(f.client)
	n.Reader = f.client
	n.JournalNamespace = "operator"
	n.SetServingSecurity(f.config)
	if err := n.EnsurePolicy(t.Context(), TenantTarget{Tenant: "tenant", Namespace: "tenant"}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestM093ConfigRequiresExplicitStrictVersionedDocument(t *testing.T) {
	validBinding := ServingSecurityBinding{Namespace: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: "model-sa", ProfileID: "profile", SecretName: "credentials", BearerKey: "bearer", CAKey: "ca.crt", ServerName: "model-admin.example"}
	for _, tc := range []struct {
		name, body string
	}{
		{"null", `null`},
		{"empty-object", `{}`},
		{"missing-version", `{"bindings":[]}`},
		{"unknown-field", `{"version":1,"bindings":[],"mode":"legacy-plaintext"}`},
		{"duplicate-version", `{"version":1,"version":1,"bindings":[]}`},
		{"case-fold-root-key", `{"version":1,"Version":1,"bindings":[]}`},
		{"null-bindings", `{"version":1,"bindings":null}`},
		{"case-fold-binding-key", `{"version":1,"bindings":[{"namespace":"tenant","policyName":"policy","policyUID":"policy-uid","serviceAccount":"model-sa","profileID":"model","secretName":"model-admin","SecretName":"replacement","bearerKey":"bearer","caKey":"ca.crt","serverName":"model.test"}]}`},
		{"trailing", `{"version":1,"bindings":[]} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadServingSecurityFile(path, ServingSecuritySecureRequired, "operator"); err == nil {
				t.Fatal("malformed explicit configuration was accepted")
			}
		})
	}
	payload, _ := json.Marshal(struct {
		Version  int                      `json:"version"`
		Bindings []ServingSecurityBinding `json:"bindings"`
	}{1, []ServingSecurityBinding{validBinding, validBinding}})
	path := filepath.Join(t.TempDir(), "duplicate.json")
	_ = os.WriteFile(path, payload, 0o600)
	if _, err := LoadServingSecurityFile(path, ServingSecuritySecureRequired, "operator"); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate exact binding accepted: %v", err)
	}
	legacyPayload, _ := json.Marshal(struct {
		Version  int                      `json:"version"`
		Bindings []ServingSecurityBinding `json:"bindings"`
	}{1, []ServingSecurityBinding{validBinding}})
	legacyPath := filepath.Join(t.TempDir(), "legacy-with-binding.json")
	_ = os.WriteFile(legacyPath, legacyPayload, 0o600)
	if _, err := LoadServingSecurityFile(legacyPath, ServingSecurityLegacyPlaintext, "operator"); err == nil {
		t.Fatal("legacy plaintext accepted an unused trusted credential binding")
	}
}

func TestM093NativeUsesFreshScopedSecretTLSAndIgnoresPodBearer(t *testing.T) {
	f := newM093Fixture(t, nil)
	n := f.native(t)
	for i, want := range []string{"trusted-token-1", "trusted-token-2"} {
		if i == 1 {
			secret := &corev1.Secret{}
			if err := f.client.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: "model-admin"}, secret); err != nil {
				t.Fatal(err)
			}
			secret.Data["bearer"] = []byte(want)
			if err := f.client.Update(t.Context(), secret); err != nil {
				t.Fatal(err)
			}
		}
		result, err := n.Actuate(t.Context(), f.request(model.ActionKVReset))
		if err != nil || !result.Emitted {
			t.Fatalf("secure dispatch %d: result=%+v err=%v", i, result, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got, want := strings.Join(f.tokens, ","), "Bearer trusted-token-1,Bearer trusted-token-2"; got != want {
		t.Fatalf("fresh exact Secret bearer not used: got %q want %q", got, want)
	}
	if strings.Contains(strings.Join(f.tokens, ","), "tenant-controlled-token") {
		t.Fatal("Pod annotation supplied authentication authority")
	}
}

func TestM093SecurePreparationRefusesScopeAndCredentialDriftBeforeHTTP(t *testing.T) {
	f := newM093Fixture(t, nil)
	cases := []struct {
		name   string
		mutate func(*v1alpha1.PhorvexPolicy, *corev1.Pod, *corev1.Secret, *ServingSecurityConfig)
	}{
		{"pod-uid", func(_ *v1alpha1.PhorvexPolicy, p *corev1.Pod, _ *corev1.Secret, _ *ServingSecurityConfig) {
			p.UID = "replacement"
		}},
		{"service-account", func(_ *v1alpha1.PhorvexPolicy, p *corev1.Pod, _ *corev1.Secret, _ *ServingSecurityConfig) {
			p.Spec.ServiceAccountName = "other"
		}},
		{"selector", func(_ *v1alpha1.PhorvexPolicy, p *corev1.Pod, _ *corev1.Secret, _ *ServingSecurityConfig) {
			p.Labels["app"] = "other"
		}},
		{"disabled-action", func(p *v1alpha1.PhorvexPolicy, _ *corev1.Pod, _ *corev1.Secret, _ *ServingSecurityConfig) {
			p.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionRotate}
		}},
		{"missing-secret", func(_ *v1alpha1.PhorvexPolicy, _ *corev1.Pod, s *corev1.Secret, _ *ServingSecurityConfig) {
			s.Name = "missing"
		}},
		{"wrong-server-name", func(_ *v1alpha1.PhorvexPolicy, _ *corev1.Pod, _ *corev1.Secret, c *ServingSecurityConfig) {
			c.Bindings[0].ServerName = "wrong.example"
			_ = c.validate()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol, pod, secret := f.policy.DeepCopy(), f.pod.DeepCopy(), &corev1.Secret{}
			if err := f.client.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: "model-admin"}, secret); err != nil {
				t.Fatal(err)
			}
			cfg := snapshotServingSecurity(f.config)
			tc.mutate(pol, pod, secret, cfg)
			objects := []client.Object{pol, pod}
			if secret.Name != "missing" {
				objects = append(objects, secret)
			}
			c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objects...).Build()
			candidate := NewNativeActuator(c)
			candidate.Reader = c
			candidate.SetServingSecurity(cfg)
			_ = candidate.EnsurePolicy(t.Context(), TenantTarget{Tenant: "tenant", Namespace: "tenant"})
			result, err := candidate.Actuate(t.Context(), f.request(model.ActionKVReset))
			if err == nil || result.Emitted {
				t.Fatalf("drift accepted: result=%+v err=%v", result, err)
			}
		})
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokens) != 0 {
		t.Fatalf("preparation refusal reached backend: %v", f.tokens)
	}
}

func TestM093TLSAndBackendErrorsDoNotLeakBearerOrRetryPlaintext(t *testing.T) {
	const token = "trusted-token-1"
	var requests int
	f := newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "backend echoed %s", token)
	}))
	result, err := f.native(t).Actuate(t.Context(), f.request(model.ActionKVReset))
	if err == nil || result.Emitted || requests != 1 {
		t.Fatalf("backend failure became success or retry: requests=%d result=%+v err=%v", requests, result, err)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(result.Note, token) {
		t.Fatalf("credential leaked through result: result=%+v err=%v", result, err)
	}

	wrong := snapshotServingSecurity(f.config)
	wrong.Bindings[0].ServerName = "wrong.example"
	if err := wrong.validate(); err != nil {
		t.Fatal(err)
	}
	n := f.native(t)
	n.SetServingSecurity(wrong)
	_, err = n.Actuate(t.Context(), f.request(model.ActionKVReset))
	if err == nil || requests != 1 {
		t.Fatalf("wrong TLS identity reached backend or downgraded: requests=%d err=%v", requests, err)
	}
}

func TestM093AllHTTPFamiliesUsePreparedEndpointClient(t *testing.T) {
	f := newM093Fixture(t, nil)
	snapshot, err := f.config.snapshotForBinding(t.Context(), f.client, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	ep := servingEndpoint{podIP: host, port: port, scheme: "https", client: snapshot.client, token: snapshot.token, resetPath: "/reset", healthPath: "/health", modelsPath: "/v1/models", unloadPath: "/unload", loadPath: "/load", drainPath: "/drain", guardPath: "/guard", kvInvPath: "/kv"}
	v := newHTTPVLLM()
	if err := v.ResetPrefixCache(t.Context(), ep); err != nil {
		t.Fatal(err)
	}
	if ready, err := v.ModelReady(t.Context(), ep); err != nil || !ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	if err := v.UnloadAdapter(t.Context(), ep, "adapter"); err != nil {
		t.Fatal(err)
	}
	if err := v.LoadAdapter(t.Context(), ep, "adapter", "/trusted/adapter"); err != nil {
		t.Fatal(err)
	}
	if aborted, err := v.DrainRequests(t.Context(), ep); err != nil || aborted != 1 {
		t.Fatalf("aborted=%d err=%v", aborted, err)
	}
	if err := (httpGuardrail{v: v}).ApplyVariant(t.Context(), ep, "strict"); err != nil {
		t.Fatal(err)
	}
	if err := (httpKVTransfer{v: v}).InvalidateLocal(t.Context(), ep); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokens) != 8 {
		t.Fatalf("authenticated requests=%d, want 8: %v", len(f.tokens), f.tokens)
	}
	for _, got := range f.tokens {
		if got != "Bearer trusted-token-1" {
			t.Fatalf("route escaped prepared credential client: %q", got)
		}
	}
}

func TestM093StableBindingDigestExcludesSecretAndEndpoint(t *testing.T) {
	f := newM093Fixture(t, nil)
	before := servingBindingDigest("operator", f.binding)
	secret := &corev1.Secret{}
	if err := f.client.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: f.binding.SecretName}, secret); err != nil {
		t.Fatal(err)
	}
	secret.UID, secret.ResourceVersion, secret.Data[f.binding.BearerKey] = "replacement-secret", "99", []byte("rotated-token")
	f.pod.Status.PodIP = "192.0.2.10"
	if after := servingBindingDigest("operator", f.binding); after != before {
		t.Fatalf("credential bytes or endpoint entered stable binding digest: %s != %s", after, before)
	}
	changed := f.binding
	changed.ServerName = "different.example"
	if servingBindingDigest("operator", changed) == before {
		t.Fatal("trusted server identity change did not change binding digest")
	}
	if _, err := x509.ParseCertificate(f.server.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
}

func TestM093ReceiptEndpointDigestPreservesLegacyAndExcludesSecureBearer(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "model"})
	const oldAdapterDigest = "765a2d1c8f42e2313aa858b6b809060099d9137013173d7660f023e44d62aae9"
	const oldDrainDigest = "a659f77284b164f3c8b8c4b4752c6c445a568390fe99135e502d9383e2fc7b2c"
	if got := adapterReceiptEndpointConfigDigest(pod, adapterRotateReceiptVersion); got != oldAdapterDigest {
		t.Fatalf("predecessor v4 adapter digest changed: %s", got)
	}
	if got := drainReceiptEndpointConfigDigest(pod, requestDrainReceiptVersion); got != oldDrainDigest {
		t.Fatalf("predecessor v3 drain digest changed: %s", got)
	}
	secureAdapter := adapterReceiptEndpointConfigDigest(pod, adapterRotateSecureReceiptVersion)
	secureDrain := drainReceiptEndpointConfigDigest(pod, requestDrainSecureReceiptVersion)
	pod.Annotations[annoServingTok] = "rotated-tenant-annotation"
	if adapterReceiptEndpointConfigDigest(pod, adapterRotateSecureReceiptVersion) != secureAdapter || drainReceiptEndpointConfigDigest(pod, requestDrainSecureReceiptVersion) != secureDrain {
		t.Fatal("secure receipt endpoint identity depended on bearer material")
	}
	if adapterReceiptEndpointConfigDigest(pod, adapterRotateReceiptVersion) == oldAdapterDigest || drainReceiptEndpointConfigDigest(pod, requestDrainReceiptVersion) == oldDrainDigest {
		t.Fatal("legacy digest fixture did not exercise predecessor bearer hashing")
	}
}

func TestM093NilSecurityInjectionIsPerServingFamily(t *testing.T) {
	request := func(action model.Action) Request {
		return Request{Action: action, Namespace: "tenant", Pod: "model-0", TargetUID: "pod-uid"}
	}
	for _, tc := range []struct {
		name   string
		action model.Action
		ec     EnactCtx
		want   bool
	}{
		{"vllm-own-family", model.ActionKVReset, EnactCtx{VLLM: &mockVLLM{}}, true},
		{"vllm-cannot-bypass-guardrail", model.ActionGuardrailRotate, EnactCtx{VLLM: &mockVLLM{}}, false},
		{"guardrail-own-family", model.ActionGuardrailRotate, EnactCtx{Guardrail: &recordingGuardrail{}}, true},
		{"guardrail-cannot-bypass-kv-transfer", model.ActionKVMigrateInvalidate, EnactCtx{Guardrail: &recordingGuardrail{}}, false},
		{"kv-transfer-own-family", model.ActionKVMigrateInvalidate, EnactCtx{KVXfer: &mockKVXfer{}}, true},
		{"mig-serving-family", model.ActionMIGRebind, EnactCtx{MIG: &mockMIG{}, VLLM: &mockVLLM{}}, true},
		{"mig-driver-cannot-bypass-serving-family", model.ActionMIGRebind, EnactCtx{MIG: &mockMIG{}}, false},
		{"mig-cannot-bypass-vllm", model.ActionKVReset, EnactCtx{MIG: &mockMIG{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := prepareServingAttempt(t.Context(), &tc.ec, request(tc.action))
			if (err == nil) != tc.want {
				t.Fatalf("prepared=%v err=%v, want prepared=%v", err == nil, err, tc.want)
			}
		})
	}
}

func TestM093EveryParticipantRequiresSamePolicyScopeAndProfile(t *testing.T) {
	f := newM093Fixture(t, nil)
	_, snapshot, err := f.config.prepare(t.Context(), f.client, f.request(model.ActionWarmSwap), string(f.pod.UID))
	if err != nil {
		t.Fatal(err)
	}
	base := f.pod.DeepCopy()
	base.Name, base.UID, base.ResourceVersion = "shadow", "shadow-uid", "21"
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod)
	}{
		{"service-account", func(p *corev1.Pod) { p.Spec.ServiceAccountName = "borrowed-sa" }},
		{"selector", func(p *corev1.Pod) { p.Labels["app"] = "other" }},
		{"declaration", func(p *corev1.Pod) { p.Annotations = nil }},
		{"namespace", func(p *corev1.Pod) { p.Namespace = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			participant := base.DeepCopy()
			tc.mutate(participant)
			objects := []client.Object{f.policy.DeepCopy(), f.pod.DeepCopy(), participant}
			secret := &corev1.Secret{}
			if err := f.client.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: f.binding.SecretName}, secret); err != nil {
				t.Fatal(err)
			}
			objects = append(objects, secret)
			reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objects...).Build()
			ec := EnactCtx{Reader: reader, ServingSecurity: f.config, ServingAttempt: snapshot}
			if _, err := servingEndpointForPod(t.Context(), ec, f.request(model.ActionWarmSwap), participant); err == nil {
				t.Fatal("participant borrowed the trigger credential profile")
			}
		})
	}
}

func TestM093SecureReceiptNeverDowngradesOrMutatesInLegacyRecovery(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "standby")
	r := testDrainReceipt(pod, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "infer", Namespace: "ns", UID: "uid-service"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "infer", labelServing: "standby"}}}, "stopped")
	// Use the actual Service identity and secure endpoint identity held by the fixture.
	service := &corev1.Service{}
	if err := controller.Get(t.Context(), client.ObjectKey{Namespace: "ns", Name: "infer"}, service); err != nil {
		t.Fatal(err)
	}
	r.ServiceUID, r.ServiceSelector = string(service.UID), copyLabels(service.Spec.Selector)
	r.Version = requestDrainSecureReceiptVersion
	r.EndpointConfigSHA256 = secureDrainEndpointConfigDigest(pod)
	r.ServingBindingSHA256 = strings.Repeat("a", 64)
	r.ServingServiceAccount = "default"
	if !r.valid() {
		t.Fatal("invalid secure request-drain fixture")
	}
	ec := requestDrainEC(controller, nil)
	if _, err := journalWrite(t.Context(), ec, r); err != nil {
		t.Fatal(err)
	}
	current := &corev1.Pod{}
	if err := controller.Get(t.Context(), client.ObjectKeyFromObject(pod), current); err != nil {
		t.Fatal(err)
	}
	current.Labels[labelServing], current.Labels[labelDrainEpoch] = "drained", r.OperationToken
	if err := controller.Update(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	legacy := legacyServingSecurityForTest(t)
	native := NewNativeActuator(controller)
	native.Reader, native.JournalNamespace, native.RecoveryVLLM = controller, "operator", &mockVLLM{drained: 1}
	native.SetServingSecurity(legacy)
	events, err := native.RecoverOperations(t.Context(), false)
	if err != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Err.Error(), "cannot be resumed") {
		t.Fatalf("secure receipt downgrade recovery=%+v err=%v", events, err)
	}
	if got := getDrainPod(t, controller); got.Labels[labelServing] != "drained" || got.Labels[labelDrainEpoch] != r.OperationToken {
		t.Fatalf("mode downgrade mutated protected Pod: %+v", got.Labels)
	}
	var receipts corev1.ConfigMapList
	if err := controller.List(t.Context(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 1 {
		t.Fatalf("mode downgrade discarded authority: count=%d err=%v", len(receipts.Items), err)
	}
}

func TestM093SecureModeRetainsOldHTTPReceiptWithoutNetwork(t *testing.T) {
	c, req := trustedAdapterCase(t, false)
	pod := &corev1.Pod{}
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		t.Fatal(err)
	}
	r := operationReceipt{
		Version: adapterRotateReceiptVersion, Kind: "adapter-rotate", Phase: "unload-dispatching",
		PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels),
		AdapterName:      req.AdapterObservation.AdapterName,
		AdapterEventName: req.AdapterObservation.EventName, AdapterEventUID: req.AdapterObservation.EventUID,
		AdapterEventCreatedAt: req.AdapterObservation.CreatedAt.UTC().Format(time.RFC3339Nano),
		AdapterCreator:        req.AdapterObservation.CreatorIdentity, AdapterEndpointSHA256: "765a2d1c8f42e2313aa858b6b809060099d9137013173d7660f023e44d62aae9",
	}
	if !r.valid() {
		t.Fatal("invalid predecessor adapter receipt")
	}
	if _, err := journalWrite(t.Context(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, r); err != nil {
		t.Fatal(err)
	}
	secureEmpty, err := LoadServingSecurityFile("", ServingSecuritySecureRequired, "operator")
	if err != nil {
		t.Fatal(err)
	}
	stack := &mockVLLM{}
	native := NewNativeActuator(c)
	native.Reader, native.JournalNamespace, native.RecoveryVLLM = c, "operator", stack
	native.SetServingSecurity(secureEmpty)
	events, err := native.RecoverOperations(t.Context(), false)
	if err != nil || len(events) != 1 || events[0].Err == nil {
		t.Fatalf("old receipt recovery=%+v err=%v", events, err)
	}
	if stack.adapterObserveCalls != 0 || stack.unloadCalls != 0 || stack.loadCalls != 0 {
		t.Fatalf("secure mode issued HTTP from an unbound old receipt: %+v", stack)
	}
	var receipts corev1.ConfigMapList
	if err := c.List(t.Context(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 1 {
		t.Fatalf("old unresolved receipt lost: count=%d err=%v", len(receipts.Items), err)
	}
}

func TestM093MIGDriverInjectionCannotReachDefaultPlaintextVLLM(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	pod := migPod("ns", "infer")
	pod.Status.PodIP = host
	pod.Annotations[annoServingPort] = portText
	c := fakeC(pod)
	result, err := (migRebindHandler{}).Enact(t.Context(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", MIG: &mockMIG{}, MIGProfiles: testMIGProfiles()}, boundReq(pod, model.ActionMIGRebind))
	if err != nil || result.Emitted || result.NoEffect != NoEffectRefused {
		t.Fatalf("MIG-only injection was not refused before serving: result=%+v err=%v", result, err)
	}
	if requests != 0 {
		t.Fatalf("MIG-only injection reached default plaintext serving HTTP %d time(s)", requests)
	}
}

func TestM093NativeSecureAdapterMultiStepPersistsBoundReceipt(t *testing.T) {
	loaded := true
	var auth []string
	f := newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == defaultModelsPath:
			id := "base"
			if loaded {
				id = "poisoned"
			}
			_, _ = fmt.Fprintf(w, `{"data":[{"id":%q}]}`, id)
		case r.Method == http.MethodPost && r.URL.Path == defaultUnloadPath:
			loaded = false
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	f.pod.Labels[labelLoRAEnabled] = "true"
	f.pod.Annotations[annoLoRAAdapter] = "tenant-drift"
	now := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	observation := model.AdapterObservation{EventName: "detected", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:tenant:detector", TargetPodUID: string(f.pod.UID), AdapterName: "poisoned", CreatedAt: now}
	event := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": observation.EventName, "uid": observation.EventUID, "creationTimestamp": now.Format(time.RFC3339Nano), "annotations": map[string]any{"phorvex.ai/creator-identity": observation.CreatorIdentity, "phorvex.ai/target-pod-uid": observation.TargetPodUID, "phorvex.ai/adapter-name": observation.AdapterName}},
		"spec":     map[string]any{"rule": map[string]any{"type": model.AttackVectorAdapter}, "targets": []any{"tenant/model-0"}},
	}}
	secret := &corev1.Secret{}
	if err := f.client.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: f.binding.SecretName}, secret); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(f.policy, f.pod, secret, event,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", UID: "tenant-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "operator-uid"}},
	).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if obj.GetUID() == "" {
			obj.SetUID(types.UID("created-" + obj.GetName()))
		}
		return c.Create(ctx, obj, opts...)
	}}).Build()
	ConfigureAdapterDetectorIdentities([]string{observation.CreatorIdentity})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	native := NewNativeActuator(c)
	native.Reader, native.JournalNamespace = c, "operator"
	native.SetServingSecurity(f.config)
	if err := native.EnsurePolicy(t.Context(), TenantTarget{Tenant: "tenant", Namespace: "tenant"}); err != nil {
		t.Fatal(err)
	}
	req := f.request(model.ActionAdapterRotate)
	req.AdapterObservation = &observation
	result, err := native.Actuate(t.Context(), req)
	if err != nil || !result.Emitted || loaded {
		t.Fatalf("secure multi-step adapter result=%+v loaded=%v err=%v", result, loaded, err)
	}
	if len(auth) < 3 {
		t.Fatalf("multi-step operation issued %d authenticated requests", len(auth))
	}
	for _, got := range auth {
		if got != "Bearer trusted-token-1" {
			t.Fatalf("multi-step request escaped one credential snapshot: %q", got)
		}
	}
	var receipts corev1.ConfigMapList
	if err := c.List(t.Context(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 1 {
		t.Fatalf("protected secure receipt count=%d err=%v", len(receipts.Items), err)
	}
	r, err := validateProtectedReceipt(&receipts.Items[0], "operator")
	if err != nil || r.Version != adapterRotateSecureReceiptVersion || r.ServingBindingSHA256 != servingBindingDigest("operator", f.binding) || r.ServingServiceAccount != "model-sa" {
		t.Fatalf("secure adapter receipt=%+v err=%v", r, err)
	}
}
