package runner

import (
	"context"
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	m178ResetEpochAnnotation = "phorvex.ai/kv-reset-epoch"
	m178MigrateAnnotation    = "phorvex.ai/kv-migrate-epoch"
	m178LocalAnnotation      = "phorvex.ai/kv-local-effect-epoch"
	m178GuardrailEpochLabel  = "phorvex.ai/guardrail-epoch"
	m178JournalLabel         = "phorvex.ai/serving-effect-journal"
)

type m178Backend struct {
	mu     sync.Mutex
	body   string
	calls  int
	tokens []string
}

func (b *m178Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/reset_prefix_cache" {
		http.NotFound(w, r)
		return
	}
	b.mu.Lock()
	b.calls++
	b.tokens = append(b.tokens, r.Header.Get("Authorization"))
	body := b.body
	b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func (b *m178Backend) observed() (int, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, append([]string(nil), b.tokens...)
}

type m178Receipt struct {
	Version         int    `json:"version"`
	Kind            string `json:"kind"`
	Phase           string `json:"phase"`
	PolicyNamespace string `json:"policyNamespace"`
	PolicyName      string `json:"policyName"`
	PolicyUID       string `json:"policyUID"`
	TargetName      string `json:"targetName"`
	TargetUID       string `json:"targetUID"`
	OperationID     string `json:"operationID"`
	TickID          string `json:"tickID"`
	Generation      uint64 `json:"generation"`
	SelectedReset   struct {
		Present bool   `json:"present"`
		Value   string `json:"value"`
	} `json:"selectedReset"`
	ExpectedReset struct {
		Present bool   `json:"present"`
		Value   string `json:"value"`
	} `json:"expectedReset"`
	ServingBindingSHA256  string `json:"servingBindingSHA256"`
	ServingServiceAccount string `json:"servingServiceAccount"`
}

type m178Fixture struct {
	ctx      context.Context
	client   client.Client
	native   *actuator.NativeActuator
	backend  *m178Backend
	server   *httptest.Server
	ns, opns string
	policy   *v1alpha1.PhorvexPolicy
	pod      *corev1.Pod
	security *actuator.ServingSecurityConfig
}

func m178SecurityConfig(t *testing.T, operatorNS string, binding actuator.ServingSecurityBinding) *actuator.ServingSecurityConfig {
	t.Helper()
	payload, err := json.Marshal(struct {
		Version  int                               `json:"version"`
		Bindings []actuator.ServingSecurityBinding `json:"bindings"`
	}{Version: 1, Bindings: []actuator.ServingSecurityBinding{binding}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "serving-security.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	configured, err := actuator.LoadServingSecurityFile(path, actuator.ServingSecuritySecureRequired, operatorNS)
	if err != nil {
		t.Fatal(err)
	}
	return configured
}

func newM178Fixture(t *testing.T, ctx context.Context, c client.Client, id, body string) *m178Fixture {
	t.Helper()
	f := &m178Fixture{ctx: ctx, client: c, ns: "m178-" + id, opns: "m178-" + id + "-op"}
	create := func(obj client.Object) {
		t.Helper()
		if err := c.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.ns}})
	create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.opns}})
	f.backend = &m178Backend{body: body}
	f.server = httptest.NewTLSServer(f.backend)
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
	f.policy = &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: f.ns, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": id}},
		Budget:  v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionKVReset)}},
	}}
	create(f.policy)
	f.pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: f.ns, Name: "model-0", Labels: map[string]string{"app": id}, Annotations: map[string]string{
		"phorvex.ai/model-id": "fixture-model", "phorvex.ai/serving-port": strconv.Itoa(port),
	}}, Spec: corev1.PodSpec{ServiceAccountName: "model-sa", Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}
	create(f.pod)
	f.pod.Status.PodIP, f.pod.Status.Phase = host, corev1.PodRunning
	if err := c.Status().Update(ctx, f.pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(f.pod), f.pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(f.policy), f.policy); err != nil {
		t.Fatal(err)
	}
	cert := f.server.Certificate()
	serverName := host
	if len(cert.DNSNames) != 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) != 0 {
		serverName = cert.IPAddresses[0].String()
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: f.opns, Name: "serving-auth"}, Data: map[string][]byte{
		"token": []byte("m178-trusted-token"), "ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
	}}
	create(secret)
	binding := actuator.ServingSecurityBinding{Namespace: f.ns, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: "model-sa", ProfileID: "m178-reset-v1", SecretName: secret.Name, BearerKey: "token", CAKey: "ca.crt", ServerName: serverName}
	f.security = m178SecurityConfig(t, f.opns, binding)
	f.native = actuator.NewNativeActuator(c)
	f.native.Reader, f.native.JournalNamespace = c, f.opns
	f.native.SetServingSecurity(f.security)
	selector := f.policy.Spec.Selector
	if err := f.native.EnsurePolicy(ctx, actuator.TenantTarget{Tenant: f.ns, Namespace: f.ns, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), Selector: &selector, EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}); err != nil {
		t.Fatal(err)
	}
	return f
}

func m178Owned(values map[string]string, key string) model.OwnedValue {
	value, present := values[key]
	return model.OwnedValue{Present: present, Value: value}
}

func (f *m178Fixture) request(t *testing.T, tick string) actuator.Request {
	t.Helper()
	pod := &corev1.Pod{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	return actuator.Request{Tenant: f.ns, Namespace: f.ns, Pod: pod.Name, TargetUID: string(pod.UID), PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), TickID: tick, Action: model.ActionKVReset,
		ServingObservation: &actuator.ServingSelectionObservation{
			KVReset: m178Owned(pod.Annotations, m178ResetEpochAnnotation), KVMigrate: m178Owned(pod.Annotations, m178MigrateAnnotation),
			KVLocalEffect: m178Owned(pod.Annotations, m178LocalAnnotation), Guardrail: m178Owned(pod.Labels, m178GuardrailEpochLabel),
		}}
}

func (f *m178Fixture) receipt(t *testing.T) (*corev1.ConfigMap, m178Receipt) {
	t.Helper()
	var list corev1.ConfigMapList
	if err := f.client.List(f.ctx, &list, client.InNamespace(f.opns), client.MatchingLabels{m178JournalLabel: "v1"}); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("protected reset receipt count=%d, want 1", len(list.Items))
	}
	cm := list.Items[0].DeepCopy()
	var receipt m178Receipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &receipt); err != nil {
		t.Fatal(err)
	}
	return cm, receipt
}

func (f *m178Fixture) session(t *testing.T) (string, string) {
	t.Helper()
	snapshot, err := ingest.CollectSnapshot(f.ctx, f.client, time.Now().UTC(), nil, f.client)
	if err != nil {
		t.Fatal(err)
	}
	pod := snapshot.PodByKey[f.ns+"/"+f.pod.Name]
	if pod == nil {
		t.Fatalf("ingest omitted %s/%s", f.ns, f.pod.Name)
	}
	return pod.SessionEpoch, model.ExposureFingerprints(*pod)[model.VarSession]
}

// TestM178RealAPINativeReceiptAndIngest requires the real Native producer,
// M93 authenticated TLS transport, M64 protected receipt and public ingest
// consumer to agree on whether reset completion was actually acknowledged.
func TestM178RealAPINativeReceiptAndIngest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	localOnly := false
	env := &envtest.Environment{UseExistingCluster: &localOnly, CRDDirectoryPaths: []string{"../../config/crd/bases", "../../../build/phoenix-extended/config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	apiClient, err := client.New(cfg, client.Options{Scheme: m034Scheme(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	t.Run("false-is-unknown-and-never-replayed", func(t *testing.T) {
		const privateMarker = "m178-private-response-marker"
		f := newM178Fixture(t, ctx, apiClient, "unknown", `{"success":false,"detail":"`+privateMarker+`"}`)
		firstReq := f.request(t, "m178-unknown-tick-1")
		result, err := f.native.Actuate(ctx, firstReq)
		calls, tokens := f.backend.observed()
		if err == nil || !strings.Contains(err.Error(), "outcome unknown") || result.Emitted || result.NoEffect != "" || result.MutationKind != "partial" || calls != 1 {
			t.Fatalf("false acknowledgement gained credit/fallback: result=%+v calls=%d err=%v", result, calls, err)
		}
		if strings.Contains(err.Error(), privateMarker) || strings.Contains(result.Note, privateMarker) {
			t.Fatalf("private response leaked: result=%+v err=%v", result, err)
		}
		if len(tokens) != 1 || tokens[0] != "Bearer m178-trusted-token" {
			t.Fatalf("secure transport token observations=%v", tokens)
		}
		cm, receipt := f.receipt(t)
		if cm.UID == "" || cm.ResourceVersion == "" || receipt.Version != 9 || receipt.Kind != string(model.ActionKVReset) || receipt.Phase != "dispatching" || receipt.Generation != 1 || receipt.TickID != firstReq.TickID || receipt.OperationID == "" || receipt.PolicyNamespace != f.ns || receipt.PolicyUID != string(f.policy.UID) || receipt.TargetUID != string(f.pod.UID) || receipt.SelectedReset.Present || !receipt.ExpectedReset.Present || receipt.ExpectedReset.Value == "" || receipt.ServingBindingSHA256 == "" || receipt.ServingServiceAccount != "model-sa" {
			t.Fatalf("unknown receipt lost required authority/effect evidence: cm=%+v receipt=%+v", cm.ObjectMeta, receipt)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if _, present := pod.Annotations[m178ResetEpochAnnotation]; present {
			t.Fatalf("false acknowledgement wrote reset epoch: %v", pod.Annotations)
		}
		if session, exposed := f.session(t); session != "|" || exposed != "|" {
			t.Fatalf("unconfirmed reset changed ingest session clock: session=%q VarSession=%q", session, exposed)
		}

		retry, retryErr := f.native.Actuate(ctx, firstReq)
		if retryErr == nil || retry.Emitted || retry.MutationKind != "partial" {
			t.Fatalf("same operation escaped pending receipt: result=%+v err=%v", retry, retryErr)
		}
		newTick, newTickErr := f.native.Actuate(ctx, f.request(t, "m178-unknown-tick-2"))
		if newTickErr == nil || newTick.Emitted || newTick.MutationKind != "partial" {
			t.Fatalf("new tick superseded unknown dispatch: result=%+v err=%v", newTick, newTickErr)
		}
		restarted := actuator.NewNativeActuator(apiClient)
		restarted.Reader, restarted.JournalNamespace = apiClient, f.opns
		restarted.SetServingSecurity(f.security)
		if events, recoverErr := restarted.RecoverOperations(ctx, false); recoverErr != nil || len(events) != 1 || events[0].Err == nil {
			t.Fatalf("restart did not retain unknown dispatch: events=%+v err=%v", events, recoverErr)
		}
		if calls, _ := f.backend.observed(); calls != 1 {
			t.Fatalf("unknown operation was replayed: calls=%d", calls)
		}
		_, after := f.receipt(t)
		if after.OperationID != receipt.OperationID || after.TickID != receipt.TickID || after.Generation != receipt.Generation || after.Phase != receipt.Phase {
			t.Fatalf("unknown receipt was rewritten: before=%+v after=%+v", receipt, after)
		}
	})

	t.Run("explicit-true-advances-receipt-and-session", func(t *testing.T) {
		f := newM178Fixture(t, ctx, apiClient, "confirmed", `{"success":true,"request_id":"fixture"}`)
		req := f.request(t, "m178-confirmed-tick")
		result, err := f.native.Actuate(ctx, req)
		if err != nil || !result.Emitted || result.MutationKind != "forward-only" {
			t.Fatalf("explicit confirmation rejected: result=%+v err=%v", result, err)
		}
		calls, tokens := f.backend.observed()
		if calls != 1 || len(tokens) != 1 || tokens[0] != "Bearer m178-trusted-token" {
			t.Fatalf("confirmed transport calls=%d tokens=%v", calls, tokens)
		}
		cm, receipt := f.receipt(t)
		if cm.UID == "" || receipt.Phase != "terminal-full" || receipt.Generation != 1 || receipt.TickID != req.TickID || receipt.OperationID == "" || receipt.ExpectedReset.Value == "" {
			t.Fatalf("confirmed terminal receipt invalid: cm=%+v receipt=%+v", cm.ObjectMeta, receipt)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations[m178ResetEpochAnnotation] != receipt.ExpectedReset.Value {
			t.Fatalf("confirmed epoch=%q, receipt=%q", pod.Annotations[m178ResetEpochAnnotation], receipt.ExpectedReset.Value)
		}
		wantSession := receipt.ExpectedReset.Value + "|"
		if session, exposed := f.session(t); session != wantSession || exposed != wantSession {
			t.Fatalf("confirmed reset missing from ingest: session=%q VarSession=%q want=%q", session, exposed, wantSession)
		}
		reconciled, retryErr := f.native.Actuate(ctx, req)
		if retryErr != nil || reconciled.Emitted || reconciled.NoEffect != actuator.NoEffectReconciled || reconciled.RollbackRef == "" {
			t.Fatalf("same confirmed operation did not reconcile: result=%+v err=%v", reconciled, retryErr)
		}
		if calls, _ := f.backend.observed(); calls != 1 {
			t.Fatalf("confirmed operation replayed HTTP: calls=%d", calls)
		}
	})

	fmt.Fprintln(os.Stderr, "M178 Native/API/receipt/ingest control PASS")
}
