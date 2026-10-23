package runner

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

type m064RunnerNative struct {
	native   *actuator.NativeActuator
	requests []actuator.Request
}

func (n *m064RunnerNative) Name() string { return n.native.Name() }
func (n *m064RunnerNative) EnsurePolicy(ctx context.Context, target actuator.TenantTarget) error {
	return n.native.EnsurePolicy(ctx, target)
}
func (n *m064RunnerNative) SupportsAction(ctx context.Context, action model.Action, target actuator.Target) (bool, string) {
	return n.native.SupportsAction(ctx, action, target)
}
func (n *m064RunnerNative) Actuate(ctx context.Context, req actuator.Request) (actuator.Result, error) {
	n.requests = append(n.requests, req)
	return n.native.Actuate(ctx, req)
}

func m064RunnerSecurity(t *testing.T, operatorNamespace string, binding actuator.ServingSecurityBinding) *actuator.ServingSecurityConfig {
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
	config, err := actuator.LoadServingSecurityFile(path, actuator.ServingSecuritySecureRequired, operatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// TestM064RealAPIRunnerNativeAccounting crosses the actual runner, Native,
// API-server and protected TLS boundaries. A confirmed partial serving result
// retains forensic evidence but earns no success, intent, failure or fallback
// credit; its exact retry reconciles the receipt without another POST. A
// separate stale-selection arm proves a genuine pre-create refusal retains the
// established clean-refusal accounting rather than inheriting partial semantics.
//
// The confirmed partial is the production kv-reset explicit negative
// acknowledgement (88daf954): a complete authenticated {"success":false} is
// retained as terminal-partial because the cache may have partially changed.
// The production-default KV migration route used to supply the local-only
// partial, but 682657b3 deliberately fails it closed before dispatch until a
// reviewed remote connector is installed; the last arm asserts that refusal is
// accounted as a clean no-effect refusal that leaves the retained partial
// evidence untouched.
func TestM064RealAPIRunnerNativeAccounting(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	useExistingCluster := false
	env := &envtest.Environment{UseExistingCluster: &useExistingCluster, CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	apiClient, err := client.New(cfg, client.Options{Scheme: m034Scheme(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/reset_prefix_cache" || r.Header.Get("Authorization") != "Bearer trusted-token" {
			t.Errorf("unexpected protected serving request: %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false}`))
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	serverName := host
	cert := server.Certificate()
	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) > 0 {
		serverName = cert.IPAddresses[0].String()
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	const (
		namespace = "m064-runner"
		operator  = "m064-runner-operator"
	)
	for _, name := range []string{namespace, operator} {
		if err := apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Tenant: namespace, Mode: v1alpha1.ModeActive,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "model"}},
		Budget: v1alpha1.BudgetSpec{
			TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionKVReset), v1alpha1.ActionType(model.ActionKVMigrateInvalidate)}},
	}}
	if err := apiClient.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: "model-0",
		Labels: map[string]string{"app": "model", "phorvex.ai/guardrail-epoch": ""},
		Annotations: map[string]string{
			"phorvex.ai/model-id":         "fixture-model",
			"phorvex.ai/serving-port":     port,
			"phorvex.ai/disagg-kv-peers":  "decode-a.invalid:8000,decode-b.invalid:8000",
			"phorvex.ai/kv-reset-epoch":   "",
			"phorvex.ai/kv-migrate-epoch": "session-old",
		},
	}, Spec: corev1.PodSpec{ServiceAccountName: "model-sa", Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}
	if err := apiClient.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIP, pod.Status.Phase = host, corev1.PodRunning
	if err := apiClient.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := apiClient.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: operator, Name: "serving-admin"}, Data: map[string][]byte{
		"bearer": []byte("trusted-token"), "ca.crt": ca,
	}}
	if err := apiClient.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	binding := actuator.ServingSecurityBinding{
		Namespace: namespace, PolicyName: policy.Name, PolicyUID: string(policy.UID), ServiceAccount: "model-sa",
		ProfileID: "model-admin-v1", SecretName: secret.Name, BearerKey: "bearer", CAKey: "ca.crt", ServerName: serverName,
	}
	native := actuator.NewNativeActuator(apiClient)
	native.SetBoundaryReader(apiClient)
	native.JournalNamespace = operator
	native.SetServingSecurity(m064RunnerSecurity(t, operator, binding))
	recording := &m064RunnerNative{native: native}
	intents := exposure.NewIntents()
	manager := &Manager{Local: &inprocess.Services{Actuator: recording}, BoundaryReader: apiClient, Intents: intents, Log: logr.Discard()}
	entry := &policyEntry{namespace: namespace, uid: string(policy.UID), key: types.NamespacedName{Namespace: namespace, Name: policy.Name}, spec: policy.Spec}
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: namespace, Name: pod.Name, UID: string(pod.UID), Labels: map[string]string{"app": "model"},
		Ready: true, DesiredReplicas: 1, ReadyReplicas: 1, ServingDeclared: true, ServingEndpointReady: true,
		KVResetEpoch:              model.OwnedValue{Present: true, Value: ""},
		KVMigrateEpoch:            model.OwnedValue{Present: true, Value: "session-old"},
		KVLocalEffectEpoch:        model.OwnedValue{Present: false},
		GuardrailEpochObservation: model.OwnedValue{Present: true, Value: ""},
	}}
	views := map[string]*model.WorkloadView{namespace + "/" + pod.Name: view}
	resolved := model.Policy{Tenant: namespace, Namespace: namespace, PolicyName: policy.Name, PolicyUID: string(policy.UID), TickID: "m064-runner-tick", EnabledActions: map[model.Action]bool{model.ActionKVReset: true, model.ActionKVMigrateInvalidate: true}}
	decision := func(name string, action model.Action) []model.Decision {
		return []model.Decision{{Tenant: namespace, Namespace: namespace, Pod: name, Action: action, Selected: true, Feasible: true}}
	}
	journal := func() corev1.ConfigMap {
		t.Helper()
		var list corev1.ConfigMapList
		if err := apiClient.List(ctx, &list, client.InNamespace(operator), client.MatchingLabels{"phorvex.ai/serving-effect-journal": "v1"}); err != nil {
			t.Fatal(err)
		}
		if len(list.Items) != 1 {
			t.Fatalf("protected serving receipts=%d, want 1", len(list.Items))
		}
		return list.Items[0]
	}

	partial := decision(pod.Name, model.ActionKVReset)
	if got := manager.actuate(ctx, entry, resolved, partial, views); got != 0 {
		t.Fatalf("confirmed negative-acknowledgement partial actuations=%d, want 0", got)
	}
	first := partial[0]
	if first.Actuated || first.DispatchOutcome != model.DispatchError || first.DispatchReason != "outcome-unknown" ||
		first.Handler != string(model.ActionKVReset) || first.MutationKind != "partial" || len(first.ObjectsTouched) == 0 || first.RollbackRef == "" {
		t.Fatalf("runner lost confirmed partial evidence: %+v", first)
	}
	retained := journal()
	if receipt := retained.Data["receipt"]; !strings.Contains(receipt, `"phase":"terminal-partial"`) || !strings.Contains(receipt, `"kvResetNegativeACK":{`) {
		t.Fatalf("runner arm did not exercise the confirmed terminal partial: %s", receipt)
	}
	if calls.Load() != 1 || len(recording.requests) != 1 || len(manager.Failures.at) != 0 || len(manager.fallbackDecisions) != 0 ||
		len(intents.Since(resolved.Owner(), namespace, pod.Name, time.Now())) != 0 {
		t.Fatalf("partial received credit or fallback: calls=%d requests=%d failures=%+v fallback=%+v intents=%+v", calls.Load(), len(recording.requests), manager.Failures.at, manager.fallbackDecisions, intents.Since(resolved.Owner(), namespace, pod.Name, time.Now()))
	}
	request := recording.requests[0]
	if request.TickID != resolved.TickID || request.ServingObservation == nil ||
		!request.ServingObservation.KVReset.Present || request.ServingObservation.KVReset.Value != "" ||
		!request.ServingObservation.KVMigrate.Present || request.ServingObservation.KVMigrate.Value != "session-old" ||
		request.ServingObservation.KVLocalEffect.Present || !request.ServingObservation.Guardrail.Present || request.ServingObservation.Guardrail.Value != "" {
		t.Fatalf("runner dropped presence-aware serving observation: %+v", request)
	}

	reconciled := decision(pod.Name, model.ActionKVReset)
	if got := manager.actuate(ctx, entry, resolved, reconciled, views); got != 0 {
		t.Fatalf("same-operation reconciliation actuations=%d", got)
	}
	if reconciled[0].Actuated || reconciled[0].DispatchOutcome != model.DispatchReconciled || reconciled[0].DispatchReason != "reconciled-prior-operation" ||
		calls.Load() != 1 || len(manager.Failures.at) != 0 || len(manager.fallbackDecisions) != 0 || len(intents.Since(resolved.Owner(), namespace, pod.Name, time.Now())) != 0 {
		t.Fatalf("reconciliation gained credit or repeated HTTP: decision=%+v calls=%d failures=%+v fallback=%+v", reconciled[0], calls.Load(), manager.Failures.at, manager.fallbackDecisions)
	}

	// Use a new target with no receipt. Reusing the terminal partial slot would
	// correctly invoke conservative supersession rules rather than the genuine
	// pre-create refusal branch this control needs to distinguish.
	refusalPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: "model-refusal", Labels: map[string]string{"app": "model"},
		Annotations: map[string]string{
			"phorvex.ai/model-id": "fixture-model", "phorvex.ai/serving-port": port,
			"phorvex.ai/kv-migrate-epoch": "fresh-current",
		},
	}, Spec: corev1.PodSpec{ServiceAccountName: "model-sa", Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}
	if err := apiClient.Create(ctx, refusalPod); err != nil {
		t.Fatal(err)
	}
	refusalPod.Status.PodIP, refusalPod.Status.Phase = host, corev1.PodRunning
	if err := apiClient.Status().Update(ctx, refusalPod); err != nil {
		t.Fatal(err)
	}
	if err := apiClient.Get(ctx, client.ObjectKeyFromObject(refusalPod), refusalPod); err != nil {
		t.Fatal(err)
	}
	refusalPolicy := resolved
	refusalPolicy.TickID = "m064-runner-stale-tick"
	staleView := &model.WorkloadView{Pod: model.Pod{
		Namespace: namespace, Name: refusalPod.Name, UID: string(refusalPod.UID), Labels: map[string]string{"app": "model"},
		Ready: true, DesiredReplicas: 1, ReadyReplicas: 1, ServingDeclared: true, ServingEndpointReady: true,
		KVMigrateEpoch: model.OwnedValue{Present: true, Value: "stale-selection"},
	}}
	refused := decision(refusalPod.Name, model.ActionKVReset)
	if got := manager.actuate(ctx, entry, refusalPolicy, refused, map[string]*model.WorkloadView{namespace + "/" + refusalPod.Name: staleView}); got != 0 {
		t.Fatalf("stale pre-create refusal actuations=%d", got)
	}
	if refused[0].DispatchOutcome != model.DispatchRefused || refused[0].DispatchReason != "definite-no-effect-refusal" ||
		refused[0].Actuated || calls.Load() != 1 || len(manager.Failures.at) != 1 || len(manager.fallbackDecisions) != 0 {
		t.Fatalf("clean refusal accounting changed: decision=%+v calls=%d failures=%+v fallback=%+v", refused[0], calls.Load(), manager.Failures.at, manager.fallbackDecisions)
	}

	// 682657b3 (Fail closed on unavailable KV migration connector): the
	// production NativeActuator has no reviewed remote connector, so KV
	// migration is refused before any serving request or journal access. The
	// runner must account that as a clean no-effect refusal, and the refusal
	// must not touch the partial evidence retained for the same target.
	migratePolicy := resolved
	migratePolicy.TickID = "m064-runner-migrate-tick"
	migrate := decision(pod.Name, model.ActionKVMigrateInvalidate)
	if got := manager.actuate(ctx, entry, migratePolicy, migrate, views); got != 0 {
		t.Fatalf("fail-closed KV migration actuations=%d", got)
	}
	if migrate[0].Actuated || migrate[0].DispatchOutcome != model.DispatchRefused || migrate[0].DispatchReason != "definite-no-effect-refusal" ||
		migrate[0].Handler != string(model.ActionKVMigrateInvalidate) || migrate[0].MutationKind != "none" || len(migrate[0].ObjectsTouched) != 0 || migrate[0].RollbackRef != "" ||
		calls.Load() != 1 || len(manager.Failures.at) != 2 || len(manager.fallbackDecisions) != 0 || len(intents.Since(resolved.Owner(), namespace, pod.Name, time.Now())) != 0 {
		t.Fatalf("fail-closed KV migration accounting changed: decision=%+v calls=%d failures=%+v fallback=%+v", migrate[0], calls.Load(), manager.Failures.at, manager.fallbackDecisions)
	}
	if after := journal(); after.UID != retained.UID || after.ResourceVersion != retained.ResourceVersion || after.Data["receipt"] != retained.Data["receipt"] {
		t.Fatalf("fail-closed KV migration changed retained partial evidence: before=%s after=%s", retained.Data["receipt"], after.Data["receipt"])
	}
}
