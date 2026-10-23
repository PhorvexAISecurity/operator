package scopedoutcome

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

// TestPost25M106ActualAPIMTLSNativeReceiptAndScopedAdmission crosses the real
// Kubernetes UID/generation/owner resolver, fixture-scoped TLS 1.3 mutual
// authentication, real Native rotate delete receipt, durable evidence boundary,
// and decision admission. The replacement session service is a bounded
// synthetic fixture; this test does not claim a kubelet, CNI, or live attacker.
func TestPost25M106ActualAPIMTLSNativeReceiptAndScopedAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	local := false
	env := &envtest.Environment{UseExistingCluster: &local, CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, policyv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	const namespace = "m106-scoped-outcome"
	if err := apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	one, yes, grace := int32(1), true, int64(30)
	labels := map[string]string{"app": "m106-model"}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "model"}, Spec: appsv1.DeploymentSpec{
		Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: labels},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}},
	}}
	if err := apiClient.Create(ctx, dep); err != nil {
		t.Fatal(err)
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "model-rs", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &yes}}}, Spec: appsv1.ReplicaSetSpec{
		Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: labels},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}},
	}}
	if err := apiClient.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	newPod := func(name string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}},
			Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &grace, Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}
	}
	oldPod := newPod("old")
	if err := apiClient.Create(ctx, oldPod); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Tenant: namespace, Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: labels},
		Budget:  v1alpha1.BudgetSpec{MaxGracePeriodSeconds: &grace, TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRotate)}},
	}}
	if err := apiClient.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}

	workload := model.PersistenceWorkloadScope{Namespace: namespace, OwnerKind: "Deployment", OwnerName: dep.Name, OwnerUID: string(dep.UID)}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ca, caKey, roots := m106CA(t)
	serverCert := m106Leaf(t, ca, caKey, "session.test", x509.ExtKeyUsageServerAuth)
	clientCert := m106Leaf(t, ca, caKey, "observer.test", x509.ExtKeyUsageClientAuth)
	var rotated atomic.Bool
	var replacementUID atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := r.URL.Query().Get("session")
		present := session == "old-session" && !rotated.Load() || session == "replacement-session" && rotated.Load()
		targetUID := string(oldPod.UID)
		if session == "replacement-session" {
			targetUID = ""
			if current := replacementUID.Load(); current != nil {
				targetUID = current.(string)
			}
		}
		status := http.StatusOK
		if !present {
			status = http.StatusGone
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: session,
			Challenge: r.URL.Query().Get("challenge"), Present: present, TargetUID: targetUID, WorkloadScopeSHA256: scopeDigest})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("client identity chain is not singular")
			}
			return state.PeerCertificates[0].VerifyHostname("observer.test")
		}}
	server.StartTLS()
	t.Cleanup(server.Close)
	clock := &m106Clock{now: time.Now().UTC()}
	engine := decision.NewCoverageEngine()
	epoch := model.PolicyEpoch{Namespace: namespace, Name: policy.Name, UID: string(policy.UID), Generation: policy.Generation}
	if err := engine.SetOwnerEpoch(epoch, true); err != nil {
		t.Fatal(err)
	}
	prepare := PrepareConfig{Policy: epoch, Workload: workload, TargetName: oldPod.Name, TargetUID: string(oldPod.UID), TargetTerminationGraceSeconds: grace,
		Old:         SessionEndpoint{URL: server.URL, SessionID: "old-session", Challenge: "before", TargetUID: string(oldPod.UID), WorkloadScopeSHA256: scopeDigest},
		Replacement: SessionEndpoint{URL: server.URL, SessionID: "replacement-session", Challenge: "after", WorkloadScopeSHA256: scopeDigest}}
	startupDir := t.TempDir()
	caFile, certFile, keyFile := writeStartupTLS(t, startupDir, ca, clientCert.Certificate, clientCert.PrivateKey.(*ecdsa.PrivateKey))
	evidenceDir := filepath.Join(startupDir, "evidence")
	startup := StartupConfig{SchemaVersion: StartupConfigSchemaV1, Prepare: prepare, CAFile: caFile, ClientCertFile: certFile,
		ClientKeyFile: keyFile, ServerName: "session.test", EvidenceDirectory: evidenceDir, EvidenceMaxItems: 8,
		EvidenceMaxBytes: 1 << 20, HTTPTimeout: "2s", AuthorityTimeout: "1s"}
	startupPath := filepath.Join(startupDir, "startup.json")
	writeStartupJSON(t, startupPath, startup)
	producer, err := OpenStartupProducer(ctx, startupPath, apiClient, engine.ScopedOutcomeProcessEpochID(), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(producer.Close)
	producer.waitUntil = func(ctx context.Context, deadline time.Time) bool { clock.Set(deadline); return ctx.Err() == nil }
	// This Ready peer appears after Prepare but before the acknowledged action.
	// It was absent from the UID snapshot, so the server creation timestamp is
	// the independent boundary that prevents it from becoming a replacement.
	interloperPod := newPod("between-prepare-and-dispatch")
	if err := apiClient.Create(ctx, interloperPod); err != nil {
		t.Fatal(err)
	}
	interloperPod.Status.Phase = corev1.PodRunning
	interloperPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := apiClient.Status().Update(ctx, interloperPod); err != nil {
		t.Fatal(err)
	}
	hybrid := actuator.NewHybridActuator(apiClient)
	hybrid.ConfigureNativeJournal(apiClient, namespace)
	prep := hybrid.PrepareRoutes(ctx, actuator.TenantTarget{Tenant: namespace, Namespace: namespace, PolicyName: policy.Name,
		PolicyUID: string(policy.UID), Generation: policy.Generation, MatchLabels: labels, EnabledActions: map[model.Action]bool{model.ActionRotate: true}})
	if err := prep.ForAction(actuator.BackendHybrid, model.ActionRotate); err != nil {
		t.Fatal(err)
	}
	request := actuator.Request{Tenant: namespace, Namespace: namespace, Pod: oldPod.Name, TargetUID: string(oldPod.UID),
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, MaxGracePeriodSeconds: grace,
		Action: model.ActionRotate, TickID: "m106-api-tick"}
	result, err := hybrid.Actuate(ctx, request)
	if err != nil || !result.Emitted || result.Actuator != "native" || result.Handler != string(model.ActionRotate) {
		t.Fatalf("actual Native receipt was not coherent: result=%+v err=%v", result, err)
	}
	acknowledgedAt := time.Now().UTC()
	clock.Set(acknowledgedAt)
	// Model the controller boundary only after the exact Native delete receipt:
	// the replacement name and UID were absent from Prepare and are assigned by
	// the API server after dispatch.
	// API-server creation timestamps are second precision. Cross the next
	// second so the accepted replacement is unambiguously later than dispatch;
	// same-second objects remain conservatively unavailable.
	createAfter := acknowledgedAt.Truncate(time.Second).Add(time.Second).Add(50 * time.Millisecond)
	for time.Now().UTC().Before(createAfter) {
		time.Sleep(10 * time.Millisecond)
	}
	replacementPod := newPod("replacement")
	if err := apiClient.Create(ctx, replacementPod); err != nil {
		t.Fatal(err)
	}
	replacementPod.Status.Phase = corev1.PodRunning
	replacementPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := apiClient.Status().Update(ctx, replacementPod); err != nil {
		t.Fatal(err)
	}
	replacementUID.Store(string(replacementPod.UID))
	rotated.Store(true)
	resolvedPolicy := model.Policy{Tenant: namespace, Namespace: namespace, PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, MaxGracePeriodSeconds: grace}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: namespace, Name: oldPod.Name, UID: string(oldPod.UID)}}
	if !producer.RecordNativeRotate(resolvedPolicy, view, request, result, acknowledgedAt) {
		t.Fatal("actual Native receipt did not bind the prepared session")
	}
	var deliveries []model.ScopedOutcomeDelivery
	for deadline := time.Now().Add(2 * time.Second); len(deliveries) == 0 && time.Now().Before(deadline); {
		deliveries = producer.Drain(4)
		time.Sleep(time.Millisecond)
	}
	if len(deliveries) != 1 || deliveries[0].Observation == nil {
		t.Fatalf("scoped producer delivery=%+v", deliveries)
	}
	entries, err := os.ReadDir(evidenceDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("durable evidence files=%d err=%v", len(entries), err)
	}
	evidenceRaw, err := os.ReadFile(filepath.Join(evidenceDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var evidence EvidenceBundle
	if err := json.Unmarshal(evidenceRaw, &evidence); err != nil || evidence.EvidenceID != deliveries[0].Observation.EvidenceID {
		t.Fatalf("durable startup evidence did not bind delivery: evidence=%+v err=%v", evidence, err)
	}
	engine.PersistenceAuthority = producer
	engine.Now = func() time.Time { return clock.Now() }
	admitted := engine.AdmitPersistenceObservation(*deliveries[0].Observation)
	if !admitted.Applied || len(admitted.Status.Cohorts) != 1 || admitted.Status.Cohorts[0].Revoked != 1 || admitted.Status.Cohorts[0].N != 1 || admitted.Status.Cohorts[0].Calibrated {
		t.Fatalf("actual producer result was not exact reporting-only revoked evidence: %+v", admitted)
	}
}
