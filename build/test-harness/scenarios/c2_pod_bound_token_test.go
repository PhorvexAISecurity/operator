package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testPodTokenJWT(podUID, accountUID string, expiry time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims := map[string]any{"exp": expiry.Unix(), "aud": []string{"https://kubernetes.default.svc"}, "kubernetes.io": map[string]any{"pod": map[string]any{"uid": podUID}, "serviceaccount": map[string]any{"uid": accountUID}}}
	raw, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
}

func TestPodTokenAtomicCreateOncePublish(t *testing.T) {
	dir := t.TempDir()
	name := "pod-bound-token-request.json"
	payload := map[string]string{"body": strings.Repeat("x", 2<<20)}
	done := make(chan error, 1)
	go func() { _, err := writePodTokenFile(dir, name, payload); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			var got map[string]string
			if json.Unmarshal(raw, &got) != nil || got["body"] != payload["body"] {
				t.Fatal("reader saw incomplete final protocol file")
			}
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("atomic publish timed out")
		}
		time.Sleep(time.Millisecond)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := writePodTokenFile(dir, name, map[string]string{"body": "replacement"}); err == nil {
		t.Fatal("create-once receipt was replaced")
	}
}

func TestPodTokenBarrierWaitRejectsForeignCoordinatorFailure(t *testing.T) {
	base := podTokenRequest{Schema: "pod-bound-token-request-v1", RunID: "run-1", Nonce: strings.Repeat("a", 24), RequestedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	requestSHA := strings.Repeat("1", 64)
	for _, tc := range []struct {
		name string
		edit func(*podTokenCoordinatorFailure)
	}{
		{"run", func(f *podTokenCoordinatorFailure) { f.RunID = "run-2" }},
		{"nonce", func(f *podTokenCoordinatorFailure) { f.Nonce = strings.Repeat("b", 24) }},
		{"request", func(f *podTokenCoordinatorFailure) { f.RequestSHA256 = strings.Repeat("2", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			failure := podTokenCoordinatorFailure{Schema: "pod-bound-token-coordinator-failure-v1",
				RunID: base.RunID, Nonce: base.Nonce, RequestSHA256: requestSHA,
				Stage: "decision-observation", Reason: "DECISION_OBSERVATION_FAILED", ErrorSHA256: strings.Repeat("3", 64), RecordedAt: podTokenUTC()}
			tc.edit(&failure)
			if _, err := writePodTokenFile(dir, podTokenCoordinatorFailureFile, failure); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			if _, _, err := podTokenWaitBarrier(ctx, dir, base, requestSHA); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("foreign failure ended barrier wait: %v", err)
			}
		})
	}
}

func TestPodTokenBarrierWaitExitsOnMatchingCoordinatorFailure(t *testing.T) {
	dir := t.TempDir()
	req := podTokenRequest{Schema: "pod-bound-token-request-v1", RunID: "run-1", Nonce: strings.Repeat("a", 24), RequestedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	requestSHA := strings.Repeat("1", 64)
	failure := podTokenCoordinatorFailure{Schema: "pod-bound-token-coordinator-failure-v1",
		RunID: req.RunID, Nonce: req.Nonce, RequestSHA256: requestSHA,
		Stage: "post-audit-disjointness", Reason: "DISJOINTNESS_FAILED", ErrorSHA256: strings.Repeat("3", 64), RecordedAt: podTokenUTC()}
	if _, err := writePodTokenFile(dir, podTokenCoordinatorFailureFile, failure); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := podTokenWaitBarrier(context.Background(), dir, req, requestSHA); err == nil ||
		!strings.Contains(err.Error(), failure.Stage) || time.Since(start) > time.Second {
		t.Fatalf("matching coordinator failure did not stop wait promptly: %v", err)
	}
	// Even a matching diagnostic is never a decision barrier.
	if _, _, err := readPodTokenBarrier(dir, req, requestSHA); !os.IsNotExist(err) {
		t.Fatalf("diagnostic satisfied decision barrier: %v", err)
	}
}

func TestPodTokenCoordinatorFailureMalformedOrStaleCannotPassBarrier(t *testing.T) {
	req := podTokenRequest{Schema: "pod-bound-token-request-v1", RunID: "run-1", Nonce: strings.Repeat("a", 24),
		RequestedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	requestSHA := strings.Repeat("1", 64)
	for _, malformed := range []bool{false, true} {
		dir := t.TempDir()
		if malformed {
			if err := os.WriteFile(filepath.Join(dir, podTokenCoordinatorFailureFile), []byte(`{"schema":`), 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			failure := podTokenCoordinatorFailure{Schema: "pod-bound-token-coordinator-failure-v1", RunID: req.RunID,
				Nonce: req.Nonce, RequestSHA256: requestSHA, Stage: "decision-observation",
				Reason: "DECISION_OBSERVATION_FAILED", ErrorSHA256: strings.Repeat("3", 64),
				RecordedAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}
			if _, err := writePodTokenFile(dir, podTokenCoordinatorFailureFile, failure); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := podTokenWaitBarrier(context.Background(), dir, req, requestSHA); err == nil ||
			!strings.Contains(err.Error(), "diagnostic") {
			t.Fatalf("malformed=%v diagnostic accepted or hidden: %v", malformed, err)
		}
		if _, _, err := readPodTokenBarrier(dir, req, requestSHA); !os.IsNotExist(err) {
			t.Fatalf("malformed=%v diagnostic satisfied barrier: %v", malformed, err)
		}
	}
}

func TestPodTokenCoordinatorFailureRejectsAmbiguousAndUnboundedFiles(t *testing.T) {
	req := podTokenRequest{RunID: "run-1", Nonce: strings.Repeat("a", 24), RequestedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	requestSHA := strings.Repeat("1", 64)
	valid := fmt.Sprintf(`{"schema":"pod-bound-token-coordinator-failure-v1","runID":%q,"nonce":%q,"requestSHA256":%q,"stage":"decision-observation","reason":"DECISION_OBSERVATION_FAILED","errorSHA256":%q,"recordedAt":%q}`,
		req.RunID, req.Nonce, requestSHA, strings.Repeat("3", 64), podTokenUTC())
	for _, tc := range []struct{ name, raw string }{
		{"duplicate", strings.Replace(valid, `"stage":"decision-observation"`, `"stage":"decision-observation","stage":"audit-start"`, 1)},
		{"unknown", strings.Replace(valid, `"stage":"decision-observation"`, `"extra":"x","stage":"decision-observation"`, 1)},
		{"oversize", valid + strings.Repeat(" ", 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, podTokenCoordinatorFailureFile), []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readPodTokenCoordinatorFailure(dir, req, requestSHA); err == nil {
				t.Fatal("ambiguous or unbounded receipt accepted")
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside.json")
		if err := os.WriteFile(outside, []byte(valid), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, podTokenCoordinatorFailureFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := readPodTokenCoordinatorFailure(dir, req, requestSHA); err == nil {
			t.Fatal("symlinked coordinator receipt accepted")
		}
	})
}

func TestPodTokenBarrierWaitStillRequiresRealBarrier(t *testing.T) {
	dir := t.TempDir()
	req := podTokenRequest{RunID: "run-1", Nonce: strings.Repeat("a", 24), SourcePodUID: "source-uid"}
	requestSHA := strings.Repeat("1", 64)
	barrier := podTokenBarrier{Schema: "pod-bound-token-barrier-v1", RunID: req.RunID, Nonce: req.Nonce,
		RequestSHA256: requestSHA, Event: podTokenEvent{UID: "event-uid", SourcePodUID: req.SourcePodUID, TrustVerified: true},
		Decision: podTokenDecision{ID: "decision-id", AuditCoverage: "COMPLETE"}, DecisionRowSHA: strings.Repeat("2", 64)}
	if _, err := writePodTokenFile(dir, podTokenBarrierFile, barrier); err != nil {
		t.Fatal(err)
	}
	got, _, err := podTokenWaitBarrier(context.Background(), dir, req, requestSHA)
	if err != nil || got.Event.UID != barrier.Event.UID {
		t.Fatalf("real matching barrier rejected: %+v, %v", got, err)
	}
}

func TestPodTokenDisjointOldVoiceSelectors(t *testing.T) {
	nonce := strings.Repeat("a", 24)
	old := map[string]string{"app": "voice-bot"}
	kube := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: "old-deployment"}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: old}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: "old-service"}, Spec: corev1.ServiceSpec{Selector: old}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: "old-pdb"}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: old}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-one", Namespace: "voice", UID: "old-pod", Labels: old}},
	)
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "voice", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce}}}
	if err := podTokenDisjointPrecreate(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	svc, _ := kube.CoreV1().Services("voice").Get(context.Background(), "voice-bot", metav1.GetOptions{})
	svc.Spec.Selector = map[string]string{podTokenRoleLabel: "source"}
	if _, err := kube.CoreV1().Services("voice").Update(context.Background(), svc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := podTokenDisjointPrecreate(context.Background(), env); err == nil {
		t.Fatal("old Voice Service source-role overlap accepted")
	}
	svc.Spec.Selector = old
	if _, err := kube.CoreV1().Services("voice").Update(context.Background(), svc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	pdb, _ := kube.PolicyV1().PodDisruptionBudgets("voice").Get(context.Background(), "voice-bot", metav1.GetOptions{})
	pdb.Spec.Selector.MatchLabels = map[string]string{podTokenRoleLabel: "source"}
	if _, err := kube.PolicyV1().PodDisruptionBudgets("voice").Update(context.Background(), pdb, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := podTokenDisjointPrecreate(context.Background(), env); err == nil {
		t.Fatal("old Voice PDB source-role overlap accepted")
	}
	pdb.Spec.Selector.MatchLabels = old
	if _, err := kube.PolicyV1().PodDisruptionBudgets("voice").Update(context.Background(), pdb, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	dep, _ := kube.AppsV1().Deployments("voice").Get(context.Background(), "voice-bot", metav1.GetOptions{})
	dep.Spec.Selector.MatchLabels = map[string]string{podTokenRoleLabel: "source"}
	if _, err := kube.AppsV1().Deployments("voice").Update(context.Background(), dep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := podTokenDisjointPrecreate(context.Background(), env); err == nil {
		t.Fatal("old Voice Deployment source-role overlap accepted")
	}
}

func TestPodTokenRefusesOtherPolicySelectorBeforeCreate(t *testing.T) {
	nonce := strings.Repeat("a", 24)
	policy := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy", "metadata": map[string]any{"name": "other-policy", "namespace": "voice", "uid": "old-policy"}, "spec": map[string]any{"tenant": "other", "selector": map[string]any{"matchLabels": map[string]any{podTokenRoleLabel: "source"}}}}}
	policy.SetGroupVersionKind(natsResponsePolicyGVK)
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(natsResponsePolicyGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(schema.GroupVersionKind{Group: natsResponsePolicyGVK.Group, Version: natsResponsePolicyGVK.Version, Kind: "PhorvexPolicyList"}, &unstructured.UnstructuredList{})
	env := &core.Env{Ctrl: ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(), Config: config.TargetConfig{Namespace: "voice", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce}}}
	if err := podTokenNoCollision(context.Background(), env); err == nil {
		t.Fatal("different-tenant policy matching planned source accepted")
	}
	if err := unstructured.SetNestedField(policy.Object, map[string]any{"matchLabels": map[string]any{"app": "voice-bot"}}, "spec", "selector"); err != nil {
		t.Fatal(err)
	}
	if err := env.Ctrl.Update(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if err := podTokenNoCollision(context.Background(), env); err != nil {
		t.Fatalf("disjoint old policy refused: %v", err)
	}
}

func TestPodTokenCPUPostCreateRefusesAdmissionAddedSelectorOverlap(t *testing.T) {
	const ns = "phorvex-catalogue-cpu"
	nonce := strings.Repeat("a", 24)
	env := &core.Env{ScenarioName: "c2-pod-bound-api-auth-response-cpu", Config: config.TargetConfig{Namespace: ns, PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce}}}
	base := podTokenCaseLabels(env)
	sourceLabels := map[string]string{}
	peerLabels := map[string]string{}
	for key, value := range base {
		sourceLabels[key] = value
		peerLabels[key] = value
	}
	sourceLabels[podTokenRoleLabel] = "source"
	sourceLabels["admission.example/foreign"] = "yes"
	source := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: ns, UID: "source-uid", Labels: sourceLabels}}
	peer := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "peer", Namespace: ns, UID: "peer-uid", Labels: peerLabels}}
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: ns, UID: "foreign-uid"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"admission.example/foreign": "yes"}}}
	env.Kube = fake.NewSimpleClientset(foreign)
	fixture := podTokenFixture{name: "pod-token-" + nonce, source: source, peer: peer}
	if err := podTokenDisjointPrecreate(context.Background(), env); err != nil {
		t.Fatalf("planned labels should remain disjoint: %v", err)
	}
	if _, err := env.Kube.CoreV1().Pods(ns).Create(context.Background(), &source, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Kube.CoreV1().Pods(ns).Create(context.Background(), &peer, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := podTokenDisjointPrecreate(context.Background(), env, fixture); err == nil {
		t.Fatal("post-CREATE actual source label joined foreign Service")
	}
}

func TestPodTokenGeneratedNetworkPolicyOwnerIdentity(t *testing.T) {
	f := podTokenFixture{name: "pod-token-" + strings.Repeat("a", 24), namespace: "voice", policyUID: "policy-uid", policyGeneration: 1, source: testPodTokenReadyPod("source", "source-uid", "image")}
	uid := types.UID("amtd-uid")
	phoenix := networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: podTokenPhoenixNPName("voice", f.source.Name), UID: "np-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "AdaptiveMovingTargetDefense", UID: uid}}}}
	if owned, err := podTokenGeneratedNP(phoenix, f, uid); !owned || err != nil {
		t.Fatalf("exact Phoenix owner refused: %v", err)
	}
	if owned, err := podTokenGeneratedNP(phoenix, f, "different"); !owned || err == nil {
		t.Fatal("foreign Phoenix AMTD owner accepted")
	}
	native := networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: podTokenNativeNPName(f.source.UID), UID: "native-uid", Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex"}, OwnerReferences: []metav1.OwnerReference{{Kind: "Pod", UID: f.source.UID}}}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/quarantined": string(f.source.UID)}}}}
	if owned, err := podTokenGeneratedNP(native, f, ""); !owned || err != nil {
		t.Fatalf("exact native owner refused: %v", err)
	}
	native.OwnerReferences[0].UID = "foreign"
	if owned, err := podTokenGeneratedNP(native, f, ""); !owned || err == nil {
		t.Fatal("foreign native owner accepted")
	}
}

func TestPodTokenGeneratedStandingAMTDPolicyAnnotations(t *testing.T) {
	nonce := strings.Repeat("a", 24)
	f := podTokenFixture{name: "pod-token-" + nonce, namespace: "voice", policyUID: "policy-uid", policyGeneration: 3}
	a := &unstructured.Unstructured{}
	a.SetName(podTokenAMTDName(f))
	a.SetNamespace("voice")
	a.SetUID("amtd-uid")
	a.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "phorvex"})
	a.SetAnnotations(map[string]string{"phorvex.ai/policy-name": f.name, "phorvex.ai/policy-uid": string(f.policyUID), "phorvex.ai/policy-generation": "3", "phorvex.ai/identity-version": "v1", "phorvex.ai/namespace-raw": "voice", "phorvex.ai/tenant-raw": nonce})
	if !podTokenOwnedAMTD(*a, f) {
		t.Fatal("installed standing AMTD annotation graph refused")
	}
	a.SetAnnotations(map[string]string{"phorvex.ai/policy-uid": "foreign"})
	if podTokenOwnedAMTD(*a, f) {
		t.Fatal("foreign AMTD policy authority accepted")
	}
}

func TestPodTokenEndpointSliceOwnerInventory(t *testing.T) {
	f := podTokenFixture{name: "pod-token-" + strings.Repeat("a", 24), serviceUID: "service-uid"}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "owned-slice", Namespace: "voice", UID: "slice-uid", Labels: map[string]string{"kubernetes.io/service-name": f.name}, OwnerReferences: []metav1.OwnerReference{{Kind: "Service", UID: "foreign-uid"}}}}
	kube := fake.NewSimpleClientset(slice)
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "voice"}}
	if err := podTokenWaitEndpointSlicesAbsent(context.Background(), env, f); err == nil {
		t.Fatal("foreign same-name EndpointSlice accepted")
	}
	slice.OwnerReferences[0].UID = f.serviceUID
	if _, err := kube.DiscoveryV1().EndpointSlices("voice").Update(context.Background(), slice, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	bound, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := podTokenWaitEndpointSlicesAbsent(bound, env, f); err == nil {
		t.Fatal("lingering exact owned EndpointSlice accepted before GC")
	}
	if err := kube.DiscoveryV1().EndpointSlices("voice").Delete(context.Background(), slice.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := podTokenWaitEndpointSlicesAbsent(context.Background(), env, f); err != nil {
		t.Fatal(err)
	}
}

func TestPodTokenSourceManifestBindsExactFileAndImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	image := "registry.example/manager@sha256:" + strings.Repeat("b", 64)
	raw := []byte(fmt.Sprintf(`{"schema":"phorvex.manager-source-image.v1","sourceCommit":"%s","managerImageID":"%s","buildEvidenceRef":"reviewed-build","buildEvidenceSHA256":"%s","reviewRecordRef":"reviewed-record","reviewRecordSHA256":"%s"}`, strings.Repeat("a", 40), image, strings.Repeat("c", 64), strings.Repeat("d", 64)))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.PodBoundTokenFixtureConfig{SourceManifestPath: path, SourceManifestSHA256: podTokenHash(raw), ManagerImageID: image}
	env := &core.Env{Config: config.TargetConfig{PodBoundTokenFixture: cfg}}
	if err := podTokenVerifySourceManifest(env); err != nil {
		t.Fatal(err)
	}
	cfg.ManagerImageID = "other"
	if err := podTokenVerifySourceManifest(env); err == nil {
		t.Fatal("source manifest accepted different manager image")
	}
	cfg.ManagerImageID = image
	if err := os.WriteFile(path, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if err := podTokenVerifySourceManifest(env); err == nil {
		t.Fatal("changed manifest bytes accepted old source pin")
	}
}
func testPodTokenReadyPod(name, uid, image string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "voice", UID: types.UID(uid)}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "responder", Ready: true, ImageID: image}}}}
}

type podTokenSilentLogger struct{}

func (podTokenSilentLogger) Logf(string, ...any) {}
func (podTokenSilentLogger) Command(string)      {}
func (podTokenSilentLogger) Commands() []string  { return nil }
func (podTokenSilentLogger) RawLogPath() string  { return "" }
func TestPodTokenCaptureOnceReplaysSameBearerThroughRealTransport(t *testing.T) {
	const sourceUID = "11111111-1111-4111-8111-111111111111"
	const saUID = "22222222-2222-4222-8222-222222222222"
	expiry := time.Now().Add(10 * time.Minute)
	original := testPodTokenJWT(sourceUID, saUID, expiry)
	replaced := testPodTokenJWT("33333333-3333-4333-8333-333333333333", saUID, expiry)
	accepted := original
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/namespaces/voice/pods/peer" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+accepted {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	pod := testPodTokenReadyPod("source", sourceUID, "reviewed-image")
	kube := fake.NewSimpleClientset(&pod)
	env := &core.Env{Kube: kube, Rest: &rest.Config{Host: server.URL}, Log: podTokenSilentLogger{}, Config: config.TargetConfig{Namespace: "voice", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{FixtureImageID: "reviewed-image"}}}
	issued := original
	core.SetTimedExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ time.Duration, command []string) core.ExecResult {
		calls++
		if len(command) != 2 || command[0] != "cat" || command[1] != "/var/run/pod-token/token" {
			return core.ExecResult{ExitCode: 1}
		}
		return core.ExecResult{Stdout: issued, ExitCode: 0}
	})
	t.Cleanup(func() { core.SetTimedExecer(nil) })
	captured, err := podTokenCapture(context.Background(), env, pod, types.UID(saUID))
	if err != nil || calls != 1 || captured.captureID == "" || captured.podUID != pod.UID {
		t.Fatalf("capture once: calls=%d err=%v", calls, err)
	}
	status, _, err := podTokenReplayAPI(context.Background(), env, captured, "peer")
	if err != nil || status != 200 {
		t.Fatalf("exact original token baseline: status=%d err=%v", status, err)
	}
	issued = replaced
	accepted = replaced
	status, _, err = podTokenReplayAPI(context.Background(), env, captured, "peer")
	if err != nil || status != 401 || calls != 1 {
		t.Fatalf("same original handle after simulated invalidation: status=%d calls=%d err=%v", status, calls, err)
	}
}

func TestPodTokenCPUOriginalSourceAndPeerHandlesThroughRealAPI(t *testing.T) {
	const ns = "phorvex-catalogue-cpu"
	const sourceUID = "11111111-1111-4111-8111-111111111111"
	const peerUID = "22222222-2222-4222-8222-222222222222"
	const saUID = "33333333-3333-4333-8333-333333333333"
	expiry := time.Now().Add(10 * time.Minute)
	sourceBearer := testPodTokenJWT(sourceUID, saUID, expiry)
	peerBearer := testPodTokenJWT(peerUID, saUID, expiry)
	sourceAllowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/"+ns+"/pods/peer" {
			http.NotFound(w, r)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer " + sourceBearer:
			if !sourceAllowed {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		case "Bearer " + peerBearer:
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	source := testPodTokenReadyPod("source", sourceUID, "reviewed-image")
	peer := testPodTokenReadyPod("peer", peerUID, "reviewed-image")
	source.Namespace, peer.Namespace = ns, ns
	kube := fake.NewSimpleClientset(&source, &peer)
	env := &core.Env{Kube: kube, Rest: &rest.Config{Host: server.URL}, Log: podTokenSilentLogger{}, Config: config.TargetConfig{Namespace: ns, PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{FixtureImageID: "reviewed-image"}}}
	captures := 0
	core.SetTimedExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, podName, _ string, _ time.Duration, command []string) core.ExecResult {
		captures++
		if len(command) != 2 || command[0] != "cat" || command[1] != "/var/run/pod-token/token" {
			return core.ExecResult{ExitCode: 1}
		}
		if podName == source.Name {
			return core.ExecResult{Stdout: sourceBearer, ExitCode: 0}
		}
		if podName == peer.Name {
			return core.ExecResult{Stdout: peerBearer, ExitCode: 0}
		}
		return core.ExecResult{ExitCode: 1}
	})
	t.Cleanup(func() { core.SetTimedExecer(nil) })
	sourceHandle, err := podTokenCapture(context.Background(), env, source, saUID)
	if err != nil {
		t.Fatal(err)
	}
	peerHandle, err := podTokenCapture(context.Background(), env, peer, saUID)
	if err != nil {
		t.Fatal(err)
	}
	if sourceHandle.captureID == peerHandle.captureID || captures != 2 {
		t.Fatal("source and peer capture identities are not independent")
	}
	for _, handle := range []podTokenHandle{sourceHandle, peerHandle} {
		status, start, end, e := podTokenReplayAPIWindow(context.Background(), env, handle, peer.Name)
		if e != nil || status != 200 || !podTokenBeforeExpiry(start, end, handle.expiry) {
			t.Fatalf("original baseline unavailable status=%d err=%v", status, e)
		}
	}
	sourceAllowed = false
	status, start, end, err := podTokenReplayAPIWindow(context.Background(), env, sourceHandle, peer.Name)
	if err != nil || status != 401 || !podTokenBeforeExpiry(start, end, sourceHandle.expiry) {
		t.Fatalf("source original handle did not become unauthorized: %d %v", status, err)
	}
	status, start, end, err = podTokenReplayAPIWindow(context.Background(), env, peerHandle, peer.Name)
	if err != nil || status != 200 || !podTokenBeforeExpiry(start, end, peerHandle.expiry) || captures != 2 {
		t.Fatalf("peer original handle or capture-once control failed: %d %v", status, err)
	}
}

func TestPodTokenPromRun21MillisecondEvaluationAndWrongInstant(t *testing.T) {
	// An independent historical query of run 21's exact source series requested
	// 1790367000.123456 and Prometheus returned 1790367000.123. The retained
	// counter, sample time and positive rate reproduce the producer's precision
	// mismatch; these were not captured outbound producer queries.
	const pod = "pod-token-60bf41c9878d9056727f1b15-5fffbbfdc7-8z9k5"
	const nonce = "60bf41c9878d9056727f1b15"
	const uid = "95c1b8ab-ffd1-4f95-ba9e-c166c0f120c0"
	const namespace = "phorvex-catalogue-cpu"
	selector := `http_requests_total{namespace="` + namespace + `",pod="` + pod + `",nonce="` + nonce + `",pod_uid="` + uid + `"}`
	evaluation := time.Unix(1790367000, 123456000).UTC()
	responseTime := "1790367000.123"
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Query().Get("time"))
		expression := r.URL.Query().Get("query")
		value := "53"
		metric := fmt.Sprintf(`"namespace":%q,"pod":%q,"nonce":%q,"pod_uid":%q`, namespace, pod, nonce, uid)
		if strings.HasPrefix(expression, "timestamp(") {
			value = "1790366975.963"
		}
		if strings.HasPrefix(expression, "sum by (pod,pod_uid)") {
			value = "0.5333333333333333"
			metric = fmt.Sprintf(`"pod":%q,"pod_uid":%q`, pod, uid)
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{%s},"value":[%s,%q]}]}}`, metric, responseTime, value)
	}))
	defer server.Close()
	for _, step := range []struct {
		expression, value string
		sourceLabels      bool
	}{
		{"timestamp(" + selector + ")", "1790366975.963", true},
		{selector, "53", true},
		{"timestamp(" + selector + ")", "1790366975.963", true},
		{`sum by (pod,pod_uid) (rate(` + selector + `[1m]))`, "0.5333333333333333", false},
	} {
		got, _, err := podTokenPromQuery(context.Background(), server.URL, step.expression, namespace, pod, nonce, uid, evaluation, step.sourceLabels)
		want, _ := strconv.ParseFloat(step.value, 64)
		if err != nil || got != want {
			t.Fatalf("run21 Prometheus row rejected: got=%g want=%g err=%v", got, want, err)
		}
	}
	for _, got := range requested {
		if got != "1790367000.123" {
			t.Fatalf("queries did not share one millisecond-aligned instant: %q", got)
		}
	}
	responseTime = "1790367000.124"
	if _, _, err := podTokenPromQuery(context.Background(), server.URL, selector, namespace, pod, nonce, uid, evaluation, true); err == nil || !strings.Contains(err.Error(), "evaluation time differs") {
		t.Fatalf("different evaluation instant accepted: %v", err)
	}
}

func TestPodTokenPromUsesActualScrapeTimestampAndSourceSeries(t *testing.T) {
	const pod = "source-abc"
	const nonce = "0123456789abcdef01234567"
	sample := time.Now().Add(-20 * time.Second).Unix()
	returnedUID := "uid"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expression := r.URL.Query().Get("query")
		// A healthy fixture has a peer series with the same nonce. Every query,
		// including the rate query, must select this source Pod incarnation.
		if r.URL.Path != "/api/v1/query" || !strings.Contains(expression, `pod="`+pod+`"`) || !strings.Contains(expression, `pod_uid="uid"`) {
			http.Error(w, "bad query", 400)
			return
		}
		value := "7"
		if strings.HasPrefix(expression, "timestamp(") {
			value = strconv.FormatInt(sample, 10)
		}
		if strings.HasPrefix(expression, "sum by (pod,pod_uid)") {
			value = "0.2"
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"voice","pod":"%s","pod_uid":"%s","nonce":"%s"},"value":[%s,"%s"]}]}}`, pod, returnedUID, nonce, r.URL.Query().Get("time"), value)
	}))
	defer server.Close()
	env := &core.Env{Config: config.TargetConfig{Namespace: "voice", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce, PrometheusURL: server.URL}}}
	at, count, hash, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")})
	if err != nil || at.Unix() != sample || count != 7 || len(hash) != 64 {
		t.Fatalf("actual scrape sample: at=%s count=%f hash=%q err=%v", at, count, hash, err)
	}
	returnedUID = "old-incarnation"
	if _, _, _, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")}); err == nil {
		t.Fatal("old Voice Pod incarnation counter accepted")
	}
	returnedUID = "uid"
	sample = time.Now().Add(-3 * time.Minute).Unix()
	if _, _, _, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")}); err == nil {
		t.Fatal("old scrape accepted from fresh instant query evaluation")
	}
}

func TestPodTokenPromRejectsSplitEvaluationForTimestampAndCounter(t *testing.T) {
	const pod, nonce = "source-abc", "0123456789abcdef01234567"
	queries := 0
	returnedUID := "uid"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries++
		if !strings.Contains(r.URL.Query().Get("query"), `pod_uid="uid"`) {
			t.Error("CPU source UID absent from exact Prometheus selector")
		}
		evaluation, err := strconv.ParseFloat(r.URL.Query().Get("time"), 64)
		if err != nil {
			t.Error(err)
			return
		}
		if queries == 2 {
			evaluation += 0.5
		} // Counter belongs to a different evaluation.
		value := "7"
		if strings.HasPrefix(r.URL.Query().Get("query"), "timestamp(") {
			value = strconv.FormatInt(time.Now().Add(-20*time.Second).Unix(), 10)
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"phorvex-catalogue-cpu","pod":"%s","pod_uid":"%s","nonce":"%s"},"value":[%.6f,"%s"]}]}}`, pod, returnedUID, nonce, evaluation, value)
	}))
	defer server.Close()
	env := &core.Env{Config: config.TargetConfig{Namespace: "phorvex-catalogue-cpu", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce, PrometheusURL: server.URL}}}
	if _, _, _, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")}); err == nil {
		t.Fatal("timestamp and counter from distinct evaluations accepted")
	}
	returnedUID = "foreign-uid"
	if _, _, _, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")}); err == nil {
		t.Fatal("foreign Pod UID source counter accepted")
	}
}

func TestPodTokenPromRejectsScrapeIngestedBetweenTimestampAndCounter(t *testing.T) {
	const pod, nonce = "source-abc", "0123456789abcdef01234567"
	oldScrape := time.Now().Add(-40 * time.Second).Unix()
	newScrape := oldScrape + 20
	queries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries++
		if !strings.Contains(r.URL.Query().Get("query"), `pod_uid="uid"`) {
			t.Error("CPU source UID absent from Prometheus query")
		}
		value := "8" // A newer counter became visible after the first query.
		if strings.HasPrefix(r.URL.Query().Get("query"), "timestamp(") {
			value = strconv.FormatInt(newScrape, 10)
			if queries == 1 {
				value = strconv.FormatInt(oldScrape, 10)
			}
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"phorvex-catalogue-cpu","pod":"%s","pod_uid":"uid","nonce":"%s"},"value":[%s,"%s"]}]}}`, pod, nonce, r.URL.Query().Get("time"), value)
	}))
	defer server.Close()
	env := &core.Env{Config: config.TargetConfig{Namespace: "phorvex-catalogue-cpu", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce, PrometheusURL: server.URL}}}
	if _, _, _, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")}); err == nil || !strings.Contains(err.Error(), "counter and scrape timestamp differ") {
		t.Fatalf("mixed-scrape counter accepted or wrong refusal: %v", err)
	}
	if queries != 3 {
		t.Fatalf("mixed-scrape counter should stop before rate query, got %d requests", queries)
	}
}

func TestPodTokenWarmMetricDelayedPodMonitorDiscovery(t *testing.T) {
	const pod, nonce, uid, namespace = "source-abc", "0123456789abcdef01234567", "source-uid", "phorvex-catalogue-cpu"
	// Scale the retained run22 timing by 100: discovery at 1s,
	// 300ms between scrapes, then the first positive rate after scrape two.
	// Each query still traverses the actual Prometheus parser and exact UID
	// selector. Two increasing post-discovery source samples are required.
	started := time.Now()
	base := started.Add(-70 * time.Second).UTC().Truncate(time.Millisecond)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if r.URL.Path != "/api/v1/query" || !strings.Contains(query, `pod_uid="`+uid+`"`) || !strings.Contains(query, `nonce="`+nonce+`"`) {
			http.Error(w, "wrong source selector", http.StatusBadRequest)
			return
		}
		elapsed := time.Since(started)
		if elapsed < time.Second || (strings.HasPrefix(query, "sum by (pod,pod_uid)") && elapsed < 1300*time.Millisecond) {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
			return
		}
		at, count := base, "55"
		if elapsed >= 1600*time.Millisecond {
			at, count = base.Add(60*time.Second), "65"
		} else if elapsed >= 1300*time.Millisecond {
			at, count = base.Add(30*time.Second), "60"
		}
		metric := fmt.Sprintf(`"namespace":%q,"pod":%q,"nonce":%q,"pod_uid":%q`, namespace, pod, nonce, uid)
		value := count
		if strings.HasPrefix(query, "timestamp(") {
			value = strconv.FormatFloat(float64(at.UnixMilli())/1000, 'f', 3, 64)
		}
		if strings.HasPrefix(query, "sum by (pod,pod_uid)") {
			metric = fmt.Sprintf(`"pod":%q,"pod_uid":%q`, pod, uid)
			value = "0.16666666666666666"
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{%s},"value":[%s,%q]}]}}`, metric, r.URL.Query().Get("time"), value)
	}))
	defer server.Close()
	env := &core.Env{Config: config.TargetConfig{Namespace: namespace, PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce, PrometheusURL: server.URL}}}
	fixture := podTokenFixture{source: testPodTokenReadyPod(pod, uid, "image"), monitorUID: "monitor-uid"}
	ready := func(context.Context, corev1.Pod, string) (int, error) { return 200, nil }
	tooShort, oldErr := podTokenWarmMetricWith(context.Background(), env, fixture, 1250*time.Millisecond, 25*time.Millisecond, podTokenMetricSample, ready)
	if !errors.Is(oldErr, context.DeadlineExceeded) || tooShort.ProducerStatus == "MEASURED_FRESH" {
		t.Fatalf("old 125-second-equivalent bound unexpectedly admitted one-scrape source: telemetry=%+v err=%v", tooShort, oldErr)
	}
	got, err := podTokenWarmMetricWith(context.Background(), env, fixture, 2700*time.Millisecond, 25*time.Millisecond, podTokenMetricSample, ready)
	if err != nil || got.ProducerStatus != "MEASURED_FRESH" || got.FirstValue != 60 || got.SecondValue != 65 || len(got.QuerySHA256) != 64 {
		t.Fatalf("delayed real-query warmup rejected: telemetry=%+v err=%v", got, err)
	}
	first, _ := time.Parse(time.RFC3339Nano, got.FirstAt)
	second, _ := time.Parse(time.RFC3339Nano, got.SecondAt)
	if second.Sub(first) != 30*time.Second {
		t.Fatalf("warmup did not require distinct source scrapes: %s and %s", first, second)
	}
}

func TestPodTokenRealResponderProducesSourceUIDCounter(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python fixture runtime unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	serverSource := strings.Replace(podTokenServerSource, `("0.0.0.0",8080)`, fmt.Sprintf(`("127.0.0.1",%d)`, port), 1)
	if serverSource == podTokenServerSource {
		t.Fatal("real Pod token responder bind declaration changed")
	}
	const uid, nonce, pod, namespace = "source-uid", "0123456789abcdef01234567", "source-abc", "phorvex-catalogue-cpu"
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-B", "-c", serverSource)
	cmd.Env = append(os.Environ(), "POD_UID="+uid, "NONCE="+nonce, "POD_NAME="+pod, "POD_NAMESPACE="+namespace)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	var reply podTokenReadyReply
	for {
		resp, err := client.Get(base + "/ready")
		if err == nil {
			raw, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil || json.Unmarshal(raw, &reply) != nil || reply.PodUID != uid || reply.Nonce != nonce {
				t.Fatalf("real responder identity differs: %v", readErr)
			}
			break
		}
		if ctx.Err() != nil {
			t.Fatal("real responder did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	readCounter := func() int {
		resp, err := client.Get(base + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("real source metric unavailable: %v status=%d", err, resp.StatusCode)
		}
		line := strings.TrimSpace(strings.Split(string(raw), "\n")[1])
		for _, label := range []string{`namespace="` + namespace + `"`, `pod="` + pod + `"`, `pod_uid="` + uid + `"`, `nonce="` + nonce + `"`} {
			if !strings.Contains(line, label) {
				t.Fatalf("real source metric lost %s", label)
			}
		}
		count, err := strconv.Atoi(line[strings.LastIndexByte(line, ' ')+1:])
		if err != nil {
			t.Fatal(err)
		}
		return count
	}
	first := readCounter()
	for i := 0; i < 3; i++ {
		resp, err := client.Get(base + "/ready")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if second := readCounter(); second != first+3 {
		t.Fatalf("real /ready traffic did not advance source counter: %d to %d", first, second)
	}
}

func TestPodTokenWarmMetricMissingRateRemainsBoundedAndSpecific(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	const pod, uid, namespace = "source-abc", "uid", "phorvex-catalogue-cpu"
	scrapedAt := time.Now().Add(-20 * time.Second).Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if strings.HasPrefix(query, "sum by (pod,pod_uid)") {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
			return
		}
		value := "7"
		if strings.HasPrefix(query, "timestamp(") {
			value = strconv.FormatInt(scrapedAt, 10)
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":%q,"pod":%q,"pod_uid":%q,"nonce":%q},"value":[%s,%q]}]}}`, namespace, pod, uid, nonce, r.URL.Query().Get("time"), value)
	}))
	defer server.Close()
	env := &core.Env{Config: config.TargetConfig{Namespace: namespace, PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce, PrometheusURL: server.URL}}}
	fixture := podTokenFixture{source: testPodTokenReadyPod(pod, uid, "image")}
	ready := func(context.Context, corev1.Pod, string) (int, error) { return 200, nil }
	start := time.Now()
	got, err := podTokenWarmMetricWith(context.Background(), env, fixture, 300*time.Millisecond, 10*time.Millisecond, podTokenMetricSample, ready)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "source request rate: Pod token Prometheus source series absent") || got.ProducerStatus == "MEASURED_FRESH" || time.Since(start) > 2*time.Second {
		t.Fatalf("missing source rate was admitted or detail lost: telemetry=%+v err=%v", got, err)
	}
}

func TestPodTokenWarmMetricCancelsSlowQueryAndRejectsLateSuccess(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	ready := func(context.Context, corev1.Pod, string) (int, error) { return 200, nil }
	fixture := podTokenFixture{source: testPodTokenReadyPod("source-abc", "uid", "image")}
	started := make(chan struct{})
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	env := &core.Env{Config: config.TargetConfig{Namespace: "phorvex-catalogue-cpu", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce, PrometheusURL: server.URL}}}
	got, err := podTokenWarmMetricWith(context.Background(), env, fixture, 300*time.Millisecond, 10*time.Millisecond, podTokenMetricSample, ready)
	if !errors.Is(err, context.DeadlineExceeded) || got.ProducerStatus == "MEASURED_FRESH" {
		t.Fatalf("slow query crossed admission deadline: telemetry=%+v err=%v", got, err)
	}
	select {
	case <-started:
	default:
		t.Fatal("slow Prometheus query was not attempted")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("warm-up deadline did not cancel in-flight Prometheus query")
	}
	first := time.Now().Add(-40 * time.Second).UTC().Truncate(time.Millisecond)
	queries := 0
	late := func(context.Context, *core.Env, podTokenFixture) (time.Time, float64, string, error) {
		queries++
		if queries == 1 {
			return first, 1, "first", nil
		}
		time.Sleep(250 * time.Millisecond) // A misbehaving sample ignores cancellation.
		return first.Add(30 * time.Second), 2, "second", nil
	}
	got, err = podTokenWarmMetricWith(context.Background(), env, fixture, 150*time.Millisecond, 10*time.Millisecond, late, ready)
	if !errors.Is(err, context.DeadlineExceeded) || queries < 2 || got.ProducerStatus == "MEASURED_FRESH" || got.SecondAt != "" {
		t.Fatalf("late sample was credited after budget: telemetry=%+v err=%v", got, err)
	}
}

func TestPodTokenWarmMetricPreservesCallerCancellation(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	env := &core.Env{Config: config.TargetConfig{PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce}}}
	fixture := podTokenFixture{source: testPodTokenReadyPod("source-abc", "uid", "image")}
	ready := func(context.Context, corev1.Pod, string) (int, error) { return 200, nil }
	entered := make(chan struct{})
	sample := func(ctx context.Context, _ *core.Env, _ podTokenFixture) (time.Time, float64, string, error) {
		close(entered)
		<-ctx.Done()
		return time.Time{}, 0, "", ctx.Err()
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-entered; cancel() }()
	got, err := podTokenWarmMetricWith(parent, env, fixture, time.Second, 5*time.Millisecond, sample, ready)
	if !errors.Is(err, context.Canceled) || got.ProducerStatus == "MEASURED_FRESH" {
		t.Fatalf("caller cancellation was converted into telemetry admission: telemetry=%+v err=%v", got, err)
	}
}

func TestPodTokenProtectedLedgerExactAbsence(t *testing.T) {
	const nsUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const sourceUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	f := podTokenFixture{namespaceUID: types.UID(nsUID), source: testPodTokenReadyPod("source", sourceUID, "image")}
	name := podTokenLedgerName(f.namespaceUID)
	kube := fake.NewSimpleClientset()
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "voice", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{ManagerNamespace: "phorvex-system", ProtectedLedgerName: name}}}
	if ok, err := podTokenProtectedAbsence(context.Background(), env, f); err != nil || !ok {
		t.Fatalf("exact NotFound should establish absence: %v %v", ok, err)
	}
	ledger := fmt.Sprintf(`{"version":1,"namespace":"voice","namespaceUID":"%s","records":{}}`, nsUID)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "phorvex-system", UID: "cm-uid", ResourceVersion: "1", Labels: map[string]string{"phorvex.ai/quarantine-capacity": "v1"}}, Data: map[string]string{"ledger": ledger}}
	if _, err := kube.CoreV1().ConfigMaps("phorvex-system").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if ok, err := podTokenProtectedAbsence(context.Background(), env, f); err != nil || !ok {
		t.Fatalf("empty exact protected ledger: %v %v", ok, err)
	}
	row := func(uid string) string {
		return fmt.Sprintf(`{"operationID":"%s","phase":"ambiguous","namespace":"voice","namespaceUID":"%s","pod":"source","podUID":"%s","policyName":"policy","policyUID":"policy-uid","backend":"native"}`, strings.Repeat("a", 40), nsUID, uid)
	}
	oldUID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	cm.Data["ledger"] = fmt.Sprintf(`{"version":1,"namespace":"voice","namespaceUID":"%s","records":{"%s":%s}}`, nsUID, oldUID, row(oldUID))
	if _, err := kube.CoreV1().ConfigMaps("phorvex-system").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if ok, count, err := podTokenProtectedInventory(context.Background(), env, f); err != nil || !ok || count != 1 {
		t.Fatalf("unrelated old reservation should remain visible without blocking exact source absence: %v %d %v", ok, count, err)
	}
	cm.Data["ledger"] = fmt.Sprintf(`{"version":1,"namespace":"voice","namespaceUID":"%s","records":{"%s":%s}}`, nsUID, sourceUID, row(sourceUID))
	if _, err := kube.CoreV1().ConfigMaps("phorvex-system").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if ok, err := podTokenProtectedAbsence(context.Background(), env, f); err == nil || ok {
		t.Fatalf("source reservation falsely cleared: %v %v", ok, err)
	}
	env.Config.PodBoundTokenFixture.ProtectedLedgerName = "phorvex-quarantine-capacity-" + strings.Repeat("0", 40)
	if ok, err := podTokenProtectedAbsence(context.Background(), env, f); err == nil || ok {
		t.Fatalf("foreign reviewed ledger name accepted: %v %v", ok, err)
	}
}
