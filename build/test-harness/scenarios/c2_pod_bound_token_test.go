package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
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
	svc.Spec.Selector = map[string]string{podTokenOwnerLabel: nonce}
	if _, err := kube.CoreV1().Services("voice").Update(context.Background(), svc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := podTokenDisjointPrecreate(context.Background(), env); err == nil {
		t.Fatal("old Voice Service selector overlap accepted")
	}
}

func TestPodTokenGeneratedNetworkPolicyOwnerIdentity(t *testing.T) {
	f := podTokenFixture{name: "pod-token-" + strings.Repeat("a", 24), policyUID: "policy-uid", policyGeneration: 1, source: testPodTokenReadyPod("source", "source-uid", "image")}
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
	f := podTokenFixture{name: "pod-token-" + nonce, policyUID: "policy-uid", policyGeneration: 3}
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

func TestPodTokenPromUsesActualScrapeTimestampAndSourceSeries(t *testing.T) {
	const pod = "source-abc"
	const nonce = "0123456789abcdef01234567"
	sample := time.Now().Add(-20 * time.Second).Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expression := r.URL.Query().Get("query")
		// A healthy fixture has a peer series with the same nonce. Every query,
		// including the rate query, must select the source Pod explicitly.
		if r.URL.Path != "/api/v1/query" || !strings.Contains(expression, `pod="`+pod+`"`) {
			http.Error(w, "bad query", 400)
			return
		}
		value := "7"
		if strings.HasPrefix(expression, "timestamp(") {
			value = strconv.FormatInt(sample, 10)
		}
		if strings.HasPrefix(expression, "sum by (pod)") {
			value = "0.2"
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pod":"%s","nonce":"%s"},"value":[%d,"%s"]}]}}`, pod, nonce, time.Now().Unix(), value)
	}))
	defer server.Close()
	env := &core.Env{Config: config.TargetConfig{Namespace: "voice", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{Nonce: nonce, PrometheusURL: server.URL}}}
	at, count, hash, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")})
	if err != nil || at.Unix() != sample || count != 7 || len(hash) != 64 {
		t.Fatalf("actual scrape sample: at=%s count=%f hash=%q err=%v", at, count, hash, err)
	}
	sample = time.Now().Add(-3 * time.Minute).Unix()
	if _, _, _, err := podTokenMetricSample(context.Background(), env, podTokenFixture{source: testPodTokenReadyPod(pod, "uid", "image")}); err == nil {
		t.Fatal("old scrape accepted from fresh instant query evaluation")
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
