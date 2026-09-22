package defenders

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func installedManagerRuntimeFixture(t *testing.T) (*core.Env, *config.InstalledManagerFixtureConfig) {
	t.Helper()
	dir := t.TempDir()
	observer := filepath.Join(dir, "installed-audit-observer")
	observerRaw := []byte("pinned-observer")
	if err := os.WriteFile(observer, observerRaw, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	observerSum := sha256.Sum256(observerRaw)
	started := time.Date(2026, 9, 21, 22, 35, 0, 0, time.UTC)
	f := &config.InstalledManagerFixtureConfig{
		ManagerNamespace: "phorvex-system", ManagerServiceAccount: "phorvex-phorvex-manager", FixtureNonce: "installed-r1", AuthorizationDenyNamespace: "installed-r1-unowned", DeploymentName: "phorvex-phorvex", DeploymentUID: "11111111-2222-4333-8444-555555555555",
		ReplicaSetName: "phorvex-phorvex-7699c6dd69", ReplicaSetUID: "22222222-3333-4444-8555-666666666666",
		PodName: "phorvex-phorvex-7699c6dd69-k4j2n", PodUID: "33333333-4444-4555-8666-777777777777", ContainerName: "manager",
		Image: "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:0.4.144", ImageID: "docker-pullable://753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:" + strings.Repeat("4", 64), StartedAt: started.Format(time.RFC3339Nano),
		OCIRevision: "60aabe2a", ExpectedBrainImage: "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:0.4.144", TraceSchema: "phorvex.decision-trace.v6",
		PolicyCRDUID: "44444444-5555-4666-8777-888888888888", PolicyCRDResourceVersion: "150500", ObserverBinary: observer, ObserverBinarySHA256: fmt.Sprintf("%x", observerSum),
		AuditURL: "https://127.0.0.1:18445", AuditServerName: "phorvex-stack-phorvex-audit-source.phorvex-system.svc", AuditCAFile: filepath.Join(dir, "ca.crt"), AuditClientCertFile: filepath.Join(dir, "tls.crt"), AuditClientKeyFile: filepath.Join(dir, "tls.key"),
		ParameterManifestID: "phorvex-production-decision-parameters", ParameterManifestHash: "sha256:" + strings.Repeat("b", 64), ObservationTimeoutSeconds: 15, ObservationMaxBytes: 16 << 20, ObservationMaxRows: 512,
	}
	controller := true
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: f.DeploymentName, Namespace: f.ManagerNamespace, UID: types.UID(f.DeploymentUID)}, Status: appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: f.ReplicaSetName, Namespace: f.ManagerNamespace, UID: types.UID(f.ReplicaSetUID), OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: f.DeploymentName, UID: types.UID(f.DeploymentUID), Controller: &controller}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: f.PodName, Namespace: f.ManagerNamespace, UID: types.UID(f.PodUID), OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: f.ReplicaSetName, UID: types.UID(f.ReplicaSetUID), Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: f.ManagerServiceAccount, Containers: []corev1.Container{{Name: f.ContainerName, Image: f.Image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: f.ContainerName, ImageID: f.ImageID, RestartCount: 0, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(started)}}}}}}
	kube := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned-fixture", UID: "55555555-6666-4777-8888-999999999999"}}, deployment, rs, pod)
	crd := &unstructured.Unstructured{}
	crd.SetGroupVersionKind(phorvexPolicyCRDGVK)
	crd.SetName("phorvexpolicies.phorvex.ai")
	crd.SetUID(types.UID(f.PolicyCRDUID))
	crd.SetResourceVersion(f.PolicyCRDResourceVersion)
	scheme := runtime.NewScheme()
	ctrl := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(crd).Build()
	env := &core.Env{Kube: kube, Ctrl: ctrl, Config: config.TargetConfig{Namespace: "owned-fixture", InstalledManagerFixture: f}, Guard: allowGuard{allow: "owned-fixture"}, Log: &nopLogger{}}
	return env, f
}

func TestInstalledManagerRuntimeAcceptsActualTaggedImageAndImmutableImageID(t *testing.T) {
	env, f := installedManagerRuntimeFixture(t)
	if err := validateInstalledManagerRuntime(context.Background(), env); err != nil {
		t.Fatalf("actual runtime producer shape rejected: %v", err)
	}
	pod, err := env.Kube.CoreV1().Pods(f.ManagerNamespace).Get(context.Background(), f.PodName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Status.ContainerStatuses[0].ImageID = "docker-pullable://foreign@sha256:" + strings.Repeat("9", 64)
	if _, err := env.Kube.CoreV1().Pods(f.ManagerNamespace).UpdateStatus(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledManagerRuntime(context.Background(), env); err == nil {
		t.Fatal("changed immutable imageID accepted")
	}
}

func TestInstalledManagerDefenderSkipsWithoutExplicitFixture(t *testing.T) {
	defender := &installedPhorvex{}
	env := &core.Env{ScenarioName: "c2-installed-manager-session", Config: config.TargetConfig{Namespace: "owned-fixture"}}
	if err := defender.Setup(context.Background(), env); err != nil {
		t.Fatalf("absent optional fixture became a hard failure: %v", err)
	}
	if skip, reason := defender.SkipReason(); !skip || reason == "" {
		t.Fatalf("absent optional fixture did not become a visible skip: skip=%v reason=%q", skip, reason)
	}
	if err := defender.Teardown(context.Background(), env); err != nil {
		t.Fatalf("skipped defender attempted cleanup authority: %v", err)
	}
}

func TestInstalledPolicyKeepsPositiveBrakesAndTwoToOneAvailabilityTransition(t *testing.T) {
	env, _ := installedManagerRuntimeFixture(t)
	control := installedPolicyObject(env, installedControlPolicyName, 2, "active")
	eligible := installedPolicyObject(env, installedEligiblePolicyName, 1, "active")
	for _, policy := range []*unstructured.Unstructured{control, eligible} {
		if got, _, _ := unstructured.NestedString(policy.Object, "spec", "objective", "disruptionAversion"); got != "0.6" {
			t.Fatalf("disruptionAversion=%q", got)
		}
		if got, _, _ := unstructured.NestedString(policy.Object, "spec", "budget", "antiOverRotationWindow"); got != "90s" {
			t.Fatalf("antiOverRotationWindow=%q", got)
		}
		if got, _, _ := unstructured.NestedString(policy.Object, "spec", "budget", "proactiveFloor"); got != "1s" {
			t.Fatalf("proactiveFloor=%q", got)
		}
	}
	if got, _, _ := unstructured.NestedInt64(control.Object, "spec", "slo", "minAvailableReplicas"); got != 2 {
		t.Fatalf("control floor=%d", got)
	}
	if got, _, _ := unstructured.NestedInt64(eligible.Object, "spec", "slo", "minAvailableReplicas"); got != 1 {
		t.Fatalf("eligible floor=%d", got)
	}
}

func TestInstalledPolicyActualAPIAdmissionPreservesExactRequestedSpec(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Skip("KUBEBUILDER_ASSETS is required for the installed policy API admission control")
	}
	if !filepath.IsAbs(assets) {
		t.Fatal("KUBEBUILDER_ASSETS must be an absolute source-bound directory")
	}
	_, sourceFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("resolve installed policy test source path")
	}
	crdDirectory := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "phorvex", "config", "crd", "bases"))
	localOnly := false
	testAPI := &envtest.Environment{UseExistingCluster: &localOnly, BinaryAssetsDirectory: assets, CRDDirectoryPaths: []string{crdDirectory}, ErrorIfCRDPathMissing: true}
	restConfig, err := testAPI.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := testAPI.Stop(); err != nil {
			t.Error(err)
		}
	})
	ctrl, err := ctrlclient.New(restConfig, ctrlclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	kube, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatal(err)
	}
	const namespace = "installed-policy-admission"
	if _, err := kube.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	env := &core.Env{Ctrl: ctrl, Kube: kube, Config: config.TargetConfig{Namespace: namespace, InstalledManagerFixture: &config.InstalledManagerFixtureConfig{FixtureNonce: "actual-api"}}, Guard: allowGuard{allow: namespace}, Log: &nopLogger{}, Trial: 7}
	expected := installedPolicyObject(env, installedControlPolicyName, 2, "active")
	created := expected.DeepCopy()
	if err := ctrl.Create(context.Background(), created); err != nil {
		t.Fatal(err)
	}
	if !exactInstalledPolicyIdentity(created, expected) {
		t.Fatalf("actual API admitted policy differs from exact requested spec: %#v", created.Object["spec"])
	}
	if got, found, _ := unstructured.NestedString(created.Object, "spec", "slo", "costCeiling"); !found || got != "1.2" {
		t.Fatalf("current CRD costCeiling default differs: found=%v value=%q", found, got)
	}
	if got, found, _ := unstructured.NestedString(created.Object, "spec", "triggers", "eventAgeHorizon"); !found || got != "1h" {
		t.Fatalf("current CRD eventAgeHorizon default differs: found=%v value=%q", found, got)
	}
	for name, mutate := range map[string]func(*unstructured.Unstructured) error{
		"selector": func(policy *unstructured.Unstructured) error {
			return unstructured.SetNestedField(policy.Object, map[string]any{"fixture.phorvex.ai/session-target": "foreign"}, "spec", "selector", "matchLabels")
		},
		"mode": func(policy *unstructured.Unstructured) error {
			return unstructured.SetNestedField(policy.Object, "dryRun", "spec", "mode")
		},
		"actions": func(policy *unstructured.Unstructured) error {
			return unstructured.SetNestedSlice(policy.Object, []any{"noop"}, "spec", "actions", "enabled")
		},
		"minimum": func(policy *unstructured.Unstructured) error {
			return unstructured.SetNestedField(policy.Object, int64(1), "spec", "slo", "minAvailableReplicas")
		},
		"budget": func(policy *unstructured.Unstructured) error {
			return unstructured.SetNestedField(policy.Object, "89s", "spec", "budget", "antiOverRotationWindow")
		},
		"triggers": func(policy *unstructured.Unstructured) error {
			return unstructured.SetNestedField(policy.Object, true, "spec", "triggers", "reactiveOnly")
		},
	} {
		t.Run(name, func(t *testing.T) {
			drifted := created.DeepCopy()
			if err := mutate(drifted); err != nil {
				t.Fatal(err)
			}
			if exactInstalledPolicyIdentity(drifted, expected) {
				t.Fatal("changed admitted policy spec accepted")
			}
		})
	}
}

func installedObserverPhaseJSON(t *testing.T, f *config.InstalledManagerFixtureConfig, request installedObserveRequest, dispatch string) []byte {
	t.Helper()
	imageSum := sha256.Sum256([]byte(f.ExpectedBrainImage))
	receipt := map[string]any{
		"schemaVersion": "phorvex.installed-audit-receipt.v1", "decisionTime": request.NotBefore.Add(time.Second), "decisionID": "decision-1", "tickID": "tick-1",
		"policy":      map[string]any{"namespace": request.Namespace, "name": request.PolicyName, "uid": request.PolicyUID, "generation": request.PolicyGeneration},
		"target":      map[string]any{"namespace": request.Namespace, "name": request.TargetName, "uid": request.TargetUID},
		"traceSchema": f.TraceSchema, "brainImageSHA256": "sha256:" + hex.EncodeToString(imageSum[:]), "gitSHA": f.OCIRevision,
		"parameterEpoch": map[string]any{"schemaVersion": "phorvex.decision-parameter-set.v1", "manifestID": f.ParameterManifestID, "manifestHash": f.ParameterManifestHash, "policyOverridesID": fmt.Sprintf("%s/%s@%s:%d", request.Namespace, request.PolicyName, request.PolicyUID, request.PolicyGeneration), "policyOverridesHash": "sha256:" + strings.Repeat("c", 64)},
		"action":         "noop", "selected": false, "feasible": false, "dryRun": false, "actuated": false, "dispatchOutcome": "not-attempted",
		"actionDisposition": map[string]any{"action": "rotate", "status": "infeasible", "exclusionKind": "feasibility", "availabilityRefusal": map[string]any{"ready": 2, "removed": 1, "minAvailable": 2}},
		"rawSHA256":         "sha256:" + strings.Repeat("d", 64),
		"sourceRanges":      []any{map[string]any{"segmentID": "live", "generation": "10300-e", "anchor": "anchor", "pinnedSize": 4096, "start": 100, "end": 200, "sha256": "sha256:" + strings.Repeat("e", 64)}},
	}
	if dispatch == "emitted" {
		receipt["action"], receipt["selected"], receipt["feasible"], receipt["actuated"], receipt["dispatchOutcome"] = "rotate", true, true, true, "emitted"
		delete(receipt, "actionDisposition")
		receipt["handler"], receipt["mutationKind"] = "rotate", "Eviction"
		receipt["objectsTouched"] = []any{request.AllowedObject}
		receipt["gracefulTermination"] = map[string]any{"policyGeneration": request.PolicyGeneration, "policyGraceCapSeconds": int64(30), "workloadGraceSeconds": int64(30), "workloadGraceExplicit": true, "effectiveGracePeriodSeconds": *request.ExpectedGrace, "podResourceVersion": request.TargetRV, "terminationStatus": "unconfirmed"}
	}
	summary := map[string]any{"schemaVersion": "phorvex.installed-audit-summary.v1", "status": "complete", "attribution": "observed", "startedAt": request.NotBefore, "completedAt": request.NotAfter, "notBefore": request.NotBefore, "notAfter": request.NotAfter, "bytesRead": 200, "rowsRead": 1, "receipts": 1}
	rawReceipt, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	rawSummary, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(rawReceipt, '\n'), append(rawSummary, '\n')...)
}

func TestInstalledObserverReceiptConsumerBindsRefusalDispatchAndPartialFailure(t *testing.T) {
	_, f := installedManagerRuntimeFixture(t)
	start := time.Date(2026, 9, 22, 0, 1, 2, 3, time.UTC)
	grace := int64(30)
	request := installedObserveRequest{Namespace: "owned-fixture", PolicyName: installedControlPolicyName, PolicyUID: "55555555-6666-4777-8888-999999999999", PolicyGeneration: 2, TargetName: "target-0", TargetUID: "66666666-7777-4888-8999-000000000000", NotBefore: start, NotAfter: start.Add(10 * time.Second)}

	control, err := parseInstalledObservation(installedObserverPhaseJSON(t, f, request, "not-attempted"))
	if err != nil || validateInstalledObservation(f, request, control) != nil || !control.safeAvailabilityRefusal() {
		t.Fatalf("exact safe refusal rejected: observation=%+v err=%v", control, errors.Join(err, validateInstalledObservation(f, request, control)))
	}
	control.receipts[0].ActionDisposition.AvailabilityRefusal.Ready = 1
	if control.safeAvailabilityRefusal() {
		t.Fatal("non-availability feasibility exclusion was promoted to the exact floor refusal")
	}
	control.receipts[0].ActionDisposition.AvailabilityRefusal = nil
	if control.safeAvailabilityRefusal() {
		t.Fatal("untyped feasibility exclusion was promoted to an availability refusal")
	}
	control, err = parseInstalledObservation(installedObserverPhaseJSON(t, f, request, "not-attempted"))
	if err != nil {
		t.Fatal(err)
	}
	mixedControl := control.receipts[0]
	mixedControl.DispatchOutcome = "dispatch-error"
	mixedControl.Action = "rotate"
	mixedControl.ActionDisposition = nil
	control.receipts = append(control.receipts, mixedControl)
	if control.safeAvailabilityRefusal() {
		t.Fatal("an exact refusal followed by a failed attempt was accepted as a safe control phase")
	}
	request.PolicyName, request.TargetRV, request.ExpectedGrace, request.AllowedObject = installedEligiblePolicyName, "174200", &grace, "Pod/owned-fixture/target-0"
	emitted, err := parseInstalledObservation(installedObserverPhaseJSON(t, f, request, "emitted"))
	if err != nil || validateInstalledObservation(f, request, emitted) != nil {
		t.Fatalf("exact dispatch receipt rejected: %v", errors.Join(err, validateInstalledObservation(f, request, emitted)))
	}
	disposition, actionAt, err := emitted.disposition()
	if err != nil || disposition != "dispatched-unconfirmed" || actionAt == nil || !actionAt.Equal(start.Add(time.Second)) {
		t.Fatalf("dispatch classification=%q at=%v err=%v", disposition, actionAt, err)
	}
	noop := control.receipts[0]
	noop.DecisionTime = start.Add(2 * time.Second)
	failed := noop
	failed.DecisionTime = start.Add(time.Second)
	failed.Action = "rotate"
	failed.DispatchOutcome = "dispatch-error"
	failed.ActionDisposition = nil
	for name, receipts := range map[string][]installedAuditReceipt{
		"early-error-later-noop": {failed, noop},
		"early-noop-later-error": {noop, failed},
	} {
		t.Run(name, func(t *testing.T) {
			got, at, classifyErr := (installedObservation{receipts: receipts}).disposition()
			if classifyErr == nil || got != "unknown" || at != nil {
				t.Fatalf("ambiguous dispatch was erased by ordering: disposition=%q at=%v err=%v", got, at, classifyErr)
			}
		})
	}
	emittedFalse := failed
	emittedFalse.DispatchOutcome = "emitted-false"
	if got, at, classifyErr := (installedObservation{receipts: []installedAuditReceipt{emittedFalse, noop}}).disposition(); classifyErr == nil || got != "unknown" || at != nil {
		t.Fatalf("emitted-false became a refused/no-action effect: disposition=%q at=%v err=%v", got, at, classifyErr)
	}
	explicitRefusal := failed
	explicitRefusal.DispatchOutcome = "refused-no-effect"
	if got, at, classifyErr := (installedObservation{receipts: []installedAuditReceipt{noop, explicitRefusal}}).disposition(); classifyErr != nil || got != "refused" || at != nil {
		t.Fatalf("explicit no-effect refusal classification differs: disposition=%q at=%v err=%v", got, at, classifyErr)
	}

	wrong := installedObserverPhaseJSON(t, f, request, "emitted")
	wrong = bytes.Replace(wrong, []byte(request.TargetRV), []byte("wrong-rv"), 1)
	parsedWrong, parseErr := parseInstalledObservation(wrong)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if err := validateInstalledObservation(f, request, parsedWrong); err == nil {
		t.Fatal("wrong emitted target resourceVersion accepted")
	}

	lines := bytes.Split(bytes.TrimSpace(installedObserverPhaseJSON(t, f, request, "emitted")), []byte{'\n'})
	var invalidSummary map[string]any
	if err := json.Unmarshal(lines[1], &invalidSummary); err != nil {
		t.Fatal(err)
	}
	invalidSummary["status"], invalidSummary["errorClass"] = "invalid", "source-read"
	invalidRaw, _ := json.Marshal(invalidSummary)
	partial, partialErr := parseInstalledObservation(append(append(lines[0], '\n'), append(invalidRaw, '\n')...))
	if partialErr == nil || len(partial.receipts) != 1 || partial.raw == "" || partial.summary.ErrorClass != "source-read" {
		t.Fatalf("prior receipt not retained with later observer failure: receipts=%d raw=%d summary=%+v err=%v", len(partial.receipts), len(partial.raw), partial.summary, partialErr)
	}
}

func TestInstalledObserverOutputBufferRefusesBeforeUnboundedGrowth(t *testing.T) {
	buffer := &installedBoundedBuffer{limit: 8}
	if n, err := buffer.Write([]byte("123456")); err != nil || n != 6 {
		t.Fatalf("bounded write n=%d err=%v", n, err)
	}
	if n, err := buffer.Write([]byte("7890")); err == nil || n != 2 || !buffer.exceeded || buffer.Len() != 8 || buffer.String() != "12345678" {
		t.Fatalf("overflow not bounded: n=%d err=%v exceeded=%v len=%d value=%q", n, err, buffer.exceeded, buffer.Len(), buffer.String())
	}
}

func TestInstalledFixtureEvictionRBACMatchesNamelessGateAndStaysInOwnedNamespace(t *testing.T) {
	env, f := installedManagerRuntimeFixture(t)
	kube := env.Kube.(*fake.Clientset)
	kube.PrependReactor("create", "roles", func(action k8stesting.Action) (bool, runtime.Object, error) {
		role := action.(k8stesting.CreateAction).GetObject().(*rbacv1.Role)
		role.UID = "77777777-8888-4999-8aaa-111111111111"
		return false, nil, nil
	})
	kube.PrependReactor("create", "rolebindings", func(action k8stesting.Action) (bool, runtime.Object, error) {
		binding := action.(k8stesting.CreateAction).GetObject().(*rbacv1.RoleBinding)
		binding.UID = "88888888-9999-4aaa-8bbb-222222222222"
		return false, nil, nil
	})
	var reviews []authorizationv1.ResourceAttributes
	kube.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		attrs := review.Spec.ResourceAttributes
		wantGroups := []string{"system:serviceaccounts", "system:serviceaccounts:" + f.ManagerNamespace, "system:authenticated"}
		if review.Spec.User != "system:serviceaccount:"+f.ManagerNamespace+":"+f.ManagerServiceAccount || !slicesEqualInstalled(review.Spec.Groups, wantGroups) || attrs == nil || attrs.Group != "" || attrs.Version != "v1" || attrs.Resource != "pods" || attrs.Subresource != "eviction" || attrs.Verb != "create" {
			t.Fatalf("SubjectAccessReview shape differs: %+v", review.Spec)
		}
		reviews = append(reviews, *attrs.DeepCopy())
		review.Status.Allowed = attrs.Namespace == env.Config.Namespace
		return true, review, nil
	})

	roleUID, bindingUID, err := createInstalledEvictionRBAC(context.Background(), env, "target-0", "66666666-7777-4888-8999-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledEvictionRBAC(context.Background(), env, "target-0"); err != nil {
		t.Fatal(err)
	}
	if len(reviews) != 3 || reviews[0].Namespace != env.Config.Namespace || reviews[0].Name != "" || reviews[1].Namespace != env.Config.Namespace || reviews[1].Name != "target-0" || reviews[2].Namespace != f.AuthorizationDenyNamespace || reviews[2].Name != "" {
		t.Fatalf("fixture/target/unrelated authorization controls differ: %+v", reviews)
	}
	role, err := env.Kube.RbacV1().Roles(env.Config.Namespace).Get(context.Background(), installedEvictionRoleName, metav1.GetOptions{})
	if err != nil || !exactInstalledEvictionRole(role, env, "target-0", "66666666-7777-4888-8999-000000000000") || len(role.Rules) != 1 || len(role.Rules[0].APIGroups) != 1 || role.Rules[0].APIGroups[0] != "" || len(role.Rules[0].ResourceNames) != 0 {
		t.Fatalf("exact core pods/eviction Role differs: role=%+v err=%v", role, err)
	}
	binding, err := env.Kube.RbacV1().RoleBindings(env.Config.Namespace).Get(context.Background(), installedEvictionRoleName, metav1.GetOptions{})
	if err != nil || !exactInstalledEvictionRoleBinding(binding, env, "66666666-7777-4888-8999-000000000000") {
		t.Fatalf("exact manager-SA RoleBinding differs: binding=%+v err=%v", binding, err)
	}
	request := core.TargetedActionRequest{Namespace: env.Config.Namespace, TargetName: "target-0", TargetUID: "66666666-7777-4888-8999-000000000000"}
	receipt, err := installedAuthorizationReceipt(env, request, roleUID, bindingUID)
	if err != nil || !strings.Contains(receipt, `"namelessFixtureAllowed":true`) || !strings.Contains(receipt, `"namedTargetAllowed":true`) || !strings.Contains(receipt, `"unrelatedNamespaceDenied":true`) || !strings.Contains(receipt, f.AuthorizationDenyNamespace) || strings.Contains(receipt, f.AuditClientKeyFile) {
		t.Fatalf("authorization receipt invalid or leaked private path: receipt=%s err=%v", receipt, err)
	}

	p := &installedPhorvex{roleUID: roleUID, roleBindingUID: bindingUID}
	if err := p.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Kube.RbacV1().Roles(env.Config.Namespace).Get(context.Background(), installedEvictionRoleName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("owned Role cleanup not verified: %v", err)
	}
	if _, err := env.Kube.RbacV1().RoleBindings(env.Config.Namespace).Get(context.Background(), installedEvictionRoleName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("owned RoleBinding cleanup not verified: %v", err)
	}
}
