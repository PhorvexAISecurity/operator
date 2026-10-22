package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	phorvexv1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const newstackTestGuard = "installed-identity-guard"

type newstackTestClient struct {
	client.Client
	beforeCreate   func(client.Object)
	afterCreate    func(client.Object)
	beforeDelete   func(client.Object, *client.DeleteOptions)
	deniedResource string
	identity       string
}

func (c *newstackTestClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	switch review := object.(type) {
	case *authenticationv1.SelfSubjectReview:
		review.Status.UserInfo.Username = c.identity
		return nil
	case *authorizationv1.SelfSubjectAccessReview:
		review.Status.Allowed = review.Spec.ResourceAttributes.Resource != c.deniedResource
		return nil
	}
	if c.beforeCreate != nil {
		c.beforeCreate(object)
	}
	object.SetUID(types.UID("uid-" + object.GetName()))
	object.SetGeneration(1)
	object.SetCreationTimestamp(metav1.Now())
	if object.GetObjectKind().GroupVersionKind().Kind == "SecurityEvent" {
		annotations := object.GetAnnotations()
		annotations[eventtrust.CreatorIdentityAnnotation] = eventtrust.Injector()
		object.SetAnnotations(annotations)
	}
	if err := c.Client.Create(ctx, object, options...); err != nil {
		return err
	}
	if c.afterCreate != nil {
		c.afterCreate(object)
	}
	return nil
}
func (c *newstackTestClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	opts := &client.DeleteOptions{}
	for _, option := range options {
		option.ApplyToDelete(opts)
	}
	if c.beforeDelete != nil {
		c.beforeDelete(object, opts)
	}
	return c.Client.Delete(ctx, object, options...)
}

func newstackTestObjects() []client.Object {
	fail, scope := admissionv1.Fail, admissionv1.AllScopes
	return []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: newstackNamespace, UID: "staging-namespace-uid"}},
		&admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: newstackTestGuard}, Spec: admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admissionv1.MatchResources{ResourceRules: []admissionv1.NamedRuleWithOperations{{RuleWithOperations: admissionv1.RuleWithOperations{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{"amtd.r6security.com"}, APIVersions: []string{"*"}, Resources: []string{"securityevents"}, Scope: &scope}}}}}, Variables: []admissionv1.Variable{{Name: "claim", Expression: "has(object.metadata.annotations) && 'phorvex.ai/creator-identity' in object.metadata.annotations ? object.metadata.annotations['phorvex.ai/creator-identity'] : ''"}, {Name: "actor", Expression: "request.userInfo.username"}}, Validations: []admissionv1.Validation{{Expression: "variables.claim == '' || variables.claim == variables.actor"}}}},
		&admissionv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: newstackTestGuard}, Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: newstackTestGuard, ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny}}},
	}
}

func newstackTestRuntime(t *testing.T, index int) (*newstackRuntime, *newstackTestClient, newstackCase) {
	t.Helper()
	old := eventtrust.Injector()
	if err := eventtrust.ConfigureInjector("phorvex-staging/staging-attacks"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eventtrust.ConfigureInjector(old) })
	t.Setenv("PHORVEX_CRM_REFUND_NAMESPACE", newstackNamespace)
	item := newstackCases[index]
	run := &newstackRun{Schema: "newstack-run-v1", RunID: "ns-" + strings.Repeat("a", 32), CaseID: item.ID, Namespace: newstackNamespace, Status: "running", Verdict: "UNKNOWN", Phase: "intent", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Objects: []newstackObject{}, Issues: []string{}}
	kube := &newstackTestClient{Client: fake.NewClientBuilder().WithScheme(newstackScheme()).WithObjects(newstackTestObjects()...).Build(), identity: eventtrust.Injector()}
	server := &Server{cfg: Config{StateDir: t.TempDir(), NewstackLoopsEnabled: true, NewstackIdentityPolicy: newstackTestGuard, PodNamespace: newstackNamespace, newstackClient: kube}}
	if err := server.newstackSave(run); err != nil {
		t.Fatal(err)
	}
	w, err := server.newstackRuntime(run)
	if err != nil {
		t.Fatal(err)
	}
	return w, kube, item
}

func TestNewstackRoutesFixedScopeAndStrictInputs(t *testing.T) {
	for _, grant := range []SubjectGrant{operatorGrant("alb-subject-1", []string{"voice"}, []string{defaultTargetID}), investorGrant("alb-subject-1", []string{newstackNamespace}, []string{defaultTargetID})} {
		f := newAuthFixture(t, Config{Root: ".", StateDir: t.TempDir()}, grant)
		for _, path := range []string{newstackFireRoute, "/api/newstack/cleanup"} {
			w := f.do(f.albReq(t, http.MethodPost, path, `{"caseId":"newstack:voice-rotate"}`))
			if w.Code != 403 {
				t.Fatalf("scope/role admitted %s: %d %s", path, w.Code, w.Body.String())
			}
		}
	}
	f := newAuthFixture(t, Config{Root: ".", StateDir: t.TempDir()}, operatorGrant("alb-subject-1", []string{newstackNamespace}, []string{defaultTargetID}))
	if w := f.do(f.albReq(t, http.MethodGet, "/api/newstack/catalog", "")); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled catalog: %d %s", w.Code, w.Body.String())
	}
	for _, body := range []string{`{}`, `{"caseId":"unknown"}`, `{"caseId":"newstack:voice-rotate","namespace":"voice"}`, `{"caseId":"newstack:voice-rotate","target":"prod"}`, `{"caseId":"newstack:voice-rotate"}{}`} {
		if w := f.do(f.albReq(t, http.MethodPost, newstackFireRoute, body)); w.Code != 400 {
			t.Fatalf("accepted %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := f.do(f.albReq(t, http.MethodPost, newstackFireRoute+"?namespace=voice", `{"caseId":"newstack:voice-rotate"}`)); w.Code != 400 {
		t.Fatalf("accepted destination query %d", w.Code)
	}
	if w := f.do(f.albReq(t, http.MethodPost, newstackFireRoute, `{"caseId":"newstack:voice-rotate"}`)); w.Code != 503 {
		t.Fatalf("disabled Fire=%d", w.Code)
	}
	for _, rt := range f.srv.apiRoutes() {
		if strings.HasPrefix(rt.path, "/api/newstack/") && (!rt.spec.attacks || rt.spec.fixedTenant != newstackNamespace || rt.spec.fixedTarget != defaultTargetID) {
			t.Fatalf("route contract drift: %+v", rt)
		}
	}
}

func TestNewstackPreflightIsReadOnlyAndRejectsIdentityPermissionsAndCollisions(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 2)
	kube.beforeCreate = func(client.Object) { t.Fatal("preflight attempted a persistent CREATE") }
	if err := w.preflight(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	kube.deniedResource = "deployments"
	if err := w.preflight(t.Context(), item); err == nil {
		t.Fatal("missing fixture permission accepted")
	}
	kube.deniedResource = ""
	kube.identity = "system:serviceaccount:voice:other"
	if err := w.preflight(t.Context(), item); err == nil {
		t.Fatal("wrong running identity accepted")
	}
	kube.identity = eventtrust.Injector()
	existing := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: newstackNamespace, Name: "crm", UID: "unowned"}}
	if err := kube.Client.Create(t.Context(), existing); err != nil {
		t.Fatal(err)
	}
	if err := w.preflight(t.Context(), item); err == nil {
		t.Fatal("fixed CRM Service collision accepted")
	}
}

func TestNewstackIntentProvisioningAndNativePolicy(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 2)
	count := 0
	kube.beforeCreate = func(object client.Object) {
		count++
		saved, err := w.server.newstackLoad(w.run.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if object.GetName() == newstackLaneName {
			if saved.Phase != "intent" {
				t.Fatalf("lane preceded intent: %+v", saved)
			}
			return
		}
		if len(saved.Objects) == 0 || saved.Objects[len(saved.Objects)-1].Name != object.GetName() {
			t.Fatalf("CREATE preceded exact object intent: %s %+v", object.GetName(), saved.Objects)
		}
		if !newstackOwned(object, w.run) {
			t.Fatalf("ownership absent before CREATE: %s", object.GetName())
		}
	}
	if err := w.acquire(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := w.provision(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := w.policy(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if count != 7 {
		t.Fatalf("unexpected persistent objects %d", count)
	}
	deploy := &appsv1.Deployment{}
	if err := kube.Get(t.Context(), client.ObjectKey{Namespace: newstackNamespace, Name: "crm"}, deploy); err != nil {
		t.Fatal(err)
	}
	if *deploy.Spec.Replicas != 2 || *deploy.Spec.Template.Spec.AutomountServiceAccountToken || deploy.Spec.Template.Labels[newstackFixtureLabel] != "crm-refund" || deploy.Spec.Template.Labels["app"] != "crm" || deploy.Spec.Template.Spec.Containers[0].Image != newstackFixtureImage {
		t.Fatalf("fixture shape drift: %+v", deploy.Spec)
	}
	for _, volume := range deploy.Spec.Template.Spec.Volumes {
		if volume.Secret != nil {
			t.Fatal("fixture mounts credentials")
		}
	}
	pdb := &policyv1.PodDisruptionBudget{}
	if err := kube.Get(t.Context(), client.ObjectKey{Namespace: newstackNamespace, Name: "crm"}, pdb); err != nil || pdb.Spec.MinAvailable.IntVal != 1 {
		t.Fatalf("PDB floor missing: %+v %v", pdb, err)
	}
	policy := &phorvexv1.PhorvexPolicy{}
	if err := kube.Get(t.Context(), client.ObjectKey{Namespace: newstackNamespace, Name: "crm-defense"}, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Spec.Mode != "active" || len(policy.Spec.Actions.Enabled) != 1 || string(policy.Spec.Actions.Enabled[0]) != item.Action || policy.Spec.SLO.MinAvailableReplicas != 1 || policy.Spec.SLO.CostCeiling != "1000" || policy.Spec.AssetValue.FromLabels["data-class"]["restricted"] != "1.0" {
		t.Fatalf("native fixture profile drift: %+v", policy.Spec)
	}
	raw, err := os.ReadFile(filepath.Join(w.server.cfg.StateDir, "newstack", w.run.RunID, "object-06-created.json"))
	if err != nil || !bytes.Contains(raw, []byte("crm-refund-revoke")) {
		t.Fatalf("original policy evidence missing: %v", err)
	}
}

func TestNewstackSharedLaneAndCrashCleanupUIDGuards(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 0)
	if err := w.acquire(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := w.provision(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	original := w.run.Objects[0]
	// A missing CREATE acknowledgement is reconciled by the exact durable name,
	// nonce and namespace, then deleted using the freshly persisted UID.
	w.run.Objects[0].UID = ""
	kube.beforeDelete = func(object client.Object, options *client.DeleteOptions) {
		if object.GetObjectKind().GroupVersionKind().Kind == "Pod" {
			t.Fatal("runner deleted a Pod")
		}
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != object.GetUID() || options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != object.GetResourceVersion() {
			t.Fatalf("delete lacked exact UID/RV guards: %s %+v", object.GetName(), options)
		}
	}
	if err := w.cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w.run.Objects[0].UID != original.UID || !w.run.CleanupComplete || !w.run.PostflightClean {
		t.Fatalf("cleanup evidence incomplete %+v", w.run)
	}
	if err := kube.Get(t.Context(), client.ObjectKey{Namespace: newstackNamespace, Name: newstackLaneName}, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		t.Fatalf("lane survived cleanup: %v", err)
	}
	saved, err := w.server.newstackLoad(w.run.RunID)
	if err != nil || !saved.CleanupComplete {
		t.Fatalf("cleanup not durable: %+v %v", saved, err)
	}
}

func TestNewstackCleanupRefusesReplacedUIDAndKeepsLane(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 0)
	if err := w.acquire(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := w.provision(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	ref := w.run.Objects[0]
	cm := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: newstackNamespace, Name: ref.Name}
	if err := kube.Get(t.Context(), key, cm); err != nil {
		t.Fatal(err)
	}
	if err := kube.Client.Delete(t.Context(), cm); err != nil {
		t.Fatal(err)
	}
	cm.ResourceVersion = ""
	cm.UID = "replacement-uid"
	if err := kube.Client.Create(t.Context(), cm); err != nil {
		t.Fatal(err)
	}
	if err := w.cleanup(t.Context()); err == nil {
		t.Fatal("cleanup deleted replacement UID")
	}
	if err := kube.Get(t.Context(), key, cm); err != nil || cm.UID != "replacement-uid" {
		t.Fatalf("replacement not preserved: %v", err)
	}
	if err := kube.Get(t.Context(), client.ObjectKey{Namespace: newstackNamespace, Name: newstackLaneName}, &corev1.ConfigMap{}); err != nil {
		t.Fatal("uncertain cleanup released shared lane")
	}
}

func TestNewstackLocalLaneAndOrphanInventory(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 0)
	unlock, err := w.server.newstackLocalLock()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := w.server.newstackLocalLock(); err == nil {
		second()
		t.Fatal("concurrent local run admitted")
	}
	unlock()
	cm := &corev1.ConfigMap{ObjectMeta: w.metadata("owned-orphan", item)}
	if err := kube.Client.Create(t.Context(), cm); err != nil {
		t.Fatal(err)
	}
	clean, err := w.orphans(t.Context(), item)
	if err != nil || clean {
		t.Fatalf("orphan inventory falsely clean: %t %v", clean, err)
	}
	if err := kube.Client.Delete(t.Context(), cm); err != nil {
		t.Fatal(err)
	}
	if clean, err = w.orphans(t.Context(), item); err != nil || !clean {
		t.Fatalf("empty inventory not clean: %t %v", clean, err)
	}
}

func newstackDecisionFixture(run *newstackRun, item newstackCase, now time.Time) audit.Record {
	trace := caseTraceValidTrace(now, true, false)
	trace.PolicyNamespace = newstackNamespace
	trace.PolicyName = newstackResourceName(item, run) + "-defense"
	trace.PolicyUID = run.PolicyUID
	trace.TenantName = newstackNamespace
	trace.AssetNamespace = newstackNamespace
	trace.AssetName = run.TargetPod
	trace.AssetUID = run.TargetUID
	trace.DispatchOutcome = model.DispatchEmitted
	event := genericCaseEvent(run.Stimulus.EventUID, run.TargetUID, eventtrust.TrustTrusted)
	event.Name = run.Stimulus.EventName
	event.Type = run.Stimulus.EventRule
	event.Source = "redteam"
	event.CreatorIdentity = eventtrust.Injector()
	return audit.Record{Kind: "phorvex.decision", Time: now, Namespace: newstackNamespace, Pod: run.TargetPod, Action: "rotate", Selected: true, Actuated: true, Feasible: true, DispatchOutcome: model.DispatchEmitted, DecisionTrace: trace, Events: []model.EventEvidence{event}}
}

func TestNewstackDecisionRequiresFreshExactTrustedEventTargetPolicyAndDispatch(t *testing.T) {
	w, _, item := newstackTestRuntime(t, 0)
	now := time.Now().UTC()
	w.run.BaselineAt = now.Add(-2 * time.Second).Format(time.RFC3339Nano)
	w.run.TargetPod = "fixture-a"
	w.run.TargetUID = "pod-old"
	w.run.PolicyUID = "policy-uid"
	w.run.Stimulus = &attackStimulusEvidence{Observed: true, TargetUID: w.run.TargetUID, EventName: "signal", EventUID: "event-uid", EventRule: "Panic", EventCreatedAt: now.Add(-time.Second).Format(time.RFC3339Nano)}
	row := newstackDecisionFixture(w.run, item, now)
	if err := row.DecisionTrace.Validate(); err != nil {
		t.Fatalf("invalid positive trace: %v", err)
	}
	if evidence, ok := newstackMatchDecision(row, w.run, item, now.Add(time.Second)); !ok || !evidence.Selected || !evidence.Actuated || evidence.DecisionID != "decision-1" {
		t.Fatalf("exact decision refused: %+v %t", evidence, ok)
	}
	for name, mutate := range map[string]func(*audit.Record){
		"stale":               func(r *audit.Record) { r.Time = now.Add(-3 * time.Second) },
		"wrong target":        func(r *audit.Record) { r.DecisionTrace.AssetUID = "other" },
		"wrong policy":        func(r *audit.Record) { r.DecisionTrace.PolicyUID = "other" },
		"wrong event":         func(r *audit.Record) { r.Events[0].EventUID = "other" },
		"untrusted":           func(r *audit.Record) { r.Events[0].TrustVerdict = "untrusted-identity" },
		"wrong creator":       func(r *audit.Record) { r.Events[0].CreatorIdentity = "someone" },
		"other trusted input": func(r *audit.Record) { r.Events = append(r.Events, r.Events[0]) },
		"dispatch mismatch":   func(r *audit.Record) { r.DispatchOutcome = model.DispatchRefused },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(row)
			var candidate audit.Record
			_ = json.Unmarshal(raw, &candidate)
			mutate(&candidate)
			if _, ok := newstackMatchDecision(candidate, w.run, item, now.Add(time.Second)); ok {
				t.Fatal("unrelated audit row earned attribution")
			}
		})
	}
}

func TestNewstackFixtureSourceParity(t *testing.T) {
	raw, err := os.ReadFile("../../../build/test-harness/newstack/fixture.py")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != newstackFixtureSource {
		t.Fatal("reviewable fixture source differs from compiled bytes")
	}
}

// A remote authenticated audit server keeps orchestration tests on the actual
// source-reader boundary. It does not replace a verdict or an oracle flag.
func newstackRemoteAudit(t *testing.T) (*audittransport.Client, string) {
	t.Helper()
	dir := t.TempDir()
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte("{\"kind\":\"startup\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := audittransport.ServerConfig{AuditPath: path, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test"}
	source := httptest.NewUnstartedServer(cfg.Handler())
	source.TLS = cfg.TLSConfig()
	source.StartTLS()
	t.Cleanup(source.Close)
	remote, err := audittransport.NewClient(audittransport.ClientConfig{URL: source.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	return remote, path
}

type newstackRoundTrip func(*http.Request) (*http.Response, error)

func (fn newstackRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func newstackReply(status int, value any) (*http.Response, error) {
	raw, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
}

func TestNewstackForegroundRotateFullChainAndFinallyCleanup(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 0)
	remote, auditPath := newstackRemoteAudit(t)
	w.server.cfg.AuditSource = remote
	w.server.cfg.AuditSourceIdentity = "local-authenticated-source"
	var mu sync.Mutex
	markers := map[string]bool{}
	uids := map[string]string{"10.45.0.1": "pod-old", "10.45.0.2": "pod-peer", "10.45.0.3": "pod-new"}
	w.http = &http.Client{Transport: newstackRoundTrip(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		ip := strings.Split(r.URL.Host, ":")[0]
		uid := uids[ip]
		if uid == "" {
			return nil, errors.New("unexpected destination")
		}
		switch r.URL.Path {
		case "/health":
			return newstackReply(200, map[string]any{"ok": true, "pod_uid": uid})
		case "/foothold":
			if r.Method == "POST" {
				markers[ip] = true
				return newstackReply(200, map[string]any{"pod_uid": uid, "installed": true})
			}
			values := []string{}
			if markers[ip] {
				values = append(values, w.run.RunID)
			}
			return newstackReply(200, map[string]any{"pod_uid": uid, "markers": values})
		}
		return newstackReply(404, map[string]string{})
	})}
	makePod := func(name, uid, ip string, age time.Duration) *corev1.Pod {
		meta := w.metadata(name, item)
		meta.UID = types.UID(uid)
		meta.CreationTimestamp = metav1.NewTime(time.Now().Add(-age))
		return &corev1.Pod{ObjectMeta: meta, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "fixture", Ready: true}}}}
	}
	old, peer, fresh := makePod("fixture-a", "pod-old", "10.45.0.1", 2*time.Second), makePod("fixture-b", "pod-peer", "10.45.0.2", time.Second), makePod("fixture-c", "pod-new", "10.45.0.3", 0)
	ready := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: newstackNamespace, Name: "fixture-endpoints", Labels: map[string]string{discoveryv1.LabelServiceName: newstackResourceName(item, w.run)}}, AddressType: discoveryv1.AddressTypeIPv4}
	endpoints := func(pods ...*corev1.Pod) []discoveryv1.Endpoint {
		out := []discoveryv1.Endpoint{}
		for _, p := range pods {
			out = append(out, discoveryv1.Endpoint{Addresses: []string{p.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: newstackNamespace, Name: p.Name, UID: p.UID}})
		}
		return out
	}
	var replacementDone chan struct{}
	kube.afterCreate = func(object client.Object) {
		switch object.GetObjectKind().GroupVersionKind().Kind {
		case "Deployment":
			if err := kube.Client.Create(t.Context(), old); err != nil {
				t.Fatal(err)
			}
			if err := kube.Client.Create(t.Context(), peer); err != nil {
				t.Fatal(err)
			}
			slice.Endpoints = endpoints(old, peer)
			if err := kube.Client.Create(t.Context(), slice); err != nil {
				t.Fatal(err)
			}
		case "SecurityEvent":
			// The simulated actuator owns this replacement; intercepted runner
			// Delete calls below remain limited to finally cleanup resources.
			if err := kube.Client.Delete(t.Context(), old); err != nil {
				t.Fatal(err)
			}
			slice.Endpoints = endpoints(peer)
			if err := kube.Client.Update(t.Context(), slice); err != nil {
				t.Fatal(err)
			}
			copyRun := *w.run
			copyStimulus := *w.run.Stimulus
			copyStimulus.EventUID = string(object.GetUID())
			copyStimulus.EventCreatedAt = object.GetCreationTimestamp().UTC().Format(time.RFC3339Nano)
			copyStimulus.Observed = true
			copyRun.Stimulus = &copyStimulus
			row := newstackDecisionFixture(&copyRun, item, time.Now().UTC())
			raw, _ := json.Marshal(row)
			file, err := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = file.Write(append(raw, '\n'))
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			replacementDone = make(chan struct{})
			go func() {
				defer close(replacementDone)
				time.Sleep(1200 * time.Millisecond)
				if err := kube.Client.Create(context.Background(), fresh); err != nil {
					t.Error(err)
					return
				}
				current := &discoveryv1.EndpointSlice{}
				if err := kube.Get(context.Background(), client.ObjectKeyFromObject(slice), current); err != nil {
					t.Error(err)
					return
				}
				current.Endpoints = endpoints(peer, fresh)
				if err := kube.Client.Update(context.Background(), current); err != nil {
					t.Error(err)
				}
			}()
		}
	}
	kube.beforeDelete = func(object client.Object, options *client.DeleteOptions) {
		if w.run.Phase != "cleanup" && w.run.Phase != "postflight-clean" {
			t.Errorf("runner removed %s before oracle finished", object.GetName())
		}
		if options.Preconditions == nil || options.Preconditions.UID == nil {
			t.Error("cleanup lacked UID guard")
		}
		if object.GetObjectKind().GroupVersionKind().Kind == "Deployment" {
			var pods corev1.PodList
			_ = kube.List(t.Context(), &pods, client.InNamespace(newstackNamespace))
			for i := range pods.Items {
				_ = kube.Client.Delete(t.Context(), &pods.Items[i])
			}
			var slices discoveryv1.EndpointSliceList
			_ = kube.List(t.Context(), &slices, client.InNamespace(newstackNamespace))
			for i := range slices.Items {
				_ = kube.Client.Delete(t.Context(), &slices.Items[i])
			}
		}
	}
	if err := w.runWithCleanup(item); err != nil {
		t.Fatalf("foreground loop: %v; run=%+v", err, w.run)
	}
	if replacementDone != nil {
		<-replacementDone
	}
	if w.run.Verdict != "DEFENDED" || w.run.Decision == nil || !w.run.Decision.Actuated || !w.run.MarkerCleared || !w.run.OldUIDAbsent || w.run.TargetUID != "pod-old" || w.run.ReplacementUID != "pod-new" || !w.run.CleanupComplete || !w.run.PostflightClean || w.run.MinimumReady < 1 || w.run.MinimumReadyEndpoints < 1 {
		t.Fatalf("full chain incomplete: %+v", w.run)
	}
	sawOne := false
	for _, sample := range w.run.AvailabilitySamples {
		sawOne = sawOne || sample.Ready == 1
	}
	if !sawOne {
		t.Fatalf("transition availability not measured: %+v", w.run.AvailabilitySamples)
	}
}

func TestNewstackUnexpectedFailureStillRunsExactCleanup(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 0)
	kube.afterCreate = func(object client.Object) {
		if object.GetObjectKind().GroupVersionKind().Kind == "Service" {
			panic("fixture failure")
		}
	}
	if err := w.runWithCleanup(item); err == nil {
		t.Fatal("unexpected panic was hidden")
	}
	if w.run.Verdict != "UNKNOWN" || !w.run.CleanupComplete || !w.run.PostflightClean {
		t.Fatalf("finally cleanup did not finish: %+v", w.run)
	}
}

func TestNewstackCRMObservationAndAllReplicaReplayOracle(t *testing.T) {
	w, kube, item := newstackTestRuntime(t, 2)
	if err := w.acquire(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := w.provision(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := w.policy(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	w.run.TargetPod = "crm-a"
	w.run.TargetUID = "target-pod-uid"
	w.run.PeerUID = "peer-pod-uid"
	w.run.BaselineAt = time.Now().UTC().Format(time.RFC3339Nano)
	w.run.BaselineLanded = true
	kube.afterCreate = func(object client.Object) {
		if object.GetObjectKind().GroupVersionKind().Kind != "SecurityEvent" {
			return
		}
		observation, err := crmrefund.ParseObservation(object.GetAnnotations()[crmrefund.ObservationAnnotation])
		if err != nil || observation.TargetPodUID != w.run.TargetUID || observation.PeerPodUID != w.run.PeerUID || observation.ServiceUID != w.run.ServiceUID || observation.GuardConfigMapUID != w.run.GuardUID || observation.PolicyUID != w.run.PolicyUID || observation.OrderID != crmLiveOrderID || observation.CallerAccountID == observation.OrderAccountID {
			t.Fatalf("exact CRM observation differs: %+v %v", observation, err)
		}
	}
	if err := w.event(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if w.run.Stimulus == nil || !w.run.Stimulus.Observed || w.run.Stimulus.EventUID == "" {
		t.Fatal("admitted CRM event identity absent")
	}
	pods := []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "crm-a", UID: types.UID(w.run.TargetUID)}, Status: corev1.PodStatus{PodIP: "10.50.0.1"}}, {ObjectMeta: metav1.ObjectMeta{Name: "crm-b", UID: types.UID(w.run.PeerUID)}, Status: corev1.PodStatus{PodIP: "10.50.0.2"}}}
	allGuarded, forbiddenDenied := false, true
	refunds := 0
	w.http = &http.Client{Transport: newstackRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/phorvex-guard/state" {
			ids := []string{}
			if allGuarded || strings.HasPrefix(request.URL.Host, "10.50.0.1:") {
				ids = append(ids, crmLiveOrderID)
			}
			return newstackReply(200, map[string]any{"denied_order_ids": ids})
		}
		var body struct {
			Order string `json:"order_id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		refunds++
		if body.Order == crmLiveOrderID && forbiddenDenied {
			return newstackReply(403, map[string]any{"error": "denied"})
		}
		return newstackReply(200, map[string]any{"refund_id": "RF-owned", "status": "issued", "order_id": body.Order, "amount": 0.01})
	})}
	if complete, err := w.crmOracle(t.Context(), item, pods); err != nil || complete {
		t.Fatalf("partial replica propagation earned credit: %t %v", complete, err)
	}
	allGuarded = true
	forbiddenDenied = false
	if complete, err := w.crmOracle(t.Context(), item, pods); err == nil || complete {
		t.Fatal("ConfigMap readback without denied replay earned credit")
	}
	forbiddenDenied = true
	refunds = 0
	if complete, err := w.crmOracle(t.Context(), item, pods); err != nil || !complete || refunds != 6 || !w.run.EveryReplicaDenied || !w.run.ReplayDenied || !w.run.LegitimateSucceeded {
		t.Fatalf("all-path exact revoke/control failed: %t %v refunds=%d", complete, err, refunds)
	}
}
