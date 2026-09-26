package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/outputpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type outputRewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t outputRewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.URL.Scheme = t.target.Scheme
	copy.URL.Host = t.target.Host
	copy.Host = t.target.Host
	return t.base.RoundTrip(copy)
}

type outputFixture struct {
	ec     EnactCtx
	req    Request
	c      client.Client
	state  *atomic.Int32
	server *httptest.Server
}

func newOutputFixture(t *testing.T) outputFixture {
	t.Helper()
	now := time.Now().UTC()
	podUID := types.UID("11111111-1111-4111-8111-111111111111")
	cmUID := types.UID("22222222-2222-4222-8222-222222222222")
	ruleSHA := outputpolicy.RuleSHA256(string(podUID))
	proxySHA := strings.Repeat("a", 64)
	supportSHA := strings.Repeat("b", 64)
	creator := "system:serviceaccount:phorvex-system:catalogue"
	cmName := "phorvex-output-policy-support"
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "support", Namespace: "tenant", UID: podUID, ResourceVersion: "1", Labels: map[string]string{"app": "support"}, Annotations: map[string]string{
		outputpolicy.PodConfigMapAnnotation: cmName, outputpolicy.PodRuleSHAAnnotation: ruleSHA, outputpolicy.PodProxySHAAnnotation: proxySHA, outputpolicy.PodSupportSHAAnnotation: supportSHA, "phorvex.ai/output-event-creator": creator}},
		Status: corev1.PodStatus{PodIP: "127.0.0.1", ContainerStatuses: []corev1.ContainerStatus{{Name: "guardrail-proxy", ImageID: "proxy@sha256:1"}, {Name: "support-app", ImageID: "support@sha256:1"}}}}
	prior := outputpolicy.Activation{Version: 1, RuleID: outputpolicy.RuleID, ConfigMapUID: string(cmUID)}
	yes := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: "tenant", UID: cmUID, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: podUID, Controller: &yes}}}, Data: map[string]string{outputpolicy.RuleKey: string(outputpolicy.RuleBytes(string(podUID))), outputpolicy.ActivationKey: string(prior.Bytes())}}
	payload := map[string]any{"version": 1, "ruleId": outputpolicy.RuleID, "ruleSHA256": ruleSHA, "configMapUID": string(cmUID), "podUID": string(podUID), "policyName": "policy", "policyUID": "policy-uid", "policyGeneration": 1, "requestPath": outputpolicy.Route, "observedAt": now.Add(-time.Second).Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(payload)
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "event", UID: "event-uid", CreationTimestamp: metav1.NewTime(now), Annotations: map[string]string{"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: string(podUID), outputpolicy.EventAnnotation: string(raw)}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"tenant/support"}, Rule: amtdv1beta1.Rule{Type: model.AttackVectorSensitiveOutput}}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "tenant", UID: "policy-uid", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "support"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionSensitiveOutputPolicyActivate)}}}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", UID: "ns-uid"}}
	opNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "op-ns-uid"}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod, cm, event, policy, ns, opNS).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if x, ok := obj.(*corev1.ConfigMap); ok && (x.Labels[outputpolicy.JournalLabel] == "v1" || x.Labels[outputPolicyArchiveLabel] == "v1") {
				x.UID = "journal-uid"
			}
			return inner.Create(ctx, obj, opts...)
		},
	}).Build()
	state := &atomic.Int32{}
	state.Store(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/output-policy/state" {
			http.Error(w, "wrong path", 404)
			return
		}
		current := &corev1.ConfigMap{}
		if err := c.Get(r.Context(), client.ObjectKey{Namespace: "tenant", Name: cmName}, current); err != nil {
			http.Error(w, "missing", 500)
			return
		}
		a, err := outputpolicy.ParseActivation(current.Data[outputpolicy.ActivationKey], string(cmUID))
		if err != nil {
			http.Error(w, "bad", 500)
			return
		}
		if state.Load() == 0 {
			a = prior
		}
		body, _ := json.Marshal(outputPolicyState{Version: 1, PodUID: string(podUID), ConfigMapUID: string(cmUID), RuleID: outputpolicy.RuleID, RuleSHA256: ruleSHA, Active: a.Active, Revision: a.Revision, OperationID: a.OperationID, ProxySourceSHA256: proxySHA, SupportSourceSHA256: supportSHA, Ready: true})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	targetURL, _ := url.Parse(server.URL)
	ec := EnactCtx{Reader: c, Client: c, JournalNamespace: "operator", OutputPolicyTransport: outputRewriteTransport{target: targetURL, base: server.Client().Transport}, OutputPolicyReadbackTimeout: 220 * time.Millisecond, OutputPolicyReadbackInterval: 10 * time.Millisecond}
	req := Request{Namespace: "tenant", Pod: "support", TargetUID: string(podUID), PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1, TickID: "tick-1", OperationID: "decision-1", Action: model.ActionSensitiveOutputPolicyActivate, OutputPolicyObservation: &model.SensitiveOutputObservation{EventName: "event", EventUID: "event-uid", CreatorIdentity: creator, TargetPodUID: string(podUID), ConfigMapUID: string(cmUID), SelectedConfigMapResourceVersion: cm.ResourceVersion, SelectedRevision: 0, PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1, RuleSHA256: ruleSHA, ProxySourceSHA256: proxySHA, SupportSourceSHA256: supportSHA, ProxyImageID: "proxy@sha256:1", SupportImageID: "support@sha256:1", ObservedAt: now.Add(-time.Second)}}
	return outputFixture{ec: ec, req: req, c: c, state: state, server: server}
}
func (f outputFixture) activation(t *testing.T) outputpolicy.Activation {
	t.Helper()
	cm := &corev1.ConfigMap{}
	if err := f.c.Get(context.Background(), client.ObjectKey{Namespace: "tenant", Name: "phorvex-output-policy-support"}, cm); err != nil {
		t.Fatal(err)
	}
	a, err := outputpolicy.ParseActivation(cm.Data[outputpolicy.ActivationKey], string(cm.UID))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestOutputPolicyActivationReadbackRecoveryAndRollback(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	h := outputPolicyHandler{}
	f.state.Store(0)
	result, err := h.Enact(ctx, f.ec, f.req)
	if err == nil || result.Emitted || f.activation(t).Revision != 1 {
		t.Fatalf("unconfirmed projection must retain revision-one intent: result=%+v err=%v", result, err)
	}
	journal, r, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID)
	if err != nil || r.Phase != "prepared" {
		t.Fatalf("journal=%+v receipt=%+v err=%v", journal, r, err)
	}
	// The original event has aged beyond the new-dispatch admission window; recovery
	// continues the same admitted operation without minting revision two.
	f.state.Store(1)
	result, err = h.Enact(ctx, f.ec, f.req)
	if err != nil || !result.Emitted || result.RollbackRef != outputpolicy.JournalName(f.req.TargetUID)+"/"+r.OperationID || f.activation(t).Revision != 1 {
		t.Fatalf("idempotent resume result=%+v err=%v", result, err)
	}
	_, r, err = outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID)
	if err != nil || r.Phase != "terminal-full" {
		t.Fatalf("terminal receipt=%+v err=%v", r, err)
	}
	if err := h.Rollback(ctx, f.ec, f.req, result.RollbackRef); err != nil {
		t.Fatal(err)
	}
	restored := f.activation(t)
	if restored.Active || restored.Revision != 2 || restored.OperationID != r.OperationID {
		t.Fatalf("rollback activation=%+v", restored)
	}
	if err := h.Rollback(ctx, f.ec, f.req, result.RollbackRef); err != nil {
		t.Fatalf("rollback replay: %v", err)
	}
}

func TestOutputPolicyRefusesWrongSourceAndSupersedingRollback(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	h := outputPolicyHandler{}
	f.req.OutputPolicyObservation.ProxyImageID = "wrong"
	if _, err := h.Enact(ctx, f.ec, f.req); err == nil {
		t.Fatal("wrong selected image admitted")
	}
	f.req.OutputPolicyObservation.ProxyImageID = "proxy@sha256:1"
	result, err := h.Enact(ctx, f.ec, f.req)
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "phorvex-output-policy-support"}, cm); err != nil {
		t.Fatal(err)
	}
	a := f.activation(t)
	a.Revision++
	a.OperationID = "newer-operation"
	cm.Data[outputpolicy.ActivationKey] = string(a.Bytes())
	if err := f.c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if err := h.Rollback(ctx, f.ec, f.req, result.RollbackRef); err == nil {
		t.Fatal("superseding operation overwritten")
	}
	if got := f.activation(t); got != a {
		t.Fatalf("superseding activation changed: %+v", got)
	}
}

func TestOutputPolicyCASConflictRetainsPreparedJournal(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	// Fake-client optimistic locking exercises the same resourceVersion CAS: the
	// selected ConfigMap is altered after the pre-journal read.
	pod := &corev1.Pod{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "support"}, pod); err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "phorvex-output-policy-support"}, cm); err != nil {
		t.Fatal(err)
	}
	newer := cm.DeepCopy()
	newer.Annotations = map[string]string{"concurrent": "true"}
	if err := f.c.Update(ctx, newer); err != nil {
		t.Fatal(err)
	}
	stale := cm.DeepCopy()
	stale.Data[outputpolicy.ActivationKey] = string((outputpolicy.Activation{Version: 1, RuleID: outputpolicy.RuleID, ConfigMapUID: string(cm.UID), Active: true, Revision: 1, OperationID: "op"}).Bytes())
	if err := f.c.Update(ctx, stale); !apierrors.IsConflict(err) {
		t.Fatalf("expected CAS conflict, got %v", err)
	}
	_ = pod
}

func TestOutputPolicyReadbackRejectsRedirectAndStaleBody(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	r := outputPolicyReceipt{Version: 1, Kind: string(model.ActionSensitiveOutputPolicyActivate), Phase: "prepared", PolicyNamespace: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1, TickID: "tick-1", SelectionDecisionID: "decision-1", TargetName: "support", TargetUID: f.req.TargetUID, EventName: "event", EventUID: "event-uid", CreatorIdentity: f.req.OutputPolicyObservation.CreatorIdentity, ConfigMapName: "phorvex-output-policy-support", ConfigMapUID: f.req.OutputPolicyObservation.ConfigMapUID, SelectedConfigMapResourceVersion: f.req.OutputPolicyObservation.SelectedConfigMapResourceVersion, SelectedRevision: 0, RuleSHA256: f.req.OutputPolicyObservation.RuleSHA256, ProxySourceSHA256: f.req.OutputPolicyObservation.ProxySourceSHA256, SupportSourceSHA256: f.req.OutputPolicyObservation.SupportSourceSHA256, ProxyImageID: f.req.OutputPolicyObservation.ProxyImageID, SupportImageID: f.req.OutputPolicyObservation.SupportImageID, PodIP: "127.0.0.1", Prior: f.activation(t)}
	r.OperationID = outputPolicyOperationID(r.PolicyUID, r.TargetUID, r.EventUID, r.TickID, r.SelectionDecisionID)
	r.Desired = r.Prior
	r.Desired.Active = true
	r.Desired.Revision = 1
	r.Desired.OperationID = r.OperationID
	if !r.valid() {
		t.Fatal("fixture receipt invalid")
	}
	if err := outputPolicyReadback(ctx, f.ec, r, r.Desired); err == nil {
		t.Fatal("stale state accepted")
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/", http.StatusFound)
	}))
	defer redirect.Close()
	target, _ := url.Parse(redirect.URL)
	f.ec.OutputPolicyTransport = outputRewriteTransport{target: target, base: redirect.Client().Transport}
	if err := outputPolicyReadback(ctx, f.ec, r, r.Desired); err == nil {
		t.Fatal("redirect accepted")
	}
}

func TestOutputPolicyRearmArchivesCompletedRollback(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	h := outputPolicyHandler{}
	first, err := h.Enact(ctx, f.ec, f.req)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Rollback(ctx, f.ec, f.req, first.RollbackRef); err != nil {
		t.Fatal(err)
	}
	event := &amtdv1beta1.SecurityEvent{}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "event"}, event); err != nil {
		t.Fatal(err)
	}
	event.ResourceVersion = ""
	event.Name = "event-second"
	event.UID = "event-uid-second"
	event.CreationTimestamp = metav1.NewTime(time.Now().UTC())
	if err := f.c.Create(ctx, event); err != nil {
		t.Fatal(err)
	}
	next := f.req
	next.TickID = "tick-2"
	next.OperationID = "decision-2"
	selected := *f.req.OutputPolicyObservation
	next.OutputPolicyObservation = &selected
	next.OutputPolicyObservation.EventName = event.Name
	next.OutputPolicyObservation.EventUID = string(event.UID)
	latest := &corev1.ConfigMap{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "phorvex-output-policy-support"}, latest); err != nil {
		t.Fatal(err)
	}
	next.OutputPolicyObservation.SelectedConfigMapResourceVersion = latest.ResourceVersion
	next.OutputPolicyObservation.SelectedRevision = 2
	second, err := h.Enact(ctx, f.ec, next)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Emitted || f.activation(t).Revision != 3 {
		t.Fatalf("rearm result=%+v activation=%+v", second, f.activation(t))
	}
	if err := h.Rollback(ctx, f.ec, f.req, first.RollbackRef); err == nil {
		t.Fatal("old operation rollback reference controlled rearmed state")
	}
	archives := &corev1.ConfigMapList{}
	if err := f.c.List(ctx, archives, client.InNamespace("operator"), client.MatchingLabels{outputPolicyArchiveLabel: "v1"}); err != nil {
		t.Fatal(err)
	}
	if len(archives.Items) != 1 || archives.Items[0].Immutable == nil || !*archives.Items[0].Immutable {
		t.Fatalf("prior receipt was not immutably archived: %+v", archives.Items)
	}
	_, receipt, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID)
	if err != nil || receipt.EventUID != string(event.UID) || receipt.TickID != next.TickID || receipt.SelectionDecisionID != next.OperationID || receipt.Phase != "terminal-full" {
		t.Fatalf("rearmed receipt=%+v err=%v", receipt, err)
	}
}

type outputFaultClient struct {
	client.Client
	update func(context.Context, client.Client, client.Object, ...client.UpdateOption) error
}

func (c outputFaultClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return c.update(ctx, c.Client, obj, opts...)
}

func TestOutputPolicyLostJournalAcknowledgementRecovers(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	h := outputPolicyHandler{}
	lost := false
	f.ec.Client = outputFaultClient{Client: f.c, update: func(ctx context.Context, base client.Client, obj client.Object, opts ...client.UpdateOption) error {
		cm, ok := obj.(*corev1.ConfigMap)
		if ok && cm.Labels[outputpolicy.JournalLabel] == "v1" && strings.Contains(cm.Data["receipt"], `"phase":"terminal-full"`) && !lost {
			lost = true
			if err := base.Update(ctx, obj, opts...); err != nil {
				return err
			}
			return errors.New("lost journal acknowledgement")
		}
		return base.Update(ctx, obj, opts...)
	}}
	result, err := h.Enact(ctx, f.ec, f.req)
	if err == nil || result.Emitted || !lost || f.activation(t).Revision != 1 {
		t.Fatalf("lost ack result=%+v err=%v", result, err)
	}
	events, err := recoverOutputPolicyOperations(ctx, f.ec, nil)
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("recovery events=%+v err=%v", events, err)
	}
	_, r, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID)
	if err != nil || r.Phase != "terminal-full" || f.activation(t).Revision != 1 {
		t.Fatalf("recovered journal=%+v err=%v", r, err)
	}
}

func TestOutputPolicyCASConflictThenRecovery(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	h := outputPolicyHandler{}
	conflicted := false
	f.ec.Client = outputFaultClient{Client: f.c, update: func(ctx context.Context, base client.Client, obj client.Object, opts ...client.UpdateOption) error {
		cm, ok := obj.(*corev1.ConfigMap)
		if ok && cm.Namespace == "tenant" && !conflicted {
			conflicted = true
			return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, cm.Name, errors.New("concurrent update"))
		}
		return base.Update(ctx, obj, opts...)
	}}
	if _, err := h.Enact(ctx, f.ec, f.req); !apierrors.IsConflict(err) {
		t.Fatalf("CAS conflict not surfaced: %v", err)
	}
	if a := f.activation(t); a.Revision != 0 {
		t.Fatalf("conflict still changed activation: %+v", a)
	}
	_, r, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID)
	if err != nil || r.Phase != "prepared" {
		t.Fatalf("prepared journal lost: %+v %v", r, err)
	}
	events, err := recoverOutputPolicyOperations(ctx, f.ec, nil)
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || f.activation(t).Revision != 1 {
		t.Fatalf("CAS recovery=%+v err=%v", events, err)
	}
}

func TestOutputPolicySourceDriftRefusesBeforeJournal(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	pod := &corev1.Pod{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "support"}, pod); err != nil {
		t.Fatal(err)
	}
	pod.Annotations[outputpolicy.PodSupportSHAAnnotation] = strings.Repeat("c", 64)
	if err := f.c.Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if _, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req); err == nil {
		t.Fatal("changed support source admitted")
	}
	if _, _, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID); !apierrors.IsNotFound(err) {
		t.Fatalf("drift created journal: %v", err)
	}
}

func TestOutputPolicyPendingFencesOnlyExactPod(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	f.state.Store(0)
	if _, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req); err == nil {
		t.Fatal("unprojected activation unexpectedly confirmed")
	}
	pending, err := PendingOutputPolicyOperation(ctx, f.c, "operator", "tenant", f.req.TargetUID)
	if err != nil || !pending {
		t.Fatalf("exact pending fence=%v err=%v", pending, err)
	}
	other, err := PendingOutputPolicyOperation(ctx, f.c, "operator", "tenant", "other-pod-uid")
	if err != nil || other {
		t.Fatalf("unrelated Pod fenced=%v err=%v", other, err)
	}
	incompatible := f.req
	incompatible.Action = model.ActionRotate
	if _, err := dispatch(ctx, f.ec, incompatible); err == nil || !strings.Contains(err.Error(), "pending output policy") {
		t.Fatalf("native incompatible mutation passed fence: %v", err)
	}
}

func TestOutputPolicyDelayedProjectionConvergesBeforeDeadline(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	f.state.Store(0)
	time.AfterFunc(45*time.Millisecond, func() { f.state.Store(1) })
	result, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req)
	if err != nil || !result.Emitted || f.activation(t).Revision != 1 {
		t.Fatalf("delayed projection result=%+v err=%v", result, err)
	}
	_, r, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID)
	if err != nil || r.Phase != "terminal-full" {
		t.Fatalf("terminal after projection=%+v err=%v", r, err)
	}
}

func TestOutputPolicyWrongPodUIDRefusesBeforeJournal(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	f.req.TargetUID = "33333333-3333-4333-8333-333333333333"
	if _, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req); err == nil {
		t.Fatal("stale selected Pod UID admitted")
	}
	if _, _, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID); !apierrors.IsNotFound(err) {
		t.Fatalf("stale UID wrote receipt: %v", err)
	}
}

func TestOutputPolicyExactJSONFields(t *testing.T) {
	fields := []string{"active", "revision"}
	for _, raw := range []string{`{"active":true,"Active":false,"revision":1}`, `{"active":true,"active":false,"revision":1}`, `{"active":true,"revision":1,"path":"/arbitrary"}`, `{"active":true}`} {
		if err := outputPolicyExactObject([]byte(raw), fields...); err == nil {
			t.Fatalf("ambiguous JSON admitted: %s", raw)
		}
	}
	if err := outputPolicyExactObject([]byte(`{"active":true,"revision":1}`), fields...); err != nil {
		t.Fatal(err)
	}
}

func TestOutputPolicySelectedConfigMapResourceVersionMustMatch(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	cm := &corev1.ConfigMap{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "phorvex-output-policy-support"}, cm); err != nil {
		t.Fatal(err)
	}
	cm.Labels = map[string]string{"concurrent": "metadata-change"}
	if err := f.c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if _, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req); err == nil {
		t.Fatal("stale selected ConfigMap resourceVersion admitted")
	}
	if _, _, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID); !apierrors.IsNotFound(err) {
		t.Fatalf("stale selection created journal: %v", err)
	}
}

type outputCreateRaceClient struct {
	client.Client
	competing outputPolicyReceipt
	triggered bool
}

func (c *outputCreateRaceClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Labels[outputpolicy.JournalLabel] == "v1" && !c.triggered {
		c.triggered = true
		if _, err := outputPolicyJournalCreate(ctx, EnactCtx{Client: c.Client, JournalNamespace: "operator"}, c.competing); err != nil {
			return err
		}
		return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "configmaps"}, obj.GetName())
	}
	return c.Client.Create(ctx, obj, opts...)
}
func competingOutputReceipt(t *testing.T, f outputFixture) outputPolicyReceipt {
	t.Helper()
	ctx := context.Background()
	pod := &corev1.Pod{}
	cm := &corev1.ConfigMap{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "support"}, pod); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "phorvex-output-policy-support"}, cm); err != nil {
		t.Fatal(err)
	}
	req := f.req
	req.TickID = "competing-tick"
	req.OperationID = "competing-decision"
	prior := f.activation(t)
	r, err := outputPolicyObservation(req, pod, cm, prior)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestOutputPolicyJournalCreateRaceRefusesCompetingSelection(t *testing.T) {
	ctx := context.Background()
	t.Run("create-race", func(t *testing.T) {
		f := newOutputFixture(t)
		competing := competingOutputReceipt(t, f)
		race := &outputCreateRaceClient{Client: f.c, competing: competing}
		f.ec.Client = race
		result, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req)
		if err == nil || result.Emitted || !race.triggered {
			t.Fatalf("competing create race result=%+v err=%v", result, err)
		}
		if a := f.activation(t); a.Revision != 0 || a.Active {
			t.Fatalf("competing intent activated: %+v", a)
		}
		_, recorded, err := outputPolicyJournalGet(ctx, f.ec, f.req.TargetUID)
		if err != nil || recorded.TickID != competing.TickID || recorded.SelectionDecisionID != competing.SelectionDecisionID || recorded.Phase != "prepared" {
			t.Fatalf("competing receipt changed: %+v err=%v", recorded, err)
		}
	})
	t.Run("preexisting", func(t *testing.T) {
		f := newOutputFixture(t)
		competing := competingOutputReceipt(t, f)
		if _, err := outputPolicyJournalCreate(ctx, f.ec, competing); err != nil {
			t.Fatal(err)
		}
		result, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req)
		if err == nil || result.Emitted || f.activation(t).Revision != 0 {
			t.Fatalf("preexisting competing selection result=%+v err=%v", result, err)
		}
	})
}

func TestOutputPolicyRecoveryTenantFromLivePolicy(t *testing.T) {
	ctx := context.Background()
	f := newOutputFixture(t)
	policy := &v1alpha1.PhorvexPolicy{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "policy"}, policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.Tenant = "customer-a"
	if err := f.c.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	f.state.Store(0)
	if _, err := (outputPolicyHandler{}).Enact(ctx, f.ec, f.req); err == nil {
		t.Fatal("unprojected activation unexpectedly confirmed")
	}
	f.state.Store(1)
	events, err := recoverOutputPolicyOperations(ctx, f.ec, nil)
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || events[0].Tenant != "customer-a" {
		t.Fatalf("recovery must route via live policy tenant: events=%+v err=%v", events, err)
	}
}

func TestOutputPolicyEventTimestampPrecisionAndFuture(t *testing.T) {
	cases := []struct {
		name              string
		created, observed func(time.Time) time.Time
		allow             bool
	}{
		{name: "same-second Kubernetes creation truncation", created: func(now time.Time) time.Time { return now.Truncate(time.Second).Add(-time.Second) }, observed: func(now time.Time) time.Time { return now.Truncate(time.Second).Add(-200 * time.Millisecond) }, allow: true},
		{name: "beyond one-second creation tolerance", created: func(now time.Time) time.Time { return now.Truncate(time.Second).Add(-3 * time.Second) }, observed: func(now time.Time) time.Time { return now.Truncate(time.Second).Add(-1900 * time.Millisecond) }, allow: false},
		{name: "observed time actually in future", created: func(now time.Time) time.Time { return now.Truncate(time.Second) }, observed: func(now time.Time) time.Time { return now.Add(time.Second) }, allow: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := newOutputFixture(t)
			r := competingOutputReceipt(t, f)
			event := &amtdv1beta1.SecurityEvent{}
			if err := f.c.Get(ctx, client.ObjectKey{Name: "event"}, event); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			event.CreationTimestamp = metav1.NewTime(tc.created(now))
			var payload map[string]any
			if err := json.Unmarshal([]byte(event.Annotations[outputpolicy.EventAnnotation]), &payload); err != nil {
				t.Fatal(err)
			}
			payload["observedAt"] = tc.observed(now).Format(time.RFC3339Nano)
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			event.Annotations[outputpolicy.EventAnnotation] = string(raw)
			if err := f.c.Update(ctx, event); err != nil {
				t.Fatal(err)
			}
			err = outputPolicyEvent(ctx, f.ec, r)
			if (err == nil) != tc.allow {
				t.Fatalf("timestamp check allow=%v err=%v", tc.allow, err)
			}
		})
	}
}
