package actuator

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m064HTTPReceiver struct {
	calls    atomic.Int32
	mu       sync.Mutex
	status   int
	hook     func() error
	token    string
	variants []string
}

func (r *m064HTTPReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	switch req.URL.Path {
	case defaultResetPath, defaultKVInvPath, defaultGuardPath:
	default:
		http.NotFound(w, req)
		return
	}
	r.calls.Add(1)
	r.mu.Lock()
	status, hook, token := r.status, r.hook, r.token
	if req.URL.Path == defaultGuardPath {
		var body struct {
			Variant string `json:"variant"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Variant == "" {
			r.mu.Unlock()
			http.Error(w, "invalid guardrail payload", http.StatusBadRequest)
			return
		}
		r.variants = append(r.variants, body.Variant)
	}
	r.hook = nil
	r.mu.Unlock()
	if token != "" && req.Header.Get("Authorization") != "Bearer "+token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if hook != nil {
		if err := hook(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if status == 0 {
		if req.URL.Path == defaultResetPath {
			status = http.StatusOK
		} else {
			status = http.StatusNoContent
		}
	}
	w.WriteHeader(status)
	if req.URL.Path == defaultResetPath && status == http.StatusOK {
		_, _ = w.Write([]byte(`{"success":true}`))
	}
}

func (r *m064HTTPReceiver) configure(status int, token string, hook func() error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status, r.token, r.hook = status, token, hook
}

func (r *m064HTTPReceiver) observedVariants() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.variants...)
}

type m064APIFaultClient struct {
	client.Client
	createMode string
	updateMode string
	phase      string
	createDone bool
	updateDone bool
	patchRace  bool
	patchRaces int
	delayed    *corev1.ConfigMap
}

type m064GCReader struct {
	client.Reader
	client  client.Client
	target  client.ObjectKey
	receipt client.ObjectKey
	fail    bool
	bump    bool
}

func (r *m064GCReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	err := r.Reader.Get(ctx, key, obj, opts...)
	if key != r.target {
		return err
	}
	if r.fail {
		return errors.New("synthetic authoritative target read failure")
	}
	if r.bump {
		r.bump = false
		cm := &corev1.ConfigMap{}
		if getErr := r.client.Get(ctx, r.receipt, cm); getErr != nil {
			return getErr
		}
		cm.Annotations = ensureMap(cm.Annotations)
		cm.Annotations["m064.test/concurrent-owner"] = "changed"
		if updateErr := r.client.Update(ctx, cm); updateErr != nil {
			return updateErr
		}
	}
	return err
}

func (c *m064APIFaultClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	cm, serving := obj.(*corev1.ConfigMap)
	if !serving || cm.Labels[servingJournalLabel] != "v1" || c.createDone || c.createMode == "" {
		return c.Client.Create(ctx, obj, opts...)
	}
	c.createDone = true
	switch c.createMode {
	case "delayed":
		c.delayed = cm.DeepCopy()
		return errors.New("synthetic create response lost before observation")
	case "ack-loss":
		if err := c.Client.Create(ctx, obj, opts...); err != nil {
			return err
		}
		return errors.New("synthetic create acknowledgement lost")
	case "missing-identity":
		if err := c.Client.Create(ctx, obj, opts...); err != nil {
			return err
		}
		obj.SetUID("")
		obj.SetResourceVersion("")
		return nil
	default:
		return fmt.Errorf("unknown create fault %q", c.createMode)
	}
}

func (c *m064APIFaultClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	cm, serving := obj.(*corev1.ConfigMap)
	if !serving || c.updateDone || c.updateMode == "" {
		return c.Client.Update(ctx, obj, opts...)
	}
	var r operationReceipt
	if json.Unmarshal([]byte(cm.Data["receipt"]), &r) != nil || r.Version != servingEffectReceiptVersion || r.Phase != c.phase {
		return c.Client.Update(ctx, obj, opts...)
	}
	c.updateDone = true
	if c.updateMode == "conflict" {
		return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, cm.Name, errors.New("synthetic competing CAS"))
	}
	if c.updateMode != "ack-loss" {
		return fmt.Errorf("unknown update fault %q", c.updateMode)
	}
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	return errors.New("synthetic update acknowledgement lost")
}

func (c *m064APIFaultClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	pod, ok := obj.(*corev1.Pod)
	if !ok || (!c.patchRace && c.patchRaces == 0) {
		return c.Client.Patch(ctx, obj, patch, opts...)
	}
	c.patchRace = false
	if c.patchRaces > 0 {
		c.patchRaces--
	}
	fresh := &corev1.Pod{}
	if err := c.Client.Get(ctx, client.ObjectKeyFromObject(pod), fresh); err != nil {
		return err
	}
	fresh.Annotations = ensureMap(fresh.Annotations)
	fresh.Annotations["m064.test/unrelated"] = fmt.Sprintf("preserved-%d", c.patchRaces)
	if err := c.Client.Update(ctx, fresh); err != nil {
		return err
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

type m064APIFixture struct {
	ctx      context.Context
	client   client.Client
	ns, opns string
	pod      *corev1.Pod
	policy   *v1alpha1.PhorvexPolicy
	req      Request
	endpoint string
}

func newM064APIFixture(t *testing.T, ctx context.Context, c client.Client, id, endpoint string, action model.Action) *m064APIFixture {
	t.Helper()
	ns, opns := "m064-"+id, "m064-"+id+"-op"
	for _, name := range []string{ns, opns} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": id}},
		Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{
			v1alpha1.ActionType(model.ActionKVReset), v1alpha1.ActionType(model.ActionKVMigrateInvalidate), v1alpha1.ActionType(model.ActionGuardrailRotate),
		}},
	}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "serving", Labels: map[string]string{"app": id}, Annotations: map[string]string{
		"phorvex.ai/model-id": "fixture-model", annoServingPort: port,
	}}, Spec: corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{{Name: "serving", Image: "registry.k8s.io/pause:3.10"}}}}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIP, pod.Status.Phase = host, corev1.PodRunning
	if err := c.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	f := &m064APIFixture{ctx: ctx, client: c, ns: ns, opns: opns, pod: pod, policy: policy, endpoint: endpoint}
	f.req = f.selectRequest(t, action, "tick-1")
	return f
}

func (f *m064APIFixture) selectRequest(t *testing.T, action model.Action, tick string) Request {
	t.Helper()
	pod := &corev1.Pod{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	owned := func(values map[string]string, key string) model.OwnedValue {
		value, present := values[key]
		return model.OwnedValue{Present: present, Value: value}
	}
	return Request{Namespace: f.ns, Pod: pod.Name, TargetUID: string(pod.UID), PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), Action: action, TickID: tick,
		ServingObservation: &ServingSelectionObservation{
			KVReset: owned(pod.Annotations, annoKVResetEpoch), KVMigrate: owned(pod.Annotations, annoKVEpoch),
			KVLocalEffect: owned(pod.Annotations, annoKVLocalEffect), Guardrail: owned(pod.Labels, "phorvex.ai/guardrail-epoch"),
		}}
}

func (f *m064APIFixture) enactReset(c client.Client, req Request) (HandlerResult, error) {
	return (kvResetHandler{}).Enact(f.ctx, EnactCtx{Client: c, Reader: f.client, JournalNamespace: f.opns, VLLM: newHTTPVLLM()}, req)
}

func (f *m064APIFixture) recover(t *testing.T) ([]RecoveryEvent, error) {
	t.Helper()
	native := NewNativeActuator(f.client)
	native.Reader, native.JournalNamespace = f.client, f.opns
	native.SetServingSecurity(legacyServingSecurityForTest(t))
	return native.RecoverOperations(f.ctx, false)
}

func TestM064RealAPIAcknowledgementCASAndLifecycle(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	localOnly := false
	env := &envtest.Environment{UseExistingCluster: &localOnly, CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	apiClient, err := client.New(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	receiver := &m064HTTPReceiver{}
	server := httptest.NewServer(receiver)
	t.Cleanup(server.Close)

	t.Run("create-acknowledgement-loss", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "create-ack", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, createMode: "ack-loss"}
		result, err := f.enactReset(fault, f.req)
		if err == nil || result.MutationKind != "partial" || receiver.calls.Load() != before {
			t.Fatalf("create ack loss: result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before, err)
		}
		if events, err := f.recover(t); err != nil || len(events) != 1 || receiver.calls.Load() != before+1 {
			t.Fatalf("prepared recovery did not own one dispatch: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
	})

	t.Run("delayed-create-after-not-found", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "delay-create", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, createMode: "delayed"}
		result, err := f.enactReset(fault, f.req)
		if err == nil || result.MutationKind != "partial" || fault.delayed == nil || receiver.calls.Load() != before {
			t.Fatalf("delayed create setup: result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before, err)
		}
		fault.delayed.SetUID("")
		fault.delayed.SetResourceVersion("")
		if err := apiClient.Create(ctx, fault.delayed); err != nil {
			t.Fatal(err)
		}
		if events, err := f.recover(t); err != nil || len(events) != 1 || receiver.calls.Load() != before+1 {
			t.Fatalf("delayed committed claim recovery: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
	})

	t.Run("successful-create-missing-response-identity", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "create-id", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, createMode: "missing-identity"}
		result, err := f.enactReset(fault, f.req)
		if err == nil || result.MutationKind != "partial" || receiver.calls.Load() != before {
			t.Fatalf("missing create identity: result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before, err)
		}
		if events, err := f.recover(t); err != nil || len(events) != 1 || receiver.calls.Load() != before+1 {
			t.Fatalf("reread did not bind created identity: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
	})

	t.Run("dispatch-cas-acknowledgement-loss", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "dispatch-ack", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, updateMode: "ack-loss", phase: "dispatching"}
		result, err := f.enactReset(fault, f.req)
		if err == nil || result.MutationKind != "partial" || receiver.calls.Load() != before {
			t.Fatalf("dispatch ack loss sent: result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before, err)
		}
		if events, err := f.recover(t); err != nil || len(events) != 1 || events[0].Err == nil || receiver.calls.Load() != before {
			t.Fatalf("observed dispatching was replayed: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
	})

	t.Run("dispatch-cas-conflict-recovery-wins", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "dispatch-cas", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, updateMode: "conflict", phase: "dispatching"}
		result, err := f.enactReset(fault, f.req)
		if err == nil || result.MutationKind != "partial" || receiver.calls.Load() != before {
			t.Fatalf("losing CAS sent: result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before, err)
		}
		if events, err := f.recover(t); err != nil || len(events) != 1 || receiver.calls.Load() != before+1 {
			t.Fatalf("prepared recovery did not win one CAS: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
	})

	t.Run("two-real-cas-contenders-one-dispatch", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "two-cas", server.URL, model.ActionKVReset)
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		ec := EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns}
		cm, r, fresh, _, err := prepareServingReceipt(ctx, ec, f.req, pod, nil, "", "")
		if err != nil || !fresh {
			t.Fatalf("prepare: fresh=%t err=%v", fresh, err)
		}
		cmA, cmB := &corev1.ConfigMap{}, &corev1.ConfigMap{}
		key := client.ObjectKeyFromObject(cm)
		if err := apiClient.Get(ctx, key, cmA); err != nil {
			t.Fatal(err)
		}
		if err := apiClient.Get(ctx, key, cmB); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		before := receiver.calls.Load()
		ep, err := validatedEndpointForPod(pod)
		if err != nil {
			t.Fatal(err)
		}
		var winners atomic.Int32
		var wg sync.WaitGroup
		for _, candidate := range []*corev1.ConfigMap{cmA, cmB} {
			wg.Add(1)
			go func(candidate *corev1.ConfigMap) {
				defer wg.Done()
				copyReceipt := r
				<-start
				if claimServingDispatch(ctx, ec, candidate, &copyReceipt, "dispatching") == nil {
					winners.Add(1)
					if err := newHTTPVLLM().ResetPrefixCache(ctx, ep); err != nil {
						t.Errorf("CAS winner HTTP: %v", err)
					}
				}
			}(candidate)
		}
		close(start)
		wg.Wait()
		if winners.Load() != 1 || receiver.calls.Load() != before+1 {
			t.Fatalf("real CAS winners=%d requests=%d/%d, want one of each", winners.Load(), receiver.calls.Load(), before)
		}
	})

	t.Run("cross-policy-reset-migrate-shared-owner", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "shared-owner", server.URL, model.ActionKVReset)
		receiver.configure(http.StatusAccepted, "", nil)
		before := receiver.calls.Load()
		first, firstErr := f.enactReset(apiClient, f.req)
		if firstErr == nil || first.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("queued owner missing: result=%+v calls=%d err=%v", first, receiver.calls.Load(), firstErr)
		}
		other := f.policy.DeepCopy()
		other.ObjectMeta = metav1.ObjectMeta{Namespace: f.ns, Name: "policy-two"}
		if err := apiClient.Create(ctx, other); err != nil {
			t.Fatal(err)
		}
		req := f.selectRequest(t, model.ActionKVMigrateInvalidate, "tick-2")
		req.PolicyName, req.PolicyUID = other.Name, string(other.UID)
		result, err := (kvMigrateInvalidateHandler{}).Enact(ctx, EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns, KVXfer: httpKVTransfer{v: newHTTPVLLM()}}, req)
		if err == nil || result.MutationKind != "partial" || result.NoEffect != "" || receiver.calls.Load() != before+1 {
			t.Fatalf("shared-domain contender escaped: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		receiver.configure(http.StatusOK, "", nil)
	})

	t.Run("effect-confirmed-acknowledgement-loss", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "effect-ack", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, updateMode: "ack-loss", phase: "effect-confirmed"}
		result, err := f.enactReset(fault, f.req)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("confirmed effect evidence lost: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		if events, err := f.recover(t); err != nil || len(events) != 1 || receiver.calls.Load() != before+1 {
			t.Fatalf("metadata-only recovery repeated HTTP: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
	})

	t.Run("terminal-partial-acknowledgement-loss", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "partial-ack", server.URL, model.ActionKVMigrateInvalidate)
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		pod.Annotations[annoDisaggPeers] = "decode-a.invalid:8000,decode-b.invalid:8000"
		if err := apiClient.Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		req := f.selectRequest(t, model.ActionKVMigrateInvalidate, "tick-partial")
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, updateMode: "ack-loss", phase: "terminal-partial"}
		result, err := (kvMigrateInvalidateHandler{}).Enact(ctx, EnactCtx{Client: fault, Reader: apiClient, JournalNamespace: f.opns, KVXfer: httpKVTransfer{v: newHTTPVLLM()}}, req)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("terminal partial ack loss: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		retry, retryErr := (kvMigrateInvalidateHandler{}).Enact(ctx, EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns, KVXfer: httpKVTransfer{v: newHTTPVLLM()}}, req)
		if retryErr != nil || retry.Emitted || retry.NoEffect != NoEffectReconciled || receiver.calls.Load() != before+1 {
			t.Fatalf("terminal partial repeated: result=%+v calls=%d err=%v", retry, receiver.calls.Load(), retryErr)
		}
	})

	t.Run("definite-pre-create-refusal", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "clean-refusal", server.URL, model.ActionKVReset)
		req := f.req
		req.ServingObservation.KVReset = model.OwnedValue{Present: true, Value: "stale"}
		before := receiver.calls.Load()
		result, err := f.enactReset(apiClient, req)
		if err == nil || !IsNoEffectRefusal(err) || result.Emitted || result.MutationKind != "" || receiver.calls.Load() != before {
			t.Fatalf("clean refusal contract: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		var cms corev1.ConfigMapList
		if err := apiClient.List(ctx, &cms, client.InNamespace(f.opns), client.MatchingLabels{servingJournalLabel: "v1"}); err != nil || len(cms.Items) != 0 {
			t.Fatalf("clean refusal created a claim: count=%d err=%v", len(cms.Items), err)
		}
	})

	t.Run("real-patch-conflict-preserves-unrelated-metadata", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "patch-race", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, patchRace: true}
		result, err := f.enactReset(fault, f.req)
		if err != nil || !result.Emitted || fault.patchRace || receiver.calls.Load() != before+1 {
			t.Fatalf("bounded patch retry: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(pod.Annotations["m064.test/unrelated"], "preserved-") || pod.Annotations[annoKVResetEpoch] == "" {
			t.Fatalf("conflict retry lost metadata: %v", pod.Annotations)
		}
	})

	t.Run("two-real-patch-conflicts-then-final-success", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "patch-final", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		fault := &m064APIFaultClient{Client: apiClient, patchRaces: metadataPatchAttempts - 1}
		result, err := f.enactReset(fault, f.req)
		if err != nil || !result.Emitted || result.MutationKind != "forward-only" || fault.patchRaces != 0 || receiver.calls.Load() != before+1 {
			t.Fatalf("final bounded patch acknowledgement: result=%+v races=%d calls=%d err=%v", result, fault.patchRaces, receiver.calls.Load(), err)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations["m064.test/unrelated"] != "preserved-0" || pod.Annotations[annoKVResetEpoch] == "" {
			t.Fatalf("final bounded Patch did not retain acknowledged state: %v", pod.Annotations)
		}
	})

	t.Run("confirmed-http-policy-revocation-retains-effect", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "revoke-after", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		receiver.configure(http.StatusOK, "", func() error {
			policy := &v1alpha1.PhorvexPolicy{}
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.policy), policy); err != nil {
				return err
			}
			policy.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionGuardrailRotate)}
			return apiClient.Update(ctx, policy)
		})
		result, err := f.enactReset(apiClient, f.req)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("confirmed effect rewritten after revocation: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		_, receipt, getErr := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: f.opns}, f.req.TargetUID, f.req.Action)
		if getErr != nil || receipt.Phase != "effect-confirmed" {
			t.Fatalf("confirmed phase not retained: receipt=%+v err=%v", receipt, getErr)
		}
		receiver.configure(http.StatusOK, "", nil)
	})

	t.Run("confirmed-http-owned-metadata-change-is-not-overwritten", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "owned-change", server.URL, model.ActionKVReset)
		before := receiver.calls.Load()
		receiver.configure(http.StatusOK, "", func() error {
			pod := &corev1.Pod{}
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				return err
			}
			pod.Annotations[annoKVResetEpoch] = "external-owner"
			return apiClient.Update(ctx, pod)
		})
		result, err := f.enactReset(apiClient, f.req)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("owned-state conflict: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations[annoKVResetEpoch] != "external-owner" {
			t.Fatalf("external owned state overwritten: %v", pod.Annotations)
		}
		delete(pod.Annotations, annoKVResetEpoch)
		if err := apiClient.Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		receiver.configure(http.StatusOK, "", nil)
		if events, err := f.recover(t); err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || receiver.calls.Load() != before+1 {
			t.Fatalf("restored selected state did not converge metadata-only: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
		retry, retryErr := f.enactReset(apiClient, f.req)
		if retryErr != nil || retry.Emitted || retry.NoEffect != NoEffectReconciled || receiver.calls.Load() != before+1 {
			t.Fatalf("expected metadata idempotence failed: result=%+v calls=%d err=%v", retry, receiver.calls.Load(), retryErr)
		}
	})

	t.Run("guardrail-confirmed-metadata-refusal-remains-partial", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "guard-revoke", server.URL, model.ActionGuardrailRotate)
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		pod.Labels[labelGuardrailTier] = "true"
		pod.Annotations[annoGuardrailVariant] = "v1"
		pod.Annotations[annoGuardrailAlts] = "v1,v2"
		if err := apiClient.Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		req := f.selectRequest(t, model.ActionGuardrailRotate, "guard-revoke")
		receiver.configure(http.StatusNoContent, "", func() error {
			policy := &v1alpha1.PhorvexPolicy{}
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.policy), policy); err != nil {
				return err
			}
			policy.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionKVReset)}
			return apiClient.Update(ctx, policy)
		})
		before := receiver.calls.Load()
		result, err := (guardrailRotateHandler{}).Enact(ctx, EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns, Guardrail: httpGuardrail{v: newHTTPVLLM()}}, req)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("guardrail confirmed metadata refusal: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
	})

	t.Run("guardrail-explicit-rollback-and-unknown-no-repeat", func(t *testing.T) {
		newGuard := func(t *testing.T, id string) (*m064APIFixture, Request) {
			t.Helper()
			f := newM064APIFixture(t, ctx, apiClient, id, server.URL, model.ActionGuardrailRotate)
			pod := &corev1.Pod{}
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			pod.Labels[labelGuardrailTier] = "true"
			pod.Annotations[annoGuardrailVariant] = "v1"
			pod.Annotations[annoGuardrailAlts] = "v1,v2"
			if err := apiClient.Update(ctx, pod); err != nil {
				t.Fatal(err)
			}
			return f, f.selectRequest(t, model.ActionGuardrailRotate, id+"-tick")
		}

		f, req := newGuard(t, "guard-rollback")
		receiver.configure(http.StatusNoContent, "", nil)
		before := receiver.calls.Load()
		result, err := (guardrailRotateHandler{}).Enact(ctx, EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns, Guardrail: httpGuardrail{v: newHTTPVLLM()}}, req)
		if err != nil || result.MutationKind != "reversible" || result.RollbackRef == "" || receiver.calls.Load() != before+1 {
			t.Fatalf("guardrail positive: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		native := NewNativeActuator(apiClient)
		native.Reader, native.JournalNamespace = apiClient, f.opns
		native.SetServingSecurity(legacyServingSecurityForTest(t))
		if err := native.Rollback(ctx, req, result.RollbackRef); err != nil || receiver.calls.Load() != before+2 {
			t.Fatalf("guardrail rollback: calls=%d err=%v", receiver.calls.Load(), err)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations[annoGuardrailVariant] != "v1" || pod.Labels["phorvex.ai/guardrail-epoch"] == "" {
			t.Fatalf("rollback metadata missing: labels=%v annotations=%v", pod.Labels, pod.Annotations)
		}

		unknown, unknownReq := newGuard(t, "guard-unknown")
		result, err = (guardrailRotateHandler{}).Enact(ctx, EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: unknown.opns, Guardrail: httpGuardrail{v: newHTTPVLLM()}}, unknownReq)
		if err != nil {
			t.Fatal(err)
		}
		receiver.configure(http.StatusAccepted, "", nil)
		before = receiver.calls.Load()
		unknownNative := NewNativeActuator(apiClient)
		unknownNative.Reader, unknownNative.JournalNamespace = apiClient, unknown.opns
		unknownNative.SetServingSecurity(legacyServingSecurityForTest(t))
		if err := unknownNative.Rollback(ctx, unknownReq, result.RollbackRef); err == nil || receiver.calls.Load() != before+1 {
			t.Fatalf("queued rollback classification: calls=%d err=%v", receiver.calls.Load(), err)
		}
		if err := unknownNative.Rollback(ctx, unknownReq, result.RollbackRef); err == nil || receiver.calls.Load() != before+1 {
			t.Fatalf("unresolved rollback repeated: calls=%d err=%v", receiver.calls.Load(), err)
		}
		if events, err := unknownNative.RecoverOperations(ctx, false); err != nil || len(events) != 1 || events[0].Err == nil || receiver.calls.Load() != before+1 {
			t.Fatalf("rollback recovery repeated: events=%+v calls=%d err=%v", events, receiver.calls.Load(), err)
		}
		receiver.configure(http.StatusNoContent, "", nil)
	})

	t.Run("guardrail-missing-target-preserves-pending-domain", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "guard-missing", server.URL, model.ActionGuardrailRotate)
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		pod.Labels[labelGuardrailTier] = "true"
		pod.Annotations[annoGuardrailVariant] = "v1"
		pod.Annotations[annoGuardrailAlts] = "v1,v2"
		if err := apiClient.Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		req := f.selectRequest(t, model.ActionGuardrailRotate, "guard-missing")
		receiver.configure(http.StatusAccepted, "", nil)
		before := receiver.calls.Load()
		result, err := (guardrailRotateHandler{}).Enact(ctx, EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns, Guardrail: httpGuardrail{v: newHTTPVLLM()}}, req)
		if err == nil || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("pending guardrail prerequisite: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		uid, rv := pod.UID, pod.ResourceVersion
		if err := apiClient.Delete(ctx, pod, client.Preconditions{UID: &uid, ResourceVersion: &rv}, client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
		result, err = (guardrailRotateHandler{}).Enact(ctx, EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns, Guardrail: httpGuardrail{v: newHTTPVLLM()}}, req)
		if err == nil || result.MutationKind != "partial" || result.NoEffect != "" || receiver.calls.Load() != before+1 {
			t.Fatalf("missing target hid pending obligation: result=%+v calls=%d err=%v", result, receiver.calls.Load(), err)
		}
		receiver.configure(http.StatusNoContent, "", nil)
	})

	t.Run("terminal-gc-exact-uid-and-unknown-retention", func(t *testing.T) {
		f := newM064APIFixture(t, ctx, apiClient, "terminal-gc", server.URL, model.ActionKVReset)
		receiver.configure(http.StatusOK, "", nil)
		before := receiver.calls.Load()
		result, err := f.enactReset(apiClient, f.req)
		if err != nil || !result.Emitted || receiver.calls.Load() != before+1 {
			t.Fatalf("terminal prerequisite: result=%+v err=%v", result, err)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		uid, rv := pod.UID, pod.ResourceVersion
		if err := apiClient.Delete(ctx, pod, client.Preconditions{UID: &uid, ResourceVersion: &rv}, client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
		if events, err := f.recover(t); err != nil || len(events) != 1 || !strings.Contains(events[0].Effect, "garbage-collected") {
			t.Fatalf("terminal GC: events=%+v err=%v", events, err)
		}
		if _, _, err := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: f.opns}, f.req.TargetUID, f.req.Action); !apierrors.IsNotFound(err) {
			t.Fatalf("terminal receipt retained after exact UID absence: %v", err)
		}

		pending := newM064APIFixture(t, ctx, apiClient, "unknown-gc", server.URL, model.ActionKVReset)
		receiver.configure(http.StatusAccepted, "", nil)
		if result, err := pending.enactReset(apiClient, pending.req); err == nil || result.MutationKind != "partial" {
			t.Fatalf("pending prerequisite: result=%+v err=%v", result, err)
		}
		old := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(pending.pod), old); err != nil {
			t.Fatal(err)
		}
		uid, rv = old.UID, old.ResourceVersion
		if err := apiClient.Delete(ctx, old, client.Preconditions{UID: &uid, ResourceVersion: &rv}, client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
		if events, err := pending.recover(t); err != nil || len(events) != 1 || events[0].Err == nil {
			t.Fatalf("unknown absent receipt classification: events=%+v err=%v", events, err)
		}
		if _, _, err := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: pending.opns}, pending.req.TargetUID, pending.req.Action); err != nil {
			t.Fatalf("unknown receipt was garbage-collected: %v", err)
		}
		receiver.configure(http.StatusOK, "", nil)
	})

	t.Run("terminal-gc-read-and-cas-failures-retain-receipt", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			fail bool
			bump bool
		}{
			{name: "read-error", fail: true},
			{name: "receipt-rv-changed", bump: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newM064APIFixture(t, ctx, apiClient, "gc-"+strings.ReplaceAll(tc.name, "-", ""), server.URL, model.ActionKVReset)
				if result, err := f.enactReset(apiClient, f.req); err != nil || !result.Emitted {
					t.Fatalf("terminal prerequisite: result=%+v err=%v", result, err)
				}
				cm, _, err := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: f.opns}, f.req.TargetUID, f.req.Action)
				if err != nil {
					t.Fatal(err)
				}
				pod := &corev1.Pod{}
				if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
					t.Fatal(err)
				}
				uid, rv := pod.UID, pod.ResourceVersion
				if !tc.fail {
					if err := apiClient.Delete(ctx, pod, client.Preconditions{UID: &uid, ResourceVersion: &rv}, client.GracePeriodSeconds(0)); err != nil {
						t.Fatal(err)
					}
				}
				reader := &m064GCReader{Reader: apiClient, client: apiClient, target: client.ObjectKeyFromObject(f.pod), receipt: client.ObjectKeyFromObject(cm), fail: tc.fail, bump: tc.bump}
				native := NewNativeActuator(apiClient)
				native.Reader, native.JournalNamespace = reader, f.opns
				events, recoverErr := native.RecoverOperations(ctx, false)
				if recoverErr != nil || len(events) != 1 || events[0].Err == nil {
					t.Fatalf("GC refusal not reported: events=%+v err=%v", events, recoverErr)
				}
				retained := &corev1.ConfigMap{}
				if err := apiClient.Get(ctx, client.ObjectKeyFromObject(cm), retained); err != nil {
					t.Fatalf("GC failure deleted receipt: %v", err)
				}
			})
		}
	})

	t.Run("secure-tls-v9-positive", func(t *testing.T) {
		tlsReceiver := &m064HTTPReceiver{}
		const token = "m064-synthetic-token"
		tlsReceiver.configure(http.StatusOK, token, nil)
		tlsServer := httptest.NewTLSServer(tlsReceiver)
		defer tlsServer.Close()
		f := newM064APIFixture(t, ctx, apiClient, "secure-tls", tlsServer.URL, model.ActionKVReset)
		cert := tlsServer.Certificate()
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: f.opns, Name: "serving-auth"}, Data: map[string][]byte{"token": []byte(token), "ca": ca}}
		if err := apiClient.Create(ctx, secret); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(tlsServer.URL)
		host, _, _ := net.SplitHostPort(u.Host)
		serverName := host
		if len(cert.DNSNames) > 0 {
			serverName = cert.DNSNames[0]
		} else if len(cert.IPAddresses) > 0 {
			serverName = cert.IPAddresses[0].String()
		}
		binding := ServingSecurityBinding{Namespace: f.ns, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: "default", ProfileID: "m064", SecretName: secret.Name, BearerKey: "token", CAKey: "ca", ServerName: serverName}
		security := writeServingSecurityConfig(t, ServingSecuritySecureRequired, f.opns, []ServingSecurityBinding{binding})
		native := NewNativeActuator(apiClient)
		native.Reader, native.JournalNamespace = apiClient, f.opns
		native.SetServingSecurity(security)
		result, err := native.Actuate(ctx, f.req)
		if err != nil || !result.Emitted || tlsReceiver.calls.Load() != 1 {
			t.Fatalf("secure TLS v9 positive: result=%+v calls=%d err=%v", result, tlsReceiver.calls.Load(), err)
		}
		cm, receipt, err := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: f.opns}, f.req.TargetUID, f.req.Action)
		if err != nil || receipt.ServingLegacy || !validDigest(receipt.ServingBindingSHA256) || strings.Contains(cm.Data["receipt"], token) {
			t.Fatalf("secure receipt provenance invalid or leaked credential: receipt=%+v err=%v", receipt, err)
		}

		rotate := newM064APIFixture(t, ctx, apiClient, "secure-rotate", tlsServer.URL, model.ActionKVReset)
		rotateSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: rotate.opns, Name: "serving-auth"}, Data: map[string][]byte{"token": []byte("token-one"), "ca": ca}}
		if err := apiClient.Create(ctx, rotateSecret); err != nil {
			t.Fatal(err)
		}
		rotateBinding := ServingSecurityBinding{Namespace: rotate.ns, PolicyName: rotate.policy.Name, PolicyUID: string(rotate.policy.UID), ServiceAccount: "default", ProfileID: "m064", SecretName: rotateSecret.Name, BearerKey: "token", CAKey: "ca", ServerName: serverName}
		rotateSecurity := writeServingSecurityConfig(t, ServingSecuritySecureRequired, rotate.opns, []ServingSecurityBinding{rotateBinding})
		ec := EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: rotate.opns, ServingSecurity: rotateSecurity}
		if err := prepareServingAttempt(ctx, &ec, rotate.req); err != nil {
			t.Fatal(err)
		}
		preparedCM, prepared, fresh, _, err := prepareServingReceipt(ctx, ec, rotate.req, ec.ServingTarget, nil, "", "")
		if err != nil || !fresh || preparedCM == nil || prepared.Phase != "prepared" {
			t.Fatalf("secure prepared receipt: fresh=%t receipt=%+v err=%v", fresh, prepared, err)
		}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(rotateSecret), rotateSecret); err != nil {
			t.Fatal(err)
		}
		rotateSecret.Data["token"] = []byte("token-two")
		if err := apiClient.Update(ctx, rotateSecret); err != nil {
			t.Fatal(err)
		}
		tlsReceiver.configure(http.StatusOK, "token-two", nil)
		before := tlsReceiver.calls.Load()
		restarted := NewNativeActuator(apiClient)
		restarted.Reader, restarted.JournalNamespace = apiClient, rotate.opns
		restarted.SetServingSecurity(rotateSecurity)
		events, err := restarted.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || tlsReceiver.calls.Load() != before+1 {
			t.Fatalf("secure prepared recovery after Secret rotation: events=%+v calls=%d err=%v", events, tlsReceiver.calls.Load(), err)
		}
		_, recovered, err := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: rotate.opns}, rotate.req.TargetUID, rotate.req.Action)
		if err != nil || recovered.ServingBindingSHA256 != prepared.ServingBindingSHA256 || recovered.OperationID != prepared.OperationID {
			t.Fatalf("Secret rotation changed stable receipt identity: prepared=%+v recovered=%+v err=%v", prepared, recovered, err)
		}
	})
}

var _ client.Client = (*m064APIFaultClient)(nil)
