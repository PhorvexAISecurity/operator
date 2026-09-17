package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

func TestM071AdapterInventoryStrictExactMembership(t *testing.T) {
	oversized := `{"data":[{"id":"` + strings.Repeat("x", servingResponseMaxBytes) + `"}]}`
	for _, tc := range []struct {
		name, body string
		want       bool
		wantErr    bool
	}{
		{"exact", `{"object":"list","data":[{"id":"base"},{"id":"target","owned_by":"operator"}]}`, true, false},
		{"collision", `{"data":[{"id":"target-v2"}]}`, false, false},
		{"empty", `{"data":[]}`, false, false},
		{"missing", `{"object":"list"}`, false, true},
		{"null", `{"data":null}`, false, true},
		{"entry missing id", `{"data":[{"object":"model"}]}`, false, true},
		{"duplicate id", `{"data":[{"id":"target"},{"id":"target"}]}`, false, true},
		{"duplicate field", `{"data":[{"id":"target","id":"other"}]}`, false, true},
		{"ambiguous data alias", `{"data":[{"id":"target"}],"Data":[]}`, false, true},
		{"uppercase id alias", `{"data":[{"ID":"target"}]}`, false, true},
		{"ambiguous id alias", `{"data":[{"id":"target","ID":"other"}]}`, false, true},
		{"nullable id", `{"data":[{"id":null}]}`, false, true},
		{"trailing", `{"data":[]} {}`, false, true},
		{"malformed", `{"data":[}`, false, true},
		{"oversized", oversized, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAdapterInventory([]byte(tc.body), "target")
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("loaded=%t err=%v, want loaded=%t error=%t", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

type m71Serving struct {
	mu               sync.Mutex
	loaded           bool
	unloadStatus     int
	loadStatus       int
	unloadCalls      int
	loadCalls        int
	inventoryCalls   int
	pollsAfterUnload int
	disappearAfter   int
	unloadPending    bool
	unloadDelay      time.Duration
}

func (s *m71Serving) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case defaultModelsPath:
		s.inventoryCalls++
		if s.unloadPending && s.loaded && s.disappearAfter > 0 {
			s.pollsAfterUnload++
			if s.pollsAfterUnload >= s.disappearAfter {
				s.loaded = false
				s.unloadPending = false
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if s.loaded {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"actual-poison","extension":true}]}`))
		} else {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"base"}]}`))
		}
	case defaultUnloadPath:
		s.unloadCalls++
		s.pollsAfterUnload = 0
		s.unloadPending = true
		if s.unloadDelay > 0 {
			time.Sleep(s.unloadDelay)
		}
		status := s.unloadStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	case defaultLoadPath:
		s.loadCalls++
		status := s.loadStatus
		if status == 0 {
			status = http.StatusOK
		}
		if status >= 200 && status < 300 {
			s.loaded = true
			s.unloadPending = false
		}
		w.WriteHeader(status)
	default:
		http.NotFound(w, r)
	}
}

func (s *m71Serving) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unloadCalls, s.loadCalls
}

func (s *m71Serving) inventoryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inventoryCalls
}

func m71HTTPFixture(t *testing.T, serving *m71Serving) (client.Client, Request, EnactCtx, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(serving.handler))
	u, err := url.Parse(server.URL)
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
	pod, event, observation := m95DispatchFixture(t)
	pod.Status.PodIP = host
	pod.Annotations[annoServingPort] = strconv.Itoa(port)
	c := fakeC(pod, event)
	ConfigureAdapterDetectorIdentities([]string{observation.CreatorIdentity})
	req := Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate,
		PolicyName: "policy", PolicyUID: "policy-uid", AdapterObservation: &observation,
	}
	ec := EnactCtx{
		Client: c, Reader: c, JournalNamespace: "operator", VLLM: &httpVLLM{hc: server.Client()},
		AdapterObservationTimeout: 40 * time.Millisecond, AdapterObservationInterval: time.Millisecond,
	}
	return c, req, ec, func() {
		ConfigureAdapterDetectorIdentities(nil)
		server.Close()
	}
}

func TestM071UnloadAcknowledgementNeedsTerminalInventory(t *testing.T) {
	t.Run("202 eventually absent", func(t *testing.T) {
		serving := &m71Serving{loaded: true, unloadStatus: http.StatusAccepted, disappearAfter: 2}
		c, req, ec, done := m71HTTPFixture(t, serving)
		defer done()
		result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
		if err != nil || !result.Emitted {
			t.Fatalf("terminal absence was not accepted: result=%+v err=%v", result, err)
		}
		var pod corev1.Pod
		if err := c.Get(context.Background(), client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations["phorvex.ai/adapter-epoch"] != req.AdapterObservation.EventUID {
			t.Fatalf("completion epoch=%q", pod.Annotations["phorvex.ai/adapter-epoch"])
		}
		if unloads, _ := serving.counts(); unloads != 1 {
			t.Fatalf("unload calls=%d", unloads)
		}
	})

	for _, tc := range []struct {
		name   string
		status int
	}{
		{"200 still present", http.StatusOK},
		{"404 contradicted by inventory", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serving := &m71Serving{loaded: true, unloadStatus: tc.status}
			c, req, ec, done := m71HTTPFixture(t, serving)
			defer done()
			result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
			if err == nil || !result.Emitted || result.MutationKind != "partial" {
				t.Fatalf("unconfirmed effect hidden: result=%+v err=%v", result, err)
			}
			var pod corev1.Pod
			if getErr := c.Get(context.Background(), client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &pod); getErr != nil {
				t.Fatal(getErr)
			}
			if pod.Annotations["phorvex.ai/adapter-epoch"] != "" {
				t.Fatal("unconfirmed unload stamped success epoch")
			}
			cm := &corev1.ConfigMap{}
			name := receiptName(operationReceipt{Kind: "adapter-rotate", PolicyUID: req.PolicyUID, TargetUID: req.TargetUID})
			if getErr := c.Get(context.Background(), client.ObjectKey{Namespace: "operator", Name: name}, cm); getErr != nil {
				t.Fatalf("protected recovery debt missing: %v", getErr)
			}
		})
	}
}

func TestM071AuthoritativeReplacementRefusesBeforeServingRead(t *testing.T) {
	serving := &m71Serving{loaded: true}
	stale, req, ec, done := m71HTTPFixture(t, serving)
	defer done()
	replacement, event, _ := m95DispatchFixture(t)
	replacement.UID = "replacement-pod-uid"
	authoritative := fakeC(replacement, event)
	ec.Client, ec.Reader = stale, authoritative
	result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
	if err != nil || result.Emitted || !strings.Contains(result.Note, "mismatched trusted observation") {
		t.Fatalf("authoritative replacement was not refused: result=%+v err=%v", result, err)
	}
	if serving.inventoryCount() != 0 {
		t.Fatalf("stale cached Pod endpoint received %d inventory request(s)", serving.inventoryCount())
	}
	name := receiptName(operationReceipt{Kind: "adapter-rotate", PolicyUID: req.PolicyUID, TargetUID: req.TargetUID})
	if err := stale.Get(context.Background(), client.ObjectKey{Namespace: "operator", Name: name}, &corev1.ConfigMap{}); err == nil {
		t.Fatal("replacement refusal created protected operation intent")
	}
}

func TestM071SameUIDEndpointDriftUsesOnlyAuthoritativeServingConfig(t *testing.T) {
	staleServing := &m71Serving{loaded: true}
	stale, req, ec, done := m71HTTPFixture(t, staleServing)
	defer done()
	currentServing := &m71Serving{loaded: false}
	currentServer := httptest.NewServer(http.HandlerFunc(currentServing.handler))
	defer currentServer.Close()
	currentURL, err := url.Parse(currentServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	currentHost, currentPortText, err := net.SplitHostPort(currentURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	currentPort, err := strconv.Atoi(currentPortText)
	if err != nil {
		t.Fatal(err)
	}
	current, event, _ := m95DispatchFixture(t)
	event.SetCreationTimestamp(metav1.NewTime(req.AdapterObservation.CreatedAt))
	current.Status.PodIP = currentHost
	current.Annotations[annoServingPort] = strconv.Itoa(currentPort)
	authoritative := fakeC(current, event)
	ec.Client, ec.Reader = stale, authoritative
	result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
	if err != nil || result.Emitted || !strings.Contains(result.Note, "already absent") {
		t.Fatalf("authoritative endpoint result=%+v err=%v", result, err)
	}
	if staleServing.inventoryCount() != 0 || currentServing.inventoryCount() != 1 {
		t.Fatalf("inventory used stale endpoint: stale=%d authoritative=%d", staleServing.inventoryCount(), currentServing.inventoryCount())
	}
}

func TestM071UnloadHTTPTimeoutRetainsUnknownRecoveryDebt(t *testing.T) {
	serving := &m71Serving{loaded: true, unloadDelay: 50 * time.Millisecond}
	_, req, ec, done := m71HTTPFixture(t, serving)
	defer done()
	ec.VLLM = &httpVLLM{hc: &http.Client{Timeout: 5 * time.Millisecond}}
	result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
	if err == nil || !result.Emitted || result.MutationKind != "partial" || result.RollbackRef == "" {
		t.Fatalf("timed-out dispatch did not retain visible protected debt: result=%+v err=%v", result, err)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 0 {
		t.Fatalf("timeout crossed unexpected serving boundary: unload=%d load=%d", unloads, loads)
	}
}

func TestM071RecoveredLoadDispatchDoesNotRepeatUnresolvedPOST(t *testing.T) {
	serving := &m71Serving{loaded: true, unloadStatus: http.StatusOK, loadStatus: http.StatusInternalServerError, disappearAfter: 1}
	c, req, ec, done := m71HTTPFixture(t, serving)
	defer done()
	ec.AdapterSources = AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): "/models/approved"}
	first, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
	if err == nil || !first.Emitted || first.MutationKind != "partial" {
		t.Fatalf("load failure was not retained as partial: result=%+v err=%v", first, err)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 1 {
		t.Fatalf("initial calls unload=%d load=%d", unloads, loads)
	}
	native := &NativeActuator{Client: c, Reader: c, JournalNamespace: "operator", RecoveryVLLM: ec.VLLM, AdapterSources: ec.AdapterSources}
	events, err := native.RecoverOperations(context.Background(), false)
	if err != nil || len(events) != 1 || events[0].Outcome != "partial" || events[0].Err == nil {
		t.Fatalf("restart did not retain unresolved load dispatch: events=%+v err=%v", events, err)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 1 {
		t.Fatalf("restart repeated a serving call: unload=%d load=%d", unloads, loads)
	}
	repeat, err := dispatch(context.Background(), ec, req)
	if err == nil || repeat.MutationKind != "partial" || repeat.RollbackRef == "" {
		t.Fatalf("persistent event did not retain unresolved operation: result=%+v err=%v", repeat, err)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 1 {
		t.Fatalf("unresolved operation repeated: unload=%d load=%d", unloads, loads)
	}
}

func TestM071NewerTrustedEventCanStartOneNewOperation(t *testing.T) {
	serving := &m71Serving{loaded: true, unloadStatus: http.StatusAccepted, loadStatus: http.StatusAccepted, disappearAfter: 1}
	c, oldReq, ec, done := m71HTTPFixture(t, serving)
	defer done()
	ec.AdapterSources = AdapterSources{adapterSourceKey(oldReq.Namespace, oldReq.AdapterObservation.AdapterName): "/models/approved"}
	first, err := (adapterRotateHandler{}).Enact(context.Background(), ec, oldReq)
	if err != nil || !first.Emitted {
		t.Fatalf("first trusted event failed: result=%+v err=%v", first, err)
	}
	_, oldEvent, _ := m95DispatchFixture(t)
	newEvent := oldEvent.DeepCopy()
	newEvent.SetName("detected-new")
	newEvent.SetUID("event-uid-new")
	newEvent.SetResourceVersion("")
	newCreatedAt := oldReq.AdapterObservation.CreatedAt.Add(time.Second)
	newEvent.SetCreationTimestamp(metav1.NewTime(newCreatedAt))
	if err := c.Create(context.Background(), newEvent); err != nil {
		t.Fatal(err)
	}
	newReq := oldReq
	newObservation := *oldReq.AdapterObservation
	newObservation.EventName, newObservation.EventUID, newObservation.CreatedAt = newEvent.GetName(), string(newEvent.GetUID()), newCreatedAt
	newReq.AdapterObservation = &newObservation
	second, err := (adapterRotateHandler{}).Enact(context.Background(), ec, newReq)
	if err != nil || !second.Emitted {
		t.Fatalf("strictly newer trusted event was blocked: result=%+v err=%v", second, err)
	}
	if unloads, loads := serving.counts(); unloads != 2 || loads != 2 {
		t.Fatalf("new event did not produce exactly one new operation: unload=%d load=%d", unloads, loads)
	}
	repeat, err := (adapterRotateHandler{}).Enact(context.Background(), ec, newReq)
	if err != nil || repeat.Emitted {
		t.Fatalf("new event repeated after completion: result=%+v err=%v", repeat, err)
	}
	if _, err := (adapterRotateHandler{}).Enact(context.Background(), ec, oldReq); err == nil {
		t.Fatal("older trusted event replay replaced a newer completed receipt")
	}
	if unloads, loads := serving.counts(); unloads != 2 || loads != 2 {
		t.Fatalf("repeat/replay crossed serving boundary: unload=%d load=%d", unloads, loads)
	}
}

func TestM071UnloadDispatchingRestartObservesBeforeRetry(t *testing.T) {
	serving := &m71Serving{loaded: false, loadStatus: http.StatusOK}
	c, req, ec, done := m71HTTPFixture(t, serving)
	defer done()
	ec.AdapterSources = AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): "/models/approved"}
	var pod corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &pod); err != nil {
		t.Fatal(err)
	}
	r := operationReceipt{
		Version: adapterRotateReceiptVersion, Kind: "adapter-rotate", Phase: "unload-dispatching",
		PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		TargetName: req.Pod, TargetUID: req.TargetUID, TargetLabels: copyLabels(pod.Labels),
		AdapterName: req.AdapterObservation.AdapterName, AdapterSource: "/models/approved", AdapterSourcePresent: true,
		AdapterEventName: req.AdapterObservation.EventName, AdapterEventUID: req.AdapterObservation.EventUID,
		AdapterEventCreatedAt: req.AdapterObservation.CreatedAt.UTC().Format(time.RFC3339Nano),
		AdapterCreator:        req.AdapterObservation.CreatorIdentity, AdapterEndpointSHA256: adapterEndpointConfigDigest(&pod),
	}
	cm, err := journalWrite(context.Background(), ec, r)
	if err != nil {
		t.Fatal(err)
	}
	result, err := continueAdapterOperation(context.Background(), ec, cm, &r, false)
	if err != nil || result.Emitted {
		t.Fatalf("ack-loss recovery failed: result=%+v err=%v", result, err)
	}
	if unloads, loads := serving.counts(); unloads != 0 || loads != 1 {
		t.Fatalf("recovery did not observe before retry: unload=%d load=%d", unloads, loads)
	}
}

func TestM071TerminalReceiptRechecksMembershipBeforeCompletion(t *testing.T) {
	for _, tc := range []struct {
		name, phase    string
		loaded, source bool
	}{
		{name: "absence drifted back to present", phase: "absent-confirmed", loaded: true},
		{name: "restored membership disappeared", phase: "loaded-confirmed", loaded: false, source: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serving := &m71Serving{loaded: tc.loaded}
			c, req, ec, done := m71HTTPFixture(t, serving)
			defer done()
			var pod corev1.Pod
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &pod); err != nil {
				t.Fatal(err)
			}
			source := ""
			if tc.source {
				source = "/models/approved"
				ec.AdapterSources = AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): source}
			}
			r := operationReceipt{
				Version: adapterRotateReceiptVersion, Kind: "adapter-rotate", Phase: tc.phase,
				PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
				TargetName: req.Pod, TargetUID: req.TargetUID, TargetLabels: copyLabels(pod.Labels),
				AdapterName: req.AdapterObservation.AdapterName, AdapterSource: source, AdapterSourcePresent: tc.source,
				AdapterEventName: req.AdapterObservation.EventName, AdapterEventUID: req.AdapterObservation.EventUID,
				AdapterEventCreatedAt: req.AdapterObservation.CreatedAt.UTC().Format(time.RFC3339Nano),
				AdapterCreator:        req.AdapterObservation.CreatorIdentity, AdapterEndpointSHA256: adapterEndpointConfigDigest(&pod),
			}
			cm, err := journalWrite(context.Background(), ec, r)
			if err != nil {
				t.Fatal(err)
			}
			result, err := continueAdapterOperation(context.Background(), ec, cm, &r, false)
			if err == nil || !result.Emitted || result.MutationKind != "partial" || !strings.Contains(err.Error(), "terminal membership drifted") {
				t.Fatalf("terminal drift was credited: result=%+v err=%v", result, err)
			}
			if unloads, loads := serving.counts(); unloads != 0 || loads != 0 {
				t.Fatalf("terminal recheck crossed POST boundary: unload=%d load=%d", unloads, loads)
			}
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &pod); err != nil {
				t.Fatal(err)
			}
			if pod.Annotations["phorvex.ai/adapter-epoch"] != "" {
				t.Fatal("drifted terminal receipt stamped a success epoch")
			}
		})
	}
}

type m71FailPhaseUpdate struct {
	client.Client
	phase  string
	failed bool
}

func (c *m71FailPhaseUpdate) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if cm, ok := obj.(*corev1.ConfigMap); ok && !c.failed {
		var receipt operationReceipt
		if json.Unmarshal([]byte(cm.Data["receipt"]), &receipt) == nil && receipt.Phase == c.phase {
			c.failed = true
			return errors.New("injected adapter journal update outage")
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestM071JournalAckLossRestartReconcilesInventoryBeforePosts(t *testing.T) {
	serving := &m71Serving{loaded: true, unloadStatus: http.StatusAccepted, loadStatus: http.StatusAccepted, disappearAfter: 1}
	base, req, ec, done := m71HTTPFixture(t, serving)
	defer done()
	guarded := &m71FailPhaseUpdate{Client: base, phase: "unload-acknowledged"}
	ec.Client, ec.Reader = guarded, guarded
	ec.AdapterSources = AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): "/models/approved"}
	result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
	if err == nil || !result.Emitted || result.MutationKind != "partial" || !guarded.failed {
		t.Fatalf("journal outage was not retained as recovery debt: result=%+v err=%v", result, err)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 0 {
		t.Fatalf("unexpected initial serving calls: unload=%d load=%d", unloads, loads)
	}
	native := &NativeActuator{Client: guarded, Reader: guarded, JournalNamespace: "operator", RecoveryVLLM: ec.VLLM, AdapterSources: ec.AdapterSources}
	events, recoverErr := native.RecoverOperations(context.Background(), false)
	if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("restart did not reconcile journal loss: events=%+v err=%v", events, recoverErr)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 1 {
		t.Fatalf("restart duplicated or omitted serving operation: unload=%d load=%d", unloads, loads)
	}
}

func TestM071LoadAckJournalLossRestartDoesNotDuplicateLoad(t *testing.T) {
	serving := &m71Serving{loaded: true, unloadStatus: http.StatusAccepted, loadStatus: http.StatusAccepted, disappearAfter: 1}
	base, req, ec, done := m71HTTPFixture(t, serving)
	defer done()
	guarded := &m71FailPhaseUpdate{Client: base, phase: "load-acknowledged"}
	ec.Client, ec.Reader = guarded, guarded
	ec.AdapterSources = AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): "/models/approved"}
	result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
	if err == nil || !result.Emitted || result.MutationKind != "partial" || !guarded.failed {
		t.Fatalf("load acknowledgement loss was not retained: result=%+v err=%v", result, err)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 1 {
		t.Fatalf("unexpected initial serving calls: unload=%d load=%d", unloads, loads)
	}
	native := &NativeActuator{Client: guarded, Reader: guarded, JournalNamespace: "operator", RecoveryVLLM: ec.VLLM, AdapterSources: ec.AdapterSources}
	events, recoverErr := native.RecoverOperations(context.Background(), false)
	if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("restart did not reconcile completed load: events=%+v err=%v", events, recoverErr)
	}
	if unloads, loads := serving.counts(); unloads != 1 || loads != 1 {
		t.Fatalf("restart duplicated an already-completed load: unload=%d load=%d", unloads, loads)
	}
}

func TestM071AbsentBeforeOperationIsNoCreditAndNoPost(t *testing.T) {
	serving := &m71Serving{loaded: false}
	c, req, ec, done := m71HTTPFixture(t, serving)
	defer done()
	result, err := (adapterRotateHandler{}).Enact(context.Background(), ec, req)
	if err != nil || result.Emitted {
		t.Fatalf("preexisting absence miscredited: result=%+v err=%v", result, err)
	}
	if unloads, loads := serving.counts(); unloads != 0 || loads != 0 {
		t.Fatalf("preexisting absence crossed POST boundary: unload=%d load=%d", unloads, loads)
	}
	name := receiptName(operationReceipt{Kind: "adapter-rotate", PolicyUID: req.PolicyUID, TargetUID: req.TargetUID})
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "operator", Name: name}, &corev1.ConfigMap{}); err == nil {
		t.Fatal("preexisting absence created recovery authority")
	}
}

func TestM071HTTPInventoryRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data":[{"id":"%s"}]}`, strings.Repeat("x", servingResponseMaxBytes))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	_, err := (&httpVLLM{hc: server.Client()}).AdapterLoaded(context.Background(), servingEndpoint{podIP: host, port: port, modelsPath: "/"}, "target")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized inventory accepted: %v", err)
	}
}

func TestM071HTTPInventoryRejectsAmbiguousReservedAliases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"target"}],"Data":[]}`))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	loaded, err := (&httpVLLM{hc: server.Client()}).AdapterLoaded(context.Background(), servingEndpoint{podIP: host, port: port, modelsPath: "/"}, "target")
	if err == nil || loaded || !strings.Contains(err.Error(), "invalid bounded response") {
		t.Fatalf("ambiguous inventory fabricated membership: loaded=%t err=%v", loaded, err)
	}
}

func TestM071HTTPInventoryStrictProducerCases(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
		wantErr    bool
	}{
		{name: "exact", body: `{"data":[{"id":"target"}]}`, want: true},
		{name: "exact collision", body: `{"data":[{"id":"target-v2"}]}`},
		{name: "duplicate id", body: `{"data":[{"id":"target"},{"id":"target"}]}`, wantErr: true},
		{name: "duplicate field", body: `{"data":[{"id":"target","id":"other"}]}`, wantErr: true},
		{name: "trailing value", body: `{"data":[]} {}`, wantErr: true},
		{name: "malformed", body: `{"data":[}`, wantErr: true},
		{name: "missing inventory", body: `{"object":"list"}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			host, portText, _ := net.SplitHostPort(u.Host)
			port, _ := strconv.Atoi(portText)
			loaded, err := (&httpVLLM{hc: server.Client()}).AdapterLoaded(context.Background(), servingEndpoint{podIP: host, port: port, modelsPath: "/"}, "target")
			if loaded != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("loaded=%t err=%v, want loaded=%t error=%t", loaded, err, tc.want, tc.wantErr)
			}
		})
	}
}

type m71RoundTripper func(*http.Request) (*http.Response, error)

func (f m71RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type m71FailingBody struct{ first bool }

func (b *m71FailingBody) Read(p []byte) (int, error) {
	if !b.first {
		b.first = true
		return copy(p, `{"data":`), nil
	}
	return 0, errors.New("injected response read failure")
}
func (*m71FailingBody) Close() error { return nil }

func TestM071HTTPInventoryReadFailureIsUnknown(t *testing.T) {
	hc := &http.Client{Transport: m71RoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: &m71FailingBody{}, Header: make(http.Header)}, nil
	})}
	loaded, err := (&httpVLLM{hc: hc}).AdapterLoaded(context.Background(), servingEndpoint{podIP: "127.0.0.1", port: 1, modelsPath: "/"}, "target")
	if err == nil || loaded || !strings.Contains(err.Error(), "read serving response") {
		t.Fatalf("failed response read fabricated absence: loaded=%t err=%v", loaded, err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !strings.Contains(err.Error(), "injected response read failure") {
		t.Fatalf("response read cause was lost: %v", err)
	}
}
