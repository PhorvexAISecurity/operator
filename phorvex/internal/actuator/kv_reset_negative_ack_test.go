package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func negativeReceipt(t *testing.T, f *m093Fixture) (*corev1.ConfigMap, operationReceipt) {
	t.Helper()
	cm, r, e := servingReceiptGet(t.Context(), EnactCtx{Reader: f.client, JournalNamespace: "operator"}, string(f.pod.UID), model.ActionKVReset)
	if e != nil {
		t.Fatal(e)
	}
	return cm, r
}
func assertNegativeEpochUnchanged(t *testing.T, f *m093Fixture, r operationReceipt) {
	t.Helper()
	p := &corev1.Pod{}
	if e := f.client.Get(t.Context(), client.ObjectKeyFromObject(f.pod), p); e != nil {
		t.Fatal(e)
	}
	if !servingObservationMatches(p, r) || r.ExpectedReset != r.SelectedReset {
		t.Fatal("negative ACK changed selected epochs")
	}
}

func TestKVResetNegativeACKRealTLSPartialAllocatorAndSameOperationRetry(t *testing.T) {
	var requests, firstAllocatorReset atomic.Int64
	var complete atomic.Bool
	const body = `{"success":false}`
	f := newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != defaultResetPath || r.Header.Get("Authorization") != "Bearer trusted-token-1" {
			t.Error("wrong authenticated reset request")
			w.WriteHeader(401)
			return
		}
		requests.Add(1)
		// Reproduce the actual non-atomic allocator behavior: allocator1 is reset,
		// allocator2 refuses with live blocks, and aggregate success is false.
		firstAllocatorReset.Add(1)
		if complete.Load() {
			w.Write([]byte(`{"success":true}`))
			return
		}
		w.Write([]byte(body))
	}))
	req := f.request(model.ActionKVReset)
	result, e := f.native(t).Actuate(t.Context(), req)
	if e == nil || result.Emitted || result.NoEffect == NoEffectRefused || result.MutationKind != "partial" || firstAllocatorReset.Load() != 1 {
		t.Fatalf("partial allocator response miscredited: %+v %v", result, e)
	}
	_, receipt := negativeReceipt(t, f)
	h := sha256.Sum256([]byte(body))
	if receipt.Phase != "terminal-partial" || receipt.KVResetNegativeACK == nil || receipt.KVResetNegativeACK.ResponseSHA256 != hex.EncodeToString(h[:]) || receipt.KVResetNegativeACK.Success == nil || *receipt.KVResetNegativeACK.Success {
		t.Fatal("strict negative proof missing")
	}
	assertNegativeEpochUnchanged(t, f, receipt)
	for i := 0; i < 2; i++ { // A new NativeActuator reads the durable receipt after restart.
		retry, e := f.native(t).Actuate(t.Context(), req)
		if e != nil || retry.Emitted || retry.NoEffect != NoEffectReconciled || retry.MutationKind != "none" || requests.Load() != 1 || !strings.Contains(retry.Note, "negative acknowledgement") {
			t.Fatalf("terminal retry repeated/miscredited POST: %+v %v", retry, e)
		}
	}
	cm, _ := negativeReceipt(t, f)
	if note, e := recoverProtectedServingEffect(t.Context(), EnactCtx{Reader: f.client, Client: f.client, ServingSecurity: f.config}, cm, &receipt); e != nil || !strings.Contains(note, "negative acknowledgement") || requests.Load() != 1 {
		t.Fatalf("maintenance repeated terminal: %s %v", note, e)
	}
	// A separate fresh ordinary selected request may progress the domain. This
	// is not replay or automatic retry of the old false result.
	complete.Store(true)
	fresh := f.request(model.ActionKVReset)
	fresh.TickID = req.TickID + "-fresh"
	next, e := f.native(t).Actuate(t.Context(), fresh)
	_, current := negativeReceipt(t, f)
	if e != nil || !next.Emitted || requests.Load() != 2 || current.Generation != receipt.Generation+1 || current.Phase != "terminal-full" || current.KVResetNegativeACK != nil {
		t.Fatalf("fresh selection did not independently progress: %+v %v", next, e)
	}
}

type negativeACKLostCASClient struct {
	client.Client
	apply, failed bool
}

func (c *negativeACKLostCASClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if cm, ok := obj.(*corev1.ConfigMap); ok && !c.failed && strings.Contains(cm.Data["receipt"], `"kvResetNegativeACK"`) {
		c.failed = true
		if c.apply {
			if e := c.Client.Update(ctx, obj, opts...); e != nil {
				return e
			}
		}
		return errors.New("negative proof update acknowledgement lost")
	}
	return c.Client.Update(ctx, obj, opts...)
}
func TestKVResetNegativeACKLostCASRetainsUnknownUntilDurableRead(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "not-applied", true: "applied"}[apply], func(t *testing.T) {
			var requests atomic.Int64
			f := newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte(`{"success":false}`)) }))
			f.client = &negativeACKLostCASClient{Client: f.client, apply: apply}
			req := f.request(model.ActionKVReset)
			result, e := f.native(t).Actuate(t.Context(), req)
			if e == nil || result.Emitted || result.NoEffect == NoEffectRefused || !strings.Contains(result.Note, "phase dispatching") {
				t.Fatalf("lost CAS fabricated terminal: %+v %v", result, e)
			}
			_, r := negativeReceipt(t, f)
			if (r.Phase == "terminal-partial") != apply {
				t.Fatal("wrong durable phase")
			}
			retry, e := f.native(t).Actuate(t.Context(), req)
			if requests.Load() != 1 || retry.Emitted || (e == nil) != apply || (retry.NoEffect == NoEffectReconciled) != apply {
				t.Fatalf("retry repeated POST or invented proof: %+v %v", retry, e)
			}
			cm, r := negativeReceipt(t, f)
			_, _ = recoverProtectedServingEffect(t.Context(), EnactCtx{Client: f.client, Reader: f.client, ServingSecurity: f.config}, cm, &r)
			if requests.Load() != 1 {
				t.Fatal("maintenance repeated POST")
			}
		})
	}
}

func TestKVResetNegativeACKMalformedAndHTTPFailuresRemainUnknown(t *testing.T) {
	for name, body := range map[string]string{"missing": "{}", "null": `{"success":null}`, "wrongtype": `{"success":"false"}`, "alias": `{"Success":false}`, "duplicate": `{"success":false,"success":false}`, "aliascollision": `{"success":false,"SUCCESS":false}`, "trailing": `{"success":false}x`, "multiple": `{"success":false}{}`, "empty": "", "http-error": `{"success":false}`} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int64
			f := newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if name == "http-error" {
					w.WriteHeader(503)
				}
				w.Write([]byte(body))
			}))
			req := f.request(model.ActionKVReset)
			result, e := f.native(t).Actuate(t.Context(), req)
			_, r := negativeReceipt(t, f)
			if e == nil || !errors.Is(e, errServingOutcomeUnknown) || result.Emitted || r.Phase != "dispatching" || r.KVResetNegativeACK != nil {
				t.Fatalf("ambiguous result promoted: %+v %v", result, e)
			}
			_, _ = f.native(t).Actuate(t.Context(), req)
			if requests.Load() != 1 {
				t.Fatal("unknown response retried POST")
			}
		})
	}
}

func TestKVResetNegativeACKAuthorityDriftBeforeTerminalCAS(t *testing.T) {
	for _, name := range []string{"pod-uid", "selected-epoch", "policy-disabled", "binding"} {
		t.Run(name, func(t *testing.T) {
			var f *m093Fixture
			f = newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "policy-disabled" {
					p := &v1alpha1.PhorvexPolicy{}
					if e := f.client.Get(r.Context(), client.ObjectKeyFromObject(f.policy), p); e != nil {
						t.Error(e)
					}
					p.Spec.Actions.Enabled = nil
					if e := f.client.Update(r.Context(), p); e != nil {
						t.Error(e)
					}
				} else {
					p := &corev1.Pod{}
					if e := f.client.Get(r.Context(), client.ObjectKeyFromObject(f.pod), p); e != nil {
						t.Error(e)
					}
					switch name {
					case "pod-uid":
						p.UID = "replaced"
					case "selected-epoch":
						p.Annotations[annoKVResetEpoch] = "different"
					case "binding":
						p.Spec.ServiceAccountName = "foreign"
					}
					if e := f.client.Update(r.Context(), p); e != nil {
						t.Error(e)
					}
				}
				w.Write([]byte(`{"success":false}`))
			}))
			result, e := f.native(t).Actuate(t.Context(), f.request(model.ActionKVReset))
			_, r := negativeReceipt(t, f)
			if e == nil || result.Emitted || r.Phase != "dispatching" || r.KVResetNegativeACK != nil {
				t.Fatalf("changed authority promoted proof: %+v %v", result, e)
			}
		})
	}
}

func TestKVResetNegativeACKReceiptRejectsUnboundShapes(t *testing.T) {
	p := aiPod("ns", "infer", nil)
	r := m064PreparedReceipt(p, model.ActionKVReset, "proof-tick")
	r.ServingLegacy = false
	r.ServingBindingSHA256 = strings.Repeat("a", 64)
	r.Phase = "terminal-partial"
	r.ExpectedReset = r.SelectedReset
	v := false
	r.KVResetNegativeACK = &kvResetNegativeACKProof{HTTPStatus: 200, Success: &v, ResponseSHA256: strings.Repeat("b", 64)}
	if !r.valid() {
		t.Fatal("bound negative receipt rejected")
	}
	for name, change := range map[string]func(*operationReceipt){"missing-bool": func(r *operationReceipt) { r.KVResetNegativeACK.Success = nil }, "true": func(r *operationReceipt) { v := true; r.KVResetNegativeACK.Success = &v }, "wrong-http": func(r *operationReceipt) { r.KVResetNegativeACK.HTTPStatus = 503 }, "wrong-hash": func(r *operationReceipt) { r.KVResetNegativeACK.ResponseSHA256 = "" }, "legacy": func(r *operationReceipt) { r.ServingLegacy = true; r.ServingBindingSHA256 = "" }, "success-epoch": func(r *operationReceipt) {
		r.ExpectedReset = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
	}, "wrong-phase": func(r *operationReceipt) { r.Phase = "dispatching" }, "other-action": func(r *operationReceipt) { r.Kind = string(model.ActionGuardrailRotate) }, "no-proof": func(r *operationReceipt) { r.KVResetNegativeACK = nil }} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(r)
			var x operationReceipt
			json.Unmarshal(b, &x)
			change(&x)
			if x.valid() {
				t.Fatal("unbound proof accepted")
			}
		})
	}
}

func TestKVResetNegativeACKDoesNotPromoteExistingDispatchingReceipt(t *testing.T) {
	var requests atomic.Int64
	f := newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte(`{"success":false}`)) }))
	req := f.request(model.ActionKVReset)
	ec := EnactCtx{Client: f.client, Reader: f.client, JournalNamespace: "operator", ServingSecurity: f.config}
	if e := prepareServingAttempt(t.Context(), &ec, req); e != nil {
		t.Fatal(e)
	}
	r := m064PreparedReceipt(f.pod, model.ActionKVReset, req.TickID)
	r.Generation = 28
	r.Phase = "dispatching"
	r.ServingBindingSHA256, r.ServingServiceAccount, r.ServingLegacy = receiptSecurity(ec, f.pod)
	cm, e := journalWrite(t.Context(), ec, r)
	if e != nil {
		t.Fatal(e)
	}
	original, RV := cm.Data["receipt"], cm.ResourceVersion
	fresh := f.request(model.ActionKVReset)
	fresh.TickID = req.TickID + "-new"
	result, e := f.native(t).Actuate(t.Context(), fresh)
	if e == nil || result.Emitted || requests.Load() != 0 {
		t.Fatalf("legacy unknown sent new reset: %+v %v", result, e)
	}
	if _, e := recoverProtectedServingEffect(t.Context(), ec, cm, &r); e == nil || requests.Load() != 0 {
		t.Fatal("unknown recovery invented negative proof or resent POST")
	}
	current, recorded := negativeReceipt(t, f)
	if current.Data["receipt"] != original || current.ResourceVersion != RV || recorded.Generation != 28 || recorded.Phase != "dispatching" || recorded.KVResetNegativeACK != nil {
		t.Fatal("existing unknown receipt rewritten")
	}
}

func TestKVResetNegativeACKPlaintextProducerRemainsUnknown(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte(`{"success":false}`))
	}))
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Status.PodIP = host
	pod.Annotations[annoServingPort] = port
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal(err)
	}
	c := fakeC(pod)
	ec := EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: newHTTPVLLM(), ServingSecurity: legacyServingSecurityForTest(t)}
	req := boundReq(pod, model.ActionKVReset)
	if err := prepareServingAttempt(t.Context(), &ec, req); err != nil {
		t.Fatal(err)
	}
	result, err := (kvResetHandler{}).Enact(t.Context(), ec, req)
	_, r, readErr := servingReceiptGet(t.Context(), ec, string(pod.UID), model.ActionKVReset)
	if err == nil || !errors.Is(err, errServingOutcomeUnknown) || result.Emitted || requests.Load() != 1 || readErr != nil || r.Phase != "dispatching" || r.KVResetNegativeACK != nil {
		t.Fatalf("plaintext false promoted to authenticated proof: %+v err=%v read=%v calls=%d", result, err, readErr, requests.Load())
	}
}
