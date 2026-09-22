package actuator

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/internal/model"
)

type m036APIFixture struct {
	*m064APIFixture
	security *ServingSecurityConfig
	receiver *m064HTTPReceiver
	native   *NativeActuator
}

func newM036APIFixture(t *testing.T, ctx context.Context, c client.Client, receiver *m064HTTPReceiver, server *httptest.Server, id, current, roster string) *m036APIFixture {
	t.Helper()
	f := newM064APIFixture(t, ctx, c, id, server.URL, model.ActionGuardrailRotate)
	pod := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	pod.Labels[labelGuardrailTier] = "true"
	if current == "" {
		delete(pod.Annotations, annoGuardrailVariant)
	} else {
		pod.Annotations[annoGuardrailVariant] = current
	}
	pod.Annotations[annoGuardrailAlts] = roster
	if err := c.Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	f.pod = pod

	const token = "m036-guardrail-token"
	cert := server.Certificate()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: f.opns, Name: "guardrail-auth"}, Data: map[string][]byte{"token": []byte(token), "ca": ca}}
	if err := c.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	serverName := host
	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) > 0 {
		serverName = cert.IPAddresses[0].String()
	}
	binding := ServingSecurityBinding{
		Namespace: f.ns, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: "default",
		ProfileID: "m036-guardrail", SecretName: secret.Name, BearerKey: "token", CAKey: "ca", ServerName: serverName,
	}
	security := writeServingSecurityConfig(t, ServingSecuritySecureRequired, f.opns, []ServingSecurityBinding{binding})
	receiver.configure(http.StatusNoContent, token, nil)
	native := NewNativeActuator(c)
	native.Reader, native.JournalNamespace = c, f.opns
	native.SetServingSecurity(security)
	if err := native.EnsurePolicy(ctx, TenantTarget{Tenant: id, Namespace: f.ns}); err != nil {
		t.Fatal(err)
	}
	return &m036APIFixture{m064APIFixture: f, security: security, receiver: receiver, native: native}
}

func (f *m036APIFixture) request(t *testing.T, tick string) Request {
	t.Helper()
	req := f.selectRequest(t, model.ActionGuardrailRotate, tick)
	req.Tenant = strings.TrimPrefix(f.ns, "m064-")
	return req
}

func (f *m036APIFixture) setRoster(t *testing.T, current, roster string) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	if current != "" {
		pod.Annotations[annoGuardrailVariant] = current
	}
	pod.Annotations[annoGuardrailAlts] = roster
	if err := f.client.Update(f.ctx, pod); err != nil {
		t.Fatal(err)
	}
	return pod
}

func (f *m036APIFixture) receipt(t *testing.T) (*corev1.ConfigMap, operationReceipt) {
	t.Helper()
	cm, receipt, err := servingReceiptGet(f.ctx, EnactCtx{Reader: f.client, JournalNamespace: f.opns}, string(f.pod.UID), model.ActionGuardrailRotate)
	if err != nil {
		t.Fatal(err)
	}
	return cm, receipt
}

// This is an isolated real kube-apiserver/etcd plus authenticated custom-CA TLS
// source control. It does not establish backend deployment or CNI behavior.
func TestM036RealAPITLSOrderedGuardrailRosterLifecycle(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	receiver := &m064HTTPReceiver{}
	server := httptest.NewTLSServer(receiver)
	t.Cleanup(server.Close)

	t.Run("three-cycle-whitespace-dedup-terminal-and-rollback", func(t *testing.T) {
		f := newM036APIFixture(t, ctx, apiClient, receiver, server, "three", " v1 ", " v1, v2, v2, v3 ")
		var slotUID, firstRollbackRef string
		var previousOperation string
		var lastReq Request
		beforeVariants := len(receiver.observedVariants())
		for i, want := range []string{"v2", "v3", "v1"} {
			pod := &corev1.Pod{}
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			target := Target{Namespace: pod.Namespace, Pod: pod.Name, UID: string(pod.UID), Labels: copyLabels(pod.Labels),
				PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: normalizeServiceAccount(pod.Spec.ServiceAccountName)}
			if ok, why := f.native.SupportsAction(ctx, model.ActionGuardrailRotate, target); !ok {
				t.Fatalf("cycle %d coherent terminal capability support=(%v,%q)", i, ok, why)
			}
			prior := strings.TrimSpace(pod.Annotations[annoGuardrailVariant])
			req := f.request(t, "m036-three-"+strconv.Itoa(i))
			result, err := f.native.Actuate(ctx, req)
			if err != nil || !result.Emitted || result.MutationKind != "reversible" || result.RollbackRef == "" {
				t.Fatalf("cycle %d result=%+v err=%v", i, result, err)
			}
			cm, receipt := f.receipt(t)
			if receipt.Phase != "terminal-full" || receipt.Generation != uint64(i+1) || receipt.PriorVariant != prior || receipt.NextVariant != want || receipt.OperationID == previousOperation {
				t.Fatalf("cycle %d receipt=%+v, want generation=%d pair=%s/%s", i, receipt, i+1, prior, want)
			}
			if i == 0 {
				slotUID, firstRollbackRef = string(cm.UID), result.RollbackRef
			} else if string(cm.UID) != slotUID {
				t.Fatalf("cycle %d replaced stable receipt slot %q with %q", i, slotUID, cm.UID)
			}
			previousOperation = receipt.OperationID
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			if pod.Annotations[annoGuardrailVariant] != want || pod.Annotations[annoGuardrailSnap] != prior || pod.Labels["phorvex.ai/guardrail-epoch"] != epochToken(receipt.OperationID, "apply") {
				t.Fatalf("cycle %d metadata labels=%v annotations=%v", i, pod.Labels, pod.Annotations)
			}
			calls := receiver.calls.Load()
			reconciled, retryErr := f.native.Actuate(ctx, req)
			if retryErr != nil || reconciled.Emitted || reconciled.NoEffect != NoEffectReconciled || receiver.calls.Load() != calls {
				t.Fatalf("cycle %d same operation repeated: result=%+v calls=%d/%d err=%v", i, reconciled, receiver.calls.Load(), calls, retryErr)
			}
			if i == 1 {
				calls = receiver.calls.Load()
				if err := f.native.Rollback(ctx, req, firstRollbackRef); err == nil || receiver.calls.Load() != calls {
					t.Fatalf("superseded rollback escaped: calls=%d/%d err=%v", receiver.calls.Load(), calls, err)
				}
			}
			lastReq = req
		}
		got := receiver.observedVariants()[beforeVariants:]
		if strings.Join(got, ",") != "v2,v3,v1" {
			t.Fatalf("canonical ordered payloads=%v", got)
		}

		_, terminalBefore := f.receipt(t)
		cmBefore, _, err := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: f.opns}, lastReq.TargetUID, lastReq.Action)
		if err != nil {
			t.Fatal(err)
		}
		f.setRoster(t, "v2", "v1,,v2")
		calls := receiver.calls.Load()
		driftedPod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), driftedPod); err != nil {
			t.Fatal(err)
		}
		driftedTarget := Target{Namespace: driftedPod.Namespace, Pod: driftedPod.Name, UID: string(driftedPod.UID), Labels: copyLabels(driftedPod.Labels),
			PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: normalizeServiceAccount(driftedPod.Spec.ServiceAccountName)}
		if ok, why := f.native.SupportsAction(ctx, model.ActionGuardrailRotate, driftedTarget); ok || !strings.Contains(why, "terminal guardrail-variant-v1 authority or expected state drifted") {
			t.Fatalf("drifted terminal capability support=(%v,%q), want preselection exclusion", ok, why)
		}
		f.setRoster(t, "v1", "v1,,v2")
		reconciled, err := f.native.Actuate(ctx, lastReq)
		if err != nil || reconciled.NoEffect != NoEffectReconciled || reconciled.Emitted || receiver.calls.Load() != calls {
			t.Fatalf("terminal same operation did not reconcile malformed current roster: result=%+v calls=%d/%d err=%v", reconciled, receiver.calls.Load(), calls, err)
		}
		fresh := f.request(t, "m036-malformed-fresh")
		refused, err := f.native.Actuate(ctx, fresh)
		if err == nil || !IsNoEffectRefusal(err) || refused.Emitted || receiver.calls.Load() != calls {
			t.Fatalf("fresh malformed roster reached serving effect: result=%+v calls=%d/%d err=%v", refused, receiver.calls.Load(), calls, err)
		}
		cmAfter, terminalAfter := f.receipt(t)
		if cmAfter.UID != cmBefore.UID || cmAfter.ResourceVersion != cmBefore.ResourceVersion || terminalAfter.OperationID != terminalBefore.OperationID || terminalAfter.Generation != terminalBefore.Generation {
			t.Fatalf("malformed fresh refusal changed terminal receipt: before=%+v after=%+v rv=%s/%s", terminalBefore, terminalAfter, cmBefore.ResourceVersion, cmAfter.ResourceVersion)
		}

		f.setRoster(t, "", "v1,v2,v3")
		calls = receiver.calls.Load()
		if err := f.native.Rollback(ctx, lastReq, servingReceiptRef(cmAfter, terminalAfter)); err != nil || receiver.calls.Load() != calls+1 {
			t.Fatalf("explicit rollback: calls=%d/%d err=%v", receiver.calls.Load(), calls+1, err)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations[annoGuardrailVariant] != "v3" || pod.Labels["phorvex.ai/guardrail-epoch"] != epochToken(terminalAfter.OperationID, "rollback") {
			t.Fatalf("rollback did not restore fixed prior: labels=%v annotations=%v", pod.Labels, pod.Annotations)
		}
	})

	t.Run("two-member-pgv2-to-pgv1", func(t *testing.T) {
		f := newM036APIFixture(t, ctx, apiClient, receiver, server, "two", "pgv2", "pgv2,pgv1")
		before := len(receiver.observedVariants())
		var lastReq Request
		var rollbackRef string
		for i, want := range []string{"pgv1", "pgv2", "pgv1"} {
			pod := &corev1.Pod{}
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				t.Fatal(err)
			}
			target := Target{Namespace: pod.Namespace, Pod: pod.Name, UID: string(pod.UID), Labels: copyLabels(pod.Labels),
				PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: normalizeServiceAccount(pod.Spec.ServiceAccountName)}
			if ok, why := f.native.SupportsAction(ctx, model.ActionGuardrailRotate, target); !ok {
				t.Fatalf("two-member cycle %d coherent terminal capability support=(%v,%q)", i, ok, why)
			}
			lastReq = f.request(t, "m036-two-"+strconv.Itoa(i))
			result, err := f.native.Actuate(ctx, lastReq)
			if err != nil || !result.Emitted {
				t.Fatalf("two-member cycle %d result=%+v err=%v", i, result, err)
			}
			rollbackRef = result.RollbackRef
			_, receipt := f.receipt(t)
			if receipt.Generation != uint64(i+1) || receipt.NextVariant != want {
				t.Fatalf("two-member cycle %d receipt=%+v", i, receipt)
			}
		}
		if got := strings.Join(receiver.observedVariants()[before:], ","); got != "pgv1,pgv2,pgv1" {
			t.Fatalf("two-member payload sequence=%q", got)
		}
		f.setRoster(t, "", "pgv1,pgv3")
		calls := receiver.calls.Load()
		if err := f.native.Rollback(ctx, lastReq, rollbackRef); err == nil || receiver.calls.Load() != calls {
			t.Fatalf("rollback used a substitute predecessor: calls=%d/%d err=%v", receiver.calls.Load(), calls, err)
		}
	})

	t.Run("queued-outcome-retains-fixed-intent-after-roster-change", func(t *testing.T) {
		f := newM036APIFixture(t, ctx, apiClient, receiver, server, "queued", "v1", "v1,v2,v3")
		receiver.configure(http.StatusAccepted, "m036-guardrail-token", nil)
		before := receiver.calls.Load()
		req := f.request(t, "m036-queued")
		result, err := f.native.Actuate(ctx, req)
		if err == nil || result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("queued result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before+1, err)
		}
		f.setRoster(t, "", "v1,,v2")
		for _, retry := range []Request{req, f.request(t, "m036-queued-contender")} {
			got, retryErr := f.native.Actuate(ctx, retry)
			if retryErr == nil || got.Emitted || got.MutationKind != "partial" || got.NoEffect != "" || receiver.calls.Load() != before+1 {
				t.Fatalf("queued retry escaped: result=%+v calls=%d/%d err=%v", got, receiver.calls.Load(), before+1, retryErr)
			}
		}
		_, receipt := f.receipt(t)
		if receipt.Phase != "dispatching" || receipt.PriorVariant != "v1" || receipt.NextVariant != "v2" {
			t.Fatalf("queued receipt lost fixed intent: %+v", receipt)
		}
		receiver.configure(http.StatusNoContent, "m036-guardrail-token", nil)
	})

	t.Run("confirmed-effect-converges-metadata-after-roster-reorder", func(t *testing.T) {
		f := newM036APIFixture(t, ctx, apiClient, receiver, server, "confirmed", "v1", "v1,v2,v3")
		req := f.request(t, "m036-confirmed")
		fault := &m064APIFaultClient{Client: apiClient, updateMode: "ack-loss", phase: "effect-confirmed"}
		native := NewNativeActuator(fault)
		native.Reader, native.JournalNamespace = apiClient, f.opns
		native.SetServingSecurity(f.security)
		if err := native.EnsurePolicy(ctx, TenantTarget{Tenant: req.Tenant, Namespace: req.Namespace}); err != nil {
			t.Fatal(err)
		}
		before := receiver.calls.Load()
		result, err := native.Actuate(ctx, req)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("effect-confirmed acknowledgement loss: result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before+1, err)
		}
		f.setRoster(t, "", "v3,v1,v2")
		restarted := NewNativeActuator(apiClient)
		restarted.Reader, restarted.JournalNamespace = apiClient, f.opns
		restarted.SetServingSecurity(f.security)
		events, err := restarted.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || events[0].Err != nil || receiver.calls.Load() != before+1 {
			t.Fatalf("metadata-only recovery after reorder: events=%+v calls=%d/%d err=%v", events, receiver.calls.Load(), before+1, err)
		}
		pod := &corev1.Pod{}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations[annoGuardrailVariant] != "v2" {
			t.Fatalf("confirmed fixed successor was redirected: annotations=%v", pod.Annotations)
		}
	})

	t.Run("confirmed-effect-owned-conflict-converges-after-restoration", func(t *testing.T) {
		f := newM036APIFixture(t, ctx, apiClient, receiver, server, "metadata-conflict", " v1 ", "v1,v2,v3")
		req := f.request(t, "m036-metadata-conflict")
		receiver.configure(http.StatusNoContent, "m036-guardrail-token", func() error {
			pod := &corev1.Pod{}
			if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
				return err
			}
			pod.Annotations[annoGuardrailVariant] = "external-owner"
			return apiClient.Update(ctx, pod)
		})
		before := receiver.calls.Load()
		result, err := f.native.Actuate(ctx, req)
		if err == nil || !result.Emitted || result.MutationKind != "partial" || receiver.calls.Load() != before+1 {
			t.Fatalf("confirmed metadata conflict: result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before+1, err)
		}
		_, receipt := f.receipt(t)
		if receipt.Phase != "effect-confirmed" || receipt.PriorVariant != "v1" || receipt.NextVariant != "v2" {
			t.Fatalf("confirmed conflict lost fixed intent: %+v", receipt)
		}
		pod := f.setRoster(t, " v1 ", "v3,v1,v2")
		if pod.Annotations[annoGuardrailVariant] != " v1 " {
			t.Fatalf("fixture did not restore exact whitespace declaration: %q", pod.Annotations[annoGuardrailVariant])
		}
		restarted := NewNativeActuator(apiClient)
		restarted.Reader, restarted.JournalNamespace = apiClient, f.opns
		restarted.SetServingSecurity(f.security)
		events, err := restarted.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || events[0].Err != nil || receiver.calls.Load() != before+1 {
			t.Fatalf("restored owned state did not converge metadata-only: events=%+v calls=%d/%d err=%v", events, receiver.calls.Load(), before+1, err)
		}
		if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Annotations[annoGuardrailVariant] != "v2" || pod.Annotations[annoGuardrailSnap] != "v1" {
			t.Fatalf("metadata recovery did not record canonical fixed pair: %v", pod.Annotations)
		}
		receiver.configure(http.StatusNoContent, "m036-guardrail-token", nil)
	})

	t.Run("prepared-recovery-reorder-and-removal", func(t *testing.T) {
		for _, tc := range []struct {
			name, changedRoster string
			wantSend            bool
		}{
			{name: "reorder", changedRoster: "v3,v1,v2", wantSend: true},
			{name: "remove-fixed-next", changedRoster: "v1,v3"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newM036APIFixture(t, ctx, apiClient, receiver, server, "prepared-"+strings.ReplaceAll(tc.name, "-", ""), "v1", "v1,v2,v3")
				req := f.request(t, "m036-prepared-"+tc.name)
				ec := EnactCtx{Client: apiClient, Reader: apiClient, JournalNamespace: f.opns, ServingSecurity: f.security}
				if err := prepareServingAttempt(ctx, &ec, req); err != nil {
					t.Fatal(err)
				}
				cm, receipt, fresh, _, err := prepareServingReceipt(ctx, ec, req, ec.ServingTarget, nil, "v1", "v2")
				if err != nil || !fresh || cm == nil || receipt.Phase != "prepared" {
					t.Fatalf("prepared receipt: fresh=%t receipt=%+v err=%v", fresh, receipt, err)
				}
				f.setRoster(t, "", tc.changedRoster)
				before := receiver.calls.Load()
				restarted := NewNativeActuator(apiClient)
				restarted.Reader, restarted.JournalNamespace = apiClient, f.opns
				restarted.SetServingSecurity(f.security)
				events, err := restarted.RecoverOperations(ctx, false)
				if err != nil || len(events) != 1 {
					t.Fatalf("prepared recovery events=%+v err=%v", events, err)
				}
				if tc.wantSend {
					if events[0].Err != nil || events[0].Outcome != "confirmed" || receiver.calls.Load() != before+1 {
						t.Fatalf("reordered recovery: events=%+v calls=%d/%d", events, receiver.calls.Load(), before+1)
					}
					_, after := f.receipt(t)
					if after.NextVariant != "v2" || after.Phase != "terminal-full" {
						t.Fatalf("reordered recovery changed intent: %+v", after)
					}
				} else {
					if events[0].Err == nil || receiver.calls.Load() != before {
						t.Fatalf("removed fixed member reached backend: events=%+v calls=%d/%d", events, receiver.calls.Load(), before)
					}
					_, after := f.receipt(t)
					if after.Phase != "prepared" || after.OperationID != receipt.OperationID {
						t.Fatalf("removed member changed protected receipt: %+v", after)
					}
				}
			})
		}
	})

	t.Run("fresh-malformed-roster-has-no-journal-or-request", func(t *testing.T) {
		for _, tc := range []struct {
			name, current, roster string
		}{
			{name: "missing-current", roster: "v1,v2"},
			{name: "current-outside", current: "v3", roster: "v1,v2"},
			{name: "singleton", current: "v1", roster: "v1"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newM036APIFixture(t, ctx, apiClient, receiver, server, "malformed-"+strings.ReplaceAll(tc.name, "-", ""), tc.current, tc.roster)
				before := receiver.calls.Load()
				result, err := f.native.Actuate(ctx, f.request(t, "m036-malformed-"+tc.name))
				if err == nil || !IsNoEffectRefusal(err) || result.Emitted || receiver.calls.Load() != before {
					t.Fatalf("malformed roster result=%+v calls=%d/%d err=%v", result, receiver.calls.Load(), before, err)
				}
				if _, _, err := servingReceiptGet(ctx, EnactCtx{Reader: apiClient, JournalNamespace: f.opns}, string(f.pod.UID), model.ActionGuardrailRotate); !apierrors.IsNotFound(err) {
					t.Fatalf("malformed roster created protected receipt: %v", err)
				}
				pod := &corev1.Pod{}
				if err := apiClient.Get(ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
					t.Fatal(err)
				}
				gotCurrent, present := pod.Annotations[annoGuardrailVariant]
				if gotCurrent != tc.current || present != (tc.current != "") || pod.Annotations[annoGuardrailAlts] != tc.roster || pod.Annotations[annoGuardrailSnap] != "" || pod.Labels["phorvex.ai/guardrail-epoch"] != "" {
					t.Fatalf("malformed refusal changed target: labels=%v annotations=%v", pod.Labels, pod.Annotations)
				}
			})
		}
	})
}
