package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type m064AfterClaimClient struct {
	client.Client
	mutate func(context.Context, client.Client) error
	fired  bool
}

func (c *m064AfterClaimClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || c.fired {
		return nil
	}
	var r operationReceipt
	if json.Unmarshal([]byte(cm.Data["receipt"]), &r) != nil || r.Version != servingEffectReceiptVersion || r.Phase != "dispatching" {
		return nil
	}
	c.fired = true
	return c.mutate(ctx, c.Client)
}

func m064PreparedReceipt(pod *corev1.Pod, action model.Action, tick string) operationReceipt {
	req := boundReq(pod, action)
	req.TickID = tick
	opID, _ := servingOperationID(req)
	reset, migrate, local, guard, _ := requestObservation(req)
	r := operationReceipt{
		Version: servingEffectReceiptVersion, Kind: string(action), Phase: "prepared", EffectDomain: effectDomain(action),
		OperationID: opID, TickID: tick, Generation: 1,
		PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels),
		SelectedReset: reset, SelectedMigrate: migrate, SelectedLocal: local, SelectedGuardrail: guard,
		ExpectedReset: reset, ExpectedMigrate: migrate, ExpectedLocal: local, ExpectedGuardrail: guard,
		ServingServiceAccount: normalizeServiceAccount(pod.Spec.ServiceAccountName), ServingLegacy: true,
		EndpointConfigSHA256: protectedEndpointConfigDigest(pod),
	}
	apply := routeOwnedValue{Present: true, Value: epochToken(opID, "apply")}
	switch action {
	case model.ActionKVReset:
		r.ExpectedReset = apply
	case model.ActionGuardrailRotate:
		r.ExpectedGuardrail = apply
		r.PriorVariant = pod.Annotations[annoGuardrailVariant]
		r.NextVariant = "v2"
		r.PriorSnapshot = podOwned(pod.Annotations, annoGuardrailSnap)
	}
	return r
}

func m064LiteralReceipt(r operationReceipt) *corev1.ConfigMap {
	b, _ := json.Marshal(r)
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "operator", Name: receiptName(r), UID: types.UID("literal-" + r.TargetUID), ResourceVersion: "1",
		Labels: map[string]string{journalLabel: "v1", servingJournalLabel: "v1"},
	}, Data: map[string]string{"receipt": string(b)}}
}

func TestM064KVTerminalReconcileSupersedeAndStaleDecision(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	c := fakeC(pod)
	stack := &mockVLLM{}
	ec := EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: stack}
	firstReq := boundReq(pod, model.ActionKVReset)
	firstReq.TickID = "tick-1"
	first, err := (kvResetHandler{}).Enact(context.Background(), ec, firstReq)
	if err != nil || !first.Emitted || stack.resetCalls != 1 {
		t.Fatalf("first reset: result=%+v calls=%d err=%v", first, stack.resetCalls, err)
	}
	retry, err := (kvResetHandler{}).Enact(context.Background(), ec, firstReq)
	if err != nil || retry.Emitted || retry.NoEffect != NoEffectReconciled || stack.resetCalls != 1 {
		t.Fatalf("same decision repeated effect: result=%+v calls=%d err=%v", retry, stack.resetCalls, err)
	}
	current := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
		t.Fatal(err)
	}
	secondReq := boundReq(current, model.ActionKVReset)
	secondReq.TickID = "tick-2"
	second, err := (kvResetHandler{}).Enact(context.Background(), ec, secondReq)
	if err != nil || !second.Emitted || stack.resetCalls != 2 {
		t.Fatalf("fresh decision did not reuse terminal slot: result=%+v calls=%d err=%v", second, stack.resetCalls, err)
	}
	stale, err := (kvResetHandler{}).Enact(context.Background(), ec, firstReq)
	if err == nil || stale.Emitted || stack.resetCalls != 2 {
		t.Fatalf("stale earlier decision superseded terminal high-water: result=%+v calls=%d err=%v", stale, stack.resetCalls, err)
	}
}

func TestM064PresenceAwareSelectionRejectsMissingVersusPresentEmpty(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	pod.Annotations[annoKVResetEpoch] = ""
	c := fakeC(pod)
	req := boundReq(pod, model.ActionKVReset)
	req.ServingObservation.KVReset.Present = false
	stack := &mockVLLM{}
	result, err := (kvResetHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: stack}, req)
	if err == nil || !IsNoEffectRefusal(err) || result.Emitted || stack.resetCalls != 0 {
		t.Fatalf("missing/present-empty mismatch reached effect: result=%+v calls=%d err=%v", result, stack.resetCalls, err)
	}
}

func TestM064PeerOutcomeSetMustBeExact(t *testing.T) {
	peers := []string{"decode-a.example:8000", "decode-b.example:8000"}
	for _, tc := range []struct {
		name string
		out  []kvPeerOutcome
	}{
		{"missing", []kvPeerOutcome{{Peer: peers[0], Disposition: kvPeerConfirmed}}},
		{"duplicate", []kvPeerOutcome{{Peer: peers[0], Disposition: kvPeerConfirmed}, {Peer: peers[0], Disposition: kvPeerConfirmed}}},
		{"unexpected", []kvPeerOutcome{{Peer: peers[0], Disposition: kvPeerConfirmed}, {Peer: "other.example:8000", Disposition: kvPeerConfirmed}}},
		{"invalid", []kvPeerOutcome{{Peer: peers[0], Disposition: "invented"}, {Peer: peers[1], Disposition: kvPeerConfirmed}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := validatePeerOutcomes(peers, tc.out); err == nil {
				t.Fatalf("malformed outcome set accepted: %+v", tc.out)
			}
		})
	}
}

func TestM064LiteralMalformedReceiptsCannotRecoverOrMutate(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	base := m064PreparedReceipt(pod, model.ActionKVReset, "literal-tick")
	if !base.valid() {
		t.Fatal("test prerequisite: prepared receipt is invalid")
	}
	peers := []string{"decode-a.example:8000", "decode-b.example:8000"}
	for _, tc := range []struct {
		name   string
		mutate func(*operationReceipt)
	}{
		{"unbound-operation-id", func(r *operationReceipt) { r.OperationID = strings.Repeat("a", 64) }},
		{"impossible-reset-remote-phase", func(r *operationReceipt) { r.Phase = "remote-dispatching" }},
		{"nondeterministic-token", func(r *operationReceipt) { r.ExpectedReset.Value = strings.Repeat("b", 40) }},
		{"migrate-full-without-peer-outcomes", func(r *operationReceipt) {
			r.Kind, r.EffectDomain = string(model.ActionKVMigrateInvalidate), kvEffectDomain
			r.OperationID = servingOperationDigest(r.TickID, r.PolicyUID, r.PolicyNamespace, r.TargetUID, model.ActionKVMigrateInvalidate)
			r.Phase, r.RemoteExpected, r.DeclaredPeers = "metadata-ready-full", len(peers), append([]string(nil), peers...)
			r.ExpectedReset = r.SelectedReset
			r.ExpectedMigrate = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			cm := m064LiteralReceipt(r)
			c := fakeC(pod.DeepCopy(), cm)
			stack := &mockVLLM{}
			native := NewNativeActuator(c)
			native.Reader, native.JournalNamespace, native.RecoveryVLLM = c, "operator", stack
			native.SetServingSecurity(legacyServingSecurityForTest(t))
			if events, err := native.RecoverOperations(context.Background(), false); err == nil {
				t.Fatalf("malformed literal receipt recovered: events=%+v", events)
			}
			if stack.resetCalls != 0 {
				t.Fatalf("malformed literal receipt reached HTTP: calls=%d", stack.resetCalls)
			}
			current := &corev1.Pod{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
				t.Fatal(err)
			}
			if current.ResourceVersion != pod.ResourceVersion || current.Annotations[annoKVResetEpoch] != "" {
				t.Fatalf("malformed receipt changed Pod: rv=%q annotations=%v", current.ResourceVersion, current.Annotations)
			}
		})
	}
}

func TestM064PreparedReceiptRecoveryDispatchesOnce(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	r := m064PreparedReceipt(pod, model.ActionKVReset, "recovery-positive")
	if !r.valid() {
		t.Fatal("test prerequisite: prepared receipt is invalid")
	}
	c := fakeC(pod, m064LiteralReceipt(r))
	stack := &mockVLLM{}
	native := NewNativeActuator(c)
	native.Reader, native.JournalNamespace, native.RecoveryVLLM = c, "operator", stack
	native.SetServingSecurity(legacyServingSecurityForTest(t))
	events, err := native.RecoverOperations(context.Background(), false)
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || stack.resetCalls != 1 {
		t.Fatalf("prepared recovery: events=%+v calls=%d err=%v", events, stack.resetCalls, err)
	}
	again, err := native.RecoverOperations(context.Background(), false)
	if err != nil || len(again) != 1 || stack.resetCalls != 1 {
		t.Fatalf("terminal recovery repeated effect: events=%+v calls=%d err=%v", again, stack.resetCalls, err)
	}
}

func TestM064PostClaimAuthorityAndEndpointChangesPreventSend(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(context.Context, client.Client) error
	}{
		{"selector", func(ctx context.Context, c client.Client) error {
			pod := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "infer"}, pod); err != nil {
				return err
			}
			pod.Labels["phorvex.ai/fixture-never"] = "revoked"
			return c.Update(ctx, pod)
		}},
		{"endpoint", func(ctx context.Context, c client.Client) error {
			pod := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "infer"}, pod); err != nil {
				return err
			}
			pod.Annotations[annoServingPort] = "9001"
			return c.Update(ctx, pod)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
			pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
			base := fakeC(pod)
			guarded := &m064AfterClaimClient{Client: base, mutate: tc.mutate}
			stack := &mockVLLM{}
			result, err := (kvResetHandler{}).Enact(context.Background(), EnactCtx{Client: guarded, Reader: guarded, JournalNamespace: "operator", VLLM: stack}, boundReq(pod, model.ActionKVReset))
			if err == nil || result.MutationKind != "partial" || result.NoEffect != "" || stack.resetCalls != 0 || !guarded.fired {
				t.Fatalf("post-claim change escaped: result=%+v calls=%d fired=%t err=%v", result, stack.resetCalls, guarded.fired, err)
			}
			_, recorded, getErr := servingReceiptGet(context.Background(), EnactCtx{Reader: guarded, JournalNamespace: "operator"}, string(pod.UID), model.ActionKVReset)
			if getErr != nil || recorded.Phase != "dispatching" {
				t.Fatalf("uncertain claim not retained: receipt=%+v err=%v", recorded, getErr)
			}
		})
	}
}

func TestM064GuardrailPriorVariantChangesAfterClaimPreventSend(t *testing.T) {
	pod := guardrailPod("ns", "guard", "v1", "v1,v2")
	base := fakeC(pod)
	guarded := &m064AfterClaimClient{Client: base, mutate: func(ctx context.Context, c client.Client) error {
		current := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), current); err != nil {
			return err
		}
		current.Annotations[annoGuardrailVariant] = "v3"
		return c.Update(ctx, current)
	}}
	stack := &recordingGuardrail{}
	result, err := (guardrailRotateHandler{}).Enact(context.Background(), EnactCtx{Client: guarded, Reader: guarded, JournalNamespace: "operator", Guardrail: stack}, boundReq(pod, model.ActionGuardrailRotate))
	if err == nil || result.MutationKind != "partial" || len(stack.variants) != 0 || !guarded.fired {
		t.Fatalf("changed prior variant escaped: result=%+v variants=%v fired=%t err=%v", result, stack.variants, guarded.fired, err)
	}
}

func TestM036GuardrailReceiptClassificationPrecedesRosterRefusal(t *testing.T) {
	t.Run("terminal-same-operation-reconciles-malformed-roster", func(t *testing.T) {
		pod := guardrailPod("ns", "guard", "v1", "v1,v2")
		c := fakeC(pod)
		stack := &mockGuardrail{}
		ec := EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: stack}
		req := boundReq(pod, model.ActionGuardrailRotate)
		req.TickID = "m036-terminal"
		first, err := (guardrailRotateHandler{}).Enact(context.Background(), ec, req)
		if err != nil || !first.Emitted || stack.applyCalls != 1 {
			t.Fatalf("terminal prerequisite: result=%+v calls=%d err=%v", first, stack.applyCalls, err)
		}
		current := &corev1.Pod{}
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
			t.Fatal(err)
		}
		current.Annotations[annoGuardrailAlts] = "v1,,v2"
		if err := c.Update(context.Background(), current); err != nil {
			t.Fatal(err)
		}
		cm, before, err := servingReceiptGet(context.Background(), ec, string(pod.UID), model.ActionGuardrailRotate)
		if err != nil {
			t.Fatal(err)
		}
		retry, err := (guardrailRotateHandler{}).Enact(context.Background(), ec, req)
		if err != nil || retry.Emitted || retry.NoEffect != NoEffectReconciled || stack.applyCalls != 1 {
			t.Fatalf("same operation did not reconcile before roster refusal: result=%+v calls=%d err=%v", retry, stack.applyCalls, err)
		}
		fresh := boundReq(current, model.ActionGuardrailRotate)
		fresh.TickID = "m036-fresh"
		refused, err := (guardrailRotateHandler{}).Enact(context.Background(), ec, fresh)
		if err == nil || !IsNoEffectRefusal(err) || refused.Emitted || stack.applyCalls != 1 {
			t.Fatalf("fresh operation used malformed roster: result=%+v calls=%d err=%v", refused, stack.applyCalls, err)
		}
		afterCM, after, err := servingReceiptGet(context.Background(), ec, string(pod.UID), model.ActionGuardrailRotate)
		if err != nil || afterCM.UID != cm.UID || afterCM.ResourceVersion != cm.ResourceVersion || after.Generation != before.Generation || after.OperationID != before.OperationID {
			t.Fatalf("fresh refusal changed terminal receipt: before=%+v after=%+v cm=%s/%s err=%v", before, after, cm.ResourceVersion, afterCM.ResourceVersion, err)
		}
	})

	t.Run("pending-operation-blocks-malformed-roster-retry", func(t *testing.T) {
		pod := guardrailPod("ns", "guard", "v1", "v1,v2")
		c := fakeC(pod)
		stack := &mockGuardrail{applyErr: errors.New("response lost")}
		ec := EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: stack}
		req := boundReq(pod, model.ActionGuardrailRotate)
		req.TickID = "m036-pending"
		first, err := (guardrailRotateHandler{}).Enact(context.Background(), ec, req)
		if err == nil || first.MutationKind != "partial" || stack.applyCalls != 1 {
			t.Fatalf("pending prerequisite: result=%+v calls=%d err=%v", first, stack.applyCalls, err)
		}
		current := &corev1.Pod{}
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
			t.Fatal(err)
		}
		current.Annotations[annoGuardrailAlts] = "v1,,v2"
		if err := c.Update(context.Background(), current); err != nil {
			t.Fatal(err)
		}
		for _, tick := range []string{req.TickID, "m036-contender"} {
			retry := boundReq(current, model.ActionGuardrailRotate)
			retry.TickID = tick
			result, retryErr := (guardrailRotateHandler{}).Enact(context.Background(), ec, retry)
			if retryErr == nil || result.MutationKind != "partial" || result.NoEffect != "" || stack.applyCalls != 1 {
				t.Fatalf("pending retry %q escaped: result=%+v calls=%d err=%v", tick, result, stack.applyCalls, retryErr)
			}
		}
	})
}

func TestM036PreparedGuardrailRecoveryUsesFixedRosterIntent(t *testing.T) {
	for _, tc := range []struct {
		name, roster string
		wantCalls    int
		wantErr      bool
	}{
		{name: "reordered-complete-roster", roster: "v3,v1,v2", wantCalls: 1},
		{name: "fixed-next-removed", roster: "v1,v3", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := guardrailPod("ns", "guard", "v1", tc.roster)
			pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
			receipt := m064PreparedReceipt(pod, model.ActionGuardrailRotate, "m036-recovery")
			receipt.PriorVariant, receipt.NextVariant = "v1", "v2"
			if !receipt.valid() {
				t.Fatal("prepared guardrail receipt fixture invalid")
			}
			c := fakeC(pod, m064LiteralReceipt(receipt))
			stack := &mockGuardrail{}
			req := boundReq(pod, model.ActionGuardrailRotate)
			req.TickID = receipt.TickID
			ec := EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: stack, ServingSecurity: legacyServingSecurityForTest(t), ServingRequest: req}
			if err := prepareServingAttempt(context.Background(), &ec, req); err != nil {
				t.Fatal(err)
			}
			cm, recorded, err := servingReceiptGet(context.Background(), ec, string(pod.UID), model.ActionGuardrailRotate)
			if err != nil {
				t.Fatal(err)
			}
			_, recoverErr := recoverProtectedServingEffect(context.Background(), ec, cm, &recorded)
			if (recoverErr != nil) != tc.wantErr || stack.applyCalls != tc.wantCalls {
				t.Fatalf("recovery calls=%d want=%d err=%v", stack.applyCalls, tc.wantCalls, recoverErr)
			}
			if tc.wantCalls == 1 && stack.lastVar != "v2" {
				t.Fatalf("reordered roster redirected fixed intent to %q", stack.lastVar)
			}
			if tc.wantErr {
				_, retained, err := servingReceiptGet(context.Background(), ec, string(pod.UID), model.ActionGuardrailRotate)
				if err != nil || retained.Phase != "prepared" {
					t.Fatalf("removed fixed member changed prepared receipt: receipt=%+v err=%v", retained, err)
				}
			}
		})
	}
}

type m064InventoryReader struct {
	client.Reader
	pages map[string]corev1.ConfigMapList
	calls int
}

func (r *m064InventoryReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	lo := &client.ListOptions{}
	for _, opt := range opts {
		opt.ApplyToList(lo)
	}
	if lo.Limit != servingInventoryPage || lo.LabelSelector.String() != servingJournalLabel+"=v1" {
		return fmt.Errorf("inventory list was not server-bounded: limit=%d selector=%q", lo.Limit, lo.LabelSelector.String())
	}
	page, ok := r.pages[lo.Continue]
	if !ok {
		return errors.New("unexpected continuation")
	}
	got, ok := list.(*corev1.ConfigMapList)
	if !ok {
		return errors.New("unexpected list type")
	}
	r.calls++
	*got = *page.DeepCopy()
	return nil
}

func TestM064ServingInventoryUsesIndexedBoundedPagination(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	one := m064LiteralReceipt(m064PreparedReceipt(pod, model.ActionKVReset, "inventory"))
	reader := &m064InventoryReader{pages: map[string]corev1.ConfigMapList{
		"":     {Items: []corev1.ConfigMap{*one}, ListMeta: metav1.ListMeta{Continue: "next"}},
		"next": {},
	}}
	count, bytes, err := servingSlotInventory(context.Background(), EnactCtx{Reader: reader, JournalNamespace: "operator"})
	if err != nil || count != 1 || bytes == 0 || reader.calls != 2 {
		t.Fatalf("bounded inventory: count=%d bytes=%d calls=%d err=%v", count, bytes, reader.calls, err)
	}
	reader.pages["next"] = corev1.ConfigMapList{ListMeta: metav1.ListMeta{Continue: "next"}}
	if _, _, err := servingSlotInventory(context.Background(), EnactCtx{Reader: reader, JournalNamespace: "operator"}); err == nil {
		t.Fatal("non-progressing incomplete inventory was accepted")
	}
}
