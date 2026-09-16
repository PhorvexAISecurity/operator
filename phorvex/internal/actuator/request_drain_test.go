package actuator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type drainEndpointController struct {
	client.Client
	serviceName   string
	address       string
	target        corev1.ObjectReference
	patchErr      func(*corev1.Pod) error
	afterWithdraw func()
	withdrew      bool
}

func (c *drainEndpointController) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	pod, isPod := obj.(*corev1.Pod)
	if isPod && c.patchErr != nil {
		if err := c.patchErr(pod); err != nil {
			return err
		}
	}
	if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	if !isPod {
		return nil
	}
	var slices discoveryv1.EndpointSliceList
	if err := c.Client.List(ctx, &slices, client.InNamespace(pod.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: c.serviceName}); err != nil {
		return err
	}
	if len(slices.Items) != 1 {
		return fmt.Errorf("fake endpoint controller found %d slices", len(slices.Items))
	}
	slice := slices.Items[0].DeepCopy()
	if pod.Labels[labelServing] == "drained" {
		slice.Endpoints = nil
	} else {
		slice.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{c.address}, TargetRef: &c.target}}
	}
	if err := c.Client.Update(ctx, slice); err != nil {
		return err
	}
	if pod.Labels[labelServing] == "drained" && !c.withdrew && c.afterWithdraw != nil {
		c.withdrew = true
		c.afterWithdraw()
	}
	return nil
}

func requestDrainFixture(t *testing.T, servingValue string) (*corev1.Pod, *corev1.Service, *discoveryv1.EndpointSlice, *drainEndpointController) {
	t.Helper()
	pod := aiPod("ns", "infer", map[string]string{"app": "infer", labelServing: servingValue})
	pod.Annotations[annoRouteService] = "infer"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "infer", UID: types.UID("uid-service"), ResourceVersion: "3"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "infer", labelServing: servingValue}}}
	ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "infer-a", UID: types.UID("uid-slice"), ResourceVersion: "4", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}}}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{pod.Status.PodIP}, TargetRef: &ref}}}
	base := fakeC(pod, svc, slice)
	return pod, svc, slice, &drainEndpointController{Client: base, serviceName: svc.Name, address: pod.Status.PodIP, target: ref}
}

func requestDrainEC(c client.Client, v vLLMClient) EnactCtx {
	return EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: v, DrainObservationTimeout: 100 * time.Millisecond, DrainObservationInterval: time.Millisecond}
}

func requestDrainReq(pod *corev1.Pod) Request {
	r := boundReq(pod, model.ActionRequestDrain)
	r.Tenant = "tenant"
	return r
}

func getDrainPod(t *testing.T, c client.Client) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, pod); err != nil {
		t.Fatal(err)
	}
	return pod
}

func testDrainReceipt(pod *corev1.Pod, svc *corev1.Service, phase string) operationReceipt {
	return operationReceipt{
		Version: requestDrainReceiptVersion, Kind: "request-drain", Phase: phase,
		PolicyNamespace: pod.Namespace, PolicyName: "policy", PolicyUID: "policy-uid",
		TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels),
		OperationToken: "00112233445566778899aabbccddeeff", ServiceName: svc.Name, ServiceUID: string(svc.UID), ServiceSelector: copyLabels(svc.Spec.Selector),
		PriorServingPresent: true, PriorServingValue: pod.Labels[labelServing], EndpointAddresses: []string{pod.Status.PodIP}, EndpointConfigSHA256: drainEndpointConfigDigest(pod),
	}
}

type afterReceiptClient struct {
	client.Client
	after func()
	done  bool
}

func (c *afterReceiptClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	if _, ok := obj.(*corev1.ConfigMap); ok && !c.done && c.after != nil {
		c.done = true
		c.after()
	}
	return nil
}

type ambiguousDrainClient struct {
	client.Client
	lostPatchAck       bool
	failReadback       bool
	persistentReadback bool
	failedPatch        bool
	failGets           int
}

type refusedDrainClient struct{ client.Client }

func (c *refusedDrainClient) Patch(_ context.Context, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
	if pod, ok := obj.(*corev1.Pod); ok && pod.Labels[labelServing] == "drained" {
		return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, errors.New("Pod Patch definitely refused"))
	}
	return errors.New("unexpected patch")
}

type unreadableDrainClient struct {
	client.Client
	unreadable bool
}

type recoverAfterClaimClient struct {
	client.Client
	once sync.Once
	hook func()
}

type lostClaimAckClient struct {
	client.Client
	lost bool
}

func (c *lostClaimAckClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	if cm, ok := obj.(*corev1.ConfigMap); ok && !c.lost && containsStr(cm.Data["receipt"], `"phase":"claimed"`) {
		c.lost = true
		return errors.New("accepted claim response lost")
	}
	return nil
}

func (c *recoverAfterClaimClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	if cm, ok := obj.(*corev1.ConfigMap); ok && containsStr(cm.Data["receipt"], `"phase":"claimed"`) {
		c.once.Do(c.hook)
	}
	return nil
}

func (c *unreadableDrainClient) Patch(_ context.Context, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
	if pod, ok := obj.(*corev1.Pod); ok && pod.Labels[labelServing] == "drained" {
		c.unreadable = true
		return errors.New("Pod Patch response unavailable")
	}
	return errors.New("unexpected patch")
}

func (c *unreadableDrainClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.unreadable {
		if _, ok := obj.(*corev1.Pod); ok {
			return errors.New("authoritative Pod outcome unreadable")
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

type finishFaultClient struct {
	client.Client
	failOnce bool
}

func (c *finishFaultClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok && c.failOnce {
		c.failOnce = false
		return errors.New("receipt delete response unavailable")
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func (c *ambiguousDrainClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	pod, isPod := obj.(*corev1.Pod)
	isStop := isPod && pod.Labels[labelServing] == "drained" && !c.failedPatch
	if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	if isStop {
		c.failedPatch = true
		if c.failReadback {
			c.failGets = 1
			if c.persistentReadback {
				c.failGets = -1
			}
		}
		if c.lostPatchAck {
			return errors.New("accepted Pod Patch response lost")
		}
	}
	return nil
}

func (c *ambiguousDrainClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.failGets != 0 {
		if _, ok := obj.(*corev1.Pod); ok {
			if c.failGets > 0 {
				c.failGets--
			}
			return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, key.Name, errors.New("authoritative readback denied"))
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestM040RequestDrainZeroRestoresWithoutCredit(t *testing.T) {
	pod, _, _, c := requestDrainFixture(t, "true")
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(c, &mockVLLM{drained: 0}), requestDrainReq(pod))
	if err == nil || !result.Emitted || !containsStr(err.Error(), "zero aborted") {
		t.Fatalf("zero abort result=%+v err=%v", result, err)
	}
	if got := getDrainPod(t, c).Labels[labelServing]; got != "true" {
		t.Fatalf("zero drain stranded capacity: %q", got)
	}
	var receipts corev1.ConfigMapList
	if err := c.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 0 {
		t.Fatalf("resolved zero drain retained receipt: count=%d err=%v", len(receipts.Items), err)
	}
}

func TestM040ReceiptVersionIsBoundToRequestDrainKind(t *testing.T) {
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow})
	pool := warmPoolIntent{RSName: "rs", RSUID: "rsuid", RSGeneration: 1, Desired: 2, RSTemplateHash: "t", RSSelectorHash: "s", ServiceName: "svc", ServiceUID: "suid", ServiceSelectorHash: "ss", Members: []string{string(old.UID), string(next.UID)}}
	warm := m066ValidV2Receipt(old, next, pool)
	warm.Version = requestDrainReceiptVersion
	if warm.valid() {
		t.Fatal("request-drain receipt version admitted for a warm-swap receipt")
	}
	quarantine := operationReceipt{Version: requestDrainReceiptVersion, Kind: "quarantine", Phase: "prepared", PolicyNamespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TargetName: "pod", TargetUID: "pod-uid", TargetLabels: map[string]string{"app": "x"}, NPName: "np"}
	if quarantine.valid() {
		t.Fatal("request-drain receipt version admitted for a quarantine receipt")
	}
}

func TestM040RequestDrainRevalidatesServiceAfterReceipt(t *testing.T) {
	pod, svc, _, controller := requestDrainFixture(t, "true")
	mv := &mockVLLM{drained: 1}
	raced := &afterReceiptClient{Client: controller}
	raced.after = func() {
		current := &corev1.Service{}
		if err := controller.Get(context.Background(), client.ObjectKeyFromObject(svc), current); err != nil {
			t.Fatal(err)
		}
		current.Spec.Selector["app"] = "other"
		if err := controller.Update(context.Background(), current); err != nil {
			t.Fatal(err)
		}
	}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(raced, mv), requestDrainReq(pod))
	if err == nil || result.Emitted || mv.drainCalls != 0 {
		t.Fatalf("service drift result=%+v calls=%d err=%v", result, mv.drainCalls, err)
	}
	if got := getDrainPod(t, raced).Labels[labelServing]; got != "true" {
		t.Fatalf("service drift mutated target: %q", got)
	}
}

func TestM040RequestDrainRejectsStaleSliceFromReplacedService(t *testing.T) {
	pod, _, slice, controller := requestDrainFixture(t, "true")
	current := &discoveryv1.EndpointSlice{}
	if err := controller.Get(context.Background(), client.ObjectKeyFromObject(slice), current); err != nil {
		t.Fatal(err)
	}
	current.OwnerReferences[0].UID = types.UID("uid-replaced-service")
	if err := controller.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	mv := &mockVLLM{drained: 1}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, mv), requestDrainReq(pod))
	if err == nil || !IsNoEffectRefusal(err) || result.Emitted || mv.drainCalls != 0 {
		t.Fatalf("stale EndpointSlice result=%+v calls=%d err=%v", result, mv.drainCalls, err)
	}
	if got := getDrainPod(t, controller).Labels[labelServing]; got != "true" {
		t.Fatalf("stale EndpointSlice mutated target: %q", got)
	}
}

func TestM040StaleSliceCannotProveCurrentServiceMembership(t *testing.T) {
	pod, svc, slice, controller := requestDrainFixture(t, "true")
	current := &discoveryv1.EndpointSlice{}
	if err := controller.Get(context.Background(), client.ObjectKeyFromObject(slice), current); err != nil {
		t.Fatal(err)
	}
	current.Endpoints = nil
	if err := controller.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	stale := slice.DeepCopy()
	stale.Name = "infer-stale"
	stale.UID = types.UID("uid-stale-slice")
	stale.ResourceVersion = ""
	stale.OwnerReferences[0].UID = types.UID("uid-replaced-service")
	if err := controller.Create(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	addresses, err := drainEndpointAddresses(context.Background(), controller, svc, pod)
	if err != nil || len(addresses) != 0 {
		t.Fatalf("stale same-name Service slice proved membership: addresses=%v err=%v", addresses, err)
	}
}

func TestM040RequestDrainRevalidatesEndpointBeforeHTTP(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	mv := &mockVLLM{drained: 1}
	controller.afterWithdraw = func() {
		current := getDrainPod(t, controller.Client)
		current.Annotations[annoDrainPath] = "/changed-after-withdrawal"
		if err := controller.Client.Update(context.Background(), current); err != nil {
			t.Fatal(err)
		}
	}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, mv), requestDrainReq(pod))
	if err == nil || !result.Emitted || mv.drainCalls != 0 || !containsStr(err.Error(), "configuration changed") {
		t.Fatalf("late endpoint drift result=%+v calls=%d err=%v", result, mv.drainCalls, err)
	}
	if got := getDrainPod(t, controller).Labels[labelServing]; got != "true" {
		t.Fatalf("late endpoint drift stranded target: %q", got)
	}
}

func TestM040RequestDrainServiceDriftAfterAbortBlocksRestorationWrite(t *testing.T) {
	pod, svc, _, controller := requestDrainFixture(t, "true")
	mv := &changingDrainVLLM{mockVLLM: mockVLLM{drained: 2}}
	mv.change = func() {
		current := &corev1.Service{}
		if err := controller.Get(context.Background(), client.ObjectKeyFromObject(svc), current); err != nil {
			t.Fatal(err)
		}
		current.Spec.Selector["app"] = "user-edited-after-abort"
		if err := controller.Update(context.Background(), current); err != nil {
			t.Fatal(err)
		}
	}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, mv), requestDrainReq(pod))
	if err == nil || !result.Emitted || mv.drainCalls != 1 || !containsStr(err.Error(), "bound Service identity") {
		t.Fatalf("post-abort Service drift result=%+v calls=%d err=%v", result, mv.drainCalls, err)
	}
	if got := getDrainPod(t, controller); got.Labels[labelServing] != "drained" || got.Labels[labelDrainEpoch] == "" {
		t.Fatalf("changed Service authority must block a restoration write: labels=%v", got.Labels)
	}
	var receipts corev1.ConfigMapList
	if listErr := controller.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 1 {
		t.Fatalf("post-abort drift must retain restoration evidence: count=%d err=%v", len(receipts.Items), listErr)
	}
}

func TestM040RequestDrainAmbiguousPatchRetainsRestorationAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
	}{
		{name: "accepted-patch-lost-ack", mode: "ack"},
		{name: "accepted-patch-forbidden-readback-readable-retry", mode: "read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, _, _, controller := requestDrainFixture(t, "true")
			ambiguous := &ambiguousDrainClient{Client: controller, lostPatchAck: tc.mode == "ack", failReadback: tc.mode == "read"}
			result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(ambiguous, &mockVLLM{drained: 1}), requestDrainReq(pod))
			if err == nil || !result.Emitted {
				t.Fatalf("ambiguous patch result=%+v err=%v", result, err)
			}
			if got := getDrainPod(t, ambiguous).Labels[labelServing]; got != "true" {
				t.Fatalf("ambiguous patch stranded serving=%q", got)
			}
			var receipts corev1.ConfigMapList
			if listErr := ambiguous.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 0 {
				t.Fatalf("completed restoration receipt count=%d err=%v", len(receipts.Items), listErr)
			}
		})
	}
}

func TestM040AcceptedPatchPersistentForbiddenReadbackRemainsUnknown(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	unreadable := &ambiguousDrainClient{Client: controller, failReadback: true, persistentReadback: true}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(unreadable, &mockVLLM{drained: 1}), requestDrainReq(pod))
	if err == nil || result.Emitted || !containsStr(result.Note, "outcome unknown") || len(result.ObjectsTouched) != 2 {
		t.Fatalf("persistent forbidden readback result=%+v err=%v", result, err)
	}
	if got := getDrainPod(t, controller); got.Labels[labelServing] != "drained" || got.Labels[labelDrainEpoch] == "" {
		t.Fatalf("accepted Patch not retained as unresolved state: %v", got.Labels)
	}
	var receipts corev1.ConfigMapList
	if listErr := controller.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 1 {
		t.Fatalf("persistent forbidden readback receipt count=%d err=%v", len(receipts.Items), listErr)
	}
}

func TestM040RequestDrainDistinguishesRefusedAndUnreadablePatchOutcome(t *testing.T) {
	t.Run("definite-refusal-is-not-emitted", func(t *testing.T) {
		pod, _, _, controller := requestDrainFixture(t, "true")
		refused := &refusedDrainClient{Client: controller}
		result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(refused, &mockVLLM{drained: 1}), requestDrainReq(pod))
		if err == nil || result.Emitted || !containsStr(result.Note, "no confirmed Pod mutation") {
			t.Fatalf("definite refusal result=%+v err=%v", result, err)
		}
		if len(result.ObjectsTouched) != 1 || !containsStr(result.ObjectsTouched[0], "ConfigMap") {
			t.Fatalf("definite refusal should report only the transient journal object: %v", result.ObjectsTouched)
		}
		var receipts corev1.ConfigMapList
		if listErr := controller.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 0 {
			t.Fatalf("definite refusal receipt count=%d err=%v", len(receipts.Items), listErr)
		}
	})

	t.Run("unreadable-outcome-retains-receipt-without-claiming-emission", func(t *testing.T) {
		pod, _, _, controller := requestDrainFixture(t, "true")
		unreadable := &unreadableDrainClient{Client: controller}
		result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(unreadable, &mockVLLM{drained: 1}), requestDrainReq(pod))
		if err == nil || result.Emitted || !containsStr(result.Note, "outcome unknown") || len(result.ObjectsTouched) != 2 {
			t.Fatalf("unreadable outcome result=%+v err=%v", result, err)
		}
		var receipts corev1.ConfigMapList
		if listErr := controller.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 1 {
			t.Fatalf("unreadable outcome receipt count=%d err=%v", len(receipts.Items), listErr)
		}
		if got := getDrainPod(t, controller); got.Labels[labelServing] != "true" {
			t.Fatalf("fixture confirms refused Patch changed serving state: %v", got.Labels)
		}
	})
}

func TestM040RecoveryBetweenPreparationAndPatchCannotEraseAuthority(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	interleaved := &recoverAfterClaimClient{Client: controller}
	recoveryVLLM := &mockVLLM{}
	var recoveryEvents []RecoveryEvent
	var recoveryErr error
	interleaved.hook = func() {
		n := &NativeActuator{Client: interleaved, Reader: interleaved, JournalNamespace: "operator", RecoveryVLLM: recoveryVLLM}
		recoveryEvents, recoveryErr = n.RecoverOperations(context.Background(), false)
	}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(interleaved, &mockVLLM{drained: 1}), requestDrainReq(pod))
	if err != nil || !result.Emitted {
		t.Fatalf("interleaved handler result=%+v err=%v", result, err)
	}
	if recoveryErr != nil || len(recoveryEvents) != 1 || recoveryEvents[0].Outcome != "partial" || recoveryEvents[0].Err == nil {
		t.Fatalf("interleaved recovery events=%+v err=%v", recoveryEvents, recoveryErr)
	}
	if recoveryVLLM.drainCalls != 0 {
		t.Fatalf("recovery replayed abort %d times", recoveryVLLM.drainCalls)
	}
	if got := getDrainPod(t, interleaved); got.Labels[labelServing] != "true" || got.Labels[labelDrainEpoch] == "" {
		t.Fatalf("interleaving stranded or lost operation state: %v", got.Labels)
	}
	var receipts corev1.ConfigMapList
	if listErr := interleaved.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 0 {
		t.Fatalf("completed interleaved operation receipt count=%d err=%v", len(receipts.Items), listErr)
	}
}

func TestM040LostClaimAcknowledgementRetainsAuthorityWithoutPodWrite(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	lost := &lostClaimAckClient{Client: controller}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(lost, &mockVLLM{drained: 1}), requestDrainReq(pod))
	if err == nil || result.Emitted || !containsStr(result.Note, "pre-write claim unconfirmed") {
		t.Fatalf("lost claim acknowledgement result=%+v err=%v", result, err)
	}
	if got := getDrainPod(t, controller); got.Labels[labelServing] != "true" || got.Labels[labelDrainEpoch] != "" {
		t.Fatalf("unacknowledged claim reached Pod write: %v", got.Labels)
	}
	var receipts corev1.ConfigMapList
	if listErr := controller.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); listErr != nil || len(receipts.Items) != 1 || !containsStr(receipts.Items[0].Data["receipt"], `"phase":"claimed"`) {
		t.Fatalf("lost claim acknowledgement receipt=%+v err=%v", receipts.Items, listErr)
	}
}

func TestM040RecoveryRestoresOnlyAndNeverReplaysAbort(t *testing.T) {
	pod, svc, _, controller := requestDrainFixture(t, "standby")
	r := testDrainReceipt(pod, svc, "prepared")
	ec := requestDrainEC(controller, nil)
	cm, err := journalWrite(context.Background(), ec, r)
	if err != nil {
		t.Fatal(err)
	}
	stopped, _, err := drainPodWithReceipt(context.Background(), ec, getDrainPod(t, controller), r)
	if err != nil {
		t.Fatal(err)
	}
	r.Phase = "stopped"
	if err := journalAdvance(context.Background(), ec, cm, r); err != nil {
		t.Fatal(err)
	}
	mv := &mockVLLM{}
	n := &NativeActuator{Client: controller, Reader: controller, JournalNamespace: "operator", RecoveryVLLM: mv}
	events, err := n.RecoverOperations(context.Background(), false)
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if mv.drainCalls != 0 {
		t.Fatalf("recovery replayed the abort endpoint %d times", mv.drainCalls)
	}
	if got := getDrainPod(t, controller).Labels[labelServing]; got != "standby" {
		t.Fatalf("recovery did not restore exact prior value: %q (stopped=%s)", got, stopped.Name)
	}
}

func TestM040RecoveryConvergesEveryReceiptPhaseAcrossTwoRestarts(t *testing.T) {
	for _, phase := range []string{"prepared", "stopped", "withdrawn", "stack-confirmed", "restored"} {
		t.Run(phase, func(t *testing.T) {
			pod, svc, slice, controller := requestDrainFixture(t, "standby")
			r := testDrainReceipt(pod, svc, phase)
			if phase == "stack-confirmed" || phase == "restored" {
				r.Aborted = 2
			}
			if phase != "prepared" {
				current := getDrainPod(t, controller)
				current.Labels[labelDrainEpoch] = r.OperationToken
				if phase == "restored" {
					current.Labels[labelServing] = "standby"
				} else {
					current.Labels[labelServing] = "drained"
				}
				if err := controller.Client.Update(context.Background(), current); err != nil {
					t.Fatal(err)
				}
				currentSlice := &discoveryv1.EndpointSlice{}
				if err := controller.Get(context.Background(), client.ObjectKeyFromObject(slice), currentSlice); err != nil {
					t.Fatal(err)
				}
				if phase != "restored" {
					currentSlice.Endpoints = nil
				}
				if err := controller.Client.Update(context.Background(), currentSlice); err != nil {
					t.Fatal(err)
				}
			}
			ec := requestDrainEC(controller, nil)
			if _, err := journalWrite(context.Background(), ec, r); err != nil {
				t.Fatal(err)
			}
			n := &NativeActuator{Client: controller, Reader: controller, JournalNamespace: "operator", RecoveryVLLM: &mockVLLM{}}
			first, err := n.RecoverOperations(context.Background(), false)
			if err != nil || len(first) != 1 || first[0].Outcome != "confirmed" {
				t.Fatalf("first recovery=%+v err=%v", first, err)
			}
			second, err := n.RecoverOperations(context.Background(), false)
			if err != nil || len(second) != 0 {
				t.Fatalf("second recovery=%+v err=%v", second, err)
			}
			if got := getDrainPod(t, controller).Labels[labelServing]; got != "standby" {
				t.Fatalf("phase %s restored serving=%q", phase, got)
			}
		})
	}
}

func TestM040RecoveryCleanupFailureRetainsThenFinishes(t *testing.T) {
	pod, svc, slice, controller := requestDrainFixture(t, "true")
	r := testDrainReceipt(pod, svc, "stopped")
	current := getDrainPod(t, controller)
	current.Labels[labelServing], current.Labels[labelDrainEpoch] = "drained", r.OperationToken
	if err := controller.Client.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	currentSlice := &discoveryv1.EndpointSlice{}
	if err := controller.Get(context.Background(), client.ObjectKeyFromObject(slice), currentSlice); err != nil {
		t.Fatal(err)
	}
	currentSlice.Endpoints = nil
	if err := controller.Client.Update(context.Background(), currentSlice); err != nil {
		t.Fatal(err)
	}
	fault := &finishFaultClient{Client: controller, failOnce: true}
	ec := requestDrainEC(fault, nil)
	if _, err := journalWrite(context.Background(), ec, r); err != nil {
		t.Fatal(err)
	}
	n := &NativeActuator{Client: fault, Reader: fault, JournalNamespace: "operator"}
	first, err := n.RecoverOperations(context.Background(), false)
	if err != nil || len(first) != 1 || first[0].Outcome != "partial" || first[0].Err == nil {
		t.Fatalf("cleanup failure events=%+v err=%v", first, err)
	}
	var receipts corev1.ConfigMapList
	if err := fault.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 1 {
		t.Fatalf("cleanup failure lost receipt: count=%d err=%v", len(receipts.Items), err)
	}
	second, err := n.RecoverOperations(context.Background(), false)
	if err != nil || len(second) != 1 || second[0].Outcome != "confirmed" {
		t.Fatalf("cleanup retry events=%+v err=%v", second, err)
	}
}

func TestM040AdministrativeRecoveryUsesHeldReviewedRequestDrainPlan(t *testing.T) {
	ctx := context.Background()
	pod, svc, _, controller := requestDrainFixture(t, "standby")
	r := testDrainReceipt(pod, svc, "prepared")
	ec := requestDrainEC(controller, nil)
	cm, err := journalWrite(ctx, ec, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := drainPodWithReceipt(ctx, ec, getDrainPod(t, controller), r); err != nil {
		t.Fatal(err)
	}
	r.Phase = "stopped"
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ns", "operator"} {
		ns := &corev1.Namespace{}
		if err := controller.Get(ctx, client.ObjectKey{Name: name}, ns); err != nil {
			t.Fatal(err)
		}
		if ns.UID == "" {
			ns.UID = types.UID("uid-" + name)
			if err := controller.Update(ctx, ns); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, obj := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: metav1.NamespaceSystem}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: RecoveryHoldName}, Data: map[string]string{"engaged": "true"}},
	} {
		if err := controller.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	native := &NativeActuator{Client: controller, Reader: controller, JournalNamespace: "operator"}
	scope := RecoveryScope{OperatorNamespace: "operator", Namespace: "ns", PolicyName: "policy", MaxItems: 1}
	inv, err := native.InventoryRecovery(ctx, scope)
	if err != nil || len(inv.Items) != 1 || inv.Items[0].Status != "ready" || inv.Items[0].SupportedOperation != RecoveryOperation {
		t.Fatalf("request-drain recovery inventory=%+v err=%v", inv, err)
	}
	plan, err := native.PlanRecovery(ctx, scope)
	if err != nil || len(plan.Items) != 1 || plan.Items[0].Kind != "request-drain" || plan.Items[0].Service == nil {
		t.Fatalf("request-drain recovery plan=%+v err=%v", plan, err)
	}
	result, err := native.ApplyRecovery(ctx, plan)
	if err != nil || !result.Complete || len(result.Items) != 1 || result.Items[0].Outcome != "restored" {
		t.Fatalf("request-drain recovery apply=%+v err=%v", result, err)
	}
	if got := getDrainPod(t, controller); got.Labels[labelServing] != "standby" {
		t.Fatalf("administrative recovery serving=%q", got.Labels[labelServing])
	}
}
