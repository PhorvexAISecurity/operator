package actuator

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type m052CapacityBackend struct {
	name   string
	result Result
	err    error
	calls  int
}

func (b *m052CapacityBackend) Name() string                                     { return b.name }
func (b *m052CapacityBackend) EnsurePolicy(context.Context, TenantTarget) error { return nil }
func (b *m052CapacityBackend) SupportsAction(context.Context, model.Action, Target) (bool, string) {
	return true, ""
}
func (b *m052CapacityBackend) Actuate(context.Context, Request) (Result, error) {
	b.calls++
	return b.result, b.err
}

type m052LostAckClient struct {
	client.Client
	mu         sync.Mutex
	loseCreate bool
	loseUpdate bool
}

func (c *m052LostAckClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	cm, capacity := obj.(*corev1.ConfigMap)
	c.mu.Lock()
	defer c.mu.Unlock()
	if capacity && cm.Labels[quarantineCapacityLabel] == "v1" && c.loseCreate {
		c.loseCreate = false
		return context.DeadlineExceeded
	}
	return nil
}

func (c *m052LostAckClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	cm, capacity := obj.(*corev1.ConfigMap)
	c.mu.Lock()
	defer c.mu.Unlock()
	if capacity && cm.Labels[quarantineCapacityLabel] == "v1" && c.loseUpdate {
		c.loseUpdate = false
		return context.DeadlineExceeded
	}
	return nil
}

func TestM052QuarantineCapacityRealAPICAS(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is required")
	}
	e := &envtest.Environment{}
	cfg, err := e.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()
	for _, name := range []string{"operator", "tenant"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatalf("create namespace %s: %v", name, err)
		}
	}
	pods := []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "tenant"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "tenant"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "native", Namespace: "tenant", Labels: map[string]string{quarantineLabel: "marked"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "phoenix", Namespace: "tenant", Labels: map[string]string{phoenixQuarantineMarker: "tenant-phoenix-policy"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}}},
	}
	for _, pod := range pods {
		if err := c.Create(ctx, pod); err != nil {
			t.Fatalf("create pod %s: %v", pod.Name, err)
		}
		if pod.UID == "" {
			t.Fatalf("API server did not assign UID to pod %s", pod.Name)
		}
	}
	guard, err := NewQuarantineCapacity(c, c, "operator", 3)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	// Two policies and targets contend for the single remaining slot through real
	// API resourceVersion CAS. Exactly one reservation may be acknowledged.
	requests := []Request{
		{PolicyName: "policy-a", PolicyUID: "policy-a-uid", Namespace: "tenant", Pod: "a", TargetUID: string(pods[0].UID), Action: model.ActionQuarantine},
		{PolicyName: "policy-b", PolicyUID: "policy-b-uid", Namespace: "tenant", Pod: "b", TargetUID: string(pods[1].UID), Action: model.ActionQuarantine},
	}
	start := make(chan struct{})
	results := make(chan error, len(requests))
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(req Request) {
			defer wg.Done()
			<-start
			_, reserveErr := guard.reserve(ctx, req, "phoenix")
			results <- reserveErr
		}(requests[i])
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded, refused := 0, 0
	for result := range results {
		if result == nil {
			succeeded++
		} else if IsNoEffectRefusal(result) {
			refused++
		} else {
			t.Fatalf("unexpected contention result: %v", result)
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("CAS results success=%d refused=%d want 1/1", succeeded, refused)
	}
	inv, err := guard.Inventory(ctx, "tenant")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if inv.Observed != 2 || inv.Reserved != 1 || inv.Used != 3 || inv.Limit != 3 {
		t.Fatalf("inventory=%+v want observed=2 reserved=1 used=3 limit=3", inv)
	}
	for i := range requests {
		if _, err := guard.reserve(ctx, requests[i], "phoenix"); err == nil {
			t.Fatal("retry or competing policy admitted another dispatch for an occupied target")
		}
	}

	// Removing an ordinary marker cannot erase the protected pending reservation.
	native := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "native"}, native); err != nil {
		t.Fatal(err)
	}
	delete(native.Labels, quarantineLabel)
	if err := c.Update(ctx, native); err != nil {
		t.Fatal(err)
	}
	inv, err = guard.Inventory(ctx, "tenant")
	if err != nil {
		t.Fatalf("inventory after marker removal: %v", err)
	}
	if inv.Observed != 1 || inv.Reserved != 1 || inv.Used != 2 {
		t.Fatalf("protected reservation lost after marker removal: %+v", inv)
	}
	strictGuard, err := NewQuarantineCapacity(c, c, "operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	blocked := &m052CapacityBackend{name: "native", result: Result{Emitted: true}}
	overcapTarget := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "overcap-target", Namespace: "tenant"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}}}
	if err := c.Create(ctx, overcapTarget); err != nil {
		t.Fatal(err)
	}
	overcapRequest := Request{PolicyName: "overcap-policy", PolicyUID: "overcap-policy-uid", Namespace: "tenant", Pod: overcapTarget.Name, TargetUID: string(overcapTarget.UID), Action: model.ActionQuarantine}
	if result, err := strictGuard.Actuate(ctx, blocked, overcapRequest); !IsNoEffectRefusal(err) || result.Emitted || blocked.calls != 0 {
		t.Fatalf("preexisting over-cap population admitted new quarantine: result=%+v calls=%d err=%v", result, blocked.calls, err)
	}
	zeroGuard, err := NewQuarantineCapacity(c, c, "operator", 0)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := zeroGuard.Actuate(ctx, blocked, overcapRequest); !IsNoEffectRefusal(err) || result.Emitted || blocked.calls != 0 {
		t.Fatalf("explicit zero cap admitted new quarantine: result=%+v calls=%d err=%v", result, blocked.calls, err)
	}
}

func TestM052QuarantineCapacityRealAPIRetainsAmbiguityAndReleasesOnlyDefiniteNoEffect(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is required")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../../build/phoenix-extended/config/crd/bases"}}
	cfg, err := e.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"operator", "release", "ambiguous", "lost-create", "lost-update", "cleanup", "oversized-effect"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	newPod := func(namespace, name string) *corev1.Pod {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}}}
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		return pod
	}
	request := func(pod *corev1.Pod, policy string) Request {
		return Request{PolicyName: policy, PolicyUID: policy + "-uid", Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionQuarantine}
	}

	releasePod := newPod("release", "target")
	releaseGuard, err := NewQuarantineCapacity(c, c, "operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	definite := &m052CapacityBackend{name: "definite", err: RefusedWithoutEffect(errors.New("pre-effect refusal"))}
	if result, err := releaseGuard.Actuate(ctx, definite, request(releasePod, "release-policy")); !IsNoEffectRefusal(err) || result.Emitted {
		t.Fatalf("definite refusal result=%+v err=%v", result, err)
	}
	if inv, err := releaseGuard.Inventory(ctx, "release"); err != nil || inv.Used != 0 || inv.Reserved != 0 {
		t.Fatalf("definite no-effect reservation was not released: inventory=%+v err=%v", inv, err)
	}

	ambiguousPod := newPod("ambiguous", "target")
	ambiguousGuard, err := NewQuarantineCapacity(c, c, "operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := &m052CapacityBackend{name: "ambiguous", err: context.DeadlineExceeded}
	if _, err := ambiguousGuard.Actuate(ctx, ambiguous, request(ambiguousPod, "ambiguous-policy")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ambiguous backend error lost: %v", err)
	}
	if inv, err := ambiguousGuard.Inventory(ctx, "ambiguous"); err != nil || inv.Used != 1 || inv.Reserved != 1 {
		t.Fatalf("ambiguous outcome did not retain capacity: inventory=%+v err=%v", inv, err)
	}

	lostCreatePod := newPod("lost-create", "target")
	lostCreateClient := &m052LostAckClient{Client: c, loseCreate: true}
	lostCreateGuard, err := NewQuarantineCapacity(lostCreateClient, c, "operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	neverCalled := &m052CapacityBackend{name: "phoenix", result: Result{Emitted: true}}
	if _, err := lostCreateGuard.Actuate(ctx, neverCalled, request(lostCreatePod, "lost-create-policy")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost create acknowledgement result: %v", err)
	}
	if neverCalled.calls != 0 {
		t.Fatalf("backend dispatched after lost reservation acknowledgement: calls=%d", neverCalled.calls)
	}
	if inv, err := lostCreateGuard.Inventory(ctx, "lost-create"); err != nil || inv.Reserved != 1 || inv.Used != 1 {
		t.Fatalf("lost create acknowledgement did not retain slot: inventory=%+v err=%v", inv, err)
	}
	restarted, _ := NewQuarantineCapacity(c, c, "operator", 1)
	if _, err := restarted.Actuate(ctx, neverCalled, request(lostCreatePod, "lost-create-policy")); err == nil || neverCalled.calls != 0 {
		t.Fatalf("restart retried pending target: calls=%d err=%v", neverCalled.calls, err)
	}

	first := newPod("lost-update", "first")
	second := newPod("lost-update", "second")
	initial, _ := NewQuarantineCapacity(c, c, "operator", 2)
	if _, err := initial.reserve(ctx, request(first, "first-policy"), "phoenix"); err != nil {
		t.Fatalf("initial reservation: %v", err)
	}
	lostUpdateClient := &m052LostAckClient{Client: c, loseUpdate: true}
	lostUpdateGuard, _ := NewQuarantineCapacity(lostUpdateClient, c, "operator", 2)
	if _, err := lostUpdateGuard.reserve(ctx, request(second, "second-policy"), "phoenix"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost update acknowledgement result: %v", err)
	}
	if inv, err := lostUpdateGuard.Inventory(ctx, "lost-update"); err != nil || inv.Reserved != 2 || inv.Used != 2 {
		t.Fatalf("lost update acknowledgement did not retain both slots: inventory=%+v err=%v", inv, err)
	}

	cleanupFirst := newPod("cleanup", "first")
	cleanupSecond := newPod("cleanup", "second")
	cleanupThird := newPod("cleanup", "third")
	cleanupGuard, _ := NewQuarantineCapacity(c, c, "operator", 2)
	confirmed := &m052CapacityBackend{name: "native", result: Result{Actuator: "native", Emitted: true, ObjectsTouched: []string{"Pod/cleanup/target"}}}
	firstCleanupRequest := request(cleanupFirst, "cleanup-first-policy")
	firstCleanupRequest.Tenant = "cleanup-tenant"
	secondCleanupRequest := request(cleanupSecond, "cleanup-second-policy")
	phoenix := NewPhoenixActuator(c)
	phoenixResult, err := cleanupGuard.Actuate(ctx, phoenix, firstCleanupRequest)
	if err != nil || phoenixResult.EventName == "" || phoenixResult.EventUID == "" {
		t.Fatal(err)
	}
	if _, err := cleanupGuard.Actuate(ctx, confirmed, secondCleanupRequest); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, cleanupFirst, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	if err := cleanupGuard.ReconcileConclusiveAbsence(ctx, "cleanup", string(cleanupFirst.UID)); err == nil {
		t.Fatal("administrative reconciliation released capacity while delayed Phoenix work still existed")
	}
	pendingEvent := &amtdv1beta1.SecurityEvent{}
	if err := c.Get(ctx, client.ObjectKey{Name: phoenixResult.EventName}, pendingEvent); err != nil {
		t.Fatal(err)
	}
	if string(pendingEvent.UID) != phoenixResult.EventUID {
		t.Fatalf("pending event UID changed: got=%s want=%s", pendingEvent.UID, phoenixResult.EventUID)
	}
	if err := c.Delete(ctx, pendingEvent); err != nil {
		t.Fatal(err)
	}
	replacement := newPod("cleanup", cleanupFirst.Name)
	if replacement.UID == cleanupFirst.UID {
		t.Fatal("same-name cleanup control did not receive a new UID")
	}
	if err := cleanupGuard.ReconcileConclusiveAbsence(ctx, "cleanup", string(cleanupFirst.UID)); err == nil {
		t.Fatal("administrative reconciliation accepted a same-name replacement as conclusive absence")
	}
	if err := c.Delete(ctx, replacement, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	if err := cleanupGuard.ReconcileConclusiveAbsence(ctx, "cleanup", string(cleanupFirst.UID)); err != nil {
		t.Fatalf("quiesced conclusive administrative reconciliation: %v", err)
	}
	cleanupNS := &corev1.Namespace{}
	if err := c.Get(ctx, client.ObjectKey{Name: "cleanup"}, cleanupNS); err != nil {
		t.Fatal(err)
	}
	cleanupCM := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: quarantineCapacityLedgerName(string(cleanupNS.UID))}, cleanupCM); err != nil {
		t.Fatal(err)
	}
	cleanupLedger, err := decodeQuarantineCapacityLedger(cleanupCM, "cleanup", string(cleanupNS.UID))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cleanupLedger.Records[string(cleanupFirst.UID)]; exists || len(cleanupLedger.Records) != 1 || cleanupLedger.Records[string(cleanupSecond.UID)].PodUID != string(cleanupSecond.UID) {
		t.Fatalf("administrative reconciliation changed a record other than its exact target: %+v", cleanupLedger.Records)
	}
	if _, err := cleanupGuard.Actuate(ctx, confirmed, request(cleanupThird, "cleanup-third-policy")); err != nil {
		t.Fatalf("conclusive cleanup did not permit next below-cap target: %v", err)
	}
	if inv, err := cleanupGuard.Inventory(ctx, "cleanup"); err != nil || inv.Used != 2 || inv.Reserved != 2 {
		t.Fatalf("post-cleanup capacity inventory=%+v err=%v", inv, err)
	}

	oversizedPod := newPod("oversized-effect", "target")
	oversizedGuard, _ := NewQuarantineCapacity(c, c, "operator", 1)
	oversizedBackend := &m052CapacityBackend{name: "native", result: Result{Actuator: "native", Emitted: true, ObjectsTouched: []string{strings.Repeat("x", quarantineCapacityMaxObject+1)}}}
	oversizedResult, err := oversizedGuard.Actuate(ctx, oversizedBackend, request(oversizedPod, "oversized-policy"))
	if err != nil || !oversizedResult.Emitted || len(oversizedResult.ObjectsTouched[0]) != quarantineCapacityMaxObject+1 {
		t.Fatalf("full acknowledged effect truth was not preserved: result=%+v err=%v", oversizedResult, err)
	}
	oversizedNS := &corev1.Namespace{}
	if err := c.Get(ctx, client.ObjectKey{Name: oversizedPod.Namespace}, oversizedNS); err != nil {
		t.Fatal(err)
	}
	oversizedCM := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: quarantineCapacityLedgerName(string(oversizedNS.UID))}, oversizedCM); err != nil {
		t.Fatal(err)
	}
	oversizedLedger, err := decodeQuarantineCapacityLedger(oversizedCM, oversizedPod.Namespace, string(oversizedNS.UID))
	if err != nil {
		t.Fatal(err)
	}
	oversizedRecord := oversizedLedger.Records[string(oversizedPod.UID)]
	if oversizedRecord.Phase != "ambiguous" || len(oversizedRecord.Objects) != 0 || !strings.Contains(oversizedRecord.Detail, "exceeded") {
		t.Fatalf("oversized effect bookkeeping was not bounded and retained: %+v", oversizedRecord)
	}

	noop := &m052CapacityBackend{name: "noop", result: Result{Actuator: "noop"}}
	if _, err := releaseGuard.Actuate(ctx, noop, Request{Action: model.ActionNoop}); err != nil || noop.calls != 1 {
		t.Fatalf("non-quarantine action should bypass capacity ledger: calls=%d err=%v", noop.calls, err)
	}
}
