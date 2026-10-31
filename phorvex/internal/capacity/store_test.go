package capacity

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	m103Namespace     = "ns"
	m103Operator      = "operator"
	m103Service       = "serving"
	m103ServiceUID    = "service-uid"
	m103ControllerUID = "controller-uid"
)

func m103Ready(value bool) *bool { return &value }

func m103Objects(t *testing.T) (*Store, client.Client, model.ResourceScope) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	controller := true
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: m103Namespace, Name: m103Service, UID: types.UID(m103ServiceUID)}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "fixture"}}}
	pod := func(name, uid string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: m103Namespace, Name: name, UID: types.UID(uid), Labels: map[string]string{"app": "fixture"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "owner", UID: types.UID(m103ControllerUID), Controller: &controller}}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: m103Namespace, Name: "serving-1", UID: "slice-uid", Labels: map[string]string{discoveryv1.LabelServiceName: m103Service}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: m103Service, UID: types.UID(m103ServiceUID), Controller: &controller}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{
		{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: m103Ready(true)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: m103Namespace, Name: "a", UID: "pod-a"}},
		{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: m103Ready(true)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: m103Namespace, Name: "b", UID: "pod-b"}},
	}}
	encoded, err := encodeLedger(emptyLedger())
	if err != nil {
		t.Fatal(err)
	}
	ledger := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: m103Operator, Name: ledgerName, UID: "ledger-uid", ResourceVersion: "1", Labels: map[string]string{ledgerLabel: "v1"}}, Data: map[string]string{ledgerDataKey: encoded}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service, pod("a", "pod-a"), pod("b", "pod-b"), slice, ledger).Build()
	store, err := NewStore(c, c, m103Operator)
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ResourceScope{Kind: model.ResourceUnavailableReadyReplica, Namespace: m103Namespace, ServiceName: m103Service, ServiceUID: m103ServiceUID, ControllerUID: m103ControllerUID}
	return store, c, scope
}

func m103Request(op, pod, uid string, action model.Action, scope model.ResourceScope) Request {
	move := model.ResourceScope{Kind: model.ResourceMoveCount, Namespace: m103Namespace, ControllerUID: "policy-uid"}
	return Request{PolicyUID: "policy-uid", TargetNamespace: m103Namespace, TargetName: pod, TargetUID: uid, Action: action, OperationID: op, MinAvailableReplica: 1, Resources: []model.ResourceConsumption{{Scope: move, Units: 1}, {Scope: scope, Units: 1}}}
}

func m103Ledger(t *testing.T, store *Store) ledger {
	t.Helper()
	_, value, err := store.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestM103ReservedCapacityIsAtomicAndClaimRevalidatesAuthority(t *testing.T) {
	ctx := context.Background()
	store, c, scope := m103Objects(t)
	first, err := store.Acquire(ctx, m103Request("op-a", "a", "pod-a", model.ActionRotate, scope))
	if err != nil || first == nil || !first.Created {
		t.Fatalf("first acquire = %#v, %v", first, err)
	}
	if _, err := store.Acquire(ctx, m103Request("op-b", "b", "pod-b", model.ActionRotate, scope)); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("second policy spent the same spare replica: %v", err)
	}
	if err := store.Claim(ctx, first); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got := m103Ledger(t, store).Records[first.OperationID].Phase; got != "dispatching" {
		t.Fatalf("claimed phase = %q", got)
	}
	if err := store.Claim(ctx, first); err == nil {
		t.Fatal("a claimed operation was replayable")
	}
	// A newly constructed store must reconstruct the same pending obligation.
	restarted, err := NewStore(c, c, m103Operator)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := restarted.Inventory(ctx)
	if err != nil || usage[scope.Key()] != 1 {
		t.Fatalf("restart inventory = %#v, %v", usage, err)
	}
}

func TestM103ClaimRefusesReadinessChangeAndReservedRecoveryIsDefinitelyUnsent(t *testing.T) {
	ctx := context.Background()
	store, c, scope := m103Objects(t)
	reservation, err := store.Acquire(ctx, m103Request("op-a", "a", "pod-a", model.ActionRotate, scope))
	if err != nil {
		t.Fatal(err)
	}
	var slice discoveryv1.EndpointSlice
	if err := c.Get(ctx, client.ObjectKey{Namespace: m103Namespace, Name: "serving-1"}, &slice); err != nil {
		t.Fatal(err)
	}
	slice.Endpoints[1].Conditions.Ready = m103Ready(false)
	if err := c.Update(ctx, &slice); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, reservation); err == nil || !strings.Contains(err.Error(), "availability changed") {
		t.Fatalf("claim accepted stale ready count: %v", err)
	}
	if got := m103Ledger(t, store).Records[reservation.OperationID].Phase; got != "reserved" {
		t.Fatalf("failed claim changed phase to %q", got)
	}
	usage, err := store.Inventory(ctx)
	if err != nil || len(usage) != 0 || len(m103Ledger(t, store).Records) != 0 {
		t.Fatalf("definitely-unsent reserved recovery = usage %#v ledger %#v err %v", usage, m103Ledger(t, store), err)
	}
}

func TestM103EffectRecoveryAndFallbackExchange(t *testing.T) {
	ctx := context.Background()
	store, c, scope := m103Objects(t)
	reservation, err := store.Acquire(ctx, m103Request("op-a", "a", "pod-a", model.ActionRotate, scope))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, reservation); err != nil {
		t.Fatal(err)
	}

	// The acknowledged effect removes A from routing. Capacity is no longer
	// double-counted, but the durable record remains until ReadyBefore recovers.
	var slice discoveryv1.EndpointSlice
	if err := c.Get(ctx, client.ObjectKey{Namespace: m103Namespace, Name: "serving-1"}, &slice); err != nil {
		t.Fatal(err)
	}
	slice.Endpoints = slice.Endpoints[1:]
	if err := c.Update(ctx, &slice); err != nil {
		t.Fatal(err)
	}
	usage, err := store.Inventory(ctx)
	if err != nil || usage[scope.Key()] != 0 || len(m103Ledger(t, store).Records) != 1 {
		t.Fatalf("post-effect inventory = %#v ledger=%#v err=%v", usage, m103Ledger(t, store), err)
	}
	controller := true
	podC := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: m103Namespace, Name: "c", UID: "pod-c", Labels: map[string]string{"app": "fixture"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "owner", UID: types.UID(m103ControllerUID), Controller: &controller}}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	if err := c.Create(ctx, podC); err != nil {
		t.Fatal(err)
	}
	slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{"10.0.0.3"}, Conditions: discoveryv1.EndpointConditions{Ready: m103Ready(true)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: m103Namespace, Name: "c", UID: "pod-c"}})
	if err := c.Update(ctx, &slice); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inventory(ctx); err != nil || len(m103Ledger(t, store).Records) != 0 {
		t.Fatalf("recovered capacity did not release exactly once: ledger=%#v err=%v", m103Ledger(t, store), err)
	}

	// A definite refusal exchanges the original claimed reservation for the
	// fallback in one ledger update; the original key never becomes free first.
	original, err := store.Acquire(ctx, m103Request("op-original", "b", "pod-b", model.ActionRotate, scope))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, original); err != nil {
		t.Fatal(err)
	}
	fallback, err := store.Exchange(ctx, original, m103Request("op-fallback", "b", "pod-b", model.ActionQuarantine, scope))
	if err != nil || fallback == nil || !fallback.Created {
		t.Fatalf("exchange = %#v, %v", fallback, err)
	}
	value := m103Ledger(t, store)
	if _, old := value.Records[original.OperationID]; old || value.Records[fallback.OperationID].Phase != "reserved" {
		t.Fatalf("fallback exchange was not atomic: %#v", value)
	}
	if err := store.Claim(ctx, fallback); err != nil {
		t.Fatal(err)
	}
	again, err := store.Acquire(ctx, m103Request("op-fallback", "b", "pod-b", model.ActionQuarantine, scope))
	if err != nil || again.Created {
		t.Fatalf("claimed fallback became replayable: %#v, %v", again, err)
	}
	if err := store.ReleaseNoEffect(ctx, fallback); err != nil {
		t.Fatal(err)
	}
	if len(m103Ledger(t, store).Records) != 0 {
		t.Fatal("authenticated no-effect did not release fallback reservation")
	}
}

func TestM103ServiceUIDChangeFailsClosed(t *testing.T) {
	ctx := context.Background()
	store, c, scope := m103Objects(t)
	var service corev1.Service
	if err := c.Get(ctx, client.ObjectKey{Namespace: m103Namespace, Name: m103Service}, &service); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, &service); err != nil {
		t.Fatal(err)
	}
	service.ResourceVersion = ""
	service.UID = "replacement-service-uid"
	if err := c.Create(ctx, &service); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(ctx, m103Request("op", "a", "pod-a", model.ActionRotate, scope)); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("recreated same-name Service inherited capacity: %v", err)
	}
}

// An eviction-based dispatch whose outcome stayed unknown (its tick expired) holds the
// capacity while its exact target remains Ready, but only for staleDispatchAfter: after
// that, the still-Ready target proves the dispatch removed no member and can no longer
// remove one. On staging, a stateful-snapshot-rotate cut off by the 40s tick deadline
// otherwise held the StatefulSet's only unit, and every later move on it was refused.
func TestStaleEvictionDispatchWithReadyTargetIsReleased(t *testing.T) {
	ctx := context.Background()
	store, _, scope := m103Objects(t)
	clock := time.Date(2026, 10, 31, 12, 15, 50, 0, time.UTC)
	store.now = func() time.Time { return clock }
	reservation, err := store.Acquire(ctx, m103Request("op-snap", "a", "pod-a", model.ActionStatefulSnapshotRotate, scope))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	if got := m103Ledger(t, store).Records["op-snap"].Since; got != clock.Format(time.RFC3339Nano) {
		t.Fatalf("claim did not stamp the dispatch time: %q", got)
	}
	clock = clock.Add(staleDispatchAfter - time.Second)
	usage, err := store.Inventory(ctx)
	if err != nil || usage[scope.Key()] != 1 || len(m103Ledger(t, store).Records) != 1 {
		t.Fatalf("a recent unknown dispatch must keep its unit: usage=%#v ledger=%#v err=%v", usage, m103Ledger(t, store), err)
	}
	clock = clock.Add(time.Second)
	usage, err = store.Inventory(ctx)
	if err != nil || usage[scope.Key()] != 0 || len(m103Ledger(t, store).Records) != 0 {
		t.Fatalf("a stale dispatch whose target is still Ready must be released: usage=%#v ledger=%#v err=%v", usage, m103Ledger(t, store), err)
	}
}

// Staleness never releases a non-eviction action, nor an eviction whose target left the
// ready endpoints (that one waits for the Service to recover, as before).
func TestStaleReleaseIsLimitedToUntouchedEvictionTargets(t *testing.T) {
	ctx := context.Background()
	store, c, scope := m103Objects(t)
	clock := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return clock }
	quarantine, err := store.Acquire(ctx, m103Request("op-q", "b", "pod-b", model.ActionQuarantine, scope))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, quarantine); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	if _, err := store.Inventory(ctx); err != nil || len(m103Ledger(t, store).Records) != 1 {
		t.Fatalf("quarantine must never be released as stale: ledger=%#v err=%v", m103Ledger(t, store), err)
	}
	if err := store.ReleaseNoEffect(ctx, quarantine); err != nil {
		t.Fatal(err)
	}

	rebuild, err := store.Acquire(ctx, m103Request("op-r", "a", "pod-a", model.ActionStatefulReplicaRebuild, scope))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, rebuild); err != nil {
		t.Fatal(err)
	}
	var slice discoveryv1.EndpointSlice
	if err := c.Get(ctx, client.ObjectKey{Namespace: m103Namespace, Name: "serving-1"}, &slice); err != nil {
		t.Fatal(err)
	}
	slice.Endpoints = slice.Endpoints[1:] // the eviction took A out; no replacement yet
	if err := c.Update(ctx, &slice); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	if _, err := store.Inventory(ctx); err != nil || len(m103Ledger(t, store).Records) != 1 {
		t.Fatalf("an eviction that removed its target must wait for recovery: ledger=%#v err=%v", m103Ledger(t, store), err)
	}
}

// A record written before dispatch times were kept is stamped on first sight and only
// released a full staleDispatchAfter later.
func TestLegacyDispatchRecordIsStampedBeforeRelease(t *testing.T) {
	ctx := context.Background()
	store, c, scope := m103Objects(t)
	clock := time.Date(2026, 10, 31, 14, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return clock }
	legacy := emptyLedger()
	legacy.Records["op-old"] = record{OperationID: "op-old", PolicyUID: "policy-uid", TargetName: "a", TargetUID: "pod-a",
		Action: model.ActionStatefulSnapshotRotate, Phase: "dispatching",
		Admissions: []admission{{Scope: scope, Units: 1, Floor: 1, ReadyBefore: 2}}}
	encoded, err := encodeLedger(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKey{Namespace: m103Operator, Name: ledgerName}, &cm); err != nil {
		t.Fatal(err)
	}
	cm.Data[ledgerDataKey] = encoded
	if err := c.Update(ctx, &cm); err != nil {
		t.Fatal(err)
	}
	usage, err := store.Inventory(ctx)
	if err != nil || usage[scope.Key()] != 1 || m103Ledger(t, store).Records["op-old"].Since != clock.Format(time.RFC3339Nano) {
		t.Fatalf("legacy record must be stamped and still held: usage=%#v ledger=%#v err=%v", usage, m103Ledger(t, store), err)
	}
	clock = clock.Add(staleDispatchAfter)
	if _, err := store.Inventory(ctx); err != nil || len(m103Ledger(t, store).Records) != 0 {
		t.Fatalf("stamped legacy record must be released after the bound: ledger=%#v err=%v", m103Ledger(t, store), err)
	}
}
