package actuator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type m052InventoryFailureReader struct {
	client.Reader
	failPodList bool
	failEvents  bool
	failLedger  bool
}

func (r m052InventoryFailureReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.PodList); ok && r.failPodList {
		return errors.New("pod inventory unavailable")
	}
	if _, ok := list.(*amtdv1beta1.SecurityEventList); ok && r.failEvents {
		return errors.New("pending event inventory unavailable")
	}
	return r.Reader.List(ctx, list, opts...)
}

func (r m052InventoryFailureReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok && r.failLedger {
		return errors.New("protected ledger unavailable")
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func TestQuarantineCapacityConfigurationBounds(t *testing.T) {
	scheme := p4bScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	for _, limit := range []int{0, 1, MaxRetainedQuarantinesUpperBound} {
		guard, err := NewQuarantineCapacity(c, c, "operator", limit)
		if err != nil || guard.Limit() != limit {
			t.Fatalf("limit %d: guard=%v err=%v", limit, guard, err)
		}
	}
	for _, limit := range []int{-1, MaxRetainedQuarantinesUpperBound + 1} {
		if _, err := NewQuarantineCapacity(c, c, "operator", limit); err == nil {
			t.Fatalf("invalid limit %d was accepted", limit)
		}
	}
	if _, err := NewQuarantineCapacity(c, c, "", 1); err == nil {
		t.Fatal("missing operator namespace was accepted")
	}
	if _, err := NewQuarantineCapacity(nil, c, "operator", 1); err == nil {
		t.Fatal("missing capacity client was accepted")
	}
}

func TestQuarantineCapacityCountsBoundPendingPhoenixEventsAndRejectsLegacy(t *testing.T) {
	ctx := context.Background()
	operationID := strings.Repeat("a", 40)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", UID: "namespace-uid"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "already", Namespace: ns.Name, UID: "pod-observed", Labels: map[string]string{phoenixQuarantineMarker: "policy"}}}
	bound := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "pending", UID: "event-uid", Annotations: map[string]string{
			phorvexQuarantineTargetUIDAnnotation:    "pod-pending",
			phorvexQuarantineNamespaceUIDAnnotation: string(ns.UID),
			phorvexQuarantineOperationAnnotation:    operationID,
		}},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets: []string{"tenant/replacement"},
			Rule:    amtdv1beta1.Rule{Type: RuleTypeQuarantine, Source: RuleSource},
		},
	}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(ns, pod, bound).Build()
	guard, err := NewQuarantineCapacity(c, c, "operator", 3)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := guard.Inventory(ctx, ns.Name)
	if err != nil || inv.Observed != 1 || inv.Pending != 1 || inv.Reserved != 0 || inv.Used != 2 {
		t.Fatalf("pending event inventory=%+v err=%v", inv, err)
	}
	ledger := quarantineCapacityLedger{
		Version: 1, Namespace: ns.Name, NamespaceUID: string(ns.UID),
		Records: map[string]quarantineCapacityRecord{
			"pod-pending": {OperationID: operationID, Phase: "phoenix-event", Namespace: ns.Name, NamespaceUID: string(ns.UID), Pod: "replacement", PodUID: "pod-pending", PolicyName: "policy", PolicyUID: "policy-uid", Backend: "phoenix", EventName: bound.Name, EventUID: string(bound.UID)},
		},
	}
	encoded, err := encodeQuarantineCapacityLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: quarantineCapacityLedgerName(string(ns.UID)), UID: "ledger-uid", Labels: map[string]string{quarantineCapacityLabel: "v1"}}, Data: map[string]string{quarantineCapacityDataKey: encoded}}
	if err := c.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	inv, err = guard.Inventory(ctx, ns.Name)
	if err != nil || inv.Observed != 1 || inv.Reserved != 1 || inv.Pending != 0 || inv.Used != 2 {
		t.Fatalf("ledger and pending event UID were not deduplicated: inventory=%+v err=%v", inv, err)
	}

	legacy := bound.DeepCopy()
	legacy.Name = "legacy"
	legacy.UID = "legacy-event-uid"
	legacy.ResourceVersion = ""
	legacy.Annotations = nil
	if err := c.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Inventory(ctx, ns.Name); err == nil || !strings.Contains(err.Error(), "administrative reconciliation is required") {
		t.Fatalf("legacy unbound event must fail inventory closed with migration diagnostic, got %v", err)
	}
}

func TestQuarantineCapacityInventoryFailuresStayUnknown(t *testing.T) {
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", UID: "namespace-uid"}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(ns).Build()
	for name, reader := range map[string]client.Reader{
		"pod-list": m052InventoryFailureReader{Reader: c, failPodList: true},
		"events":   m052InventoryFailureReader{Reader: c, failEvents: true},
		"ledger":   m052InventoryFailureReader{Reader: c, failLedger: true},
	} {
		t.Run(name, func(t *testing.T) {
			guard, err := NewQuarantineCapacity(c, reader, "operator", 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := guard.Inventory(ctx, ns.Name); err == nil {
				t.Fatal("incomplete authoritative inventory was treated as zero")
			}
		})
	}
}

func TestQuarantineCapacityRejectsTerminatingOrRecreatedLedger(t *testing.T) {
	now := metav1.NewTime(time.Now())
	operationID := strings.Repeat("b", 40)
	ledger := quarantineCapacityLedger{
		Version: 1, Namespace: "tenant", NamespaceUID: "namespace-uid",
		Records: map[string]quarantineCapacityRecord{
			"pod-uid": {OperationID: operationID, Phase: "dispatching", Namespace: "tenant", NamespaceUID: "namespace-uid", Pod: "pod", PodUID: "pod-uid", PolicyName: "policy", PolicyUID: "policy-uid", Backend: "native"},
		},
	}
	encoded, err := encodeQuarantineCapacityLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	terminating := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: quarantineCapacityLedgerName("namespace-uid"), UID: "ledger-old", ResourceVersion: "1", DeletionTimestamp: &now}, Data: map[string]string{quarantineCapacityDataKey: encoded}}
	terminating.Labels = map[string]string{quarantineCapacityLabel: "v1"}
	if _, err := decodeQuarantineCapacityLedger(terminating, "tenant", "namespace-uid"); err == nil {
		t.Fatal("terminating protected ledger was accepted")
	}

	recreated := terminating.DeepCopy()
	recreated.DeletionTimestamp = nil
	recreated.UID = "ledger-new"
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(recreated).Build()
	guard, err := NewQuarantineCapacity(c, c, "operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	reservation := &QuarantineReservation{
		ledgerName: recreated.Name, ledgerUID: types.UID("ledger-old"), namespace: "tenant", namespaceUID: "namespace-uid", targetName: "pod", targetUID: "pod-uid", operationID: operationID,
	}
	if err := guard.mutateReservation(context.Background(), reservation, func(record *quarantineCapacityRecord) bool { return true }); err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("recreated protected ledger accepted stale handle: %v", err)
	}
	got := &corev1.ConfigMap{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(recreated), got); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeQuarantineCapacityLedger(got, "tenant", "namespace-uid")
	if err != nil || decoded.Records["pod-uid"].OperationID != operationID {
		t.Fatalf("stale handle changed replacement ledger: ledger=%+v err=%v", decoded, err)
	}
}

func TestQuarantineCapacityLedgerCountAndByteBounds(t *testing.T) {
	base := quarantineCapacityLedger{Version: 1, Namespace: strings.Repeat("n", 253), NamespaceUID: strings.Repeat("s", 128), Records: map[string]quarantineCapacityRecord{}}
	for i := 0; i < MaxRetainedQuarantinesUpperBound; i++ {
		uid := fmt.Sprintf("%0128d", i)
		objects := make([]string, quarantineCapacityMaxObjects)
		for j := range objects {
			objects[j] = strings.Repeat(string(rune('a'+j)), quarantineCapacityMaxObject)
		}
		base.Records[uid] = quarantineCapacityRecord{
			OperationID: strings.Repeat("c", 40), Phase: "native-effect", Namespace: base.Namespace, NamespaceUID: base.NamespaceUID,
			Pod: strings.Repeat("p", 253), PodUID: uid, PolicyName: strings.Repeat("q", 253), PolicyUID: strings.Repeat("u", 128),
			Backend: strings.Repeat("b", 64), Objects: objects, Detail: strings.Repeat("d", 512),
		}
	}
	if _, err := encodeQuarantineCapacityLedger(base); err == nil || !strings.Contains(err.Error(), "byte storage bound") {
		t.Fatalf("oversized 128-record ledger was accepted: %v", err)
	}
	extra := quarantineCapacityRecord{OperationID: strings.Repeat("d", 40), Phase: "dispatching", Namespace: base.Namespace, NamespaceUID: base.NamespaceUID, Pod: "extra", PodUID: "extra", PolicyName: "policy", PolicyUID: "policy-uid", Backend: "native"}
	base.Records = map[string]quarantineCapacityRecord{}
	for i := 0; i <= MaxRetainedQuarantinesUpperBound; i++ {
		uid := fmt.Sprintf("pod-%d", i)
		record := extra
		record.PodUID = uid
		base.Records[uid] = record
	}
	if _, err := encodeQuarantineCapacityLedger(base); err == nil || !strings.Contains(err.Error(), "configured bounds") {
		t.Fatalf("129-record ledger was accepted: %v", err)
	}
	if objects, ok := capacityRecordObjects([]string{strings.Repeat("x", quarantineCapacityMaxObject+1)}); ok || objects != nil {
		t.Fatal("unbounded effect object reference was accepted for protected bookkeeping")
	}
}
