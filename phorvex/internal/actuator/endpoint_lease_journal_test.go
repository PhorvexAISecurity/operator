package actuator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/endpointlease"
)

func leaseTestReceipt(t *testing.T) endpointLeaseReceipt {
	t.Helper()
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	op := strings.Repeat("c", 64)
	serviceUID := "11111111-1111-4111-8111-111111111111"
	secretUID := "22222222-2222-4222-8222-222222222222"
	sourceSHA := strings.Repeat("d", 64)
	seedSHA := strings.Repeat("e", 64)
	old := endpointlease.State{Version: 1, Revision: 0, ServiceUID: serviceUID, ProxySourceSHA256: sourceSHA,
		SecretUID: secretUID, SeedSHA256: seedSHA, AllowedClientHMACs: []string{a, b}, RevokedClientHMACs: []string{}, LastOperationID: ""}
	oldRaw, err := endpointlease.EncodeState(old)
	if err != nil {
		t.Fatal(err)
	}
	next, err := old.Revoke(a, b, op)
	if err != nil {
		t.Fatal(err)
	}
	nextRaw, err := endpointlease.EncodeState(next)
	if err != nil {
		t.Fatal(err)
	}
	return endpointLeaseReceipt{Phase: "prepared", OperationID: op, EventName: "lease-event", EventUID: "33333333-3333-4333-8333-333333333333",
		DecisionID: op, TickID: "tick-1", PolicyName: "vllm-defense", PolicyUID: "44444444-4444-4444-8444-444444444444", PolicyGeneration: 1,
		Namespace: endpointlease.Namespace, TargetPodName: "vllm-pod", TargetPodUID: "55555555-5555-4555-8555-555555555555",
		ServiceUID: serviceUID, ProxySourceSHA256: sourceSHA, PolicyConfigMapUID: "66666666-6666-4666-8666-666666666666",
		SecretUID: secretUID, SeedSHA256: seedSHA, OldRevision: 0, NewRevision: 1,
		OldStateSHA256: endpointlease.SHA256([]byte(oldRaw)), NewStateSHA256: endpointlease.SHA256([]byte(nextRaw)),
		RevokedClientHMAC: a, RetainedClientHMAC: b, PreCASPodUIDs: []string{"55555555-5555-4555-8555-555555555555"},
		PreCASProxyContainerIDs: []string{"containerd://old-proxy"}}
}

func TestPendingEndpointLeaseJournalScopesMalformedSlotToServingPod(t *testing.T) {
	r := leaseTestReceipt(t)
	cm := leaseTestJournalCM(r)
	cm.Data[endpointlease.JournalKey] = "malformed"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.ServiceName, Namespace: endpointlease.Namespace},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "vllm"}}}
	serving := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "vllm-pod", Namespace: endpointlease.Namespace,
		UID: types.UID(r.TargetPodUID), Labels: map[string]string{"app": "vllm"}}}
	unrelated := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "support", Namespace: endpointlease.Namespace,
		UID: types.UID("88888888-8888-4888-8888-888888888888"), Labels: map[string]string{"app": "support"}}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(cm, svc, serving, unrelated).Build()
	if pending, err := PendingEndpointLeaseOperation(context.Background(), c, "phorvex-system", endpointlease.Namespace, string(unrelated.UID)); err != nil || pending {
		t.Fatalf("unrelated Pod fenced by malformed serving journal: pending=%v err=%v", pending, err)
	}
	if pending, err := PendingEndpointLeaseOperation(context.Background(), c, "phorvex-system", endpointlease.Namespace, r.TargetPodUID); !pending || err == nil {
		t.Fatalf("serving Pod not fail-closed on malformed journal: pending=%v err=%v", pending, err)
	}
}

func leaseTestJournalCM(r endpointLeaseReceipt) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.JournalName, Namespace: "phorvex-system",
		UID: types.UID("77777777-7777-4777-8777-777777777777"), ResourceVersion: "1",
		Labels: map[string]string{endpointlease.JournalLabel: "v1"}},
		Data: map[string]string{endpointlease.JournalKey: endpointLeaseJournalRaw(endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseReceipt{r}})}}
}

func TestEndpointLeaseJournalBindsInitialStateAndAbortedLineage(t *testing.T) {
	r := leaseTestReceipt(t)
	for _, phase := range []string{"prepared", "terminal-full", "aborted"} {
		good := r
		good.Phase = phase
		if phase == "aborted" {
			good.AbortReason = "definitive-policy-conflict"
		}
		if _, err := endpointLeaseReadJournal(leaseTestJournalCM(good)); err != nil {
			t.Fatalf("valid %s: %v", phase, err)
		}
		for _, mutation := range []string{"old-revision", "old-state", "new-state"} {
			bad := good
			switch mutation {
			case "old-revision":
				bad.OldRevision, bad.NewRevision = 42, 43
			case "old-state":
				bad.OldStateSHA256 = strings.Repeat("f", 64)
			case "new-state":
				bad.NewStateSHA256 = strings.Repeat("f", 64)
			}
			if _, err := endpointLeaseReadJournal(leaseTestJournalCM(bad)); err == nil {
				t.Fatalf("%s accepted %s lineage drift", phase, mutation)
			}
		}
	}
}
