package actuator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/outputpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type liteOutputTrip func(*http.Request) (*http.Response, error)

func (f liteOutputTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func liteOutputTestReceipt(t *testing.T) (liteOutputReceipt, outputpolicy.LiteState) {
	t.Helper()
	rule := outputpolicy.LiteRule{Version: 2, ObjectiveID: outputpolicy.LiteDocumentObjective, RunNonce: strings.Repeat("1", 32),
		Method: "POST", Path: "/v1/chat/completions", FieldPath: []any{"choices", float64(0), "message", "content"}, MaxResponseBytes: 131072,
		ProtectedSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), ServiceUID: "svc-uid", DeploymentUID: "deployment-uid",
		TargetPodUID: "pod-a", PeerPodUID: "pod-b", ContextSecretUID: "secret-uid", ContextSeedSHA256: strings.Repeat("c", 64)}
	prior := outputpolicy.LiteState{Version: 2, Revision: 0, Entries: []outputpolicy.LiteEntry{}}
	op := liteOutputOperationID("policy-uid", rule.DeploymentUID, "event-uid", "tick-id", "decision-id")
	entry := outputpolicy.LiteEntry{ObjectiveID: rule.ObjectiveID, RunNonce: rule.RunNonce, RuleSHA256: rule.SHA256(), ProtectedSHA256: rule.ProtectedSHA256,
		OperationID: op, ServiceUID: rule.ServiceUID, DeploymentUID: rule.DeploymentUID, TargetPodUID: rule.TargetPodUID, PeerPodUID: rule.PeerPodUID,
		SourceSHA256: rule.SourceSHA256, ContextSecretUID: rule.ContextSecretUID, ContextSeedSHA256: rule.ContextSeedSHA256}
	desired, err := prior.Append(entry)
	if err != nil {
		t.Fatal(err)
	}
	r := liteOutputReceipt{Version: 2, Phase: "prepared", PolicyName: "litellm-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
		TargetName: "litellm-a", TargetUID: "pod-a", EventName: "event-name", EventUID: "event-uid", CreatorIdentity: eventtrust.Injector(),
		TickID: "tick-id", SelectionDecisionID: "decision-id", OperationID: op, ConfigMapUID: "cm-uid", SelectedConfigMapResourceVersion: "8",
		RuleConfigMapName: outputpolicy.LiteRuleSlotName(0), RuleConfigMapUID: "rule-cm-uid", RuleSHA256: rule.SHA256(), Rule: rule, Prior: string(prior.Bytes()), Desired: string(desired.Bytes()),
		RequestSHA256: strings.Repeat("d", 64), OriginalCompletionSHA256: strings.Repeat("e", 64), ObservedAt: time.Now().UTC()}
	if !r.valid() {
		t.Fatal("valid protected receipt rejected")
	}
	return r, desired
}

func TestLiteOutputReceiptRejectsSelectionOrDesiredDrift(t *testing.T) {
	r, _ := liteOutputTestReceipt(t)
	wrong := r
	wrong.EventUID = "another-event"
	if wrong.valid() {
		t.Fatal("event changed without operation identity")
	}
	wrong = r
	wrong.TickID = "other-tick"
	if wrong.valid() {
		t.Fatal("tick changed without operation identity")
	}
	wrong = r
	wrong.SelectionDecisionID = "other-decision"
	if wrong.valid() {
		t.Fatal("decision changed without operation identity")
	}
	wrong = r
	wrong.Desired = wrong.Prior
	if wrong.valid() {
		t.Fatal("desired append missing")
	}
	wrong = r
	wrong.Rule.ContextSeedSHA256 = strings.Repeat("f", 64)
	if wrong.valid() {
		t.Fatal("private source drift accepted")
	}
}

func TestLiteOutputTerminalPreservesOlderEntryAcrossAppend(t *testing.T) {
	r, desired := liteOutputTestReceipt(t)
	if !liteOutputContainsState(desired, desired) {
		t.Fatal("same policy missing")
	}
	more := desired.Entries[0]
	more.RunNonce = strings.Repeat("2", 32)
	more.OperationID = strings.Repeat("f", 64)
	more.RuleSHA256 = strings.Repeat("f", 64)
	after, err := desired.Append(more)
	if err != nil {
		t.Fatal(err)
	}
	if !liteOutputContainsState(after, desired) {
		t.Fatal("later append lost prior receipt")
	}
	after.Entries[0].OperationID = strings.Repeat("9", 64)
	if liteOutputContainsState(after, desired) {
		t.Fatal("rewritten prior operation accepted")
	}
	_ = r
}

func TestLiteOutputReadbackRequiresBothExactGatewayPods(t *testing.T) {
	r, want := liteOutputTestReceipt(t)
	live := litellmclient.Live{Pods: []litellmclient.Pod{{Name: "a", UID: "pod-a", IP: "10.0.0.1"}, {Name: "b", UID: "pod-b", IP: "10.0.0.2"}}}
	wrongSecond := false
	transport := liteOutputTrip(func(req *http.Request) (*http.Response, error) {
		uid := "pod-a"
		if req.URL.Hostname() == "10.0.0.2" {
			uid = "pod-b"
			if wrongSecond {
				uid = "stale-pod"
			}
		}
		if req.Header.Get("Authorization") != "Bearer private-test-token" {
			t.Fatal("private readback credential absent")
		}
		state := map[string]any{"version": 2, "podUID": uid, "sourceSHA256": r.Rule.SourceSHA256, "policyConfigMapUID": r.ConfigMapUID,
			"objectiveId": r.Rule.ObjectiveID, "runNonce": r.Rule.RunNonce, "ruleSHA256": r.RuleSHA256, "protectedSHA256": r.Rule.ProtectedSHA256,
			"contextSecretUID": r.Rule.ContextSecretUID, "contextSeedSHA256": r.Rule.ContextSeedSHA256, "active": true, "revision": want.Revision,
			"operationId": r.OperationID, "ready": true, "counters": map[string]any{"providerCompletions": 0, "redactions": 0}}
		b, _ := json.Marshal(state)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	})
	ec := EnactCtx{LiteLLMStatusTransport: transport, LiteLLMStatusToken: "private-test-token"}
	if err := liteOutputReadbackOnce(context.Background(), ec, live, r, want); err != nil {
		t.Fatalf("two exact states rejected: %v", err)
	}
	wrongSecond = true
	if err := liteOutputReadbackOnce(context.Background(), ec, live, r, want); err == nil {
		t.Fatal("stale second Pod readback accepted")
	}
}

func TestLiteOutputFixedJournalPreservesHistoryAndFencesPrepared(t *testing.T) {
	r, desired := liteOutputTestReceipt(t)
	bootstrap := liteOutputJournalDocument{Version: 2, Receipts: []liteOutputReceipt{}}
	if string(bootstrap.bytes()) != `{"receipts":[],"version":2}` {
		t.Fatalf("unexpected fixed journal bootstrap: %s", bootstrap.bytes())
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: outputpolicy.LiteJournalName, Namespace: "phorvex-system",
		UID: types.UID("protected-journal-uid"), ResourceVersion: "1", Labels: map[string]string{outputpolicy.LiteJournalLabel: "v2"}},
		Data: map[string]string{outputpolicy.LiteJournalKey: string(bootstrap.bytes())}}
	policyCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: outputpolicy.LitePolicyConfigMap, Namespace: outputpolicy.LiteNamespace},
		Data: map[string]string{outputpolicy.LitePolicyKey: r.Prior}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(cm, policyCM).Build()
	ec := EnactCtx{Reader: c, Client: c, JournalNamespace: "phorvex-system"}
	journal, err := liteOutputCreateJournal(context.Background(), ec, r)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := pendingLiteOutputOperations(context.Background(), c, ec.JournalNamespace, r.TargetUID); err != nil || !pending {
		t.Fatalf("prepared row did not fence successor: pending=%t err=%v", pending, err)
	}
	if _, err := liteOutputCreateJournal(context.Background(), ec, r); err == nil {
		t.Fatal("competing append replaced prepared operation")
	}
	after := r
	after.Phase = "terminal-full"
	replaced := journal.DeepCopy()
	replaced.UID = types.UID("replacement-journal-uid")
	if err := liteOutputAdvanceJournal(context.Background(), ec, replaced, r, after); err == nil {
		t.Fatal("replacement protected journal identity accepted")
	}
	if err := liteOutputAdvanceJournal(context.Background(), ec, journal, r, after); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: outputpolicy.LitePolicyConfigMap}, policyCM); err != nil {
		t.Fatal(err)
	}
	policyCM.Data[outputpolicy.LitePolicyKey] = after.Desired
	if err := c.Update(context.Background(), policyCM); err != nil {
		t.Fatal(err)
	}
	_, doc, err := liteOutputReadJournalDocument(context.Background(), ec)
	if err != nil || len(doc.Receipts) != 1 || doc.Receipts[0].Phase != "terminal-full" || !liteOutputJournalMatchesState(doc, desired) {
		t.Fatalf("terminal row/history inconsistent: %v", err)
	}
	if pending, err := pendingLiteOutputOperations(context.Background(), c, ec.JournalNamespace, r.TargetUID); err != nil || pending {
		t.Fatalf("terminal row still pending: pending=%t err=%v", pending, err)
	}
	if recovered, err := recoverLiteOutputOperations(context.Background(), ec, nil); err != nil || len(recovered) != 0 {
		t.Fatalf("historical terminal row re-credited as a recovery effect: rows=%d err=%v", len(recovered), err)
	}
	mutated := desired
	mutated.Entries = append([]outputpolicy.LiteEntry(nil), desired.Entries...)
	mutated.Entries[0].ContextSecretUID = "unrelated-private-source"
	if liteOutputJournalMatchesState(doc, mutated) {
		t.Fatal("changed historical context source matched protected journal")
	}
}

func TestLiteOutputRecoveryOptInJournalBoundary(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).Build()
	ec := EnactCtx{Reader: c, Client: c, JournalNamespace: "phorvex-system"}
	if pending, err := pendingLiteOutputOperations(ctx, c, ec.JournalNamespace, "current-lite-pod-uid"); err != nil || pending {
		t.Fatalf("absent optional v2 fixture fenced existing LiteLLM action: pending=%t err=%v", pending, err)
	}
	if events, err := recoverLiteOutputOperations(ctx, ec, nil); err != nil || len(events) != 0 {
		t.Fatalf("absent optional v2 fixture interrupted existing recovery: events=%d err=%v", len(events), err)
	}
	policy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: outputpolicy.LiteNamespace, Name: outputpolicy.LitePolicyConfigMap}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverLiteOutputOperations(ctx, ec, nil); err == nil {
		t.Fatal("installed v2 policy with missing protected journal accepted")
	}
	if _, err := pendingLiteOutputOperations(ctx, c, ec.JournalNamespace, "current-lite-pod-uid"); err == nil {
		t.Fatal("installed v2 policy with missing protected journal did not fence dispatch")
	}
}
