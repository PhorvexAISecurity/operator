package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type recoveryReader struct {
	client.Reader
	failHold bool
}

type pagedRecoveryReader struct {
	client.Reader
	pages  map[string]corev1.ConfigMapList
	calls  int
	limits []int64
}

func (r *pagedRecoveryReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	lo := &client.ListOptions{}
	for _, opt := range opts {
		opt.ApplyToList(lo)
	}
	r.calls++
	r.limits = append(r.limits, lo.Limit)
	page, ok := r.pages[lo.Continue]
	if !ok {
		return errors.New("unexpected continuation token")
	}
	got, ok := list.(*corev1.ConfigMapList)
	if !ok {
		return errors.New("unexpected list type")
	}
	*got = *page.DeepCopy()
	return nil
}

func (r recoveryReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if r.failHold && key.Namespace == "operator" && key.Name == RecoveryHoldName {
		return errors.New("hold read denied")
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func recoveryFixture(t *testing.T, names ...string) (*NativeActuator, client.Client) {
	t.Helper()
	pods := make([]client.Object, 0, len(names))
	for _, name := range names {
		pods = append(pods, aiPod("ns", name, map[string]string{"app": "victim"}))
	}
	c := qtnClient(pods...)
	ctx := context.Background()
	for _, name := range names {
		enactQuarantine(t, c, "ns", name)
	}
	for _, obj := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: metav1.NamespaceSystem, UID: "cluster-uid", ResourceVersion: "1"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: RecoveryHoldName, UID: "hold-uid", ResourceVersion: "1"}, Data: map[string]string{"engaged": "true"}},
	} {
		if err := c.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	n := NewNativeActuator(c)
	n.Reader, n.JournalNamespace = c, "operator"
	return n, c
}

func recoveryScope(max int) RecoveryScope {
	return RecoveryScope{OperatorNamespace: "operator", Namespace: "ns", PolicyName: "policy", MaxItems: max}
}

func TestAdministrativeRecoveryProducerInventoryPlanApply(t *testing.T) {
	ctx := context.Background()
	n, c := recoveryFixture(t, "b", "a")
	before := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "a"}, before); err != nil {
		t.Fatal(err)
	}
	inv, err := n.InventoryRecovery(ctx, recoveryScope(2))
	if err != nil || len(inv.Items) != 2 || inv.Items[0].Receipt.Name >= inv.Items[1].Receipt.Name || inv.Items[0].Status != "ready" || inv.Items[1].Status != "ready" {
		t.Fatalf("inventory=%+v err=%v", inv, err)
	}
	after := &corev1.Pod{}
	_ = c.Get(ctx, client.ObjectKeyFromObject(before), after)
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatal("read-only inventory wrote the Pod")
	}
	plan, err := n.PlanRecovery(ctx, recoveryScope(2))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 2 || plan.SHA256 == "" {
		t.Fatalf("plan=%+v", plan)
	}
	result, err := n.ApplyRecovery(ctx, plan)
	if err != nil || !result.Complete || len(result.Items) != 2 || result.Items[0].Outcome != "restored" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, name := range []string{"a", "b"} {
		pod := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, pod); err != nil {
			t.Fatal(err)
		}
		if pod.Labels[quarantineLabel] != "" || pod.Annotations[quarantineSnapAnno] != "" {
			t.Fatalf("%s not restored", name)
		}
		var receipt ObjectBinding
		for _, item := range plan.Items {
			if item.Pod.Name == name {
				receipt = item.Receipt
			}
		}
		cm := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: receipt.Namespace, Name: receipt.Name}, cm); !apierrors.IsNotFound(err) {
			t.Fatalf("receipt retained for %s: %v", name, err)
		}
	}
}

func TestAdministrativeRecoveryHoldReadFailureIsNotEngaged(t *testing.T) {
	n, c := recoveryFixture(t, "victim")
	plan, err := n.PlanRecovery(context.Background(), recoveryScope(1))
	if err != nil {
		t.Fatal(err)
	}
	n.Reader = recoveryReader{Reader: c, failHold: true}
	if result, err := n.ApplyRecovery(context.Background(), plan); err == nil || len(result.Items) != 0 {
		t.Fatalf("hold read failure bypass: %+v %v", result, err)
	}
}

func TestAdministrativeRecoveryDryRunAndIdentityControls(t *testing.T) {
	for _, mutate := range []string{"dry-run", "cluster", "operator", "policy", "pod-uid", "network-policy"} {
		t.Run(mutate, func(t *testing.T) {
			n, c := recoveryFixture(t, "victim")
			ctx := context.Background()
			plan, err := n.PlanRecovery(ctx, recoveryScope(1))
			if err != nil {
				t.Fatal(err)
			}
			switch mutate {
			case "dry-run":
				n.DryRun = true
			case "cluster":
				plan.Cluster.UID = "other"
				plan.SHA256 = recoveryPlanHash(plan)
			case "operator":
				plan.Operator.UID = "other"
				plan.SHA256 = recoveryPlanHash(plan)
			case "policy":
				plan.Items[0].Policy.UID = "other"
				plan.SHA256 = recoveryPlanHash(plan)
			case "pod-uid":
				plan.Items[0].Pod.UID = "new-incarnation"
				plan.SHA256 = recoveryPlanHash(plan)
			case "network-policy":
				plan.Items[0].NetworkPolicy.UID = "other"
				plan.SHA256 = recoveryPlanHash(plan)
			}
			result, err := n.ApplyRecovery(ctx, plan)
			if err == nil || result.Complete {
				t.Fatalf("%s accepted: %+v", mutate, result)
			}
			pod := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "victim"}, pod)
			if pod.Labels[quarantineLabel] == "" {
				t.Fatalf("%s refusal wrote Pod", mutate)
			}
		})
	}
}

func TestAdministrativeRecoveryInventoriesUnsafeActionsWithoutUndo(t *testing.T) {
	n, c := recoveryFixture(t, "victim")
	r := operationReceipt{Version: 1, Kind: "warm-swap", Phase: "prepared", PolicyNamespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TargetName: "old", TargetUID: "old-uid", OldName: "old", OldUID: "old-uid", NewName: "new", NewUID: "new-uid", GroupKey: labelSwapGroup, GroupValue: "group"}
	b, _ := json.Marshal(r)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: receiptName(r), UID: "warm-receipt", ResourceVersion: "1", Labels: map[string]string{journalLabel: "v1"}}, Data: map[string]string{"receipt": string(b)}}
	if err := c.Create(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	inv, err := n.InventoryRecovery(context.Background(), recoveryScope(2))
	if err != nil {
		t.Fatal(err)
	}
	manual := false
	for _, item := range inv.Items {
		if item.Kind == "warm-swap" && item.Status == "manual" && item.SupportedOperation == "" {
			manual = true
		}
	}
	if !manual {
		t.Fatalf("unsafe operation reported as recoverable: %+v", inv.Items)
	}
}

func TestAdministrativeRecoveryReportsPartialBatchAndStops(t *testing.T) {
	n, c := recoveryFixture(t, "one", "two")
	ctx := context.Background()
	plan, err := n.PlanRecovery(ctx, recoveryScope(2))
	if err != nil {
		t.Fatal(err)
	}
	second := &corev1.Pod{}
	if err = c.Get(ctx, client.ObjectKey{Namespace: plan.Items[1].Pod.Namespace, Name: plan.Items[1].Pod.Name}, second); err != nil {
		t.Fatal(err)
	}
	second.Labels["concurrent"] = "edit"
	if err = c.Update(ctx, second); err != nil {
		t.Fatal(err)
	}
	result, err := n.ApplyRecovery(ctx, plan)
	if err == nil || result.Complete || len(result.Items) != 2 || result.Items[0].Outcome != "restored" || result.Items[1].Outcome != "refused" {
		t.Fatalf("partial result=%+v err=%v", result, err)
	}
}

func TestAdministrativeRecoveryHoldMustBeRealAndEngaged(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		remove      bool
	}{
		{"absent", "", true}, {"false", "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, c := recoveryFixture(t, "victim")
			plan, err := n.PlanRecovery(context.Background(), recoveryScope(1))
			if err != nil {
				t.Fatal(err)
			}
			hold := &corev1.ConfigMap{}
			_ = c.Get(context.Background(), client.ObjectKey{Namespace: "operator", Name: RecoveryHoldName}, hold)
			if tc.remove {
				_ = c.Delete(context.Background(), hold)
			} else {
				hold.Data["engaged"] = tc.value
				_ = c.Update(context.Background(), hold)
			}
			if result, err := n.ApplyRecovery(context.Background(), plan); err == nil || len(result.Items) != 0 {
				t.Fatalf("hold bypass: %+v %v", result, err)
			}
			pod := &corev1.Pod{}
			_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "victim"}, pod)
			if pod.Labels[quarantineLabel] == "" {
				t.Fatal("hold refusal wrote Pod")
			}
		})
	}
}

func TestAdministrativeRecoveryRejectsTamperAndStaleBindings(t *testing.T) {
	n, c := recoveryFixture(t, "victim")
	ctx := context.Background()
	plan, err := n.PlanRecovery(ctx, recoveryScope(1))
	if err != nil {
		t.Fatal(err)
	}
	tampered := plan
	tampered.Operation = "forged"
	if _, err = n.ApplyRecovery(ctx, tampered); err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("tampered plan accepted: %v", err)
	}
	cm := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: plan.Items[0].Receipt.Namespace, Name: plan.Items[0].Receipt.Name}
	if err = c.Get(ctx, key, cm); err != nil {
		t.Fatal(err)
	}
	var receipt operationReceipt
	_ = json.Unmarshal([]byte(cm.Data["receipt"]), &receipt)
	receipt.TargetLabels["changed"] = "yes"
	b, _ := json.Marshal(receipt)
	cm.Data["receipt"] = string(b)
	if err = c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if result, err := n.ApplyRecovery(ctx, plan); err == nil || len(result.Items) != 1 || result.Items[0].Outcome != "refused" {
		t.Fatalf("altered receipt accepted: %+v %v", result, err)
	}
}

func TestAdministrativeRecoveryCopiedSnapshotHasNoAuthority(t *testing.T) {
	n, c := recoveryFixture(t, "source")
	source := &corev1.Pod{}
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "source"}, source)
	copyPod := aiPod("ns", "copy", map[string]string{"app": "victim", quarantineLabel: string(source.UID)})
	copyPod.Annotations = map[string]string{quarantineSnapAnno: source.Annotations[quarantineSnapAnno]}
	if err := c.Create(context.Background(), copyPod); err != nil {
		t.Fatal(err)
	}
	inv, err := n.InventoryRecovery(context.Background(), recoveryScope(2))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Items) != 1 || inv.Items[0].TargetName != "source" {
		t.Fatalf("tenant annotation became authority: %+v", inv.Items)
	}
}

func TestAdministrativeRecoveryRejectsWholeInvalidBatchBeforeEffects(t *testing.T) {
	for _, mode := range []string{"duplicate", "tenant-receipt"} {
		t.Run(mode, func(t *testing.T) {
			n, c := recoveryFixture(t, "victim")
			ctx := context.Background()
			plan, err := n.PlanRecovery(ctx, recoveryScope(1))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "duplicate" {
				plan.Scope.MaxItems = 2
				plan.Items = append(plan.Items, plan.Items[0])
				plan.SHA256 = recoveryPlanHash(plan)
			} else {
				real := &corev1.ConfigMap{}
				if err = c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: plan.Items[0].Receipt.Name}, real); err != nil {
					t.Fatal(err)
				}
				copy := real.DeepCopy()
				copy.Namespace, copy.ResourceVersion, copy.UID = "ns", "", ""
				if err = c.Create(ctx, copy); err != nil {
					t.Fatal(err)
				}
				if err = c.Delete(ctx, real); err != nil {
					t.Fatal(err)
				}
				plan.Items[0].Receipt = binding(copy, "v1", "ConfigMap")
				plan.SHA256 = recoveryPlanHash(plan)
			}
			if _, err = n.ApplyRecovery(ctx, plan); err == nil {
				t.Fatalf("%s invalid plan accepted", mode)
			}
			pod := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "victim"}, pod)
			if pod.Labels[quarantineLabel] == "" {
				t.Fatalf("%s invalid batch caused rollback", mode)
			}
		})
	}
}

func TestAdministrativeRecoveryIntentWriteFailurePreventsEffects(t *testing.T) {
	n, c := recoveryFixture(t, "victim")
	ctx := context.Background()
	plan, err := n.PlanRecovery(ctx, recoveryScope(1))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = n.ApplyRecoveryWithRecorder(ctx, plan, func(RecoveryApplyResult) error { calls++; return errors.New("disk full") })
	if err == nil || calls != 1 {
		t.Fatalf("intent failure not surfaced: calls=%d err=%v", calls, err)
	}
	pod := &corev1.Pod{}
	_ = c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "victim"}, pod)
	if pod.Labels[quarantineLabel] == "" {
		t.Fatal("effect occurred without durable intent")
	}
}

func TestAdministrativeRecoveryBoundsMalformedInventoryAndPlanParser(t *testing.T) {
	n, c := recoveryFixture(t, "victim")
	bad := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "bad", UID: "bad-uid", ResourceVersion: "1", Labels: map[string]string{journalLabel: "v1"}}, Data: map[string]string{"receipt": "{"}}
	if err := c.Create(context.Background(), bad); err != nil {
		t.Fatal(err)
	}
	if _, err := n.InventoryRecovery(context.Background(), recoveryScope(1)); err == nil {
		t.Fatal("malformed receipt bypassed collection bound")
	}
	if _, err := RecoveryPlanFromJSON(make([]byte, RecoveryPlanMaxBytes+1)); err == nil {
		t.Fatal("oversized plan accepted")
	}
	if _, err := RecoveryPlanFromJSON([]byte(`{"version":1,"version":1}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate JSON field accepted: %v", err)
	}
}

func unrelatedRecoveryReceipt(name string) *corev1.ConfigMap {
	r := operationReceipt{Version: 1, Kind: "warm-swap", Phase: "prepared", PolicyNamespace: "other", PolicyName: "other-policy", PolicyUID: "other-policy-uid", TargetName: name, TargetUID: "uid-" + name, OldName: name, OldUID: "uid-" + name, NewName: name + "-new", NewUID: "uid-" + name + "-new", GroupKey: labelSwapGroup, GroupValue: "group"}
	b, _ := json.Marshal(r)
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: receiptName(r), UID: types.UID("cm-" + name), ResourceVersion: "1", Labels: map[string]string{journalLabel: "v1"}}, Data: map[string]string{"receipt": string(b)}}
}

func TestAdministrativeRecoveryScopedLimitIgnoresUnrelatedReceipts(t *testing.T) {
	n, c := recoveryFixture(t, "victim")
	for _, name := range []string{"other-a", "other-b", "other-c"} {
		if err := c.Create(context.Background(), unrelatedRecoveryReceipt(name)); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := n.InventoryRecovery(context.Background(), recoveryScope(1))
	if err != nil || len(inv.Items) != 1 || inv.Items[0].TargetName != "victim" {
		t.Fatalf("scoped inventory=%+v err=%v", inv.Items, err)
	}
}

func TestAdministrativeRecoveryPaginatesWithinFixedScanCap(t *testing.T) {
	n, c := recoveryFixture(t, "victim")
	matching := &corev1.ConfigMap{}
	var list corev1.ConfigMapList
	if err := c.List(context.Background(), &list, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil {
		t.Fatal(err)
	}
	for i := range list.Items {
		var r operationReceipt
		if json.Unmarshal([]byte(list.Items[i].Data["receipt"]), &r) == nil && r.TargetName == "victim" {
			matching = list.Items[i].DeepCopy()
		}
	}
	reader := &pagedRecoveryReader{Reader: c, pages: map[string]corev1.ConfigMapList{"": {Items: []corev1.ConfigMap{*unrelatedRecoveryReceipt("other")}, ListMeta: metav1.ListMeta{Continue: "next"}}, "next": {Items: []corev1.ConfigMap{*matching}}}}
	n.Reader = reader
	inv, err := n.InventoryRecovery(context.Background(), recoveryScope(1))
	if err != nil || len(inv.Items) != 1 || reader.calls != 2 || len(reader.limits) != 2 || reader.limits[0] != recoveryJournalPageSize || reader.limits[1] != recoveryJournalPageSize {
		t.Fatalf("pagination calls=%d limits=%v inventory=%+v err=%v", reader.calls, reader.limits, inv.Items, err)
	}
}

func TestAdministrativeRecoveryRejectsScanCapAndScopedOverflow(t *testing.T) {
	t.Run("scan-cap", func(t *testing.T) {
		n, c := recoveryFixture(t, "victim")
		items := make([]corev1.ConfigMap, RecoveryJournalScanMax+1)
		reader := &pagedRecoveryReader{Reader: c, pages: map[string]corev1.ConfigMapList{"": {Items: items}}}
		n.Reader = reader
		if _, err := n.InventoryRecovery(context.Background(), recoveryScope(1)); err == nil || !strings.Contains(err.Error(), "scan cap") {
			t.Fatalf("scan cap not enforced: %v", err)
		}
	})
	t.Run("scoped-overflow", func(t *testing.T) {
		n, _ := recoveryFixture(t, "one", "two")
		if _, err := n.InventoryRecovery(context.Background(), recoveryScope(1)); err == nil || !strings.Contains(err.Error(), "scoped inventory") {
			t.Fatalf("scoped overflow accepted: %v", err)
		}
	})
}
