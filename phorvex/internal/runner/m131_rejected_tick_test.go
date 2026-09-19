package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/ingest"
	metricspkg "github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type m131Recon struct{ collision bool }

func (m131Recon) Name() string { return "m131-actual-recon" }

func (r m131Recon) AssetFacts(v *model.WorkloadView, _ recon.FactContext) recon.AssetFacts {
	key := v.Pod.Namespace + "/" + v.Pod.Name + "|podIdentity"
	if r.collision {
		key = "shared-block|podIdentity"
	}
	return recon.AssetFacts{CoverByAction: map[model.Action][]string{model.ActionRotate: {key}}}
}

func m131Snapshot(now time.Time) *ingest.Snapshot {
	pods := []model.Pod{
		{Namespace: "ns", Name: "a", UID: "uid-a", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3},
		{Namespace: "ns", Name: "b", UID: "uid-b", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3},
	}
	snap := &ingest.Snapshot{
		Now: now, Pods: pods, PodByKey: map[string]*model.Pod{}, Graph: graph.Build(graph.Input{}),
		PodInventoryComplete: true, PolicyInventoryComplete: true, EventInventoryComplete: true,
	}
	for i := range snap.Pods {
		snap.PodByKey[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name] = &snap.Pods[i]
	}
	return snap
}

func m131Condition(t *testing.T, p *v1alpha1.PhorvexPolicy, conditionType string) *metav1.Condition {
	t.Helper()
	condition := meta.FindStatusCondition(p.Status.Conditions, conditionType)
	if condition == nil {
		t.Fatalf("condition %q missing from %+v", conditionType, p.Status.Conditions)
	}
	return condition
}

func m131HistogramCount(t *testing.T, name string, labels map[string]string) uint64 {
	t.Helper()
	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, sample := range family.Metric {
			matched := true
			for wantName, wantValue := range labels {
				found := false
				for _, pair := range sample.Label {
					if pair.GetName() == wantName && pair.GetValue() == wantValue {
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
			}
			if matched && sample.Histogram != nil {
				return sample.Histogram.GetSampleCount()
			}
		}
	}
	return 0
}

func TestM131CheckedReasonClassificationIsStructuralAndBounded(t *testing.T) {
	collision := actionset.CrossBlockCollision{Key: "secret-dynamic-key", ExistingBlock: "a", ConflictingBlock: "b"}
	for _, tc := range []struct {
		name    string
		err     error
		reason  metricspkg.TickRejectionReason
		current bool
	}{
		{name: "collision-value", err: fmt.Errorf("wrapped: %w", collision), reason: metricspkg.RejectCrossBlockCollision, current: true},
		{name: "collision-pointer", err: &collision, reason: metricspkg.RejectCrossBlockCollision, current: true},
		{name: "generic", err: errors.New("credential-shaped unbounded detail"), reason: metricspkg.RejectDecisionContractError, current: true},
		{name: "owner-retired", err: fmt.Errorf("wrapped: %w", decision.ErrOwnerRetired), current: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, current := checkedSelectionRejectionReason(tc.err)
			if reason != tc.reason || current != tc.current {
				t.Fatalf("classification = (%q,%v), want (%q,%v)", reason, current, tc.reason, tc.current)
			}
			if strings.Contains(string(reason), "secret") || strings.Contains(string(reason), "credential") {
				t.Fatalf("unbounded error detail escaped into reason %q", reason)
			}
		})
	}
}

func TestM131ActualCollisionPublishesRejectedTickAndRecovers(t *testing.T) {
	ctx := context.Background()
	tenant := "m131-collision-recovery"
	p := m140Policy("policy", tenant, "m131-owner")
	p.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRotate)}
	p.Spec.Mode = "active"
	oldTick := time.Unix(1_700_000_000, 0).UTC()
	lastDecision := metav1.NewTime(oldTick.Add(-time.Hour))
	p.Status = v1alpha1.PhorvexPolicyStatus{
		SelectedPods: 99, LastTickTime: metav1.NewTime(oldTick), LastDecisionTime: lastDecision,
		DecisionsTotal: 7,
		Conditions: []metav1.Condition{
			{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ticking"},
			{Type: "ValidationError", Status: metav1.ConditionTrue, Reason: "ControllerOwned", Message: "preserve me"},
		},
	}
	m, engine := m140BlockedTickManager(t, nil, p)
	hands := &fakeActuator{}
	m.Actuator = hands
	m.Calibration = nil
	var auditLines []string
	var auditJSON bytes.Buffer
	m.Audit = audit.New(funcr.New(func(prefix, args string) {
		auditLines = append(auditLines, prefix+" "+args)
	}, funcr.Options{}), &auditJSON)
	engine.Recon = m131Recon{collision: true}
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	entry := m.policies[client.ObjectKeyFromObject(p).String()]
	now := oldTick.Add(2 * time.Hour)
	m.emissionWindow(entry, 2, now.Add(-time.Minute))
	snap := m131Snapshot(now)

	metric := func(name string, labels map[string]string) float64 { return metricValue(t, name, labels) }
	tickLabels := map[string]string{"tenant": tenant, "policy": p.Name}
	rejectedLabels := map[string]string{"tenant": tenant, "policy": p.Name, "outcome": string(metricspkg.TickSelectionRejected)}
	completedLabels := map[string]string{"tenant": tenant, "policy": p.Name, "outcome": string(metricspkg.TickCompleted)}
	reasonLabels := map[string]string{"tenant": tenant, "reason": string(metricspkg.RejectCrossBlockCollision)}
	beforeTicks := metric("phorvex_ticks_total", tickLabels)
	beforeRejected := metric("phorvex_tick_outcomes_total", rejectedLabels)
	beforeCompleted := metric("phorvex_tick_outcomes_total", completedLabels)
	beforeReason := metric("phorvex_action_set_rejections_total", reasonLabels)
	beforeDurations := m131HistogramCount(t, "phorvex_tick_duration_seconds", map[string]string{"tenant": tenant})
	beforeDecisions := metric("phorvex_decisions_total", map[string]string{"tenant": tenant})
	beforeAttempts := metric("phorvex_actuation_attempts_total", map[string]string{"tenant": tenant})
	beforeFailures := metric("phorvex_actuation_failures_total", map[string]string{"tenant": tenant})
	beforeSuppressions := metric("phorvex_actuation_suppressions_total", map[string]string{"tenant": tenant})

	m.processTenant(ctx, snap, entry, false)
	if hands.calls != 0 {
		t.Fatalf("rejected selection reached actuator: calls=%d", hands.calls)
	}
	if metric("phorvex_ticks_total", tickLabels) != beforeTicks+1 ||
		metric("phorvex_tick_outcomes_total", rejectedLabels) != beforeRejected+1 ||
		metric("phorvex_tick_outcomes_total", completedLabels) != beforeCompleted ||
		metric("phorvex_action_set_rejections_total", reasonLabels) != beforeReason+1 {
		t.Fatal("rejected tick did not publish exactly one denominator, outcome, and structural reason")
	}
	if m131HistogramCount(t, "phorvex_tick_duration_seconds", map[string]string{"tenant": tenant}) != beforeDurations+1 {
		t.Fatal("rejected tick did not publish exactly one duration observation")
	}
	if metric("phorvex_protected_pods", map[string]string{"tenant": tenant}) != 2 {
		t.Fatal("rejected tick did not publish its two protected inputs")
	}
	if metric("phorvex_decisions_total", map[string]string{"tenant": tenant}) != beforeDecisions ||
		metric("phorvex_actuation_attempts_total", map[string]string{"tenant": tenant}) != beforeAttempts ||
		metric("phorvex_actuation_failures_total", map[string]string{"tenant": tenant}) != beforeFailures ||
		metric("phorvex_actuation_suppressions_total", map[string]string{"tenant": tenant}) != beforeSuppressions {
		t.Fatal("rejected tick fabricated decision or actuation accounting")
	}

	var rejectedStatus v1alpha1.PhorvexPolicy
	if err := m.Client.Get(ctx, client.ObjectKeyFromObject(p), &rejectedStatus); err != nil {
		t.Fatal(err)
	}
	ready := m131Condition(t, &rejectedStatus, "Ready")
	if ready.Status != metav1.ConditionFalse || ready.Reason != "ActionSetRejected" ||
		!strings.Contains(ready.Message, string(metricspkg.RejectCrossBlockCollision)) {
		t.Fatalf("rejected Ready condition = %+v", ready)
	}
	prepared := m131Condition(t, &rejectedStatus, "ActuationPrepared")
	if prepared.Status != metav1.ConditionUnknown || prepared.Reason != "NotAttempted" {
		t.Fatalf("rejected preparation condition = %+v", prepared)
	}
	validation := m131Condition(t, &rejectedStatus, "ValidationError")
	if validation.Reason != "ControllerOwned" || validation.Message != "preserve me" {
		t.Fatalf("controller-owned validation condition changed: %+v", validation)
	}
	for _, conditionType := range []string{"DryRun", ConditionActionsSupported, ConditionTelemetryDegraded, "KillSwitch", "EmissionHistory"} {
		m131Condition(t, &rejectedStatus, conditionType)
	}
	if rejectedStatus.Tenant != tenant || rejectedStatus.ObservedGeneration != p.Generation || rejectedStatus.KillSwitchEngaged {
		t.Fatalf("policy identity/generation/kill observation not preserved: %+v", rejectedStatus.Status)
	}
	if rejectedStatus.SelectedPods != 2 || !rejectedStatus.LastTickTime.Time.After(oldTick) ||
		rejectedStatus.DecisionsTotal != 7 || !rejectedStatus.LastDecisionTime.Equal(&lastDecision) {
		t.Fatalf("rejected status lost current inputs or prior decision history: %+v", rejectedStatus.Status)
	}
	if rejectedStatus.MovesThisWindow != 2 || !rejectedStatus.Actuated {
		t.Fatalf("rolling emission history was erased: moves=%d actuated=%v", rejectedStatus.MovesThisWindow, rejectedStatus.Actuated)
	}
	joinedAudit := strings.Join(auditLines, "\n")
	if !strings.Contains(joinedAudit, "outcome") || !strings.Contains(joinedAudit, "selection-rejected") ||
		!strings.Contains(joinedAudit, "reason") || !strings.Contains(joinedAudit, "cross-block-collision") ||
		!strings.Contains(joinedAudit, p.Name) || !strings.Contains(joinedAudit, string(p.UID)) {
		t.Fatalf("bounded rejected audit summary missing:\n%s", joinedAudit)
	}
	if strings.Contains(auditJSON.String(), `"decisionTrace"`) {
		t.Fatalf("rejected tick fabricated a decision trace:\n%s", auditJSON.String())
	}

	// The same actual producer becomes structurally valid on the next tick. It
	// must pass through the completed boundary and restore operational readiness.
	engine.Recon = m131Recon{collision: false}
	snap.Now = now.Add(time.Minute)
	m.processTenant(ctx, snap, entry, false)
	var recovered v1alpha1.PhorvexPolicy
	if err := m.Client.Get(ctx, client.ObjectKeyFromObject(p), &recovered); err != nil {
		t.Fatal(err)
	}
	ready = m131Condition(t, &recovered, "Ready")
	if ready.Status != metav1.ConditionTrue || ready.Reason != "Ticking" {
		t.Fatalf("valid successor tick did not recover readiness: %+v", ready)
	}
	if metric("phorvex_ticks_total", tickLabels) != beforeTicks+2 ||
		metric("phorvex_tick_outcomes_total", rejectedLabels) != beforeRejected+1 ||
		metric("phorvex_tick_outcomes_total", completedLabels) != beforeCompleted+1 ||
		metric("phorvex_action_set_rejections_total", reasonLabels) != beforeReason+1 {
		t.Fatal("recovery tick duplicated rejection or missed completed accounting")
	}
	if m131HistogramCount(t, "phorvex_tick_duration_seconds", map[string]string{"tenant": tenant}) != beforeDurations+2 {
		t.Fatal("recovery did not leave one duration observation per tick outcome")
	}
	completedAudit := false
	for _, line := range auditLines {
		if strings.Contains(line, "completed") && strings.Contains(line, p.Name) && strings.Contains(line, string(p.UID)) {
			completedAudit = true
			break
		}
	}
	if !completedAudit {
		t.Fatalf("completed recovery audit missing exact policy identity:\n%s", strings.Join(auditLines, "\n"))
	}
}

func TestM131RejectedAuditDistinguishesSiblingPolicies(t *testing.T) {
	tenant := "m131-shared-display"
	first := m140Policy("first", tenant, "m131-first-uid")
	second := m140Policy("second", tenant, "m131-second-uid")
	for _, policy := range []*v1alpha1.PhorvexPolicy{first, second} {
		policy.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRotate)}
	}
	m, engine := m140BlockedTickManager(t, nil, first, second)
	m.Calibration = nil
	engine.Recon = m131Recon{collision: true}
	var lines []string
	m.Audit = audit.New(funcr.New(func(prefix, args string) {
		lines = append(lines, prefix+" "+args)
	}, funcr.Options{}), nil)
	for _, policy := range []*v1alpha1.PhorvexPolicy{first, second} {
		if err := m.Upsert(policy); err != nil {
			t.Fatal(err)
		}
		m.processTenant(context.Background(), m131Snapshot(time.Unix(1_700_000_100, 0)),
			m.policies[client.ObjectKeyFromObject(policy).String()], false)
	}

	for _, policy := range []*v1alpha1.PhorvexPolicy{first, second} {
		found := false
		for _, line := range lines {
			if strings.Contains(line, "selection-rejected") && strings.Contains(line, policy.Name) && strings.Contains(line, string(policy.UID)) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("shared-tenant rejected audit missing exact identity for %s/%s uid=%s:\n%s",
				policy.Namespace, policy.Name, policy.UID, strings.Join(lines, "\n"))
		}
	}
}

type m131ErrorOptimizer struct{ err error }

func (m131ErrorOptimizer) Name() string { return "m131-error" }
func (m131ErrorOptimizer) Decide([]*model.WorkloadView, model.Policy) []model.Decision {
	panic("unchecked decision path called")
}
func (o m131ErrorOptimizer) DecideChecked([]*model.WorkloadView, model.Policy) ([]model.Decision, error) {
	return nil, o.err
}

type m131ReplacingOptimizer struct {
	m           *Manager
	replacement *v1alpha1.PhorvexPolicy
}

func (m131ReplacingOptimizer) Name() string { return "m131-replacing" }
func (m131ReplacingOptimizer) Decide([]*model.WorkloadView, model.Policy) []model.Decision {
	panic("unchecked decision path called")
}
func (o m131ReplacingOptimizer) DecideChecked([]*model.WorkloadView, model.Policy) ([]model.Decision, error) {
	if err := o.m.Upsert(o.replacement); err != nil {
		return nil, err
	}
	return nil, actionset.CrossBlockCollision{Key: "shared", ExistingBlock: "a", ConflictingBlock: "b"}
}

func TestM131ReplacementDuringSelectionCannotPublishPredecessorMetrics(t *testing.T) {
	old := m140Policy("policy", "m131-replaced-mid-selection", "old-uid")
	replacement := m140Policy("policy", old.Spec.Tenant, "new-uid")
	m, _ := m140BlockedTickManager(t, nil, old)
	m.Calibration = nil
	if err := m.Upsert(old); err != nil {
		t.Fatal(err)
	}
	stale := m.policies[client.ObjectKeyFromObject(old).String()]
	m.Optimizer = m131ReplacingOptimizer{m: m, replacement: replacement}
	tickLabels := map[string]string{"tenant": old.Spec.Tenant, "policy": old.Name}
	reasonLabels := map[string]string{"tenant": old.Spec.Tenant, "reason": string(metricspkg.RejectCrossBlockCollision)}
	beforeTicks := metricValue(t, "phorvex_ticks_total", tickLabels)
	beforeRejections := metricValue(t, "phorvex_action_set_rejections_total", reasonLabels)
	m.processTenant(context.Background(), m131Snapshot(time.Unix(1_700_000_100, 0)), stale, false)
	if metricValue(t, "phorvex_ticks_total", tickLabels) != beforeTicks ||
		metricValue(t, "phorvex_action_set_rejections_total", reasonLabels) != beforeRejections {
		t.Fatal("predecessor rejection was attributed after its owner epoch changed")
	}
	if current := m.policies[client.ObjectKeyFromObject(old).String()]; current == nil || current.uid != string(replacement.UID) {
		t.Fatalf("replacement control did not change current owner: %+v", current)
	}
}

func TestM131GenericCheckedErrorPublishesBoundedReason(t *testing.T) {
	p := m140Policy("generic", "m131-generic", "m131-generic-owner")
	m, _ := m140BlockedTickManager(t, nil, p)
	m.Optimizer = m131ErrorOptimizer{err: errors.New("sensitive arbitrary optimizer detail")}
	m.Calibration = nil
	var auditLines []string
	m.Audit = audit.New(funcr.New(func(_, args string) { auditLines = append(auditLines, args) }, funcr.Options{}), nil)
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	reasonLabels := map[string]string{"tenant": p.Spec.Tenant, "reason": string(metricspkg.RejectDecisionContractError)}
	before := metricValue(t, "phorvex_action_set_rejections_total", reasonLabels)
	m.processTenant(context.Background(), m131Snapshot(time.Unix(1_700_000_100, 0)),
		m.policies[client.ObjectKeyFromObject(p).String()], false)
	if metricValue(t, "phorvex_action_set_rejections_total", reasonLabels) != before+1 {
		t.Fatal("generic checked error did not use the bounded rejection reason")
	}
	var got v1alpha1.PhorvexPolicy
	if err := m.Client.Get(context.Background(), client.ObjectKeyFromObject(p), &got); err != nil {
		t.Fatal(err)
	}
	ready := m131Condition(t, &got, "Ready")
	if ready.Reason != "ActionSetRejected" || !strings.Contains(ready.Message, string(metricspkg.RejectDecisionContractError)) ||
		strings.Contains(ready.Message, "sensitive") {
		t.Fatalf("generic rejection status was unbounded: %+v", ready)
	}
	joined := strings.Join(auditLines, "\n")
	if !strings.Contains(joined, string(metricspkg.RejectDecisionContractError)) || strings.Contains(joined, "sensitive") {
		t.Fatalf("generic rejection audit was unbounded:\n%s", joined)
	}
}

func TestM131RetiredOwnerIsLifecycleSkip(t *testing.T) {
	p := m140Policy("retired", "m131-retired", "m131-retired-owner")
	p.Status.SelectedPods = 41
	p.Status.LastTickTime = metav1.NewTime(time.Unix(1_700_000_000, 0))
	m, _ := m140BlockedTickManager(t, nil, p)
	m.Optimizer = m131ErrorOptimizer{err: decision.ErrOwnerRetired}
	m.Calibration = nil
	m.Audit = audit.New(funcr.New(func(_, _ string) {}, funcr.Options{}), nil)
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	entry := m.policies[client.ObjectKeyFromObject(p).String()]
	labels := map[string]string{"tenant": p.Spec.Tenant, "policy": p.Name}
	before := metricValue(t, "phorvex_ticks_total", labels)
	m.processTenant(context.Background(), m131Snapshot(time.Unix(1_700_000_100, 0)), entry, false)
	if metricValue(t, "phorvex_ticks_total", labels) != before {
		t.Fatal("retired owner was counted as a current rejected tick")
	}
	var got v1alpha1.PhorvexPolicy
	if err := m.Client.Get(context.Background(), client.ObjectKeyFromObject(p), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.SelectedPods != 41 || !got.Status.LastTickTime.Equal(&p.Status.LastTickTime) {
		t.Fatalf("retired owner changed operational status: %+v", got.Status)
	}
}

func TestM131ReplacementUIDRejectsOperationalAndExistentialStatusWrites(t *testing.T) {
	ctx := context.Background()
	replacement := m140Policy("policy", "m131-replacement", "replacement-uid")
	replacement.Status.SelectedPods = 17
	replacement.Status.DecisionsTotal = 23
	replacement.Status.Conditions = []metav1.Condition{{
		Type: "ValidationError", Status: metav1.ConditionTrue, Reason: "ReplacementOwned", Message: "untouched",
	}}
	m, _ := m140BlockedTickManager(t, nil, replacement)
	if err := m.Upsert(replacement); err != nil {
		t.Fatal(err)
	}
	stale := &policyEntry{
		key: client.ObjectKeyFromObject(replacement), uid: "predecessor-uid", tenant: "old-tenant",
		namespace: replacement.Namespace, spec: replacement.Spec, generation: replacement.Generation,
	}
	m.updateExistentialStatus(ctx, stale, []model.Decision{{
		Namespace: replacement.Namespace, Pod: "old-pod",
		Existential: &model.ExistentialDecision{Present: true, Result: "uncontainable"},
	}})
	m.updateRejectedStatusObserved(ctx, stale, 2, legacyKillSwitchObservation(false), time.Now(),
		metricspkg.RejectCrossBlockCollision)

	var got v1alpha1.PhorvexPolicy
	if err := m.Client.Get(ctx, client.ObjectKeyFromObject(replacement), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.SelectedPods != 17 || got.Status.DecisionsTotal != 23 || len(got.Status.Conditions) != 1 {
		t.Fatalf("predecessor wrote status onto replacement UID: %+v", got.Status)
	}
	condition := m131Condition(t, &got, "ValidationError")
	if condition.Reason != "ReplacementOwned" || condition.Message != "untouched" {
		t.Fatalf("replacement-owned status changed: %+v", condition)
	}
}
