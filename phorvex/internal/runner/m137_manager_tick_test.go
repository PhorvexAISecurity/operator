package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func m137Histogram(t *testing.T, name string, labels map[string]string) (uint64, float64) {
	t.Helper()
	count, sum, err := m137HistogramValue(name, labels)
	if err != nil {
		t.Fatal(err)
	}
	return count, sum
}

func m137HistogramValue(name string, labels map[string]string) (uint64, float64, error) {
	families, err := crmetrics.Registry.Gather()
	if err != nil {
		return 0, 0, err
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			matched := true
			for key, value := range labels {
				found := false
				for _, pair := range metric.Label {
					if pair.GetName() == key && pair.GetValue() == value {
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
			}
			if matched && metric.Histogram != nil {
				return metric.Histogram.GetSampleCount(), metric.Histogram.GetSampleSum(), nil
			}
		}
	}
	return 0, 0, nil
}

type m137ListClient struct {
	client.Client
	once  sync.Once
	delay time.Duration
	err   error
}

func (c *m137ListClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.PodList); ok {
		c.once.Do(func() {
			if c.delay > 0 {
				time.Sleep(c.delay)
			}
		})
		if c.err != nil {
			return c.err
		}
	}
	return c.Client.List(ctx, list, opts...)
}

func TestM137ManagerDurationIncludesSharedSnapshotWork(t *testing.T) {
	policy := m128Policy("m137-duration", "policy", "m137-duration-owner")
	m := m128Manager(t, &m128RecordingSource{}, policy)
	const delay = 40 * time.Millisecond
	m.Client = &m137ListClient{Client: m.Client, delay: delay}

	managerLabels := map[string]string{"outcome": "finished-full-snapshot"}
	policyLabels := map[string]string{"tenant": policy.Spec.Tenant}
	managerCountBefore, managerSumBefore := m137Histogram(t, "phorvex_manager_tick_duration_seconds", managerLabels)
	policyCountBefore, policySumBefore := m137Histogram(t, "phorvex_tick_duration_seconds", policyLabels)
	if result := m.tick(context.Background()); result != tickSnapshotSucceeded {
		t.Fatalf("tick result=%v", result)
	}
	managerCountAfter, managerSumAfter := m137Histogram(t, "phorvex_manager_tick_duration_seconds", managerLabels)
	policyCountAfter, policySumAfter := m137Histogram(t, "phorvex_tick_duration_seconds", policyLabels)
	if managerCountAfter-managerCountBefore != 1 || policyCountAfter-policyCountBefore != 1 {
		t.Fatalf("histogram counts manager=%d policy=%d", managerCountAfter-managerCountBefore, policyCountAfter-policyCountBefore)
	}
	managerDuration := managerSumAfter - managerSumBefore
	policyDuration := policySumAfter - policySumBefore
	if managerDuration < delay.Seconds() || managerDuration-policyDuration < delay.Seconds()/2 {
		t.Fatalf("full manager duration=%v policy duration=%v, shared delay=%v was not included only in full tick", managerDuration, policyDuration, delay)
	}
}

func TestM137ManagerDurationClosedOutcomes(t *testing.T) {
	t.Run("no-snapshot", func(t *testing.T) {
		m := m128Manager(t, &m128RecordingSource{})
		before, _ := m137Histogram(t, "phorvex_manager_tick_duration_seconds", map[string]string{"outcome": "no-snapshot"})
		if result := m.tick(context.Background()); result != tickNoSnapshot {
			t.Fatalf("tick result=%v", result)
		}
		after, _ := m137Histogram(t, "phorvex_manager_tick_duration_seconds", map[string]string{"outcome": "no-snapshot"})
		if after-before != 1 {
			t.Fatalf("no-snapshot observations=%d", after-before)
		}
	})

	t.Run("snapshot-failed", func(t *testing.T) {
		policy := m128Policy("m137-failed", "policy", "m137-failed-owner")
		m := m128Manager(t, &m128RecordingSource{}, policy)
		m.Client = &m137ListClient{Client: m.Client, err: errors.New("m137 snapshot failure")}
		before, _ := m137Histogram(t, "phorvex_manager_tick_duration_seconds", map[string]string{"outcome": "snapshot-failed"})
		if result := m.tick(context.Background()); result != tickSnapshotFailed {
			t.Fatalf("tick result=%v", result)
		}
		after, _ := m137Histogram(t, "phorvex_manager_tick_duration_seconds", map[string]string{"outcome": "snapshot-failed"})
		if after-before != 1 {
			t.Fatalf("snapshot-failed observations=%d", after-before)
		}
	})

	for _, tc := range []struct {
		name, outcome string
		ctx           func() (context.Context, context.CancelFunc)
	}{
		{name: "deadline", outcome: "deadline", ctx: func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}},
		{name: "canceled", outcome: "canceled", ctx: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			m := m128Manager(t, &m128RecordingSource{})
			before, _ := m137Histogram(t, "phorvex_manager_tick_duration_seconds", map[string]string{"outcome": tc.outcome})
			if result := m.tick(ctx); result != tickInterrupted {
				t.Fatalf("tick result=%v", result)
			}
			after, _ := m137Histogram(t, "phorvex_manager_tick_duration_seconds", map[string]string{"outcome": tc.outcome})
			if after-before != 1 {
				t.Fatalf("%s observations=%d", tc.outcome, after-before)
			}
		})
	}
}

func TestM137ExistentialStatusSkipsUnchangedWriteAndPersistsRecovery(t *testing.T) {
	policy := m140Policy("policy", "m137-status", "m137-status-owner")
	policy.Generation = 7
	policy.Status.Conditions = []metav1.Condition{{
		Type: "ValidationError", Status: metav1.ConditionFalse, Reason: "ControllerOwned",
		Message: "preserve me", ObservedGeneration: 7,
	}}
	m, _ := m140BlockedTickManager(t, nil, policy)
	recorder := record.NewFakeRecorder(4)
	m.Recorder = recorder
	if err := m.Upsert(policy); err != nil {
		t.Fatal(err)
	}
	writes := 0
	failWrites := false
	m.Client = interceptor.NewClient(m.Client.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if subResourceName == "status" {
				writes++
				if failWrites {
					return errors.New("m137 forced status failure")
				}
			}
			return c.SubResource(subResourceName).Update(ctx, obj, opts...)
		},
	})
	e := m.policies["ns/policy"]
	decisions := []model.Decision{{Namespace: "ns", Pod: "protected", Existential: &model.ExistentialDecision{Present: true, Result: "uncontainable"}}}
	m.updateExistentialStatus(context.Background(), e, decisions)
	if writes != 1 {
		t.Fatalf("changed existential status writes=%d", writes)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "ExistentialUncontainable") {
			t.Fatalf("changed warning=%q", event)
		}
	default:
		t.Fatal("successful changed condition emitted no warning")
	}
	m.updateExistentialStatus(context.Background(), e, decisions)
	if writes != 1 {
		t.Fatalf("unchanged existential status wrote again: writes=%d", writes)
	}
	select {
	case event := <-recorder.Events:
		t.Fatalf("unchanged condition emitted warning %q", event)
	default:
	}
	decisions[0].Existential.Result = "selected"
	m.updateExistentialStatus(context.Background(), e, decisions)
	if writes != 2 {
		t.Fatalf("changed recovery writes=%d", writes)
	}
	select {
	case event := <-recorder.Events:
		t.Fatalf("recovery emitted warning %q", event)
	default:
	}
	decisions[0].Existential.Result = "uncontainable"
	failWrites = true
	m.updateExistentialStatus(context.Background(), e, decisions)
	if writes != 3 {
		t.Fatalf("failed changed status attempts=%d", writes)
	}
	select {
	case event := <-recorder.Events:
		t.Fatalf("failed status write emitted warning %q", event)
	default:
	}
	var current v1alpha1.PhorvexPolicy
	if err := m.Client.Get(context.Background(), e.key, &current); err != nil {
		t.Fatal(err)
	}
	validation := findStatusCondition(current.Status.Conditions, "ValidationError")
	existential := findStatusCondition(current.Status.Conditions, "ExistentialUncontainable")
	if validation == nil || validation.Message != "preserve me" || validation.ObservedGeneration != policy.Generation {
		t.Fatalf("controller-owned condition changed: %+v", validation)
	}
	if existential == nil || existential.Status != metav1.ConditionFalse || existential.ObservedGeneration != policy.Generation {
		t.Fatalf("recovery condition=%+v", existential)
	}
}

func findStatusCondition(conditions []metav1.Condition, kind string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == kind {
			return &conditions[i]
		}
	}
	return nil
}
