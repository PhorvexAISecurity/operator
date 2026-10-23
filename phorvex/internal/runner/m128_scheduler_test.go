package runner

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
)

type m128RecordingSource struct {
	mu    sync.Mutex
	calls []string
	hook  func(context.Context, string)
}

func (*m128RecordingSource) Name() string { return "m128-actual-metrics" }

func (s *m128RecordingSource) PodMetrics(ctx context.Context, namespace string, _ []string) (map[string]model.Telemetry, error) {
	s.mu.Lock()
	s.calls = append(s.calls, namespace)
	hook := s.hook
	s.mu.Unlock()
	if hook != nil {
		hook(ctx, namespace)
	}
	return map[string]model.Telemetry{}, ctx.Err()
}

func (s *m128RecordingSource) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *m128RecordingSource) reset() {
	s.mu.Lock()
	s.calls = nil
	s.mu.Unlock()
}

func m128Policy(namespace, name, uid string) *v1alpha1.PhorvexPolicy {
	p := m140Policy(name, "tenant-"+namespace, uid)
	p.Namespace = namespace
	return p
}

func m128Manager(t *testing.T, src *m128RecordingSource, policies ...*v1alpha1.PhorvexPolicy) *Manager {
	t.Helper()
	m, _ := m140BlockedTickManager(t, src, policies...)
	m.Calibration = nil
	localServices(m).Actuator = nil
	for _, policy := range policies {
		if err := m.Upsert(policy); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func m128LastTick(m *Manager, key types.NamespacedName) time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entry := m.policies[key.String()]; entry != nil {
		return entry.lastTick
	}
	return time.Time{}
}

func TestM128ActualProducerCompletionAndCancellationCadence(t *testing.T) {
	t.Run("completed", func(t *testing.T) {
		policy := m128Policy("ns", "policy", "owner-positive")
		source := &m128RecordingSource{}
		m := m128Manager(t, source, policy)
		if result := m.tick(context.Background()); result != tickSnapshotSucceeded {
			t.Fatalf("tick result=%v", result)
		}
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"ns"}) || m128LastTick(m, typesName("ns", "policy")).IsZero() {
			t.Fatalf("completed producer calls=%v cadence=%v", calls, m128LastTick(m, typesName("ns", "policy")))
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		policy := m128Policy("ns", "policy", "owner-cancel")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		source := &m128RecordingSource{hook: func(_ context.Context, _ string) { cancel() }}
		m := m128Manager(t, source, policy)
		if result := m.tick(ctx); result != tickInterrupted {
			t.Fatalf("tick result=%v, want interrupted", result)
		}
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"ns"}) || !m128LastTick(m, typesName("ns", "policy")).IsZero() {
			t.Fatalf("cancelled producer calls=%v cadence=%v", calls, m128LastTick(m, typesName("ns", "policy")))
		}
	})
}

func TestM128ActualTickOrderIsIndependentOfInsertion(t *testing.T) {
	want := []string{"a", "b", "c", "d"}
	for round := 0; round < 24; round++ {
		policies := make([]*v1alpha1.PhorvexPolicy, 0, len(want))
		for i := range want {
			namespace := want[(len(want)-1-i+round)%len(want)]
			policies = append(policies, m128Policy(namespace, "policy", "owner-"+namespace))
		}
		source := &m128RecordingSource{}
		m := m128Manager(t, source, policies...)
		if result := m.tick(context.Background()); result != tickSnapshotSucceeded {
			t.Fatalf("round %d result=%v", round, result)
		}
		if calls := source.snapshot(); !reflect.DeepEqual(calls, want) {
			t.Fatalf("round %d producer order=%v, want=%v", round, calls, want)
		}
	}
}

func TestM128DueClassesDeadlinesAndTieBreakers(t *testing.T) {
	t.Run("established-deadlines", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0)
		policies := []*v1alpha1.PhorvexPolicy{
			m128Policy("a", "policy", "owner-a"),
			m128Policy("b", "policy", "owner-b"),
			m128Policy("c", "policy", "owner-c"),
		}
		for _, p := range policies {
			p.Spec.Budget.TickInterval = metav1.Duration{Duration: 10 * time.Second}
		}
		source := &m128RecordingSource{}
		m := m128Manager(t, source, policies...)
		m.scheduleClock = &manualManagerClock{now: now}
		m.policies["a/policy"].lastTick = now.Add(-12 * time.Second)
		m.policies["b/policy"].lastTick = now.Add(-11 * time.Second)
		m.policies["c/policy"].lastTick = now.Add(-13 * time.Second)
		m.tick(context.Background())
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"c", "a", "b"}) {
			t.Fatalf("deadline order=%v", calls)
		}
	})

	t.Run("never-run-first", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0)
		established := m128Policy("a", "policy", "owner-established")
		established.Spec.Budget.TickInterval = metav1.Duration{Duration: time.Second}
		never := m128Policy("z", "policy", "owner-never")
		never.Spec.Budget.TickInterval = metav1.Duration{Duration: 24 * time.Hour}
		source := &m128RecordingSource{}
		m := m128Manager(t, source, established, never)
		m.scheduleClock = &manualManagerClock{now: now}
		m.policies["a/policy"].lastTick = now.Add(-time.Hour)
		m.tick(context.Background())
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"z", "a"}) {
			t.Fatalf("first-run class order=%v", calls)
		}
	})

	t.Run("bytewise-ties", func(t *testing.T) {
		at := time.Unix(1, 0)
		rows := []duePolicy{
			{dueAt: at, namespace: "b", name: "a", uid: "1"},
			{dueAt: at, namespace: "a", name: "b", uid: "1"},
			{dueAt: at, namespace: "a", name: "a", uid: "2"},
			{dueAt: at, namespace: "a", name: "a", uid: "1"},
		}
		sortDuePolicies(rows)
		got := make([]string, 0, len(rows))
		for _, row := range rows {
			got = append(got, row.namespace+"/"+row.name+"@"+row.uid)
		}
		want := []string{"a/a@1", "a/a@2", "a/b@1", "b/a@1"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("tie order=%v, want=%v", got, want)
		}
	})
}

func TestM128TimeoutStopsLaterRowsAndKeepsCompletedCredit(t *testing.T) {
	policies := []*v1alpha1.PhorvexPolicy{
		m128Policy("a", "policy", "owner-a"),
		m128Policy("b", "policy", "owner-b"),
		m128Policy("c", "policy", "owner-c"),
	}
	source := &m128RecordingSource{hook: func(ctx context.Context, namespace string) {
		if namespace == "b" {
			<-ctx.Done()
		}
	}}
	m := m128Manager(t, source, policies...)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if result := m.tick(ctx); result != tickInterrupted {
		t.Fatalf("tick result=%v, want interrupted", result)
	}
	if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"a", "b"}) {
		t.Fatalf("producer calls=%v", calls)
	}
	if m128LastTick(m, typesName("a", "policy")).IsZero() {
		t.Fatal("completed first row lost cadence")
	}
	for _, namespace := range []string{"b", "c"} {
		if got := m128LastTick(m, typesName(namespace, "policy")); !got.IsZero() {
			t.Fatalf("%s received false cadence %v", namespace, got)
		}
	}
}

type m128QueuedSource struct {
	mu      sync.Mutex
	calls   []string
	blocked bool
	entered chan struct{}
	release chan struct{}
}

func (*m128QueuedSource) Name() string { return "m128-queued-metrics" }

func (s *m128QueuedSource) PodMetrics(ctx context.Context, namespace string, _ []string) (map[string]model.Telemetry, error) {
	s.mu.Lock()
	s.calls = append(s.calls, namespace)
	block := namespace == "a" && !s.blocked
	if block {
		s.blocked = true
	}
	s.mu.Unlock()
	if block {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
		}
	}
	return map[string]model.Telemetry{}, ctx.Err()
}

func (s *m128QueuedSource) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *m128QueuedSource) reset() {
	s.mu.Lock()
	s.calls = nil
	s.mu.Unlock()
}

func m128QueuedManager(t *testing.T, source *m128QueuedSource, policies ...*v1alpha1.PhorvexPolicy) *Manager {
	t.Helper()
	m, _ := m140BlockedTickManager(t, source, policies...)
	m.Calibration, localServices(m).Actuator = nil, nil
	for _, policy := range policies {
		if err := m.Upsert(policy); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func m128AwaitQueuedTick(t *testing.T, done <-chan tickResult) tickResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("queued tick did not finish")
		return tickInterrupted
	}
}

func m128AwaitSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestM128QueuedOwnerLifecycleAndSameUIDUpdate(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		first := m128Policy("a", "policy", "owner-a")
		queued := m128Policy("b", "policy", "owner-old")
		source := &m128QueuedSource{entered: make(chan struct{}), release: make(chan struct{})}
		m := m128QueuedManager(t, source, first, queued)
		done := make(chan tickResult, 1)
		go func() { done <- m.tick(context.Background()) }()
		m128AwaitSignal(t, source.entered, "replacement queue boundary")
		replacement := m128Policy("b", "policy", "owner-new")
		if err := m.Upsert(replacement); err != nil {
			t.Fatal(err)
		}
		close(source.release)
		if result := m128AwaitQueuedTick(t, done); result != tickSnapshotSucceeded {
			t.Fatalf("tick result=%v", result)
		}
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"a"}) || !m128LastTick(m, typesName("b", "policy")).IsZero() {
			t.Fatalf("replacement calls=%v cadence=%v", calls, m128LastTick(m, typesName("b", "policy")))
		}
		source.reset()
		m.tick(context.Background())
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"b"}) || m128LastTick(m, typesName("b", "policy")).IsZero() {
			t.Fatalf("replacement next tick calls=%v cadence=%v", calls, m128LastTick(m, typesName("b", "policy")))
		}
	})

	t.Run("removal", func(t *testing.T) {
		first := m128Policy("a", "policy", "owner-a")
		queued := m128Policy("b", "policy", "owner-b")
		source := &m128QueuedSource{entered: make(chan struct{}), release: make(chan struct{})}
		m := m128QueuedManager(t, source, first, queued)
		done := make(chan tickResult, 1)
		go func() { done <- m.tick(context.Background()) }()
		m128AwaitSignal(t, source.entered, "removal queue boundary")
		m.Remove(typesName("b", "policy"))
		close(source.release)
		m128AwaitQueuedTick(t, done)
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"a"}) {
			t.Fatalf("removed queued owner reached producer: %v", calls)
		}
	})

	t.Run("same-uid-update", func(t *testing.T) {
		first := m128Policy("a", "policy", "owner-a")
		queued := m128Policy("b", "policy", "owner-stable")
		source := &m128QueuedSource{entered: make(chan struct{}), release: make(chan struct{})}
		m := m128QueuedManager(t, source, first, queued)
		captured := m.policies["b/policy"]
		done := make(chan tickResult, 1)
		go func() { done <- m.tick(context.Background()) }()
		m128AwaitSignal(t, source.entered, "same-UID queue boundary")
		updated := queued.DeepCopy()
		updated.Generation++
		updated.Spec.Budget.TickInterval = metav1.Duration{Duration: 3 * time.Minute}
		if err := m.Upsert(updated); err != nil {
			t.Fatal(err)
		}
		if m.policies["b/policy"] == captured {
			t.Fatal("same-UID update did not replace the entry pointer")
		}
		close(source.release)
		m128AwaitQueuedTick(t, done)
		current := m.policies["b/policy"]
		if calls := source.snapshot(); !reflect.DeepEqual(calls, []string{"a", "b"}) || m128LastTick(m, typesName("b", "policy")).IsZero() {
			t.Fatalf("same-UID update calls=%v cadence=%v", calls, m128LastTick(m, typesName("b", "policy")))
		}
		if current.generation != updated.Generation || current.spec.Budget.TickInterval.Duration != 3*time.Minute {
			t.Fatalf("cadence did not land on current generation/spec: generation=%d interval=%v", current.generation, current.spec.Budget.TickInterval.Duration)
		}
		if !captured.lastTick.IsZero() {
			t.Fatalf("captured predecessor pointer received cadence %v", captured.lastTick)
		}
	})
}

type m128TimeoutSource struct {
	calls         atomic.Int32
	active        atomic.Int32
	maxConcurrent atomic.Int32
	entered       chan int
}

func (*m128TimeoutSource) Name() string { return "m128-timeout-metrics" }

func (s *m128TimeoutSource) PodMetrics(ctx context.Context, _ string, _ []string) (map[string]model.Telemetry, error) {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		old := s.maxConcurrent.Load()
		if active <= old || s.maxConcurrent.CompareAndSwap(old, active) {
			break
		}
	}
	n := int(s.calls.Add(1))
	s.entered <- n
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestM128StartTimeoutRetriesOnlyAtFutureMaintenance(t *testing.T) {
	clock := &manualManagerClock{now: time.Unix(1_900_000_000, 0), created: make(chan *manualManagerTimer, 1)}
	source := &m128TimeoutSource{entered: make(chan int, 2)}
	policy := m128Policy("ns", "policy", "owner-timeout")
	m, _ := m140BlockedTickManager(t, source, policy)
	m.BaseInterval = 100 * time.Millisecond
	m.PerTickTimeout = 20 * time.Millisecond
	m.Calibration, localServices(m).Actuator = nil, nil
	m.scheduleClock = clock
	if err := m.Upsert(policy); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	var timer *manualManagerTimer
	select {
	case timer = <-clock.created:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("Start did not create its timer")
	}
	select {
	case <-timer.resets:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("Start did not arm initial maintenance")
	}
	clock.advance(m.BaseInterval, timer)
	select {
	case call := <-source.entered:
		if call != 1 {
			t.Fatalf("first producer call=%d", call)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("first producer did not start")
	}
	var retry time.Duration
	select {
	case retry = <-timer.resets:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("Start did not rearm after timeout")
	}
	if retry <= 0 || retry != m.BaseInterval {
		t.Fatalf("interrupted retry=%v, want future maintenance %v", retry, m.BaseInterval)
	}
	if got := m128LastTick(m, typesName("ns", "policy")); !got.IsZero() {
		t.Fatalf("timed-out producer received cadence %v", got)
	}
	select {
	case call := <-source.entered:
		t.Fatalf("producer hot-looped before timer advance: call=%d", call)
	case <-time.After(25 * time.Millisecond):
	}
	clock.advance(retry, timer)
	select {
	case call := <-source.entered:
		if call != 2 {
			t.Fatalf("second producer call=%d", call)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("second producer did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not stop after parent cancellation")
	}
	if got := source.maxConcurrent.Load(); got != 1 {
		t.Fatalf("maximum concurrent producers=%d", got)
	}
}

type m128SelectedOptimizer struct {
	decisions []model.Decision
}

func (*m128SelectedOptimizer) Name() string { return "m128-selected" }
func (o *m128SelectedOptimizer) Decide(views []*model.WorkloadView, pol model.Policy) []model.Decision {
	if len(views) == 0 {
		return nil
	}
	o.decisions = []model.Decision{
		{
			Tenant: pol.Tenant, Namespace: views[0].Pod.Namespace, Pod: views[0].Pod.Name,
			Action: model.ActionKVReset, Selected: true, Feasible: true,
			Existential: &model.ExistentialDecision{Present: true, EffectStatus: "not-attempted"},
		},
		{
			Tenant: pol.Tenant, Namespace: views[0].Pod.Namespace, Pod: views[0].Pod.Name,
			Action: model.ActionKVReset, Selected: true, Feasible: true,
			Existential: &model.ExistentialDecision{Present: true, EffectStatus: "not-attempted"},
		},
	}
	return o.decisions
}

type m128AttemptingActuator struct {
	cancel context.CancelFunc
	calls  int
}

func (*m128AttemptingActuator) Name() string { return "m128-attempting" }
func (*m128AttemptingActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	return nil
}
func (*m128AttemptingActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (a *m128AttemptingActuator) Actuate(ctx context.Context, _ actuator.Request) (actuator.Result, error) {
	a.calls++
	a.cancel()
	return actuator.Result{Emitted: true, Handler: "m128-attempt", MutationKind: "irreversible", ObjectsTouched: []string{"Pod/ns/crown"}}, ctx.Err()
}

func TestM128CancellationAfterDispatchPreservesAttemptAuditWithoutCadence(t *testing.T) {
	policy := m128Policy("ns", "policy", "owner-attempt")
	policy.Spec.Mode = v1alpha1.ModeActive
	policy.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionKVReset)}
	source := &m128RecordingSource{}
	m := m128Manager(t, source, policy)
	var pod corev1.Pod
	if err := m.Client.Get(context.Background(), typesName("ns", "crown"), &pod); err != nil {
		t.Fatal(err)
	}
	pod.Annotations = map[string]string{
		"phorvex.ai/serving-port":   "8000",
		"phorvex.ai/kv-reset-epoch": "old",
	}
	if err := m.Client.Update(context.Background(), &pod); err != nil {
		t.Fatal(err)
	}
	if err := m.Client.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}); err != nil {
		t.Fatal(err)
	}
	m.KillSwitch = &KillSwitch{}
	m.BoundaryReader = m.Client
	m.Clock.Observe(exposure.Observation{
		Owner: m.policies["ns/policy"].ownerKey(), Namespace: "ns", Pod: "crown",
		StartedAt:    time.Now().Add(-24 * time.Hour),
		Fingerprints: map[string]string{model.VarPodIdentity: "u-crown", model.VarSession: "old|"},
	}, time.Now().Add(-24*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hands := &m128AttemptingActuator{cancel: cancel}
	var records bytes.Buffer
	optimizer := &m128SelectedOptimizer{}
	localServices(m).Optimizer = optimizer
	localServices(m).Actuator = hands
	m.Audit = audit.New(logr.Discard(), &records)
	if result := m.tick(ctx); result != tickInterrupted {
		t.Fatalf("tick result=%v actuator calls=%d decisions=%+v audit=%s", result, hands.calls, optimizer.decisions, records.String())
	}
	if hands.calls != 1 {
		t.Fatalf("actuator calls=%d", hands.calls)
	}
	if len(optimizer.decisions) != 2 || optimizer.decisions[0].Handler != "m128-attempt" ||
		optimizer.decisions[0].Existential.EffectStatus != "failed-or-unconfirmed" {
		t.Fatalf("first attempted decision evidence=%+v", optimizer.decisions)
	}
	second := optimizer.decisions[1]
	if second.Handler != "" || second.Actuated || second.DispatchOutcome != model.DispatchNotAttempted ||
		second.Existential.EffectStatus != "not-attempted" {
		t.Fatalf("second decision crossed cancellation boundary: %+v", second)
	}
	if got := records.String(); !strings.Contains(got, "m128-attempt") || !strings.Contains(got, "Pod/ns/crown") {
		t.Fatalf("attempt evidence was discarded after cancellation: %s", got)
	}
	if count, _ := m.emissionWindow(m.policies["ns/policy"], 0, time.Now()); count != 1 {
		t.Fatalf("attempted emission local accounting=%d, want 1", count)
	}
	if got := m128LastTick(m, typesName("ns", "policy")); !got.IsZero() {
		t.Fatalf("attempted timeout received cadence %v", got)
	}
}
