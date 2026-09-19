package runner

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// cadenceSource is the real final producer in the runner path. Recording here proves
// Manager.Start admitted a policy, built a shared snapshot, and reached PodMetrics;
// scheduler-only callbacks cannot satisfy these tests.
type cadenceSource struct {
	mu    sync.Mutex
	times []time.Time
	wake  chan struct{}
}

func (*cadenceSource) Name() string { return "m174-cadence-source" }

func (s *cadenceSource) PodMetrics(context.Context, string, []string) (map[string]model.Telemetry, error) {
	s.mu.Lock()
	s.times = append(s.times, time.Now())
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return map[string]model.Telemetry{}, nil
}

func (s *cadenceSource) snapshot() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.times...)
}

func runCadenceProducer(t *testing.T, base, policyInterval time.Duration, samples int) []time.Time {
	t.Helper()
	src := &cadenceSource{wake: make(chan struct{}, samples+2)}
	p := m140Policy("policy", "tenant", "uid-cadence")
	p.Spec.Budget.TickInterval = metav1.Duration{Duration: policyInterval}
	m, _ := m140BlockedTickManager(t, src, p)
	m.BaseInterval = base
	m.PerTickTimeout = 2 * time.Second
	m.Calibration = nil
	m.Actuator = nil
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	window := max(base, policyInterval)
	deadline := time.NewTimer(base + time.Duration(samples+5)*window)
	defer deadline.Stop()
	for i := 0; i < samples; i++ {
		select {
		case <-src.wake:
		case <-deadline.C:
			cancel()
			<-done
			t.Fatalf("producer ran %d times, want %d", len(src.snapshot()), samples)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Start: %v", err)
	}
	return src.snapshot()
}

func assertProducerGaps(t *testing.T, got []time.Time, min, medianMax time.Duration) {
	t.Helper()
	if len(got) < 2 {
		t.Fatalf("producer calls = %d, want at least 2", len(got))
	}
	gaps := make([]time.Duration, 0, len(got)-1)
	for i := 1; i < len(got); i++ {
		gap := got[i].Sub(got[i-1])
		if gap < min {
			t.Fatalf("producer gap[%d] = %v, want >= %v; calls=%v", i, gap, min, got)
		}
		gaps = append(gaps, gap)
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	if median := gaps[len(gaps)/2]; median > medianMax {
		t.Fatalf("median producer gap = %v, want <= %v; gaps=%v", median, medianMax, gaps)
	}
}

func TestM174StartHonorsBelowBasePolicyCadence(t *testing.T) {
	got := runCadenceProducer(t, 200*time.Millisecond, 100*time.Millisecond, 6)
	assertProducerGaps(t, got, 70*time.Millisecond, 165*time.Millisecond)
}

func TestM174StartFasterBasePositiveControl(t *testing.T) {
	got := runCadenceProducer(t, 20*time.Millisecond, 100*time.Millisecond, 6)
	assertProducerGaps(t, got, 70*time.Millisecond, 145*time.Millisecond)
}

func TestM174StartHonorsEqualAndNonDivisorCadence(t *testing.T) {
	for _, tc := range []struct {
		name, base, interval string
	}{
		{name: "equal", base: "100ms", interval: "100ms"},
		{name: "non-divisor", base: "30ms", interval: "100ms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := time.ParseDuration(tc.base)
			interval, _ := time.ParseDuration(tc.interval)
			got := runCadenceProducer(t, base, interval, 7)
			assertProducerGaps(t, got, 70*time.Millisecond, 115*time.Millisecond)
		})
	}
}

func TestM174DeadlineSelectionAndMaintenanceCoalescing(t *testing.T) {
	now := time.Unix(100, 0)
	key := "ns/policy"
	m := &Manager{policies: map[string]*policyEntry{key: {
		key: typesName("ns", "policy"), uid: "uid-A", lastTick: now,
		spec: policySpecWithInterval(100 * time.Millisecond),
	}}}
	base := now.Add(200 * time.Millisecond)
	if got := m.nextWakeDeadline(now, base, true); !got.Equal(now.Add(100 * time.Millisecond)) {
		t.Fatalf("non-divisor/below-base deadline = %v", got)
	}
	// Equal deadlines are neither rounded nor doubled.
	m.policies[key].spec = policySpecWithInterval(200 * time.Millisecond)
	if got := m.nextWakeDeadline(now, base, true); !got.Equal(base) {
		t.Fatalf("equal deadline = %v, want %v", got, base)
	}
	// Successful overrun gets one immediate eligibility; a failed snapshot arms only base.
	m.policies[key].lastTick = now.Add(-500 * time.Millisecond)
	if got := m.nextWakeDeadline(now, base, true); !got.Before(now) {
		t.Fatalf("overdue successful deadline = %v, want immediate eligibility", got)
	}
	if got := m.nextWakeDeadline(now, base, false); !got.Equal(base) {
		t.Fatalf("failed-snapshot retry = %v, want maintenance %v", got, base)
	}
	if got := nextMaintenanceDeadline(now.Add(-450*time.Millisecond), now, 200*time.Millisecond); !got.Equal(now.Add(150 * time.Millisecond)) {
		t.Fatalf("coalesced maintenance = %v, want %v", got, now.Add(150*time.Millisecond))
	}
}

func typesName(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}

func policySpecWithInterval(interval time.Duration) v1alpha1.PhorvexPolicySpec {
	var spec v1alpha1.PhorvexPolicySpec
	spec.Budget.TickInterval = metav1.Duration{Duration: interval}
	return spec
}

func TestM174CadenceIdentityUpdateReplacementAndRemoval(t *testing.T) {
	now := time.Unix(200, 0)
	m := &Manager{policies: map[string]*policyEntry{}, emits: map[string]*emissionHistory{}}
	p := m140Policy("policy", "tenant", "uid-A")
	p.Spec.Budget.TickInterval = metav1.Duration{Duration: 100 * time.Millisecond}
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	e := m.policies["ns/policy"]
	m.creditCadence(context.Background(), e, now)

	updated := p.DeepCopy()
	updated.Generation++
	updated.Spec.Budget.TickInterval = metav1.Duration{Duration: 250 * time.Millisecond}
	if err := m.Upsert(updated); err != nil {
		t.Fatal(err)
	}
	if got := m.policies["ns/policy"].lastTick; !got.Equal(now) {
		t.Fatalf("same UID lost cadence: %v", got)
	}
	if got := m.nextWakeDeadline(now, now.Add(time.Second), true); !got.Equal(now.Add(250 * time.Millisecond)) {
		t.Fatalf("updated interval deadline = %v", got)
	}

	replacement := updated.DeepCopy()
	replacement.UID = "uid-B"
	if err := m.Upsert(replacement); err != nil {
		t.Fatal(err)
	}
	m.creditCadence(context.Background(), e, now.Add(time.Second)) // stale predecessor completion
	if got := m.policies["ns/policy"].lastTick; !got.IsZero() {
		t.Fatalf("predecessor credited replacement: %v", got)
	}
	base := now.Add(2 * time.Second)
	if got := m.nextWakeDeadline(now, base, true); !got.Equal(base) {
		t.Fatalf("new UID bypassed initial maintenance pickup: %v", got)
	}
	m.Remove(typesName("ns", "policy"))
	if got := m.nextWakeDeadline(now, base, true); !got.Equal(base) {
		t.Fatalf("removed policy retained deadline: %v", got)
	}
}

type failingListClient struct {
	client.Client
	fail         atomic.Bool
	failures     atomic.Int32
	failureDelay time.Duration
	failureTimes chan time.Time
}

func (c *failingListClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.fail.Load() {
		c.failures.Add(1)
		if c.failureTimes != nil {
			c.failureTimes <- time.Now()
		}
		if c.failureDelay > 0 {
			time.Sleep(c.failureDelay)
		}
		return errors.New("m174 snapshot unavailable")
	}
	return c.Client.List(ctx, list, opts...)
}

func TestM174SlowFailedSnapshotStillRetriesInFuture(t *testing.T) {
	src := &cadenceSource{wake: make(chan struct{}, 2)}
	p := m140Policy("policy", "tenant", "uid-slow-failure")
	p.Spec.Budget.TickInterval = metav1.Duration{Duration: 20 * time.Millisecond}
	m, _ := m140BlockedTickManager(t, src, p)
	fc := &failingListClient{Client: m.Client, failureDelay: 90 * time.Millisecond, failureTimes: make(chan time.Time, 3)}
	m.Client, m.OwnershipReader = fc, fc
	m.KillSwitch.Client = fc
	m.BaseInterval, m.PerTickTimeout, m.Calibration, m.Actuator = 60*time.Millisecond, time.Second, nil, nil
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	select {
	case <-src.wake:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("successful producer never established cadence")
	}
	fc.fail.Store(true)
	first := <-fc.failureTimes
	second := <-fc.failureTimes
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The failure itself crosses a maintenance boundary. A stale deadline would arm
	// Reset(0), so the next List would start at once when the first one returns.
	if gap := second.Sub(first) - fc.failureDelay; gap < 5*time.Millisecond {
		t.Fatalf("slow snapshot failure retried without a future maintenance wait: %v", gap)
	}
}

func TestM174FailedSnapshotRetriesAtMaintenanceWithoutSpin(t *testing.T) {
	src := &cadenceSource{wake: make(chan struct{}, 4)}
	p := m140Policy("policy", "tenant", "uid-failure")
	p.Spec.Budget.TickInterval = metav1.Duration{Duration: 30 * time.Millisecond}
	m, _ := m140BlockedTickManager(t, src, p)
	fc := &failingListClient{Client: m.Client}
	m.Client, m.OwnershipReader = fc, fc
	m.KillSwitch.Client = fc
	m.BaseInterval, m.PerTickTimeout, m.Calibration, m.Actuator = 80*time.Millisecond, time.Second, nil, nil
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	select {
	case <-src.wake:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("successful producer never established cadence")
	}
	fc.fail.Store(true)
	time.Sleep(150 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if failures := fc.failures.Load(); failures < 1 || failures > 3 {
		t.Fatalf("failed snapshot attempts = %d, want bounded maintenance retries", failures)
	}
	if calls := len(src.snapshot()); calls != 1 {
		t.Fatalf("metrics producer ran after failed snapshots: %d", calls)
	}
}

type cancelBlockingSource struct {
	entered chan struct{}
	calls   atomic.Int32
}

func (*cancelBlockingSource) Name() string { return "m174-cancel-blocking" }
func (s *cancelBlockingSource) PodMetrics(ctx context.Context, _ string, _ []string) (map[string]model.Telemetry, error) {
	s.calls.Add(1)
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestM174CancellationDuringBlockedTickStartsNoNextTick(t *testing.T) {
	src := &cancelBlockingSource{entered: make(chan struct{}, 1)}
	p := m140Policy("policy", "tenant", "uid-cancel")
	p.Spec.Budget.TickInterval = metav1.Duration{Duration: 10 * time.Millisecond}
	m, _ := m140BlockedTickManager(t, src, p)
	m.BaseInterval, m.PerTickTimeout, m.Calibration, m.Actuator = 20*time.Millisecond, time.Second, nil, nil
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	select {
	case <-src.entered:
	case <-time.After(time.Second):
		t.Fatal("producer did not block")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not exit")
	}
	if got := src.calls.Load(); got != 1 {
		t.Fatalf("producer calls after cancellation = %d", got)
	}
}

type overrunSource struct {
	mu            sync.Mutex
	times         []time.Time
	wake          chan struct{}
	concurrent    atomic.Int32
	maxConcurrent atomic.Int32
}

func (*overrunSource) Name() string { return "m174-overrun" }
func (s *overrunSource) PodMetrics(context.Context, string, []string) (map[string]model.Telemetry, error) {
	active := s.concurrent.Add(1)
	defer s.concurrent.Add(-1)
	for {
		old := s.maxConcurrent.Load()
		if active <= old || s.maxConcurrent.CompareAndSwap(old, active) {
			break
		}
	}
	s.mu.Lock()
	s.times = append(s.times, time.Now())
	n := len(s.times)
	s.mu.Unlock()
	if n == 1 {
		time.Sleep(110 * time.Millisecond)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return map[string]model.Telemetry{}, nil
}

func TestM174SuccessfulOverrunCoalescesWithoutOverlap(t *testing.T) {
	src := &overrunSource{wake: make(chan struct{}, 4)}
	p := m140Policy("policy", "tenant", "uid-overrun")
	p.Spec.Budget.TickInterval = metav1.Duration{Duration: 30 * time.Millisecond}
	m, _ := m140BlockedTickManager(t, src, p)
	m.BaseInterval, m.PerTickTimeout, m.Calibration, m.Actuator = 50*time.Millisecond, time.Second, nil, nil
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	for i := 0; i < 3; i++ {
		select {
		case <-src.wake:
		case <-time.After(time.Second):
			cancel()
			<-done
			t.Fatal("producer did not complete")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := src.maxConcurrent.Load(); got != 1 {
		t.Fatalf("maximum tick overlap = %d", got)
	}
	src.mu.Lock()
	times := append([]time.Time(nil), src.times...)
	src.mu.Unlock()
	if gap := times[1].Sub(times[0]); gap < 100*time.Millisecond {
		t.Fatalf("overrun did not block the next serialized producer: %v", gap)
	}
	if gap := times[2].Sub(times[1]); gap < 20*time.Millisecond {
		t.Fatalf("missed deadlines replayed as a burst: %v", gap)
	}
}

type manualManagerClock struct {
	mu      sync.Mutex
	now     time.Time
	created chan *manualManagerTimer
}

type manualManagerTimer struct {
	clock    *manualManagerClock
	c        chan time.Time
	resets   chan time.Duration
	mu       sync.Mutex
	deadline time.Time
}

func (c *manualManagerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *manualManagerClock) NewTimer(d time.Duration) managerTimer {
	t := &manualManagerTimer{clock: c, c: make(chan time.Time, 1), resets: make(chan time.Duration, 4)}
	t.Reset(d)
	c.created <- t
	return t
}
func (c *manualManagerClock) advance(d time.Duration, timer *manualManagerTimer) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	timer.mu.Lock()
	due := !timer.deadline.After(now)
	timer.mu.Unlock()
	if due {
		timer.c <- now
	}
}
func (t *manualManagerTimer) C() <-chan time.Time { return t.c }
func (t *manualManagerTimer) Reset(d time.Duration) {
	t.mu.Lock()
	t.deadline = t.clock.Now().Add(d)
	t.mu.Unlock()
	select {
	case t.resets <- d:
	default:
	}
}
func (*manualManagerTimer) Stop() {}

func TestM174ManualTimerArmsExactPolicyDeadline(t *testing.T) {
	clock := &manualManagerClock{now: time.Unix(300, 0), created: make(chan *manualManagerTimer, 1)}
	src := &cadenceSource{wake: make(chan struct{}, 2)}
	p := m140Policy("policy", "tenant", "uid-manual")
	p.Spec.Budget.TickInterval = metav1.Duration{Duration: 100 * time.Millisecond}
	m, _ := m140BlockedTickManager(t, src, p)
	m.BaseInterval, m.PerTickTimeout, m.Calibration, m.Actuator = 200*time.Millisecond, time.Second, nil, nil
	m.scheduleClock = clock
	if err := m.Upsert(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	timer := <-clock.created
	<-timer.resets // initial maintenance arm
	clock.advance(200*time.Millisecond, timer)
	select {
	case <-src.wake:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("manual maintenance tick did not reach producer")
	}
	select {
	case got := <-timer.resets:
		if got != 100*time.Millisecond {
			t.Fatalf("timer reset = %v, want exact policy deadline", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timer was not reset after successful snapshot")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

var _ ingest.MetricsSource = (*cadenceSource)(nil)
