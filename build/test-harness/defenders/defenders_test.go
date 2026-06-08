package defenders

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

// --- test doubles (mirror the core unit-test helpers without importing them) ---

// allowGuard permits mutation only against the configured sandbox namespace,
// exactly like the real safety guard's sandbox assertion.
type allowGuard struct{ allow string }

func (g allowGuard) AssertMutationAllowed(ns string) error {
	if ns != g.allow {
		return errors.New("REFUSED: namespace " + ns + " != sandbox " + g.allow)
	}
	return nil
}

type nopLogger struct{ cmds []string }

func (l *nopLogger) Logf(string, ...any) {}
func (l *nopLogger) Command(c string)    { l.cmds = append(l.cmds, c) }
func (l *nopLogger) Commands() []string  { return l.cmds }
func (l *nopLogger) RawLogPath() string  { return "" }

// newDefenderTestEnv builds a deterministic, fully-offline Env for the rotation
// engine: a fake clientset, the sandbox guard, a no-op logger and a seeded RNG.
func newDefenderTestEnv(ns string, objs ...runtime.Object) *core.Env {
	return &core.Env{
		Kube:   fake.NewSimpleClientset(objs...),
		Config: config.TargetConfig{Namespace: ns, Context: "kind-amtd-test", OwnedAck: true},
		Log:    &nopLogger{},
		Guard:  allowGuard{allow: ns},
		Rand:   rand.New(rand.NewSource(1)),
	}
}

// targetPod builds a bare pod carrying the rotation-target label so the timer
// engine selects it.
func targetPod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{RotationTargetLabel: "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: "busybox"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// allDefenders returns one instance of every registered arm, by metadata name, so
// the table tests assert against the SAME objects the runner enumerates.
func allDefenders() map[string]core.Defender {
	m := map[string]core.Defender{}
	for _, d := range core.Defenders() {
		m[d.Metadata().Name] = d
	}
	return m
}

// TestAllArmsRegistered asserts every required defender self-registered (the
// extensibility contract: enumerating the registry yields all five arms).
func TestAllArmsRegistered(t *testing.T) {
	want := []string{"d-nomtd", "d-r6blindtimer", "d-randomequal", "d-fullphoenix", "d-reactive-only", "d-phorvex"}
	got := allDefenders()
	for _, name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("defender %q is not registered", name)
		}
	}
	if len(got) < len(want) {
		t.Errorf("registry has %d defenders, want at least %d", len(got), len(want))
	}
}

// TestMetadataComplete is the table test asserting each arm's Metadata is complete
// and internally consistent with its role.
func TestMetadataComplete(t *testing.T) {
	cases := []struct {
		name             string
		wantBaseline     bool
		wantRotation     bool // expects a non-zero mean rotation interval
		descMustNotEmpty bool
	}{
		{"d-nomtd", true, false, true},
		{"d-r6blindtimer", false, true, true},
		{"d-randomequal", false, true, true},
		{"d-fullphoenix", false, true, true},
		{"d-reactive-only", false, false, true},
		{"d-phorvex", false, false, true},
	}
	reg := allDefenders()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := reg[tc.name]
			if !ok {
				t.Fatalf("defender %q not registered", tc.name)
			}
			md := d.Metadata()
			if md.Name != tc.name {
				t.Errorf("Name = %q, want %q", md.Name, tc.name)
			}
			if tc.descMustNotEmpty && md.Description == "" {
				t.Errorf("Description must not be empty")
			}
			if md.IsNegativeControlBaseline != tc.wantBaseline {
				t.Errorf("IsNegativeControlBaseline = %v, want %v", md.IsNegativeControlBaseline, tc.wantBaseline)
			}
			if tc.wantRotation && md.MeanRotationIntervalSeconds <= 0 {
				t.Errorf("MeanRotationIntervalSeconds = %v, want > 0", md.MeanRotationIntervalSeconds)
			}
			if !tc.wantRotation && md.MeanRotationIntervalSeconds != 0 {
				t.Errorf("MeanRotationIntervalSeconds = %v, want 0 (no rotation arm)", md.MeanRotationIntervalSeconds)
			}
		})
	}
}

// TestExactlyOneBaseline asserts the registry advertises a single positive-control
// baseline (the 100% anchor) — a duplicate would corrupt every disruption number.
func TestExactlyOneBaseline(t *testing.T) {
	n := 0
	for _, d := range core.Defenders() {
		if d.Metadata().IsNegativeControlBaseline {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one baseline arm, got %d", n)
	}
}

// TestEqualMeanRotationRate is the FAIR-COMPARISON invariant: the blind-timer and
// random arms advertise the SAME mean rotation rate (equal cost). This is what
// makes d-randomequal the honest equal-cost comparison to FullPhoenix.
func TestEqualMeanRotationRate(t *testing.T) {
	reg := allDefenders()
	blind := reg["d-r6blindtimer"].Metadata().MeanRotationIntervalSeconds
	random := reg["d-randomequal"].Metadata().MeanRotationIntervalSeconds
	full := reg["d-fullphoenix"].Metadata().MeanRotationIntervalSeconds
	if blind != random {
		t.Errorf("blind mean %v != random mean %v — equal-cost invariant violated", blind, random)
	}
	if blind != full {
		t.Errorf("blind mean %v != fullphoenix mean %v — equal-cost invariant violated", blind, full)
	}
}

// TestEqualMeanDelaySampled drives the actual nextDelay schedulers (the real code
// path the goroutine uses) and asserts the EMPIRICAL mean inter-rotation gap of
// the random arm matches the blind arm's fixed interval within tolerance. This is
// the strong form of the fair-comparison invariant: equal mean RATE in practice,
// not just in metadata.
func TestEqualMeanDelaySampled(t *testing.T) {
	env := newDefenderTestEnv("sandbox")

	blind := &blindTimer{}
	if err := blind.Setup(context.Background(), env); err != nil {
		t.Fatalf("blind setup: %v", err)
	}
	random := &randomEqual{}
	if err := random.Setup(context.Background(), env); err != nil {
		t.Fatalf("random setup: %v", err)
	}

	const n = 20000
	var blindSum, randSum float64
	for i := 0; i < n; i++ {
		blindSum += blind.eng.nextDelay().Seconds()
		randSum += random.eng.nextDelay().Seconds()
	}
	blindMean := blindSum / n
	randMean := randSum / n

	// Blind is deterministic == the fixed interval.
	if math.Abs(blindMean-BlindRotationInterval.Seconds()) > 1e-9 {
		t.Errorf("blind mean delay %v != fixed interval %v", blindMean, BlindRotationInterval.Seconds())
	}
	// The random arm is exponential with the same mean, but clamped to [1s, 3*mean];
	// clamping pulls the empirical mean modestly BELOW the raw exponential mean. We
	// assert the two arms are within 15%% of each other — same rate at matched cost.
	rel := math.Abs(randMean-blindMean) / blindMean
	if rel > 0.15 {
		t.Errorf("random mean delay %v vs blind %v differ by %.1f%% (> 15%%) — not equal-rate", randMean, blindMean, rel*100)
	}
	t.Logf("blind mean=%.3fs random mean=%.3fs (%.1f%% apart)", blindMean, randMean, rel*100)
}

// TestBlindTimerHonorsInterval verifies the blind scheduler's gap is exactly the
// configured fixed interval every time (a TimeBasedTrigger with no jitter).
func TestBlindTimerHonorsInterval(t *testing.T) {
	env := newDefenderTestEnv("sandbox")
	b := &blindTimer{}
	if err := b.Setup(context.Background(), env); err != nil {
		t.Fatalf("setup: %v", err)
	}
	for i := 0; i < 100; i++ {
		if got := b.eng.nextDelay(); got != BlindRotationInterval {
			t.Fatalf("blind delay %v != fixed %v at draw %d", got, BlindRotationInterval, i)
		}
	}
}

// TestRandomEqualGapsAreBounded asserts every random gap stays inside the
// documented [1s, 3*mean] window so a smoke trial always observes a rotation and
// no gap is pathologically long.
func TestRandomEqualGapsAreBounded(t *testing.T) {
	env := newDefenderTestEnv("sandbox")
	r := &randomEqual{}
	if err := r.Setup(context.Background(), env); err != nil {
		t.Fatalf("setup: %v", err)
	}
	mean := BlindRotationInterval.Seconds()
	for i := 0; i < 5000; i++ {
		g := r.eng.nextDelay().Seconds()
		if g < 1.0-1e-9 || g > 3*mean+1e-9 {
			t.Fatalf("random gap %v out of bounds [1, %v] at draw %d", g, 3*mean, i)
		}
	}
}

// TestRandomEqualDeterministicForSeed asserts the random arm is reproducible: the
// SAME seed yields the SAME gap sequence (the whole run derives from masterSeed).
func TestRandomEqualDeterministicForSeed(t *testing.T) {
	seq := func() []float64 {
		env := newDefenderTestEnv("sandbox")
		env.Rand = rand.New(rand.NewSource(42))
		r := &randomEqual{}
		_ = r.Setup(context.Background(), env)
		out := make([]float64, 16)
		for i := range out {
			out[i] = r.eng.nextDelay().Seconds()
		}
		return out
	}
	a, b := seq(), seq()
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic gap at %d: %v != %v", i, a[i], b[i])
		}
	}
}

// TestTimerEngineRotatesTargetPods drives the live engine against a fake cluster:
// a fast-cadence timer must delete the rotation-target pod and record at least one
// defensive action within a short window. This exercises the scheduler -> guard ->
// delete -> action-record path the runner relies on.
func TestTimerEngineRotatesTargetPods(t *testing.T) {
	env := newDefenderTestEnv("sandbox", targetPod("sandbox", "victim"))

	b := &blindTimer{}
	// Override the cadence to a few ms so the test runs fast but exercises the SAME
	// engine the production interval uses.
	if err := b.Setup(context.Background(), env); err != nil {
		t.Fatalf("setup: %v", err)
	}
	b.eng.nextDelay = func() time.Duration { return 5 * time.Millisecond }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.Start(ctx, env); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Poll for the first defensive action (a rotation) rather than sleeping a fixed
	// duration.
	deadline := time.Now().Add(2 * time.Second)
	var count int
	for time.Now().Before(deadline) {
		count, _, _ = b.DefensiveActions(ctx, env)
		if count > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = b.Stop(ctx, env)

	if count == 0 {
		t.Fatalf("blind timer recorded no rotations; expected at least one")
	}
	// The original victim pod must be gone (deleted by the rotation).
	if _, err := env.Kube.CoreV1().Pods("sandbox").Get(ctx, "victim", metav1.GetOptions{}); err == nil {
		t.Errorf("victim pod still present after rotation; expected it deleted")
	}
}

// TestTimerEngineRefusesOutsideSandbox asserts the rotation engine never mutates
// outside the sandbox: with a guard that disallows the env namespace, no pod is
// deleted and no action is recorded.
func TestTimerEngineRefusesOutsideSandbox(t *testing.T) {
	env := &core.Env{
		Kube:   fake.NewSimpleClientset(targetPod("evil", "victim")),
		Config: config.TargetConfig{Namespace: "evil", Context: "kind-amtd-test", OwnedAck: true},
		Log:    &nopLogger{},
		Guard:  allowGuard{allow: "sandbox"}, // only sandbox allowed; env targets "evil"
		Rand:   rand.New(rand.NewSource(1)),
	}
	b := &blindTimer{}
	_ = b.Setup(context.Background(), env)
	b.eng.nextDelay = func() time.Duration { return 5 * time.Millisecond }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = b.Start(ctx, env)
	time.Sleep(100 * time.Millisecond)
	_ = b.Stop(ctx, env)

	count, _, _ := b.DefensiveActions(ctx, env)
	if count != 0 {
		t.Fatalf("engine performed %d rotations outside the sandbox; must refuse", count)
	}
	if _, err := env.Kube.CoreV1().Pods("evil").Get(ctx, "victim", metav1.GetOptions{}); err != nil {
		t.Errorf("victim pod in non-sandbox ns was deleted; guard must have refused")
	}
}

// TestNoMTDIsInert asserts the positive-control baseline takes zero defensive
// actions across its whole lifecycle (it must never disrupt an attack).
func TestNoMTDIsInert(t *testing.T) {
	env := newDefenderTestEnv("sandbox", targetPod("sandbox", "victim"))
	n := &noMTD{}
	ctx := context.Background()
	for _, step := range []func(context.Context, *core.Env) error{n.Setup, n.Start, n.Stop, n.Teardown} {
		if err := step(ctx, env); err != nil {
			t.Fatalf("noMTD lifecycle step errored: %v", err)
		}
	}
	count, at, err := n.DefensiveActions(ctx, env)
	if err != nil || count != 0 || at != nil {
		t.Fatalf("noMTD took defensive actions: count=%d at=%v err=%v", count, at, err)
	}
	// The target pod must be untouched.
	if _, err := env.Kube.CoreV1().Pods("sandbox").Get(ctx, "victim", metav1.GetOptions{}); err != nil {
		t.Errorf("noMTD deleted the target pod; baseline must be inert")
	}
}

// TestPhoenixClassArmsAreSkipReporters asserts the real Phoenix-class arms (PX and
// reactive-only) implement the optional SkipReporter interface so they degrade to
// skip-with-note (never a hard failure) when the Phoenix/Phorvex toolchain or source
// is unavailable — the same portable contract FullPhoenix honors.
func TestPhoenixClassArmsAreSkipReporters(t *testing.T) {
	reg := allDefenders()
	for _, name := range []string{"d-phorvex", "d-reactive-only"} {
		d, ok := reg[name]
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if _, ok := d.(core.SkipReporter); !ok {
			t.Errorf("%s must implement core.SkipReporter (skip-with-note when source/toolchain absent)", name)
		}
	}
}

// TestFullPhoenixSkipsWithoutSource asserts the FullPhoenix arm degrades to
// skip-with-note (never a hard failure) when no Phoenix source dir is configured —
// the portable default so the SAME plugin set runs on a cluster without the
// operator toolchain.
func TestFullPhoenixSkipsWithoutSource(t *testing.T) {
	env := newDefenderTestEnv("sandbox")
	env.Config.PhoenixSrcDir = "" // not configured
	f := &fullPhoenix{}
	if err := f.Setup(context.Background(), env); err != nil {
		t.Fatalf("FullPhoenix Setup must not hard-fail when source is absent: %v", err)
	}
	sr, ok := core.Defender(f).(core.SkipReporter)
	if !ok {
		t.Fatalf("fullPhoenix must implement core.SkipReporter")
	}
	skip, msg := sr.SkipReason()
	if !skip || msg == "" {
		t.Fatalf("FullPhoenix without source must skip-with-note; got skip=%v msg=%q", skip, msg)
	}
}
