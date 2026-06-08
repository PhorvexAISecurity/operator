package defenders

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// sweptBlind is the P3-DEEP INTERVAL-SWEEP arm: a blind fixed-interval rotator IDENTICAL
// in mechanism to d-r6blindtimer but at a parameterized interval, so the harness can run
// the blind strategy across a RANGE of intervals (very-fast .. realistic .. slow) and
// build the structural frontier table. It reuses the shared timerEngine UNCHANGED (the
// nextDelay closure already accepts any period), so each interval is one registration —
// ZERO harness-core / ZERO extended-Phoenix change.
//
// The intervals are SCALED-FOR-TEST seconds (R6/Phoenix's documented production rotation
// is ~hourly; 15s ≈ a 240× compression). The honest RELATIVE ordering is preserved and
// stated: PX proactive floor 6s < attacker objective 9s < documented blind 15s — and 6,9
// sit INSIDE the swept range so a clean blind win at a fast interval is REACHABLE and
// would be printed (the design cannot hide a clean interval).
type sweptBlind struct {
	eng      timerEngine
	interval time.Duration
	name     string
}

func (s *sweptBlind) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:                        s.name,
		Description:                 fmt.Sprintf("INTERVAL-SWEEP blind arm: fixed-interval rotation every %s (same mechanism as d-r6blindtimer; no telemetry, no targeting, rotate-ALL). Scaled-for-test; relative ordering PX-floor<objective<blind preserved.", s.interval),
		MeanRotationIntervalSeconds: s.interval.Seconds(),
	}
}

func (s *sweptBlind) Setup(ctx context.Context, env *core.Env) error {
	iv := s.interval
	s.eng.nextDelay = func() time.Duration { return iv }
	return nil
}

func (s *sweptBlind) Start(ctx context.Context, env *core.Env) error {
	env.Log.Logf("%s: arming blind rotation every %s (no emitter)", s.name, s.interval)
	s.eng.startEngine(ctx, env)
	return nil
}

func (s *sweptBlind) Stop(ctx context.Context, env *core.Env) error     { s.eng.stopEngine(); return nil }
func (s *sweptBlind) Teardown(ctx context.Context, env *core.Env) error { s.eng.stopEngine(); return nil }

func (s *sweptBlind) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	a := s.eng.actions()
	return len(a), a, nil
}

// SweptBlindIntervalsSeconds is the documented swept range (the existing d-r6blindtimer
// covers 15s; these add the rest of the frontier).
var SweptBlindIntervalsSeconds = []int{3, 6, 9, 12, 30, 60}

func init() {
	for _, iv := range SweptBlindIntervalsSeconds {
		d := time.Duration(iv) * time.Second
		core.RegisterDefender(&sweptBlind{interval: d, name: fmt.Sprintf("d-blind-%ds", iv)})
	}
}
