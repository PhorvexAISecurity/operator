package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type m019Hands struct {
	calls   []model.Action
	refusal error
	result  actuator.Result
}

func (*m019Hands) Name() string                                              { return "native" }
func (*m019Hands) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (h *m019Hands) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (h *m019Hands) Actuate(_ context.Context, r actuator.Request) (actuator.Result, error) {
	h.calls = append(h.calls, r.Action)
	if len(h.calls) == 1 {
		return h.result, h.refusal
	}
	return actuator.Result{Emitted: true}, nil
}

func m019Scenario(t *testing.T) (*decision.CoverageEngine, model.Policy, []*model.WorkloadView, []model.Decision) {
	t.Helper()
	ce := decision.NewCoverageEngine()
	exp := map[string]time.Duration{}
	for _, variable := range model.LiveExposureVariables {
		exp[variable] = 2 * time.Hour
	}
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "pod", UID: "pod-uid", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, MountedSecrets: []string{"creds"}}, Phase: model.PhaseWarm, BlastRadius: .6, ExposureByVariable: exp}
	pol := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TraceEnabled: true, BrainImage: "fixture", GitSHA: "fixture", Lambda: .4, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, MaxMovesPerTick: 1, ProactiveFloor: time.Hour, AntiOverRotationWindow: 5 * time.Minute, MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true}}
	ds, err := ce.DecideChecked([]*model.WorkloadView{v}, pol)
	if err != nil || len(ds) != 1 || !ds[0].Selected {
		t.Fatalf("real decision absent: %v %+v", err, ds)
	}
	if _, ok := ce.SelectAlternative(pol.Owner(), "ns/pod", ds[0].Action); !ok {
		t.Fatalf("real producer has no positive alternative: %+v", ds[0])
	}
	return ce, pol, []*model.WorkloadView{v}, ds
}

func TestM019CleanRefusalGetsOneReservedAlternative(t *testing.T) {
	ce, pol, views, ds := m019Scenario(t)
	lambdaAfterDecision := ce.Cost.Dual.Lambda()
	h := &m019Hands{refusal: actuator.RefusedWithoutEffect(errors.New("precondition unavailable"))}
	m := &Manager{Actuator: h, Optimizer: ce, Intents: exposure.NewIntents(), Log: logr.Discard()}
	n := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{"ns/pod": views[0]})
	if n != 1 || len(h.calls) != 2 || h.calls[0] == h.calls[1] {
		t.Fatalf("fallback not bounded/distinct: n=%d calls=%v", n, h.calls)
	}
	if got := ce.Cost.Dual.Lambda(); got != lambdaAfterDecision {
		t.Fatalf("fallback second-committed dual price: before=%g after=%g", lambdaAfterDecision, got)
	}
	if len(m.fallbackDecisions) != 1 || !m.fallbackDecisions[0].Actuated || m.fallbackDecisions[0].Trace.DispatchOutcome != model.DispatchEmitted || ds[0].Trace.DispatchOutcome != model.DispatchError {
		t.Fatalf("attempt evidence lost: initial=%+v fallback=%+v", ds[0], m.fallbackDecisions)
	}
	if err := m.fallbackDecisions[0].Trace.Validate(); err != nil {
		t.Fatalf("fallback trace invalid: %v", err)
	}
	if len(m.Intents.Since(pol.Owner(), "ns", "pod", time.Now())) != 1 {
		t.Fatal("initial failed action stamped success intent or fallback did not stamp")
	}
	if r := m.Failures.at[failureKey{pol.Owner(), "ns", "pod-uid", ds[0].Action}]; r.consecutive != 1 {
		t.Fatalf("failure feedback absent: %+v", r)
	}
}

func TestM019AmbiguousRefusalNeverGetsAlternative(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		result actuator.Result
	}{
		{"untyped", errors.New("unknown"), actuator.Result{}},
		{"partial", actuator.RefusedWithoutEffect(errors.New("claimed clean but touched")), actuator.Result{ObjectsTouched: []string{"pod/ns/pod"}}},
		{"deadline", context.DeadlineExceeded, actuator.Result{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ce, pol, views, ds := m019Scenario(t)
			h := &m019Hands{refusal: tc.err, result: tc.result}
			m := &Manager{Actuator: h, Optimizer: ce, Intents: exposure.NewIntents(), Log: logr.Discard()}
			if n := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{"ns/pod": views[0]}); n != 0 || len(h.calls) != 1 {
				t.Fatalf("ambiguous effect triggered fallback: n=%d calls=%v", n, h.calls)
			}
			if tc.name == "partial" || tc.name == "deadline" {
				if len(m.Failures.at) != 0 {
					t.Fatalf("uncertain or canceled effect entered failure cooldown: %+v", m.Failures.at)
				}
			}
		})
	}
}

func TestM019RealProducerExcludesRepeatedFailureAndShadowMatches(t *testing.T) {
	ce, pol, views, first := m019Scenario(t)
	failed := first[0].Action
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	var failures actionFailures
	k := failureKey{pol.Owner(), "ns", views[0].Pod.UID, failed}
	failures.observe(k, now)
	if _, cooled := failures.exclusion(k, now); cooled {
		t.Fatal("single transient failure cooled")
	}
	failures.observe(k, now.Add(time.Second))
	ce.FailureExclusion = func(v *model.WorkloadView, a model.Action) (string, bool) {
		return failures.exclusion(failureKey{pol.Owner(), v.Pod.Namespace, v.Pod.UID, a}, now.Add(2*time.Second))
	}
	production, err := ce.DecideChecked(views, pol)
	if err != nil || len(production) != 1 || !production[0].Selected || production[0].Action == failed {
		t.Fatalf("repeated failure not excluded by real producer: %v %+v", err, production)
	}
	shadow, err := ce.DecideShadowChecked(views, pol)
	if err != nil || shadow[0].Action != production[0].Action {
		t.Fatalf("shadow failure gate drift: %v %+v / %+v", err, production, shadow)
	}
	if production[0].Trace == nil {
		t.Fatal("failure decision lacks trace")
	}
	found := false
	for _, row := range production[0].Trace.ActionStatus {
		if row.Action == string(failed) {
			found = row.Status == model.ActionStatusIneligible && row.Reason != ""
		}
	}
	if !found {
		t.Fatalf("failure exclusion not narrated: %+v", production[0].Trace.ActionStatus)
	}
	failures.reset(k)
	if _, cooled := failures.exclusion(k, now.Add(2*time.Second)); cooled {
		t.Fatal("successful dispatch did not reset failure history")
	}
}

func TestM019OriginalKVVectorProducerFailsThenSelectsAlternative(t *testing.T) {
	ce, pol, views, _ := m019Scenario(t)
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("UCW producer unavailable")
	}
	ce.Recon = profile
	views[0].Pod.HasGPU = true
	views[0].Pod.ModelID = "served-model"
	views[0].Pod.ServingEndpointReady = true
	views[0].Physics = model.NeutralPhysics()
	views[0].Events = []model.SecurityEventInfo{{Name: "detector-kv", Type: model.AttackVectorKV, Source: "detector", TargetsPod: true}}
	pol.EnabledActions[model.ActionKVReset] = true
	baseline, err := ce.DecideChecked(views, pol)
	if err != nil || len(baseline) != 1 || !baseline[0].Selected || baseline[0].Action != model.ActionKVReset {
		t.Fatalf("KV attack producer did not choose failing move: %v %+v", err, baseline)
	}
	if _, ok := ce.SelectAlternative(pol.Owner(), "ns/pod", model.ActionKVReset); !ok {
		t.Fatal("positive control alternative absent")
	}
	var failures actionFailures
	now := time.Date(2026, 9, 15, 1, 54, 32, 0, time.UTC)
	k := failureKey{pol.Owner(), "ns", views[0].Pod.UID, model.ActionKVReset}
	failures.observe(k, now)
	failures.observe(k, now.Add(10*time.Second))
	ce.FailureExclusion = func(v *model.WorkloadView, a model.Action) (string, bool) {
		return failures.exclusion(failureKey{pol.Owner(), v.Pod.Namespace, v.Pod.UID, a}, now.Add(20*time.Second))
	}
	after, err := ce.DecideChecked(views, pol)
	if err != nil || len(after) != 1 || !after[0].Selected || after[0].Action == model.ActionKVReset {
		t.Fatalf("permanent KV failure repeated after cooldown feedback: %v %+v", err, after)
	}
}

func TestM019OriginalDeadEndpointRunnerLoopBoundedAtHead(t *testing.T) {
	ce, pol, views, _ := m019Scenario(t)
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("UCW producer unavailable")
	}
	ce.Recon = profile
	views[0].Pod.HasGPU, views[0].Pod.ModelID, views[0].Pod.ServingEndpointReady = true, "served-model", true
	views[0].Physics = model.NeutralPhysics()
	views[0].Events = []model.SecurityEventInfo{{Name: "detector-kv", Type: model.AttackVectorKV, Source: "detector", TargetsPod: true}}
	pol.EnabledActions[model.ActionKVReset] = true
	now := time.Date(2026, 9, 15, 1, 54, 32, 0, time.UTC)
	h := &m019Hands{refusal: errors.New("dead inference endpoint")}
	m := &Manager{Actuator: h, Optimizer: ce, Intents: exposure.NewIntents(), Log: logr.Discard(), FailureNow: func() time.Time { return now }}
	ce.FailureExclusion = func(v *model.WorkloadView, a model.Action) (string, bool) {
		return m.Failures.exclusion(failureKey{pol.Owner(), v.Pod.Namespace, v.Pod.UID, a}, now)
	}
	viewMap := map[string]*model.WorkloadView{"ns/pod": views[0]}
	for tick := 0; tick < 2; tick++ {
		ds, err := ce.DecideChecked(views, pol)
		if err != nil || len(ds) != 1 || !ds[0].Selected || ds[0].Action != model.ActionKVReset {
			t.Fatalf("incident action absent on tick %d: %v %+v", tick, err, ds)
		}
		h.calls = nil
		if n := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, viewMap); n != 0 || len(h.calls) != 1 || ds[0].Trace.DispatchOutcome != model.DispatchError {
			t.Fatalf("dead endpoint not reached: tick=%d n=%d calls=%v", tick, n, h.calls)
		}
		now = now.Add(10 * time.Second)
	}
	after, err := ce.DecideChecked(views, pol)
	if err != nil || len(after) != 1 || !after[0].Selected || after[0].Action != model.ActionQuarantine {
		t.Fatalf("permanent failure repeated instead of positive control: %v %+v", err, after)
	}
	if r := m.Failures.at[failureKey{pol.Owner(), "ns", "pod-uid", model.ActionKVReset}]; r.consecutive != 2 || !r.retry.After(now) {
		t.Fatalf("bounded feedback absent: %+v", r)
	}
}

func TestM019RetiredOwnerCannotReceiveLateFailureFeedback(t *testing.T) {
	ce, pol, views, ds := m019Scenario(t)
	h := &m019Hands{refusal: errors.New("late failure")}
	m := &Manager{Actuator: h, Optimizer: ce, Intents: exposure.NewIntents(), Log: logr.Discard(),
		epochsTracked: true, epochs: map[string]uint64{pol.Owner(): 2}, tickEpochs: map[string]uint64{pol.Owner(): 1}}
	if n := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{"ns/pod": views[0]}); n != 0 || len(h.calls) != 1 {
		t.Fatalf("late actuator path not exercised: n=%d calls=%v", n, h.calls)
	}
	if len(m.Failures.at) != 0 {
		t.Fatalf("stale generation acquired failure state: %+v", m.Failures.at)
	}
}
