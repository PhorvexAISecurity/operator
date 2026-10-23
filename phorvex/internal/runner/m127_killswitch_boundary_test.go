package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

type m127BoundaryActuator struct {
	name         string
	ensure       func(context.Context) error
	actuate      func(context.Context, actuator.Request) (actuator.Result, error)
	ensureCalls  int
	actuateCalls int
	recoverCalls int
}

type m127FailAfterReader struct {
	client.Reader
	failAfter int
	gets      int
}

func (r *m127FailAfterReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	r.gets++
	if r.gets > r.failAfter {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, key.Name, errors.New("read denied"))
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (a *m127BoundaryActuator) Name() string {
	if a.name != "" {
		return a.name
	}
	return "native"
}
func (a *m127BoundaryActuator) EnsurePolicy(ctx context.Context, _ actuator.TenantTarget) error {
	a.ensureCalls++
	if a.ensure != nil {
		return a.ensure(ctx)
	}
	return nil
}
func (a *m127BoundaryActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (a *m127BoundaryActuator) Actuate(ctx context.Context, request actuator.Request) (actuator.Result, error) {
	a.actuateCalls++
	if a.actuate != nil {
		return a.actuate(ctx, request)
	}
	return actuator.Result{Emitted: true}, nil
}
func (a *m127BoundaryActuator) RecoverOperations(context.Context, bool) ([]actuator.RecoveryEvent, error) {
	a.recoverCalls++
	return nil, nil
}

func m127SentinelClient(t *testing.T, engaged string) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(ksScheme()).WithObjects(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: DefaultKillSwitchName},
		Data:       map[string]string{"engaged": engaged},
	}).Build()
}

func m127SetSentinel(ctx context.Context, c client.Client, engaged string) error {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: "operator", Name: DefaultKillSwitchName}
	if err := c.Get(ctx, key, &cm); err != nil {
		return err
	}
	cm.Data["engaged"] = engaged
	return c.Update(ctx, &cm)
}

func m127FeasibleViews(names ...string) map[string]*model.WorkloadView {
	views := make(map[string]*model.WorkloadView, len(names))
	for _, name := range names {
		views["ns/"+name] = &model.WorkloadView{Pod: model.Pod{
			Namespace: "ns", Name: name, UID: "uid-" + name,
			Ready: true, DesiredReplicas: 3, ReadyReplicas: 3,
		}}
	}
	return views
}

func TestM127SentinelFlipAfterRoutePreparationRefusesDispatch(t *testing.T) {
	ctx := context.Background()
	c := m127SentinelClient(t, "false")
	var httpCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	hands := &m127BoundaryActuator{}
	hands.ensure = func(ctx context.Context) error { return m127SetSentinel(ctx, c, "true") }
	hands.actuate = func(ctx context.Context, _ actuator.Request) (actuator.Result, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, nil)
		if err != nil {
			return actuator.Result{}, err
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			return actuator.Result{}, err
		}
		defer resp.Body.Close()
		return actuator.Result{Emitted: resp.StatusCode == http.StatusAccepted}, nil
	}
	m := &Manager{
		Local:      &inprocess.Services{Actuator: hands},
		KillSwitch: &KillSwitch{Client: c, Namespace: "operator"},
		Log:        logr.Discard(),
	}
	decisions := tracedSelectedDecision()
	decisions[0].Handler = "stale-handler"
	decisions[0].ObjectsTouched = []string{"stale-object"}
	decisions[0].RollbackRef = "stale-receipt"
	decisions[0].MutationKind = "stale-kind"
	pol := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}

	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, pol, decisions, m127FeasibleViews("p1")); got != 0 {
		t.Fatalf("actuated = %d after sentinel flip", got)
	}
	if hands.ensureCalls != 1 || hands.actuateCalls != 0 || httpCalls.Load() != 0 {
		t.Fatalf("route/dispatch/HTTP calls = %d/%d/%d, want 1/0/0", hands.ensureCalls, hands.actuateCalls, httpCalls.Load())
	}
	d := decisions[0]
	if !d.KillSwitch || d.KillSwitchCause != string(KillSwitchSentinelEngaged) ||
		d.Trace.KillSwitchCause != string(KillSwitchSentinelEngaged) ||
		d.Trace.DispatchOutcome != model.DispatchNotAttempted ||
		d.Trace.DispatchReason != "kill-switch" {
		t.Fatalf("late refusal evidence = %+v trace=%+v", d, d.Trace)
	}
	if d.Actuated || d.Handler != "" || len(d.ObjectsTouched) != 0 || d.RollbackRef != "" || d.MutationKind != "" || d.Phoenix != nil {
		t.Fatalf("late refusal retained stale result metadata: %+v", d)
	}

	if err := m127SetSentinel(ctx, c, "false"); err != nil {
		t.Fatal(err)
	}
	hands.ensure = nil
	m.Intents = exposure.NewIntents()
	allowed := tracedSelectedDecision()
	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, pol, allowed, m127FeasibleViews("p1")); got != 1 || hands.actuateCalls != 1 || httpCalls.Load() != 1 {
		t.Fatalf("disengaged positive control got=%d dispatches=%d HTTP=%d trace=%+v", got, hands.actuateCalls, httpCalls.Load(), allowed[0].Trace)
	}
}

func TestM127SentinelFlipBetweenSelectedDispatchesStopsLaterMove(t *testing.T) {
	ctx := context.Background()
	c := m127SentinelClient(t, "false")
	hands := &m127BoundaryActuator{}
	hands.actuate = func(ctx context.Context, _ actuator.Request) (actuator.Result, error) {
		if hands.actuateCalls == 1 {
			if err := m127SetSentinel(ctx, c, "true"); err != nil {
				return actuator.Result{}, err
			}
		}
		return actuator.Result{Emitted: true}, nil
	}
	m := &Manager{
		Local:      &inprocess.Services{Actuator: hands},
		KillSwitch: &KillSwitch{Client: c, Namespace: "operator"},
		Intents:    exposure.NewIntents(),
		Log:        logr.Discard(),
	}
	decisions := tracedSelectedDecision()
	second := tracedSelectedDecision()[0]
	second.Pod = "p2"
	decisions = append(decisions, second)
	pol := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}

	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, pol, decisions, m127FeasibleViews("p1", "p2")); got != 1 {
		t.Fatalf("actuated = %d, want only first dispatch", got)
	}
	if hands.actuateCalls != 1 || !decisions[0].Actuated || decisions[1].Actuated {
		t.Fatalf("dispatches=%d decisions=%+v", hands.actuateCalls, decisions)
	}
	if decisions[1].KillSwitchCause != string(KillSwitchSentinelEngaged) ||
		decisions[1].Trace.DispatchOutcome != model.DispatchNotAttempted {
		t.Fatalf("second dispatch did not retain refusal cause: %+v", decisions[1])
	}
}

func TestM127EngagementAfterCleanRefusalSuppressesLearningAndFallback(t *testing.T) {
	ctx := context.Background()
	c := m127SentinelClient(t, "false")
	ce, pol, views, decisions := m019Scenario(t)
	hands := &m127BoundaryActuator{}
	hands.actuate = func(ctx context.Context, _ actuator.Request) (actuator.Result, error) {
		if err := m127SetSentinel(ctx, c, "true"); err != nil {
			return actuator.Result{}, err
		}
		return actuator.Result{}, actuator.RefusedWithoutEffect(errors.New("precondition unavailable"))
	}
	m := &Manager{
		Local:      &inprocess.Services{Actuator: hands, Optimizer: ce},
		KillSwitch: &KillSwitch{Client: c, Namespace: "operator"},
		Intents:    exposure.NewIntents(),
		Log:        logr.Discard(),
	}

	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, pol, decisions, map[string]*model.WorkloadView{"ns/pod": views[0]}); got != 0 {
		t.Fatalf("actuated = %d", got)
	}
	if hands.actuateCalls != 1 || len(m.fallbackDecisions) != 0 || len(m.Failures.at) != 0 {
		t.Fatalf("kill-switch allowed failure learning/fallback: calls=%d fallbacks=%d failures=%v", hands.actuateCalls, len(m.fallbackDecisions), m.Failures.at)
	}
	if _, ok := ce.SelectAlternative(pol.Owner(), "ns/pod", decisions[0].Action); !ok {
		t.Fatal("kill-switch path reserved the fallback slot despite refusing fallback")
	}
	if !decisions[0].KillSwitch || decisions[0].KillSwitchCause != string(KillSwitchSentinelEngaged) ||
		decisions[0].Trace.DispatchOutcome != model.DispatchRefused ||
		!strings.Contains(decisions[0].Trace.DispatchReason, "fallback-blocked-kill-switch") {
		t.Fatalf("refused fallback evidence = %+v trace=%+v", decisions[0], decisions[0].Trace)
	}
}

func TestM127DeniedPostFailureReadSuppressesLearningAndFallback(t *testing.T) {
	ctx := context.Background()
	c := m127SentinelClient(t, "false")
	reader := &m127FailAfterReader{Reader: c, failAfter: 2}
	ce, pol, views, decisions := m019Scenario(t)
	hands := &m127BoundaryActuator{}
	hands.actuate = func(context.Context, actuator.Request) (actuator.Result, error) {
		return actuator.Result{}, actuator.RefusedWithoutEffect(errors.New("precondition unavailable"))
	}
	m := &Manager{
		Local:      &inprocess.Services{Actuator: hands, Optimizer: ce},
		KillSwitch: &KillSwitch{Client: reader, Namespace: "operator"},
		Intents:    exposure.NewIntents(),
		Log:        logr.Discard(),
	}

	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, pol, decisions, map[string]*model.WorkloadView{"ns/pod": views[0]}); got != 0 {
		t.Fatalf("actuated = %d", got)
	}
	if reader.gets != 3 || hands.actuateCalls != 1 || len(m.fallbackDecisions) != 0 || len(m.Failures.at) != 0 {
		t.Fatalf("denied read allowed failure learning/fallback: reads=%d calls=%d fallbacks=%d failures=%v", reader.gets, hands.actuateCalls, len(m.fallbackDecisions), m.Failures.at)
	}
	if _, ok := ce.SelectAlternative(pol.Owner(), "ns/pod", decisions[0].Action); !ok {
		t.Fatal("denied read path reserved the fallback slot")
	}
	if decisions[0].KillSwitchCause != string(KillSwitchReadError) ||
		!strings.Contains(decisions[0].Trace.DispatchReason, "fallback-blocked-kill-switch") {
		t.Fatalf("denied-read refusal evidence = %+v trace=%+v", decisions[0], decisions[0].Trace)
	}
}

func TestM127AutomaticMaintenanceRechecksSentinel(t *testing.T) {
	ctx := context.Background()
	c := m127SentinelClient(t, "true")
	hands := &m127BoundaryActuator{}
	m := &Manager{
		Local:      &inprocess.Services{Actuator: hands},
		KillSwitch: &KillSwitch{Client: c, Namespace: "operator"},
		Log:        logr.Discard(),
	}

	got := m.reconcileWedged(ctx, KillSwitchObservation{Cause: KillSwitchSentinelDisengaged})
	if !got.Engaged || got.Cause != KillSwitchSentinelEngaged || hands.recoverCalls != 0 {
		t.Fatalf("maintenance was not refused after fresh observation: got=%+v calls=%d", got, hands.recoverCalls)
	}
	if err := m127SetSentinel(ctx, c, "false"); err != nil {
		t.Fatal(err)
	}
	got = m.reconcileWedged(ctx, KillSwitchObservation{Cause: KillSwitchSentinelDisengaged})
	if got.Engaged || got.Cause != KillSwitchSentinelDisengaged || hands.recoverCalls != 1 {
		t.Fatalf("disengaged maintenance positive control: got=%+v calls=%d", got, hands.recoverCalls)
	}
}
