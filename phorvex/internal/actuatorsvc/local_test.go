package actuatorsvc

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
)

// plainBackend implements only the required actuator surface.
type plainBackend struct {
	name      string
	ensureErr error
	ensured   int
	actuated  int
}

func (p *plainBackend) Name() string { return p.name }
func (p *plainBackend) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	p.ensured++
	return p.ensureErr
}
func (p *plainBackend) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	p.actuated++
	return actuator.Result{Emitted: true, Handler: "plain"}, nil
}
func (p *plainBackend) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return false, "plain-why"
}

// fullBackend adds every optional capability the dispatcher discovers.
type fullBackend struct {
	plainBackend
	retired []string
	kill    []bool
}

func (f *fullBackend) ObserveStandingPolicy(context.Context, actuator.TenantTarget) actuator.PolicyMaintenanceResult {
	return actuator.PolicyMaintenanceResult{Phoenix: actuator.PolicyRouteMaintenance{State: actuator.PolicyMaintenanceDrifted}}
}
func (f *fullBackend) ReconcileStandingPolicy(context.Context, actuator.TenantTarget) actuator.PolicyMaintenanceResult {
	return actuator.PolicyMaintenanceResult{Phoenix: actuator.PolicyRouteMaintenance{State: actuator.PolicyMaintenanceRepaired}}
}
func (f *fullBackend) PrepareRoutes(context.Context, actuator.TenantTarget) actuator.RoutePreparation {
	return actuator.RoutePreparation{NativeSkipped: true}
}
func (f *fullBackend) RetirePolicyBinding(uid string) { f.retired = append(f.retired, uid) }
func (f *fullBackend) RecoverOperations(_ context.Context, globalKill bool) ([]actuator.RecoveryEvent, error) {
	f.kill = append(f.kill, globalKill)
	return []actuator.RecoveryEvent{{Receipt: "r1", Outcome: "restored"}}, nil
}
func (f *fullBackend) CapabilityAdvisory(model.Action, actuator.Target) string { return "advice" }

func TestLocalDiscoversOptionalCapabilitiesAsTheRunnerDid(t *testing.T) {
	ctx := context.Background()
	plain := &Local{Actuator: &plainBackend{name: "plain"}}
	if retained, err := plain.RetirePolicyBinding(ctx, "uid"); retained || err != nil {
		t.Fatalf("a plain backend retired a binding: %v %v", retained, err)
	}
	if plain.MaintainsStandingPolicy() || plain.CapabilityAdvisory(ctx, model.ActionRotate, actuatorapi.Target{}) != "" {
		t.Fatal("a plain backend reported optional capabilities")
	}
	if events, supported, err := plain.RecoverOperations(ctx, false); supported || events != nil || err != nil {
		t.Fatalf("a plain backend recovered operations: %v %v %v", events, supported, err)
	}
	if got := plain.ObserveStandingPolicy(ctx, actuatorapi.TenantTarget{}); !reflect.DeepEqual(got, actuatorapi.PolicyMaintenanceResult{}) {
		t.Fatalf("a plain backend observed standing policy: %+v", got)
	}

	backend := &fullBackend{plainBackend: plainBackend{name: "native"}}
	full := &Local{Actuator: backend}
	if !full.MaintainsStandingPolicy() {
		t.Fatal("standing-policy maintenance not discovered")
	}
	if got := full.ObserveStandingPolicy(ctx, actuatorapi.TenantTarget{}).Phoenix.State; got != actuatorapi.PolicyMaintenanceDrifted {
		t.Fatalf("observe = %s", got)
	}
	if got := full.ReconcileStandingPolicy(ctx, actuatorapi.TenantTarget{}).Phoenix.State; got != actuatorapi.PolicyMaintenanceRepaired {
		t.Fatalf("reconcile = %s", got)
	}
	if retained, err := full.RetirePolicyBinding(ctx, "uid-1"); !retained || err != nil || !reflect.DeepEqual(backend.retired, []string{"uid-1"}) {
		t.Fatalf("binding retirement not delegated: %v %v %v", retained, err, backend.retired)
	}
	events, supported, err := full.RecoverOperations(ctx, true)
	if !supported || err != nil || len(events) != 1 || events[0].Receipt != "r1" || !reflect.DeepEqual(backend.kill, []bool{true}) {
		t.Fatalf("recovery = %v %v %v kill=%v", events, supported, err, backend.kill)
	}
	if full.CapabilityAdvisory(ctx, model.ActionRotate, actuatorapi.Target{}) != "advice" {
		t.Fatal("advisory not delegated")
	}
}

func TestLocalPreparesRoutesOrEnsuresPolicy(t *testing.T) {
	ctx := context.Background()
	routed := &Local{Actuator: &fullBackend{plainBackend: plainBackend{name: "hybrid"}}}
	if prep, err := routed.PrepareRoutes(ctx, actuatorapi.TenantTarget{}); err != nil || !prep.NativeSkipped {
		t.Fatalf("route preparation not delegated: %+v %v", prep, err)
	}
	refused := errors.New("amtd refused")
	for _, tc := range []struct {
		name        string
		wantNative  bool
		wantPhoenix bool
	}{{"native", true, false}, {"phoenix", false, true}, {"other", false, true}} {
		backend := &plainBackend{name: tc.name, ensureErr: refused}
		prep, err := (&Local{Actuator: backend}).PrepareRoutes(ctx, actuatorapi.TenantTarget{})
		if !errors.Is(err, refused) || backend.ensured != 1 {
			t.Fatalf("%s: EnsurePolicy failure not returned: %v", tc.name, err)
		}
		if (prep.NativeErr != nil) != tc.wantNative || (prep.PhoenixErr != nil) != tc.wantPhoenix {
			t.Fatalf("%s: refusal on the wrong leg: %+v", tc.name, prep)
		}
	}
}

func TestLocalActuatesAndReportsTheRouteTable(t *testing.T) {
	backend := &plainBackend{name: "native"}
	l := &Local{Actuator: backend}
	res, invoked, err := l.Actuate(context.Background(), actuatorapi.Request{Action: model.ActionRotate})
	if err != nil || !invoked || !res.Emitted || backend.actuated != 1 {
		t.Fatalf("unbounded actuation = %+v invoked=%v err=%v", res, invoked, err)
	}
	if got := l.QuarantineCapacity(context.Background(), "ns"); got.Configured {
		t.Fatalf("no ledger, yet capacity configured: %+v", got)
	}
	if ok, why := l.SupportsAction(context.Background(), model.ActionRotate, actuatorapi.Target{}); ok || why != "plain-why" {
		t.Fatal("support not delegated")
	}
	if l.Backend() != actuatorapi.BackendNative {
		t.Fatalf("backend = %s", l.Backend())
	}
	if got, want := l.RequiredVerbs(model.ActionRotate), actuator.RequiredVerbsForBackend(actuator.BackendNative, model.ActionRotate); !reflect.DeepEqual(got, want) {
		t.Fatalf("verbs = %v, want the native backend's %v", got, want)
	}
	double := &Local{Actuator: &plainBackend{name: "test-double"}}
	if got, want := double.RequiredVerbs(model.ActionQuarantine), actuator.RequiredVerbsForBackend(actuator.BackendHybrid, model.ActionQuarantine); !reflect.DeepEqual(got, want) {
		t.Fatalf("a non-production backend name must use the hybrid verbs: %v, want %v", got, want)
	}
}

func TestUnknownPendingOperationKindIsNeverClear(t *testing.T) {
	pending, err := (&Local{Actuator: &plainBackend{}}).PendingOperation(context.Background(), actuatorapi.PendingOperation{Kind: "future-journal"})
	if !pending || err == nil || !strings.Contains(err.Error(), "future-journal") {
		t.Fatalf("unknown journal kind = %v, %v", pending, err)
	}
}

// namespaceReviews allows every verb outside the denied namespace.
type namespaceReviews struct {
	denied string
	calls  int
}

func (r *namespaceReviews) Create(_ context.Context, sar *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	r.calls++
	sar.Status.Allowed = sar.Spec.ResourceAttributes.Namespace != r.denied
	return sar, nil
}

func TestLocalReviewsAccessWithItsOwnChecker(t *testing.T) {
	ctx := context.Background()
	if (&Local{Actuator: &plainBackend{}}).ReviewsAccess() {
		t.Fatal("a Local without a checker reviews access")
	}
	reviews := &namespaceReviews{denied: "locked"}
	l := &Local{Actuator: &plainBackend{}, Access: authz.NewCheckerWithClient(reviews, time.Minute)}
	verbs := []authz.Verb{{Resource: "pods", Verb: "delete"}}
	if !l.ReviewsAccess() {
		t.Fatal("a Local with a checker does not review access")
	}
	if _, unknown, _ := l.AccessObserved(ctx, "vllm", verbs); !unknown || reviews.calls != 0 {
		t.Fatalf("an observation without a held review must be unknown and issue none: unknown=%v calls=%d", unknown, reviews.calls)
	}
	if allowed, unknown, _ := l.AccessAllowed(ctx, "vllm", verbs); !allowed || unknown || reviews.calls != 1 {
		t.Fatalf("review = allowed %v unknown %v calls %d", allowed, unknown, reviews.calls)
	}
	if allowed, unknown, _ := l.AccessObserved(ctx, "vllm", verbs); !allowed || unknown || reviews.calls != 1 {
		t.Fatalf("observation of a held review = allowed %v unknown %v calls %d", allowed, unknown, reviews.calls)
	}
	if allowed, unknown, why := l.AccessAllowed(ctx, "locked", verbs); allowed || unknown || why == "" {
		t.Fatalf("denied review = allowed %v unknown %v why %q", allowed, unknown, why)
	}
}
