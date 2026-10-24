package runner

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/actuatorclient"
	"github.com/phorvex/phorvex/internal/actuatorpb"
	"github.com/phorvex/phorvex/internal/actuatorsvc"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

// Only the apiserver is substituted: dispatcher and executor have independent
// credentials, represented by independent SSAR clients. All service/gate code is real.
type remoteAccessReviews struct {
	mu      sync.Mutex
	allowed bool
	err     error
	calls   []authorizationv1.ResourceAttributes
}

func (r *remoteAccessReviews) Create(_ context.Context, review *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, *review.Spec.ResourceAttributes)
	return &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: r.allowed}}, r.err
}

func (r *remoteAccessReviews) reviewed() []authorizationv1.ResourceAttributes {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]authorizationv1.ResourceAttributes(nil), r.calls...)
}

func remoteAccessManager(t *testing.T, checker *authz.Checker) (*Manager, *remoteAccessReviews) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	config := actuatorapi.Config{OperatorNamespace: "phorvex-staging"}
	local := &actuatorsvc.Local{Actuator: actuator.NewNativeActuator(nil), Access: checker}
	service, err := actuatorsvc.NewServer(local, config.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	actuatorpb.RegisterActuatorServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///actuator",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	remote, err := actuatorclient.New(ctx, conn, actuatorclient.Options{Config: config})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &remoteAccessReviews{allowed: false}
	return &Manager{ActuatorService: remote, Authz: authz.NewCheckerWithClient(dispatcher, time.Minute)}, dispatcher
}

func TestRemoteExecutorAuthorizationOffersAndSelectsRotate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed bool
		err     error
	}{
		{name: "dispatcher-denied-executor-allowed", allowed: true},
		{name: "executor-denied"},
		{name: "executor-review-error", err: errors.New("apiserver unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor := &remoteAccessReviews{allowed: tc.allowed, err: tc.err}
			now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
			checker := authz.NewCheckerWithClock(executor, time.Minute, func() time.Time { return now })
			m, dispatcher := remoteAccessManager(t, checker)
			pod := model.Pod{Namespace: "phorvex-staging-demo", Name: "demo-api", UID: "victim-uid",
				Ready: true, DesiredReplicas: 3, ReadyReplicas: 3}
			view := &model.WorkloadView{Pod: pod, Phase: model.PhaseWarm,
				ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour}}
			witness := capability.BuildWitness(t.Context(), capability.BuildIndex([]model.Pod{pod}, nil, nil), nil, m.access(), m.actuation())
			gate := capabilityGate(witness, m.access() == nil, noQualified)
			if ok, why := witness.Capable(view, model.ActionRotate); !ok {
				t.Fatalf("fixture must reach the RBAC leg: %s", why)
			}
			keys := []string{"pod-identity"}
			if got := gate.ShadowCapability(view, model.ActionRotate, keys); got == nil || got.Excluded || !got.RBACUnknown || len(executor.reviewed()) != 0 {
				t.Fatalf("unreviewed shadow must remain unknown without a review: %+v", got)
			}
			pol := model.Policy{Tenant: "demo", Namespace: pod.Namespace, PolicyUID: "policy-uid", PolicyName: "defense",
				TraceEnabled: true, BrainImage: "fixture", GitSHA: "fixture", DryRun: true,
				MaxMovesPerTick: 1, ProactiveFloor: time.Minute, CostCeiling: 10, MinAvailableReplicas: 1,
				EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
			engine := decision.NewCoverageEngine()
			engine.Now = func() time.Time { return now }
			engine.Capability, engine.ShadowCapability = gate.Capability, gate.ShadowCapability
			decisions, err := engine.DecideChecked([]*model.WorkloadView{view}, pol)
			if err != nil || len(decisions) != 1 || decisions[0].Trace == nil {
				t.Fatalf("decision trace unavailable: %v %+v", err, decisions)
			}
			d := decisions[0]
			wantSelected := tc.allowed || tc.err != nil
			if d.Selected != wantSelected || (wantSelected && d.Action != model.ActionRotate) {
				t.Fatalf("rotate selected=%v, want %v: action=%s reason=%s", d.Selected, wantSelected, d.Action, d.Reason)
			}
			var status *model.DecisionActionStatusV3
			for i := range d.Trace.ActionStatus {
				if d.Trace.ActionStatus[i].Action == string(model.ActionRotate) {
					status = &d.Trace.ActionStatus[i]
				}
			}
			if status == nil || (wantSelected && status.Status != model.ActionStatusSelected) || (!wantSelected && status.ExclusionKind != capability.ReasonNoRBAC) {
				t.Fatalf("rotate must be selected or explicitly denied by executor RBAC: %+v", status)
			}
			got := gate.Capability(view, model.ActionRotate, keys)
			if tc.err != nil && (got == nil || got.Excluded || !got.RBACUnknown) {
				t.Fatalf("review error must fail open with unknown evidence: %+v", got)
			}
			wantCalls := 1
			if tc.err != nil {
				wantCalls = 2 // errors must not be cached
			}
			wantReview := authorizationv1.ResourceAttributes{Namespace: pod.Namespace, Resource: "pods", Subresource: "eviction", Verb: "create"}
			reviews := executor.reviewed()
			if len(reviews) != wantCalls {
				t.Fatalf("executor reviews=%d, want %d", len(reviews), wantCalls)
			}
			for _, review := range reviews {
				if review != wantReview {
					t.Fatalf("reviewed the wrong operation: %+v", review)
				}
			}
			now = now.Add(time.Minute)
			if got := gate.ShadowCapability(view, model.ActionRotate, keys); got == nil || got.Excluded || !got.RBACUnknown || len(executor.reviewed()) != wantCalls {
				t.Fatalf("expired shadow must not refresh authorization: %+v", got)
			}
			gate.Capability(view, model.ActionRotate, keys)
			if len(executor.reviewed()) != wantCalls+1 {
				t.Fatal("production must refresh expired authorization")
			}
			if reviews := dispatcher.reviewed(); len(reviews) != 0 {
				t.Fatalf("dispatcher credentials reached the gate: %+v", reviews)
			}
		})
	}
}

func TestRemoteExecutorReviewsEveryWorkloadActionsVerbs(t *testing.T) {
	executor := &remoteAccessReviews{allowed: true}
	m, dispatcher := remoteAccessManager(t, authz.NewCheckerWithClient(executor, time.Minute))
	for _, action := range []model.Action{model.ActionRotate, model.ActionWarmSwap, model.ActionQuarantine, model.ActionMIGRebind} {
		t.Run(string(action), func(t *testing.T) {
			verbs := m.actuation().RequiredVerbs(action)
			if want := actuator.RequiredVerbsForBackend(actuator.BackendNative, action); len(verbs) == 0 || !reflect.DeepEqual(verbs, want) {
				t.Fatalf("native route verbs differ: got %+v, want %+v", verbs, want)
			}
			if allowed, unknown, why := m.access().AccessAllowed(t.Context(), "phorvex-staging-demo", verbs); !allowed || unknown {
				t.Fatalf("executor must answer authorization for %s: %s", action, why)
			}
		})
	}
	if len(executor.reviewed()) == 0 || len(dispatcher.reviewed()) != 0 {
		t.Fatal("workload action reviews must use only the executor identity")
	}
}
