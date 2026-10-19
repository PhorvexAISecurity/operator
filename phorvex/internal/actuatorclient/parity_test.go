package actuatorclient_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/actuatorclient"
	"github.com/phorvex/phorvex/internal/actuatorpb"
	"github.com/phorvex/phorvex/internal/actuatorsvc"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/wire"
)

var testConfig = actuatorapi.Config{OperatorNamespace: "phorvex-system", TrustedDetectors: []string{"vllm/detector", "batch/detector"}}

func TestWireTypesRoundTripStructurally(t *testing.T) {
	if problems := wire.Problems(actuatorapi.Target{}, actuatorapi.TenantTarget{}, actuatorapi.Request{}, actuatorapi.Result{},
		map[model.Action][]authz.Verb{}); len(problems) > 0 {
		t.Fatalf("types crossing the actuator wire would not survive CBOR:\n  %s", strings.Join(problems, "\n  "))
	}
}

// serve runs act behind a gRPC server on an in-memory listener.
func serve(t *testing.T, act actuatorapi.Actuator) (*grpc.ClientConn, *grpc.Server) {
	t.Helper()
	server, err := actuatorsvc.NewServer(act, testConfig.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(wire.MaxMessageBytes), grpc.MaxSendMsgSize(wire.MaxMessageBytes))
	actuatorpb.RegisterActuatorServiceServer(srv, server)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///actuator",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(wire.MaxMessageBytes)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, srv
}

func connect(t *testing.T, act actuatorapi.Actuator, opt actuatorclient.Options) (*actuatorclient.Client, *grpc.Server) {
	t.Helper()
	conn, srv := serve(t, act)
	opt.Config = testConfig
	client, err := actuatorclient.New(context.Background(), conn, opt)
	if err != nil {
		t.Fatal(err)
	}
	return client, srv
}

var (
	refusal  = actuatorapi.RefusedWithoutEffect(errors.New("serving receipt differs"))
	deadline = fmt.Errorf("journal read: %w", context.DeadlineExceeded)
	plain    = errors.New("amtd refused")
	coverage = 0.75
	created  = time.Date(2026, 10, 19, 9, 30, 0, 123, time.UTC)
)

// scripted answers every contract call with fixed values, varied by its input
// so a dropped argument shows, and records what it was asked.
type scripted struct {
	backend actuatorapi.Backend
	// hold, when set, makes Actuate and SupportsAction wait for it or their context.
	hold chan struct{}

	mu       sync.Mutex
	targets  []actuatorapi.Target
	tenants  []actuatorapi.TenantTarget
	requests []actuatorapi.Request
	pending  []actuatorapi.PendingOperation
	canceled int
}

var _ actuatorapi.Actuator = (*scripted)(nil)

func (s *scripted) wait(ctx context.Context) error {
	if s.hold == nil {
		return nil
	}
	select {
	case <-s.hold:
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		s.canceled++
		s.mu.Unlock()
		return ctx.Err()
	}
}

func (s *scripted) Backend() actuatorapi.Backend { return s.backend }
func (s *scripted) RequiredVerbs(a model.Action) []authz.Verb {
	switch a {
	case model.ActionRotate:
		return []authz.Verb{{Resource: "pods", Subresource: "eviction", Verb: "create"}}
	case model.ActionVoiceSessionAdmissionEnforce:
		return []authz.Verb{{Resource: "configmaps", Name: "journal", Verb: "update", OperatorScoped: true}, {Group: "apps", Resource: "deployments", Verb: "get", ClusterScoped: true}}
	case model.ActionQuarantine:
		return []authz.Verb{} // empty: needs no access
	}
	return nil
}
func (s *scripted) SupportsAction(ctx context.Context, a model.Action, target actuatorapi.Target) (bool, string) {
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return false, "waited: " + err.Error()
	}
	return a == model.ActionRotate, "why-" + string(a) + "-" + target.Pod
}
func (s *scripted) CapabilityAdvisory(_ context.Context, a model.Action, target actuatorapi.Target) string {
	return "advice-" + string(a) + "-" + target.NodeName
}
func (s *scripted) MaintainsStandingPolicy() bool { return true }
func (s *scripted) maintenance(target actuatorapi.TenantTarget, state actuatorapi.PolicyMaintenanceState) actuatorapi.PolicyMaintenanceResult {
	s.mu.Lock()
	s.tenants = append(s.tenants, target)
	s.mu.Unlock()
	return actuatorapi.PolicyMaintenanceResult{
		Preparation: actuatorapi.RoutePreparation{PhoenixErr: plain, NativeSkipped: true},
		Phoenix:     actuatorapi.PolicyRouteMaintenance{State: state, Detail: "phoenix-" + target.PolicyUID},
		Native:      actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceNotRequired, Detail: "native route not required"},
	}
}
func (s *scripted) ObserveStandingPolicy(_ context.Context, target actuatorapi.TenantTarget) actuatorapi.PolicyMaintenanceResult {
	return s.maintenance(target, actuatorapi.PolicyMaintenanceDrifted)
}
func (s *scripted) ReconcileStandingPolicy(_ context.Context, target actuatorapi.TenantTarget) actuatorapi.PolicyMaintenanceResult {
	return s.maintenance(target, actuatorapi.PolicyMaintenanceRepaired)
}
func (s *scripted) PrepareRoutes(_ context.Context, target actuatorapi.TenantTarget) (actuatorapi.RoutePreparation, error) {
	if target.Tenant == "refused" {
		return actuatorapi.RoutePreparation{NativeErr: plain}, plain
	}
	return actuatorapi.RoutePreparation{NativeErr: refusal, PhoenixSkipped: true}, nil
}
func (s *scripted) RetirePolicyBinding(_ context.Context, uid string) (bool, error) {
	if uid == "broken" {
		return false, plain
	}
	return uid != "", nil
}
func (s *scripted) RecoverOperations(_ context.Context, globalKill bool) ([]actuatorapi.RecoveryEvent, bool, error) {
	if globalKill {
		return nil, true, deadline
	}
	return []actuatorapi.RecoveryEvent{
		{Receipt: "r1", Kind: "native-quarantine", Phase: "rollback", Tenant: "t", PolicyNamespace: "vllm", PolicyName: "p",
			PolicyUID: "puid", TargetName: "web-0", TargetUID: "uid-web-0", Outcome: "restored", Effect: "removed"},
		{Receipt: "r2", Kind: "endpoint-lease", Outcome: "refused", Err: refusal},
	}, true, nil
}
func (s *scripted) QuarantineCapacity(_ context.Context, namespace string) actuatorapi.QuarantineCapacity {
	if namespace == "unread" {
		return actuatorapi.QuarantineCapacity{Configured: true, Limit: 2, Reason: "inventory unreadable"}
	}
	return actuatorapi.QuarantineCapacity{Configured: true, Limit: 3, Known: true, Used: len(namespace)}
}
func (s *scripted) PendingOperation(_ context.Context, q actuatorapi.PendingOperation) (bool, error) {
	s.mu.Lock()
	s.pending = append(s.pending, q)
	s.mu.Unlock()
	if q.Kind == actuatorapi.PendingVoiceOutput {
		return true, deadline
	}
	return q.Kind == actuatorapi.PendingEndpointLease, nil
}
func (s *scripted) Actuate(ctx context.Context, req actuatorapi.Request) (actuatorapi.Result, bool, error) {
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return actuatorapi.Result{Note: "interrupted"}, true, err
	}
	switch req.Reason {
	case "capacity":
		return actuatorapi.Result{Note: "capacity exhausted"}, false, refusal
	case "partial":
		return actuatorapi.Result{Emitted: true, Handler: string(req.Action), ObjectsTouched: []string{"pod/" + req.Pod}, MutationKind: "partial"}, true, plain
	}
	return actuatorapi.Result{
		Actuator: "native", Emitted: true, Handler: string(req.Action), ObjectsTouched: []string{"pod/" + req.Pod, "networkpolicy/q"},
		RollbackRef: "rb-1", MutationKind: "reversible", EventUID: "e-uid", NoEffect: actuatorapi.NoEffectUnknown,
		GracefulTermination: &model.GracefulTerminationReceipt{PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, EffectiveGracePeriodSeconds: req.MaxGracePeriodSeconds, PodUID: req.TargetUID},
		DrainOperation:      &model.DrainOperationEvidence{OperationID: req.OperationID, SnapshotRequests: []string{"sha"}},
	}, true, nil
}

// sameError reports whether got keeps want's text and the identities the
// dispatcher branches on.
func sameError(t *testing.T, what string, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("%s: error %v, want %v", what, got, want)
	}
	if want == nil {
		return
	}
	if got.Error() != want.Error() ||
		actuatorapi.IsNoEffectRefusal(got) != actuatorapi.IsNoEffectRefusal(want) ||
		errors.Is(got, context.DeadlineExceeded) != errors.Is(want, context.DeadlineExceeded) ||
		errors.Is(got, context.Canceled) != errors.Is(want, context.Canceled) {
		t.Fatalf("%s: error %q (refusal=%v deadline=%v), want %q (refusal=%v deadline=%v)", what,
			got, actuatorapi.IsNoEffectRefusal(got), errors.Is(got, context.DeadlineExceeded),
			want, actuatorapi.IsNoEffectRefusal(want), errors.Is(want, context.DeadlineExceeded))
	}
}

func samePreparation(t *testing.T, what string, got, want actuatorapi.RoutePreparation) {
	t.Helper()
	sameError(t, what+" phoenix", got.PhoenixErr, want.PhoenixErr)
	sameError(t, what+" native", got.NativeErr, want.NativeErr)
	if got.PhoenixSkipped != want.PhoenixSkipped || got.NativeSkipped != want.NativeSkipped {
		t.Fatalf("%s: skipped %v/%v, want %v/%v", what, got.PhoenixSkipped, got.NativeSkipped, want.PhoenixSkipped, want.NativeSkipped)
	}
}

func sameMaintenance(t *testing.T, what string, got, want actuatorapi.PolicyMaintenanceResult) {
	t.Helper()
	samePreparation(t, what, got.Preparation, want.Preparation)
	if got.Phoenix != want.Phoenix || got.Native != want.Native {
		t.Fatalf("%s: routes %+v/%+v, want %+v/%+v", what, got.Phoenix, got.Native, want.Phoenix, want.Native)
	}
}

func tenantTargets() []actuatorapi.TenantTarget {
	return []actuatorapi.TenantTarget{
		{Tenant: "t", Namespace: "vllm", PolicyName: "p", PolicyUID: "puid", Generation: 7, PolicyOwnerCount: 1,
			MatchLabels: map[string]string{"app": "web"},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}}}},
			EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: false}},
		// A nil action set keeps the default policy's meaning, an empty one enables nothing.
		{Tenant: "default", Namespace: "vllm", PolicyUID: "nil-actions"},
		{Tenant: "none", Namespace: "vllm", PolicyUID: "no-actions", EnabledActions: map[model.Action]bool{}},
	}
}

func TestClientAnswersAsTheActuatorDoes(t *testing.T) {
	ctx := context.Background()
	want := &scripted{backend: actuatorapi.BackendHybrid}
	got := &scripted{backend: actuatorapi.BackendHybrid}
	client, _ := connect(t, got, actuatorclient.Options{})

	if client.Backend() != actuatorapi.BackendHybrid || !client.MaintainsStandingPolicy() {
		t.Fatalf("hello answers: backend=%s maintains=%v", client.Backend(), client.MaintainsStandingPolicy())
	}
	for _, a := range append([]model.Action{model.ActionNoop, model.ActionDisable, "future-action"}, model.MutatingActions...) {
		if g, w := client.RequiredVerbs(a), want.RequiredVerbs(a); len(g) != len(w) || len(w) > 0 && !reflect.DeepEqual(g, w) {
			t.Fatalf("required verbs for %s = %+v, want %+v", a, g, w)
		}
	}
	verbs := client.RequiredVerbs(model.ActionRotate)
	verbs[0].Verb = "mutated"
	if client.RequiredVerbs(model.ActionRotate)[0].Verb != "create" {
		t.Fatal("a caller's change to the verbs reached the client's table")
	}

	target := actuatorapi.Target{Namespace: "vllm", Pod: "web-0", UID: "uid-web-0", Labels: map[string]string{"app": "web"},
		NodeName: "node-1", HasGPU: true, MIGResource: "nvidia.com/mig-1g.10gb", PolicyName: "p", PolicyUID: "puid", ServiceAccount: "sa"}
	for _, a := range []model.Action{model.ActionRotate, model.ActionMIGRebind} {
		gotOK, gotWhy := client.SupportsAction(ctx, a, target)
		wantOK, wantWhy := want.SupportsAction(ctx, a, target)
		if gotOK != wantOK || gotWhy != wantWhy {
			t.Fatalf("supports %s = %v %q, want %v %q", a, gotOK, gotWhy, wantOK, wantWhy)
		}
		if g, w := client.CapabilityAdvisory(ctx, a, target), want.CapabilityAdvisory(ctx, a, target); g != w {
			t.Fatalf("advisory %s = %q, want %q", a, g, w)
		}
	}
	if !reflect.DeepEqual(got.targets, want.targets) {
		t.Fatalf("targets reached the actuator as %+v, want %+v", got.targets, want.targets)
	}

	for _, tenant := range tenantTargets() {
		sameMaintenance(t, "observe", client.ObserveStandingPolicy(ctx, tenant), want.ObserveStandingPolicy(ctx, tenant))
		sameMaintenance(t, "reconcile", client.ReconcileStandingPolicy(ctx, tenant), want.ReconcileStandingPolicy(ctx, tenant))
	}
	if !reflect.DeepEqual(got.tenants, want.tenants) {
		t.Fatalf("tenant targets reached the actuator as %+v, want %+v", got.tenants, want.tenants)
	}
	// Each target was observed, then reconciled.
	if got.tenants[2].EnabledActions != nil || got.tenants[4].EnabledActions == nil {
		t.Fatal("a nil action set and an empty one must stay distinct")
	}
	for _, tenant := range []actuatorapi.TenantTarget{{Tenant: "t"}, {Tenant: "refused"}} {
		gotPrep, gotErr := client.PrepareRoutes(ctx, tenant)
		wantPrep, wantErr := want.PrepareRoutes(ctx, tenant)
		samePreparation(t, "prepare "+tenant.Tenant, gotPrep, wantPrep)
		sameError(t, "prepare "+tenant.Tenant, gotErr, wantErr)
	}

	for _, uid := range []string{"puid", "", "broken"} {
		gotRetained, gotErr := client.RetirePolicyBinding(ctx, uid)
		wantRetained, wantErr := want.RetirePolicyBinding(ctx, uid)
		if gotRetained != wantRetained {
			t.Fatalf("retire %q = %v, want %v", uid, gotRetained, wantRetained)
		}
		sameError(t, "retire "+uid, gotErr, wantErr)
	}

	for _, kill := range []bool{false, true} {
		gotEvents, gotSupported, gotErr := client.RecoverOperations(ctx, kill)
		wantEvents, wantSupported, wantErr := want.RecoverOperations(ctx, kill)
		sameError(t, "recover", gotErr, wantErr)
		if gotSupported != wantSupported || len(gotEvents) != len(wantEvents) {
			t.Fatalf("recover(kill=%v) = %d events supported=%v, want %d supported=%v", kill, len(gotEvents), gotSupported, len(wantEvents), wantSupported)
		}
		for i := range wantEvents {
			sameError(t, "recovery event", gotEvents[i].Err, wantEvents[i].Err)
			gotEvents[i].Err, wantEvents[i].Err = nil, nil
			if gotEvents[i] != wantEvents[i] {
				t.Fatalf("recovery event %+v, want %+v", gotEvents[i], wantEvents[i])
			}
		}
	}

	for _, ns := range []string{"vllm", "unread"} {
		if g, w := client.QuarantineCapacity(ctx, ns), want.QuarantineCapacity(ctx, ns); g != w {
			t.Fatalf("capacity %s = %+v, want %+v", ns, g, w)
		}
	}

	for _, kind := range []actuatorapi.PendingKind{actuatorapi.PendingEndpointLease, actuatorapi.PendingLiteLLMClient, actuatorapi.PendingVoiceOutput} {
		q := actuatorapi.PendingOperation{Kind: kind, Namespace: "vllm", Pod: "web-0", PodUID: "uid-web-0"}
		gotPending, gotErr := client.PendingOperation(ctx, q)
		wantPending, wantErr := want.PendingOperation(ctx, q)
		if gotPending != wantPending {
			t.Fatalf("pending %s = %v, want %v", kind, gotPending, wantPending)
		}
		sameError(t, "pending "+string(kind), gotErr, wantErr)
	}
	if !reflect.DeepEqual(got.pending, want.pending) {
		t.Fatalf("fences reached the actuator as %+v, want %+v", got.pending, want.pending)
	}

	request := actuatorapi.Request{
		AdapterObservation: &model.AdapterObservation{EventName: "ev", EventUID: "ev-uid", CreatorIdentity: "vllm/detector", TargetPodUID: "uid-web-0", AdapterName: "lora-a", CreatedAt: created},
		ServingObservation: &actuatorapi.ServingSelectionObservation{KVReset: model.OwnedValue{Present: true, Value: "v1"}, Guardrail: model.OwnedValue{Present: true}},
		TargetUID:          "uid-web-0", TargetNamespaceUID: "ns-uid", OperationID: "op-1", TickID: "tick-9",
		PolicyName: "p", PolicyUID: "puid", PolicyGeneration: 7, MaxGracePeriodSeconds: 30,
		Tenant: "t", Namespace: "vllm", Pod: "web-0", Action: model.ActionQuarantine, Reason: "selected", Score: 0.42, CoverageValue: &coverage,
	}
	for _, reason := range []string{"selected", "capacity", "partial"} {
		request.Reason = reason
		gotResult, gotInvoked, gotErr := client.Actuate(ctx, request)
		wantResult, wantInvoked, wantErr := want.Actuate(ctx, request)
		sameError(t, "actuate "+reason, gotErr, wantErr)
		if gotInvoked != wantInvoked || !reflect.DeepEqual(gotResult, wantResult) {
			t.Fatalf("actuate %s = %+v invoked=%v, want %+v invoked=%v", reason, gotResult, gotInvoked, wantResult, wantInvoked)
		}
	}
	if !reflect.DeepEqual(got.requests, want.requests) {
		t.Fatalf("requests reached the actuator as\n  %+v\nwant\n  %+v", got.requests, want.requests)
	}
}

func TestHelloRefusesAnotherContractOrConfiguration(t *testing.T) {
	conn, _ := serve(t, &scripted{backend: actuatorapi.BackendNative})
	other := testConfig
	other.EndpointLeaseApprovedSource = "sha256:other"
	if _, err := actuatorclient.New(context.Background(), conn, actuatorclient.Options{Config: other}); status.Code(errors.Unwrap(err)) != codes.FailedPrecondition {
		t.Fatalf("a client with another configuration was accepted: %v", err)
	}
	reordered := testConfig
	reordered.TrustedDetectors = []string{"batch/detector", "vllm/detector"}
	if _, err := actuatorclient.New(context.Background(), conn, actuatorclient.Options{Config: reordered}); err != nil {
		t.Fatalf("the same detectors in another order were refused: %v", err)
	}
	_, err := actuatorpb.NewActuatorServiceClient(conn).Hello(context.Background(),
		&actuatorpb.HelloRequest{ContractVersion: actuatorapi.ContractVersion + 1, ConfigSha256: testConfig.SHA256()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a client of another contract version was accepted: %v", err)
	}
}

// TestUnansweredCallsFailClosed stops the actuator after the handshake: every
// answer the dispatcher acts on must then refuse, and an actuation must read as
// possibly enacted.
func TestUnansweredCallsFailClosed(t *testing.T) {
	for _, backend := range []actuatorapi.Backend{actuatorapi.BackendNative, actuatorapi.BackendPhoenix, actuatorapi.BackendHybrid} {
		t.Run(string(backend), func(t *testing.T) {
			client, srv := connect(t, &scripted{backend: backend}, actuatorclient.Options{CallTimeout: time.Second})
			srv.Stop()
			ctx := context.Background()
			tenant := tenantTargets()[0]

			if ok, why := client.SupportsAction(ctx, model.ActionRotate, actuatorapi.Target{}); ok || !strings.HasPrefix(why, actuatorapi.ReasonBackendUnavailable+": ") {
				t.Fatalf("unanswered support = %v %q", ok, why)
			}
			if advisory := client.CapabilityAdvisory(ctx, model.ActionRotate, actuatorapi.Target{}); advisory != "" {
				t.Fatalf("unanswered advisory = %q", advisory)
			}
			for name, result := range map[string]actuatorapi.PolicyMaintenanceResult{
				"observe": client.ObserveStandingPolicy(ctx, tenant), "reconcile": client.ReconcileStandingPolicy(ctx, tenant),
			} {
				for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
					if result.Preparation.ForAction(a) == nil {
						t.Fatalf("unanswered %s left %s dispatchable: %+v", name, a, result.Preparation)
					}
				}
				if result.Phoenix.State == actuatorapi.PolicyMaintenanceInSync || result.Native.State == actuatorapi.PolicyMaintenanceInSync {
					t.Fatalf("unanswered %s reads in sync: %+v", name, result)
				}
			}
			preparation, err := client.PrepareRoutes(ctx, tenant)
			if err == nil || preparation.ForAction(model.ActionRotate) == nil || preparation.ForAction(model.ActionQuarantine) == nil {
				t.Fatalf("unanswered route preparation = %+v, %v", preparation, err)
			}
			if retained, err := client.RetirePolicyBinding(ctx, "puid"); retained || err == nil {
				t.Fatalf("unanswered retirement = %v, %v", retained, err)
			}
			if events, supported, err := client.RecoverOperations(ctx, false); !supported || err == nil || events != nil {
				t.Fatalf("unanswered recovery = %v %v %v", events, supported, err)
			}
			if capacity := client.QuarantineCapacity(ctx, "vllm"); !capacity.Configured || capacity.Known || capacity.Reason == "" {
				t.Fatalf("unanswered capacity = %+v", capacity)
			}
			if pending, err := client.PendingOperation(ctx, actuatorapi.PendingOperation{Kind: actuatorapi.PendingEndpointLease}); !pending || err == nil {
				t.Fatalf("unanswered fence = %v, %v", pending, err)
			}
			if _, invoked, err := client.Actuate(ctx, actuatorapi.Request{Action: model.ActionRotate}); !invoked || err == nil || actuatorapi.IsNoEffectRefusal(err) {
				t.Fatalf("unanswered actuation = invoked %v, %v", invoked, err)
			}
		})
	}
}

func TestActuationKeepsTheCallersDeadline(t *testing.T) {
	act := &scripted{backend: actuatorapi.BackendNative, hold: make(chan struct{})}
	client, _ := connect(t, act, actuatorclient.Options{CallTimeout: 20 * time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, invoked, err := client.Actuate(ctx, actuatorapi.Request{Action: model.ActionRotate})
	if !invoked || !errors.Is(err, context.DeadlineExceeded) || actuatorapi.IsNoEffectRefusal(err) {
		t.Fatalf("expired actuation = invoked %v, %v", invoked, err)
	}
	if ctx.Err() == nil {
		t.Fatal("the actuation ended before the caller's deadline: the call timeout bounded a mutation")
	}
	until := time.Now().Add(5 * time.Second)
	for {
		act.mu.Lock()
		canceled := act.canceled
		act.mu.Unlock()
		if canceled == 1 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("the actuator never saw the caller's deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}

	started := time.Now()
	ok, why := client.SupportsAction(context.Background(), model.ActionRotate, actuatorapi.Target{})
	if ok || !strings.Contains(why, context.DeadlineExceeded.Error()) || time.Since(started) > 5*time.Second {
		t.Fatalf("a held question = %v %q after %s; the call timeout must bound it", ok, why, time.Since(started))
	}
}

// TestLocalBackendServedRemotely runs the in-process adapter over a backend
// behind the gRPC server, the way the actuator service runs it.
func TestLocalBackendServedRemotely(t *testing.T) {
	backend := &recordingBackend{}
	client, _ := connect(t, &actuatorsvc.Local{Actuator: backend}, actuatorclient.Options{})
	if client.Backend() != actuatorapi.BackendNative || !reflect.DeepEqual(client.RequiredVerbs(model.ActionRotate), (&actuatorsvc.Local{Actuator: backend}).RequiredVerbs(model.ActionRotate)) {
		t.Fatalf("hello answers: backend=%s", client.Backend())
	}
	res, invoked, err := client.Actuate(context.Background(), actuatorapi.Request{Action: model.ActionRotate, Namespace: "vllm", Pod: "web-0", CoverageValue: &coverage})
	if err != nil || !invoked || !res.Emitted || len(backend.requests) != 1 || *backend.requests[0].CoverageValue != coverage {
		t.Fatalf("actuation = %+v invoked=%v err=%v requests=%+v", res, invoked, err, backend.requests)
	}
	if _, err := client.PrepareRoutes(context.Background(), actuatorapi.TenantTarget{Tenant: "t"}); !actuatorapi.IsNoEffectRefusal(err) {
		t.Fatalf("an EnsurePolicy refusal lost its identity: %v", err)
	}
}

type recordingBackend struct{ requests []actuatorapi.Request }

func (*recordingBackend) Name() string { return "native" }
func (*recordingBackend) EnsurePolicy(context.Context, actuatorapi.TenantTarget) error {
	return actuatorapi.RefusedWithoutEffect(errors.New("policy refused"))
}
func (b *recordingBackend) Actuate(_ context.Context, req actuatorapi.Request) (actuatorapi.Result, error) {
	b.requests = append(b.requests, req)
	return actuatorapi.Result{Emitted: true, Handler: string(req.Action)}, nil
}
func (*recordingBackend) SupportsAction(context.Context, model.Action, actuatorapi.Target) (bool, string) {
	return true, ""
}
