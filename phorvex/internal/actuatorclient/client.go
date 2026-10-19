// Package actuatorclient is the dispatcher's side of the actuator service
// (ADR-0001): an actuatorapi.Actuator that acts through a separate actuator over
// gRPC.
//
// It keeps the in-process contract and fails closed. An unanswered capability
// question reads as unsupported, an unanswered fence as unresolved, unanswered
// capacity as unknown, and an unanswered route preparation or standing-policy
// call as a refusal of the routes the backend owns. An Actuate the service did
// not answer may have reached the backend: it reports the backend invoked, with
// an error that is never a refusal without effect.
package actuatorclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/actuatorpb"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/wire"
)

const defaultCallTimeout = 30 * time.Second

// Options configures a Client.
type Options struct {
	// Config is the dispatcher's actuator configuration. The actuator refuses a
	// client whose configuration differs from its own.
	Config actuatorapi.Config
	// CallTimeout bounds each question within the caller's own deadline. Zero
	// means 30 seconds. Calls that may mutate (Actuate, ReconcileStandingPolicy,
	// PrepareRoutes, RecoverOperations) are bounded only by the caller, as in
	// process, so a slow mutation is never cancelled halfway by the client.
	CallTimeout time.Duration
}

// Client is an actuatorapi.Actuator served by a remote actuator.
type Client struct {
	rpc                     actuatorpb.ActuatorServiceClient
	timeout                 time.Duration
	backend                 actuatorapi.Backend
	maintainsStandingPolicy bool
	requiredVerbs           map[model.Action][]authz.Verb
}

var _ actuatorapi.Actuator = (*Client)(nil)

// New checks the actuator's contract version and configuration over conn,
// waiting for the actuator until ctx ends. It fails when the actuator cannot be
// reached or refuses the client.
func New(ctx context.Context, conn grpc.ClientConnInterface, opt Options) (*Client, error) {
	if opt.CallTimeout <= 0 {
		opt.CallTimeout = defaultCallTimeout
	}
	c := &Client{rpc: actuatorpb.NewActuatorServiceClient(conn), timeout: opt.CallTimeout}
	hello, err := c.rpc.Hello(ctx, &actuatorpb.HelloRequest{ContractVersion: actuatorapi.ContractVersion, ConfigSha256: opt.Config.SHA256()},
		grpc.WaitForReady(true))
	if err != nil {
		return nil, fmt.Errorf("actuator service hello: %w", err)
	}
	if err := wire.Decode(hello.GetRequiredVerbs(), &c.requiredVerbs); err != nil {
		return nil, fmt.Errorf("actuator service hello: required verbs: %w", err)
	}
	c.backend = actuatorapi.Backend(hello.GetBackend())
	c.maintainsStandingPolicy = hello.GetMaintainsStandingPolicy()
	return c, nil
}

func (c *Client) Backend() actuatorapi.Backend { return c.backend }

func (c *Client) RequiredVerbs(a model.Action) []authz.Verb {
	verbs := c.requiredVerbs[a]
	if verbs == nil {
		return nil
	}
	return append([]authz.Verb{}, verbs...)
}

func (c *Client) MaintainsStandingPolicy() bool { return c.maintainsStandingPolicy }

func (c *Client) SupportsAction(ctx context.Context, a model.Action, t actuatorapi.Target) (bool, string) {
	target, err := wire.Encode(t)
	if err != nil {
		return false, actuatorapi.ReasonBackendUnavailable + ": actuator service: target: " + err.Error()
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.SupportsAction(ctx, &actuatorpb.SupportsActionRequest{Action: string(a), Target: target})
	if err != nil {
		return false, actuatorapi.ReasonBackendUnavailable + ": " + callFailed(ctx, "supports-action", err).Error()
	}
	return resp.GetOk(), resp.GetWhy()
}

// CapabilityAdvisory is posture only; an unanswered question advises nothing.
func (c *Client) CapabilityAdvisory(ctx context.Context, a model.Action, t actuatorapi.Target) string {
	target, err := wire.Encode(t)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.CapabilityAdvisory(ctx, &actuatorpb.CapabilityAdvisoryRequest{Action: string(a), Target: target})
	if err != nil {
		return ""
	}
	return resp.GetAdvisory()
}

func (c *Client) ObserveStandingPolicy(ctx context.Context, target actuatorapi.TenantTarget) actuatorapi.PolicyMaintenanceResult {
	raw, err := wire.Encode(target)
	if err != nil {
		return c.maintenanceFailed(fmt.Errorf("actuator service: target: %w", err))
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.ObserveStandingPolicy(ctx, &actuatorpb.ObserveStandingPolicyRequest{Target: raw})
	if err != nil {
		return c.maintenanceFailed(callFailed(ctx, "observe-standing-policy", err))
	}
	return actuatorpb.DecodePolicyMaintenance(resp.GetResult())
}

func (c *Client) ReconcileStandingPolicy(ctx context.Context, target actuatorapi.TenantTarget) actuatorapi.PolicyMaintenanceResult {
	raw, err := wire.Encode(target)
	if err != nil {
		return c.maintenanceFailed(fmt.Errorf("actuator service: target: %w", err))
	}
	resp, err := c.rpc.ReconcileStandingPolicy(ctx, &actuatorpb.ReconcileStandingPolicyRequest{Target: raw})
	if err != nil {
		return c.maintenanceFailed(callFailed(ctx, "reconcile-standing-policy", err))
	}
	return actuatorpb.DecodePolicyMaintenance(resp.GetResult())
}

func (c *Client) PrepareRoutes(ctx context.Context, target actuatorapi.TenantTarget) (actuatorapi.RoutePreparation, error) {
	raw, err := wire.Encode(target)
	if err != nil {
		err = fmt.Errorf("actuator service: target: %w", err)
		return c.preparationFailed(err), err
	}
	resp, err := c.rpc.PrepareRoutes(ctx, &actuatorpb.PrepareRoutesRequest{Target: raw})
	if err != nil {
		err = callFailed(ctx, "prepare-routes", err)
		return c.preparationFailed(err), err
	}
	return actuatorpb.DecodeRoutePreparation(resp.GetPreparation()), actuatorpb.DecodeError(resp.GetError())
}

func (c *Client) RetirePolicyBinding(ctx context.Context, policyUID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.RetirePolicyBinding(ctx, &actuatorpb.RetirePolicyBindingRequest{PolicyUid: policyUID})
	if err != nil {
		return false, callFailed(ctx, "retire-policy-binding", err)
	}
	return resp.GetRetained(), actuatorpb.DecodeError(resp.GetError())
}

// RecoverOperations reports an unanswered call as a failed journal read: whether
// the actuator keeps journals is then unknown, and the failure must be seen.
func (c *Client) RecoverOperations(ctx context.Context, globalKill bool) ([]actuatorapi.RecoveryEvent, bool, error) {
	resp, err := c.rpc.RecoverOperations(ctx, &actuatorpb.RecoverOperationsRequest{GlobalKill: globalKill})
	if err != nil {
		return nil, true, callFailed(ctx, "recover-operations", err)
	}
	return actuatorpb.DecodeRecoveryEvents(resp.GetEvents()), resp.GetSupported(), actuatorpb.DecodeError(resp.GetError())
}

// QuarantineCapacity reports an unanswered call as a configured bound whose usage
// is unknown, which admits no new quarantine.
func (c *Client) QuarantineCapacity(ctx context.Context, namespace string) actuatorapi.QuarantineCapacity {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.QuarantineCapacity(ctx, &actuatorpb.QuarantineCapacityRequest{Namespace: namespace})
	if err != nil {
		return actuatorapi.QuarantineCapacity{Configured: true, Reason: callFailed(ctx, "quarantine-capacity", err).Error()}
	}
	return actuatorapi.QuarantineCapacity{Configured: resp.GetConfigured(), Limit: int(resp.GetLimit()),
		Known: resp.GetKnown(), Used: int(resp.GetUsed()), Reason: resp.GetReason()}
}

// PendingOperation reports an unanswered fence as unresolved.
func (c *Client) PendingOperation(ctx context.Context, q actuatorapi.PendingOperation) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.PendingOperation(ctx, &actuatorpb.PendingOperationRequest{Kind: string(q.Kind),
		Namespace: q.Namespace, Pod: q.Pod, PodUid: q.PodUID})
	if err != nil {
		return true, callFailed(ctx, "pending-operation", err)
	}
	return resp.GetPending(), actuatorpb.DecodeError(resp.GetError())
}

// Actuate reports a move the service did not answer as possibly enacted.
func (c *Client) Actuate(ctx context.Context, req actuatorapi.Request) (actuatorapi.Result, bool, error) {
	raw, err := wire.Encode(req)
	if err != nil {
		return actuatorapi.Result{}, false, fmt.Errorf("actuator service: request: %w", err)
	}
	resp, err := c.rpc.Actuate(ctx, &actuatorpb.ActuateRequest{Request: raw})
	if err != nil {
		return actuatorapi.Result{}, true, callFailed(ctx, "actuate", err)
	}
	var result actuatorapi.Result
	if err := wire.Decode(resp.GetResult(), &result); err != nil {
		return actuatorapi.Result{}, true, fmt.Errorf("actuator service: result: %w", err)
	}
	return result, resp.GetInvoked(), actuatorpb.DecodeError(resp.GetError())
}

// maintenanceFailed is the standing-policy result of a call the actuator did not
// answer: the routes the backend owns are unknown and refused for this tick.
func (c *Client) maintenanceFailed(err error) actuatorapi.PolicyMaintenanceResult {
	unknown := actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceUnknown, Detail: err.Error()}
	result := actuatorapi.PolicyMaintenanceResult{Preparation: c.preparationFailed(err), Phoenix: unknown, Native: unknown}
	switch c.backend {
	case actuatorapi.BackendNative:
		result.Phoenix = actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceNotRequired, Detail: "Phoenix route not required"}
	case actuatorapi.BackendPhoenix:
		result.Native = actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceNotRequired, Detail: "native route not required"}
	}
	return result
}

// preparationFailed refuses the routes the backend owns.
func (c *Client) preparationFailed(err error) actuatorapi.RoutePreparation {
	switch c.backend {
	case actuatorapi.BackendNative:
		return actuatorapi.RoutePreparation{PhoenixSkipped: true, NativeErr: err}
	case actuatorapi.BackendPhoenix:
		return actuatorapi.RoutePreparation{PhoenixErr: err, NativeSkipped: true}
	}
	return actuatorapi.RoutePreparation{PhoenixErr: err, NativeErr: err}
}

// callFailed is the error of a call the actuator did not answer. When the call's
// context ended it wraps that context error, as the backend's own would.
func callFailed(ctx context.Context, method string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("actuator service: %s: %w", method, ctxErr)
	}
	return fmt.Errorf("actuator service: %s: %w", method, err)
}
