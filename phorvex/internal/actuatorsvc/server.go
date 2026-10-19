package actuatorsvc

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/actuatorpb"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/wire"
)

// Server serves an actuatorapi.Actuator over gRPC (actuatorpb.ActuatorService).
// Every answer, error included, travels in the response; a gRPC error means the
// request could not be decoded or the answer could not be encoded.
type Server struct {
	actuatorpb.UnimplementedActuatorServiceServer

	actuator      actuatorapi.Actuator
	configSHA256  string
	requiredVerbs []byte
}

var _ actuatorpb.ActuatorServiceServer = (*Server)(nil)

// NewServer serves act. configSHA256 is this process's actuatorapi.Config hash; a
// client presenting another is refused.
func NewServer(act actuatorapi.Actuator, configSHA256 string) (*Server, error) {
	verbs := map[model.Action][]authz.Verb{}
	for _, a := range knownActions() {
		if required := act.RequiredVerbs(a); len(required) > 0 {
			verbs[a] = required
		}
	}
	raw, err := wire.Encode(verbs)
	if err != nil {
		return nil, fmt.Errorf("required verbs: %w", err)
	}
	return &Server{actuator: act, configSHA256: configSHA256, requiredVerbs: raw}, nil
}

// knownActions are the actions an actuator can be asked about. Any other action
// needs no access, because no backend dispatches it.
func knownActions() []model.Action {
	return append([]model.Action{model.ActionNoop, model.ActionDisable}, model.MutatingActions...)
}

func (s *Server) Hello(_ context.Context, req *actuatorpb.HelloRequest) (*actuatorpb.HelloResponse, error) {
	if req.GetContractVersion() != actuatorapi.ContractVersion {
		return nil, status.Errorf(codes.FailedPrecondition, "actuator contract version %d, client %d", actuatorapi.ContractVersion, req.GetContractVersion())
	}
	if req.GetConfigSha256() != s.configSHA256 {
		return nil, status.Errorf(codes.FailedPrecondition, "actuator configuration differs: actuator %s, client %s", s.configSHA256, req.GetConfigSha256())
	}
	return &actuatorpb.HelloResponse{
		ContractVersion:         actuatorapi.ContractVersion,
		ConfigSha256:            s.configSHA256,
		Backend:                 string(s.actuator.Backend()),
		MaintainsStandingPolicy: s.actuator.MaintainsStandingPolicy(),
		RequiredVerbs:           s.requiredVerbs,
	}, nil
}

func (s *Server) SupportsAction(ctx context.Context, req *actuatorpb.SupportsActionRequest) (*actuatorpb.SupportsActionResponse, error) {
	var target actuatorapi.Target
	if err := wire.Decode(req.GetTarget(), &target); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "target: %v", err)
	}
	ok, why := s.actuator.SupportsAction(ctx, model.Action(req.GetAction()), target)
	return &actuatorpb.SupportsActionResponse{Ok: ok, Why: why}, nil
}

func (s *Server) CapabilityAdvisory(ctx context.Context, req *actuatorpb.CapabilityAdvisoryRequest) (*actuatorpb.CapabilityAdvisoryResponse, error) {
	var target actuatorapi.Target
	if err := wire.Decode(req.GetTarget(), &target); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "target: %v", err)
	}
	return &actuatorpb.CapabilityAdvisoryResponse{Advisory: s.actuator.CapabilityAdvisory(ctx, model.Action(req.GetAction()), target)}, nil
}

func (s *Server) ObserveStandingPolicy(ctx context.Context, req *actuatorpb.ObserveStandingPolicyRequest) (*actuatorpb.ObserveStandingPolicyResponse, error) {
	target, err := decodeTenantTarget(req.GetTarget())
	if err != nil {
		return nil, err
	}
	return &actuatorpb.ObserveStandingPolicyResponse{Result: actuatorpb.EncodePolicyMaintenance(s.actuator.ObserveStandingPolicy(ctx, target))}, nil
}

func (s *Server) ReconcileStandingPolicy(ctx context.Context, req *actuatorpb.ReconcileStandingPolicyRequest) (*actuatorpb.ReconcileStandingPolicyResponse, error) {
	target, err := decodeTenantTarget(req.GetTarget())
	if err != nil {
		return nil, err
	}
	return &actuatorpb.ReconcileStandingPolicyResponse{Result: actuatorpb.EncodePolicyMaintenance(s.actuator.ReconcileStandingPolicy(ctx, target))}, nil
}

func (s *Server) PrepareRoutes(ctx context.Context, req *actuatorpb.PrepareRoutesRequest) (*actuatorpb.PrepareRoutesResponse, error) {
	target, err := decodeTenantTarget(req.GetTarget())
	if err != nil {
		return nil, err
	}
	preparation, err := s.actuator.PrepareRoutes(ctx, target)
	return &actuatorpb.PrepareRoutesResponse{Preparation: actuatorpb.EncodeRoutePreparation(preparation), Error: actuatorpb.EncodeError(err)}, nil
}

func (s *Server) RetirePolicyBinding(ctx context.Context, req *actuatorpb.RetirePolicyBindingRequest) (*actuatorpb.RetirePolicyBindingResponse, error) {
	retained, err := s.actuator.RetirePolicyBinding(ctx, req.GetPolicyUid())
	return &actuatorpb.RetirePolicyBindingResponse{Retained: retained, Error: actuatorpb.EncodeError(err)}, nil
}

func (s *Server) RecoverOperations(ctx context.Context, req *actuatorpb.RecoverOperationsRequest) (*actuatorpb.RecoverOperationsResponse, error) {
	events, supported, err := s.actuator.RecoverOperations(ctx, req.GetGlobalKill())
	return &actuatorpb.RecoverOperationsResponse{Supported: supported, Events: actuatorpb.EncodeRecoveryEvents(events), Error: actuatorpb.EncodeError(err)}, nil
}

func (s *Server) QuarantineCapacity(ctx context.Context, req *actuatorpb.QuarantineCapacityRequest) (*actuatorpb.QuarantineCapacityResponse, error) {
	capacity := s.actuator.QuarantineCapacity(ctx, req.GetNamespace())
	return &actuatorpb.QuarantineCapacityResponse{Configured: capacity.Configured, Limit: int64(capacity.Limit),
		Known: capacity.Known, Used: int64(capacity.Used), Reason: capacity.Reason}, nil
}

func (s *Server) PendingOperation(ctx context.Context, req *actuatorpb.PendingOperationRequest) (*actuatorpb.PendingOperationResponse, error) {
	pending, err := s.actuator.PendingOperation(ctx, actuatorapi.PendingOperation{Kind: actuatorapi.PendingKind(req.GetKind()),
		Namespace: req.GetNamespace(), Pod: req.GetPod(), PodUID: req.GetPodUid()})
	return &actuatorpb.PendingOperationResponse{Pending: pending, Error: actuatorpb.EncodeError(err)}, nil
}

func (s *Server) Actuate(ctx context.Context, req *actuatorpb.ActuateRequest) (*actuatorpb.ActuateResponse, error) {
	var request actuatorapi.Request
	if err := wire.Decode(req.GetRequest(), &request); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "request: %v", err)
	}
	result, invoked, err := s.actuator.Actuate(ctx, request)
	raw, encodeErr := wire.Encode(result)
	if encodeErr != nil {
		return nil, status.Errorf(codes.Internal, "result: %v", encodeErr)
	}
	return &actuatorpb.ActuateResponse{Result: raw, Invoked: invoked, Error: actuatorpb.EncodeError(err)}, nil
}

func decodeTenantTarget(raw []byte) (actuatorapi.TenantTarget, error) {
	var target actuatorapi.TenantTarget
	if err := wire.Decode(raw, &target); err != nil {
		return target, status.Errorf(codes.InvalidArgument, "target: %v", err)
	}
	return target, nil
}
