package actuatorpb

import (
	"context"
	"errors"

	"github.com/phorvex/phorvex/internal/actuatorapi"
)

// EncodeError carries err across the wire. A nil error stays nil.
func EncodeError(err error) *Error {
	if err == nil {
		return nil
	}
	return &Error{
		Message:          err.Error(),
		NoEffectRefusal:  actuatorapi.IsNoEffectRefusal(err),
		DeadlineExceeded: errors.Is(err, context.DeadlineExceeded),
		Canceled:         errors.Is(err, context.Canceled),
	}
}

// DecodeError restores an error EncodeError carried: the same text, a
// NoEffectRefusal when it was one, matching the context errors it wrapped.
func DecodeError(e *Error) error {
	if e == nil {
		return nil
	}
	err := &remoteError{message: e.GetMessage(), deadline: e.GetDeadlineExceeded(), canceled: e.GetCanceled()}
	if e.GetNoEffectRefusal() {
		return actuatorapi.NoEffectRefusal{Err: err}
	}
	return err
}

// remoteError is an error the actuator service returned.
type remoteError struct {
	message            string
	deadline, canceled bool
}

func (e *remoteError) Error() string { return e.message }

// Is matches the context errors the actuator's error wrapped.
func (e *remoteError) Is(target error) bool {
	return e.deadline && target == context.DeadlineExceeded || e.canceled && target == context.Canceled
}

func EncodeRoutePreparation(p actuatorapi.RoutePreparation) *RoutePreparation {
	return &RoutePreparation{
		PhoenixError:   EncodeError(p.PhoenixErr),
		NativeError:    EncodeError(p.NativeErr),
		PhoenixSkipped: p.PhoenixSkipped,
		NativeSkipped:  p.NativeSkipped,
	}
}

func DecodeRoutePreparation(p *RoutePreparation) actuatorapi.RoutePreparation {
	return actuatorapi.RoutePreparation{
		PhoenixErr:     DecodeError(p.GetPhoenixError()),
		NativeErr:      DecodeError(p.GetNativeError()),
		PhoenixSkipped: p.GetPhoenixSkipped(),
		NativeSkipped:  p.GetNativeSkipped(),
	}
}

func EncodePolicyMaintenance(r actuatorapi.PolicyMaintenanceResult) *PolicyMaintenanceResult {
	return &PolicyMaintenanceResult{
		Preparation: EncodeRoutePreparation(r.Preparation),
		Phoenix:     &RouteMaintenance{State: string(r.Phoenix.State), Detail: r.Phoenix.Detail},
		Native:      &RouteMaintenance{State: string(r.Native.State), Detail: r.Native.Detail},
	}
}

func DecodePolicyMaintenance(r *PolicyMaintenanceResult) actuatorapi.PolicyMaintenanceResult {
	return actuatorapi.PolicyMaintenanceResult{
		Preparation: DecodeRoutePreparation(r.GetPreparation()),
		Phoenix:     actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceState(r.GetPhoenix().GetState()), Detail: r.GetPhoenix().GetDetail()},
		Native:      actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceState(r.GetNative().GetState()), Detail: r.GetNative().GetDetail()},
	}
}

func EncodeRecoveryEvents(events []actuatorapi.RecoveryEvent) []*RecoveryEvent {
	if events == nil {
		return nil
	}
	out := make([]*RecoveryEvent, len(events))
	for i, ev := range events {
		out[i] = &RecoveryEvent{
			Receipt: ev.Receipt, Kind: ev.Kind, Phase: ev.Phase, Tenant: ev.Tenant,
			PolicyNamespace: ev.PolicyNamespace, PolicyName: ev.PolicyName, PolicyUid: ev.PolicyUID,
			TargetName: ev.TargetName, TargetUid: ev.TargetUID, Outcome: ev.Outcome, Effect: ev.Effect,
			Error: EncodeError(ev.Err),
		}
	}
	return out
}

func DecodeRecoveryEvents(events []*RecoveryEvent) []actuatorapi.RecoveryEvent {
	if events == nil {
		return nil
	}
	out := make([]actuatorapi.RecoveryEvent, len(events))
	for i, ev := range events {
		out[i] = actuatorapi.RecoveryEvent{
			Receipt: ev.GetReceipt(), Kind: ev.GetKind(), Phase: ev.GetPhase(), Tenant: ev.GetTenant(),
			PolicyNamespace: ev.GetPolicyNamespace(), PolicyName: ev.GetPolicyName(), PolicyUID: ev.GetPolicyUid(),
			TargetName: ev.GetTargetName(), TargetUID: ev.GetTargetUid(), Outcome: ev.GetOutcome(), Effect: ev.GetEffect(),
			Err: DecodeError(ev.GetError()),
		}
	}
	return out
}
