package runner

import (
	"context"

	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/model"
)

type actuationBrakeTickState struct {
	namespace model.ActuationBrakeObservation
	pods      map[string]model.ActuationBrakeObservation
}

// Engaged Namespace and Pod observations are retained for the remainder of this
// tick. A late clear therefore resumes only on a later tick.
func (s *actuationBrakeTickState) observeNamespace(ctx context.Context, m *Manager, namespace string) model.ActuationBrakeObservation {
	if s.namespace.Engaged {
		return s.namespace
	}
	observation := actuationbrake.ObserveNamespace(ctx, m.BoundaryReader, m.ActuationBrakeReadTimeout, namespace)
	s.namespace = observation
	return observation
}

func (s *actuationBrakeTickState) observePod(ctx context.Context, m *Manager, namespace, pod, uid string) model.ActuationBrakeObservation {
	if uid == "" {
		return model.ActuationBrakeObservation{Engaged: true, Cause: actuationbrake.PodUIDChanged}
	}
	key := namespace + "\x00" + pod + "\x00" + uid
	if observation := s.pods[key]; observation.Engaged {
		return observation
	}
	observation := actuationbrake.ObservePod(ctx, m.BoundaryReader, m.ActuationBrakeReadTimeout, namespace, pod, uid)
	if observation.Engaged {
		if s.pods == nil {
			s.pods = map[string]model.ActuationBrakeObservation{}
		}
		s.pods[key] = observation
	}
	return observation
}

func clearDispatchEvidence(d *model.Decision) {
	d.Actuated = false
	d.Handler, d.RollbackRef, d.MutationKind = "", "", ""
	d.ObjectsTouched = nil
	d.Phoenix = nil
}

func stampNamespaceDryRun(d *model.Decision, observation model.ActuationBrakeObservation) {
	clearDispatchEvidence(d)
	d.DryRun = true
	d.DryRunCause = observation.Cause
	d.ActuationBrakeCause = observation.Cause
	if d.Trace != nil {
		d.Trace.DryRun = true
		d.Trace.DryRunCause = observation.Cause
		d.Trace.ActuationBrakeCause = observation.Cause
		if d.Selected {
			d.Trace.DispatchOutcome = model.DispatchNotAttempted
			d.Trace.DispatchReason = "namespace-dry-run: " + observation.Cause
		}
	}
}

func stampPolicyDryRun(d *model.Decision) {
	clearDispatchEvidence(d)
	d.DryRun = true
	d.DryRunCause = actuationbrake.PolicyDryRun
	if d.Trace != nil {
		d.Trace.DryRun = true
		d.Trace.DryRunCause = actuationbrake.PolicyDryRun
		if d.Selected {
			d.Trace.DispatchOutcome = model.DispatchNotAttempted
			d.Trace.DispatchReason = "policy-dry-run"
		}
	}
}

func stampTargetBrake(d *model.Decision, observation model.ActuationBrakeObservation) {
	clearDispatchEvidence(d)
	d.ActuationBrakeCause = observation.Cause
	if d.Trace != nil {
		d.Trace.ActuationBrakeCause = observation.Cause
		d.Trace.DispatchOutcome = model.DispatchNotAttempted
		d.Trace.DispatchReason = "actuation-brake: " + observation.Cause
	}
}

func hasPermittedTarget(decisions []model.Decision, views []*model.WorkloadView) bool {
	permitted := make(map[string]bool, len(views))
	for _, view := range views {
		if view != nil && !view.Pod.OptOut.Engaged {
			permitted[view.Pod.Namespace+"/"+view.Pod.Name] = true
		}
	}
	for _, decision := range decisions {
		if decision.Selected && decision.Feasible && decision.Action != model.ActionNoop && permitted[decision.Namespace+"/"+decision.Pod] {
			return true
		}
	}
	return false
}
