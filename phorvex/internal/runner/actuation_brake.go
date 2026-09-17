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
	d.DispatchOutcome, d.DispatchReason = "", ""
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
			stampDispatchEvidence(d, model.DispatchNotAttempted, "namespace-dry-run")
		}
	} else if d.Selected {
		stampDispatchEvidence(d, model.DispatchNotAttempted, "namespace-dry-run")
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
			stampDispatchEvidence(d, model.DispatchNotAttempted, "policy-dry-run")
		}
	} else if d.Selected {
		stampDispatchEvidence(d, model.DispatchNotAttempted, "policy-dry-run")
	}
}

func stampTargetBrake(d *model.Decision, observation model.ActuationBrakeObservation) {
	clearDispatchEvidence(d)
	d.ActuationBrakeCause = observation.Cause
	if d.Trace != nil {
		d.Trace.ActuationBrakeCause = observation.Cause
	}
	stampDispatchEvidence(d, model.DispatchNotAttempted, "actuation-brake")
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
