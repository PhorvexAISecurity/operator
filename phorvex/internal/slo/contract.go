/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package slo

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// PathKind names the execution outcome whose phases are being bounded.
type PathKind string

const (
	PathSuccess        PathKind = "success"
	PathFailure        PathKind = "failure"
	PathDeadlineExpiry PathKind = "deadline_expiry"
	PathRollback       PathKind = "rollback"
)

// Phase is one serial phase, or a conservative composite of parallel phases.
//
// A replica-losing phase is bounded only when the deadline is enforced and its
// expiry stops the unsafe work or transfers control to another bounded phase.
// Merely returning an error to the caller does not satisfy StopsAtDeadline.
type Phase struct {
	Name                   string
	MaxUnavailableReplicas int
	Deadline               time.Duration
	DeadlineEnforced       bool
	StopsAtDeadline        bool
	BoundSource            string

	// Parallel holds phases that execute concurrently. The composite uses the
	// longest deadline and maximum simultaneous replica loss, as required by the
	// PHORVEXSEC-145 conservative-envelope rule.
	Parallel []Phase
}

// ExecutionPath is one permitted success, failure, deadline-expiry, or rollback
// path. SafeReturnVerified must be true for any path that can lose a replica.
type ExecutionPath struct {
	Name               string
	Kind               PathKind
	Phases             []Phase
	SafeReturnVerified bool
}

// ActionContract is the complete deterministic contract for one action.
// EnumerationComplete is deliberately explicit: an incomplete path inventory
// cannot accidentally turn the paths that happened to be listed into a bound.
type ActionContract struct {
	Action              model.Action
	Paths               []ExecutionPath
	EnumerationComplete bool
	Provenance          string
}

type phaseImpact struct {
	maxReplicas   int
	lossDuration  time.Duration
	replicaSecond float64
	bounded       bool
	missing       string
}

func evaluatePhase(phase Phase) phaseImpact {
	if len(phase.Parallel) > 0 {
		out := phaseImpact{bounded: true}
		for _, child := range phase.Parallel {
			impact := evaluatePhase(child)
			if impact.maxReplicas > out.maxReplicas {
				out.maxReplicas = impact.maxReplicas
			}
			if impact.lossDuration > out.lossDuration {
				out.lossDuration = impact.lossDuration
			}
			if !impact.bounded {
				out.bounded = false
				out.missing = appendMissing(out.missing, impact.missing)
			}
		}
		out.replicaSecond = float64(out.maxReplicas) * out.lossDuration.Seconds()
		return out
	}

	if phase.MaxUnavailableReplicas <= 0 {
		return phaseImpact{bounded: true}
	}
	impact := phaseImpact{
		maxReplicas:   phase.MaxUnavailableReplicas,
		lossDuration:  phase.Deadline,
		replicaSecond: float64(phase.MaxUnavailableReplicas) * phase.Deadline.Seconds(),
		bounded:       true,
	}
	switch {
	case phase.Deadline <= 0:
		impact.bounded = false
		impact.missing = fmt.Sprintf("phase %q has no finite deadline", phase.Name)
	case !phase.DeadlineEnforced:
		impact.bounded = false
		impact.missing = fmt.Sprintf("phase %q deadline is not enforced", phase.Name)
	case !phase.StopsAtDeadline:
		impact.bounded = false
		impact.missing = fmt.Sprintf("phase %q timeout returns while unsafe work or degradation may continue", phase.Name)
	case phase.BoundSource == "":
		impact.bounded = false
		impact.missing = fmt.Sprintf("phase %q has no code/policy bound provenance", phase.Name)
	}
	return impact
}

func appendMissing(current, next string) string {
	if next == "" {
		return current
	}
	if current == "" {
		return next
	}
	return current + "; " + next
}

// DeriveContract calculates max_p sum_k n[p,k]*tau[p,k]. Unknown is returned
// whenever the execution-path inventory or one contributing phase is incomplete.
func DeriveContract(contract ActionContract) Bound {
	bound := Bound{Action: contract.Action, Status: StatusUnknown, Evidence: contract.Provenance}
	if !contract.EnumerationComplete {
		bound.MissingBound = "success/failure/deadline-expiry/rollback path inventory is incomplete"
		return bound
	}
	if len(contract.Paths) == 0 {
		bound.MissingBound = "no execution paths were supplied"
		return bound
	}

	allZero := true
	var missing []string
	for _, path := range contract.Paths {
		pathLoss := time.Duration(0)
		pathReplicaSeconds := float64(0)
		pathHasLoss := false
		for _, phase := range path.Phases {
			impact := evaluatePhase(phase)
			if impact.maxReplicas > 0 {
				allZero = false
				pathHasLoss = true
			}
			if impact.maxReplicas > bound.MaxUnavailableReplicas {
				bound.MaxUnavailableReplicas = impact.maxReplicas
			}
			pathLoss += impact.lossDuration
			pathReplicaSeconds += impact.replicaSecond
			if !impact.bounded {
				missing = append(missing, fmt.Sprintf("%s/%s: %s", path.Kind, path.Name, impact.missing))
			}
		}
		if pathHasLoss && !path.SafeReturnVerified {
			missing = append(missing, fmt.Sprintf("%s/%s: return to a safe state is not verified", path.Kind, path.Name))
		}
		if pathLoss > bound.MaxUnavailableDuration {
			bound.MaxUnavailableDuration = pathLoss
		}
		if pathReplicaSeconds > bound.MaxReplicaSeconds {
			bound.MaxReplicaSeconds = pathReplicaSeconds
		}
	}

	if allZero {
		bound.Status = StatusZero
		bound.MaxUnavailableDuration = 0
		bound.MaxReplicaSeconds = 0
		bound.MissingBound = ""
		return bound
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		bound.MissingBound = strings.Join(missing, "; ")
		return bound
	}
	bound.Status = StatusBounded
	return bound
}

// AvailabilityFromContract derives max_p sum_k tau[p,k] for phases that can
// cross the service's Ready floor. Unknown non-breaching phases do not poison an
// availability-zero proof when replica headroom makes a breach impossible.
func AvailabilityFromContract(contract ActionContract, readyReplicas, minAvailableReplicas int) AvailabilityBound {
	if readyReplicas < 0 || minAvailableReplicas < 0 {
		return AvailabilityBound{Status: StatusUnknown, Evidence: "service Ready-floor input is unavailable"}
	}
	if !contract.EnumerationComplete || len(contract.Paths) == 0 {
		return AvailabilityBound{Status: StatusUnknown, Evidence: "execution-path inventory is incomplete"}
	}

	allZero := true
	worst := time.Duration(0)
	var missing []string
	for _, path := range contract.Paths {
		pathBreach := time.Duration(0)
		pathCanBreach := false
		for _, phase := range path.Phases {
			impact := evaluatePhase(phase)
			if readyReplicas-impact.maxReplicas >= minAvailableReplicas {
				continue
			}
			allZero = false
			pathCanBreach = true
			pathBreach += impact.lossDuration
			if !impact.bounded {
				missing = append(missing, fmt.Sprintf("%s/%s: %s", path.Kind, path.Name, impact.missing))
			}
		}
		if pathCanBreach && !path.SafeReturnVerified {
			missing = append(missing, fmt.Sprintf("%s/%s: return to a safe state is not verified", path.Kind, path.Name))
		}
		if pathBreach > worst {
			worst = pathBreach
		}
	}
	if allZero {
		return AvailabilityBound{Status: StatusZero, Evidence: "every path preserves minAvailableReplicas"}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return AvailabilityBound{Status: StatusUnknown, Evidence: strings.Join(missing, "; ")}
	}
	return AvailabilityBound{Status: StatusBounded, MaxDuration: worst, Evidence: contract.Provenance}
}
