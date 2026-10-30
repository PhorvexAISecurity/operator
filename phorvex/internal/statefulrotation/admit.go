package statefulrotation

import (
	"fmt"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// Admit is the per-class admission law. It is pure: the feasibility law evaluates it on the
// snapshot observation and each native handler evaluates it again on a live observation
// immediately before mutating. ok=false carries exactly one reason.
//
// Common preconditions keep the replacement recoverable: the contract parsed, the owner and
// every claim were read, the owner is not mid-rollout (a replacement would start on an
// unproven template), every member is Ready (an OrderedReady StatefulSet recreates a member
// only behind Ready predecessors, and a degraded set has no redundancy to spend), and a
// replicated set keeps its quorum with the target out.
func Admit(o *model.StatefulRotationObservation, targetReady bool, a model.Action) (bool, string) {
	if !model.IsStatefulRotation(a) {
		return false, "not a stateful rotation action"
	}
	if o == nil {
		return false, "owner declares no stateful rotation contract"
	}
	if o.Invalid != "" {
		return false, "contract invalid: " + o.Invalid
	}
	if !o.Complete {
		return false, "observation incomplete: " + o.Reason
	}
	c := o.Contract
	if why := classDeclared(c, a); why != "" {
		return false, why
	}
	if !targetReady {
		return false, "target not Ready"
	}
	if o.RolloutInProgress {
		return false, "owner rollout in progress"
	}
	if o.Replicas < 1 || o.ReadyReplicas < o.Replicas {
		return false, fmt.Sprintf("owner degraded: ready=%d < replicas=%d", o.ReadyReplicas, o.Replicas)
	}
	if c.Quorum > 0 && o.ReadyReplicas-1 < c.Quorum {
		return false, fmt.Sprintf("quorum headroom: ready=%d-1 < quorum=%d", o.ReadyReplicas, c.Quorum)
	}
	// One member at a time, and only once the set has settled: a member that just became
	// Ready (typically the previous replacement) may still be catching up beyond its
	// readiness probe, so the owner's declared resync (or recovery) bound must pass first.
	if settle := settleBound(c); o.SinceMemberReady < settle {
		return false, fmt.Sprintf("owner settling: a member became Ready %s ago < %s", o.SinceMemberReady.Round(time.Second), settle)
	}
	switch a {
	case model.ActionStatefulReplicaRebuild:
		if o.Leader {
			return false, "target is the declared leader"
		}
		if !o.HasClaims() {
			return false, "target has no volume claims to rebuild"
		}
		for _, claim := range o.Claims {
			if !claim.FromTemplate {
				return false, "claim " + claim.Name + " is not recreated by the owner's volumeClaimTemplates"
			}
		}
		return claimsUsable(o)
	case model.ActionStatefulSnapshotRotate:
		if !o.SnapshotClassReady {
			return false, "volume snapshot class " + c.SnapshotClass + " unavailable"
		}
		if !o.HasClaims() {
			return false, "target has no volume claims to snapshot"
		}
		return claimsUsable(o)
	default: // ActionStatefulCheckpointHandoff
		if o.HasClaims() {
			return false, "target keeps state on volume claims; volume-backed classes apply"
		}
		return true, ""
	}
}

// settleBound is how long the set must have been unchanged before another member is
// replaced: the declared peer-resync bound when members re-seed from peers, else the
// declared recovery bound.
func settleBound(c model.StatefulRotationContract) time.Duration {
	if c.PeerResync {
		return time.Duration(c.ResyncSeconds) * time.Second
	}
	return time.Duration(c.RecoverySeconds) * time.Second
}

func classDeclared(c model.StatefulRotationContract, a model.Action) string {
	switch a {
	case model.ActionStatefulReplicaRebuild:
		if !c.PeerResync {
			return "contract does not declare peer-resync replica rebuild"
		}
	case model.ActionStatefulSnapshotRotate:
		if c.SnapshotClass == "" {
			return "contract does not declare a snapshot class"
		}
	case model.ActionStatefulCheckpointHandoff:
		if c.CheckpointPort == 0 {
			return "contract does not declare a checkpoint endpoint"
		}
	}
	return ""
}

func claimsUsable(o *model.StatefulRotationObservation) (bool, string) {
	for _, claim := range o.Claims {
		if claim.Terminating {
			return false, "claim " + claim.Name + " is terminating"
		}
		if !claim.Bound {
			return false, "claim " + claim.Name + " is not Bound"
		}
	}
	return true, ""
}

// Covers reports whether the declared contract and the target's volume layout make class a
// physically applicable. It deliberately ignores live health: cover describes what the move
// invalidates if executed, and Admit decides whether it may execute now.
func Covers(o *model.StatefulRotationObservation, a model.Action) bool {
	if o == nil || o.Invalid != "" || classDeclared(o.Contract, a) != "" {
		return false
	}
	if a == model.ActionStatefulCheckpointHandoff {
		return !o.HasClaims()
	}
	return o.HasClaims()
}
