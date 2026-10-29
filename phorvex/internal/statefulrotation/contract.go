// Package statefulrotation is the single definition of the stateful rotation contract, its
// authoritative observation and its per-class admission law. The sensor projects the
// observation into the snapshot, the feasibility law admits each class from it, and the
// native handlers re-observe and re-admit it against the live API before any mutation, so
// brain and hands can never disagree about when a stateful Pod may be replaced.
//
// Three classes are defined, each a distinct model.Action:
//
//	A stateful-replica-rebuild     replicated member, rebuilt on fresh volumes from peers
//	B stateful-snapshot-rotate     single writer, restarted behind a ready CSI snapshot
//	C stateful-checkpoint-handoff  volume-less state, checkpointed and restored
//
// A class is offered only when the owning StatefulSet declares it. Plain rotate stays
// infeasible on every stateful Pod (feasibility stateful-integrity).
package statefulrotation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/phorvex/phorvex/internal/model"
)

// Owner-declared contract annotations, read from the StatefulSet object itself (never the
// Pod, which a foothold inside the workload is closer to).
const (
	AnnotationQuorum          = "phorvex.ai/stateful-quorum"
	AnnotationReplicaRebuild  = "phorvex.ai/stateful-replica-rebuild"
	AnnotationLeaderLabel     = "phorvex.ai/stateful-leader-label"
	AnnotationSnapshotClass   = "phorvex.ai/stateful-snapshot-class"
	AnnotationCheckpointPort  = "phorvex.ai/stateful-checkpoint-port"
	AnnotationCheckpointPath  = "phorvex.ai/stateful-checkpoint-path"
	AnnotationRestorePath     = "phorvex.ai/stateful-restore-path"
	AnnotationRecoverySeconds = "phorvex.ai/stateful-recovery-seconds"
	AnnotationResyncSeconds   = "phorvex.ai/stateful-resync-seconds"

	// ReplicaRebuildPeerResync is the only accepted value of AnnotationReplicaRebuild.
	ReplicaRebuildPeerResync = "peer-resync"

	// DefaultRecoverySeconds applies when no recovery bound is declared.
	DefaultRecoverySeconds = 300
	// MaxDeclaredSeconds bounds every declared duration. An undeclared resync bound
	// defaults to it: an unknown catch-up time is priced as the slowest admissible one.
	MaxDeclaredSeconds = 3600
	// MaxQuorum bounds the declared quorum to a realistic consensus group size.
	MaxQuorum     = 15
	maxPathLength = 256
)

var contractAnnotations = []string{
	AnnotationQuorum, AnnotationReplicaRebuild, AnnotationLeaderLabel, AnnotationSnapshotClass,
	AnnotationCheckpointPort, AnnotationCheckpointPath, AnnotationRestorePath,
	AnnotationRecoverySeconds, AnnotationResyncSeconds,
}

// Declared reports whether the owner declares any part of the contract.
func Declared(annotations map[string]string) bool {
	for _, k := range contractAnnotations {
		if _, ok := annotations[k]; ok {
			return true
		}
	}
	return false
}

// ParseContract validates a declared contract strictly. Any malformed value fails the whole
// contract: a partially understood contract must not admit a destructive class.
func ParseContract(annotations map[string]string) (model.StatefulRotationContract, error) {
	c := model.StatefulRotationContract{RecoverySeconds: DefaultRecoverySeconds, ResyncSeconds: MaxDeclaredSeconds}
	var errs []error
	intValue := func(key string, lo, hi int) int {
		raw, ok := annotations[key]
		if !ok {
			return 0
		}
		v, err := strconv.Atoi(raw)
		if err != nil || v < lo || v > hi {
			errs = append(errs, fmt.Errorf("%s must be an integer in [%d,%d]", key, lo, hi))
			return 0
		}
		return v
	}
	c.Quorum = intValue(AnnotationQuorum, 1, MaxQuorum)
	if v := intValue(AnnotationRecoverySeconds, 1, MaxDeclaredSeconds); v > 0 {
		c.RecoverySeconds = v
	}
	if v := intValue(AnnotationResyncSeconds, 1, MaxDeclaredSeconds); v > 0 {
		c.ResyncSeconds = v
	}

	if raw, ok := annotations[AnnotationReplicaRebuild]; ok {
		switch {
		case raw != ReplicaRebuildPeerResync:
			errs = append(errs, fmt.Errorf("%s must be %q", AnnotationReplicaRebuild, ReplicaRebuildPeerResync))
		case c.Quorum == 0:
			errs = append(errs, fmt.Errorf("%s requires %s", AnnotationReplicaRebuild, AnnotationQuorum))
		default:
			c.PeerResync = true
		}
	}
	if raw, ok := annotations[AnnotationLeaderLabel]; ok {
		key, value, found := strings.Cut(raw, "=")
		if !found || len(validation.IsQualifiedName(key)) > 0 || value == "" || len(validation.IsValidLabelValue(value)) > 0 {
			errs = append(errs, fmt.Errorf("%s must be a key=value label", AnnotationLeaderLabel))
		} else {
			c.LeaderLabelKey, c.LeaderLabelValue = key, value
		}
	}
	if raw, ok := annotations[AnnotationSnapshotClass]; ok {
		if len(validation.IsDNS1123Subdomain(raw)) > 0 {
			errs = append(errs, fmt.Errorf("%s must be a VolumeSnapshotClass name", AnnotationSnapshotClass))
		} else {
			c.SnapshotClass = raw
		}
	}

	_, hasPort := annotations[AnnotationCheckpointPort]
	_, hasCheckpoint := annotations[AnnotationCheckpointPath]
	_, hasRestore := annotations[AnnotationRestorePath]
	if hasPort || hasCheckpoint || hasRestore {
		port := intValue(AnnotationCheckpointPort, 1, 65535)
		checkpoint, cErr := httpPath(annotations, AnnotationCheckpointPath)
		restore, rErr := httpPath(annotations, AnnotationRestorePath)
		errs = append(errs, cErr, rErr)
		if !hasPort {
			errs = append(errs, fmt.Errorf("%s is required for a checkpoint handoff", AnnotationCheckpointPort))
		}
		if port > 0 && cErr == nil && rErr == nil {
			c.CheckpointPort, c.CheckpointPath, c.RestorePath = port, checkpoint, restore
		}
	}

	if err := errors.Join(errs...); err != nil {
		return model.StatefulRotationContract{}, err
	}
	if !c.PeerResync && c.SnapshotClass == "" && c.CheckpointPort == 0 {
		return model.StatefulRotationContract{}, errors.New("contract declares no stateful rotation class")
	}
	return c, nil
}

// httpPath accepts an absolute, normalized request path without query or traversal.
func httpPath(annotations map[string]string, key string) (string, error) {
	raw, ok := annotations[key]
	if !ok {
		return "", fmt.Errorf("%s is required for a checkpoint handoff", key)
	}
	if !strings.HasPrefix(raw, "/") || len(raw) > maxPathLength || strings.ContainsAny(raw, "?#% \t\r\n\\") ||
		strings.Contains(raw, "//") || strings.Contains(raw, "/../") || strings.HasSuffix(raw, "/..") || strings.Contains(raw, "/./") {
		return "", fmt.Errorf("%s must be an absolute path without query, encoding or traversal", key)
	}
	return raw, nil
}
