package model

// StatefulRotationContract is the stateful rotation contract a StatefulSet owner declares
// through its own annotations (parsed by internal/statefulrotation). Each class is opt-in:
// an undeclared class is never offered, whatever the workload looks like.
type StatefulRotationContract struct {
	// Quorum > 0 declares a replicated workload: at least Quorum members must stay Ready
	// while any member is replaced.
	Quorum int
	// PeerResync opts class A (stateful-replica-rebuild) in: the application re-seeds a
	// member created on fresh volumes from its peers, so the member's claims may be deleted.
	PeerResync bool
	// LeaderLabelKey/LeaderLabelValue identify the current leader/primary. Class A never
	// rebuilds the member carrying this label. Empty = no leader distinction.
	LeaderLabelKey   string
	LeaderLabelValue string
	// SnapshotClass opts class B (stateful-snapshot-rotate) in: the CSI VolumeSnapshotClass
	// used for the pre-rotation rollback point.
	SnapshotClass string
	// CheckpointPort/CheckpointPath/RestorePath opt class C (stateful-checkpoint-handoff) in:
	// POST CheckpointPath commits state to the application's durable store; GET RestorePath
	// on the replacement reports the checkpoint it restored.
	CheckpointPort int
	CheckpointPath string
	RestorePath    string
	// RecoverySeconds is the declared bound for a replacement member to become Ready.
	RecoverySeconds int
	// ResyncSeconds is the declared bound for a rebuilt member to catch up from its peers.
	ResyncSeconds int
}

// StatefulClaim is one PersistentVolumeClaim the target Pod mounts.
type StatefulClaim struct {
	Name        string
	UID         string
	Bound       bool
	Terminating bool
	// FromTemplate is true when the claim is the target ordinal's claim of one of the
	// owner's volumeClaimTemplates, i.e. the StatefulSet recreates it if it is deleted.
	FromTemplate bool
}

// StatefulRotationObservation is the authoritative StatefulSet + claim witness for one Pod.
// Brain admission reads the snapshot copy; dispatch re-observes it live before mutating.
type StatefulRotationObservation struct {
	Contract StatefulRotationContract
	// Invalid carries the parse error of a declared but malformed contract. Every class
	// fails closed on it.
	Invalid string

	OwnerName            string
	OwnerUID             string
	OwnerResourceVersion string
	Replicas             int
	ReadyReplicas        int
	// RolloutInProgress is true while the owner has an unobserved generation or its current
	// and update revisions differ: a replacement would start on an unproven template.
	RolloutInProgress bool
	// Leader is true when the target carries the declared leader label.
	Leader bool
	Claims []StatefulClaim
	// SnapshotClassReady is true when the declared VolumeSnapshotClass was read.
	SnapshotClassReady bool

	// Complete is true only when the owner and every claim were read authoritatively.
	Complete bool
	Reason   string
}

// HasClaims reports whether the target mounts at least one PersistentVolumeClaim.
func (o *StatefulRotationObservation) HasClaims() bool { return o != nil && len(o.Claims) > 0 }
