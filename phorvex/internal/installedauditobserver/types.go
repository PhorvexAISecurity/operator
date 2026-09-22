// Package installedauditobserver reads the existing authenticated audit stream
// and emits a small, safe decision/dispatch projection for installed-manager
// catalogue trials. It does not infer workload effect from dispatch evidence.
package installedauditobserver

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
)

const (
	CursorSchema  = "phorvex.installed-audit-cursor.v1"
	ReceiptSchema = "phorvex.installed-audit-receipt.v1"
	SummarySchema = "phorvex.installed-audit-summary.v1"

	DefaultMaxBytes   int64 = 8 << 20
	AbsoluteMaxBytes  int64 = 64 << 20
	DefaultMaxRows          = 512
	AbsoluteMaxRows         = 4096
	MaxRecordBytes    int64 = 512 << 10
	MaxObjectsTouched       = 8
	MaxActionStatuses       = 32
	MaxIdentityBytes        = 253
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var anchorPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Cursor pins the end of the live segment before a trial begins. A collector
// must find this exact generation (possibly as a retained backup) and reads only
// bytes appended after Offset plus newer, contiguous generations.
type Cursor struct {
	SchemaVersion string                 `json:"schemaVersion"`
	CapturedAt    time.Time              `json:"capturedAt"`
	Segment       audittransport.Segment `json:"segment"`
	Offset        int64                  `json:"offset"`
}

type Config struct {
	PolicyNamespace            string
	PolicyName                 string
	PolicyUID                  string
	PolicyGeneration           int64
	TargetNamespace            string
	TargetName                 string
	TargetUID                  string
	ExpectedTraceSchema        string
	ExpectedBrainImage         string
	ExpectedGitSHA             string
	ExpectedManifestID         string
	ExpectedManifestHash       string
	ExpectedOverridesHash      string
	ExpectedPodResourceVersion string
	ExpectedGraceSeconds       *int64
	AllowedObjectsTouched      []string
	NotBefore                  time.Time
	NotAfter                   time.Time
	MaxBytes                   int64
	MaxRows                    int
}

func (c *Config) normalize() error {
	if c.MaxBytes == 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.MaxRows == 0 {
		c.MaxRows = DefaultMaxRows
	}
	if c.MaxBytes < 1 || c.MaxBytes > AbsoluteMaxBytes || c.MaxRows < 1 || c.MaxRows > AbsoluteMaxRows {
		return errors.New("audit observation bounds are outside the supported range")
	}
	for name, value := range map[string]string{
		"policy namespace": c.PolicyNamespace, "policy name": c.PolicyName, "policy UID": c.PolicyUID,
		"target namespace": c.TargetNamespace, "target name": c.TargetName, "target UID": c.TargetUID,
		"trace schema": c.ExpectedTraceSchema, "brain image": c.ExpectedBrainImage,
		"git SHA": c.ExpectedGitSHA, "parameter manifest ID": c.ExpectedManifestID,
		"parameter manifest hash": c.ExpectedManifestHash,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
		if len(value) > MaxIdentityBytes && name != "brain image" {
			return fmt.Errorf("%s exceeds its size bound", name)
		}
	}
	if len(c.ExpectedBrainImage) > 2048 {
		return errors.New("brain image exceeds its size bound")
	}
	if c.PolicyGeneration < 1 {
		return errors.New("policy generation must be positive")
	}
	if !shaPattern.MatchString(c.ExpectedGitSHA) {
		return errors.New("expected git SHA is not a lowercase hexadecimal revision")
	}
	if !digestPattern.MatchString(c.ExpectedManifestHash) || (c.ExpectedOverridesHash != "" && !digestPattern.MatchString(c.ExpectedOverridesHash)) {
		return errors.New("configured parameter hashes must be lowercase SHA-256 digests")
	}
	if c.NotBefore.IsZero() || c.NotAfter.IsZero() || !c.NotBefore.Before(c.NotAfter) {
		return errors.New("a non-empty increasing observation window is required")
	}
	if c.NotAfter.Sub(c.NotBefore) > 2*time.Minute {
		return errors.New("audit observation window exceeds two minutes")
	}
	if len(c.AllowedObjectsTouched) > MaxObjectsTouched {
		return errors.New("object allowlist exceeds its bound")
	}
	seen := map[string]bool{}
	for _, item := range c.AllowedObjectsTouched {
		if item == "" || len(item) > 253 || seen[item] {
			return errors.New("object allowlist is empty, duplicated, or oversized")
		}
		seen[item] = true
	}
	if c.ExpectedGraceSeconds != nil && (*c.ExpectedGraceSeconds < 1 || *c.ExpectedGraceSeconds > 300) {
		return errors.New("expected grace is outside the supported range")
	}
	if (c.ExpectedPodResourceVersion == "") != (c.ExpectedGraceSeconds == nil) {
		return errors.New("target resourceVersion and expected grace must be configured together")
	}
	return nil
}

func (c Config) overridesID() string {
	return fmt.Sprintf("%s/%s@%s:%d", c.PolicyNamespace, c.PolicyName, c.PolicyUID, c.PolicyGeneration)
}

type SourceRange struct {
	SegmentID  string `json:"segmentID"`
	Generation string `json:"generation"`
	Anchor     string `json:"anchor"`
	PinnedSize int64  `json:"pinnedSize"`
	Start      int64  `json:"start"`
	End        int64  `json:"end"`
	SHA256     string `json:"sha256"`
}

type PolicyIdentity struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}

type TargetIdentity struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type ParameterEpoch struct {
	SchemaVersion       string `json:"schemaVersion"`
	ManifestID          string `json:"manifestID"`
	ManifestHash        string `json:"manifestHash"`
	PolicyOverridesID   string `json:"policyOverridesID"`
	PolicyOverridesHash string `json:"policyOverridesHash"`
}

type ActionDisposition struct {
	Action              string               `json:"action"`
	Status              string               `json:"status"`
	ExclusionKind       string               `json:"exclusionKind,omitempty"`
	AvailabilityRefusal *AvailabilityRefusal `json:"availabilityRefusal,omitempty"`
}

// AvailabilityRefusal is the bounded numeric projection of the availability
// floor's exact producer reason. The reason itself remains private.
type AvailabilityRefusal struct {
	Ready        int `json:"ready"`
	Removed      int `json:"removed"`
	MinAvailable int `json:"minAvailable"`
}

type GracefulTermination struct {
	PolicyGeneration            int64  `json:"policyGeneration"`
	PolicyGraceCapSeconds       int64  `json:"policyGraceCapSeconds"`
	WorkloadGraceSeconds        int64  `json:"workloadGraceSeconds"`
	WorkloadGraceExplicit       bool   `json:"workloadGraceExplicit"`
	EffectiveGracePeriodSeconds int64  `json:"effectiveGracePeriodSeconds"`
	PodResourceVersion          string `json:"podResourceVersion"`
	TerminationStatus           string `json:"terminationStatus"`
}

// Receipt is intentionally an allowlist. It excludes raw reasons, model inputs,
// rationales, credentials, parameter documents, and application payloads.
type Receipt struct {
	SchemaVersion       string               `json:"schemaVersion"`
	DecisionTime        time.Time            `json:"decisionTime"`
	DecisionID          string               `json:"decisionID"`
	TickID              string               `json:"tickID"`
	Policy              PolicyIdentity       `json:"policy"`
	Target              TargetIdentity       `json:"target"`
	TraceSchema         string               `json:"traceSchema"`
	BrainImageSHA256    string               `json:"brainImageSHA256"`
	GitSHA              string               `json:"gitSHA"`
	ParameterEpoch      ParameterEpoch       `json:"parameterEpoch"`
	Action              string               `json:"action"`
	Selected            bool                 `json:"selected"`
	Feasible            bool                 `json:"feasible"`
	DryRun              bool                 `json:"dryRun"`
	Actuated            bool                 `json:"actuated"`
	DispatchOutcome     string               `json:"dispatchOutcome"`
	ActionDisposition   *ActionDisposition   `json:"actionDisposition,omitempty"`
	Handler             string               `json:"handler,omitempty"`
	MutationKind        string               `json:"mutationKind,omitempty"`
	ObjectsTouched      []string             `json:"objectsTouched,omitempty"`
	GracefulTermination *GracefulTermination `json:"gracefulTermination,omitempty"`
	RawSHA256           string               `json:"rawSHA256"`
	SourceRanges        []SourceRange        `json:"sourceRanges"`
}

type Summary struct {
	SchemaVersion string    `json:"schemaVersion"`
	Status        string    `json:"status"`
	Attribution   string    `json:"attribution"`
	StartedAt     time.Time `json:"startedAt"`
	CompletedAt   time.Time `json:"completedAt"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	BytesRead     int64     `json:"bytesRead"`
	RowsRead      int       `json:"rowsRead"`
	Receipts      int       `json:"receipts"`
	ErrorClass    string    `json:"errorClass,omitempty"`
}
