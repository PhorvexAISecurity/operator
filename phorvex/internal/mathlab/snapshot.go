// Package mathlab records production decision ticks as replayable snapshots and replays
// them offline on a fresh engine (Math/OR Benchmark Lab).
//
// The recorder is observation-only: it copies inputs and verdicts that the production tick
// already produced, never changes a decision, and degrades by dropping a snapshot (with a
// counter) rather than delaying or failing the tick. The replay runs the unmodified
// production CoverageEngine on an isolated in-memory engine restored from the recorded
// owner state; it has no Kubernetes client and dispatches nothing.
package mathlab

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	// SnapshotSchema versions the snapshot file. A replay refuses other versions.
	SnapshotSchema = "math-lab.snapshot.v1"
	fileMagic      = "PXMLSNP1"
	// maxHeaderBytes bounds the uncompressed JSON header.
	maxHeaderBytes = 1 << 20
	// MaxPayloadBytes bounds a decoded payload so a corrupt file cannot exhaust memory.
	MaxPayloadBytes = 64 << 20
)

// Header is the uncompressed, human-readable identity of one snapshot. It is enough to
// list, filter and join snapshots without decoding the payload.
type Header struct {
	Schema                string            `json:"schema"`
	CapturedAt            time.Time         `json:"capturedAt"`
	DecidedAt             time.Time         `json:"decidedAt"`
	GitSHA                string            `json:"gitSHA"`
	BrainImage            string            `json:"brainImage"`
	TickID                string            `json:"tickID"`
	Tenant                string            `json:"tenant"`
	Namespace             string            `json:"namespace"`
	PolicyName            string            `json:"policyName"`
	PolicyUID             string            `json:"policyUID"`
	PolicyGeneration      int64             `json:"policyGeneration"`
	Owner                 string            `json:"owner"`
	ParameterSetID        string            `json:"parameterSetID"`
	ParameterManifestHash string            `json:"parameterManifestHash"`
	PolicyOverridesHash   string            `json:"policyOverridesHash"`
	ProcessConfig         map[string]string `json:"processConfig"`
	ProcessConfigHash     string            `json:"processConfigHash"`
	ReconProfile          string            `json:"reconProfile"`
	ContextProvider       string            `json:"contextProvider"`
	GPUEnvelopeMax        float64           `json:"gpuEnvelopeMax"`
	EconomicsMode         string            `json:"economicsMode"`
	Assets                []string          `json:"assets"`
	Selected              []string          `json:"selected"`
	ProductionError       string            `json:"productionError,omitempty"`
	Finalized             bool              `json:"finalized"`
	UnreplayableFields    []string          `json:"unreplayableFields,omitempty"`
}

// CapabilityVerdict is one recorded answer of the production capability gate.
type CapabilityVerdict struct {
	Namespace   string
	PodUID      string
	Action      model.Action
	CoverKeys   string
	Nil         bool
	Eligibility actionset.Eligibility
}

// FailureVerdict is one recorded answer of the production failure-cooldown gate.
type FailureVerdict struct {
	Namespace string
	PodUID    string
	Action    model.Action
	Detail    string
	Excluded  bool
}

// Inputs are the pre-decision inputs, encoded before the engine runs so later stamping
// of shared views cannot leak into the record.
type Inputs struct {
	SpecJSON []byte // configured v1alpha1.PhorvexPolicySpec
	Policy   model.Policy
	Views    []*model.WorkloadView
	Engine   decision.OwnerState
	// Optional additive evidence. Its absence does not invalidate legacy replay.
	EndpointCostEvidence *model.ReplayCostEvidence
}

// Outcome is what production computed for the tick.
type Outcome struct {
	CapabilityWired bool
	Capability      []CapabilityVerdict
	FailureWired    bool
	Failures        []FailureVerdict
	ProductionError string
	Production      []model.Decision // raw DecideChecked output, before runner stamping
}

// Final carries the decisions as audited after dispatch (dry-run, kill-switch and
// dispatch outcome stamps). It is absent when the tick ended before the audit write.
type Final struct {
	Decisions []model.Decision
}

// Snapshot is a decoded snapshot file.
type Snapshot struct {
	Digest  string
	Header  Header
	Inputs  Inputs
	Outcome Outcome
	Final   *Final
}

// Digest returns the content address of a snapshot file.
func Digest(file []byte) string {
	sum := sha256.Sum256(file)
	return hex.EncodeToString(sum[:])
}

// assemble writes header + gzip(gob stream) into one file image.
func assemble(header Header, gobStream []byte) ([]byte, error) {
	raw, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("snapshot header: %w", err)
	}
	if len(raw) > maxHeaderBytes {
		return nil, fmt.Errorf("snapshot header is %d bytes", len(raw))
	}
	var out bytes.Buffer
	out.WriteString(fileMagic)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	out.Write(n[:])
	out.Write(raw)
	zw, err := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(gobStream); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ReadHeader reads only the uncompressed header.
func ReadHeader(r io.Reader) (Header, error) {
	br := bufio.NewReader(r)
	var h Header
	magic := make([]byte, len(fileMagic))
	if _, err := io.ReadFull(br, magic); err != nil {
		return h, fmt.Errorf("snapshot magic: %w", err)
	}
	if string(magic) != fileMagic {
		return h, errors.New("not a math-lab snapshot")
	}
	var n [4]byte
	if _, err := io.ReadFull(br, n[:]); err != nil {
		return h, fmt.Errorf("snapshot header length: %w", err)
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > maxHeaderBytes {
		return h, fmt.Errorf("snapshot header length %d out of range", size)
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(br, raw); err != nil {
		return h, fmt.Errorf("snapshot header: %w", err)
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, fmt.Errorf("snapshot header: %w", err)
	}
	if h.Schema != SnapshotSchema {
		return h, fmt.Errorf("unsupported snapshot schema %q", h.Schema)
	}
	return h, nil
}

// Decode parses a complete snapshot file.
func Decode(file []byte) (*Snapshot, error) {
	r := bytes.NewReader(file)
	h, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}
	offset := len(fileMagic) + 4
	size := int(binary.BigEndian.Uint32(file[len(fileMagic):offset]))
	zr, err := gzip.NewReader(bytes.NewReader(file[offset+size:]))
	if err != nil {
		return nil, fmt.Errorf("snapshot payload: %w", err)
	}
	dec := gob.NewDecoder(io.LimitReader(zr, MaxPayloadBytes))
	s := &Snapshot{Digest: Digest(file), Header: h}
	if err := dec.Decode(&s.Inputs); err != nil {
		return nil, fmt.Errorf("snapshot inputs: %w", err)
	}
	if err := dec.Decode(&s.Outcome); err != nil {
		return nil, fmt.Errorf("snapshot outcome: %w", err)
	}
	var final Final
	switch err := dec.Decode(&final); {
	case err == nil:
		s.Final = &final
	case errors.Is(err, io.EOF):
	default:
		return nil, fmt.Errorf("snapshot final decisions: %w", err)
	}
	if h.Finalized != (s.Final != nil) {
		return nil, fmt.Errorf("snapshot header finalized=%v disagrees with payload", h.Finalized)
	}
	return s, nil
}

func coverKey(keys []string) string {
	var b bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(0x1f)
		}
		b.WriteString(k)
	}
	return b.String()
}
