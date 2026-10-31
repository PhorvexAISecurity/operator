package mathlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/slo"
)

// Default bounds for one snapshot and for the recorder's queue.
const (
	DefaultMaxSnapshotBytes = 16 << 20
)

// Pending is one assembled-but-unwritten snapshot handed to the store.
type Pending struct {
	Header Header
	Stream []byte // gob stream; the store compresses and writes it off the tick path
}

// Sink receives finished snapshots. Enqueue must never block.
type Sink interface {
	Enqueue(Pending) bool
}

// Result labels for the capture counter.
const (
	ResultQueued       = "queued"
	ResultDroppedFull  = "dropped_queue_full"
	ResultDroppedLarge = "dropped_too_large"
	ResultEncodeError  = "encode_error"
	ResultAbandoned    = "abandoned"
)

// Config selects which policies are recorded and with what process identity.
type Config struct {
	// Policies is the allowlist of "namespace/name" policies to record. Empty disables
	// recording entirely; there is no wildcard.
	Policies         []string
	MaxSnapshotBytes int
	// ProcessConfig holds the decision-relevant, non-secret effective operator flags.
	ProcessConfig  map[string]string
	GPUEnvelopeMax float64
}

// Recorder records allowlisted production ticks. A nil *Recorder records nothing.
type Recorder struct {
	cfg         Config
	allow       map[string]bool
	sink        Sink
	processHash string
	observe     func(result string, seconds float64, bytes int)
}

// NewRecorder validates the configuration. It returns nil (recording disabled) when the
// allowlist is empty.
func NewRecorder(cfg Config, sink Sink, observe func(result string, seconds float64, bytes int)) (*Recorder, error) {
	if len(cfg.Policies) == 0 {
		return nil, nil
	}
	if sink == nil {
		return nil, fmt.Errorf("math-lab recorder needs a snapshot store")
	}
	allow := map[string]bool{}
	for _, p := range cfg.Policies {
		p = strings.TrimSpace(p)
		ns, name, ok := strings.Cut(p, "/")
		if !ok || ns == "" || name == "" || strings.Contains(name, "/") || p == "*" {
			return nil, fmt.Errorf("math-lab capture policy %q must be namespace/name", p)
		}
		allow[p] = true
	}
	if cfg.MaxSnapshotBytes <= 0 {
		cfg.MaxSnapshotBytes = DefaultMaxSnapshotBytes
	}
	if observe == nil {
		observe = func(string, float64, int) {}
	}
	return &Recorder{cfg: cfg, allow: allow, sink: sink, processHash: ProcessConfigHash(cfg.ProcessConfig), observe: observe}, nil
}

// ProcessConfigHash is the canonical identity of the effective operator flags.
func ProcessConfigHash(cfg map[string]string) string {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(cfg[k]))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Enabled reports whether this policy is recorded.
func (r *Recorder) Enabled(namespace, name string) bool {
	return r != nil && r.allow[namespace+"/"+name]
}

// TickCapture is one in-flight recording. Every method is safe on a nil receiver.
type TickCapture struct {
	r        *Recorder
	ce       *decision.CoverageEngine
	start    time.Time
	elapsed  time.Duration
	buf      bytes.Buffer
	enc      *gob.Encoder
	header   Header
	failed   bool
	decided  bool
	closed   bool
	origCap  func(*model.WorkloadView, model.Action, []string) *actionset.Eligibility
	origFail func(*model.WorkloadView, model.Action) (string, bool)
	mu       sync.Mutex
	capVerd  []CapabilityVerdict
	failVerd []FailureVerdict
}

// Begin records the pre-decision inputs and starts recording the gate verdicts the
// production decision will request. Call it immediately before DecideChecked.
func (r *Recorder) Begin(ce *decision.CoverageEngine, spec v1alpha1.PhorvexPolicySpec, views []*model.WorkloadView, pol model.Policy, capturedAt time.Time, costEvidence ...*slo.ReplayCostEvidence) *TickCapture {
	if r == nil || ce == nil || !r.Enabled(pol.Namespace, pol.PolicyName) {
		return nil
	}
	c := &TickCapture{r: r, ce: ce, start: time.Now()}
	defer func() { c.elapsed += time.Since(c.start) }()
	c.header = Header{Schema: SnapshotSchema, CapturedAt: capturedAt.UTC(), GitSHA: pol.GitSHA, BrainImage: pol.BrainImage,
		TickID: pol.TickID, Tenant: pol.Tenant, Namespace: pol.Namespace, PolicyName: pol.PolicyName, PolicyUID: pol.PolicyUID,
		PolicyGeneration: pol.PolicyGeneration, Owner: pol.Owner(), ProcessConfig: r.cfg.ProcessConfig,
		ProcessConfigHash: r.processHash, GPUEnvelopeMax: r.cfg.GPUEnvelopeMax}
	// The profiles are the engine's own, not the registry default: an engine built before a
	// default changed keeps the profile it was built with.
	if ce.Recon != nil {
		c.header.ReconProfile = ce.Recon.Name()
	} else {
		c.header.UnreplayableFields = append(c.header.UnreplayableFields, "reconProfile")
	}
	if ce.Context != nil {
		c.header.ContextProvider = ce.Context.Name()
	} else {
		c.header.UnreplayableFields = append(c.header.UnreplayableFields, "contextProvider")
	}
	for _, v := range views {
		c.header.Assets = append(c.header.Assets, v.Pod.Namespace+"/"+v.Pod.Name)
	}
	if ref, _, _, err := decision.ParameterSetForPolicy(pol); err == nil && ref != nil {
		c.header.ParameterSetID = ref.ManifestID + "/" + ref.PolicyOverridesID
		c.header.ParameterManifestHash, c.header.PolicyOverridesHash = ref.ManifestHash, ref.PolicyOverridesHash
	} else {
		c.header.UnreplayableFields = append(c.header.UnreplayableFields, "parameterSet")
	}
	state := ce.ExportOwnerState(pol.Owner())
	lambda := pol.Lambda
	if state.HasBucket && state.Bucket.HasDual {
		lambda = state.Bucket.Dual.RuntimeLegacy
	}
	if economics, err := pol.Economics(lambda); err == nil {
		c.header.EconomicsMode = economics.Version
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		c.fail()
		return c
	}
	c.enc = gob.NewEncoder(&c.buf)
	var evidence *slo.ReplayCostEvidence
	if len(costEvidence) == 1 {
		evidence = costEvidence[0].Clone()
	}
	if err := c.enc.Encode(Inputs{SpecJSON: specJSON, Policy: pol, Views: views, Engine: state, EndpointCostEvidence: evidence}); err != nil {
		c.fail()
		return c
	}
	c.origCap, c.origFail = ce.Capability, ce.FailureExclusion
	if c.origCap != nil {
		orig := c.origCap
		ce.Capability = func(v *model.WorkloadView, a model.Action, keys []string) *actionset.Eligibility {
			out := orig(v, a, keys)
			rec := CapabilityVerdict{Namespace: v.Pod.Namespace, PodUID: v.Pod.UID, Action: a, CoverKeys: coverKey(keys), Nil: out == nil}
			if out != nil {
				rec.Eligibility = *out
			}
			c.mu.Lock()
			c.capVerd = append(c.capVerd, rec)
			c.mu.Unlock()
			return out
		}
	}
	if c.origFail != nil {
		orig := c.origFail
		ce.FailureExclusion = func(v *model.WorkloadView, a model.Action) (string, bool) {
			detail, excluded := orig(v, a)
			c.mu.Lock()
			c.failVerd = append(c.failVerd, FailureVerdict{Namespace: v.Pod.Namespace, PodUID: v.Pod.UID, Action: a, Detail: detail, Excluded: excluded})
			c.mu.Unlock()
			return detail, excluded
		}
	}
	return c
}

func (c *TickCapture) fail() {
	c.failed = true
	c.restore()
}

func (c *TickCapture) restore() {
	if c.ce == nil {
		return
	}
	if c.origCap != nil {
		c.ce.Capability = c.origCap
	}
	if c.origFail != nil {
		c.ce.FailureExclusion = c.origFail
	}
	c.origCap, c.origFail = nil, nil
}

// Decided records the raw production decisions (before the runner stamps dry-run,
// kill-switch or dispatch evidence) and stops recording gate verdicts.
func (c *TickCapture) Decided(decisions []model.Decision, decideErr error) {
	if c == nil || c.decided {
		return
	}
	start := time.Now()
	defer func() { c.elapsed += time.Since(start) }()
	c.decided = true
	c.restore()
	if c.failed {
		return
	}
	out := Outcome{CapabilityWired: c.ce.Capability != nil, FailureWired: c.ce.FailureExclusion != nil,
		Capability: c.capVerd, Failures: c.failVerd, Production: decisions}
	if decideErr != nil {
		out.ProductionError = decideErr.Error()
		c.header.ProductionError = out.ProductionError
	}
	for _, d := range decisions {
		if c.header.DecidedAt.IsZero() && !d.DecidedAt.IsZero() {
			c.header.DecidedAt = d.DecidedAt.UTC()
		}
		if d.Selected {
			c.header.Selected = append(c.header.Selected, d.Namespace+"/"+d.Pod+":"+string(d.Action))
		}
	}
	if err := c.enc.Encode(out); err != nil {
		c.failed = true
	}
}

// Finalize records the decisions as audited after dispatch.
func (c *TickCapture) Finalize(decisions []model.Decision) {
	if c == nil || !c.decided || c.failed || c.header.Finalized {
		return
	}
	start := time.Now()
	defer func() { c.elapsed += time.Since(start) }()
	if err := c.enc.Encode(Final{Decisions: decisions}); err != nil {
		c.failed = true
		return
	}
	c.header.Finalized = true
}

// Close hands the snapshot to the store. It never blocks; a full queue drops the snapshot.
func (c *TickCapture) Close() {
	if c == nil || c.closed {
		return
	}
	c.closed = true
	c.restore()
	result := ResultQueued
	switch {
	case !c.decided:
		result = ResultAbandoned
	case c.failed:
		result = ResultEncodeError
	case c.buf.Len() > c.r.cfg.MaxSnapshotBytes:
		result = ResultDroppedLarge
	default:
		stream := append([]byte(nil), c.buf.Bytes()...)
		if !c.r.sink.Enqueue(Pending{Header: c.header, Stream: stream}) {
			result = ResultDroppedFull
		}
	}
	c.r.observe(result, c.elapsed.Seconds(), c.buf.Len())
}
