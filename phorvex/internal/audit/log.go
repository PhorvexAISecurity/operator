/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package audit is the explainable decision log (PRD FR7 / FR6): every decision is
// recorded with its inputs (coverage value, observational context, pHold), the chosen action and
// WHY, the R6 counterfactual (what the blind machinery would have done), and the
// dry-run flag. Records go to the structured logger AND, optionally, as JSON Lines to
// a writer (the demo/forensic artifact).
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/model"
)

// Record is the serialized form of one decision (stable JSON for the audit trail).
type Record struct {
	Representation *model.Representation      `json:"representation,omitempty"`
	Existential    *model.ExistentialDecision `json:"existential,omitempty"`
	Claim          *model.ClaimScope          `json:"claim,omitempty"`
	SchemaVersion  string                     `json:"schemaVersion"`
	// SourceSchemaVersion records the input contract used by the old-to-new read shim.
	// It is process metadata, not part of the v2 wire representation.
	SourceSchemaVersion string    `json:"-"`
	Kind                string    `json:"kind"`
	Time                time.Time `json:"time"`
	Tenant              string    `json:"tenant"`
	Namespace           string    `json:"namespace"`
	Pod                 string    `json:"pod"`
	Node                string    `json:"node,omitempty"`
	Action              string    `json:"action"`
	Selected            bool      `json:"selected"`
	Feasible            bool      `json:"feasible"`
	InfeasibleWhy       string    `json:"infeasibleWhy,omitempty"`
	DryRun              bool      `json:"dryRun"`
	DryRunCause         string    `json:"dryRunCause,omitempty"`
	ActuationBrakeCause string    `json:"actuationBrakeCause,omitempty"`
	// KillSwitch is emitted only when engaged, so an existing consumer sees no change on a
	// normal tick, and a suppressed decision is no longer indistinguishable from a failed one.
	KillSwitch      bool    `json:"killSwitch,omitempty"`
	KillSwitchCause string  `json:"killSwitchCause,omitempty"`
	Actuated        bool    `json:"actuated"`
	DispatchOutcome string  `json:"dispatchOutcome,omitempty"`
	DispatchReason  string  `json:"dispatchReason,omitempty"`
	CoverageValue   float64 `json:"coverageValue"`
	// CoverageBasis qualifies selection-time coverage as a modeled opportunity,
	// never measured mitigation or observed execution.
	CoverageBasis string  `json:"coverageBasis,omitempty"`
	ThreatRisk    float64 `json:"threatRisk,omitempty"`
	Cost          float64 `json:"cost"`
	Net           float64 `json:"net"`
	Residual      float64 `json:"residual"`      // observational under P1
	ThreatPosture float64 `json:"threatPosture"` // observational under P1
	Exposure      float64 `json:"exposure"`
	PHold         float64 `json:"pHold"`
	Provenance    float64 `json:"provenance,omitempty"` // prov(key) applied to coverage in selection/demand/fallback (M-110)
	// PHoldInputs (M-143): the capped noisy-OR terms behind pHold. Emitted so a reader can see
	// that the posterior (betaMean) still moves pHold at every exposure age.
	PHoldInputs *PHoldInputsRecord `json:"pHoldInputs,omitempty"`
	// M-27 per-asset event evidence: which events were seen, how old, what weight they
	// carried, the weighted evidence sum and the evidence-following event stage.
	StageEvent         string                `json:"stageEvent,omitempty"`
	StageAI            string                `json:"stageAI,omitempty"`
	StageMergeRule     string                `json:"stageMergeRule,omitempty"`
	EventEvidence      float64               `json:"eventEvidence,omitempty"`
	Events             []model.EventEvidence `json:"events,omitempty"`
	AssetValue         float64               `json:"assetValue"`
	BlastRadius        float64               `json:"blastRadius"`
	SLOHeadroom        float64               `json:"sloHeadroom"`
	Phase              string                `json:"phase"`
	Reason             string                `json:"reason"`
	R6Counterfactual   string                `json:"r6Counterfactual"`
	CounterfactualNote string                `json:"counterfactualNote,omitempty"`
	BlindCost          float64               `json:"blindCost"` // cost R6's blind timer incurs this cycle (always rotates) — for the cost comparison

	// P1 (coverage engine) fields — present only under the p1-coverage brain.
	Engine        string                   `json:"engine,omitempty"`
	PerDollar     float64                  `json:"perDollar,omitempty"`
	CoveredWeight float64                  `json:"coveredWeight,omitempty"`
	CoveredFacts  int                      `json:"coveredFacts,omitempty"`
	Stage         string                   `json:"stage,omitempty"`
	NextStage     string                   `json:"nextStage,omitempty"`
	StageHazard   float64                  `json:"stageHazard,omitempty"`
	Lambda        float64                  `json:"lambda,omitempty"`
	Economics     *model.EconomicsMetadata `json:"economics,omitempty"`
	// ParameterSet is compact provenance for the values used by this decision.
	// The full manifest and effective override document are retained separately.
	ParameterSet *model.ParameterSetReference `json:"parameterSet,omitempty"`
	// ParameterMaterialStatus says whether the exact manifest and effective
	// override documents referenced above reached the durable sibling store.
	// A reference alone never implies that its material was retained.
	ParameterMaterialStatus string `json:"parameterMaterialStatus,omitempty"`
	ParameterMaterialReason string `json:"parameterMaterialReason,omitempty"`
	// PersistenceLearning reports the source and disposition of independent
	// categorical labels. It is provenance, not an efficacy claim.
	PersistenceLearning *model.PersistenceLearningStatus `json:"persistenceLearning,omitempty"`
	ProactiveRate       float64                          `json:"proactiveRate,omitempty"`
	Attribution         []model.AttributionTerm          `json:"attribution,omitempty"`

	// P-ACTUATOR native-actuator forensic fields — what the hands actually did, so a
	// kv-reset is distinguishable from a kill. Present only when the native actuator emitted.
	Handler             string                            `json:"handler,omitempty"`
	ObjectsTouched      []string                          `json:"objectsTouched,omitempty"`
	RollbackRef         string                            `json:"rollbackRef,omitempty"`
	MutationKind        string                            `json:"mutationKind,omitempty"`
	GracefulTermination *model.GracefulTerminationReceipt `json:"gracefulTermination,omitempty"`

	// M-18 Phoenix forensic identity of the emission attempt: the AMTD context, the
	// created SecurityEvent's name and server-assigned UID, and the logical rule tuple.
	// ADDITIVE AND OPTIONAL — a pointer with omitempty, so records that have no such
	// metadata serialize exactly as before and the v2 top-level contract is unchanged.
	// It establishes CORRELATION for an investigator, never execution success.
	//
	// COMPATIBILITY LIMIT (documented, not claimed away): a reader built before this
	// field exists simply ignores it — but such a reader CANNOT be said to preserve the
	// payload if it decodes and re-serializes a record, because the unknown field is
	// dropped on the way out. Records written before this field carry no metadata at
	// all; that means UNAVAILABLE, and never that no SecurityEvent was emitted.
	Phoenix *model.PhoenixForensics `json:"phoenix,omitempty"`
	// AdapterObservation is the exact detector assertion bound to adapter-rotate
	// selection and dispatch. Empty when no valid assertion exists.
	AdapterObservation *model.AdapterObservation `json:"adapterObservation,omitempty"`

	// P-DASHBOARD-2: the P-CONTEXT predictive horizon, serialized so the Live-Ops + Context
	// panels can stream the moved-before-next-stage story (IP-sensitive — owner-redacted).
	PreemptMargin         float64 `json:"preemptMargin,omitempty"`
	ProjectedNextStageSec float64 `json:"projectedNextStageSec,omitempty"`
	AIClassified          bool    `json:"aiClassified,omitempty"`

	// DecisionTrace is the complete, versioned decision-reconstruction payload.
	// It is nested to preserve the existing phorvex.audit.v2 top-level contract.
	DecisionTrace *model.DecisionTraceV2        `json:"decisionTrace,omitempty"`
	Measurements  *model.DecisionMeasurementsV1 `json:"measurements,omitempty"`

	// preparedRepresentation is populated only by Logger.Record after making an
	// owned, redacted representation. It is never accepted from callers or wire
	// input and cannot bypass the defensive public Representation marshaler.
	preparedRepresentation json.RawMessage
}

type recordJSONField struct {
	name  string
	value json.RawMessage
}

// splitRecordJSONObject scans a compact object produced by encoding/json. It
// retains each already-encoded value instead of decoding the entire record into
// interface-backed RawMessages and encoding those values a second time.
func splitRecordJSONObject(b []byte) ([]recordJSONField, error) {
	if len(b) < 2 || b[0] != '{' || b[len(b)-1] != '}' {
		return nil, fmt.Errorf("audit record encoder returned a non-object")
	}
	body := b[1 : len(b)-1]
	if len(body) == 0 {
		return nil, nil
	}
	fields := make([]recordJSONField, 0, 64)
	start, depth := 0, 0
	inString, escaped := false, false
	appendField := func(raw []byte) error {
		colon := -1
		quoted, slash := false, false
		for i, c := range raw {
			if quoted {
				if slash {
					slash = false
				} else if c == '\\' {
					slash = true
				} else if c == '"' {
					quoted = false
				}
				continue
			}
			if c == '"' {
				quoted = true
			} else if c == ':' {
				colon = i
				break
			}
		}
		if colon <= 0 {
			return fmt.Errorf("audit record encoder returned an invalid field")
		}
		var name string
		if err := json.Unmarshal(raw[:colon], &name); err != nil {
			return err
		}
		fields = append(fields, recordJSONField{name: name, value: raw[colon+1:]})
		return nil
	}
	for i, c := range body {
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			if depth == 0 {
				if err := appendField(body[start:i]); err != nil {
					return nil, err
				}
				start = i + 1
			}
		}
	}
	if inString || depth != 0 {
		return nil, fmt.Errorf("audit record encoder returned an unterminated field")
	}
	if err := appendField(body[start:]); err != nil {
		return nil, err
	}
	return fields, nil
}

func marshalSortedRecordObject(b []byte, additions map[string]json.RawMessage) ([]byte, error) {
	fields, err := splitRecordJSONObject(b)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]json.RawMessage, len(fields)+len(additions))
	for _, field := range fields {
		byName[field.name] = field.value
	}
	for name, value := range additions {
		byName[name] = value
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	var out bytes.Buffer
	out.Grow(len(b) + 64)
	out.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			out.WriteByte(',')
		}
		nameJSON, _ := json.Marshal(name)
		out.Write(nameJSON)
		out.WriteByte(':')
		out.Write(byName[name])
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// MarshalJSON is the only write direction: canonical v2. Legacy compatibility is intentionally
// old-to-new on read; this package never writes a downgraded v0/v1 record.
func (r Record) MarshalJSON() ([]byte, error) {
	type recordAlias Record
	r.SchemaVersion = SchemaVersionCurrent
	r.Attribution = canonicalizeAttribution(r.Attribution)
	if err := validateMeasurements(r.Measurements); err != nil {
		return nil, err
	}
	if err := measurementsMatch(r); err != nil {
		return nil, err
	}
	if err := model.ValidateEconomicsMetadata(r.Economics); err != nil {
		return nil, err
	}
	if r.ParameterSet != nil {
		if err := r.ParameterSet.Validate(); err != nil {
			return nil, err
		}
	}
	if err := validateParameterMaterialStatus(r.ParameterSet, r.ParameterMaterialStatus, r.ParameterMaterialReason); err != nil {
		return nil, err
	}
	if err := model.ValidatePersistenceLearningStatus(r.PersistenceLearning); err != nil {
		return nil, err
	}
	if !EconomicsMatchesRoundedLambda(r.Economics, r.Lambda) {
		return nil, fmt.Errorf("rounded lambda alias contradicts exact economics metadata")
	}
	prepared := r.preparedRepresentation
	if len(prepared) != 0 {
		r.Representation = nil
	}
	b, err := json.Marshal(recordAlias(r))
	if err != nil || r.Measurements == nil {
		return b, err
	}
	additions := make(map[string]json.RawMessage, 14)
	if len(prepared) != 0 {
		additions["representation"] = prepared
	}
	put := func(name string, present bool, value any) error {
		if !present {
			return nil
		}
		v, err := json.Marshal(value)
		if err == nil {
			additions[name] = v
		}
		return err
	}
	m := r.Measurements
	for _, item := range []struct {
		name    string
		present bool
		value   any
	}{
		{"threatRisk", m.ThreatRisk.Present, r.ThreatRisk}, {"perDollar", m.PerDollar.Present, r.PerDollar},
		{"coveredWeight", m.CoveredWeight.Present, r.CoveredWeight}, {"coveredFacts", m.CoveredFacts.Present, r.CoveredFacts},
		{"stageHazard", m.StageHazard.Present, r.StageHazard}, {"lambda", m.Lambda.Present, r.Lambda},
		{"proactiveRate", m.ProactiveRate.Present, r.ProactiveRate}, {"preemptMargin", m.PreemptMargin.Present, r.PreemptMargin},
		{"projectedNextStageSec", m.ProjectedNextStageSec.Present, r.ProjectedNextStageSec}, {"killSwitch", m.KillSwitch.Present, r.KillSwitch},
		{"aiClassified", m.AIClassified.Present, r.AIClassified}, {"eventEvidence", m.EventEvidence.Present, r.EventEvidence},
		{"provenance", m.Provenance.Present, r.Provenance},
	} {
		if err := put(item.name, item.present, item.value); err != nil {
			return nil, err
		}
	}
	return marshalSortedRecordObject(b, additions)
}

// UnmarshalJSON translates v0/v1 records into the canonical v2 in-memory shape. The shim expires
// when ReadTranslationExpiresAt becomes current; extending it requires an explicit schema decision.
func (r *Record) UnmarshalJSON(data []byte) error {
	type recordAlias Record
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var decoded recordAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	sourceVersion := decoded.SchemaVersion
	if sourceVersion == "" {
		sourceVersion = SchemaVersionLegacy
	}
	switch sourceVersion {
	case SchemaVersionCurrent:
		if _, oldRisk := fields["risk"]; oldRisk {
			return fmt.Errorf("%s record contains retired field %q", SchemaVersionCurrent, "risk")
		}
		if _, oldBelief := fields["belief"]; oldBelief {
			return fmt.Errorf("%s record contains retired field %q", SchemaVersionCurrent, "belief")
		}
		for _, term := range decoded.Attribution {
			if term.Source == "cover:modelFingerprint" || term.Source == "cover:nodePlacement" {
				return fmt.Errorf("%s record contains retired attribution source %q", SchemaVersionCurrent, term.Source)
			}
		}
	case SchemaVersionLegacy, SchemaVersionPrevious:
		var oldRisk float64
		if raw, ok := fields["risk"]; ok {
			if err := json.Unmarshal(raw, &oldRisk); err != nil {
				return fmt.Errorf("translate risk: %w", err)
			}
		}
		if decoded.Engine == "p1-coverage" {
			decoded.CoverageValue = oldRisk
		} else {
			decoded.ThreatRisk = oldRisk
		}
		// pHold is authoritative when both old names exist. belief is only the
		// compatibility fallback for P0 and early records that omitted pHold.
		if _, hasPHold := fields["pHold"]; !hasPHold {
			if raw, hasBelief := fields["belief"]; hasBelief {
				if err := json.Unmarshal(raw, &decoded.PHold); err != nil {
					return fmt.Errorf("translate belief: %w", err)
				}
			}
		}
	default:
		return fmt.Errorf("unsupported audit schemaVersion %q", sourceVersion)
	}
	decoded.SchemaVersion = SchemaVersionCurrent
	decoded.SourceSchemaVersion = sourceVersion
	decoded.Attribution = canonicalizeAttribution(decoded.Attribution)
	if decoded.Measurements == nil {
		decoded.Measurements = legacyMeasurements(fields, Record(decoded))
	}
	if err := validateMeasurements(decoded.Measurements); err != nil {
		return err
	}
	if err := measurementsHaveFields(decoded.Measurements, fields); err != nil {
		return err
	}
	if err := measurementsMatch(Record(decoded)); err != nil {
		return err
	}
	if err := model.ValidateEconomicsMetadata(decoded.Economics); err != nil {
		return err
	}
	if decoded.ParameterSet != nil {
		if err := decoded.ParameterSet.Validate(); err != nil {
			return err
		}
		if decoded.ParameterMaterialStatus == "" {
			decoded.ParameterMaterialStatus = parameterMaterialUnavailable
			decoded.ParameterMaterialReason = "legacy-unreported"
		}
	}
	if err := validateParameterMaterialStatus(decoded.ParameterSet, decoded.ParameterMaterialStatus, decoded.ParameterMaterialReason); err != nil {
		return err
	}
	if err := model.ValidatePersistenceLearningStatus(decoded.PersistenceLearning); err != nil {
		return err
	}
	if !EconomicsMatchesRoundedLambda(decoded.Economics, decoded.Lambda) {
		return fmt.Errorf("rounded lambda alias contradicts exact economics metadata")
	}
	*r = Record(decoded)
	return nil
}

// Logger writes decision records.
type Logger struct {
	log     logr.Logger
	mu      sync.Mutex
	jsonOut io.Writer // optional JSON-Lines sink (the single shared / single-tenant sink)
	// [P-VCLUSTER O10] sinkFor, when set, routes each record to a PER-TENANT sink (by rec.Tenant) so a
	// noisy tenant's rotation cannot evict another tenant's audit history. nil => the single jsonOut
	// (byte-identical single-tenant path).
	sinkFor            func(tenant string) io.Writer
	degraded           map[string]bool // sink routes awaiting a subsequent successful persistence attempt
	parameterStore     *ParameterMaterialStore
	parameterRetention map[string]parameterMaterialRetention
	parameterOrder     []string
	parameterNext      int
	parameterMu        sync.Mutex
	// OnlySelected, when true, logs only Selected (non-noop) decisions to the logger
	// to keep operator logs quiet; the JSON sink (if set) always gets every record.
	OnlySelected bool
}

// SetTenantSink installs a per-tenant JSON-Lines sink router (O10 audit isolation): each tenant's
// records go to its OWN writer, so one tenant's volume/rotation never evicts another's history. Pass
// nil to revert to the single shared sink.
func (l *Logger) SetTenantSink(router func(tenant string) io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sinkFor = router
}

// New constructs a Logger. jsonOut may be nil.
func New(log logr.Logger, jsonOut io.Writer) *Logger {
	return &Logger{log: log.WithName("audit"), jsonOut: jsonOut, OnlySelected: true}
}

const (
	parameterMaterialRetained    = "retained"
	parameterMaterialUnavailable = "unavailable"
	parameterMaterialFailed      = "failed"
	maxParameterRetentionEntries = MaxParameterMaterialDocuments
)

type parameterMaterialRetention struct{ status, reason string }

// setParameterRetentionLocked bounds transient per-reference outcomes separately
// from the immutable sibling store. Eviction loses only the ability to assert a
// retention result on a later row; a miss is reported as unavailable and never
// deletes or contradicts durable material.
func (l *Logger) setParameterRetentionLocked(key string, retention parameterMaterialRetention) {
	if l.parameterRetention == nil {
		l.parameterRetention = make(map[string]parameterMaterialRetention)
	}
	if _, exists := l.parameterRetention[key]; exists {
		l.parameterRetention[key] = retention
		return
	}
	if len(l.parameterOrder) < maxParameterRetentionEntries {
		l.parameterOrder = append(l.parameterOrder, key)
	} else {
		delete(l.parameterRetention, l.parameterOrder[l.parameterNext])
		l.parameterOrder[l.parameterNext] = key
		l.parameterNext = (l.parameterNext + 1) % maxParameterRetentionEntries
	}
	l.parameterRetention[key] = retention
}

func parameterMaterialKey(ref *model.ParameterSetReference) string {
	if ref == nil {
		return ""
	}
	return ref.ManifestHash + "\x00" + ref.PolicyOverridesHash
}

func validateParameterMaterialStatus(ref *model.ParameterSetReference, status, reason string) error {
	if ref == nil {
		if status != "" || reason != "" {
			return errors.New("parameter material status has no parameter-set reference")
		}
		return nil
	}
	switch status {
	case parameterMaterialRetained:
		if reason != "" {
			return errors.New("retained parameter material has a failure reason")
		}
	case parameterMaterialUnavailable, parameterMaterialFailed:
		if reason == "" {
			return errors.New("unretained parameter material requires a bounded reason")
		}
	default:
		return errors.New("parameter-set reference has no valid material retention status")
	}
	return nil
}

// SetParameterMaterialStore installs the durable content-addressed sibling
// store used by production audit. nil preserves an explicit unavailable state.
func (l *Logger) SetParameterMaterialStore(store *ParameterMaterialStore) {
	l.parameterMu.Lock()
	defer l.parameterMu.Unlock()
	l.parameterStore = store
}

// RetainParameterSet verifies and persists exact source/effective inputs before
// decision rows are written. Failure is audit degradation, not actuation input.
func (l *Logger) RetainParameterSet(tenant string, ref *model.ParameterSetReference, manifest model.DecisionParameterManifest, overrides model.EffectivePolicyOverrides) error {
	key := parameterMaterialKey(ref)
	l.parameterMu.Lock()
	defer l.parameterMu.Unlock()
	if err := model.VerifyParameterSet(ref, &manifest, &overrides); err != nil {
		l.setParameterRetentionLocked(key, parameterMaterialRetention{parameterMaterialFailed, "material-invalid"})
		parameterMaterialErrors.WithLabelValues(parameterMaterialFailed).Inc()
		l.log.Error(err, "parameter material verification failed", "tenant", tenant)
		return err
	}
	if l.parameterStore == nil {
		err := errors.New("parameter material store is not configured")
		l.setParameterRetentionLocked(key, parameterMaterialRetention{parameterMaterialUnavailable, "store-unconfigured"})
		parameterMaterialErrors.WithLabelValues(parameterMaterialUnavailable).Inc()
		l.log.Error(err, "parameter material retention unavailable", "tenant", tenant)
		return err
	}
	if err := l.parameterStore.Store(ref, manifest, overrides); err != nil {
		l.setParameterRetentionLocked(key, parameterMaterialRetention{parameterMaterialFailed, "store-write-failed"})
		parameterMaterialErrors.WithLabelValues(parameterMaterialFailed).Inc()
		l.log.Error(err, "parameter material retention failed", "tenant", tenant)
		return err
	}
	l.setParameterRetentionLocked(key, parameterMaterialRetention{parameterMaterialRetained, ""})
	return nil
}

func (l *Logger) parameterMaterialStatus(ref *model.ParameterSetReference) parameterMaterialRetention {
	if ref == nil {
		return parameterMaterialRetention{}
	}
	l.parameterMu.Lock()
	defer l.parameterMu.Unlock()
	if retained, ok := l.parameterRetention[parameterMaterialKey(ref)]; ok {
		return retained
	}
	return parameterMaterialRetention{parameterMaterialUnavailable, "material-not-retained"}
}

// ToRecord converts a Decision to a Record.
func ToRecord(d model.Decision) Record {
	return toRecord(d, false)
}

func toRecord(d model.Decision, prepareWire bool) Record {
	claim := model.NewClaimScope(nil, false, "", "")
	if d.Trace != nil {
		claim = model.NewClaimScope(nil, false, d.Trace.BrainImage, d.Trace.GitSHA)
	}
	if d.Claim != nil {
		claim = model.NewClaimScope(d.Claim.DetectorSet, d.Claim.DetectorSetKnown, d.Claim.BrainImage, d.Claim.GitSHA)
	}
	coverageBasis := ""
	if d.Engine == "p1-coverage" {
		coverageBasis = "modeled-selection-opportunity"
	}
	dispatchOutcome := model.SafeDispatchOutcome(d.DispatchOutcome)
	dispatchReason := ""
	if dispatchOutcome != "" {
		dispatchReason = model.SafeDispatchReason(d.DispatchReason)
	}
	var representation *model.Representation
	var economics *model.EconomicsMetadata
	if d.Economics != nil {
		copy := *d.Economics
		economics = &copy
	}
	var parameterSet *model.ParameterSetReference
	if d.ParameterSet != nil {
		copy := *d.ParameterSet
		parameterSet = &copy
	}
	var persistenceLearning *model.PersistenceLearningStatus
	if d.PersistenceLearning != nil {
		copy := *d.PersistenceLearning
		if copy.Policy != nil {
			epoch := *copy.Policy
			copy.Policy = &epoch
		}
		persistenceLearning = &copy
	}
	var preparedRepresentation json.RawMessage
	if prepareWire && d.Measurements != nil {
		representation, preparedRepresentation = prepareRepresentation(d.Representation)
	} else {
		representation = cloneRepresentation(d.Representation)
	}
	record := Record{
		AdapterObservation:     d.AdapterObservation,
		Representation:         representation,
		Existential:            d.Existential,
		Claim:                  &claim,
		SchemaVersion:          SchemaVersionCurrent,
		SourceSchemaVersion:    SchemaVersionCurrent,
		Kind:                   "phorvex.decision",
		Time:                   d.DecidedAt,
		Tenant:                 d.Tenant,
		Namespace:              d.Namespace,
		Pod:                    d.Pod,
		Node:                   d.Node,
		Action:                 string(d.Action),
		Selected:               d.Selected,
		Feasible:               d.Feasible,
		InfeasibleWhy:          d.InfeasibleWhy,
		DryRun:                 d.DryRun,
		DryRunCause:            d.DryRunCause,
		ActuationBrakeCause:    d.ActuationBrakeCause,
		KillSwitch:             d.KillSwitch,
		KillSwitchCause:        d.KillSwitchCause,
		Actuated:               d.Actuated,
		DispatchOutcome:        dispatchOutcome,
		DispatchReason:         dispatchReason,
		CoverageValue:          round4(d.CoverageValue),
		CoverageBasis:          coverageBasis,
		ThreatRisk:             round4(d.ThreatRisk),
		Cost:                   round4(d.Cost),
		Net:                    round4(d.Net),
		Residual:               round4(d.Residual),
		ThreatPosture:          round4(d.ThreatPosture),
		Exposure:               round4(d.Exposure),
		AssetValue:             round4(d.AssetValue),
		BlastRadius:            round4(d.BlastRadius),
		SLOHeadroom:            round4(d.SLOHeadroom),
		Phase:                  string(d.Phase),
		Reason:                 d.Reason,
		R6Counterfactual:       string(d.R6Counterfactual),
		CounterfactualNote:     d.CounterfactualNote,
		BlindCost:              round4(d.BlindCost),
		Engine:                 d.Engine,
		PerDollar:              round4(d.PerDollar),
		CoveredWeight:          round4(d.CoveredWeight),
		CoveredFacts:           d.CoveredFacts,
		Stage:                  d.Stage,
		NextStage:              d.NextStage,
		StageHazard:            round4(d.StageHazard),
		PHold:                  round4(d.PHold),
		Provenance:             round4(d.Provenance),
		PHoldInputs:            pHoldInputsRecord(d.PHoldInputs),
		StageEvent:             d.StageEvent,
		StageAI:                d.StageAI,
		StageMergeRule:         d.StageMergeRule,
		EventEvidence:          round4(d.EventEvidence),
		Events:                 roundEvents(d.Events),
		Lambda:                 round4(d.Lambda),
		Economics:              economics,
		ParameterSet:           parameterSet,
		PersistenceLearning:    persistenceLearning,
		ProactiveRate:          round4(d.ProactiveRate),
		Attribution:            canonicalizeAttribution(d.Attribution),
		Handler:                d.Handler,
		ObjectsTouched:         d.ObjectsTouched,
		RollbackRef:            d.RollbackRef,
		MutationKind:           d.MutationKind,
		GracefulTermination:    gracefulTerminationRecord(d.GracefulTermination),
		Phoenix:                phoenixRecord(d.Phoenix),
		PreemptMargin:          round4(d.PreemptMargin),
		ProjectedNextStageSec:  round4(d.ProjectedNextStageSec),
		AIClassified:           d.AIClassified,
		DecisionTrace:          d.Trace,
		Measurements:           recordMeasurements(d.Measurements),
		preparedRepresentation: preparedRepresentation,
	}
	if parameterSet != nil {
		record.ParameterMaterialStatus = parameterMaterialUnavailable
		record.ParameterMaterialReason = "material-not-retained"
	}
	return record
}

func gracefulTerminationRecord(in *model.GracefulTerminationReceipt) *model.GracefulTerminationReceipt {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func recordMeasurements(in *model.DecisionMeasurementsV1) *model.DecisionMeasurementsV1 {
	if in == nil {
		return nil
	}
	m := *in
	for _, v := range []*model.OptionalFloat{&m.ThreatRisk, &m.PerDollar, &m.CoveredWeight, &m.StageHazard, &m.Lambda, &m.ProactiveRate, &m.PreemptMargin, &m.ProjectedNextStageSec, &m.EventEvidence, &m.Provenance} {
		if v.Present && !math.IsNaN(v.Value) && !math.IsInf(v.Value, 0) {
			v.Value = round4(v.Value)
		}
	}
	return &m
}

func legacyMeasurements(fields map[string]json.RawMessage, r Record) *model.DecisionMeasurementsV1 {
	m := &model.DecisionMeasurementsV1{SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "legacy-recorded"}
	seen := false
	present := func(name string) bool { raw, ok := fields[name]; return ok && string(raw) != "null" }
	setF := func(name string, dst *model.OptionalFloat) {
		if present(name) {
			dst.Present = true
			seen = true
		}
	}
	setI := func(name string, dst *model.OptionalInt) {
		if present(name) {
			dst.Present = true
			seen = true
		}
	}
	setB := func(name string, dst *model.OptionalBool) {
		if present(name) {
			dst.Present = true
			seen = true
		}
	}
	setF("threatRisk", &m.ThreatRisk)
	setF("perDollar", &m.PerDollar)
	setF("coveredWeight", &m.CoveredWeight)
	setI("coveredFacts", &m.CoveredFacts)
	setF("stageHazard", &m.StageHazard)
	setF("lambda", &m.Lambda)
	setF("proactiveRate", &m.ProactiveRate)
	setF("preemptMargin", &m.PreemptMargin)
	setF("projectedNextStageSec", &m.ProjectedNextStageSec)
	setB("killSwitch", &m.KillSwitch)
	setB("aiClassified", &m.AIClassified)
	setF("eventEvidence", &m.EventEvidence)
	setF("provenance", &m.Provenance)
	if present("risk") && r.Engine == "p0-greedy" {
		m.ThreatRisk.Present = true
		seen = true
	}
	if !seen {
		return nil
	}
	m.ThreatRisk.Value = r.ThreatRisk
	m.PerDollar.Value = r.PerDollar
	m.CoveredWeight.Value = r.CoveredWeight
	m.CoveredFacts.Value = r.CoveredFacts
	m.StageHazard.Value = r.StageHazard
	m.Lambda.Value = r.Lambda
	m.ProactiveRate.Value = r.ProactiveRate
	m.PreemptMargin.Value = r.PreemptMargin
	m.ProjectedNextStageSec.Value = r.ProjectedNextStageSec
	m.KillSwitch.Value = r.KillSwitch
	m.AIClassified.Value = r.AIClassified
	m.EventEvidence.Value = r.EventEvidence
	m.Provenance.Value = r.Provenance
	return m
}

func measurementsHaveFields(m *model.DecisionMeasurementsV1, fields map[string]json.RawMessage) error {
	if m == nil {
		return nil
	}
	for name, present := range map[string]bool{"threatRisk": m.ThreatRisk.Present, "perDollar": m.PerDollar.Present, "coveredWeight": m.CoveredWeight.Present, "coveredFacts": m.CoveredFacts.Present, "stageHazard": m.StageHazard.Present, "lambda": m.Lambda.Present, "proactiveRate": m.ProactiveRate.Present, "preemptMargin": m.PreemptMargin.Present, "projectedNextStageSec": m.ProjectedNextStageSec.Present, "killSwitch": m.KillSwitch.Present, "aiClassified": m.AIClassified.Present, "eventEvidence": m.EventEvidence.Present, "provenance": m.Provenance.Present} {
		raw, ok := fields[name]
		if name == "threatRisk" && m.Source == "legacy-recorded" && !ok {
			raw, ok = fields["risk"]
		}
		if present && (!ok || string(raw) == "null") {
			return fmt.Errorf("measurements %s is present without a recorded top-level value", name)
		}
	}
	return nil
}

func validateMeasurements(m *model.DecisionMeasurementsV1) error {
	if m == nil {
		return nil
	}
	if m.SchemaVersion != model.DecisionMeasurementsSchemaV1 {
		return fmt.Errorf("unsupported measurements schemaVersion %q", m.SchemaVersion)
	}
	if m.Source == "" {
		return fmt.Errorf("measurements source is required")
	}
	for name, v := range map[string]model.OptionalFloat{"threatRisk": m.ThreatRisk, "perDollar": m.PerDollar, "coveredWeight": m.CoveredWeight, "stageHazard": m.StageHazard, "lambda": m.Lambda, "proactiveRate": m.ProactiveRate, "preemptMargin": m.PreemptMargin, "projectedNextStageSec": m.ProjectedNextStageSec, "eventEvidence": m.EventEvidence, "provenance": m.Provenance} {
		if v.Present && (math.IsNaN(v.Value) || math.IsInf(v.Value, 0)) {
			return fmt.Errorf("measurements %s is non-finite", name)
		}
	}
	return nil
}

func measurementsMatch(r Record) error {
	if r.Measurements == nil {
		return nil
	}
	m := r.Measurements
	for name, item := range map[string]struct {
		p    bool
		a, b float64
	}{"threatRisk": {m.ThreatRisk.Present, m.ThreatRisk.Value, r.ThreatRisk}, "perDollar": {m.PerDollar.Present, m.PerDollar.Value, r.PerDollar}, "coveredWeight": {m.CoveredWeight.Present, m.CoveredWeight.Value, r.CoveredWeight}, "stageHazard": {m.StageHazard.Present, m.StageHazard.Value, r.StageHazard}, "lambda": {m.Lambda.Present, m.Lambda.Value, r.Lambda}, "proactiveRate": {m.ProactiveRate.Present, m.ProactiveRate.Value, r.ProactiveRate}, "preemptMargin": {m.PreemptMargin.Present, m.PreemptMargin.Value, r.PreemptMargin}, "projectedNextStageSec": {m.ProjectedNextStageSec.Present, m.ProjectedNextStageSec.Value, r.ProjectedNextStageSec}, "eventEvidence": {m.EventEvidence.Present, m.EventEvidence.Value, r.EventEvidence}, "provenance": {m.Provenance.Present, m.Provenance.Value, r.Provenance}} {
		if item.p && item.a != item.b {
			return fmt.Errorf("measurements %s does not match top-level value", name)
		}
	}
	if (m.CoveredFacts.Present && m.CoveredFacts.Value != r.CoveredFacts) || (m.KillSwitch.Present && m.KillSwitch.Value != r.KillSwitch) || (m.AIClassified.Present && m.AIClassified.Value != r.AIClassified) {
		return fmt.Errorf("measurements do not match top-level values")
	}
	return nil
}

// phoenixRecord deep-copies the decision's Phoenix payload into the record (M-18).
//
// The record must OWN its copy. Sharing the pointer would let any later write to
// decision.Phoenix — the next tick's clear, or a reused decision being re-mapped — change
// what an already-built Record reports. That is a lifetime property, not a threading one:
// Logger.Record calls ToRecord and writeRecord synchronously today, and the copy holds
// regardless of whether that stays true. PhoenixForensics is all-scalar, so copying the
// value is a complete deep copy — there is no reference field left aliased. nil stays nil:
// absence is preserved, never materialized into empty strings.
func phoenixRecord(p *model.PhoenixForensics) *model.PhoenixForensics {
	if p == nil {
		return nil
	}
	owned := *p
	return &owned
}

// Record logs one decision.
func (l *Logger) Record(d model.Decision) error {
	rec := toRecord(d, true)
	retention := l.parameterMaterialStatus(rec.ParameterSet)
	rec.ParameterMaterialStatus = retention.status
	rec.ParameterMaterialReason = retention.reason
	err := l.writeRecord(rec.Tenant, rec)
	if l.OnlySelected && !d.Selected && (d.Existential == nil || (len(d.Existential.Evidence) == 0 && len(d.Existential.Reasons) == 0)) {
		return err
	}
	existentialJSON := ""
	if d.Existential != nil {
		if b, err := json.Marshal(d.Existential); err == nil {
			existentialJSON = string(b)
		}
	}
	l.log.Info("decision",
		"existential", existentialJSON,
		"tenant", rec.Tenant, "pod", rec.Namespace+"/"+rec.Pod, "action", rec.Action,
		"selected", rec.Selected, "feasible", rec.Feasible, "dryRun", rec.DryRun,
		"actuated", rec.Actuated, "dispatchOutcome", rec.DispatchOutcome, "dispatchReason", rec.DispatchReason,
		"dryRunCause", rec.DryRunCause, "actuationBrakeCause", rec.ActuationBrakeCause,
		"representation", rec.Representation, "claim", rec.Claim, "engine", rec.Engine,
		"coverageValue", rec.CoverageValue, "coverageBasis", rec.CoverageBasis,
		"perDollar", rec.PerDollar, "coveredWeight", rec.CoveredWeight, "coveredFacts", rec.CoveredFacts,
		"stage", rec.Stage, "nextStage", rec.NextStage, "hazard", rec.StageHazard,
		"pHold", rec.PHold, "lambda", rec.Lambda, "proactiveRate", rec.ProactiveRate,
		"economics", rec.Economics,
		"persistenceLearning", rec.PersistenceLearning,
		"cost", rec.Cost, "net", rec.Net, "asset", rec.AssetValue, "blast", rec.BlastRadius,
		"attribution", rec.Attribution,
		"r6Would", rec.R6Counterfactual, "r6Note", rec.CounterfactualNote,
		"why", rec.Reason, "infeasibleWhy", rec.InfeasibleWhy)
	return err
}

// TickSummary logs one completed per-tenant tick rollup. Outcome is explicit so
// a healthy empty tick cannot be confused with a checked-selection refusal.
func (l *Logger) TickSummary(tenant string, total, selected, infeasible int, dur time.Duration, mode string, killSwitch bool, killSwitchCause string) {
	l.tickSummary(tenant, "", "", "", total, selected, infeasible, dur, mode, "completed", "", killSwitch, killSwitchCause)
}

// TickSummaryForPolicy adds the exact M-140 owner identity to a completed
// rollup. TickSummary remains available for callers that do not own that context.
func (l *Logger) TickSummaryForPolicy(tenant, namespace, policy, uid string, total, selected, infeasible int, dur time.Duration, mode string, killSwitch bool, killSwitchCause string) {
	l.tickSummary(tenant, namespace, policy, uid, total, selected, infeasible, dur, mode, "completed", "", killSwitch, killSwitchCause)
}

// RejectedTickSummary logs a checked-selection refusal without fabricating a
// zero-decision result. reason must come from the runner's closed classifier.
func (l *Logger) RejectedTickSummary(tenant, namespace, policy, uid string, protected int, dur time.Duration, mode, reason string, killSwitch bool, killSwitchCause string) {
	l.tickSummary(tenant, namespace, policy, uid, protected, 0, 0, dur, mode, "selection-rejected", reason, killSwitch, killSwitchCause)
}

func (l *Logger) tickSummary(tenant, namespace, policy, uid string, total, selected, infeasible int, dur time.Duration, mode, outcome, reason string, killSwitch bool, killSwitchCause string) {
	fields := []any{"tenant", tenant}
	if namespace != "" || policy != "" || uid != "" {
		fields = append(fields, "namespace", namespace, "policy", policy, "policyUID", uid)
	}
	fields = append(fields, "pods", total)
	if outcome == "completed" {
		fields = append(fields, "selected", selected, "infeasible", infeasible)
	}
	fields = append(fields, "mode", mode, "outcome", outcome)
	if reason != "" {
		fields = append(fields, "reason", reason)
	}
	fields = append(fields, "killSwitch", killSwitch, "killSwitchCause", killSwitchCause, "durationMs", dur.Milliseconds())
	l.log.Info("tick", fields...)
}

func round4(x float64) float64 {
	return float64(int64(x*10000+sign(x)*0.5)) / 10000
}

// EconomicsMatchesRoundedLambda verifies the legacy display alias without
// discarding the descriptor's authoritative full-precision runtime value.
// Records written before economics metadata remain readable.
func EconomicsMatchesRoundedLambda(metadata *model.EconomicsMetadata, roundedLambda float64) bool {
	return metadata == nil || (metadata.LambdaRuntimeLegacy.Present && round4(metadata.LambdaRuntimeLegacy.Value) == roundedLambda)
}

func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}

// PHoldInputsRecord is the audited form of model.PHoldInputs (M-143).
type PHoldInputsRecord struct {
	BetaMean float64 `json:"betaMean"`
	Pressure float64 `json:"p"`
	Cap      float64 `json:"cap"` // INSUFFICIENT EVIDENCE — provisional, fit in T3-D
	ScaleSec float64 `json:"scaleSec"`
	Raw      float64 `json:"raw"`
	Final    float64 `json:"final"`
}

func pHoldInputsRecord(in model.PHoldInputs) *PHoldInputsRecord {
	if in.Cap == 0 && in.ScaleSec == 0 && in.Raw == 0 && in.Final == 0 {
		return nil // engine that does not compute pHold inputs (p0-greedy)
	}
	return &PHoldInputsRecord{
		BetaMean: round4(in.BetaMean), Pressure: round4(in.Pressure), Cap: round4(in.Cap),
		ScaleSec: round4(in.ScaleSec), Raw: round4(in.Raw), Final: round4(in.Final),
	}
}

func roundEvents(in []model.EventEvidence) []model.EventEvidence {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.EventEvidence, len(in))
	for i, e := range in {
		e.AgeSec = round4(e.AgeSec)
		e.Weight = round4(e.Weight)
		out[i] = e
	}
	return out
}

// TenantLifecycle records the completion of one ownership transition (M-140). It is emitted
// at the tick-loop DRAIN, which is where removal actually completes — never at enqueue, so
// the record cannot claim a prune that has not happened yet. replacedBy is set when an
// Upsert changed identity without a preceding NotFound reconcile.
func (l *Logger) TenantLifecycle(tenant, owner, replacedBy string, storesPruned int) {
	event := "removed"
	if replacedBy != "" {
		event = "replaced"
	}
	l.log.Info("tenant-lifecycle",
		"tenant", tenant, "owner", owner, "event", event,
		"replacedBy", replacedBy, "storesPruned", storesPruned)
}

// TenantDisplayNameChanged records a label-only maintenance event (M-140): the policy's
// spec.tenant display name changed while its UID — and therefore its economic identity,
// learned state and creation record — stayed exactly the same. It is deliberately NOT a
// lifecycle removal: nothing was retired, only stale label series were retracted.
func (l *Logger) TenantDisplayNameChanged(previousTenant, currentTenant, owner string) {
	l.log.Info("tenant-display-name-changed",
		"previousTenant", previousTenant, "tenant", currentTenant, "owner", owner,
		"economicIdentityRetained", true)
}

// Maintenance records every attempted administrative recovery, including refused
// and partial outcomes. It is a separate wire kind from decision records.
func (l *Logger) Maintenance(receipt, kind, tenant, namespace, policy, policyUID, targetName, targetUID, outcome, effect string, failure error) {
	reason := ""
	if failure != nil {
		reason = failure.Error()
	}
	rec := struct {
		SchemaVersion string    `json:"schemaVersion"`
		Kind          string    `json:"kind"`
		Time          time.Time `json:"time"`
		Receipt       string    `json:"receipt"`
		Operation     string    `json:"operation"`
		Tenant        string    `json:"tenant,omitempty"`
		Namespace     string    `json:"namespace"`
		Policy        string    `json:"policy"`
		PolicyUID     string    `json:"policyUID"`
		TargetName    string    `json:"targetName"`
		TargetUID     string    `json:"targetUID"`
		Outcome       string    `json:"outcome"`
		Effect        string    `json:"effect"`
		Error         string    `json:"error,omitempty"`
	}{SchemaVersionCurrent, "phorvex.maintenance", time.Now().UTC(), receipt, kind, tenant, namespace, policy, policyUID, targetName, targetUID, outcome, effect, reason}
	l.log.Info("maintenance", "receipt", receipt, "operation", kind, "namespace", namespace, "policy", policy, "policyUID", policyUID, "target", targetName, "targetUID", targetUID, "outcome", outcome, "effect", effect, "error", reason)
	b, err := json.Marshal(rec)
	if err != nil {
		l.log.Error(err, "maintenance audit encoding failed")
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.jsonOut
	if l.sinkFor != nil && tenant != "" {
		out = l.sinkFor(tenant)
	}
	if out != nil {
		if _, err := out.Write(append(b, '\n')); err != nil {
			l.log.Error(err, "maintenance audit persistence failed")
		}
	}
}

// RotationObservationTerminated records that an in-flight rotation observation ended because
// its owning policy was removed. ledgerRecorded distinguishes the two honest arms: with an
// existing entry the ledger is left untouched (its measured or censored amounts stand), and
// without one a single unmeasured emitted outcome was written.
func (l *Logger) RotationObservationTerminated(tenant, owner, namespace, pod string, ledgerRecorded bool) {
	l.log.Info("rotation-observation-terminated",
		"tenant", tenant, "owner", owner, "namespace", namespace, "pod", pod,
		"priorLedgerEntry", ledgerRecorded)
}

// RotationObservation appends asynchronous Phoenix execution/recovery evidence.
// It never rewrites the dispatch decision: EventUID and TargetUID bind this row
// to the exact submitted event and selected Pod, while the two booleans keep
// accepted execution distinct from replacement readiness.
func (l *Logger) RotationObservation(tenant, owner, decisionID, namespace, pod, targetUID, eventName, eventUID, outcome string, executionConfirmed, recoveryConfirmed bool, startedAt, observedAt time.Time) {
	rec := struct {
		SchemaVersion      string    `json:"schemaVersion"`
		Kind               string    `json:"kind"`
		Time               time.Time `json:"time"`
		Tenant             string    `json:"tenant"`
		Owner              string    `json:"owner"`
		DecisionID         string    `json:"decisionID,omitempty"`
		Namespace          string    `json:"namespace"`
		Pod                string    `json:"pod"`
		TargetUID          string    `json:"targetUID"`
		Action             string    `json:"action"`
		Backend            string    `json:"backend"`
		EventName          string    `json:"eventName"`
		EventUID           string    `json:"eventUID"`
		Outcome            string    `json:"outcome"`
		ExecutionConfirmed bool      `json:"executionConfirmed"`
		RecoveryConfirmed  bool      `json:"recoveryConfirmed"`
		StartedAt          time.Time `json:"startedAt"`
		ObservedAt         time.Time `json:"observedAt"`
	}{SchemaVersionCurrent, "phorvex.actuation-observation", observedAt.UTC(), tenant, owner, decisionID,
		namespace, pod, targetUID, "rotate", "phoenix", eventName, eventUID, outcome,
		executionConfirmed, recoveryConfirmed, startedAt.UTC(), observedAt.UTC()}
	l.log.Info("actuation-observation", "tenant", tenant, "namespace", namespace, "pod", pod,
		"targetUID", targetUID, "action", "rotate", "backend", "phoenix", "event", eventName,
		"eventUID", eventUID, "outcome", outcome, "executionConfirmed", executionConfirmed,
		"recoveryConfirmed", recoveryConfirmed)
	b, err := json.Marshal(rec)
	if err != nil {
		l.log.Error(err, "actuation observation audit encoding failed")
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.jsonOut
	if l.sinkFor != nil && tenant != "" {
		out = l.sinkFor(tenant)
	}
	if out != nil {
		if _, err := out.Write(append(b, '\n')); err != nil {
			l.log.Error(err, "actuation observation audit persistence failed")
		}
	}
}
