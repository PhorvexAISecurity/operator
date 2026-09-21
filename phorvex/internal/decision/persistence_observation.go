package decision

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/model"
)

// PersistenceObservationAuthority resolves immutable retained operation state.
// AuthorizeObservation must authenticate the complete categorical result and
// evidence hashes; knowing an operation ID or source name is insufficient.
type PersistenceObservationAuthority interface {
	Source() string
	AuthorizeObservation(model.PersistenceObservation) (model.PersistenceOperationBinding, bool)
}

type scopedOutcomeCounts struct {
	held, revoked, unknown, censored int
}

type scopedOutcomeOwner struct {
	seen            map[string][sha256.Size]byte
	cohorts         map[model.ScopedOutcomeCohortKey]scopedOutcomeCounts
	current         model.PolicyEpoch
	live            bool
	retired         bool
	lastDisposition string
	lastEvidenceID  string
	lastOutcome     string
	lastReason      string
}

type scopedOutcomeStore struct {
	mu             sync.RWMutex
	processEpochID string
	owners         map[string]*scopedOutcomeOwner // includes retired replay tombstones
}

func newScopedOutcomeStore() *scopedOutcomeStore {
	return &scopedOutcomeStore{processEpochID: newScopedOutcomeProcessEpoch(), owners: map[string]*scopedOutcomeOwner{}}
}

func newScopedOutcomeProcessEpoch() string {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	// crypto/rand failure does not permit evidence admission under a reused
	// epoch. Leave the epoch invalid so the boundary fails closed.
	return ""
}

// PersistenceObservationResult reports whether one authenticated observation
// entered the reporting-only cohort store. Applied never means mitigation or
// attacker-state learning.
type PersistenceObservationResult struct {
	Disposition string
	Applied     bool
	Reason      string
	Status      model.ScopedOutcomeReport
}

// SetOwnerEpoch registers the exact current policy identity. Generation changes
// retain replay IDs but create separate cohorts. A retired UID cannot re-enter;
// Kubernetes replacement policies have a new UID and a fresh lifecycle.
func (e *CoverageEngine) SetOwnerEpoch(epoch model.PolicyEpoch, live bool) error {
	if err := epoch.Validate(); err != nil {
		return err
	}
	if e.scopedOutcomes == nil {
		e.scopedOutcomes = newScopedOutcomeStore()
	}
	owner := epoch.Owner()
	store := e.scopedOutcomes
	store.mu.Lock()
	defer store.mu.Unlock()
	state := store.owners[owner]
	if !live {
		if state != nil {
			state.live = false
			state.retired = true
		}
		e.SetOwnerLive(owner, false)
		return nil
	}
	if state != nil && state.retired {
		return fmt.Errorf("%w: scoped outcome owner UID is retired", ErrOwnerRetired)
	}
	if state != nil && epoch.Generation < state.current.Generation {
		return fmt.Errorf("scoped outcome policy generation regressed")
	}
	if state != nil && (epoch.Namespace != state.current.Namespace || epoch.Name != state.current.Name) {
		return fmt.Errorf("scoped outcome policy UID changed namespace or name")
	}
	if state == nil {
		if len(store.owners) >= model.ScopedOutcomeOwnerCapacity {
			return fmt.Errorf("scoped outcome lifetime owner capacity is full")
		}
		state = &scopedOutcomeOwner{
			seen: map[string][sha256.Size]byte{}, cohorts: map[model.ScopedOutcomeCohortKey]scopedOutcomeCounts{},
			current: epoch, live: true, lastDisposition: model.PersistenceDispositionNoLabel,
		}
		store.owners[owner] = state
	} else {
		state.live = true
		if state.current != epoch {
			state.current = epoch
			state.lastDisposition = model.PersistenceDispositionNoLabel
			state.lastEvidenceID = ""
			state.lastOutcome = ""
			state.lastReason = ""
		}
	}
	e.SetOwnerLive(owner, true)
	return nil
}

func (e *CoverageEngine) retireScopedOutcomeOwner(owner string) {
	if e.scopedOutcomes == nil {
		return
	}
	e.scopedOutcomes.mu.Lock()
	defer e.scopedOutcomes.mu.Unlock()
	if state := e.scopedOutcomes.owners[owner]; state != nil {
		state.live = false
		state.retired = true
	}
}

// ScopedOutcomeReportFor is observational. It allocates no lifecycle, cohort,
// replay ID or belief state and returns defensive copies.
func (e *CoverageEngine) ScopedOutcomeReportFor(owner string) (model.ScopedOutcomeReport, bool) {
	if e.scopedOutcomes == nil {
		return e.emptyScopedOutcomeReport(model.PersistenceDispositionNoProducer), false
	}
	e.scopedOutcomes.mu.RLock()
	defer e.scopedOutcomes.mu.RUnlock()
	state, ok := e.scopedOutcomes.owners[owner]
	return e.scopedOutcomeReportLocked(state, ""), ok
}

func (e *CoverageEngine) scopedOutcomeReport(owner string) *model.ScopedOutcomeReport {
	report, _ := e.ScopedOutcomeReportFor(owner)
	return &report
}

func (e *CoverageEngine) scopedSource() string {
	if e.PersistenceAuthority == nil || e.PersistenceAuthority.Source() == "" {
		return "none"
	}
	return e.PersistenceAuthority.Source()
}

func (e *CoverageEngine) emptyScopedOutcomeReport(disposition string) model.ScopedOutcomeReport {
	epoch := ""
	owners := 0
	if e.scopedOutcomes != nil {
		e.scopedOutcomes.mu.RLock()
		defer e.scopedOutcomes.mu.RUnlock()
		epoch = e.scopedOutcomes.processEpochID
		owners = len(e.scopedOutcomes.owners)
	}
	if e.scopedSource() == "none" {
		epoch = "unconfigured"
	}
	return model.ScopedOutcomeReport{
		SchemaVersion: model.ScopedOutcomeReportSchemaV1, Source: e.scopedSource(), ProcessEpochID: epoch,
		ResetBoundary: "process-start", Disposition: disposition,
		ReplayCapacity: model.ScopedOutcomeEvidenceCapacity, CohortCapacity: model.ScopedOutcomeCohortCapacity,
		LifetimeOwners: owners, LifetimeOwnerCapacity: model.ScopedOutcomeOwnerCapacity,
	}
}

func (e *CoverageEngine) scopedOutcomeReportLocked(state *scopedOutcomeOwner, override string) model.ScopedOutcomeReport {
	disposition := model.PersistenceDispositionNoLabel
	if e.PersistenceAuthority == nil || e.PersistenceAuthority.Source() == "" {
		disposition = model.PersistenceDispositionNoProducer
	}
	if state != nil && state.lastDisposition != "" && disposition != model.PersistenceDispositionNoProducer {
		disposition = state.lastDisposition
	}
	if override != "" {
		disposition = override
	}
	source := e.scopedSource()
	processEpochID := e.scopedOutcomes.processEpochID
	if source == "none" {
		processEpochID = "unconfigured"
	}
	report := model.ScopedOutcomeReport{
		SchemaVersion: model.ScopedOutcomeReportSchemaV1, Source: source, ProcessEpochID: processEpochID,
		ResetBoundary: "process-start", Disposition: disposition,
		ReplayCapacity: model.ScopedOutcomeEvidenceCapacity, CohortCapacity: model.ScopedOutcomeCohortCapacity,
		LifetimeOwners: len(e.scopedOutcomes.owners), LifetimeOwnerCapacity: model.ScopedOutcomeOwnerCapacity,
	}
	if disposition == model.PersistenceDispositionNoProducer {
		if state != nil {
			policy := state.current
			report.Policy = &policy
		}
		return report
	}
	if state == nil {
		return report
	}
	policy := state.current
	report.Policy = &policy
	report.EvidenceID = state.lastEvidenceID
	report.Outcome = state.lastOutcome
	report.Reason = state.lastReason
	report.ReplayEntries = len(state.seen)
	report.Cohorts = make([]model.ScopedOutcomeCohort, 0, len(state.cohorts))
	for key, counts := range state.cohorts {
		n := counts.held + counts.revoked
		cohort := model.ScopedOutcomeCohort{
			Key: key, Held: counts.held, Revoked: counts.revoked, Unknown: counts.unknown, Censored: counts.censored,
			N: n, PriorAlpha: 1, PriorBeta: 1, PosteriorMean: float64(1+counts.held) / float64(2+n), Calibrated: false,
		}
		if n > 0 {
			lower, upper := model.Wilson95(counts.held, n)
			cohort.RawHeldInterval = &model.ScopedOutcomeInterval{Method: model.ScopedOutcomeIntervalWilson95, Lower: lower, Upper: upper}
		}
		report.Cohorts = append(report.Cohorts, cohort)
	}
	sort.Slice(report.Cohorts, func(i, j int) bool {
		a, _ := json.Marshal(report.Cohorts[i].Key)
		b, _ := json.Marshal(report.Cohorts[j].Key)
		return string(a) < string(b)
	})
	return report
}

// ScopedOutcomeProcessEpochID returns the process-local replay epoch without
// allocating any owner state. Producers must bind operations to this exact ID.
func (e *CoverageEngine) ScopedOutcomeProcessEpochID() string {
	if e.scopedOutcomes == nil {
		return ""
	}
	e.scopedOutcomes.mu.RLock()
	defer e.scopedOutcomes.mu.RUnlock()
	return e.scopedOutcomes.processEpochID
}

// RecordScopedOutcomeUnavailable records a bounded producer/storage/transport
// disposition without allocating a lifecycle or changing cohort counts.
func (e *CoverageEngine) RecordScopedOutcomeUnavailable(policy model.PolicyEpoch, reason string) PersistenceObservationResult {
	if len(reason) > 253 {
		reason = reason[:253]
	}
	if !utf8.ValidString(reason) {
		reason = "producer returned invalid diagnostic text"
	}
	base := e.emptyScopedOutcomeReport(model.PersistenceDispositionUnavailable)
	if e.scopedOutcomes == nil {
		return observationResult(base, model.PersistenceDispositionUnavailable, "", "", reason, false)
	}
	owner := policy.Owner()
	e.scopedOutcomes.mu.Lock()
	defer e.scopedOutcomes.mu.Unlock()
	state := e.scopedOutcomes.owners[owner]
	if state == nil || state.retired || !state.live || state.current != policy {
		return observationResult(e.scopedOutcomeReportLocked(state, model.PersistenceDispositionRejected), model.PersistenceDispositionRejected, "", "", "unavailable result does not match a live current policy lifecycle", false)
	}
	state.lastDisposition, state.lastEvidenceID, state.lastOutcome, state.lastReason = model.PersistenceDispositionUnavailable, "", "", reason
	return observationResult(e.scopedOutcomeReportLocked(state, model.PersistenceDispositionUnavailable), model.PersistenceDispositionUnavailable, "", "", reason, false)
}

func observationResult(report model.ScopedOutcomeReport, disposition, evidenceID, outcome, reason string, applied bool) PersistenceObservationResult {
	report.Disposition = disposition
	report.EvidenceID = evidenceID
	report.Outcome = outcome
	report.Reason = reason
	return PersistenceObservationResult{Disposition: disposition, Applied: applied, Reason: reason, Status: report}
}

func boundedObservationString(name, value string, limit int) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > limit {
		return fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	return nil
}

func validatePersistenceObservation(observation model.PersistenceObservation) error {
	if observation.SchemaVersion != model.ScopedOutcomeObservationSchemaV1 {
		return fmt.Errorf("unsupported scoped outcome observation schema %q", observation.SchemaVersion)
	}
	if observation.Source != model.ScopedSessionCapability || observation.ContractVersion != model.ScopedSessionNativeRotateV1 ||
		observation.Capability != model.ScopedSessionCapability || observation.Action != model.ActionRotate {
		return fmt.Errorf("unsupported scoped outcome source, capability, action, or contract")
	}
	if err := observation.Policy.Validate(); err != nil {
		return err
	}
	if err := observation.Workload.Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		name, value string
		limit       int
	}{
		{"source", observation.Source, 128}, {"processEpochID", observation.ProcessEpochID, 253},
		{"contractVersion", observation.ContractVersion, 253}, {"evidenceID", observation.EvidenceID, 253},
		{"operationID", observation.OperationID, 253}, {"targetUID", observation.TargetUID, 253},
		{"capability", observation.Capability, 253},
	} {
		if err := boundedObservationString(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	for name, value := range map[string]string{"beforeSHA256": observation.BeforeSHA256, "actionSHA256": observation.ActionSHA256, "afterSHA256": observation.AfterSHA256} {
		if !validScopedSHA256(value) {
			return fmt.Errorf("%s is not a lowercase SHA-256", name)
		}
	}
	if observation.ObservationStart.IsZero() || observation.ObservationEnd.IsZero() || observation.ObservationEnd.Before(observation.ObservationStart) {
		return fmt.Errorf("observation timestamps are missing or reversed")
	}
	if !validScopedOutcome(observation.Outcome) {
		return fmt.Errorf("unknown persistence outcome %q", observation.Outcome)
	}
	return nil
}

func validatePersistenceBinding(binding model.PersistenceOperationBinding) error {
	if err := binding.Policy.Validate(); err != nil {
		return err
	}
	if err := binding.Workload.Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		name, value string
		limit       int
	}{
		{"processEpochID", binding.ProcessEpochID, 253}, {"contractVersion", binding.ContractVersion, 253},
		{"operationID", binding.OperationID, 253}, {"targetUID", binding.TargetUID, 253}, {"capability", binding.Capability, 253},
	} {
		if err := boundedObservationString(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	if binding.ContractVersion != model.ScopedSessionNativeRotateV1 || binding.Capability != model.ScopedSessionCapability || binding.Action != model.ActionRotate {
		return fmt.Errorf("retained binding is outside the supported scoped outcome contract")
	}
	if binding.DispatchAcknowledgedAt.IsZero() ||
		!binding.ObservationNotBefore.Equal(binding.DispatchAcknowledgedAt.Add(60*time.Second)) ||
		!binding.ObservationDeadline.Equal(binding.DispatchAcknowledgedAt.Add(65*time.Second)) {
		return fmt.Errorf("retained binding does not declare the exact 60-65 second observation window")
	}
	if binding.TargetTerminationGraceSeconds < 0 || binding.TargetTerminationGraceSeconds > 30 {
		return fmt.Errorf("target termination grace exceeds the synthetic contract")
	}
	return nil
}

// DecodeScopedOutcomeObservation is the strict wire decoder used by producer
// boundaries. It rejects unknown fields and trailing JSON values.
func DecodeScopedOutcomeObservation(raw []byte) (model.PersistenceObservation, error) {
	var observation model.PersistenceObservation
	if !utf8.Valid(raw) {
		return observation, fmt.Errorf("scoped outcome payload is not valid UTF-8")
	}
	if err := currentinventory.RejectDuplicateFields(raw); err != nil {
		return observation, err
	}
	decoder := json.NewDecoder(newByteReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil {
		return observation, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return observation, fmt.Errorf("scoped outcome payload contains a trailing JSON value")
		}
		return observation, err
	}
	if err := validatePersistenceObservation(observation); err != nil {
		return observation, err
	}
	return observation, nil
}

type byteReader struct {
	raw    []byte
	offset int
}

func newByteReader(raw []byte) *byteReader { return &byteReader{raw: raw} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.raw) {
		return 0, io.EOF
	}
	n := copy(p, r.raw[r.offset:])
	r.offset += n
	return n, nil
}

func validScopedSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validScopedOutcome(value string) bool {
	switch value {
	case model.PersistenceHeld, model.PersistenceRevoked, model.PersistenceUnknown, model.PersistenceCensored:
		return true
	default:
		return false
	}
}

// AdmitPersistenceObservation validates one categorical result against the
// current process/policy epoch and an independently authenticated operation.
// It updates only descriptive cohorts and never attacker-state memory.
func (e *CoverageEngine) AdmitPersistenceObservation(observation model.PersistenceObservation) PersistenceObservationResult {
	base := e.emptyScopedOutcomeReport(model.PersistenceDispositionRejected)
	if err := validatePersistenceObservation(observation); err != nil {
		return observationResult(base, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, err.Error(), false)
	}
	if e.scopedOutcomes == nil || e.scopedOutcomes.processEpochID == "" || observation.ProcessEpochID != e.scopedOutcomes.processEpochID {
		return observationResult(base, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "observation does not match the current process epoch", false)
	}
	owner := observation.Policy.Owner()
	if e.ownerAbsent(owner) {
		return observationResult(base, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, ErrOwnerRetired.Error(), false)
	}
	if e.PersistenceAuthority == nil || e.PersistenceAuthority.Source() != model.ScopedSessionCapability || observation.Source != e.PersistenceAuthority.Source() {
		disposition := model.PersistenceDispositionRejected
		if e.PersistenceAuthority == nil || e.PersistenceAuthority.Source() == "" {
			disposition = model.PersistenceDispositionNoProducer
		}
		return observationResult(base, disposition, observation.EvidenceID, observation.Outcome, "no matching qualified scoped outcome authority is connected", false)
	}
	binding, ok := e.PersistenceAuthority.AuthorizeObservation(observation)
	if !ok {
		return observationResult(base, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "trusted producer did not authenticate the complete observation", false)
	}
	if err := validatePersistenceBinding(binding); err != nil {
		return observationResult(base, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, err.Error(), false)
	}
	if binding.Policy != observation.Policy || binding.ProcessEpochID != observation.ProcessEpochID || binding.ContractVersion != observation.ContractVersion ||
		binding.Workload != observation.Workload || binding.OperationID != observation.OperationID || binding.TargetUID != observation.TargetUID ||
		binding.Capability != observation.Capability || binding.Action != observation.Action {
		return observationResult(base, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "observation does not exactly match the retained operation binding", false)
	}
	if observation.ObservationStart.Before(binding.ObservationNotBefore) {
		return observationResult(base, model.PersistenceDispositionEarly, observation.EvidenceID, observation.Outcome, "observation began before the 60 second horizon", false)
	}
	if observation.ObservationEnd.After(e.now()) {
		return observationResult(base, model.PersistenceDispositionExpired, observation.EvidenceID, observation.Outcome, "observation ends in the future", false)
	}
	if (observation.Outcome == model.PersistenceHeld || observation.Outcome == model.PersistenceRevoked) &&
		(observation.ObservationStart.After(binding.ObservationDeadline) || observation.ObservationEnd.After(binding.ObservationDeadline)) {
		return observationResult(base, model.PersistenceDispositionExpired, observation.EvidenceID, observation.Outcome, "categorical outcome is outside the retained 60-65 second window", false)
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		return observationResult(base, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, err.Error(), false)
	}
	digest := sha256.Sum256(encoded)
	workloadDigest, _ := observation.Workload.Digest()
	key := model.ScopedOutcomeCohortKey{PolicyUID: observation.Policy.UID, PolicyGeneration: observation.Policy.Generation,
		WorkloadScopeSHA256: workloadDigest, Capability: observation.Capability, Action: observation.Action, ContractVersion: observation.ContractVersion}

	store := e.scopedOutcomes
	store.mu.Lock()
	defer store.mu.Unlock()
	state := store.owners[owner]
	if state == nil || !state.live || state.retired || state.current != observation.Policy {
		report := e.scopedOutcomeReportLocked(state, model.PersistenceDispositionRejected)
		return observationResult(report, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "observation does not match a live current policy lifecycle", false)
	}
	if previous, exists := state.seen[observation.EvidenceID]; exists {
		disposition, reason := model.PersistenceDispositionDuplicate, "identical evidence was already recorded"
		if previous != digest {
			disposition, reason = model.PersistenceDispositionConflict, "evidence ID was reused with a different payload"
		}
		report := e.scopedOutcomeReportLocked(state, disposition)
		return observationResult(report, disposition, observation.EvidenceID, observation.Outcome, reason, false)
	}
	if len(state.seen) >= model.ScopedOutcomeEvidenceCapacity {
		report := e.scopedOutcomeReportLocked(state, model.PersistenceDispositionSaturated)
		return observationResult(report, model.PersistenceDispositionSaturated, observation.EvidenceID, observation.Outcome, "bounded replay store is full; no entry was evicted", false)
	}
	if _, exists := state.cohorts[key]; !exists && len(state.cohorts) >= model.ScopedOutcomeCohortCapacity {
		report := e.scopedOutcomeReportLocked(state, model.PersistenceDispositionSaturated)
		return observationResult(report, model.PersistenceDispositionSaturated, observation.EvidenceID, observation.Outcome, "bounded cohort store is full; no entry was evicted", false)
	}
	counts := state.cohorts[key]
	switch observation.Outcome {
	case model.PersistenceHeld:
		counts.held++
	case model.PersistenceRevoked:
		counts.revoked++
	case model.PersistenceUnknown:
		counts.unknown++
	case model.PersistenceCensored:
		counts.censored++
	}
	state.cohorts[key] = counts
	state.seen[observation.EvidenceID] = digest
	state.lastDisposition, state.lastEvidenceID, state.lastOutcome, state.lastReason = model.PersistenceDispositionApplied, observation.EvidenceID, observation.Outcome, "authenticated scoped outcome was recorded for reporting only"
	report := e.scopedOutcomeReportLocked(state, model.PersistenceDispositionApplied)
	return observationResult(report, model.PersistenceDispositionApplied, observation.EvidenceID, observation.Outcome, "authenticated scoped outcome was recorded for reporting only", true)
}

// PersistenceLearningStatusFor remains as a compatibility read seam for old
// callers. New scoped observations never allocate or update this legacy status.
func (e *CoverageEngine) PersistenceLearningStatusFor(owner string) (model.PersistenceLearningStatus, bool) {
	status := model.PersistenceLearningStatus{SchemaVersion: model.PersistenceLearningSchemaV1, Source: "none", Disposition: model.PersistenceDispositionNoProducer,
		DedupCapacity: model.ScopedOutcomeEvidenceCapacity}
	if report, ok := e.ScopedOutcomeReportFor(owner); ok && report.Policy != nil {
		policy := *report.Policy
		status.Policy = &policy
	}
	return status, false
}
