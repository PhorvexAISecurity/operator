package decision

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/phorvex/phorvex/internal/model"
)

const defaultPersistenceDedupLimit = 1024

// PersistenceObservationAuthority resolves immutable retained operation state.
// Production intentionally installs no implementation until a real effect
// adapter can prove the outcome and binding independently of optimizer output.
type PersistenceObservationAuthority interface {
	Source() string
	// AuthorizeObservation authenticates the complete categorical evidence and
	// returns its independently retained operation binding. Matching Source or
	// knowing an operation ID is not authority to choose an outcome.
	AuthorizeObservation(model.PersistenceObservation) (model.PersistenceOperationBinding, bool)
}

type persistenceLearningState struct {
	seen    map[string][sha256.Size]byte
	held    int
	revoked int
	epoch   model.PolicyEpoch
	status  model.PersistenceLearningStatus
}

// PersistenceObservationResult reports admission without implying effect,
// efficacy, or calibration.
type PersistenceObservationResult struct {
	Disposition string
	Applied     bool
	Reason      string
	Status      model.PersistenceLearningStatus
}

func (e *CoverageEngine) persistenceDedupCapacity() int {
	if e.PersistenceDedupLimit > 0 {
		return e.PersistenceDedupLimit
	}
	return defaultPersistenceDedupLimit
}

// SetOwnerEpoch registers the exact active identity used by the trusted
// observation boundary. It complements SetOwnerLive; ordinary scoring callers
// that have no observed-label producer do not need it.
func (e *CoverageEngine) SetOwnerEpoch(epoch model.PolicyEpoch, live bool) error {
	if err := epoch.Validate(); err != nil {
		return err
	}
	if e.persistenceEpochs == nil {
		e.persistenceEpochs = map[string]model.PolicyEpoch{}
	}
	owner := epoch.Owner()
	if live {
		e.SetOwnerLive(owner, true)
		e.persistenceEpochs[owner] = epoch
		// A policy generation change is still the same UID-owned lifecycle: keep
		// its counts and non-evicting replay barrier. Clear the prior generation's
		// last-evidence fields so they are never attributed to the new epoch.
		if state := e.persistenceLearning[owner]; state != nil && state.epoch != epoch {
			state.epoch = epoch
			current := epoch
			state.status = model.PersistenceLearningStatus{
				SchemaVersion:   model.PersistenceLearningSchemaV1,
				Source:          state.status.Source,
				Disposition:     model.PersistenceDispositionNoLabel,
				Policy:          &current,
				QualifiedLabels: state.held + state.revoked,
				HeldLabels:      state.held,
				RevokedLabels:   state.revoked,
				DedupEntries:    len(state.seen),
				DedupCapacity:   e.persistenceDedupCapacity(),
			}
		}
		return nil
	}
	e.SetOwnerLive(owner, false)
	return nil
}

func clonePersistenceLearningStatus(in model.PersistenceLearningStatus) model.PersistenceLearningStatus {
	out := in
	if in.Policy != nil {
		policy := *in.Policy
		out.Policy = &policy
	}
	return out
}

func (e *CoverageEngine) persistenceStatus(owner string) *model.PersistenceLearningStatus {
	if state := e.persistenceLearning[owner]; state != nil {
		status := clonePersistenceLearningStatus(state.status)
		return &status
	}
	source := "none"
	disposition := model.PersistenceDispositionNoProducer
	if e.PersistenceAuthority != nil && e.PersistenceAuthority.Source() != "" {
		source = e.PersistenceAuthority.Source()
		disposition = model.PersistenceDispositionNoLabel
	}
	status := &model.PersistenceLearningStatus{
		SchemaVersion: model.PersistenceLearningSchemaV1, Source: source, Disposition: disposition,
		DedupCapacity: e.persistenceDedupCapacity(),
	}
	if epoch, ok := e.persistenceEpochs[owner]; ok {
		copy := epoch
		status.Policy = &copy
	}
	return status
}

// PersistenceLearningStatusFor is a read-only observability seam. It does not
// allocate an owner, a prior, or a dedup slot.
func (e *CoverageEngine) PersistenceLearningStatusFor(owner string) (model.PersistenceLearningStatus, bool) {
	if state := e.persistenceLearning[owner]; state != nil {
		return clonePersistenceLearningStatus(state.status), true
	}
	return *e.persistenceStatus(owner), false
}

func observationResult(source, disposition, evidenceID, outcome, reason string, state *persistenceLearningState, capacity int) PersistenceObservationResult {
	status := model.PersistenceLearningStatus{
		SchemaVersion: model.PersistenceLearningSchemaV1, Source: source, Disposition: disposition,
		EvidenceID: evidenceID, Outcome: outcome, DedupCapacity: capacity,
	}
	if state != nil {
		epoch := state.epoch
		status.Policy = &epoch
		status.HeldLabels = state.held
		status.RevokedLabels = state.revoked
		status.QualifiedLabels = state.held + state.revoked
		status.DedupEntries = len(state.seen)
		state.status = status
	}
	return PersistenceObservationResult{Disposition: disposition, Applied: disposition == model.PersistenceDispositionApplied, Reason: reason, Status: clonePersistenceLearningStatus(status)}
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
	if observation.SchemaVersion != model.PersistenceObservationSchemaV1 {
		return fmt.Errorf("unsupported persistence observation schema %q", observation.SchemaVersion)
	}
	if err := observation.Policy.Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"source", observation.Source, 128}, {"evidenceID", observation.EvidenceID, 253},
		{"operationID", observation.OperationID, 253}, {"targetUID", observation.TargetUID, 253},
		{"capability", observation.Capability, 253}, {"scope", observation.Scope, 1024},
	} {
		if err := boundedObservationString(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	if observation.ObservationStart.IsZero() || observation.ObservationEnd.IsZero() || observation.ObservationEnd.Before(observation.ObservationStart) {
		return fmt.Errorf("observation timestamps are missing or reversed")
	}
	switch observation.Outcome {
	case model.PersistenceHeld, model.PersistenceRevoked, model.PersistenceUnknown, model.PersistenceCensored:
		return nil
	default:
		return fmt.Errorf("unknown persistence outcome %q", observation.Outcome)
	}
}

func validatePersistenceBinding(binding model.PersistenceOperationBinding) error {
	if err := binding.Policy.Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"operationID", binding.OperationID, 253}, {"targetUID", binding.TargetUID, 253},
		{"capability", binding.Capability, 253}, {"scope", binding.Scope, 1024},
	} {
		if err := boundedObservationString(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	if binding.ObservationNotBefore.IsZero() || binding.ObservationDeadline.IsZero() || !binding.ObservationDeadline.After(binding.ObservationNotBefore) {
		return fmt.Errorf("operation observation window is missing or empty")
	}
	return nil
}

// AdmitPersistenceObservation validates one categorical outcome against the
// current policy epoch and an independently retained operation binding. The
// initial production configuration has no authority and therefore admits none.
func (e *CoverageEngine) AdmitPersistenceObservation(observation model.PersistenceObservation) PersistenceObservationResult {
	capacity := e.persistenceDedupCapacity()
	if err := validatePersistenceObservation(observation); err != nil {
		return observationResult(observation.Source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, err.Error(), nil, capacity)
	}
	owner := observation.Policy.Owner()
	if e.ownerAbsent(owner) {
		return observationResult(observation.Source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, ErrOwnerRetired.Error(), nil, capacity)
	}
	current, ok := e.persistenceEpochs[owner]
	if !ok || current != observation.Policy {
		return observationResult(observation.Source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "observation does not match the active policy epoch", nil, capacity)
	}
	if e.PersistenceAuthority == nil || e.PersistenceAuthority.Source() == "" {
		return observationResult("none", model.PersistenceDispositionNoProducer, observation.EvidenceID, observation.Outcome, "no qualified live outcome producer is connected", nil, capacity)
	}
	source := e.PersistenceAuthority.Source()
	if observation.Source != source {
		return observationResult(source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "observation source does not match the configured authority", nil, capacity)
	}
	binding, ok := e.PersistenceAuthority.AuthorizeObservation(observation)
	if !ok {
		return observationResult(source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "trusted producer did not authenticate the complete observation", nil, capacity)
	}
	if err := validatePersistenceBinding(binding); err != nil {
		return observationResult(source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, err.Error(), nil, capacity)
	}
	if binding.Policy != current || binding.OperationID != observation.OperationID || binding.TargetUID != observation.TargetUID ||
		binding.Capability != observation.Capability || binding.Scope != observation.Scope {
		return observationResult(source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "observation does not exactly match the retained operation binding", nil, capacity)
	}
	now := e.now()
	if observation.ObservationStart.Before(binding.ObservationNotBefore) || observation.ObservationEnd.After(binding.ObservationDeadline) ||
		observation.ObservationEnd.After(now) || now.After(binding.ObservationDeadline) {
		return observationResult(source, model.PersistenceDispositionExpired, observation.EvidenceID, observation.Outcome, "observation is outside the retained operation window", nil, capacity)
	}
	if observation.Outcome == model.PersistenceUnknown || observation.Outcome == model.PersistenceCensored {
		return observationResult(source, model.PersistenceDispositionUnresolved, observation.EvidenceID, observation.Outcome, "unknown and censored outcomes are not Bernoulli labels", nil, capacity)
	}
	if e.Killchain == nil || e.Killchain.Memory == nil {
		return observationResult(source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, "persistence belief store is unavailable", nil, capacity)
	}

	encoded, err := json.Marshal(observation)
	if err != nil {
		return observationResult(source, model.PersistenceDispositionRejected, observation.EvidenceID, observation.Outcome, err.Error(), nil, capacity)
	}
	digest := sha256.Sum256(encoded)
	state := e.persistenceLearning[owner]
	if state != nil {
		if previous, exists := state.seen[observation.EvidenceID]; exists {
			if previous == digest {
				return observationResult(source, model.PersistenceDispositionDuplicate, observation.EvidenceID, observation.Outcome, "identical evidence was already applied", state, capacity)
			}
			return observationResult(source, model.PersistenceDispositionConflict, observation.EvidenceID, observation.Outcome, "evidence ID was reused with a different payload", state, capacity)
		}
		if len(state.seen) >= capacity {
			return observationResult(source, model.PersistenceDispositionSaturated, observation.EvidenceID, observation.Outcome, "bounded dedup store is full; no entry was evicted", state, capacity)
		}
	} else {
		state = &persistenceLearningState{seen: map[string][sha256.Size]byte{}, epoch: current}
		if e.persistenceLearning == nil {
			e.persistenceLearning = map[string]*persistenceLearningState{}
		}
		e.persistenceLearning[owner] = state
	}
	state.seen[observation.EvidenceID] = digest
	held := observation.Outcome == model.PersistenceHeld
	if held {
		state.held++
	} else {
		state.revoked++
	}
	e.Killchain.Memory.ObserveBernoulli(owner, held)
	return observationResult(source, model.PersistenceDispositionApplied, observation.EvidenceID, observation.Outcome, "one qualified categorical outcome was applied", state, capacity)
}
