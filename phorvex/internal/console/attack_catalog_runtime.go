package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
)

const (
	attackCatalogExecutionKind    = "catalogue-validation"
	attackCatalogRunRecordSchema  = "phorvex.attack-catalogue-run.v1"
	attackCatalogResultFile       = "catalogue-result.json"
	attackCatalogRunRecordFile    = "catalogue-run.json"
	attackCatalogCleanupTimeout   = 30 * time.Second
	attackCatalogDefaultRunBudget = 4 * time.Minute
)

// AttackCatalogRunContext is the immutable catalogue identity handed to an
// adapter. It contains no caller-controlled destination, command, path, or
// profile. The registry has already bound the exact ID to the adapter.
type AttackCatalogRunContext struct {
	RunID              string
	CatalogueID        string
	ExpectedAction     string
	ReactiveCompatible bool
}

// AttackCatalogPreparation is adapter-owned, run-private state produced by a
// preflight that must not mutate the attack target or persistent fixture state.
// Runtime modes and the Prometheus tenant must be resolved from current
// server-owned state before any attack mutation starts.
type AttackCatalogPreparation interface {
	ExecutionMode() AttackCatalogExecutionMode
	TriggerMode() AttackCatalogTriggerMode
	EvidenceTenant() string
}

// AttackCatalogObservation contains independently observed stages. Adapters do
// not set a verdict: only the shared lifecycle can do that after cleanup.
type AttackCatalogObservation struct {
	MutationStarted        bool
	Launched               bool
	Signal                 AttackCatalogSignalResult
	Decision               AttackCatalogDecisionResult
	Actuator               AttackCatalogActuatorResult
	PhysicalValidation     AttackCatalogPhysicalResult
	DefensiveChainComplete bool
	Reason                 string
}

type AttackCatalogAdapterAvailability struct {
	Available         bool
	UnavailableReason string
	RunnableNote      string
	RuntimeContext    string
	TargetLabel       string
	FixtureTenant     string
}

// AttackCatalogAdapter is the reviewed family seam. Implementations own only
// fixed server-side destination/profile resolution, non-mutating preflight,
// bounded mutation and exact signal/decision binding, their physical oracle,
// and exact cleanup. Authorization, concurrency/rate admission, cancellation,
// persistence, Prometheus evidence, cleanup gating, and verdicts stay shared.
type AttackCatalogAdapter interface {
	CatalogueID() string
	Availability() AttackCatalogAdapterAvailability
	Destination() (runDestination, error)
	Preflight(context.Context, AttackCatalogRunContext) (AttackCatalogPreparation, error)
	Execute(context.Context, AttackCatalogRunContext, AttackCatalogPreparation) (AttackCatalogObservation, error)
	Cleanup(context.Context, AttackCatalogRunContext, AttackCatalogPreparation) AttackCatalogCleanupResult
	ValidateDefended(AttackCatalogResult) error
	DefendedReason() string
}

// AttackCatalogAdapterRegistry is an exact-ID map. Registration rejects
// unknown metadata IDs, aliases, whitespace variants, and duplicates.
type AttackCatalogAdapterRegistry struct {
	mu       sync.RWMutex
	adapters map[string]AttackCatalogAdapter
}

func NewAttackCatalogAdapterRegistry() *AttackCatalogAdapterRegistry {
	return &AttackCatalogAdapterRegistry{adapters: map[string]AttackCatalogAdapter{}}
}

func (r *AttackCatalogAdapterRegistry) Register(adapter AttackCatalogAdapter) error {
	if r == nil || adapter == nil {
		return errors.New("catalogue adapter registry and adapter are required")
	}
	id := adapter.CatalogueID()
	entry, ok := attackcatalog.Lookup(id)
	if !ok || id == "" || strings.TrimSpace(id) != id || entry.ID != id {
		return fmt.Errorf("catalogue adapter ID %q is not one exact metadata ID", id)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.adapters[id]; exists {
		return fmt.Errorf("catalogue adapter %q is already registered", id)
	}
	r.adapters[id] = adapter
	return nil
}

func (r *AttackCatalogAdapterRegistry) Lookup(id string) (AttackCatalogAdapter, bool) {
	if r == nil || id == "" || strings.TrimSpace(id) != id {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, ok := r.adapters[id]
	return adapter, ok
}

func newAttackCatalogAdapterRegistry(s *Server, cfg Config) *AttackCatalogAdapterRegistry {
	registry := NewAttackCatalogAdapterRegistry()
	// AML.T0012 keeps its original adapter. Every other registration comes from
	// one reviewed exact-ID family factory; metadata rows never synthesize an
	// adapter or inherit launch authority from a family label.
	register := func(adapters ...AttackCatalogAdapter) {
		for _, adapter := range adapters {
			if err := registry.Register(adapter); err != nil {
				panic(err)
			}
		}
	}
	register(&identityAttackCatalogAdapter{server: s, cfg: cfg})

	k8s, err := newK8sCatalogueAdapters(s, cfg)
	if err != nil {
		panic(err)
	}
	register(k8s...)
	register(newInfraCatalogueAdapters(s, cfg)...)
	register(newServingCatalogueAdapters(s)...)
	identity, err := bindIdentityCatalogueAdapters(s, cfg, newIdentityCatalogueAdapters())
	if err != nil {
		panic(err)
	}
	register(identity...)
	if len(registry.adapters) != attackcatalog.ExpectedSize {
		panic(fmt.Errorf("catalogue adapter registry has %d exact IDs, want %d", len(registry.adapters), attackcatalog.ExpectedSize))
	}
	return registry
}

func attackCatalogueDestination(s *Server, _ *http.Request, body scopedBody) (runDestination, error) {
	entry, ok := attackcatalog.Lookup(body.ID)
	if !ok {
		return runDestination{}, errors.New("unknown catalogue ID")
	}
	adapter, ok := s.attackCatalogAdapters.Lookup(entry.ID)
	if !ok {
		return runDestination{}, errors.New("catalogue entry is visible but has no reviewed launch adapter")
	}
	return adapter.Destination()
}

func (s *Server) launchAttackCatalogue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || decoder.Decode(new(any)) != io.EOF || strings.TrimSpace(body.ID) != body.ID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "one exact catalogue ID is required"})
		return
	}
	entry, ok := attackcatalog.Lookup(body.ID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "catalogue ID is not allowlisted"})
		return
	}
	adapter, ok := s.attackCatalogAdapters.Lookup(entry.ID)
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "catalogue entry is visible but no reviewed server-side launch adapter is packaged"})
		return
	}
	availability := adapter.Availability()
	if !availability.Available {
		reason := availability.UnavailableReason
		if reason == "" {
			reason = "catalogue launch adapter is not ready in this attacks-service deployment"
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": reason})
		return
	}
	destination, err := adapter.Destination()
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	principal := principalOf(r)
	if principal == nil || !principalAllowsRunDestination(principal, destination) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "catalogue adapter destination is outside this identity's current scope"})
		return
	}
	id, err := s.startAttackCatalogueRun(entry, adapter, availability, destination, principalKey(principal))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "context": destination.ScopeTarget, "catalogueID": entry.ID})
}

func principalAllowsRunDestination(principal *Principal, destination runDestination) bool {
	if principal == nil || destination.ScopeTarget == "" || destination.ScopeTenant == "" || len(destination.Targets) == 0 || len(destination.Tenants) == 0 {
		return false
	}
	for _, target := range destination.Targets {
		if !principal.AllowsTarget(target) {
			return false
		}
	}
	for _, tenant := range destination.Tenants {
		if !principal.AllowsTenant(tenant) {
			return false
		}
	}
	return true
}

func (s *Server) startAttackCatalogueRun(entry attackcatalog.Entry, adapter AttackCatalogAdapter, availability AttackCatalogAdapterAvailability, destination runDestination, owner string) (string, error) {
	if adapter == nil || adapter.CatalogueID() != entry.ID {
		return "", errors.New("exact catalogue adapter binding changed before launch")
	}
	rm := s.runs
	rm.mu.Lock()
	for _, prior := range rm.runs {
		if prior.ExecutionKind == attackCatalogExecutionKind && (prior.State == "running" || prior.UnsafeToRetry) {
			rm.mu.Unlock()
			return "", errors.New("a catalogue run is active or requires cleanup reconciliation")
		}
	}
	if err := rm.guard(time.Now()); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	rm.seq++
	id := fmt.Sprintf("cat-%d", rm.seq)
	out := rm.cfg.runOutputPath(id)
	if err := os.MkdirAll(out, 0o750); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now().UTC()
	targetLabel := availability.TargetLabel
	if targetLabel == "" {
		targetLabel = availability.RuntimeContext
	}
	if targetLabel == "" {
		targetLabel = destination.ScopeTarget
	}
	st := &RunStatus{ID: id, Config: entry.ID, State: "running", Started: now.Format(time.RFC3339Nano), Date: tsNow(),
		ExpectedTrials: 1, Owner: owner, ScopeTarget: destination.ScopeTarget, ScopeTenant: destination.ScopeTenant,
		ScopeTargets: slices.Clone(destination.Targets), ScopeTenants: slices.Clone(destination.Tenants), FixtureTenant: availability.FixtureTenant,
		Target: destination.ScopeTarget, TargetLabel: targetLabel, Provider: "Kubernetes",
		ExecutionKind: attackCatalogExecutionKind, ClaimClass: "security"}
	rm.runs[id], rm.runOut[id], rm.attackCatalogCancels[id] = st, id, cancel
	rm.active++
	rm.lastStart = time.Now()
	if err := rm.persistStatus(st, id); err != nil {
		delete(rm.runs, id)
		delete(rm.runOut, id)
		delete(rm.attackCatalogCancels, id)
		rm.active--
		cancel()
		rm.mu.Unlock()
		return "", fmt.Errorf("persist catalogue run before launch: %w", err)
	}
	rm.mu.Unlock()
	go s.executeAttackCatalogueRun(ctx, id, entry, adapter, now)
	return id, nil
}

func (s *Server) executeAttackCatalogueRun(parent context.Context, id string, entry attackcatalog.Entry, adapter AttackCatalogAdapter, startedAt time.Time) {
	timeout := s.cfg.AttackCatalogRunTimeout
	if timeout <= 0 {
		timeout = attackCatalogDefaultRunBudget
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	run := AttackCatalogRunContext{RunID: id, CatalogueID: entry.ID, ExpectedAction: entry.ExpectedAction, ReactiveCompatible: entry.ReactiveCompatible}
	result := AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: entry.ID, RunID: id,
		Visible: true, ExpectedAction: entry.ExpectedAction, StartedAt: startedAt}
	prepared, preflightErr := adapter.Preflight(ctx, run)
	if prepared != nil {
		result.ExecutionMode = prepared.ExecutionMode()
		result.TriggerMode = prepared.TriggerMode()
		result.ReactiveOnly = result.TriggerMode == AttackCatalogTriggerReactive
	}
	if preflightErr == nil {
		preflightErr = validateAttackCatalogPreparation(prepared)
	}
	if preflightErr == nil && result.ReactiveOnly && !entry.ReactiveCompatible {
		preflightErr = errors.New("catalogue entry is not compatible with the fixture's reactive-only policy")
	}
	if preflightErr != nil {
		result.Cleanup = noMutationAttackCatalogCleanup("preflight failed before mutation")
		result.FinishedAt, result.Verdict, result.Reason = time.Now().UTC(), "ERROR", preflightErr.Error()
		s.finalizeAttackCatalogueRun(id, adapter, result, nil, nil)
		return
	}
	if err := s.persistAttackCatalogModes(id, result.ExecutionMode, result.TriggerMode); err != nil {
		result.Cleanup = noMutationAttackCatalogCleanup("runtime modes could not be persisted before mutation")
		result.FinishedAt, result.Verdict, result.Reason = time.Now().UTC(), "ERROR", err.Error()
		s.finalizeAttackCatalogueRun(id, adapter, result, nil, nil)
		return
	}
	prometheusEvidence, prometheusErr := s.beginPrometheusRunEvidence(ctx, id, entry.ID, prepared.EvidenceTenant(), entry.ExpectedAction, result.ExecutionMode, result.TriggerMode, startedAt)
	if prometheusErr != nil {
		result.Cleanup = noMutationAttackCatalogCleanup("Prometheus evidence preflight failed before mutation")
		result.FinishedAt, result.Verdict = time.Now().UTC(), "ERROR"
		result.Reason = "Prometheus evidence preflight failed before mutation: " + prometheusErr.Error()
		s.finalizeAttackCatalogueRun(id, adapter, result, prometheusEvidence, prometheusErr)
		return
	}
	result = s.executePreparedAttackCatalogueRun(ctx, run, adapter, prepared, result)
	if prometheusEvidence != nil {
		captureTimeout := s.cfg.RunPrometheusEvidence.normalized().SettleDelay + 2*time.Minute
		captureCtx, captureCancel := context.WithTimeout(context.Background(), captureTimeout)
		prometheusErr = s.completePrometheusRunEvidence(captureCtx, prometheusEvidence, result.FinishedAt)
		captureCancel()
	}
	s.finalizeAttackCatalogueRun(id, adapter, result, prometheusEvidence, prometheusErr)
}

func validateAttackCatalogPreparation(prepared AttackCatalogPreparation) error {
	if prepared == nil {
		return errors.New("catalogue adapter returned no preflight state")
	}
	if !validAttackCatalogModes(prepared.ExecutionMode(), prepared.TriggerMode()) {
		return errors.New("catalogue adapter returned invalid execution or trigger mode")
	}
	if strings.TrimSpace(prepared.EvidenceTenant()) == "" {
		return errors.New("catalogue adapter returned no Prometheus evidence tenant")
	}
	return nil
}

func noMutationAttackCatalogCleanup(reason string) AttackCatalogCleanupResult {
	return AttackCatalogCleanupResult{EventDeleted: true, MarkerDeleted: true, Verified: true, Reason: reason}
}

func (s *Server) persistAttackCatalogModes(id string, execution AttackCatalogExecutionMode, trigger AttackCatalogTriggerMode) error {
	if !validAttackCatalogModes(execution, trigger) {
		return errors.New("catalogue runtime modes are invalid")
	}
	rm := s.runs
	rm.mu.Lock()
	defer rm.mu.Unlock()
	st := rm.runs[id]
	if st == nil || st.ExecutionKind != attackCatalogExecutionKind || st.State != "running" {
		return errors.New("catalogue run is no longer active")
	}
	st.ExecutionMode, st.TriggerMode = execution, trigger
	if err := rm.persistStatus(st, rm.runOut[id]); err != nil {
		return fmt.Errorf("persist catalogue runtime modes before mutation: %w", err)
	}
	return nil
}

func (s *Server) executePreparedAttackCatalogueRun(ctx context.Context, run AttackCatalogRunContext, adapter AttackCatalogAdapter, prepared AttackCatalogPreparation, result AttackCatalogResult) AttackCatalogResult {
	result.Available = true
	observation, executionErr := adapter.Execute(ctx, run, prepared)
	result.Launched = observation.Launched
	result.Signal = observation.Signal
	result.Decision = observation.Decision
	result.Actuator = observation.Actuator
	result.PhysicalValidation = observation.PhysicalValidation
	cleanupTimeout := attackCatalogCleanupTimeout
	if bounded, ok := adapter.(interface{ CleanupTimeout() time.Duration }); ok {
		if candidate := bounded.CleanupTimeout(); candidate >= attackCatalogCleanupTimeout && candidate <= 2*time.Minute {
			cleanupTimeout = candidate
		}
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cleanupTimeout)
	result.Cleanup = adapter.Cleanup(cleanupCtx, run, prepared)
	cleanupCancel()
	reason := observation.Reason
	if executionErr != nil {
		reason = executionErr.Error()
	}
	if reason == "" {
		reason = "bounded validation did not complete before its deadline"
	}
	if observation.DefensiveChainComplete && !result.Cleanup.Verified {
		reason = "defensive signal, decision, actuator receipt and family-specific physical oracle passed, but exact cleanup did not pass"
	}
	result.finishVerdict(adapter, reason)
	return result
}

func (s *Server) finalizeAttackCatalogueRun(id string, adapter AttackCatalogAdapter, result AttackCatalogResult, prometheusEvidence *PrometheusRunEvidence, prometheusErr error) {
	artifactErr := s.persistAttackCatalogRunArtifacts(adapter, result, prometheusEvidence)
	rm := s.runs
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.attackCatalogCancels, id)
	if rm.active > 0 {
		rm.active--
	}
	st := rm.runs[id]
	if st == nil {
		return
	}
	st.Finished = tsNow()
	st.Outcome = result.Verdict
	st.UnsafeToRetry = result.UnsafeToRetry || !result.Cleanup.Verified
	if result.Cleanup.Verified {
		st.CleanupStatus = "verified"
	} else {
		st.CleanupStatus = "unverified"
	}
	stopping := rm.stopping[id]
	delete(rm.stopping, id)
	switch {
	case artifactErr != nil:
		st.State, st.UnsafeToRetry, st.Outcome = "partial", true, ""
		st.Error = "catalogue terminal evidence missing or invalid: " + artifactErr.Error()
	case !result.Cleanup.Verified:
		st.State, st.Error = "partial", "catalogue postflight is unverified; reconcile before retry"
	case stopping:
		st.State, st.Error = "stopped", "stopped by operator after verified cleanup"
	case result.Verdict == "ERROR":
		st.State, st.Error = "error", result.Reason
	case prometheusErr != nil:
		st.State, st.Error = "partial", "Prometheus run evidence is incomplete: "+prometheusErr.Error()
	case result.Verdict == "DEFENDED":
		st.State = "done"
	default:
		st.State, st.Error = "error", result.Reason
	}
	if err := rm.persistStatus(st, id); err != nil {
		st.State, st.UnsafeToRetry, st.Outcome = "partial", true, ""
		st.Error = "catalogue terminal status persistence failed"
	}
	rm.dequeueNextLocked()
}

// AttackCatalogRunRecord is the single durable terminal record joining the
// Console result, complete raw Prometheus evidence, and explicit runtime modes.
// The legacy per-artifact files remain for backward-compatible API readers.
type AttackCatalogRunRecord struct {
	Schema             string                     `json:"schema"`
	RunID              string                     `json:"runID"`
	CatalogueID        string                     `json:"catalogueID"`
	ExecutionMode      AttackCatalogExecutionMode `json:"executionMode"`
	TriggerMode        AttackCatalogTriggerMode   `json:"triggerMode"`
	Result             AttackCatalogResult        `json:"result"`
	PrometheusEvidence *PrometheusRunEvidence     `json:"prometheusEvidence,omitempty"`
}

func (s *Server) persistAttackCatalogRunArtifacts(adapter AttackCatalogAdapter, result AttackCatalogResult, prometheusEvidence *PrometheusRunEvidence) error {
	if err := result.Validate(); err != nil {
		return err
	}
	if result.Verdict == "DEFENDED" {
		if err := result.defendedRequirements(adapter); err != nil {
			return fmt.Errorf("adapter verdict validation: %w", err)
		}
	}
	record := AttackCatalogRunRecord{Schema: attackCatalogRunRecordSchema, RunID: result.RunID, CatalogueID: result.CatalogueID,
		ExecutionMode: result.ExecutionMode, TriggerMode: result.TriggerMode, Result: result, PrometheusEvidence: prometheusEvidence}
	resultRaw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	recordRaw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	out := s.cfg.runOutputPath(result.RunID)
	if err = atomicWriteState(filepath.Join(out, attackCatalogResultFile), append(resultRaw, '\n')); err != nil {
		return err
	}
	return atomicWriteState(filepath.Join(out, attackCatalogRunRecordFile), append(recordRaw, '\n'))
}

func (rm *RunManager) AttackCatalogResult(id string) (*AttackCatalogResult, error) {
	rm.mu.Lock()
	st, ok := rm.runs[id]
	out := rm.runOut[id]
	registry := rm.attackCatalogAdapters
	rm.mu.Unlock()
	if !ok || st.ExecutionKind != attackCatalogExecutionKind {
		return nil, nil
	}
	if st.State == "running" || st.State == "queued" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(rm.cfg.runOutputPath(out), attackCatalogResultFile))
	if err != nil {
		return nil, err
	}
	var result AttackCatalogResult
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("catalogue result is malformed")
	}
	if err = result.Validate(); err != nil {
		return nil, err
	}
	if result.Verdict == "DEFENDED" {
		adapter, found := registry.Lookup(result.CatalogueID)
		if !found {
			return nil, errors.New("catalogue result has no registered adapter validator")
		}
		if err = result.withLegacyRuntimeModes().defendedRequirements(adapter); err != nil {
			return nil, err
		}
	}
	return &result, nil
}

func (rm *RunManager) AttackCatalogRunRecord(id string) (*AttackCatalogRunRecord, error) {
	rm.mu.Lock()
	st, ok := rm.runs[id]
	out := rm.runOut[id]
	registry := rm.attackCatalogAdapters
	rm.mu.Unlock()
	if !ok || st.ExecutionKind != attackCatalogExecutionKind || st.State == "running" || st.State == "queued" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(rm.cfg.runOutputPath(out), attackCatalogRunRecordFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record AttackCatalogRunRecord
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&record); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("catalogue run record is malformed")
	}
	if record.Schema != attackCatalogRunRecordSchema || record.RunID != id || record.CatalogueID != st.Config ||
		record.ExecutionMode != record.Result.ExecutionMode || record.TriggerMode != record.Result.TriggerMode ||
		!validAttackCatalogModes(record.ExecutionMode, record.TriggerMode) {
		return nil, errors.New("catalogue run record identity or runtime modes are invalid")
	}
	if err = record.Result.Validate(); err != nil {
		return nil, err
	}
	if record.Result.Verdict == "DEFENDED" {
		adapter, found := registry.Lookup(record.CatalogueID)
		if !found {
			return nil, errors.New("catalogue run record has no registered adapter validator")
		}
		if err = record.Result.defendedRequirements(adapter); err != nil {
			return nil, err
		}
	}
	if record.PrometheusEvidence != nil && (record.PrometheusEvidence.RunID != id || record.PrometheusEvidence.CatalogueID != record.CatalogueID ||
		record.PrometheusEvidence.ExecutionMode != record.ExecutionMode || record.PrometheusEvidence.TriggerMode != record.TriggerMode) {
		return nil, errors.New("catalogue run Prometheus evidence identity or runtime modes differ")
	}
	return &record, nil
}
