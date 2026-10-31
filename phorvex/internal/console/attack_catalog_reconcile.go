package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AttackCatalogRetrySafety is an adapter's authoritative, read-only answer to
// whether a prior terminal run left the cluster clean enough that a new run is
// safe to launch. It is NEVER a DEFENDED claim: it clears only the single-active-
// run retry gate. RetrySafe is set only when run-owned SecurityEvents/artifacts
// are absent and active mutations are restored; an environmental Pod rollout alone
// does not block it, but leftover credentials/artifacts or genuine drift do.
type AttackCatalogRetrySafety struct {
	Verified  bool      `json:"verified"`
	RetrySafe bool      `json:"retrySafe"`
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

// AttackCatalogRetryReconciler is implemented by catalogue adapters that can
// re-verify retry-safety from current cluster state and their own fixed profile,
// WITHOUT the run-private prepared state that is lost on a service restart.
// Adapters that cannot prove cleanliness read-only do not implement it, and their
// stale unsafe runs stay unsafe until an operator intervenes.
type AttackCatalogRetryReconciler interface {
	ReconcileRetrySafety(ctx context.Context, persisted AttackCatalogResult) (AttackCatalogRetrySafety, error)
}

// attackCatalogReconcilerFor returns the adapter's read-only retry reconciler when
// it both implements the interface and (if it exposes a capability probe) reports
// that this exact family can prove cleanliness. A shared family adapter that wraps
// a non-reconcilable binding is treated as unsupported, so the runtime skips it
// cleanly instead of appending a useless unresolved record.
func attackCatalogReconcilerFor(adapter AttackCatalogAdapter) (AttackCatalogRetryReconciler, bool) {
	reconciler, ok := adapter.(AttackCatalogRetryReconciler)
	if !ok {
		return nil, false
	}
	if probe, hasProbe := adapter.(interface{ supportsRetryReconcile() bool }); hasProbe && !probe.supportsRetryReconcile() {
		return nil, false
	}
	return reconciler, true
}

type attackCatalogReconcileAudit struct {
	Kind      string `json:"kind"`
	Phase     string `json:"phase"`
	RunID     string `json:"runId"`
	AttemptID string `json:"attemptId"`
	Actor     string `json:"actor"`
	Status    string `json:"status"`
	At        string `json:"at"`
}

func (rm *RunManager) appendAttackCatalogReconcileAudit(id, actor, attemptID, phase, status string) error {
	raw, err := json.Marshal(attackCatalogReconcileAudit{Kind: "phorvex.console.catalogue.reconcile", Phase: phase,
		RunID: id, AttemptID: attemptID, Actor: actor, Status: status, At: rm.cfg.now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	return rm.cfg.appendState(rm.cfg.statePath("run-events.jsonl"), raw)
}

// loadAttackCatalogResult reads a run's persisted terminal result read-only so the
// adapter can re-verify against the run's own identity (its SecurityEvent name).
// A finalized run always has one; a run interrupted before finalization may not,
// in which case the adapter re-verifies against its fixed profile alone.
func (rm *RunManager) loadAttackCatalogResult(out string) (AttackCatalogResult, bool, error) {
	raw, err := os.ReadFile(filepath.Join(rm.cfg.runOutputPath(out), attackCatalogResultFile))
	if errors.Is(err, os.ErrNotExist) {
		return AttackCatalogResult{}, false, nil
	}
	if err != nil {
		return AttackCatalogResult{}, false, err
	}
	var result AttackCatalogResult
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil || decoder.Decode(new(any)) != io.EOF {
		return AttackCatalogResult{}, false, errors.New("catalogue result is malformed")
	}
	if err = result.Validate(); err != nil {
		return AttackCatalogResult{}, false, err
	}
	return result, true, nil
}

// ReconcileAttackCatalogRun is the operator-facing API path: it re-verifies a
// single interrupted unsafe catalogue run read-only, authorized against the owning
// identity, and appends a new superseding status record when the cluster is clean.
func (rm *RunManager) ReconcileAttackCatalogRun(id, actor string) error {
	return rm.reconcileAttackCatalogRun(id, actor, true)
}

// reconcileAttackCatalogRun re-verifies one stale unsafe catalogue run read-only
// and, only when the registered adapter authoritatively confirms the cluster is
// clean, APPENDS a new status record flipping UnsafeToRetry to false. It never
// rewrites or deletes a prior journal record, never claims DEFENDED, and leaves a
// genuinely contaminated run unsafe. requireOwner is false for the server's own
// startup reconciliation of its interrupted runs.
func (rm *RunManager) reconcileAttackCatalogRun(id, actor string, requireOwner bool) error {
	rm.mu.Lock()
	st := rm.runs[id]
	registry := rm.attackCatalogAdapters
	if st == nil || st.ExecutionKind != attackCatalogExecutionKind || !st.UnsafeToRetry ||
		st.State == "running" || st.State == "queued" || rm.procs[id] != nil || rm.stopping[id] ||
		rm.attackCatalogReconciling[id] || rm.loadErr != nil || registry == nil {
		rm.mu.Unlock()
		return errors.New("catalogue run is not an interrupted unsafe run eligible for read-only reconciliation")
	}
	if requireOwner && (actor == "" || (st.Owner != "" && st.Owner != actor)) {
		rm.mu.Unlock()
		return errors.New("catalogue reconciliation requires the owning identity")
	}
	adapter, ok := registry.Lookup(st.Config)
	if !ok || adapter.CatalogueID() != st.Config {
		rm.mu.Unlock()
		return errors.New("catalogue run has no registered adapter for reconciliation")
	}
	reconciler, ok := attackCatalogReconcilerFor(adapter)
	if !ok {
		rm.mu.Unlock()
		return errors.New("catalogue family does not support automatic retry reconciliation")
	}
	out := rm.runOut[id]
	priorState, priorConfig := st.State, st.Config
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		rm.mu.Unlock()
		return err
	}
	attemptID := hex.EncodeToString(seed)
	if err := rm.appendAttackCatalogReconcileAudit(id, actor, attemptID, "intent", "READ_ONLY"); err != nil {
		rm.mu.Unlock()
		return fmt.Errorf("persist catalogue reconciliation intent: %w", err)
	}
	rm.attackCatalogReconciling[id] = true
	rm.mu.Unlock()
	defer func() {
		rm.mu.Lock()
		delete(rm.attackCatalogReconciling, id)
		rm.mu.Unlock()
	}()

	persisted, _, loadErr := rm.loadAttackCatalogResult(out)
	// Bind the run's own identity even when no terminal result survives, so the
	// adapter can still scope its read-only check to this exact catalogue run.
	if persisted.RunID == "" {
		persisted.RunID = id
	}
	if persisted.CatalogueID == "" {
		persisted.CatalogueID = priorConfig
	}
	var safety AttackCatalogRetrySafety
	var verifyErr error
	if loadErr != nil {
		verifyErr = loadErr
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		safety, verifyErr = reconciler.ReconcileRetrySafety(ctx, persisted)
		cancel()
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	current := rm.runs[id]
	if current == nil || current.ExecutionKind != attackCatalogExecutionKind || !current.UnsafeToRetry ||
		current.State != priorState || current.Config != priorConfig || rm.procs[id] != nil || rm.stopping[id] {
		_ = rm.appendAttackCatalogReconcileAudit(id, actor, attemptID, "terminal", "UNRESOLVED")
		return errors.New("catalogue run changed during reconciliation")
	}
	verified := verifyErr == nil && safety.RetrySafe
	status := "UNRESOLVED"
	if verified {
		status = "VERIFIED_READ_ONLY"
	}
	if err := rm.appendAttackCatalogReconcileAudit(id, actor, attemptID, "terminal", status); err != nil {
		return fmt.Errorf("persist catalogue reconciliation terminal audit: %w", err)
	}
	previous := *current
	current.Finished = tsNow()
	if verified {
		// Keep the historical State, Outcome and Reason; only the retry gate and
		// the cleanup disposition change. The original partial/error record is left
		// intact in the journal — this is a new, superseding append.
		current.UnsafeToRetry = false
		current.CleanupStatus = "reconciled-read-only"
		current.Error = "interrupted catalogue run reconciled read-only; original outcome remains incomplete"
	} else {
		current.UnsafeToRetry = true
		current.CleanupStatus = "unverified"
		reason := "read-only catalogue reconciliation refused; run-owned absence unverified"
		switch {
		case verifyErr != nil:
			reason = "read-only catalogue reconciliation could not verify owned absence: " + verifyErr.Error()
		case safety.Reason != "":
			reason = "read-only catalogue reconciliation refused: " + safety.Reason
		}
		current.Error = reason
	}
	if err := rm.persistStatus(current, out); err != nil {
		*current = previous
		current.UnsafeToRetry = true
		return fmt.Errorf("persist catalogue reconciliation status: %w", err)
	}
	if !verified {
		return errors.New("read-only catalogue reconciliation did not verify owned absence")
	}
	return nil
}

// reconcileInterruptedAttackCatalog is the server-initiated startup pass. It
// re-verifies every stale unsafe catalogue run whose adapter supports read-only
// reconciliation, so an environmental Pod rollout that falsely marked a run unsafe
// no longer bricks every future launch across a restart. It is a no-op when there
// are no eligible runs, and it never claims DEFENDED or rewrites a prior record.
func (rm *RunManager) reconcileInterruptedAttackCatalog() {
	rm.cfg.sleep(2 * time.Second)
	rm.mu.Lock()
	registry := rm.attackCatalogAdapters
	var ids []string
	if registry != nil && rm.loadErr == nil {
		for id, st := range rm.runs {
			if st == nil || st.ExecutionKind != attackCatalogExecutionKind || !st.UnsafeToRetry ||
				st.State == "running" || st.State == "queued" || rm.procs[id] != nil || rm.stopping[id] {
				continue
			}
			adapter, ok := registry.Lookup(st.Config)
			if !ok {
				continue
			}
			if _, ok = attackCatalogReconcilerFor(adapter); ok {
				ids = append(ids, id)
			}
		}
	}
	rm.mu.Unlock()
	for _, id := range ids {
		// Best-effort: a run that cannot be proven clean stays unsafe. Errors are
		// recorded on the run's own status by reconcileAttackCatalogRun.
		_ = rm.reconcileAttackCatalogRun(id, "system", false)
	}
}
