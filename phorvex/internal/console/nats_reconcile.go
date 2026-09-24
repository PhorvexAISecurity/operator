package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

type natsReconcileAudit struct {
	Kind      string `json:"kind"`
	Phase     string `json:"phase"`
	RunID     string `json:"runId"`
	AttemptID string `json:"attemptId"`
	Actor     string `json:"actor"`
	Status    string `json:"status"`
	At        string `json:"at"`
}

func (rm *RunManager) appendNATSReconcileAudit(id, actor, attemptID, phase, status string) error {
	raw, err := json.Marshal(natsReconcileAudit{Kind: "phorvex.console.nats.reconcile", Phase: phase, RunID: id, AttemptID: attemptID, Actor: actor, Status: status, At: rm.cfg.now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	return rm.cfg.appendState(rm.cfg.statePath("run-events.jsonl"), raw)
}

// ReconcileNATS runs one bounded read-only exact-identity check. It never
// replays the measurement or deletes a resource; the original result remains
// partial even when the next fresh run is safe to admit.
func (rm *RunManager) ReconcileNATS(id, actor string) error {
	return rm.reconcileNATSWithRunner(id, actor, func(ctx context.Context, configPath, outAbs, id, attemptID string) error {
		cmd := exec.CommandContext(ctx, rm.cfg.HarnessBin, "-config", configPath, "-nats-reconcile=true", "-nats-safety-out="+outAbs, "-nats-safety-id="+id, "-nats-reconcile-attempt="+attemptID)
		cmd.Dir = rm.cfg.HarnessDir
		cmd.Env = envBase()
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		return cmd.Run()
	})
}

func (rm *RunManager) reconcileNATSWithRunner(id, actor string, runner func(context.Context, string, string, string, string) error) error {
	rm.mu.Lock()
	st := rm.runs[id]
	if st == nil || st.Config != natsBaselineConfig || st.State != "partial" || !st.UnsafeToRetry || rm.procs[id] != nil || rm.natsReconciling[id] || rm.active != 0 {
		rm.mu.Unlock()
		return errors.New("NATS run is not an interrupted unsafe run eligible for read-only reconciliation")
	}
	out := rm.runOut[id]
	if out == "" || st.Namespace != "phorvex-nats-exposure-fixture" {
		rm.mu.Unlock()
		return errors.New("NATS run output or fixture namespace unavailable")
	}
	namespace := st.Namespace
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		rm.mu.Unlock()
		return err
	}
	attemptID := hex.EncodeToString(seed)
	if err := rm.appendNATSReconcileAudit(id, actor, attemptID, "intent", "READ_ONLY"); err != nil {
		rm.mu.Unlock()
		return fmt.Errorf("persist NATS reconciliation intent: %w", err)
	}
	if rm.natsReconciling == nil {
		rm.natsReconciling = map[string]bool{}
	}
	rm.natsReconciling[id] = true
	rm.active++
	rm.mu.Unlock()
	defer func() {
		rm.mu.Lock()
		delete(rm.natsReconciling, id)
		rm.active--
		rm.dequeueNextLocked()
		rm.mu.Unlock()
	}()
	outAbs := rm.cfg.runOutputPath(out)
	configPath := filepath.Join(rm.cfg.runsDir(), "configs", id+".yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmdErr := runner(ctx, configPath, outAbs, id, attemptID)
	verified := cmdErr == nil && ctx.Err() == nil && readNATSReconciliation(outAbs, id, namespace, configPath, attemptID)
	rm.mu.Lock()
	defer rm.mu.Unlock()
	current := rm.runs[id]
	if current == nil || current.Config != natsBaselineConfig || current.State != "partial" || !current.UnsafeToRetry || rm.procs[id] != nil {
		return errors.New("NATS run changed during reconciliation")
	}
	status := "UNVERIFIED"
	if verified {
		status = "VERIFIED_READ_ONLY"
	}
	if err := rm.appendNATSReconcileAudit(id, actor, attemptID, "terminal", status); err != nil {
		return fmt.Errorf("persist NATS reconciliation terminal audit: %w", err)
	}
	previous := *current
	current.State = "partial"
	current.Finished = tsNow()
	if verified {
		current.CleanupStatus = "VERIFIED_READ_ONLY"
		current.UnsafeToRetry = false
		current.Error = "interrupted NATS run reconciled read-only; original measurement remains incomplete"
	} else {
		current.CleanupStatus = "UNVERIFIED"
		current.UnsafeToRetry = true
		current.Error = "read-only NATS reconciliation refused; original outcome or owned absence unverified"
	}
	if err := rm.persistStatus(current, out); err != nil {
		*current = previous
		current.UnsafeToRetry = true
		return fmt.Errorf("persist NATS reconciliation status: %w", err)
	}
	if !verified {
		return errors.New("exact read-only NATS reconciliation did not verify owned absence")
	}
	return nil
}
