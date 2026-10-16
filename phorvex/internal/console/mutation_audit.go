/*
 * Phorvex Console — audit trail of console-initiated cluster writes (PHORVEXSEC-205 / M-145).
 *
 * Every write the console attempts against a PhorvexPolicy is appended here with its verdict:
 * applied, rejected-by-apiserver (the API server's message verbatim) or
 * rejected-tenant-key-write (the console refused to touch spec.tenant). The decision audit
 * (phorvex.decision records) stays untouched: this is a separate kind in a separate file.
 */

package console

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"
)

// consoleMutation is one audited console write attempt.
type consoleMutation struct {
	Kind      string `json:"kind"` // "phorvex.console.mutation"
	Time      string `json:"time"`
	Actor     string `json:"actor"` // the VERIFIED principal "<issuer>#<subject>" (M-136), never a self-asserted lens
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	Policy    string `json:"policy"`
	Field     string `json:"field"`           // "spec.tenant" for the key guard, "spec" for a merge patch
	Patch     string `json:"patch,omitempty"` // the merge patch as sent
	Verdict   string `json:"verdict"`         // applied | rejected-by-apiserver | rejected-tenant-key-write
	Message   string `json:"message,omitempty"`

	// Runtime optimizer parameter changes (/api/optimizer/runtime/apply) also carry the change
	// identity, the policy generations around the write and each knob's before/after, so the
	// change can be matched to the brain's first decision at the new generation and undone.
	ChangeID           string            `json:"changeId,omitempty"`
	PolicyUID          string            `json:"policyUid,omitempty"`
	PreviousGeneration int64             `json:"previousGeneration,omitempty"`
	Generation         int64             `json:"generation,omitempty"`
	BeforeMode         string            `json:"economicsModeBefore,omitempty"`
	AfterMode          string            `json:"economicsModeAfter,omitempty"`
	Parameters         []parameterChange `json:"parameters,omitempty"`
	Note               string            `json:"note,omitempty"`
	RestoreOf          string            `json:"restoreOf,omitempty"`
}

// mutationAuditPath never derives from the manager-owned decision audit.
func (c *Config) mutationAuditPath() string {
	if c.MutationAuditPath != "" {
		return c.MutationAuditPath
	}
	return c.statePath("console-mutations.jsonl")
}

// auditConsoleMutation returns only after the record is durable. The log is supplementary.
func (s *Server) auditConsoleMutation(m consoleMutation) error {
	m.Kind = "phorvex.console.mutation"
	m.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode mutation evidence: %w", err)
	}
	slog.Info("console mutation", "record", json.RawMessage(b))
	path := s.cfg.mutationAuditPath()
	if path == "" {
		err := fmt.Errorf("console state path is not configured")
		s.recordStateError(err)
		return err
	}
	if m.Verdict == "intent" {
		path = filepath.Join(filepath.Dir(path), "mutation-intents.jsonl")
	}
	if err := s.cfg.appendState(path, b); err != nil {
		err = fmt.Errorf("persist mutation evidence: %w", err)
		s.recordStateError(err)
		return err
	}
	return nil
}
