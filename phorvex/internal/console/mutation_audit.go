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
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// consoleMutation is one audited console write attempt.
type consoleMutation struct {
	Kind      string `json:"kind"` // "phorvex.console.mutation"
	Time      string `json:"time"`
	Actor     string `json:"actor"` // the request lens (owner/investor/operator); OIDC subject when available
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	Policy    string `json:"policy"`
	Field     string `json:"field"`           // "spec.tenant" for the key guard, "spec" for a merge patch
	Patch     string `json:"patch,omitempty"` // the merge patch as sent
	Verdict   string `json:"verdict"`         // applied | rejected-by-apiserver | rejected-tenant-key-write
	Message   string `json:"message,omitempty"`
}

var mutationAuditMu sync.Mutex

// mutationAuditPath resolves the append-only trail: an explicit path, else beside the decision
// audit, else under the harness dir. Empty when nothing is configured (log line only).
func (c *Config) mutationAuditPath() string {
	if c.MutationAuditPath != "" {
		return c.MutationAuditPath
	}
	if c.AuditPath != "" {
		return filepath.Join(filepath.Dir(c.AuditPath), "console-mutations.jsonl")
	}
	if c.HarnessDir != "" {
		return filepath.Join(c.HarnessDir, "console-mutations.jsonl")
	}
	return ""
}

// auditConsoleMutation appends the entry (best-effort; never blocks or fails the request)
// and always emits a structured log line so the verdict survives even without a writable path.
func (s *Server) auditConsoleMutation(m consoleMutation) {
	m.Kind = "phorvex.console.mutation"
	m.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	log.Printf("console-mutation %s", b)
	path := s.cfg.mutationAuditPath()
	if path == "" {
		return
	}
	mutationAuditMu.Lock()
	defer mutationAuditMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}
