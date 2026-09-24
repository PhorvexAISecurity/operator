package scenarios

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"time"
)

// ClaimNATSResponseRun is an irreversible, local one-use output claim before
// a logger can truncate evidence or a second invocation can reach Kubernetes.
// Recovery of an interrupted response run is read-only, never another fire.
func ClaimNATSResponseRun(out, runID, nonce string) error {
	if !natsResponseRunID.MatchString(runID) || !natsResponseNonce.MatchString(nonce) {
		return errors.New("NATS response run claim identity invalid")
	}
	root, err := natsResponseRoot(out)
	if err != nil {
		return err
	}
	if err := root.Close(); err != nil {
		return err
	}
	raw, err := json.Marshal(struct {
		Schema string `json:"schema"`
		RunID  string `json:"runId"`
		Nonce  string `json:"nonce"`
		At     string `json:"at"`
	}{natsResponseSchema, runID, nonce, time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil || len(raw) > 256 {
		return errors.New("NATS response run claim invalid")
	}
	return writeNATSResponseExclusive(filepath.Join(out, "nats-response-run-claim.json"), raw)
}
