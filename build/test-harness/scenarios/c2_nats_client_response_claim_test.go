package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNATSResponseRunClaimPreservesFirstRunEvidence(t *testing.T) {
	out := t.TempDir()
	const nonce = "0123456789abcdef01234567"
	if err := ClaimNATSResponseRun(out, "run-7", nonce); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "nats-response-run-claim.json")
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ClaimNATSResponseRun(out, "run-7", nonce); err == nil {
		t.Fatal("second invocation reached run-owned output")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(first) {
		t.Fatal("refused rerun changed first run claim")
	}
	if err := ClaimNATSResponseRun(out, "run-8", nonce); err == nil {
		t.Fatal("different run ID adopted one-use output directory")
	}
}
