package console

import (
	"strings"
	"testing"
)

func TestCPUUnsafePredecessorRequiresDifferentSuccessorNonce(t *testing.T) {
	old := strings.Repeat("a", 24)
	proofs := []cpuCleanupProof{{cpuPreEventProof: cpuPreEventProof{nonce: old}}}
	if err := cpuNewNonceDisjoint(old, proofs); err == nil {
		t.Fatal("unsafe predecessor nonce reused")
	}
	if err := cpuNewNonceDisjoint(strings.Repeat("b", 24), proofs); err != nil {
		t.Fatalf("different successor nonce refused: %v", err)
	}
	if err := cpuNewNonceDisjoint("", proofs); err == nil {
		t.Fatal("empty successor nonce accepted")
	}
}
