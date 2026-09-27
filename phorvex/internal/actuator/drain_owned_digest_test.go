package actuator

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDrainV11TerminalRetainsExactInitialSchedulerID(t *testing.T) {
	receipt, _ := drainV11ConfirmedReceipt(t, drainV11TestPod("one"), strings.Repeat("6", 64), strings.Repeat("2", 64))
	want := sha256.Sum256([]byte("request-a"))
	digest := hex.EncodeToString(want[:])
	if len(receipt.SnapshotDigests) != 1 || len(receipt.TerminalDigests) != 1 ||
		receipt.SnapshotDigests[0] != digest || receipt.TerminalDigests[0].RequestSHA256 != digest ||
		receipt.TerminalDigests[0].Disposition != "aborted" || !receipt.prepared() {
		t.Fatalf("initial scheduler ID and terminal disposition not bound: %#v", receipt)
	}
	bad := *receipt
	bad.SnapshotDigests = []string{strings.Repeat("f", 64)}
	if bad.prepared() {
		t.Fatal("changed initial scheduler ID accepted")
	}
}
