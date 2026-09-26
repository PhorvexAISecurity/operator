package console

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCPUPreEventProofReconcilesCleanRun21Shape(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	const target = "arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks"
	const nonce = "60bf41c9878d9056727f1b15"
	const runID = "run-21"
	prior := &RunStatus{
		ID: runID, Config: podBoundTokenCPUConfig, State: "partial",
		Namespace: podBoundTokenCPUNamespace, CleanupStatus: "UNVERIFIED",
		UnsafeToRetry: true, ScopeTenant: podBoundTokenCPUNamespace,
		ScopeTarget: target, Finished: "2026-09-25 20:10:49 UTC",
		Owner: "reviewed-owner", Trials: 0, Error: "Pod-bound token early unsafe receipt: 8 created UIDs, cleanup CONFIRMED_ABSENT; exact reconciliation required",
	}
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{runID: prior}, procs: map[string]*exec.Cmd{}, stopping: map[string]bool{}}
	out := cfg.runOutputPath(runID)
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	uid := map[string]string{
		"serviceaccounts":      "f4d0ca3d-91c1-48c4-841d-56a0b6d67e0e",
		"deployments":          "2cf99b32-5d77-44e6-aad0-0077b78656ba",
		"services":             "73ed6616-5f68-48e7-9b83-43b48aa41f36",
		"poddisruptionbudgets": "42542f86-782b-4474-8ecf-c071ff07934b",
		"roles":                "ef57c89a-e80f-4726-98f3-db8f51bd50ad",
		"rolebindings":         "b90e75f5-39cd-4a5f-b229-dcc10e6b3cfe",
		"phorvexpolicies":      "a9df3289-8a3e-487b-9293-48c814cbf5ca",
		"podmonitors":          "c24062e2-2052-441d-a9b2-346a90439387",
	}
	const sourceUID = "95c1b8ab-ffd1-4f95-ba9e-c166c0f120c0"
	const peerUID = "9c1f34d5-aee1-441e-8126-75ecf9533574"
	const rsUID = "ee2d1530-1dad-4ba8-bb26-e181d8e49fb8"
	const amtdUID = "84d76124-b101-4b9c-a9c5-292ccea6b7a4"
	var rows []podBoundPhaseRow
	at := time.Date(2026, 9, 25, 20, 7, 59, 0, time.UTC)
	add := func(op, resource, name, identity string) {
		rows = append(rows, podBoundPhaseRow{Schema: "pod-bound-token-phase-v1", RunID: runID, Nonce: nonce, Operation: op, Resource: resource, Name: name, UID: identity, At: at.Format(time.RFC3339Nano)})
		at = at.Add(time.Millisecond)
	}
	resources := []string{"serviceaccounts", "deployments", "services", "poddisruptionbudgets", "roles", "rolebindings", "phorvexpolicies", "podmonitors"}
	name := "pod-token-" + nonce
	for _, resource := range resources {
		add("CREATE_INTENT", resource, name, "")
		add("CREATE_ACK", resource, name, uid[resource])
	}
	add("PATCH_INTENT", "pods", name+"-5fffbbfdc7-8z9k5", sourceUID)
	add("PATCH_ACK", "pods", name+"-5fffbbfdc7-8z9k5", sourceUID)
	add("DELETE_INTENT", "phorvexpolicies", name, uid["phorvexpolicies"])
	add("DELETE_ACK", "phorvexpolicies", name, uid["phorvexpolicies"])
	add("DELETE_INTENT", "adaptivemovingtargetdefenses", "phorvex-"+podBoundTokenCPUNamespace+"-"+nonce, amtdUID)
	add("DELETE_ACK", "adaptivemovingtargetdefenses", "phorvex-"+podBoundTokenCPUNamespace+"-"+nonce, amtdUID)
	for _, resource := range []string{"podmonitors", "poddisruptionbudgets", "deployments", "rolebindings", "roles", "services", "serviceaccounts"} {
		add("DELETE_INTENT", resource, name, uid[resource])
		add("DELETE_ACK", resource, name, uid[resource])
	}
	var journal bytes.Buffer
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		journal.Write(raw)
		journal.WriteByte('\n')
	}
	journalRaw := journal.Bytes()
	created := make([]string, 0, len(resources))
	for _, resource := range resources {
		created = append(created, resource+"/"+name+"/"+uid[resource])
	}
	sort.Strings(created)
	unsafe := PodBoundTokenUnsafeReceipt{
		Schema: "pod-bound-token-unsafe-v1", RunID: runID, Nonce: nonce,
		NamespaceUID: "a1b25080-ee41-4485-918b-e67481b0c4ed", CreatedUIDs: created,
		DeploymentUID: uid["deployments"], ReplicaSetUID: rsUID, SourcePodUID: sourceUID,
		PeerPodUID: peerUID, PhaseJournalSHA256: podBoundHash(journalRaw), CleanupStatus: "CONFIRMED_ABSENT",
		InventorySHA256: strings.Repeat("c", 64), ErrorSHA256: podBoundHash([]byte("CPU token source-Pod measured request rate unavailable before event")),
		RecordedAt: at.Format(time.RFC3339Nano),
	}
	write := func() {
		t.Helper()
		if err := os.WriteFile(filepath.Join(out, podBoundPhaseFile), journalRaw, 0600); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(unsafe)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "pod-bound-token-unsafe.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, err := rm.cpuPreEventProofsLocked(target); err != nil {
		t.Fatalf("actual cleaned run21 shape rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, podBoundRequestFile), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.cpuPreEventProofsLocked(target); err == nil {
		t.Fatal("a pre-event predecessor with a request artifact was admitted")
	}
	if err := os.Remove(filepath.Join(out, podBoundRequestFile)); err != nil {
		t.Fatal(err)
	}
	journalRaw = bytes.Replace(journalRaw, []byte(uid["deployments"]), []byte("2cf99b32-5d77-44e6-aad0-0077b78656b"), 1)
	unsafe.PhaseJournalSHA256 = podBoundHash(journalRaw)
	write()
	if _, err := rm.cpuPreEventProofsLocked(target); err == nil {
		t.Fatal("a changed cleanup UID was admitted")
	}
}
