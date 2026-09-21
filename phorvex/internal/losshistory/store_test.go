package losshistory

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/model"
)

func admittedRecord(t *testing.T, evidence, version string) model.AdmittedLossV1 {
	t.Helper()
	now := time.Unix(200, 0).UTC()
	digest := strings.Repeat("a", 64)
	p := model.CompletedDisclosureV1{
		SchemaVersion: model.CompletedDisclosureSchemaV1, EvidenceID: evidence,
		PolicyEpoch:         model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1},
		DecisionAsset:       model.DecisionAssetIdentity{Namespace: "ns", Name: "old-pod", TargetUID: "old-uid"},
		ImmediateController: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "ns", Name: "old-rs", UID: "rs-uid"},
		StableWorkloadOwner: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "app", UID: "deployment-uid"},
		ProtectedScope:      model.ProtectedScope{Tenant: "tenant", Asset: "synthetic", Version: version, Property: "confidentiality"},
		Classification: model.DisclosureClassification{RuleVersion: "rule-v1", RuleDigest: digest,
			ObserverClass: model.CompletedDisclosureClass, ObserverIdentity: "system:serviceaccount:ns:observer"},
		Observation: model.DisclosureObservation{StartedAt: now, CompletedAt: now.Add(time.Second), StatusCode: 200,
			ExpectedBytes: 5, ObservedBytes: 5, ReachedEOF: true, ExpectedSHA256: digest, ObservedSHA256: digest}, Synthetic: true,
	}
	_, payloadDigest, err := disclosure.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return model.AdmittedLossV1{SchemaVersion: model.AdmittedLossSchemaV1, Disclosure: p, CanonicalPayloadSHA256: payloadDigest,
		SecurityEvent:        model.SecurityEventIdentity{Name: "event-" + evidence, UID: "event-uid-" + evidence, CreationTimestamp: now.Add(2 * time.Second)},
		AuthenticatedCreator: "system:serviceaccount:ns:observer",
		TrustBoundary:        model.DisclosureTrustBoundary{ConfigurationUID: "mwc-uid", ConfigurationResourceVersion: "7", ActivationTime: now, ContractVersion: disclosure.BoundaryContract},
		IngestedAt:           now.Add(3 * time.Second)}
}

func TestM100LossHistoryImmutableRestartAndOwnerIsolation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	record := admittedRecord(t, "one", "v1")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- store.Put(record) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("idempotent concurrent put: %v", err)
		}
	}
	if got := store.Query("policy-uid", "deployment-uid"); got.Status != "available" || len(got.Records) != 1 {
		t.Fatalf("query = %+v", got)
	}
	if got := store.Query("other-policy", "deployment-uid"); len(got.Records) != 0 {
		t.Fatalf("replacement policy inherited history: %+v", got)
	}
	if got := store.Query("policy-uid", "other-owner"); len(got.Records) != 0 {
		t.Fatalf("unrelated owner inherited history: %+v", got)
	}
	restarted, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Put(record); err != nil {
		t.Fatalf("acknowledgement-loss retry: %v", err)
	}
	if got := restarted.Query("policy-uid", "deployment-uid"); len(got.Records) != 1 {
		t.Fatalf("restart = %+v", got)
	}

	conflict := record
	conflict.Disclosure.ProtectedScope.Version = "v2"
	_, conflict.CanonicalPayloadSHA256, _ = disclosure.Marshal(conflict.Disclosure)
	if err := restarted.Put(conflict); err == nil {
		t.Fatal("conflicting evidence ID replaced original")
	}
}

func TestM100LossHistoryCapacityTamperAndSpecialFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.max = 1
	first := admittedRecord(t, "one", "v1")
	if err := store.Put(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(admittedRecord(t, "two", "v2")); err == nil {
		t.Fatal("capacity exhaustion silently admitted new history")
	}
	if got := store.Query("policy-uid", "deployment-uid"); got.Status != "partial" || len(got.Records) != 1 {
		t.Fatalf("full store erased original or reported complete: %+v", got)
	}

	key := idKey(first.Disclosure.PolicyEpoch.UID, first.Disclosure.EvidenceID)
	path := filepath.Join(dir, fileName(key))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["authenticatedCreator"] = "forged"
	tampered, _ := json.Marshal(doc)
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if store.ContainsExact(first.Disclosure.PolicyEpoch.UID, first.Disclosure.EvidenceID, first.CanonicalPayloadSHA256, first.SecurityEvent.UID) {
		t.Fatal("changed durable entry accepted as acknowledgement retry")
	}
	if err := store.Put(first); err == nil {
		t.Fatal("acknowledgement retry hid changed durable entry")
	}
	reloaded, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Query("policy-uid", "deployment-uid"); got.Status != "partial" || len(got.Records) != 0 {
		t.Fatalf("tampered entry accepted: %+v", got)
	}

	symlinkRoot := filepath.Join(t.TempDir(), "history")
	if err := os.Symlink(dir, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := New(symlinkRoot); err == nil {
		t.Fatal("symlink root accepted")
	}
	leafDir := filepath.Join(t.TempDir(), "history")
	if err := os.Mkdir(leafDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(leafDir, strings.Repeat("b", 64)+".json")); err != nil {
		t.Fatal(err)
	}
	leafStore, err := New(leafDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := leafStore.Query("policy-uid", "deployment-uid"); got.Status != "partial" {
		t.Fatalf("symlink leaf hidden: %+v", got)
	}
}

func TestM100LossHistoryDirectoryPrivacy(t *testing.T) {
	public := t.TempDir()
	if _, err := New(public); err == nil {
		t.Fatal("world-accessible history root accepted")
	}
	groupPrivate := filepath.Join(t.TempDir(), "history")
	if err := os.Mkdir(groupPrivate, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupPrivate, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := New(groupPrivate); err != nil {
		t.Fatalf("fsGroup-private PVC root rejected: %v", err)
	}
}

func TestM100LossHistoryWriteFailureLatchesIncompleteAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.writeAll = func(io.Writer, []byte) error { return errors.New("injected record write failure") }
	if err := store.Put(admittedRecord(t, "lost", "v1")); err == nil {
		t.Fatal("injected retention failure was hidden")
	}
	if got := store.Query("policy-uid", "deployment-uid"); got.Status != "partial" || len(got.Records) != 0 {
		t.Fatalf("failed write later looked like complete empty history: %+v", got)
	}
	restarted, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.Query("policy-uid", "deployment-uid"); got.Status != "partial" || len(got.Records) != 0 {
		t.Fatalf("restart forgot retention incompleteness: %+v", got)
	}
}
