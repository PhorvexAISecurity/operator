package currentinventory

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func validCurrent(now time.Time) model.CurrentInventoryV1 {
	id := func(kind, name, uid string) model.ObjectIdentity {
		return model.ObjectIdentity{APIVersion: "apps/v1", Kind: kind, Namespace: "ns", Name: name, UID: uid}
	}
	return model.CurrentInventoryV1{SchemaVersion: model.CurrentInventorySchemaV1, EvidenceID: "current-v2", PolicyEpoch: model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 2}, DecisionAsset: model.DecisionAssetIdentity{Namespace: "ns", Name: "pod", TargetUID: "pod-uid"}, ImmediateController: id("ReplicaSet", "rs", "rs-uid"), StableWorkloadOwner: id("Deployment", "app", "dep-uid"), ProtectedScope: model.ProtectedScope{Tenant: "tenant", Asset: "synthetic-data", Version: "v2", Property: "confidentiality"}, SourceBinding: model.CurrentInventorySourceBinding{ConfigMap: model.ObjectIdentity{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "data", UID: "cm-uid"}, ResourceVersion: "7", Key: "payload", VolumeName: "data", ContainerName: "server", MountPath: "/data", ProjectedPath: "payload", Bytes: 2, SHA256: strings.Repeat("a", 64)}, Classification: model.CurrentInventoryClassification{RuleVersion: model.CurrentInventoryRuleVersionV1, RuleDigest: strings.Repeat("b", 64), InventoryClass: model.CurrentInventoryClass, PossibleOutcome: "unauthorized-disclosure", ObserverIdentity: "system:serviceaccount:ns:observer"}, Observation: model.CurrentInventoryObservation{StartedAt: now, CompletedAt: now.Add(time.Second), ValidUntil: now.Add(time.Minute), StatusCode: 200, ManifestEOF: true}, Synthetic: true}
}

func TestM100CurrentInventoryStrictContractAndBoundedStore(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	p := validCurrent(now)
	raw, digest, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, canonical, parsedDigest, err := Parse(raw)
	if err != nil || parsedDigest != digest || string(canonical) != raw || parsed.EvidenceID != p.EvidenceID {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, _, _, err := Parse(raw + ` true`); err == nil {
		t.Fatal("trailing JSON value accepted")
	}
	duplicate := strings.Replace(raw, `"evidenceID":"current-v2"`, `"evidenceID":"current-v2","evidenceID":"forged"`, 1)
	if _, _, _, err := Parse(duplicate); err == nil {
		t.Fatal("duplicate JSON field accepted")
	}
	bad := p
	bad.Synthetic = false
	if _, _, err := Marshal(bad); err == nil {
		t.Fatal("non-synthetic inventory accepted")
	}
	bad = p
	bad.Observation.ValidUntil = bad.Observation.CompletedAt.Add(MaxObservationTTL + time.Nanosecond)
	if _, _, err := Marshal(bad); err == nil {
		t.Fatal("unbounded observation accepted")
	}
	store := NewStore()
	record := model.AdmittedCurrentInventory{SchemaVersion: model.AdmittedCurrentInventorySchemaV1, Inventory: p, CanonicalPayloadSHA256: digest, SecurityEvent: model.SecurityEventIdentity{Name: "event", UID: "event-uid", CreationTimestamp: now.Add(2 * time.Second)}, AdmissionTime: now.Add(2500 * time.Millisecond), AuthenticatedCreator: p.Classification.ObserverIdentity, TrustBoundary: model.DisclosureTrustBoundary{ConfigurationUID: "webhook-uid", ConfigurationResourceVersion: "7", ActivationTime: now.Add(-time.Second), ContractVersion: BoundaryContract}, IngestedAt: now.Add(3 * time.Second)}
	if err := store.Put(record); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(record); err != nil {
		t.Fatalf("idempotent put: %v", err)
	}
	if got := store.Query(p.PolicyEpoch.UID, p.StableWorkloadOwner.UID, now.Add(30*time.Second)); got.Status != "available" || len(got.Records) != 1 {
		t.Fatalf("current query = %#v", got)
	}
	conflict := record
	conflict.SecurityEvent.UID = "other"
	if err := store.Put(conflict); err == nil {
		t.Fatal("conflicting evidence accepted")
	}
	if got := store.Query(p.PolicyEpoch.UID, p.StableWorkloadOwner.UID, now); got.Status != "partial" {
		t.Fatalf("conflict gap not retained: %#v", got)
	}
	if got := store.Query("other-policy", "other-owner", now); got.Status != "available" || len(got.Gaps) != 0 {
		t.Fatalf("conflict poisoned unrelated scope: %#v", got)
	}
	if got := store.Query(p.PolicyEpoch.UID, p.StableWorkloadOwner.UID, p.Observation.ValidUntil); len(got.Records) != 0 || got.Status != "available" {
		t.Fatalf("expired observation or conflict gap retained: %#v", got)
	}
}

func TestM100CurrentInventoryReclaimsExpiryAndScopesCapacityGaps(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := NewStore()
	store.max = 2
	record := func(policyUID, ownerUID, evidenceID string, started time.Time) model.AdmittedCurrentInventory {
		p := validCurrent(started)
		p.PolicyEpoch.UID = policyUID
		p.EvidenceID = evidenceID
		p.StableWorkloadOwner.UID = ownerUID
		raw, digest, err := Marshal(p)
		if err != nil || raw == "" {
			t.Fatalf("marshal %s: %v", evidenceID, err)
		}
		return model.AdmittedCurrentInventory{SchemaVersion: model.AdmittedCurrentInventorySchemaV1, Inventory: p, CanonicalPayloadSHA256: digest, SecurityEvent: model.SecurityEventIdentity{Name: "event-" + evidenceID, UID: "event-uid-" + evidenceID, CreationTimestamp: started.Add(2 * time.Second)}, AdmissionTime: started.Add(2500 * time.Millisecond), AuthenticatedCreator: p.Classification.ObserverIdentity, TrustBoundary: model.DisclosureTrustBoundary{ConfigurationUID: "webhook-uid", ConfigurationResourceVersion: "7", ActivationTime: started.Add(-time.Second), ContractVersion: BoundaryContract}, IngestedAt: started.Add(3 * time.Second)}
	}
	first := record("policy-a", "owner-a", "first", now)
	second := record("policy-b", "owner-b", "second", now)
	if err := store.Put(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(second); err != nil {
		t.Fatal(err)
	}
	blocked := record("policy-c", "owner-c", "blocked", now)
	if err := store.Put(blocked); err == nil {
		t.Fatal("active capacity bound accepted a third record")
	}
	if got := store.Query("policy-a", "owner-a", now.Add(4*time.Second)); got.Status != "available" || len(got.Records) != 1 {
		t.Fatalf("capacity failure poisoned retained owner: %#v", got)
	}
	if got := store.Query("policy-c", "owner-c", now.Add(4*time.Second)); got.Status != "partial" || len(got.Gaps) != 1 || got.Gaps[0] != "current-inventory-capacity-exhausted" {
		t.Fatalf("capacity failure was not scoped to affected owner: %#v", got)
	}

	afterExpiry := first.Inventory.Observation.ValidUntil
	if got := store.Query("policy-a", "owner-a", afterExpiry); got.Status != "available" || len(got.Records) != 0 {
		t.Fatalf("expired record was not reclaimed: %#v", got)
	}
	if got := store.Query("policy-c", "owner-c", afterExpiry); got.Status != "available" || len(got.Gaps) != 0 {
		t.Fatalf("expired capacity failure remained latched: %#v", got)
	}
	fresh := record("policy-a", "owner-a", "first", afterExpiry.Add(time.Second))
	if err := store.Put(fresh); err != nil {
		t.Fatalf("fresh post-expiry report rejected: %v", err)
	}
	if err := store.Put(first); err == nil {
		t.Fatal("stale expired report resurrected after the store watermark advanced")
	}
	if got := store.Query("policy-a", "owner-a", afterExpiry.Add(5*time.Second)); len(got.Records) != 1 || got.Records[0].SecurityEvent.UID != fresh.SecurityEvent.UID {
		t.Fatalf("fresh record was not retained exactly: %#v", got)
	}
}
