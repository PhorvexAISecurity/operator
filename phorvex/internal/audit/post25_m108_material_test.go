package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/model"
)

func post25M108MaterialFixture(t *testing.T, id string, value float64) (*model.ParameterSetReference, model.DecisionParameterManifest, model.EffectivePolicyOverrides) {
	t.Helper()
	manifest := model.DecisionParameterManifest{SchemaVersion: model.DecisionParameterManifestV1, ID: "source-a", Parameters: []model.DecisionParameter{{
		Name: "parameter-a", Group: "group-a", Unit: "ratio", Domain: "[0,1]", Default: 0.5,
		Source: "fixture", Provenance: model.ParameterUnknown, Limitations: "fixture only", DependencyGroup: "group-a",
	}}}
	overrides := model.EffectivePolicyOverrides{SchemaVersion: model.DecisionPolicyOverridesV1, ID: id,
		Values: []model.EffectivePolicyParameter{{Name: "policy-a", Unit: "ratio", Present: true, Value: value}}}
	mh, err := manifest.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	oh, err := overrides.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	return &model.ParameterSetReference{SchemaVersion: model.DecisionParameterSetV1, ManifestID: manifest.ID, ManifestHash: mh,
		PolicyOverridesID: overrides.ID, PolicyOverridesHash: oh}, manifest, overrides
}

func TestPost25M108MaterialStoreRestartAndAuditRowJoin(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{store.root, filepath.Join(store.root, ParameterMaterialManifest), filepath.Join(store.root, ParameterMaterialPolicyOverrides)} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("material directory is not mode 0700: path=%s info=%v err=%v", path, info, err)
		}
	}
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	if err := store.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	manifestPath, _ := store.materialPath(ParameterMaterialManifest, ref.ManifestHash)
	if info, err := os.Lstat(manifestPath); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("material file is not a regular mode-0600 file: info=%v err=%v", info, err)
	}
	// A restarted process reopens and verifies immutable existing bytes rather
	// than depending on an in-memory registry.
	restarted, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	changedRef, _, changedOverrides := post25M108MaterialFixture(t, "ns/policy@uid:2", 0.75)
	if err := restarted.Store(changedRef, manifest, changedOverrides); err != nil {
		t.Fatal(err)
	}
	for kind, hash := range map[string]string{ParameterMaterialManifest: ref.ManifestHash, ParameterMaterialPolicyOverrides: ref.PolicyOverridesHash} {
		raw, err := ReadParameterMaterial(auditPath, kind, hash)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatalf("%s material is empty", kind)
		}
	}
	// A later generation/configuration does not replace the old document; both
	// remain independently reconstructable after the policy object is gone.
	if _, err := ReadParameterMaterial(auditPath, ParameterMaterialPolicyOverrides, changedRef.PolicyOverridesHash); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadParameterMaterial(auditPath, ParameterMaterialManifest, "sha256:../escape"); err == nil {
		t.Fatal("non-digest material name accepted")
	}
	if _, err := ReadParameterMaterial(auditPath, ParameterMaterialManifest, "sha256:"+strings.Repeat("A", 64)); err == nil {
		t.Fatal("uppercase digest material name accepted")
	}

	var out bytes.Buffer
	logger := New(logr.Discard(), &out)
	logger.SetParameterMaterialStore(restarted)
	if err := logger.RetainParameterSet("tenant-a", ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	if err := logger.Record(model.Decision{Tenant: "tenant-a", Engine: "p1-coverage", ParameterSet: ref}); err != nil {
		t.Fatal(err)
	}
	var row Record
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &row); err != nil {
		t.Fatal(err)
	}
	if row.ParameterMaterialStatus != parameterMaterialRetained || row.ParameterMaterialReason != "" || !reflect.DeepEqual(row.ParameterSet, ref) {
		t.Fatalf("decision row did not join retained material exactly: %+v", row)
	}
	out.Reset()
	if err := logger.Record(model.Decision{Tenant: "tenant-a", Engine: "p1-coverage", ParameterSet: ref,
		Reason: "rejected", Existential: &model.ExistentialDecision{}}); err != nil {
		t.Fatal(err)
	}
	var rejected Record
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.ParameterMaterialStatus != parameterMaterialRetained || !reflect.DeepEqual(rejected.ParameterSet, ref) {
		t.Fatalf("rejected decision row did not join retained material exactly: %+v", rejected)
	}
}

func TestPost25M108MaterialStoreRejectsPartialTamperedSymlinkAndCapacity(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	store.writeAll = func(out io.Writer, raw []byte) error {
		_, _ = out.Write(raw[:min(5, len(raw))])
		return errors.New("injected partial write")
	}
	if err := store.Store(ref, manifest, overrides); err == nil {
		t.Fatal("partial write reported success")
	}
	manifestDir := filepath.Join(store.root, ParameterMaterialManifest)
	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			t.Fatalf("partial material became visible: %s", entry.Name())
		}
	}

	store.writeAll = writeParameterBytes
	if err := store.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	manifestPath, _ := store.materialPath(ParameterMaterialManifest, ref.ManifestHash)
	if err := os.WriteFile(manifestPath, []byte(`{"tampered":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(ref, manifest, overrides); err == nil {
		t.Fatal("tampered material accepted")
	}

	symlinkStore, err := NewParameterMaterialStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	symlinkPath, _ := symlinkStore.materialPath(ParameterMaterialManifest, ref.ManifestHash)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := symlinkStore.Store(ref, manifest, overrides); err == nil {
		t.Fatal("symlink material accepted")
	}
	if raw, _ := os.ReadFile(victim); string(raw) != "unchanged" {
		t.Fatalf("symlink target changed: %q", raw)
	}

	capacityPath := filepath.Join(t.TempDir(), "audit.jsonl")
	capacity, err := NewParameterMaterialStore(capacityPath)
	if err != nil {
		t.Fatal(err)
	}
	capacity.maxDocs = 2
	firstRef, firstManifest, firstOverrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	if err := capacity.Store(firstRef, firstManifest, firstOverrides); err != nil {
		t.Fatal(err)
	}
	secondRef, _, secondOverrides := post25M108MaterialFixture(t, "ns/policy@uid:2", 0.5)
	if err := capacity.Store(secondRef, firstManifest, secondOverrides); err == nil {
		t.Fatal("bounded store accepted a third unique document")
	}
	var fullOut bytes.Buffer
	fullLogger := New(logr.Discard(), &fullOut)
	fullLogger.SetParameterMaterialStore(capacity)
	if err := fullLogger.RetainParameterSet("tenant-a", secondRef, firstManifest, secondOverrides); err == nil {
		t.Fatal("full store reported retained material")
	}
	if err := fullLogger.Record(model.Decision{Tenant: "tenant-a", Engine: "p1-coverage", ParameterSet: secondRef}); err != nil {
		t.Fatal(err)
	}
	var fullRow Record
	if err := json.Unmarshal(bytes.TrimSpace(fullOut.Bytes()), &fullRow); err != nil {
		t.Fatal(err)
	}
	if fullRow.ParameterMaterialStatus != parameterMaterialFailed || fullRow.ParameterMaterialReason != "store-write-failed" {
		t.Fatalf("full-store failure was not explicit on the decision row: %+v", fullRow)
	}
}

func TestPost25M108AuditMarksUnretainedParameterMaterial(t *testing.T) {
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	var out bytes.Buffer
	logger := New(logr.Discard(), &out)
	if err := logger.RetainParameterSet("tenant-a", ref, manifest, overrides); err == nil {
		t.Fatal("unconfigured store reported retained material")
	}
	if err := logger.Record(model.Decision{Tenant: "tenant-a", Engine: "p1-coverage", ParameterSet: ref}); err != nil {
		t.Fatal(err)
	}
	var row Record
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &row); err != nil {
		t.Fatal(err)
	}
	if row.ParameterMaterialStatus != parameterMaterialUnavailable || row.ParameterMaterialReason != "store-unconfigured" {
		t.Fatalf("unretained reference implied durable material: %+v", row)
	}
}

func TestPost25M108MaterialStoreRejectsOversizedDocument(t *testing.T) {
	store, err := NewParameterMaterialStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	manifest.Parameters[0].Limitations = strings.Repeat("x", MaxParameterMaterialBytes)
	ref.ManifestHash, err = manifest.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(ref, manifest, overrides); err == nil {
		t.Fatal("oversized canonical material accepted")
	}
}

func TestPost25M108MaterialStoreRejectsSymlinkedRootAndKindAfterInitialization(t *testing.T) {
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)

	rootStore, err := NewParameterMaterialStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rootStore.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	realRoot := rootStore.root + ".real"
	if err := os.Rename(rootStore.root, realRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, rootStore.root); err != nil {
		t.Fatal(err)
	}
	if err := rootStore.Store(ref, manifest, overrides); err == nil {
		t.Fatal("symlinked material root accepted for write")
	}
	if _, err := ReadParameterMaterial(strings.TrimSuffix(rootStore.root, ".parameters"), ParameterMaterialManifest, ref.ManifestHash); err == nil {
		t.Fatal("symlinked material root accepted for read")
	}

	kindStore, err := NewParameterMaterialStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := kindStore.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	kindDir := filepath.Join(kindStore.root, ParameterMaterialManifest)
	realKind := kindDir + ".real"
	if err := os.Rename(kindDir, realKind); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realKind, kindDir); err != nil {
		t.Fatal(err)
	}
	if err := kindStore.Store(ref, manifest, overrides); err == nil {
		t.Fatal("symlinked material kind directory accepted for write")
	}
	if _, err := ReadParameterMaterial(strings.TrimSuffix(kindStore.root, ".parameters"), ParameterMaterialManifest, ref.ManifestHash); err == nil {
		t.Fatal("symlinked material kind directory accepted for read")
	}
}

func TestPost25M108ParameterRetentionBookkeepingIsBounded(t *testing.T) {
	logger := New(logr.Discard(), nil)
	saturated, err := NewParameterMaterialStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	saturated.maxDocs = 0
	var first, latest *model.ParameterSetReference
	for i := 0; i <= maxParameterRetentionEntries+127; i++ {
		ref, manifest, overrides := post25M108MaterialFixture(t, "policy-"+strconv.Itoa(i), float64(i%100)/100)
		if i == 0 {
			first = ref
		}
		if i%2 != 0 {
			logger.SetParameterMaterialStore(saturated)
		} else {
			logger.SetParameterMaterialStore(nil)
		}
		latest = ref
		if err := logger.RetainParameterSet("tenant-a", ref, manifest, overrides); err == nil {
			t.Fatal("unconfigured/saturated material unexpectedly retained")
		}
	}
	logger.parameterMu.Lock()
	entries, order := len(logger.parameterRetention), len(logger.parameterOrder)
	logger.parameterMu.Unlock()
	if entries != maxParameterRetentionEntries || order != maxParameterRetentionEntries {
		t.Fatalf("retention bookkeeping grew past bound: entries=%d order=%d", entries, order)
	}
	if got := logger.parameterMaterialStatus(first); got.status != parameterMaterialUnavailable || got.reason != "material-not-retained" {
		t.Fatalf("evicted cache miss was not safely unavailable: %+v", got)
	}
	if got := logger.parameterMaterialStatus(latest); got.status != parameterMaterialFailed || got.reason != "store-write-failed" {
		t.Fatalf("current failure was not retained explicitly: %+v", got)
	}
	logger.parameterMu.Lock()
	logger.setParameterRetentionLocked(parameterMaterialKey(latest), parameterMaterialRetention{parameterMaterialRetained, ""})
	entries, order = len(logger.parameterRetention), len(logger.parameterOrder)
	logger.parameterMu.Unlock()
	if entries != maxParameterRetentionEntries || order != maxParameterRetentionEntries || logger.parameterMaterialStatus(latest).status != parameterMaterialRetained {
		t.Fatalf("same-key reuse changed bound or lost current status: entries=%d order=%d status=%+v", entries, order, logger.parameterMaterialStatus(latest))
	}
}

func TestPost25M108AuditMarksFailedParameterMaterial(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	store.writeAll = func(io.Writer, []byte) error { return errors.New("injected persistence failure") }
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	var out bytes.Buffer
	logger := New(logr.Discard(), &out)
	logger.SetParameterMaterialStore(store)
	if err := logger.RetainParameterSet("tenant-a", ref, manifest, overrides); err == nil {
		t.Fatal("injected persistence failure reported success")
	}
	if err := logger.Record(model.Decision{Tenant: "tenant-a", Engine: "p1-coverage", ParameterSet: ref}); err != nil {
		t.Fatal(err)
	}
	var row Record
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &row); err != nil {
		t.Fatal(err)
	}
	if row.ParameterMaterialStatus != parameterMaterialFailed || row.ParameterMaterialReason != "store-write-failed" {
		t.Fatalf("failed retention was not explicit on the decision row: %+v", row)
	}
}
