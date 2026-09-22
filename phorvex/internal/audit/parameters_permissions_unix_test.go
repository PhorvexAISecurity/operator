//go:build linux

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParameterMaterialStoreRecoversExactFSGroupModesWithoutChangingBytes(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "live.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	first, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	if err := store.Store(first, manifest, overrides); err != nil {
		t.Fatal(err)
	}

	want := make(map[string][]byte)
	for kind, hash := range map[string]string{
		ParameterMaterialManifest: first.ManifestHash, ParameterMaterialPolicyOverrides: first.PolicyOverridesHash,
	} {
		path, err := store.materialPath(kind, hash)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want[path] = raw
		mustUnixChmod(t, path, fsGroupMaterialFile)
	}
	tempName := "." + strings.Repeat("a", 64) + ".json." + strings.Repeat("b", 24) + ".tmp"
	tempPath := filepath.Join(store.root, ParameterMaterialPolicyOverrides, tempName)
	tempBytes := []byte("crash-left-partial-bytes")
	if err := os.WriteFile(tempPath, tempBytes, privateFileMode); err != nil {
		t.Fatal(err)
	}
	mustUnixChmod(t, tempPath, fsGroupMaterialFile)
	want[tempPath] = tempBytes
	for _, dir := range []string{filepath.Join(store.root, ParameterMaterialManifest), filepath.Join(store.root, ParameterMaterialPolicyOverrides), store.root} {
		mustUnixChmod(t, dir, fsGroupMaterialDir)
	}

	reopened, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range want {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("startup changed retained bytes at %s", filepath.Base(path))
		}
		assertUnixMode(t, path, privateFileMode)
	}
	for _, dir := range []string{reopened.root, filepath.Join(reopened.root, ParameterMaterialManifest), filepath.Join(reopened.root, ParameterMaterialPolicyOverrides)} {
		assertUnixMode(t, dir, privateDirMode)
	}
	for kind, hash := range map[string]string{ParameterMaterialManifest: first.ManifestHash, ParameterMaterialPolicyOverrides: first.PolicyOverridesHash} {
		raw, err := ReadParameterMaterial(auditPath, kind, hash)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if "sha256:"+hex.EncodeToString(sum[:]) != hash {
			t.Fatalf("reopened %s bytes did not retain their digest", kind)
		}
	}

	second, _, secondOverrides := post25M108MaterialFixture(t, "ns/policy@uid:2", 0.75)
	if err := reopened.Store(second, manifest, secondOverrides); err != nil {
		t.Fatalf("append after restoration: %v", err)
	}
	if _, err := ReadParameterMaterial(auditPath, ParameterMaterialPolicyOverrides, second.PolicyOverridesHash); err != nil {
		t.Fatal(err)
	}
	if _, err := NewParameterMaterialStore(auditPath); err != nil {
		t.Fatalf("repeated strict restart: %v", err)
	}

	// The preserved crash file remains part of the bounded document count.
	reopened.maxDocs = len(want) + 1
	third, _, thirdOverrides := post25M108MaterialFixture(t, "ns/policy@uid:3", 0.5)
	if err := reopened.Store(third, manifest, thirdOverrides); err == nil {
		t.Fatal("preserved crash-left file did not count toward capacity")
	}
}

func TestParameterMaterialStoreCreatesPrivateTreeUnderSetgidAuditDirectory(t *testing.T) {
	parent := t.TempDir()
	mustUnixChmod(t, parent, 02775)
	auditPath := filepath.Join(parent, "live.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{store.root, filepath.Join(store.root, ParameterMaterialManifest), filepath.Join(store.root, ParameterMaterialPolicyOverrides)} {
		assertUnixMode(t, dir, privateDirMode)
	}
}

func TestParameterMaterialStoreRecoveryRejectsUntrustedExistingObjects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, store *ParameterMaterialStore, finalPath string)
	}{
		{name: "world-readable file", mutate: func(t *testing.T, _ *ParameterMaterialStore, path string) { mustUnixChmod(t, path, 0604) }},
		{name: "world-writable directory", mutate: func(t *testing.T, store *ParameterMaterialStore, _ string) { mustUnixChmod(t, store.root, 0702) }},
		{name: "group mode without observed setgid shape", mutate: func(t *testing.T, store *ParameterMaterialStore, _ string) { mustUnixChmod(t, store.root, 0770) }},
		{name: "unexpected root hierarchy", mutate: func(t *testing.T, store *ParameterMaterialStore, _ string) {
			if err := os.Mkdir(filepath.Join(store.root, "other"), privateDirMode); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unexpected file name", mutate: func(t *testing.T, store *ParameterMaterialStore, _ string) {
			if err := os.WriteFile(filepath.Join(store.root, ParameterMaterialManifest, "other.json"), []byte("{}"), privateFileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", mutate: func(t *testing.T, store *ParameterMaterialStore, path string) {
			name := "." + strings.Repeat("c", 64) + ".json." + strings.Repeat("d", 24) + ".tmp"
			if err := os.Symlink(path, filepath.Join(store.root, ParameterMaterialManifest, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", mutate: func(t *testing.T, store *ParameterMaterialStore, path string) {
			name := "." + strings.Repeat("c", 64) + ".json." + strings.Repeat("d", 24) + ".tmp"
			if err := os.Link(path, filepath.Join(store.root, ParameterMaterialManifest, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "digest mismatch", mutate: func(t *testing.T, _ *ParameterMaterialStore, path string) {
			if err := os.WriteFile(path, []byte(`{"changed":true}`), privateFileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed digest-addressed JSON", mutate: func(t *testing.T, store *ParameterMaterialStore, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"incomplete":`)
			sum := sha256.Sum256(raw)
			name := hex.EncodeToString(sum[:]) + ".json"
			if err := os.WriteFile(filepath.Join(store.root, ParameterMaterialManifest, name), raw, privateFileMode); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "live.jsonl")
			store, err := NewParameterMaterialStore(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
			if err := store.Store(ref, manifest, overrides); err != nil {
				t.Fatal(err)
			}
			path, err := store.materialPath(ParameterMaterialManifest, ref.ManifestHash)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, store, path)
			if _, err := NewParameterMaterialStore(auditPath); err == nil {
				t.Fatal("untrusted existing store was accepted")
			}
		})
	}
}

func TestParameterMaterialStoreRecoveryRejectsForeignOwnershipWhenPermitted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	auditPath := filepath.Join(t.TempDir(), "live.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	if err := store.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	path, err := store.materialPath(ParameterMaterialManifest, ref.ManifestHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewParameterMaterialStore(auditPath); err == nil {
		t.Fatal("foreign-owned material was accepted")
	}
}

func TestParameterMaterialStoreRecoveryRejectsSymlinkedRoot(t *testing.T) {
	parent := t.TempDir()
	auditPath := filepath.Join(parent, "live.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	if err := store.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	realRoot := store.root + ".real"
	if err := os.Rename(store.root, realRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, store.root); err != nil {
		t.Fatal(err)
	}
	if _, err := NewParameterMaterialStore(auditPath); err == nil {
		t.Fatal("symlinked store root was accepted during recovery")
	}
	if _, err := os.Stat(filepath.Join(realRoot, ParameterMaterialManifest)); err != nil {
		t.Fatalf("refused recovery changed the retained tree: %v", err)
	}
}

func TestParameterMaterialStoreRecoveryPreflightsBeforeChangingModes(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "live.jsonl")
	store, err := NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	ref, manifest, overrides := post25M108MaterialFixture(t, "ns/policy@uid:1", 0.25)
	if err := store.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	path, err := store.materialPath(ParameterMaterialManifest, ref.ManifestHash)
	if err != nil {
		t.Fatal(err)
	}
	mustUnixChmod(t, path, fsGroupMaterialFile)
	if err := os.WriteFile(filepath.Join(store.root, ParameterMaterialManifest, "unexpected"), []byte("leave everything unchanged"), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := NewParameterMaterialStore(auditPath); err == nil {
		t.Fatal("store with an unexpected entry was accepted")
	}
	assertUnixMode(t, path, fsGroupMaterialFile)
}

func TestParameterMaterialStoreRejectsForeignRootBeforeCreatingChildren(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "live.jsonl.parameters")
	if err := os.Mkdir(root, privateDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := NewParameterMaterialStore(filepath.Join(parent, "live.jsonl")); err == nil {
		t.Fatal("foreign-owned store root was accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("foreign root was modified before refusal: %v", entries)
	}
}

func assertUnixMode(t *testing.T, path string, want uint32) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatal(err)
	}
	if got := stat.Mode & 07777; got != want {
		t.Fatalf("%s mode=%#o, want %#o", path, got, want)
	}
}

func mustUnixChmod(t *testing.T, path string, mode uint32) {
	t.Helper()
	if err := unix.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
