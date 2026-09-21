package scopedoutcome

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

type m106ShortEvidenceFile struct{ evidenceTempFile }

func (f m106ShortEvidenceFile) Write(raw []byte) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	return f.evidenceTempFile.Write(raw[:len(raw)-1])
}

func m106EvidenceBundle(id string) EvidenceBundle {
	return EvidenceBundle{SchemaVersion: model.ScopedOutcomeObservationSchemaV1, EvidenceID: id,
		Observation: model.PersistenceObservation{EvidenceID: id}, Before: []byte(`{"present":true}`), Action: []byte(`{"emitted":true}`), After: []byte(`{"present":false}`)}
}

func TestPost25M106DirectoryEvidenceStoreRestartConflictAndCapacity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "evidence")
	store, err := NewDirectoryEvidenceStore(root, 1, maxEvidenceBytes)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	bundle := m106EvidenceBundle(id)
	if err := store.Put(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), bundle); err != nil {
		t.Fatalf("identical retry was not idempotent: %v", err)
	}
	conflict := bundle
	conflict.After = []byte(`{"present":true}`)
	if err := store.Put(context.Background(), conflict); err == nil {
		t.Fatal("conflicting evidence ID overwrote retained bytes")
	}
	if err := store.Put(context.Background(), m106EvidenceBundle(strings.Repeat("b", 64))); err == nil {
		t.Fatal("bounded store evicted evidence")
	}
	restarted, err := NewDirectoryEvidenceStore(root, 1, maxEvidenceBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Put(context.Background(), m106EvidenceBundle(strings.Repeat("c", 64))); err == nil {
		t.Fatal("restart forgot non-evicting capacity")
	}
	info, err := os.Stat(filepath.Join(root, id+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence permissions=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestPost25M106DirectoryEvidenceStoreRejectsSymlinkRootAndLeaf(t *testing.T) {
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(parent, "linked")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectoryEvidenceStore(linkedRoot, 1, maxEvidenceBytes); err == nil {
		t.Fatal("accepted symlink evidence root")
	}
	store, err := NewDirectoryEvidenceStore(realRoot, 1, maxEvidenceBytes)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	outside := filepath.Join(parent, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(realRoot, id+".json")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), m106EvidenceBundle(id)); err == nil {
		t.Fatal("followed symlink evidence leaf")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "outside" {
		t.Fatal("symlink refusal changed outside bytes")
	}
}

func TestPost25M106DirectoryEvidenceStoreRejectsShortWriteAndResyncsRetry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "evidence")
	store, err := NewDirectoryEvidenceStore(root, 2, maxEvidenceBytes*2)
	if err != nil {
		t.Fatal(err)
	}
	realCreate := store.createTemp
	store.createTemp = func(dir, pattern string) (evidenceTempFile, error) {
		file, err := realCreate(dir, pattern)
		if err != nil {
			return nil, err
		}
		return m106ShortEvidenceFile{evidenceTempFile: file}, nil
	}
	shortID := strings.Repeat("d", 64)
	if err := store.Put(context.Background(), m106EvidenceBundle(shortID)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short durable write was not refused: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, shortID+".json")); !os.IsNotExist(err) {
		t.Fatalf("short evidence became visible: %v", err)
	}

	store.createTemp = realCreate
	realSync := store.syncRoot
	syncCalls := 0
	store.syncRoot = func() error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected directory sync failure")
		}
		return realSync()
	}
	id := strings.Repeat("e", 64)
	bundle := m106EvidenceBundle(id)
	if err := store.Put(context.Background(), bundle); err == nil {
		t.Fatal("directory sync failure was reported as durable success")
	}
	if err := store.Put(context.Background(), bundle); err != nil {
		t.Fatalf("identical retry did not re-sync retained bytes: %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("idempotent retry did not re-sync its parent directory: calls=%d", syncCalls)
	}
}

func TestPost25M106ConcurrentEqualLinkStillRequiresDirectoryDurabilityAndCapacity(t *testing.T) {
	id := strings.Repeat("f", 64)
	bundle := m106EvidenceBundle(id)
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		maxItems      int
		maxTotalBytes int64
	}{
		{name: "item capacity", maxItems: 1, maxTotalBytes: maxEvidenceBytes * 2},
		{name: "byte capacity", maxItems: 2, maxTotalBytes: int64(len(raw) + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "evidence")
			store, err := NewDirectoryEvidenceStore(root, tc.maxItems, tc.maxTotalBytes)
			if err != nil {
				t.Fatal(err)
			}
			realLink := store.link
			store.link = func(oldname, newname string) error {
				if err := realLink(oldname, newname); err != nil {
					return err
				}
				return os.ErrExist
			}
			realSync := store.syncRoot
			syncCalls := 0
			store.syncRoot = func() error {
				syncCalls++
				if syncCalls == 1 {
					return errors.New("injected concurrent-link directory sync failure")
				}
				return realSync()
			}
			if err := store.Put(context.Background(), bundle); err == nil {
				t.Fatal("equal concurrent link bypassed parent-directory durability")
			}
			if syncCalls != 1 || store.items != 1 || store.totalBytes != int64(len(raw)) {
				t.Fatalf("concurrent link was not accounted exactly once: sync=%d items=%d bytes=%d wantBytes=%d", syncCalls, store.items, store.totalBytes, len(raw))
			}
			store.link = realLink
			if err := store.Put(context.Background(), bundle); err != nil {
				t.Fatalf("idempotent retry did not establish directory durability: %v", err)
			}
			if syncCalls != 2 || store.items != 1 || store.totalBytes != int64(len(raw)) {
				t.Fatalf("retry double-counted or skipped sync: sync=%d items=%d bytes=%d", syncCalls, store.items, store.totalBytes)
			}
			if err := store.Put(context.Background(), m106EvidenceBundle(strings.Repeat("e", 64))); err == nil {
				t.Fatal("concurrent link accounting allowed capacity overflow")
			}
		})
	}
}
