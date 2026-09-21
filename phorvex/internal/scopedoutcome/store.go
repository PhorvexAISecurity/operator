package scopedoutcome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// DirectoryEvidenceStore is a bounded, non-evicting private evidence store.
// Files are content-addressed by the already validated evidence SHA-256 ID.
type DirectoryEvidenceStore struct {
	mu            sync.Mutex
	root          string
	maxItems      int
	maxTotalBytes int64
	items         int
	totalBytes    int64
	createTemp    func(string, string) (evidenceTempFile, error)
	link          func(string, string) error
	syncRoot      func() error
}

type evidenceTempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

func NewDirectoryEvidenceStore(root string, maxItems int, maxTotalBytes int64) (*DirectoryEvidenceStore, error) {
	if !filepath.IsAbs(root) || maxItems <= 0 || maxItems > maxRetainedOperations || maxTotalBytes <= 0 {
		return nil, errors.New("scoped outcome evidence store configuration is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("scoped outcome evidence root is not a private directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	store := &DirectoryEvidenceStore{root: filepath.Clean(root), maxItems: maxItems, maxTotalBytes: maxTotalBytes,
		createTemp: func(dir, pattern string) (evidenceTempFile, error) { return os.CreateTemp(dir, pattern) }, link: os.Link}
	store.syncRoot = func() error {
		dir, err := os.Open(store.root)
		if err != nil {
			return err
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("unexpected evidence-store entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		store.items++
		store.totalBytes += info.Size()
	}
	if store.items > store.maxItems || store.totalBytes > store.maxTotalBytes {
		return nil, errors.New("existing scoped outcome evidence exceeds configured capacity")
	}
	return store, nil
}

func (s *DirectoryEvidenceStore) Put(ctx context.Context, bundle EvidenceBundle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validDigest(bundle.EvidenceID) || bundle.EvidenceID != bundle.Observation.EvidenceID {
		return errors.New("scoped outcome evidence identity is invalid")
	}
	raw, err := json.Marshal(bundle)
	if err != nil || len(raw) == 0 || len(raw) > maxEvidenceBytes {
		return errors.New("scoped outcome evidence encoding is invalid or oversized")
	}
	name := bundle.EvidenceID + ".json"
	path := filepath.Join(s.root, name)
	if filepath.Dir(path) != s.root {
		return errors.New("scoped outcome evidence path escaped its root")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rootInfo, err := os.Lstat(s.root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("scoped outcome evidence root identity changed")
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxEvidenceBytes {
			return errors.New("scoped outcome evidence leaf is not regular")
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Equal(existing, raw) {
			// A prior call may have linked these exact bytes but failed while
			// syncing the parent directory. Re-establish directory durability
			// before declaring an idempotent retry successful.
			return s.syncRoot()
		}
		return errors.New("scoped outcome evidence ID conflicts with retained bytes")
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if s.items >= s.maxItems || s.totalBytes+int64(len(raw)) > s.maxTotalBytes {
		return errors.New("scoped outcome evidence store is full")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tmp, err := s.createTemp(s.root, ".pending-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	err = tmp.Chmod(0o600)
	if err == nil {
		var written int
		written, err = tmp.Write(raw)
		if err == nil && written != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.link(tmpName, path); err != nil {
		// The path was absent at the locked check above. If another store
		// instance won the link race, account the newly observed regular leaf
		// exactly once before checking content or durability.
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxEvidenceBytes {
			return errors.New("scoped outcome evidence link-race leaf is not regular")
		}
		s.items++
		s.totalBytes += info.Size()
		if s.items > s.maxItems || s.totalBytes > s.maxTotalBytes {
			return errors.New("scoped outcome evidence store is full after a concurrent link")
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Equal(existing, raw) {
			// Equality authenticates content, not parent-directory durability.
			return s.syncRoot()
		}
		return errors.New("scoped outcome evidence ID conflicts with concurrently retained bytes")
	}
	s.items++
	s.totalBytes += int64(len(raw))
	err = s.syncRoot()
	if err != nil {
		// The linked bytes may exist but their durability is unknown. Keep the
		// file and return failure; a later identical retry can re-open and report
		// the same uncertainty to an operator without overwriting evidence.
		return err
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
