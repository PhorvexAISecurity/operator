package mathlab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
)

const snapshotExt = ".pxms"

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// StoreEntry is one stored snapshot.
type StoreEntry struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Header Header `json:"header"`
}

// StoreStats is reported to metrics after every write.
type StoreStats struct {
	Files   int
	Bytes   int64
	Evicted int
	Written int64
	Failed  bool
}

// Store is a bounded, content-addressed snapshot directory. Writes happen on one
// background goroutine; Enqueue never blocks the decision tick. When the directory would
// exceed MaxBytes the oldest snapshots (by capture time) are evicted first.
type Store struct {
	dir      string
	maxBytes int64
	queue    chan Pending
	observe  func(StoreStats)

	mu      sync.RWMutex
	entries []StoreEntry // sorted by CapturedAt, then digest
	total   int64
}

// OpenStore indexes an existing directory (creating it if needed). Unreadable or foreign
// files are left untouched and not indexed.
func OpenStore(dir string, maxBytes int64, queueSize int, observe func(StoreStats)) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("math-lab store directory is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("math-lab store max bytes must be positive")
	}
	if queueSize <= 0 {
		queueSize = 4
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("math-lab store: %w", err)
	}
	if observe == nil {
		observe = func(StoreStats) {}
	}
	s := &Store{dir: dir, maxBytes: maxBytes, queue: make(chan Pending, queueSize), observe: observe}
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, de := range names {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, snapshotExt) || !digestPattern.MatchString(strings.TrimSuffix(name, snapshotExt)) {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		h, herr := ReadHeader(f)
		info, serr := f.Stat()
		_ = f.Close()
		if herr != nil || serr != nil {
			continue
		}
		s.entries = append(s.entries, StoreEntry{Digest: strings.TrimSuffix(name, snapshotExt), Size: info.Size(), Header: h})
		s.total += info.Size()
	}
	s.sortLocked()
	return s, nil
}

func (s *Store) sortLocked() {
	sort.Slice(s.entries, func(i, j int) bool {
		a, b := s.entries[i], s.entries[j]
		if !a.Header.CapturedAt.Equal(b.Header.CapturedAt) {
			return a.Header.CapturedAt.Before(b.Header.CapturedAt)
		}
		return a.Digest < b.Digest
	})
}

// Enqueue implements Sink.
func (s *Store) Enqueue(p Pending) bool {
	select {
	case s.queue <- p:
		return true
	default:
		return false
	}
}

// Run writes queued snapshots until ctx ends. It is the only writer.
func (s *Store) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-s.queue:
			s.write(p)
		}
	}
}

// Write stores one snapshot synchronously (used by Run and tests).
func (s *Store) write(p Pending) {
	file, err := assemble(p.Header, p.Stream)
	if err != nil {
		s.observe(StoreStats{Failed: true})
		return
	}
	digest := Digest(file)
	path := filepath.Join(s.dir, digest+snapshotExt)
	if int64(len(file)) > s.maxBytes {
		s.observe(StoreStats{Failed: true})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.Digest == digest {
			return
		}
	}
	evicted := 0
	for s.total+int64(len(file)) > s.maxBytes && len(s.entries) > 0 {
		old := s.entries[0]
		if err := os.Remove(filepath.Join(s.dir, old.Digest+snapshotExt)); err != nil && !os.IsNotExist(err) {
			s.observe(StoreStats{Failed: true})
			return
		}
		s.entries = s.entries[1:]
		s.total -= old.Size
		evicted++
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		s.observe(StoreStats{Failed: true, Evicted: evicted})
		return
	}
	_, werr := tmp.Write(file)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		s.observe(StoreStats{Failed: true, Evicted: evicted})
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		s.observe(StoreStats{Failed: true, Evicted: evicted})
		return
	}
	s.entries = append(s.entries, StoreEntry{Digest: digest, Size: int64(len(file)), Header: p.Header})
	s.total += int64(len(file))
	s.sortLocked()
	s.observe(StoreStats{Files: len(s.entries), Bytes: s.total, Evicted: evicted, Written: int64(len(file))})
}

// ListFilter narrows a listing.
type ListFilter struct {
	PolicyUID string
	Namespace string
	Policy    string
	Since     time.Time
	Until     time.Time
	Limit     int
}

// List returns stored snapshot entries in capture order.
func (s *Store) List(f ListFilter) []StoreEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]StoreEntry, 0)
	for _, e := range s.entries {
		h := e.Header
		if f.PolicyUID != "" && h.PolicyUID != f.PolicyUID {
			continue
		}
		if f.Namespace != "" && h.Namespace != f.Namespace {
			continue
		}
		if f.Policy != "" && h.PolicyName != f.Policy {
			continue
		}
		if !f.Since.IsZero() && h.CapturedAt.Before(f.Since) {
			continue
		}
		if !f.Until.IsZero() && !h.CapturedAt.Before(f.Until) {
			continue
		}
		out = append(out, e)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// Read returns the raw bytes of one snapshot after verifying its content address.
func (s *Store) Read(digest string) ([]byte, error) {
	if !digestPattern.MatchString(digest) {
		return nil, fmt.Errorf("invalid snapshot digest")
	}
	return ReadVerified(filepath.Join(s.dir, digest+snapshotExt), digest)
}

// ReadVerified reads a snapshot file and checks that its bytes hash to digest.
func ReadVerified(path, digest string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if Digest(raw) != digest {
		return nil, fmt.Errorf("snapshot %s failed its content-address check", digest)
	}
	return raw, nil
}

// IndexJSON serves the audit-transport snapshot index (audittransport.MathLabSnapshotSource).
func (s *Store) IndexJSON(q audittransport.MathLabSnapshotQuery) ([]byte, error) {
	entries := s.List(ListFilter{PolicyUID: q.PolicyUID, Namespace: q.Namespace, Policy: q.Policy, Since: q.Since, Until: q.Until, Limit: q.Limit})
	return json.Marshal(struct {
		Schema  string       `json:"schema"`
		Entries []StoreEntry `json:"entries"`
	}{Schema: "math-lab.snapshot-index.v1", Entries: entries})
}
