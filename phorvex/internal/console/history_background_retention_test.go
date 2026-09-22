package console

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	bolt "go.etcd.io/bbolt"
)

func TestHistoryStartupServesWhileRetentionWaits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := capacityTestConfig(dir, path)
	s := testHistoryStore(t, cfg)
	writeHistory(t, path, testDurableRecord(1))
	importHistoryNow(s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A startup migration would remove this file and synchronously ask for the
	// cutoff time. Background retention may wait, but HTTP must remain usable.
	sentinel := filepath.Join(dir, "audit-history.db.compact")
	if err := os.WriteFile(sentinel, []byte("unpublished maintenance copy"), 0600); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	cfg.HistoryRetentionDays = 30
	cfg.Now = func() time.Time { <-release; return time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC) }
	started := make(chan *Server, 1)
	go func() { started <- NewServer(cfg) }()
	var live *Server
	select {
	case live = <-started:
	case <-time.After(2 * time.Second):
		t.Cleanup(func() { (<-started).Close() })
		t.Fatal("history maintenance blocked HTTP server construction")
	}
	t.Cleanup(func() { live.Close() })
	if live.history == nil || live.historyInitErr != "" {
		t.Fatalf("history failed to open: %s", live.historyInitErr)
	}
	response := httptest.NewRecorder()
	live.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health during maintenance: %d %s", response.Code, response.Body.String())
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "unpublished maintenance copy" {
		t.Fatalf("startup touched the offline copy: %q %v", data, err)
	}
}

func TestHistoryBoundedRetentionPreservesNewImportsAndUnknownTimes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := capacityTestConfig(dir, path)
	now := time.Date(2026, 9, 22, 18, 0, 0, 0, time.UTC)
	cfg.Now = func() time.Time { return now }
	s := testHistoryStore(t, cfg)
	var records []audit.Record
	wantKept, expiredFirstBatch := 0, 0
	for i := 0; i < historyBatchRecords*3+17; i++ {
		r := testDurableRecord(i + 1)
		r.Reason = strings.Repeat("compress this legacy record ", 24)
		switch i % 3 {
		case 0:
			r.Time = now.Add(-31 * 24 * time.Hour)
			if i < historyBatchRecords {
				expiredFirstBatch++
			}
		case 1:
			r.Time = now.Add(-time.Hour)
			wantKept++
		case 2:
			r.Time = time.Time{}
			wantKept++
		}
		records = append(records, r)
	}
	writeHistory(t, path, records...)
	for i := 0; i < 10 && historyRecordCount(t, s.history) < len(records); i++ {
		importHistoryNow(s)
	}
	if historyRecordCount(t, s.history) != len(records) {
		t.Fatal("fixture import incomplete")
	}
	progress := singleHistoryProgress(t, s.history)
	var sequence uint64
	originals := map[string][]byte{}
	if err := s.history.db.View(func(tx *bolt.Tx) error {
		sequence = tx.Bucket(historyRecords).Sequence()
		return tx.Bucket(historyRecords).ForEach(func(k, v []byte) error {
			originals[string(k)] = bytes.Clone(v)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	s.history.cfg.HistoryRetentionDays = 30
	if err := s.history.pruneExpiredHistory(); err != nil {
		t.Fatal(err)
	}
	if got := historyRecordCount(t, s.history); got != len(records)-expiredFirstBatch || len(s.history.pruneAfter) == 0 {
		t.Fatalf("maintenance exceeded its first batch or skipped records: count=%d cursor=%x", got, s.history.pruneAfter)
	}
	if singleHistoryProgress(t, s.history) != progress {
		t.Fatal("maintenance changed source progress")
	}
	// New audit input must be imported while several maintenance batches remain.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	fresh := testDurableRecord(9999)
	fresh.Time = now
	err = json.NewEncoder(f).Encode(fresh)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	importHistoryNow(s)
	if p := singleHistoryProgress(t, s.history); !p.Complete || p.Offset <= progress.Offset {
		t.Fatalf("fresh import stalled behind maintenance: %+v", p)
	}
	if len(s.history.pruneAfter) == 0 {
		t.Fatal("fixture did not exercise concurrent import and unfinished maintenance")
	}
	for i := 0; i < 10 && len(s.history.pruneAfter) > 0; i++ {
		if err := s.history.pruneExpiredHistory(); err != nil {
			t.Fatal(err)
		}
	}
	if got := historyRecordCount(t, s.history); got != wantKept+1 {
		t.Fatalf("expired/recent/unknown record count: got=%d want=%d", got, wantKept+1)
	}
	compressed := 0
	if err := s.history.db.View(func(tx *bolt.Tx) error {
		rows := tx.Bucket(historyRecords)
		if rows.Sequence() != sequence+1 || tx.Bucket(historySeen).Stats().KeyN != wantKept+1 || tx.Bucket(historyIndex).Stats().KeyN != wantKept+1 {
			t.Fatal("maintenance changed sequence or indexes")
		}
		return rows.ForEach(func(k, v []byte) error {
			raw, err := decodeHistoryValue(v)
			if err != nil {
				return err
			}
			if original, exists := originals[string(k)]; exists {
				if !bytes.Equal(raw, original) {
					t.Fatalf("retained record %x changed", k)
				}
				if bytes.HasPrefix(v, []byte{0x1f, 0x8b}) {
					compressed++
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if compressed != wantKept {
		t.Fatalf("legacy compression incomplete: %d/%d", compressed, wantKept)
	}
}
