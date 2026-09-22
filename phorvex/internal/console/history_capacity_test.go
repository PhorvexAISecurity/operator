package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/audit"
	bolt "go.etcd.io/bbolt"
)

func capacityTestConfig(dir, auditPath string) Config {
	return Config{
		StateDir:                       dir,
		AuditPath:                      auditPath,
		HistoryArchiveMaxBytes:         8 << 20,
		HistoryMinFreeBytes:            8 << 10,
		historyTransactionReserveBytes: 4 << 10,
	}
}

func historyDatabaseSnapshot(t *testing.T, h *historyStore) [32]byte {
	t.Helper()
	var buf bytes.Buffer
	if err := h.db.View(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{historyRecords, historySeen, historyOffsets, historyGaps, historyGapMeta, historyIndex, historyActive} {
			bucket := tx.Bucket(name)
			if bucket == nil {
				return fmt.Errorf("missing bucket %q", name)
			}
			buf.Write(name)
			var seq [8]byte
			binary.BigEndian.PutUint64(seq[:], bucket.Sequence())
			buf.Write(seq[:])
			if err := bucket.ForEach(func(k, v []byte) error {
				buf.Write(k)
				buf.WriteByte(0)
				buf.Write(v)
				buf.WriteByte(0xff)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(buf.Bytes())
}

func historyRecordCount(t *testing.T, h *historyStore) int {
	t.Helper()
	count := 0
	if err := h.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(historyRecords).ForEach(func(_, _ []byte) error { count++; return nil })
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func singleHistoryProgress(t *testing.T, h *historyStore) historyProgress {
	t.Helper()
	var values []historyProgress
	if err := h.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(historyOffsets).ForEach(func(_, raw []byte) error {
			var progress historyProgress
			if err := json.Unmarshal(raw, &progress); err != nil {
				return err
			}
			values = append(values, progress)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 {
		t.Fatalf("history progress entries = %d, want 1", len(values))
	}
	return values[0]
}

func TestHistoryCapacityPausePreservesOffsetsAndRetries(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	cfg := capacityTestConfig(dir, auditPath)
	s := testHistoryStore(t, cfg)
	available := int64(1 << 30)
	s.history.filesystemUsage = func(string) (historyFilesystemUsage, error) {
		return historyFilesystemUsage{availableBytes: available}, nil
	}

	writeHistory(t, auditPath, testDurableRecord(1))
	importHistoryNow(s)
	if got := historyRecordCount(t, s.history); got != 1 {
		t.Fatalf("initial record count = %d", got)
	}
	initialSize, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if progress := singleHistoryProgress(t, s.history); progress.Offset != uint64(initialSize.Size()) || !progress.Complete {
		t.Fatalf("initial progress = %+v, source bytes = %d", progress, initialSize.Size())
	}
	writeHistory(t, auditPath, testDurableRecord(2))
	before := historyDatabaseSnapshot(t, s.history)
	available = s.history.minFreeBytes + s.history.transactionReserve - 1
	importHistoryNow(s)
	if got := historyDatabaseSnapshot(t, s.history); got != before {
		t.Fatal("capacity rejection changed durable records or offsets")
	}
	if progress := singleHistoryProgress(t, s.history); progress.Offset != uint64(initialSize.Size()) {
		t.Fatalf("rejected import advanced offset to %d, want %d", progress.Offset, initialSize.Size())
	}
	status := s.history.statusFor("default")
	if !status.capacityPaused || status.ready {
		t.Fatalf("capacity status = %+v", status)
	}
	page, body := getHistory(t, s, url.Values{"lens": {"operator"}}, 200)
	if len(page.Events) != 1 || !page.Partial || !strings.Contains(body, "paused by the capacity guard") || strings.Contains(body, "source is currently unavailable") {
		t.Fatalf("capacity page = %s", body)
	}

	available = 1 << 30
	importHistoryNow(s)
	if got := historyRecordCount(t, s.history); got != 2 {
		t.Fatalf("restored record count = %d", got)
	}
	restoredSize, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if progress := singleHistoryProgress(t, s.history); progress.Offset != uint64(restoredSize.Size()) || !progress.Complete {
		t.Fatalf("restored progress = %+v, source bytes = %d", progress, restoredSize.Size())
	}
	if !s.history.statusFor("default").ready {
		t.Fatalf("restored status = %+v", s.history.statusFor("default"))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = testHistoryStore(t, cfg)
	importHistoryNow(s)
	if got := historyRecordCount(t, s.history); got != 2 {
		t.Fatalf("restart duplicated records: %d", got)
	}
}

func TestHistoryCapacityExistingArchiveReadableAndMetadataFailClosed(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	cfg := capacityTestConfig(dir, auditPath)
	s := testHistoryStore(t, cfg)
	s.history.filesystemUsage = func(string) (historyFilesystemUsage, error) {
		return historyFilesystemUsage{availableBytes: 1 << 30}, nil
	}
	writeHistory(t, auditPath, testDurableRecord(1))
	importHistoryNow(s)
	missingKey := []byte(s.history.sourceID("default") + "\x00missing-generation")
	progress, err := json.Marshal(historyProgress{Offset: 7, Anchor: "retained-anchor"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.history.update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(historyOffsets).Put(missingKey, progress); err != nil {
			return err
		}
		return tx.Bucket(historyActive).Put(missingKey, progress)
	}); err != nil {
		t.Fatal(err)
	}

	before := historyDatabaseSnapshot(t, s.history)
	s.history.filesystemUsage = func(string) (historyFilesystemUsage, error) {
		return historyFilesystemUsage{}, errors.New("statfs unavailable")
	}
	writeHistory(t, auditPath, testDurableRecord(2))
	importHistoryNow(s)
	if got := historyDatabaseSnapshot(t, s.history); got != before {
		t.Fatal("filesystem-stat failure changed durable records or offsets")
	}
	if !s.history.statusFor("default").capacityPaused {
		t.Fatalf("statfs status = %+v", s.history.statusFor("default"))
	}
	if err := s.history.noteMissingGenerations(historySource{id: "default"}); err == nil {
		t.Fatal("missing-generation metadata ignored capacity failure")
	}
	if got := historyDatabaseSnapshot(t, s.history); got != before {
		t.Fatal("rejected missing-generation metadata changed database")
	}
	if err := s.history.resetProgressAfterRewrite([]byte("new-key"), "source", "generation", 7, "rewrite"); err == nil {
		t.Fatal("metadata reset ignored capacity failure")
	}
	if got := historyDatabaseSnapshot(t, s.history); got != before {
		t.Fatal("rejected metadata reset changed database")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	over := cfg
	over.HistoryArchiveMaxBytes = 2 * over.historyTransactionReserveBytes
	s = testHistoryStore(t, over)
	importHistoryNow(s)
	if got := historyRecordCount(t, s.history); got != 1 {
		t.Fatalf("over-budget archive lost existing record: %d", got)
	}
	if !s.history.statusFor("default").capacityPaused {
		t.Fatalf("over-budget status = %+v", s.history.statusFor("default"))
	}
	page, _ := getHistory(t, s, url.Values{"lens": {"operator"}}, 200)
	if len(page.Events) != 1 || !page.Partial {
		t.Fatalf("over-budget archive unreadable: %+v", page)
	}
}

func TestHistoryCapacityBboltGrowthFitsTransactionReserve(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	cfg := Config{StateDir: dir, AuditPath: auditPath}
	s := testHistoryStore(t, cfg)
	records := make([]audit.Record, 120)
	for i := range records {
		records[i] = historyRecord(i, true)
	}
	writeHistory(t, auditPath, records...)
	iterations := 0
	var maxGrowth int64
	for ; iterations < 10 && !s.history.statusFor("default").ready; iterations++ {
		before, err := os.Stat(s.history.db.Path())
		if err != nil {
			t.Fatal(err)
		}
		importHistoryNow(s)
		after, err := os.Stat(s.history.db.Path())
		if err != nil {
			t.Fatal(err)
		}
		growth := after.Size() - before.Size()
		if growth > maxGrowth {
			maxGrowth = growth
		}
		if growth > s.history.transactionReserve {
			t.Fatalf("bbolt batch grew %d bytes; reserve %d", growth, s.history.transactionReserve)
		}
	}
	if iterations < 2 || !s.history.statusFor("default").ready {
		t.Fatalf("expected repeated bounded batches, iterations=%d status=%+v", iterations, s.history.statusFor("default"))
	}
	if got := historyRecordCount(t, s.history); got != len(records) {
		t.Fatalf("imported %d records, want %d", got, len(records))
	}
	t.Logf("actual repeated bbolt producer: iterations=%d max-file-growth=%d transaction-reserve=%d", iterations, maxGrowth, s.history.transactionReserve)
}

func TestHistoryCapacityConfigurationValidation(t *testing.T) {
	cfg := Config{HistoryArchiveMaxBytes: 1, HistoryMinFreeBytes: 1}
	if err := cfg.ValidateHistoryCapacity(); err == nil {
		t.Fatal("unsafe history capacity limits accepted")
	}
	cfg = capacityTestConfig(t.TempDir(), "unused")
	if err := cfg.ValidateHistoryCapacity(); err != nil {
		t.Fatalf("bounded test limits rejected: %v", err)
	}
}
