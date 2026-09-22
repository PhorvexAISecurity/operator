package console

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestHistoryRetentionMigrationPreservesRecentOffsetsAndCursorSequence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	now := time.Date(2026, 9, 22, 18, 0, 0, 0, time.UTC)
	cfg := capacityTestConfig(dir, path)
	cfg.Now = func() time.Time { return now }
	s := testHistoryStore(t, cfg)
	old, recent, unknown := testDurableRecord(1), testDurableRecord(2), testDurableRecord(3)
	old.Time = now.Add(-31 * 24 * time.Hour)
	recent.Time = now.Add(-time.Hour)
	unknown.Time = time.Time{}
	recent.Reason = strings.Repeat("retained decision trace ", 4000)
	writeHistory(t, path, old, recent, unknown)
	importHistoryNow(s)
	beforeProgress := singleHistoryProgress(t, s.history)
	var seq uint64
	s.history.db.View(func(tx *bolt.Tx) error { seq = tx.Bucket(historyRecords).Sequence(); return nil })
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(filepath.Join(dir, "audit-history.db"))
	before := stat.Size()
	cfg.HistoryRetentionDays = 30
	s = testHistoryStore(t, cfg)
	if got := historyRecordCount(t, s.history); got != 2 {
		t.Fatalf("retained records=%d", got)
	}
	if got := singleHistoryProgress(t, s.history); got != beforeProgress {
		t.Fatalf("offset changed: %+v != %+v", got, beforeProgress)
	}
	s.history.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(historyRecords).Sequence() != seq {
			t.Fatal("sequence reset")
		}
		if tx.Bucket(historySeen).Stats().KeyN != 2 || tx.Bucket(historyIndex).Stats().KeyN != 2 {
			t.Fatal("stale indexes")
		}
		return nil
	})
	stat, _ = os.Stat(filepath.Join(dir, "audit-history.db"))
	if stat.Size() >= before {
		t.Fatalf("no storage reduction: %d >= %d", stat.Size(), before)
	}
	page, _ := getHistory(t, s, url.Values{"lens": {"operator"}, "includeNoop": {"true"}}, 200)
	if len(page.Events) != 2 {
		t.Fatalf("page lost records: %+v", page)
	}
	importHistoryNow(s)
	if historyRecordCount(t, s.history) != 2 {
		t.Fatal("expired source was reimported")
	}
	now = now.Add(31 * 24 * time.Hour)
	if err := s.history.pruneExpiredHistory(); err != nil {
		t.Fatal(err)
	}
	if historyRecordCount(t, s.history) != 1 {
		t.Fatal("retention failed to age recent record; unknown time must stay")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = testHistoryStore(t, cfg)
	if historyRecordCount(t, s.history) != 1 {
		t.Fatal("restart lost retention state")
	}
}

func TestHistoryCompressionRoundtripAndCorruption(t *testing.T) {
	raw, _ := json.Marshal(storedHistoryRecord{Source: "s", ID: "i", Record: json.RawMessage(`{"reason":"` + strings.Repeat("repeated ", 1000) + `"}`)})
	value, err := encodeHistoryValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeHistoryValue(value)
	if err != nil || !bytes.Equal(decoded, raw) || len(value) >= len(raw) {
		t.Fatalf("compression: %d -> %d err=%v", len(raw), len(value), err)
	}
	value[len(value)-5] ^= 0xff
	if _, err := decodeHistoryValue(value); err == nil {
		t.Fatal("corrupt compressed record accepted")
	}
	if got, err := decodeHistoryValue(raw); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("legacy record rejected")
	}
}

func TestHistoryCompactionFailureRetainsOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := capacityTestConfig(dir, path)
	s := testHistoryStore(t, cfg)
	writeHistory(t, path, testDurableRecord(1))
	importHistoryNow(s)
	before := historyDatabaseSnapshot(t, s.history)
	cfg.HistoryRetentionDays = 30
	cfg.HistoryMinFreeBytes = 1 << 60
	if err := compactHistoryStorage(cfg, s.history.db); err == nil {
		t.Fatal("compaction ignored capacity reserve")
	}
	if got := historyDatabaseSnapshot(t, s.history); got != before {
		t.Fatal("failed migration changed original")
	}
	if _, err := os.Stat(s.history.db.Path() + ".compact"); !os.IsNotExist(err) {
		t.Fatal("partial copy retained")
	}
}

func TestHistoryRetentionHonorsCapacityBeforeDeleting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := capacityTestConfig(dir, path)
	s := testHistoryStore(t, cfg)
	writeHistory(t, path, testDurableRecord(1))
	importHistoryNow(s)
	before := historyDatabaseSnapshot(t, s.history)
	s.history.cfg.HistoryRetentionDays = 30
	s.history.cfg.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	info, err := os.Stat(s.history.db.Path())
	if err != nil {
		t.Fatal(err)
	}
	s.history.archiveMaxBytes = info.Size() + s.history.transactionReserve - 1
	if err := s.history.pruneExpiredHistory(); err == nil {
		t.Fatal("retention bypassed archive headroom")
	}
	if got := historyDatabaseSnapshot(t, s.history); got != before {
		t.Fatal("capacity refusal changed retained records or offsets")
	}
	if len(s.history.pruneAfter) != 0 {
		t.Fatal("failed retention advanced its scan cursor")
	}
}
