package console

// The history store is a console-owned, append-only archive of decision records. JSONL remains
// the compatibility/live source, but rotation or deletion of that source never deletes rows here.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	bolt "go.etcd.io/bbolt"
)

var (
	historyRecords = []byte("records-v1")
	historySeen    = []byte("seen-v1")
	historyOffsets = []byte("offsets-v1")
	historyGaps    = []byte("gaps-v1")
	historyGapMeta = []byte("gap-meta-v1")
	historyIndex   = []byte("source-index-v1")
	historyActive  = []byte("active-imports-v1")
)

const (
	historyBatchBytes   = 4 << 20
	historyBatchRecords = 256
)

type historyProgress struct {
	Offset   uint64 `json:"offset"`
	Anchor   string `json:"anchor"`
	SkipScan uint64 `json:"skipScan,omitempty"`
	Complete bool   `json:"complete"`
}

type historyGap struct {
	Source, Generation, Message string
	Offset                      uint64
	At                          string
}

type storedHistoryRecord struct {
	Source string          `json:"source"`
	ID     string          `json:"id"`
	Record json.RawMessage `json:"record"`
}

type databaseCursor struct {
	Version  int    `json:"v"`
	Scope    string `json:"scope"`
	Snapshot uint64 `json:"snapshot"`
	Before   uint64 `json:"before"`
}

type historyStore struct {
	db                 *bolt.DB
	cfg                Config
	cancel             context.CancelFunc
	done               chan struct{}
	mu                 sync.RWMutex
	status             map[string]historySourceStatus
	closed             bool
	bind               string
	archiveMaxBytes    int64
	minFreeBytes       int64
	transactionReserve int64
	filesystemUsage    func(string) (historyFilesystemUsage, error)
}

type historySourceStatus struct {
	err            string
	ready          bool
	capacityPaused bool
	capacityNotice string
}

type historyFilesystemUsage struct {
	availableBytes int64
}

type historyCapacityError struct {
	reason string
	detail string
}

func (e *historyCapacityError) Error() string {
	return "durable history import paused by capacity guard: " + e.reason + " (" + e.detail + ")"
}

func (e *historyCapacityError) notice() string {
	switch e.reason {
	case "archive byte ceiling reached", "filesystem free-space reserve reached":
		return e.reason + " (" + e.detail + ")"
	default:
		// Filesystem and stat errors can contain host paths. The authenticated API needs the
		// actionable class of failure, but never its environment-specific error text.
		return e.reason
	}
}

func readHistoryFilesystemUsage(path string) (historyFilesystemUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return historyFilesystemUsage{}, err
	}
	blockSize, available := uint64(stat.Bsize), uint64(stat.Bavail)
	if blockSize == 0 || available > math.MaxInt64/blockSize {
		return historyFilesystemUsage{}, errors.New("filesystem availability is outside supported range")
	}
	return historyFilesystemUsage{availableBytes: int64(available * blockSize)}, nil
}

type historyGapMetaRecord struct {
	Count  uint64 `json:"count"`
	Latest string `json:"latest"`
	At     string `json:"at"`
}

func openHistoryStore(cfg Config) (*historyStore, error) {
	archiveMax, minFree, transactionReserve, err := cfg.historyCapacityLimits()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(cfg.StateDir, "audit-history.db")
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		usage, usageErr := readHistoryFilesystemUsage(cfg.StateDir)
		if usageErr != nil {
			return nil, &historyCapacityError{reason: "filesystem availability unavailable before database creation", detail: usageErr.Error()}
		}
		if usage.availableBytes < minFree+transactionReserve {
			return nil, &historyCapacityError{reason: "filesystem free-space reserve reached before database creation", detail: fmt.Sprintf("available=%d minimum-free=%d transaction-reserve=%d", usage.availableBytes, minFree, transactionReserve)}
		}
	} else if statErr != nil {
		return nil, statErr
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoFreelistSync: false})
	if err != nil {
		return nil, err
	}
	identity := cfg.AuditSourceIdentity
	if cfg.AuditSource != nil && identity == "" {
		db.Close()
		return nil, errors.New("remote audit source identity is required for durable history")
	}
	if identity == "" {
		identity = "local:" + filepath.Clean(cfg.AuditPath)
	}
	identityHash := sha256.Sum256([]byte(identity))
	h := &historyStore{db: db, cfg: cfg, bind: hex.EncodeToString(identityHash[:16]), status: map[string]historySourceStatus{},
		archiveMaxBytes: archiveMax, minFreeBytes: minFree, transactionReserve: transactionReserve, filesystemUsage: readHistoryFilesystemUsage}
	missingBuckets := false
	if err = db.View(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{historyRecords, historySeen, historyOffsets, historyGaps, historyGapMeta, historyIndex, historyActive} {
			if tx.Bucket(name) == nil {
				missingBuckets = true
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	if missingBuckets {
		err = h.update(func(tx *bolt.Tx) error {
			for _, name := range [][]byte{historyRecords, historySeen, historyOffsets, historyGaps, historyGapMeta, historyIndex, historyActive} {
				if _, e := tx.CreateBucketIfNotExists(name); e != nil {
					return e
				}
			}
			return nil
		})
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan struct{})
	go h.ingestLoop(ctx)
	return h, nil
}

func (h *historyStore) checkCapacity() error {
	info, err := os.Stat(h.db.Path())
	if err != nil {
		return &historyCapacityError{reason: "database size unavailable", detail: err.Error()}
	}
	if info.Size() > h.archiveMaxBytes-h.transactionReserve {
		return &historyCapacityError{reason: "archive byte ceiling reached", detail: fmt.Sprintf("database=%d maximum=%d transaction-reserve=%d", info.Size(), h.archiveMaxBytes, h.transactionReserve)}
	}
	usage, err := h.filesystemUsage(h.db.Path())
	if err != nil {
		return &historyCapacityError{reason: "filesystem availability unavailable", detail: err.Error()}
	}
	if usage.availableBytes < h.minFreeBytes+h.transactionReserve {
		return &historyCapacityError{reason: "filesystem free-space reserve reached", detail: fmt.Sprintf("available=%d minimum-free=%d transaction-reserve=%d", usage.availableBytes, h.minFreeBytes, h.transactionReserve)}
	}
	return nil
}

func (h *historyStore) update(fn func(*bolt.Tx) error) error {
	if err := h.checkCapacity(); err != nil {
		return err
	}
	return h.db.Update(fn)
}

func (h *historyStore) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	<-h.done
	return h.db.Close()
}

func (h *historyStore) setStatus(source string, err error, ready bool) {
	h.mu.Lock()
	s := historySourceStatus{ready: ready}
	if err == nil {
		s.err = ""
	} else {
		s.err = err.Error()
		var capacityErr *historyCapacityError
		s.capacityPaused = errors.As(err, &capacityErr)
		if s.capacityPaused {
			s.capacityNotice = capacityErr.notice()
		}
	}
	h.status[source] = s
	h.mu.Unlock()
}

func (h *historyStore) ingestLoop(ctx context.Context) {
	defer close(h.done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		h.ingestOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type historySource struct {
	id       string
	segments []auditSegment
	open     auditOpener
	err      error
}

func (h *historyStore) sources(ctx context.Context) []historySource {
	if h.cfg.AuditSource != nil {
		manifest, err := h.cfg.AuditSource.Manifest(ctx)
		if err != nil {
			return []historySource{{id: "default", err: err}, {id: "vcluster", err: err}}
		}
		bySource := map[string][]auditSegment{"default": {}, "vcluster": {}}
		pinned := map[string]audittransport.Segment{}
		for _, seg := range manifest.Segments {
			if seg.ID != "live" && !strings.HasPrefix(seg.ID, "backup-") && seg.ID != "vcluster-live" && !strings.HasPrefix(seg.ID, "vcluster-backup-") {
				continue
			}
			source := "default"
			if strings.HasPrefix(seg.ID, "vcluster-") {
				source = "vcluster"
			}
			logical := "audit://" + seg.ID
			pinned[logical] = seg
			n := 0
			if i := strings.LastIndex(seg.ID, "backup-"); i >= 0 {
				n, _ = strconv.Atoi(seg.ID[i+len("backup-"):])
			}
			bySource[source] = append(bySource[source], auditSegment{path: logical, number: n, generation: seg.Generation})
		}
		open := func(path string) (auditHandle, error) {
			seg, ok := pinned[path]
			if !ok {
				return nil, errAuditChanged
			}
			return h.cfg.AuditSource.Open(ctx, seg), nil
		}
		var out []historySource
		for _, id := range []string{"default", "vcluster"} {
			segs := bySource[id]
			sortAuditOldestFirst(segs)
			out = append(out, historySource{id: id, segments: segs, open: open})
		}
		if len(bySource["default"]) == 0 {
			out[0].err = errors.New("configured audit source is unavailable")
		}
		if len(bySource["vcluster"]) == 0 {
			out[1].err = errors.New("configured vcluster audit source is unavailable")
		}
		return out
	}
	if h.cfg.AuditPath == "" {
		return []historySource{{id: "default", err: errors.New("audit history import waiting for a configured audit-json source")}, {id: "vcluster", err: errors.New("vcluster audit source is unavailable")}}
	}
	var out []historySource
	for _, source := range []struct{ id, path string }{{"default", h.cfg.AuditPath}, {"vcluster", h.cfg.auditPathForContext("vcluster")}} {
		segs, err := retainedAuditSegments(source.path, openAuditFile)
		if err != nil {
			out = append(out, historySource{id: source.id, open: openAuditFile, err: err})
			continue
		}
		sortAuditOldestFirst(segs)
		out = append(out, historySource{id: source.id, segments: segs, open: openAuditFile})
		if len(segs) == 0 {
			out[len(out)-1].err = errors.New("configured audit source is unavailable")
		}
	}
	return out
}

func sortAuditOldestFirst(segs []auditSegment) {
	// backup-N grows older as N grows; live (0) is always last. Never trust manifest order.
	sort.Slice(segs, func(i, j int) bool { return segs[i].number > segs[j].number })
}

func (h *historyStore) sourceID(id string) string { return h.bind + "\x00" + id }

func (h *historyStore) ingestOnce(ctx context.Context) {
	for _, source := range h.sources(ctx) {
		if source.err != nil {
			h.setStatus(source.id, source.err, false)
			continue
		}
		if err := h.noteMissingGenerations(source); err != nil {
			h.setStatus(source.id, err, false)
			continue
		}
		complete, failed := true, false
		for _, seg := range source.segments {
			done, err := h.ingestSegment(ctx, source, seg)
			if err != nil {
				h.setStatus(source.id, fmt.Errorf("%s: %w", seg.generation, err), false)
				complete = false
				failed = true
				break
			}
			if !done {
				complete = false
				break // preserve oldest-to-newest append chronology
			}
		}
		if complete {
			h.setStatus(source.id, nil, true)
		} else if !failed {
			h.setStatus(source.id, nil, false)
		}
	}
}

func (h *historyStore) statusFor(source string) historySourceStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.status[source]
}

func (h *historyStore) noteMissingGenerations(source historySource) error {
	if len(source.segments) > retainedFileLimit {
		return fmt.Errorf("retained audit exceeds %d segments", retainedFileLimit)
	}
	present := map[string]bool{}
	for _, seg := range source.segments {
		present[seg.generation] = true
	}
	prefix := []byte(h.sourceID(source.id) + "\x00")
	return h.update(func(tx *bolt.Tx) error {
		active, offsets := tx.Bucket(historyActive), tx.Bucket(historyOffsets)
		placeholder, err := json.Marshal(historyProgress{})
		if err != nil {
			return err
		}
		for _, seg := range source.segments {
			key := []byte(h.sourceID(source.id) + "\x00" + seg.generation)
			if offsets.Get(key) != nil {
				continue
			}
			if err := offsets.Put(key, placeholder); err != nil {
				return err
			}
			if err := active.Put(key, placeholder); err != nil {
				return err
			}
		}
		c := active.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var p historyProgress
			if json.Unmarshal(v, &p) != nil || p.Complete {
				continue
			}
			generation := string(k[len(prefix):])
			if !present[generation] {
				if err := putHistoryGap(tx, h.sourceID(source.id), generation, p.Offset, "source generation disappeared before import completed"); err != nil {
					return err
				}
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (h *historyStore) ingestSegment(ctx context.Context, source historySource, seg auditSegment) (bool, error) {
	sourceID := h.sourceID(source.id)
	offsetKey := []byte(sourceID + "\x00" + seg.generation)
	var progress historyProgress
	if err := h.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(historyOffsets).Get(offsetKey); b != nil {
			return json.Unmarshal(b, &progress)
		}
		return nil
	}); err != nil {
		return false, err
	}
	f, err := source.open(seg.path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	generation, err := auditGeneration(f)
	if err != nil || generation != seg.generation {
		return false, errAuditChanged
	}
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	snapshot := uint64(st.Size())
	if progress.Offset > snapshot || progress.SkipScan > snapshot {
		return false, h.resetProgressAfterRewrite(offsetKey, sourceID, seg.generation, progress.Offset, "source generation shrank or was cleared before import completed")
	}
	if progress.Anchor != "" {
		anchor, anchorErr := auditAnchor(f, int64(progress.Offset))
		if anchorErr != nil || anchor != progress.Anchor {
			return false, h.resetProgressAfterRewrite(offsetKey, sourceID, seg.generation, progress.Offset, "source prefix changed before import completed")
		}
	}
	start, readAt := progress.Offset, progress.Offset
	if progress.SkipScan > readAt {
		readAt = progress.SkipScan
	}
	startAnchor, err := auditAnchor(f, int64(start))
	if err != nil {
		return false, err
	}
	snapshotAnchor, err := auditAnchor(f, int64(snapshot))
	if err != nil {
		return false, err
	}
	if progress.Complete && progress.Offset == snapshot && progress.SkipScan == 0 {
		return true, nil
	}
	readLimit := min(uint64(historyBatchBytes), snapshot-readAt)
	raw := make([]byte, readLimit)
	if readLimit > 0 {
		if n, readErr := f.ReadAt(raw, int64(readAt)); uint64(n) != readLimit || readErr != nil {
			return false, errAuditChanged
		}
	}
	rd := bufio.NewReaderSize(bytes.NewReader(raw), 64<<10)
	pos, recordCount := readAt, 0
	overlong := progress.SkipScan > progress.Offset
	var line []byte
	type pendingRecord struct {
		identity [32]byte
		env      []byte
	}
	var pending []pendingRecord
	var gaps []historyGap
	reportedOverlong := overlong
	for pos < readAt+readLimit && recordCount < historyBatchRecords {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		chunk, readErr := rd.ReadSlice('\n')
		pos += uint64(len(chunk))
		if readErr != nil && !errors.Is(readErr, bufio.ErrBufferFull) && !errors.Is(readErr, io.EOF) {
			return false, readErr
		}
		if len(chunk) == 0 {
			break
		}
		if !overlong && len(line)+len(chunk) <= liveRecordBytes {
			line = append(line, chunk...)
		} else {
			overlong = true
			line = nil
			if !reportedOverlong {
				gaps = append(gaps, historyGap{Source: sourceID, Generation: seg.generation, Offset: progress.Offset, Message: "oversized source record detected; scanning bounded batches for its newline boundary"})
				reportedOverlong = true
			}
		}
		if chunk[len(chunk)-1] != '\n' {
			if overlong {
				progress.SkipScan = pos
			}
			continue
		}
		lineStart := progress.Offset
		progress.Offset, progress.SkipScan = pos, 0
		if overlong {
			gaps = append(gaps, historyGap{Source: sourceID, Generation: seg.generation, Offset: lineStart, Message: "oversized source record omitted at a verified newline boundary"})
			overlong = false
			line = nil
			continue
		}
		recordCount++
		line = line[:len(line)-1] // remove only LF; retain CR byte exactly
		var rec audit.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			gaps = append(gaps, historyGap{Source: sourceID, Generation: seg.generation, Offset: lineStart, Message: "malformed bounded source record omitted: " + err.Error()})
			line = nil
			continue
		}
		if rec.Kind != "phorvex.decision" {
			line = nil
			continue
		}
		identity := sha256.Sum256(append([]byte(sourceID+"\x00"+seg.generation+"\x00"+strconv.FormatUint(lineStart, 10)+"\x00"), line...))
		id := hex.EncodeToString(identity[:16])
		env, err := json.Marshal(storedHistoryRecord{Source: sourceID, ID: id, Record: line})
		if err != nil {
			return false, err
		}
		pending = append(pending, pendingRecord{identity: identity, env: env})
		line = nil
	}
	progress.Complete = progress.Offset == snapshot && progress.SkipScan == 0
	if remote, ok := f.(interface{ Verify() error }); ok {
		if err := remote.Verify(); err != nil {
			return false, err
		}
		progress.Anchor, err = auditAnchor(f, int64(progress.Offset))
	} else {
		batchHash := sha256.Sum256(raw[:pos-readAt])
		progress.Anchor, err = verifyLocalHistoryBatch(source, seg, start, startAnchor, snapshot, snapshotAnchor, readAt, pos-readAt, batchHash, progress.Offset)
	}
	if err != nil {
		return false, err
	}
	err = h.update(func(tx *bolt.Tx) error {
		seen, records, index := tx.Bucket(historySeen), tx.Bucket(historyRecords), tx.Bucket(historyIndex)
		for _, item := range pending {
			if seen.Get(item.identity[:]) != nil {
				continue
			}
			seq, err := records.NextSequence()
			if err != nil {
				return err
			}
			seqKey := make([]byte, 8)
			binary.BigEndian.PutUint64(seqKey, seq)
			if err = records.Put(seqKey, item.env); err != nil {
				return err
			}
			if err = seen.Put(item.identity[:], seqKey); err != nil {
				return err
			}
			if err = index.Put(append(append([]byte(sourceID), 0), seqKey...), nil); err != nil {
				return err
			}
		}
		for _, gap := range gaps {
			if err := putHistoryGap(tx, gap.Source, gap.Generation, gap.Offset, gap.Message); err != nil {
				return err
			}
		}
		raw, err := json.Marshal(progress)
		if err != nil {
			return err
		}
		if err := tx.Bucket(historyOffsets).Put(offsetKey, raw); err != nil {
			return err
		}
		if progress.Complete {
			return tx.Bucket(historyActive).Delete(offsetKey)
		}
		return tx.Bucket(historyActive).Put(offsetKey, raw)
	})
	return progress.Complete, err
}

func auditRangeHash(f auditHandle, offset, length uint64) ([32]byte, error) {
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(f, int64(offset), int64(length)))
	if err == nil && uint64(n) != length {
		err = io.ErrUnexpectedEOF
	}
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out, err
}

func verifyLocalHistoryBatch(source historySource, seg auditSegment, start uint64, startAnchor string, snapshot uint64, snapshotAnchor string, batchStart, batchLength uint64, batchHash [32]byte, newOffset uint64) (string, error) {
	f, err := source.open(seg.path)
	if err != nil {
		return "", errAuditChanged
	}
	defer f.Close()
	generation, err := auditGeneration(f)
	if err != nil || generation != seg.generation {
		return "", errAuditChanged
	}
	a, err := auditAnchor(f, int64(start))
	if err != nil || a != startAnchor {
		return "", errAuditChanged
	}
	a, err = auditAnchor(f, int64(snapshot))
	if err != nil || a != snapshotAnchor {
		return "", errAuditChanged
	}
	currentHash, err := auditRangeHash(f, batchStart, batchLength)
	if err != nil || currentHash != batchHash {
		return "", errAuditChanged
	}
	newAnchor, err := auditAnchor(f, int64(newOffset))
	if err != nil {
		return "", errAuditChanged
	}
	return newAnchor, nil
}

func (h *historyStore) resetProgressAfterRewrite(key []byte, source, generation string, offset uint64, message string) error {
	return h.update(func(tx *bolt.Tx) error {
		if err := putHistoryGap(tx, source, generation, offset, message); err != nil {
			return err
		}
		raw, err := json.Marshal(historyProgress{})
		if err != nil {
			return err
		}
		if err := tx.Bucket(historyOffsets).Put(key, raw); err != nil {
			return err
		}
		return tx.Bucket(historyActive).Put(key, raw)
	})
}

func putHistoryGap(tx *bolt.Tx, source, generation string, offset uint64, message string) error {
	key := sha256.Sum256([]byte(source + "\x00" + generation + "\x00" + strconv.FormatUint(offset, 10) + "\x00" + message))
	if tx.Bucket(historyGaps).Get(key[:]) != nil {
		return nil
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(historyGap{Source: source, Generation: generation, Offset: offset, Message: message, At: at})
	if err != nil {
		return err
	}
	if err := tx.Bucket(historyGaps).Put(key[:], raw); err != nil {
		return err
	}
	var meta historyGapMetaRecord
	if current := tx.Bucket(historyGapMeta).Get([]byte(source)); current != nil {
		if err := json.Unmarshal(current, &meta); err != nil {
			return err
		}
	}
	meta.Count++
	meta.Latest, meta.At = message, at
	raw, err = json.Marshal(meta)
	if err != nil {
		return err
	}
	return tx.Bucket(historyGapMeta).Put([]byte(source), raw)
}

func (h *historyStore) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	q := r.URL.Query()
	limit := 15
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > historyMaxPage {
			writeJSON(w, 400, map[string]string{"error": "limit must be between 1 and 50"})
			return
		}
		limit = n
	}
	actuated := q.Get("actuated")
	if actuated != "" && actuated != "true" && actuated != "false" {
		writeJSON(w, 400, map[string]string{"error": "actuated must be true or false"})
		return
	}
	includeNoop := q.Get("includeNoop") == "true"
	if raw := q.Get("includeNoop"); raw != "" && raw != "true" && raw != "false" {
		writeJSON(w, 400, map[string]string{"error": "includeNoop must be true or false"})
		return
	}
	var from, to time.Time
	for key, dst := range map[string]*time.Time{"from": &from, "to": &to} {
		if raw := q.Get(key); raw != "" {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "invalid " + key + " timestamp"})
				return
			}
			*dst = parsed
		}
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		writeJSON(w, 400, map[string]string{"error": "to precedes from"})
		return
	}
	p := principalOf(r)
	lens, tenant := lensOfRequest(r), strings.TrimSpace(q.Get("tenant"))
	if tenant != "" && !p.AllowsTenant(tenant) {
		writeJSON(w, 403, map[string]string{"error": "tenant " + tenant + " is outside this identity's tenant scope"})
		return
	}
	if lens != string(RoleOwner) && !p.CanRead() {
		writeJSON(w, 403, map[string]string{"error": accessDenialMessage(accessRead)})
		return
	}
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	if len(search) > 512 || len(q.Get("action")) > 128 || len(tenant) > 512 || len(q.Get("context")) > 1024 {
		writeJSON(w, 400, map[string]string{"error": "history filter too long"})
		return
	}
	sourceName := "default"
	if isVClusterContext(q.Get("context")) {
		sourceName = "vcluster"
	}
	sourceID := h.sourceID(sourceName)
	key, _ := json.Marshal([]string{sourceID, q.Get("context"), lens, tenant, q.Get("action"), actuated, search, q.Get("from"), q.Get("to"), strconv.FormatBool(includeNoop)})
	hash := sha256.Sum256(key)
	scope := hex.EncodeToString(hash[:])
	page := historyPage{Events: []historyItem{}, Projection: "summary (decisionTrace omitted); scalar evidence, reasoning and claim provenance retained"}
	status := h.statusFor(sourceName)
	page.Notice = "Durable console history begins with the first source generation observed by this state directory; records deleted before observation are unrecoverable."
	if !status.ready && status.err == "" {
		page.Partial = true
		page.Notice += " Initial import is still running."
	}
	if status.capacityPaused {
		page.Partial = true
		page.Notice += " Durable history import is paused by the capacity guard: " + status.capacityNotice + ". Existing records remain readable and durable source offsets are unchanged. Expand or archive console state, or apply reviewed capacity limits, and import will retry automatically."
	} else if status.err != "" {
		page.Partial = true
		page.Notice += " The requested source is currently unavailable; import is incomplete."
	}
	gapCount, gapErr := h.gapNotice(sourceID)
	if gapErr != nil {
		writeJSON(w, 503, map[string]string{"error": "audit history database unavailable: " + gapErr.Error()})
		return
	}
	if gapCount > 0 {
		page.Partial = true
		page.Notice += fmt.Sprintf(" %d durable import gap notice(s) affect coverage.", gapCount)
	}
	if lens == string(RoleOwner) {
		page.Projection = "owner whitelist"
		if tenant == "" {
			page.Notice += " Select a tenant to read owner history."
			writeJSON(w, 200, page)
			return
		}
	}
	var cursor databaseCursor
	if raw := q.Get("cursor"); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if len(raw) > 2048 || err != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.Version != 3 || cursor.Scope != scope || cursor.Snapshot == 0 || cursor.Before == 0 || cursor.Before > cursor.Snapshot+1 {
			writeJSON(w, 400, map[string]string{"error": "invalid cursor or changed history scope"})
			return
		}
	}
	var next uint64
	err := h.db.View(func(tx *bolt.Tx) error {
		if err := r.Context().Err(); err != nil {
			return err
		}
		bucket, index := tx.Bucket(historyRecords), tx.Bucket(historyIndex)
		if cursor.Snapshot == 0 {
			cursor.Snapshot = bucket.Sequence()
			cursor.Before = cursor.Snapshot + 1
		}
		prefix := append([]byte(sourceID), 0)
		seek := append(bytes.Clone(prefix), make([]byte, 8)...)
		binary.BigEndian.PutUint64(seek[len(prefix):], cursor.Before)
		c := index.Cursor()
		k, _ := c.Seek(seek)
		if k == nil || !bytes.HasPrefix(k, prefix) || binary.BigEndian.Uint64(k[len(prefix):]) >= cursor.Before {
			k, _ = c.Prev()
		}
		for ; k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Prev() {
			if err := r.Context().Err(); err != nil {
				return err
			}
			seq := binary.BigEndian.Uint64(k[len(prefix):])
			if seq > cursor.Snapshot {
				continue
			}
			seqKey := make([]byte, 8)
			binary.BigEndian.PutUint64(seqKey, seq)
			v := bucket.Get(seqKey)
			page.ScannedBytes += int64(len(v))
			if page.ScannedBytes > historyScanBytes {
				page.Partial = true
				page.Notice += " Query scan budget reached; continue older to search further."
				next = seq + 1
				break
			}
			var env storedHistoryRecord
			var rec audit.Record
			if json.Unmarshal(v, &env) != nil || env.Source != sourceID || json.Unmarshal(env.Record, &rec) != nil {
				continue
			}
			if tenant != "" && rec.Tenant != tenant || tenant == "" && !p.TenantWildcard() && !p.AllowsTenant(rec.Tenant) {
				continue
			}
			if q.Get("action") != "" && rec.Action != q.Get("action") || !includeNoop && q.Get("action") == "" && rec.Action == "noop" {
				continue
			}
			if actuated == "true" && !rec.Actuated || actuated == "false" && rec.Actuated {
				continue
			}
			if search != "" {
				fields := rec.Namespace + "/" + rec.Pod + " " + rec.Tenant
				if lens != string(RoleOwner) {
					fields += " " + rec.Action + " " + rec.Reason
				}
				if !strings.Contains(strings.ToLower(fields), search) {
					continue
				}
			}
			if !from.IsZero() && rec.Time.Before(from) || !to.IsZero() && rec.Time.After(to) {
				continue
			}
			if lens == string(RoleOwner) && (!rec.Selected && !rec.Actuated) {
				continue
			}
			var event any = rec
			if lens == string(RoleOwner) {
				event = ToOwnerEvent(rec)
			} else {
				rec.DecisionTrace = nil
				event = rec
			}
			page.Events = append(page.Events, historyItem{ID: env.ID, Event: event})
			if len(page.Events) == limit {
				if pk, _ := c.Prev(); pk != nil && bytes.HasPrefix(pk, prefix) {
					next = seq
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		writeJSON(w, 503, map[string]string{"error": "audit history database unavailable: " + err.Error()})
		return
	}
	if next != 0 {
		cursor.Version, cursor.Scope, cursor.Before = 3, scope, next
		encoded, _ := json.Marshal(cursor)
		page.NextCursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	writeJSON(w, 200, page)
}

func (h *historyStore) gapNotice(source string) (uint64, error) {
	var meta historyGapMetaRecord
	err := h.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(historyGapMeta).Get([]byte(source))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &meta)
	})
	return meta.Count, err
}
