package console

// History reads retained JSONL in reverse, with fixed scan/record/page budgets. A
// cursor addresses a file generation and byte boundary, never a timestamp or path.
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
)

const (
	historyScanBytes  = 8 << 20
	liveRecordBytes   = 1 << 20
	historyMaxPage    = 50
	retainedFileLimit = 128
)

type auditSegment struct {
	path       string
	number     int
	generation string
}

type auditHandle interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
	Stat() (os.FileInfo, error)
	Name() string
}
type auditOpener func(string) (auditHandle, error)

var errAuditChanged = errors.New("audit retention changed; refresh latest history")

type historyCursor struct {
	Version        int    `json:"v"`
	Scope          string `json:"scope"`
	Generation     string `json:"generation"`
	Offset         int64  `json:"offset"`
	Anchor         string `json:"anchor"`
	Snapshot       int64  `json:"snapshot"`
	SnapshotAnchor string `json:"snapshotAnchor"`
	Skip           bool   `json:"skip,omitempty"`
}
type historyItem struct {
	ID    string `json:"id"`
	Event any    `json:"event"`
}
type historyPage struct {
	Events       []historyItem `json:"events"`
	NextCursor   string        `json:"nextCursor,omitempty"`
	Partial      bool          `json:"partial"`
	Notice       string        `json:"notice"`
	Projection   string        `json:"projection"`
	ScannedBytes int64         `json:"scannedBytes"`
}

func (s *Server) liveAuditPath(r *http.Request) string {
	p := s.cfg.auditPathForContext(r.URL.Query().Get("context"))
	if p == "" {
		p = s.newestAudit()
	}
	return p
}

func retainedAuditSegments(path string, openFile auditOpener) ([]auditSegment, error) {
	if path == "" {
		return nil, nil
	}
	dir, err := os.Open(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	base := filepath.Base(path)
	var segments []auditSegment
	// Bounded directory batches; unrelated entries are never retained in memory.
	for {
		entries, err := dir.ReadDir(128)
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			n := 0
			if e.Name() != base {
				suffix, ok := strings.CutPrefix(e.Name(), base+".")
				if !ok {
					continue
				}
				var parseErr error
				n, parseErr = strconv.Atoi(suffix)
				if parseErr != nil || n <= 0 || strconv.Itoa(n) != suffix {
					continue
				}
			}
			segments = append(segments, auditSegment{path: filepath.Join(filepath.Dir(path), e.Name()), number: n})
			if len(segments) > retainedFileLimit {
				return nil, fmt.Errorf("retained audit exceeds %d segments", retainedFileLimit)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].number < segments[j].number })
	seen := map[string]bool{}
	for i := range segments {
		f, e := openFile(segments[i].path)
		if e != nil {
			return nil, errAuditChanged
		}
		generation, e := auditGeneration(f)
		f.Close()
		if e != nil {
			return nil, e
		}
		if seen[generation] {
			return nil, errAuditChanged
		}
		seen[generation] = true
		segments[i].generation = generation
	}
	return segments, nil
}

func validateAuditSegments(segments []auditSegment, openFile auditOpener) bool {
	for _, seg := range segments {
		f, e := openFile(seg.path)
		if e != nil {
			return false
		}
		generation, e := auditGeneration(f)
		if remote, ok := f.(interface{ Verify() error }); ok && e == nil {
			e = remote.Verify()
		}
		f.Close()
		if e != nil || generation != seg.generation {
			return false
		}
	}
	return true
}

func auditGeneration(f auditHandle) (string, error) {
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("audit is not a regular file")
	}
	if remote, ok := f.(interface{ Generation() string }); ok {
		return remote.Generation(), nil
	}
	// File identity survives rename to a retained numeric segment (Linux/macOS).
	id, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("audit file identity unavailable")
	}
	return fmt.Sprintf("%x-%x", id.Dev, id.Ino), nil
}

func openAuditFile(path string) (auditHandle, error) {
	// Never block on a FIFO or follow a substituted symlink while inspecting
	// retained segments. O_NONBLOCK is inert for the regular files we accept.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("audit is not a readable regular file")
	}
	return f, nil
}

func auditAnchor(f auditHandle, offset int64) (string, error) {
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if offset < 0 || offset > st.Size() {
		return "", errors.New("audit boundary no longer retained")
	}
	n := min(offset, int64(256))
	b := make([]byte, n)
	if n > 0 {
		if _, err := f.ReadAt(b, offset-n); err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16]), nil
}

func encodeHistoryCursor(c historyCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// reverseAuditReader never holds more than one bounded record plus a 64KiB block.
// pos is an exclusive byte boundary. skip discards an incomplete/oversized suffix.
type reverseAuditReader struct {
	f          auditHandle
	pos, read  int64
	skip       bool
	block      []byte
	blockStart int64
}

func (s *reverseAuditReader) byteBefore() (byte, error) {
	if s.pos <= 0 {
		return 0, io.EOF
	}
	if s.block == nil || s.pos-1 < s.blockStart || s.pos-1 >= s.blockStart+int64(len(s.block)) {
		start := max(int64(0), s.pos-65536)
		s.block = make([]byte, s.pos-start)
		if _, err := s.f.ReadAt(s.block, start); err != nil {
			return 0, err
		}
		s.blockStart = start
	}
	s.pos--
	s.read++
	return s.block[s.pos-s.blockStart], nil
}
func (s *reverseAuditReader) next(budget int64) (line []byte, start int64, oversized bool, err error) {
	var reversed []byte
	for s.pos > 0 {
		// Blank lines and a discarded suffix must not bypass the scan budget.
		if s.read >= budget && len(reversed) == 0 {
			return nil, s.pos, oversized, nil
		}
		b, e := s.byteBefore()
		if e != nil {
			return nil, 0, false, e
		}
		if b == '\n' {
			if s.skip {
				s.skip = false
				reversed = nil
				continue
			}
			if len(reversed) == 0 {
				continue
			}
			start = s.pos + 1
			for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
				reversed[i], reversed[j] = reversed[j], reversed[i]
			}
			return reversed, start, oversized, nil
		}
		if !s.skip {
			if len(reversed) >= liveRecordBytes {
				s.skip = true
				reversed = nil
				oversized = true
			} else {
				reversed = append(reversed, b)
			}
		}
		// Once the budget is reached, complete at most one normal-size record;
		// an oversized suffix instead carries its discard state into the cursor.
		if s.read >= budget && s.skip {
			return nil, s.pos, oversized, nil
		}
	}
	if s.skip {
		s.skip = false
		return nil, 0, oversized, nil
	}
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed, 0, oversized, nil
}

func (s *Server) liveHistory(w http.ResponseWriter, r *http.Request) {
	s.liveHistoryWithOpener(w, r, openAuditFile)
}

func (s *Server) liveHistoryWithOpener(w http.ResponseWriter, r *http.Request, openFile auditOpener) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "GET only"})
		return
	}
	q := r.URL.Query()
	limit := 15
	if raw := q.Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > historyMaxPage {
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
	var from, to time.Time
	for key, dst := range map[string]*time.Time{"from": &from, "to": &to} {
		if raw := q.Get(key); raw != "" {
			v, e := time.Parse(time.RFC3339Nano, raw)
			if e != nil {
				writeJSON(w, 400, map[string]string{"error": "invalid " + key + " timestamp"})
				return
			}
			*dst = v
		}
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		writeJSON(w, 400, map[string]string{"error": "to precedes from"})
		return
	}
	// [M-136] Projection and tenant scope come from the verified grant, narrowed by any lens the
	// request asked for — never from the X-Phorvex-Lens header or a self-asserted ?tenant=.
	p := principalOf(r)
	lens, tenant, path := lensOfRequest(r), strings.TrimSpace(q.Get("tenant")), s.liveAuditPath(r)
	if tenant != "" && !p.AllowsTenant(tenant) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "tenant " + tenant + " is outside this identity's tenant scope"})
		return
	}
	if lens != string(RoleOwner) && !p.CanRead() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": accessDenialMessage(accessRead)})
		return
	}
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	if len(search) > 512 || len(q.Get("action")) > 128 || len(tenant) > 512 || len(q.Get("context")) > 1024 {
		writeJSON(w, 400, map[string]string{"error": "history filter too long"})
		return
	}
	key, _ := json.Marshal([]string{path, q.Get("context"), lens, tenant, q.Get("action"), actuated, search, q.Get("from"), q.Get("to")})
	sum := sha256.Sum256(key)
	scope := hex.EncodeToString(sum[:])
	var cursor historyCursor
	if raw := q.Get("cursor"); raw != "" {
		if len(raw) > 2048 {
			writeJSON(w, 400, map[string]string{"error": "history cursor too long"})
			return
		}
		b, e := base64.RawURLEncoding.DecodeString(raw)
		if e != nil || json.Unmarshal(b, &cursor) != nil || cursor.Version != 1 || cursor.Scope != scope || cursor.Generation == "" || cursor.Offset < 0 || cursor.Snapshot < cursor.Offset || cursor.SnapshotAnchor == "" {
			writeJSON(w, 400, map[string]string{"error": "invalid cursor or changed history scope"})
			return
		}
	}
	page := historyPage{Events: []historyItem{}, Notice: "Only retained audit files are searchable; older deleted records are unavailable.", Projection: "summary (decisionTrace omitted); scalar evidence, reasoning and claim provenance retained"}
	if lens == "owner" {
		page.Projection = "owner whitelist"
		if tenant == "" {
			page.Notice = "Select a tenant to read owner history."
			writeJSON(w, 200, page)
			return
		}
	}
	var segments []auditSegment
	var err error
	if s.cfg.AuditSource != nil {
		manifest, sourceErr := s.cfg.AuditSource.Manifest(r.Context())
		if sourceErr != nil {
			writeJSON(w, 503, map[string]string{"error": "audit source unavailable: " + sourceErr.Error()})
			return
		}
		pinned := map[string]audittransport.Segment{}
		prefix := ""
		if path == "audit://vcluster-live" {
			prefix = "vcluster-"
		}
		for _, remote := range manifest.Segments {
			if remote.ID != prefix+"live" && !strings.HasPrefix(remote.ID, prefix+"backup-") {
				continue
			}
			number := 0
			if remote.ID != prefix+"live" {
				number, _ = strconv.Atoi(strings.TrimPrefix(remote.ID, prefix+"backup-"))
			}
			logical := "audit://" + remote.ID
			pinned[logical] = remote
			segments = append(segments, auditSegment{path: logical, number: number, generation: remote.Generation})
		}
		if len(segments) == 0 {
			writeJSON(w, 503, map[string]string{"error": "configured provider audit source unavailable"})
			return
		}
		sort.Slice(segments, func(i, j int) bool { return segments[i].number < segments[j].number })
		openFile = func(path string) (auditHandle, error) {
			seg, ok := pinned[path]
			if !ok {
				return nil, errAuditChanged
			}
			return s.cfg.AuditSource.Open(r.Context(), seg), nil
		}
	} else {
		segments, err = retainedAuditSegments(path, openFile)
	}
	if err != nil {
		if errors.Is(err, errAuditChanged) {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 503, map[string]string{"error": "audit history unavailable: " + err.Error()})
		return
	}
	found := cursor.Generation == ""
	for _, seg := range segments {
		if r.Context().Err() != nil {
			return
		}
		f, e := openFile(seg.path)
		if e != nil {
			writeJSON(w, 409, map[string]string{"error": "audit retention changed; refresh latest history"})
			return
		}
		generation, e := auditGeneration(f)
		if e != nil {
			f.Close()
			writeJSON(w, 503, map[string]string{"error": e.Error()})
			return
		}
		if generation != seg.generation {
			f.Close()
			writeJSON(w, 409, map[string]string{"error": errAuditChanged.Error()})
			return
		}
		if !found {
			if generation != cursor.Generation {
				f.Close()
				continue
			}
			found = true
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			writeJSON(w, 503, map[string]string{"error": "audit stat failed"})
			return
		}
		end := st.Size()
		snapshot := end
		skip := false
		if cursor.Generation != "" {
			end = cursor.Offset
			snapshot = cursor.Snapshot
			snapshotAnchor, e := auditAnchor(f, snapshot)
			if e != nil || snapshotAnchor != cursor.SnapshotAnchor {
				f.Close()
				writeJSON(w, 409, map[string]string{"error": "history snapshot expired after audit truncation; refresh latest"})
				return
			}
			anchor, e := auditAnchor(f, end)
			if e != nil || anchor != cursor.Anchor {
				f.Close()
				writeJSON(w, 409, map[string]string{"error": "history cursor expired after audit truncation; refresh latest"})
				return
			}
			skip = cursor.Skip
			cursor.Generation = ""
		} else if end > 0 {
			b := []byte{0}
			if _, e = f.ReadAt(b, end-1); e != nil {
				f.Close()
				writeJSON(w, 503, map[string]string{"error": "audit read failed"})
				return
			}
			skip = b[0] != '\n'
		}
		snapshotAnchor, e := auditAnchor(f, snapshot)
		if e != nil {
			f.Close()
			writeJSON(w, 409, map[string]string{"error": "audit changed while reading; refresh latest"})
			return
		}
		rd := reverseAuditReader{f: f, pos: end, skip: skip}
		for rd.pos > 0 && len(page.Events) < limit && page.ScannedBytes+rd.read < historyScanBytes {
			line, start, large, e := rd.next(historyScanBytes - page.ScannedBytes)
			if e != nil {
				f.Close()
				writeJSON(w, 409, map[string]string{"error": "audit changed while reading; refresh latest"})
				return
			}
			if large {
				page.Partial = true
				page.Notice += " A record exceeds the 1 MiB read limit and was omitted."
			}
			if len(line) == 0 {
				continue
			}
			var rec audit.Record
			if json.Unmarshal(bytes.TrimSpace(line), &rec) != nil {
				page.Partial = true
				continue
			}
			if rec.Kind != "phorvex.decision" {
				continue
			}
			if lens == "owner" && (rec.Tenant != tenant || (!rec.Selected && !rec.Actuated)) {
				continue
			}
			// [M-136] The cross-tenant control applies to EVERY lens: an explicit ?tenant= pins
			// the page to that tenant, and with none named a scoped grant still sees only the
			// tenants it holds. Counts and notices derive from these same filtered records.
			if tenant != "" {
				if rec.Tenant != tenant {
					continue
				}
			} else if !p.TenantWildcard() && !p.AllowsTenant(rec.Tenant) {
				continue
			}
			if q.Get("action") != "" && rec.Action != q.Get("action") {
				continue
			}
			if (actuated == "true" && !rec.Actuated) || (actuated == "false" && rec.Actuated) {
				continue
			}
			if search != "" && !strings.Contains(strings.ToLower(rec.Namespace+"/"+rec.Pod+" "+rec.Tenant), search) {
				continue
			}
			if !from.IsZero() && rec.Time.Before(from) || !to.IsZero() && rec.Time.After(to) {
				continue
			}
			var event any
			if lens == "owner" {
				event = ToOwnerEvent(rec)
			} else {
				rec.DecisionTrace = nil
				event = rec
			}
			identityBytes := line
			if lens == "owner" {
				identityBytes, _ = json.Marshal(event)
			}
			recordSum := sha256.Sum256(identityBytes)
			page.Events = append(page.Events, historyItem{ID: generation + ":" + strconv.FormatInt(start, 10) + ":" + hex.EncodeToString(recordSum[:8]), Event: event})
		}
		page.ScannedBytes += rd.read
		if current, e := auditAnchor(f, snapshot); e != nil || current != snapshotAnchor {
			f.Close()
			writeJSON(w, 409, map[string]string{"error": "audit changed while reading; refresh latest"})
			return
		}
		if rd.pos > 0 || len(page.Events) >= limit || page.ScannedBytes >= historyScanBytes {
			anchor, e := auditAnchor(f, rd.pos)
			f.Close()
			if e != nil {
				writeJSON(w, 409, map[string]string{"error": "audit changed while reading; refresh latest"})
				return
			}
			page.NextCursor = encodeHistoryCursor(historyCursor{Version: 1, Scope: scope, Generation: generation, Offset: rd.pos, Anchor: anchor, Snapshot: snapshot, SnapshotAnchor: snapshotAnchor, Skip: rd.skip})
			if page.ScannedBytes >= historyScanBytes {
				page.Partial = true
				page.Notice += " Scan budget reached; continue older to search further."
			}
			if page.Partial {
				page.Notice += " Malformed or oversized records may be omitted."
			}
			if !validateAuditSegments(segments, openFile) {
				writeJSON(w, 409, map[string]string{"error": errAuditChanged.Error()})
				return
			}
			writeJSON(w, 200, page)
			return
		}
		f.Close()
	}
	if !found {
		writeJSON(w, 409, map[string]string{"error": "history cursor expired from retention; refresh latest"})
		return
	}
	if page.Partial {
		page.Notice += " Malformed or oversized records were omitted."
	}
	if !validateAuditSegments(segments, openFile) {
		writeJSON(w, 409, map[string]string{"error": errAuditChanged.Error()})
		return
	}
	writeJSON(w, 200, page)
}
