package installedauditobserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
)

type Source interface {
	Manifest(context.Context) (audittransport.Manifest, error)
	Chunk(context.Context, audittransport.Segment, int64) ([]byte, error)
	ParameterMaterial(context.Context, string, string) ([]byte, error)
}

func CaptureCursor(ctx context.Context, source Source) (Cursor, error) {
	m, err := source.Manifest(ctx)
	if err != nil {
		return Cursor{}, err
	}
	var live *audittransport.Segment
	for i := range m.Segments {
		if m.Segments[i].ID == "live" {
			live = &m.Segments[i]
			break
		}
	}
	if live == nil {
		return Cursor{}, errors.New("live audit segment is missing")
	}
	if !anchorPattern.MatchString(live.Anchor) || len(live.Generation) > 128 {
		return Cursor{}, errors.New("live audit segment identity is invalid")
	}
	if live.Size > 0 {
		last, err := source.Chunk(ctx, *live, live.Size-1)
		if err != nil {
			return Cursor{}, fmt.Errorf("pin live boundary: %w", err)
		}
		if len(last) != 1 || last[0] != '\n' {
			return Cursor{}, errors.New("live audit cursor is inside a partial record")
		}
	}
	return Cursor{SchemaVersion: CursorSchema, CapturedAt: time.Unix(0, m.FetchedAt).UTC(), Segment: *live, Offset: live.Size}, nil
}

type segmentRange struct {
	segment audittransport.Segment
	start   int64
}

func orderedRanges(m audittransport.Manifest, cursor Cursor) ([]segmentRange, error) {
	if cursor.SchemaVersion != CursorSchema || cursor.Offset < 0 || cursor.Offset != cursor.Segment.Size || cursor.Segment.Generation == "" || cursor.Segment.Anchor == "" {
		return nil, errors.New("invalid installed audit cursor")
	}
	if cursor.CapturedAt.IsZero() || cursor.Segment.ID != "live" || len(cursor.Segment.Generation) > 128 || !anchorPattern.MatchString(cursor.Segment.Anchor) ||
		(cursor.Segment.Size == 0 && cursor.Segment.Anchor != "e3b0c44298fc1c149afbf4c8996fb924") {
		return nil, errors.New("invalid installed audit cursor identity")
	}
	plain := make([]audittransport.Segment, 0, len(m.Segments))
	for _, s := range m.Segments {
		if !strings.HasPrefix(s.ID, "vcluster-") {
			plain = append(plain, s)
		}
	}
	if len(plain) == 0 || plain[0].ID != "live" {
		return nil, errors.New("live audit segment is missing")
	}
	seenGeneration := map[string]bool{}
	for _, s := range plain {
		if len(s.Generation) > 128 || !anchorPattern.MatchString(s.Anchor) {
			return nil, errors.New("audit manifest segment identity is invalid")
		}
		if seenGeneration[s.Generation] {
			return nil, errors.New("audit manifest repeats a generation")
		}
		seenGeneration[s.Generation] = true
	}
	start := -1
	for i, s := range plain {
		if s.Generation == cursor.Segment.Generation {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, errors.New("cursor generation is no longer retained")
	}
	for i, s := range plain {
		want := "live"
		if i > 0 {
			want = "backup-" + strconv.Itoa(i)
		}
		if s.ID != want {
			return nil, errors.New("audit segment history is not contiguous")
		}
	}
	if plain[start].Size < cursor.Offset {
		return nil, errors.New("cursor generation was truncated")
	}
	ranges := []segmentRange{{segment: plain[start], start: cursor.Offset}}
	for i := start - 1; i >= 0; i-- {
		ranges = append(ranges, segmentRange{segment: plain[i]})
	}
	return ranges, nil
}

type span struct {
	start, end int
	source     SourceRange
}

type lineBuffer struct {
	data  []byte
	spans []span
}

func (b *lineBuffer) append(chunk []byte, source SourceRange) {
	start := len(b.data)
	b.data = append(b.data, chunk...)
	b.spans = append(b.spans, span{start: start, end: len(b.data), source: source})
}

func (b *lineBuffer) pop() ([]byte, []SourceRange, bool) {
	end := bytes.IndexByte(b.data, '\n')
	if end < 0 {
		return nil, nil, false
	}
	line := b.data[:end]
	ranges := make([]SourceRange, 0, 2)
	for _, sp := range b.spans {
		lo, hi := max(0, sp.start), min(end, sp.end)
		if lo >= hi {
			continue
		}
		rg := sp.source
		rg.Start += int64(lo - sp.start)
		rg.End = rg.Start + int64(hi-lo)
		sum := sha256.Sum256(b.data[lo:hi])
		rg.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
		ranges = append(ranges, rg)
	}
	consumed := end + 1
	remaining := b.spans[:0]
	for _, sp := range b.spans {
		if sp.end <= consumed {
			continue
		}
		if sp.start < consumed {
			sp.source.Start += int64(consumed - sp.start)
			sp.start = 0
		} else {
			sp.start -= consumed
		}
		sp.end -= consumed
		remaining = append(remaining, sp)
	}
	b.spans = remaining
	b.data = b.data[consumed:]
	return line, ranges, true
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "budget"), strings.Contains(s, "oversized"):
		return "bound-exceeded"
	case strings.Contains(s, "generation"), strings.Contains(s, "segment"), strings.Contains(s, "cursor"):
		return "source-continuity"
	case strings.Contains(s, "parameter"):
		return "parameter-epoch"
	case strings.Contains(s, "identity"), strings.Contains(s, "UID"), strings.Contains(s, "source"):
		return "identity"
	case strings.Contains(s, "duplicate"), strings.Contains(s, "ambiguous"), strings.Contains(s, "contradict"):
		return "ambiguous-record"
	default:
		return "invalid-record"
	}
}

func verifyMaterials(ctx context.Context, source Source, receipt Receipt) error {
	p := receipt.ParameterEpoch
	manifestRaw, err := source.ParameterMaterial(ctx, audit.ParameterMaterialManifest, p.ManifestHash)
	if err != nil {
		return fmt.Errorf("read parameter manifest: %w", err)
	}
	overridesRaw, err := source.ParameterMaterial(ctx, audit.ParameterMaterialPolicyOverrides, p.PolicyOverridesHash)
	if err != nil {
		return fmt.Errorf("read policy overrides: %w", err)
	}
	if err := rejectDuplicateFields(manifestRaw); err != nil {
		return fmt.Errorf("ambiguous parameter manifest: %w", err)
	}
	if err := rejectDuplicateFields(overridesRaw); err != nil {
		return fmt.Errorf("ambiguous policy overrides: %w", err)
	}
	var manifest model.DecisionParameterManifest
	var overrides model.EffectivePolicyOverrides
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return fmt.Errorf("decode parameter manifest: %w", err)
	}
	if err := json.Unmarshal(overridesRaw, &overrides); err != nil {
		return fmt.Errorf("decode policy overrides: %w", err)
	}
	ref := model.ParameterSetReference{SchemaVersion: p.SchemaVersion, ManifestID: p.ManifestID, ManifestHash: p.ManifestHash,
		PolicyOverridesID: p.PolicyOverridesID, PolicyOverridesHash: p.PolicyOverridesHash}
	if err := model.VerifyParameterSet(&ref, &manifest, &overrides); err != nil {
		return fmt.Errorf("verify parameter epoch: %w", err)
	}
	return nil
}

// Collect reads one exact post-cursor range. It returns receipts accumulated
// before an error so callers can persist partial evidence with an invalid summary.
func Collect(ctx context.Context, source Source, cursor Cursor, cfg Config, now func() time.Time) (receipts []Receipt, summary Summary, retErr error) {
	started := now().UTC()
	summary = Summary{SchemaVersion: SummarySchema, Status: "invalid", Attribution: "unavailable", StartedAt: started, NotBefore: cfg.NotBefore, NotAfter: cfg.NotAfter}
	defer func() {
		summary.CompletedAt = now().UTC()
		summary.Receipts = len(receipts)
		if retErr != nil {
			summary.ErrorClass = classifyError(retErr)
		}
	}()
	if err := cfg.normalize(); err != nil {
		return nil, summary, err
	}
	if cursor.CapturedAt.After(cfg.NotBefore) {
		return nil, summary, errors.New("cursor was captured after the observation window began")
	}
	m, err := source.Manifest(ctx)
	if err != nil {
		return nil, summary, err
	}
	if time.Unix(0, m.FetchedAt).Before(cfg.NotAfter) {
		return nil, summary, errors.New("observation window has not completed")
	}
	ranges, err := orderedRanges(m, cursor)
	if err != nil {
		return nil, summary, err
	}
	// Re-validate the original anchor at its original size after a rotation.
	if cursor.Offset > 0 {
		pin := cursor.Segment
		pin.ID = ranges[0].segment.ID
		if _, err := source.Chunk(ctx, pin, cursor.Offset-1); err != nil {
			return nil, summary, fmt.Errorf("cursor anchor verification: %w", err)
		}
	}
	seen := map[string]string{}
	var verifiedEpoch *ParameterEpoch
	processLine := func(line []byte, lineRanges []SourceRange) error {
		if len(bytes.TrimSpace(line)) != 0 {
			summary.RowsRead++
			if summary.RowsRead > cfg.MaxRows {
				return errors.New("audit row budget exceeded")
			}
			receipt, matched, err := project(line, lineRanges, cfg)
			if err != nil {
				return err
			}
			if matched {
				if verifiedEpoch != nil && receipt.ParameterEpoch != *verifiedEpoch {
					return errors.New("matching decisions span multiple parameter epochs")
				}
				if old, ok := seen[receipt.DecisionID]; ok {
					if old != receipt.RawSHA256 {
						return errors.New("decision ID was reused with conflicting bytes")
					}
				} else {
					if verifiedEpoch == nil {
						if err := verifyMaterials(ctx, source, receipt); err != nil {
							return err
						}
						epoch := receipt.ParameterEpoch
						verifiedEpoch = &epoch
					}
					seen[receipt.DecisionID] = receipt.RawSHA256
					receipts = append(receipts, receipt)
				}
			}
		}
		return nil
	}
	var pending lineBuffer
	for _, r := range ranges {
		if r.segment.Size-r.start > cfg.MaxBytes-summary.BytesRead {
			return receipts, summary, errors.New("audit byte budget exceeded")
		}
		for off := r.start; off < r.segment.Size; {
			chunk, err := source.Chunk(ctx, r.segment, off)
			if err != nil {
				return receipts, summary, err
			}
			if len(chunk) == 0 || len(chunk) > audittransport.ChunkBytes || int64(len(chunk)) > r.segment.Size-off {
				return receipts, summary, errors.New("audit source returned an invalid chunk")
			}
			sourceRange := SourceRange{SegmentID: r.segment.ID, Generation: r.segment.Generation, Anchor: r.segment.Anchor, PinnedSize: r.segment.Size, Start: off, End: off + int64(len(chunk))}
			pending.append(chunk, sourceRange)
			off += int64(len(chunk))
			summary.BytesRead += int64(len(chunk))
			for {
				line, lineRanges, ok := pending.pop()
				if !ok {
					break
				}
				if err := processLine(line, lineRanges); err != nil {
					return receipts, summary, err
				}
			}
			if int64(len(pending.data)) > MaxRecordBytes {
				return receipts, summary, errors.New("audit row is oversized")
			}
		}
	}
	if len(pending.data) > 0 {
		return receipts, summary, errors.New("pinned audit range ends with a partial record")
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].DecisionTime.Equal(receipts[j].DecisionTime) {
			return receipts[i].DecisionID < receipts[j].DecisionID
		}
		return receipts[i].DecisionTime.Before(receipts[j].DecisionTime)
	})
	summary.Status = "complete"
	if len(receipts) > 0 {
		summary.Attribution = "observed"
	}
	return receipts, summary, nil
}
