package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
)

const drainAuditLimit int64 = 64 << 20

// Errors expose fixed local stages, never remote response or credential material.
type drainAuditIssue struct {
	Stage string
	Retry bool
}

func (e *drainAuditIssue) Error() string               { return "request-drain audit " + e.Stage }
func drainAuditFailure(stage string, retry bool) error { return &drainAuditIssue{stage, retry} }

type drainAuditCursor struct {
	source               *audittransport.Client
	targetUID, policyUID string
	identity, managerUID string
	segment              audittransport.Segment
	offset, fetched      int64
	pending              []byte
	records              []audit.Record
	originals            [][]byte
	spans                []map[string]any
	out                  string
	sequence             int
}

func (s *Server) newDrainAuditCursor(ctx context.Context, out string, p drainLiveProfile) (*drainAuditCursor, error) {
	if s.cfg.AuditSource == nil || s.cfg.AuditSourceIdentity != p.AuditSourceIdentity {
		return nil, drainAuditFailure("source-identity", false)
	}
	uid := p.ManagerPodUID
	if p.components != nil {
		uid = p.components.Manager.PodUID
	}
	if uid == "" {
		return nil, drainAuditFailure("manager-identity", false)
	}
	manifest, err := s.cfg.AuditSource.Manifest(ctx)
	if err != nil {
		return nil, drainAuditFailure("manifest-unavailable", true)
	}
	segments, err := drainCursorSegments(manifest)
	if err != nil {
		return nil, err
	}
	seg := segments[0]
	c := &drainAuditCursor{source: s.cfg.AuditSource, identity: s.cfg.AuditSourceIdentity, managerUID: uid, targetUID: p.PodUID, policyUID: p.PolicyUID, segment: seg, out: out}
	c.offset = max(int64(0), seg.Size-(16<<20))
	if err = c.consume(ctx, seg, true); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *drainAuditCursor) consume(ctx context.Context, seg audittransport.Segment, leading bool) error {
	if seg.Generation != c.segment.Generation || seg.Anchor != c.segment.Anchor || seg.Size < c.offset {
		return drainAuditFailure("segment-identity", false)
	}
	// Commit each authenticated chunk transactionally. A failed next chunk retains
	// the original generation/offset and all preceding proof; no whole fleet window
	// is buffered or retained as parsed records.
	for c.offset < seg.Size {
		if ctx.Err() != nil {
			return drainAuditFailure("deadline", false)
		}
		start := c.offset
		aligned := (start / audittransport.ChunkBytes) * audittransport.ChunkBytes
		n := min(int64(audittransport.ChunkBytes), seg.Size-aligned)
		if c.fetched+n > drainAuditLimit {
			return drainAuditFailure("byte-limit", false)
		}
		raw, err := c.source.Chunk(ctx, seg, aligned)
		c.fetched += n
		if err != nil {
			return drainAuditFailure("segment-read-unavailable", true)
		}
		data := raw[start-aligned:]
		endOffset := aligned + int64(len(raw))
		combined := append(append([]byte(nil), c.pending...), data...)
		if leading && start > 0 {
			cut := bytes.IndexByte(combined, '\n')
			if cut < 0 {
				return drainAuditFailure("leading-row-unavailable", true)
			}
			combined = combined[cut+1:]
		}
		end := bytes.LastIndexByte(combined, '\n')
		complete := combined[:max(0, end+1)]
		rest := combined[max(0, end+1):]
		if len(rest) > liveRecordBytes {
			return drainAuditFailure("row-size", false)
		}
		rows, originals, err := c.parseRows(ctx, complete)
		if err != nil {
			return err
		}
		c.sequence++
		name := fmt.Sprintf("audit-cursor-%04d-original.jsonl", c.sequence)
		if err = publishMongoAuditFile(c.out, name, data, audittransport.ChunkBytes); err != nil {
			return drainAuditFailure("evidence-persistence", false)
		}
		span := map[string]any{"segment": seg, "start": start, "end": endOffset, "originalSHA256": availabilityHash(data), "file": name, "retainedRows": len(rows), "pendingBytes": len(rest)}
		if err = publishMongoAuditFile(c.out, fmt.Sprintf("audit-cursor-%04d-commitment.json", c.sequence), drainJSON(span), 4096); err != nil {
			return drainAuditFailure("evidence-persistence", false)
		}
		c.spans = append(c.spans, span)
		c.records = append(c.records, rows...)
		c.originals = append(c.originals, originals...)
		c.pending = append([]byte(nil), rest...)
		c.offset = endOffset
		c.segment = seg
		leading = false
	}
	return nil
}

func (c *drainAuditCursor) parseRows(ctx context.Context, b []byte) ([]audit.Record, [][]byte, error) {
	var records []audit.Record
	var originals [][]byte
	for len(b) > 0 {
		if ctx.Err() != nil {
			return nil, nil, drainAuditFailure("deadline", false)
		}
		i := bytes.IndexByte(b, '\n')
		if i <= 0 || i > liveRecordBytes {
			return nil, nil, drainAuditFailure("complete-row-malformed", false)
		}
		var row audit.Record
		if json.Unmarshal(b[:i], &row) != nil || row.Kind == "" || row.Time.IsZero() {
			return nil, nil, drainAuditFailure("complete-row-malformed", false)
		}
		tr := row.DecisionTrace
		if row.Kind == "phorvex.decision" && tr != nil && tr.AssetUID == c.targetUID && tr.PolicyUID == c.policyUID {
			records = append(records, row)
			originals = append(originals, append([]byte(nil), b[:i]...))
		} else if len(c.records) == 0 && len(records) == 0 {
			// A validated source row establishes the pre-event interval. This sentinel
			// cannot supply a decision or effect because it has no trace or native proof.
			records = append(records, audit.Record{Kind: row.Kind, Time: row.Time})
			originals = append(originals, append([]byte(nil), b[:i]...))
		}
		b = b[i+1:]
	}
	return records, originals, nil
}

func (c *drainAuditCursor) update(ctx context.Context) error {
	manifest, err := c.source.Manifest(ctx)
	if err != nil {
		return drainAuditFailure("manifest-unavailable", true)
	}
	segments, err := drainCursorSegments(manifest)
	if err != nil {
		return err
	}
	index := -1
	for i, seg := range segments {
		if seg.Generation == c.segment.Generation && seg.Anchor == c.segment.Anchor {
			index = i
			break
		}
	}
	if index < 0 {
		return drainAuditFailure("generation-no-longer-retained", false)
	}
	seg := segments[index]
	if err = c.consume(ctx, seg, false); err != nil {
		return err
	}
	// The old generation may move from live to backup; consume it before the next generation.
	for index > 0 {
		if len(c.pending) > 0 {
			return drainAuditFailure("rotated-incomplete-row", true)
		}
		index--
		next := segments[index]
		if strings.HasPrefix(next.ID, "vcluster-") {
			return drainAuditFailure("segment-order", false)
		}
		c.segment = next
		c.offset = 0
		if err = c.consume(ctx, next, false); err != nil {
			return err
		}
	}
	return nil
}

// The authenticated server orders live, backup-1, backup-2 (newest first).
// Separate vcluster streams can never become continuation authority.
func drainCursorSegments(m audittransport.Manifest) ([]audittransport.Segment, error) {
	var segments []audittransport.Segment
	seen := map[string]bool{}
	last := 0
	for _, seg := range m.Segments {
		if strings.HasPrefix(seg.ID, "vcluster-") {
			continue
		}
		if len(segments) == 0 {
			if seg.ID != "live" {
				return nil, drainAuditFailure("segment-order", false)
			}
		} else {
			var n int
			if _, err := fmt.Sscanf(seg.ID, "backup-%d", &n); err != nil || n != last+1 || seg.ID != fmt.Sprintf("backup-%d", n) {
				return nil, drainAuditFailure("segment-order", false)
			}
			last = n
		}
		if seen[seg.Generation] || seg.Generation == "" || seg.Anchor == "" {
			return nil, drainAuditFailure("segment-identity", false)
		}
		seen[seg.Generation] = true
		segments = append(segments, seg)
	}
	if len(segments) == 0 {
		return nil, drainAuditFailure("segment-order", false)
	}
	return segments, nil
}

func (c *drainAuditCursor) updateWithRetry(ctx context.Context) error {
	for {
		err := c.update(ctx)
		if !drainAuditRetry(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return drainAuditFailure("deadline", false)
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *drainAuditCursor) window() drainAuditWindow {
	return drainAuditWindow{Records: c.records, Originals: c.originals, Generation: c.segment.Generation, Start: 0, End: c.offset, WindowSHA256: availabilityHash(drainJSON(c.spans))}
}

func (s *Server) drainLaunchCooldown(ctx context.Context, out, phase string, p drainLiveProfile, c *drainAuditCursor) error {
	raw, err := s.drainReadKube(ctx, out, phase+"-cooldown-policy", false, "-n", "vllm", "get", "phorvexpolicy", p.PolicyName, "-o", "json")
	if err != nil {
		return drainAuditFailure("cooldown-policy-unavailable", false)
	}
	var policy struct {
		Metadata struct {
			UID        string `json:"uid"`
			Generation int64  `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Budget struct {
				Window string `json:"antiOverRotationWindow"`
				Tick   string `json:"tickInterval"`
			} `json:"budget"`
		} `json:"spec"`
	}
	if json.Unmarshal(raw, &policy) != nil || policy.Metadata.UID != p.PolicyUID || policy.Metadata.Generation != p.PolicyGeneration {
		return drainAuditFailure("cooldown-policy-identity", false)
	}
	window, e1 := time.ParseDuration(policy.Spec.Budget.Window)
	tick, e2 := time.ParseDuration(policy.Spec.Budget.Tick)
	if e1 != nil || e2 != nil || window <= 0 || tick <= 0 {
		return drainAuditFailure("cooldown-policy-clock", false)
	}
	latest, err := drainCooldownRecord(c.records, p, s.cfg.now(), window, tick)
	if err != nil {
		return err
	}
	fresh := min(30*time.Second, 2*tick+5*time.Second)
	return publishMongoAuditFile(out, phase+"-cooldown-observation.json", drainJSON(map[string]any{"schema": "request-drain-cooldown-observation-v1", "sourceIdentity": c.identity, "managerUID": c.managerUID, "targetUID": p.PodUID, "policyUID": p.PolicyUID, "policyGeneration": p.PolicyGeneration, "traceTime": latest.Time, "traceSHA256": availabilityHash(drainJSON(latest)), "antiOverRotationSeconds": window.Seconds(), "freshnessSeconds": fresh.Seconds(), "cooldownObserved": false}), 4096)
}

func drainCooldownRecord(records []audit.Record, p drainLiveProfile, now time.Time, window, tick time.Duration) (*audit.Record, error) {
	fresh := min(30*time.Second, 2*tick+5*time.Second)
	var latest *audit.Record
	for i := range records {
		row := &records[i]
		tr := row.DecisionTrace
		if tr == nil || tr.AssetUID != p.PodUID || tr.PolicyUID != p.PolicyUID || tr.PolicyName != p.PolicyName || tr.PolicyNamespace != "vllm" || tr.AssetNamespace != "vllm" {
			continue
		}
		if p.components != nil && (tr.BrainImage != p.components.Release.Manager.TemplateImage || tr.GitSHA != p.components.Release.Manager.SourceSHA) {
			continue
		}
		if latest == nil || row.Time.After(latest.Time) {
			latest = row
		}
	}
	if latest == nil || now.Sub(latest.Time) > fresh || latest.Time.After(now.Add(2*time.Second)) {
		return nil, drainAuditFailure("cooldown-current-trace-unavailable", false)
	}
	input := latest.DecisionTrace.Inputs.AntiOverRotateSec
	if math.IsNaN(input) || math.IsInf(input, 0) || input != window.Seconds() {
		return nil, drainAuditFailure("cooldown-window-mismatch", false)
	}
	matches := 0
	for _, status := range latest.DecisionTrace.ActionStatus {
		if status.Action != "request-drain" {
			continue
		}
		matches++
		if strings.HasPrefix(status.Reason, "anti-over-rotation: drainEpoch unchanged for ") {
			return nil, drainAuditFailure("cooldown-active", false)
		}
		if status.ExclusionKind == "action-failure-cooldown" || strings.HasPrefix(status.Reason, "action-failure-cooldown:") {
			return nil, drainAuditFailure("failure-cooldown-active", false)
		}
	}
	if matches != 1 {
		return nil, drainAuditFailure("cooldown-action-status-unavailable", false)
	}
	return latest, nil
}

func drainAuditRetry(err error) bool {
	var issue *drainAuditIssue
	return errors.As(err, &issue) && issue.Retry
}
