package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
)

type availabilityAuditStart struct {
	Schema          string                 `json:"schema"`
	SourceIdentity  string                 `json:"sourceIdentity"`
	ManifestSHA256  string                 `json:"manifestSHA256"`
	Segment         audittransport.Segment `json:"segment"`
	CheckpointSize  int64                  `json:"checkpointSize"`
	AlignedOffset   int64                  `json:"alignedOffset"`
	PriorTailSHA256 string                 `json:"priorTailSHA256"`
	ObservedAt      string                 `json:"observedAt"`
}
type availabilityAuditChunk struct {
	SegmentID  string `json:"segmentID"`
	Generation string `json:"generation"`
	Offset     int64  `json:"offset"`
	Bytes      int    `json:"bytes"`
	SHA256     string `json:"sha256"`
}
type availabilityDecision struct {
	Time                    string  `json:"time"`
	PolicyUID               string  `json:"policyUID"`
	AssetUID                string  `json:"assetUID"`
	DecisionID              string  `json:"decisionID"`
	TickID                  string  `json:"tickID"`
	Action                  string  `json:"action"`
	Selected                bool    `json:"selected"`
	Actuated                bool    `json:"actuated"`
	DispatchOutcome         string  `json:"dispatchOutcome"`
	TopLevelDispatchOutcome string  `json:"topLevelDispatchOutcome"`
	Handler                 string  `json:"handler,omitempty"`
	MutationKind            string  `json:"mutationKind,omitempty"`
	GracefulTermination     bool    `json:"gracefulTermination"`
	EventCoverage           string  `json:"eventCoverage"`
	ExactEventUID           string  `json:"exactEventUID,omitempty"`
	ExactEventName          string  `json:"exactEventName,omitempty"`
	ExactEventCreator       string  `json:"exactEventCreator,omitempty"`
	ExactEventTargetPodUID  string  `json:"exactEventTargetPodUID,omitempty"`
	EventWeight             float64 `json:"eventWeight,omitempty"`
	EventEvidence           float64 `json:"eventEvidence,omitempty"`
	OtherTrustedEventCount  int     `json:"otherTrustedEventCount"`
}
type availabilityAuditTerminal struct {
	Schema                  string                   `json:"schema"`
	Status                  string                   `json:"status"`
	Gap                     string                   `json:"gap,omitempty"`
	CoverageComplete        bool                     `json:"coverageComplete"`
	SourceIdentity          string                   `json:"sourceIdentity"`
	StartSHA256             string                   `json:"startSHA256"`
	EndManifestSHA256       string                   `json:"endManifestSHA256"`
	TerminalManifestSHA256  string                   `json:"terminalManifestSHA256"`
	FrozenBytes             int64                    `json:"frozenBytes"`
	BytesRead               int64                    `json:"bytesRead"`
	DataGETs                int                      `json:"dataGETs"`
	ControlGETs             int                      `json:"controlGETs"`
	AuditReadElapsedSeconds float64                  `json:"auditReadElapsedSeconds"`
	PayloadBytes            int64                    `json:"payloadBytes"`
	RawAuditRetained        bool                     `json:"rawAuditRetained"`
	CloseStartedLate        bool                     `json:"closeStartedLate"`
	UnboundTargetRows       *int                     `json:"unboundTargetRows"`
	TargetRows              []availabilityDecision   `json:"targetRows"`
	ChunkReceipts           []availabilityAuditChunk `json:"chunkReceipts"`
}

func availabilityOperationID(tick, policyUID, namespace, targetUID string) string {
	h := sha256.New()
	for _, v := range []string{"phorvex-serving-operation-v1", tick, policyUID, namespace, targetUID, "guardrail-rotate"} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(v))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func availabilityEpoch(op string) string {
	h := sha256.Sum256([]byte("phorvex-serving-epoch-v1\x00apply\x00" + op))
	return hex.EncodeToString(h[:20])
}

func (w *availabilityWorker) auditStart() (availabilityAuditStart, error) {
	var out availabilityAuditStart
	if w.rm.cfg.AuditSource == nil {
		return out, errors.New("authenticated audit source unavailable")
	}
	c, stop := context.WithTimeout(w.ctx, 15*time.Second)
	defer stop()
	m, e := w.rm.cfg.AuditSource.Manifest(c)
	if e != nil {
		return out, errors.New("authenticated audit checkpoint unavailable")
	}
	manifestRaw, _ := json.Marshal(m)
	if e = w.save("audit-start-manifest.json", manifestRaw); e != nil {
		return out, e
	}
	seg := m.Segments[0]
	if seg.ID != "live" {
		return out, errors.New("audit live segment absent")
	}
	tailStart := max(int64(0), seg.Size-audittransport.ChunkBytes)
	var tail []byte
	if seg.Size > tailStart {
		tail, e = w.rm.cfg.AuditSource.Chunk(c, seg, tailStart)
		if e != nil {
			return out, errors.New("audit checkpoint tail unavailable")
		}
	}
	align := seg.Size
	if len(tail) > 0 && tail[len(tail)-1] != '\n' {
		if i := bytes.LastIndexByte(tail, '\n'); i >= 0 {
			align = tailStart + int64(i) + 1
		} else if tailStart == 0 {
			align = 0
		} else {
			return out, errors.New("audit prior line exceeds bound")
		}
	}
	out = availabilityAuditStart{"guardrail-availability-audit-start-v1", w.rm.cfg.AuditSourceIdentity, availabilityHash(manifestRaw), seg, seg.Size, align, availabilityHash(tail), time.Now().UTC().Format(time.RFC3339Nano)}
	return out, w.saveJSON("audit-start.json", out)
}

func availabilitySpans(start availabilityAuditStart, m audittransport.Manifest) ([][3]any, error) {
	byID := map[string]audittransport.Segment{}
	var first audittransport.Segment
	matches := 0
	for _, s := range m.Segments {
		byID[s.ID] = s
		if s.Generation == start.Segment.Generation && s.Anchor == start.Segment.Anchor {
			first = s
			matches++
		}
	}
	if matches != 1 || first.Size < start.CheckpointSize {
		return nil, errors.New("audit start generation missing or changed")
	}
	spans := [][3]any{{first, start.AlignedOffset, first.Size}}
	if first.ID != "live" {
		if !strings.HasPrefix(first.ID, "backup-") {
			return nil, errors.New("audit backup identity invalid")
		}
		n, e := strconv.Atoi(strings.TrimPrefix(first.ID, "backup-"))
		if e != nil || n < 1 || n > audittransport.MaxSegments {
			return nil, errors.New("audit backup number invalid")
		}
		for i := n - 1; i > 0; i-- {
			s, ok := byID[fmt.Sprintf("backup-%d", i)]
			if !ok {
				return nil, errors.New("audit intermediate generation missing")
			}
			spans = append(spans, [3]any{s, int64(0), s.Size})
		}
		live, ok := byID["live"]
		if !ok {
			return nil, errors.New("audit terminal live missing")
		}
		spans = append(spans, [3]any{live, int64(0), live.Size})
	}
	seen := map[string]bool{}
	for _, span := range spans {
		s := span[0].(audittransport.Segment)
		if seen[s.Generation] {
			return nil, errors.New("audit generation duplicated")
		}
		seen[s.Generation] = true
	}
	return spans, nil
}

func availabilityProjectAudit(raw []byte, before availabilitySnapshot, targetName string, event *availabilityEvent) ([]availabilityDecision, int, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, 0, errors.New("audit terminal line incomplete")
	}
	var rows []availabilityDecision
	unbound := 0
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		if len(line) == 0 || len(line) > 1<<20 {
			return nil, unbound, errors.New("audit row size invalid")
		}
		var head map[string]json.RawMessage
		if e := availabilityDecode(line, &head); e != nil {
			return nil, unbound, e
		}
		var rec audit.Record
		if e := availabilityDecode(line, &rec); e != nil {
			return nil, unbound, e
		}
		if rec.Kind != "phorvex.decision" {
			continue
		}
		targetRelated := rec.Namespace == "vllm" && rec.Pod == targetName
		if rec.DecisionTrace != nil && rec.DecisionTrace.AssetUID == before.TargetPodUID {
			targetRelated = true
		}
		if !targetRelated {
			continue
		}
		if rec.Namespace != "vllm" || rec.Pod != targetName || rec.DecisionTrace == nil || rec.DecisionTrace.AssetUID != before.TargetPodUID || rec.DecisionTrace.PolicyUID != before.PolicyUID || rec.DecisionTrace.AssetNamespace != "vllm" || rec.DecisionTrace.AssetName != rec.Pod {
			unbound++
			continue
		}
		if selected := string(head["selected"]); selected != "true" && selected != "false" {
			unbound++
			continue
		}
		if actuated := string(head["actuated"]); actuated != "true" && actuated != "false" {
			unbound++
			continue
		}
		var traceHead map[string]json.RawMessage
		if availabilityDecode(head["decisionTrace"], &traceHead) != nil {
			unbound++
			continue
		}
		if dispatch := traceHead["dispatchOutcome"]; len(dispatch) == 0 || dispatch[0] != '"' {
			unbound++
			continue
		}
		if len(rows) >= 256 {
			return nil, unbound, errors.New("audit target row bound exceeded")
		}
		d := availabilityDecision{Time: rec.Time.UTC().Format(time.RFC3339Nano), PolicyUID: rec.DecisionTrace.PolicyUID, AssetUID: rec.DecisionTrace.AssetUID, DecisionID: rec.DecisionTrace.DecisionID, TickID: rec.DecisionTrace.TickID, Action: rec.Action, Selected: rec.Selected, Actuated: rec.Actuated, DispatchOutcome: rec.DecisionTrace.DispatchOutcome, TopLevelDispatchOutcome: rec.DispatchOutcome, Handler: rec.Handler, MutationKind: rec.MutationKind, GracefulTermination: rec.GracefulTermination != nil, EventEvidence: rec.EventEvidence, EventCoverage: "EXACT_EVENT_NOT_PRESENT_IN_THIS_DECISION"}
		if event == nil {
			d.EventCoverage = "NOT_EVALUATED"
		} else {
			matched := 0
			for _, v := range rec.Events {
				if v.EventUID == event.UID {
					matched++
					if v.Name == event.Name && v.CreatorIdentity == event.CreatorIdentity && v.TargetPodUID == before.TargetPodUID && v.TargetsPod && v.TrustVerdict == "trusted" && v.TimestampPresent && v.Weight > 0 && v.Weight <= 1 {
						d.EventCoverage = "EXACT_TRUSTED_EVENT_OBSERVED"
						d.ExactEventUID = v.EventUID
						d.ExactEventName = v.Name
						d.ExactEventCreator = v.CreatorIdentity
						d.ExactEventTargetPodUID = v.TargetPodUID
						d.EventWeight = v.Weight
					} else {
						d.EventCoverage = "EVENT_BINDING_MISMATCH"
					}
				}
				if v.EventUID != event.UID && v.TimestampPresent && v.TrustVerdict == "trusted" && v.TargetsPod && v.Weight > 0 {
					d.OtherTrustedEventCount++
				}
			}
			if matched > 1 {
				d.EventCoverage = "EVENT_IDENTITY_AMBIGUOUS"
			}
		}
		rows = append(rows, d)
	}
	return rows, unbound, nil
}

func (w *availabilityWorker) auditClose(start availabilityAuditStart, event *availabilityEvent) (availabilityAuditTerminal, error) {
	begin := time.Now()
	out := availabilityAuditTerminal{Schema: "guardrail-availability-audit-terminal-v1", Status: "AUDIT_COVERAGE_GAP", SourceIdentity: w.rm.cfg.AuditSourceIdentity, RawAuditRetained: false, TargetRows: []availabilityDecision{}, ChunkReceipts: []availabilityAuditChunk{}}
	startRaw, _ := json.Marshal(start)
	out.StartSHA256 = availabilityHash(startRaw)
	readDeadline := time.Now().Add(180 * time.Second)
	if w.deadline.Before(readDeadline) {
		readDeadline = w.deadline
	}
	if !time.Now().Before(readDeadline) {
		return out, errors.New("audit observation deadline exhausted")
	}
	ctx, stop := context.WithDeadline(w.ctx, readDeadline)
	defer stop()
	m, e := w.rm.cfg.AuditSource.Manifest(ctx)
	out.ControlGETs++
	if e != nil {
		return out, errors.New("audit end manifest unavailable")
	}
	endRaw, _ := json.Marshal(m)
	out.EndManifestSHA256 = availabilityHash(endRaw)
	if e = w.save("audit-end-manifest.json", endRaw); e != nil {
		return out, e
	}
	spans, e := availabilitySpans(start, m)
	if e != nil {
		return out, e
	}
	// Re-read the original pre-stimulus tail against its frozen generation.
	// Without this, a same-generation rewrite before the selected interval
	// could leave the later bytes self-consistent but break chronology.
	priorTailStart := max(int64(0), start.CheckpointSize-audittransport.ChunkBytes)
	if start.CheckpointSize > priorTailStart {
		tailSeg := spans[0][0].(audittransport.Segment)
		tailSeg.Size = start.CheckpointSize
		tail, e := w.rm.cfg.AuditSource.Chunk(ctx, tailSeg, priorTailStart)
		out.ControlGETs++
		if e != nil || availabilityHash(tail) != start.PriorTailSHA256 {
			return out, errors.New("audit start tail changed before terminal")
		}
		out.PayloadBytes = int64(2 * len(tail)) // start capture and immutable re-read
	}
	var count int64
	for _, span := range spans {
		count += span[2].(int64) - span[1].(int64)
	}
	out.FrozenBytes = count
	out.PayloadBytes += count
	if count < 0 || out.PayloadBytes > 96<<20 {
		return out, errors.New("audit payload byte budget exceeded")
	}
	var raw bytes.Buffer
	for _, span := range spans {
		seg, off, end := span[0].(audittransport.Segment), span[1].(int64), span[2].(int64)
		for off < end {
			if out.DataGETs >= 100 {
				return out, errors.New("audit data GET budget exceeded")
			}
			frozen := seg
			frozen.Size = end
			chunk, e := w.rm.cfg.AuditSource.Chunk(ctx, frozen, off)
			out.DataGETs++
			if e != nil {
				return out, errors.New("authenticated audit chunk unavailable")
			}
			want := min(int64(audittransport.ChunkBytes), end-off)
			if int64(len(chunk)) != want {
				return out, errors.New("authenticated audit chunk truncated")
			}
			out.ChunkReceipts = append(out.ChunkReceipts, availabilityAuditChunk{seg.ID, seg.Generation, off, len(chunk), availabilityHash(chunk)})
			if _, e = raw.Write(chunk); e != nil {
				return out, e
			}
			off += want
		}
	}
	out.BytesRead = int64(raw.Len())
	final, e := w.rm.cfg.AuditSource.Manifest(ctx)
	out.ControlGETs++
	if e != nil {
		return out, errors.New("audit terminal manifest unavailable")
	}
	finalRaw, _ := json.Marshal(final)
	out.TerminalManifestSHA256 = availabilityHash(finalRaw)
	if e = w.save("audit-terminal-manifest.json", finalRaw); e != nil {
		return out, e
	}
	// The frozen prefix must still resolve to the same generation/anchor after
	// all data GETs; a newer live tail is allowed and outside this interval.
	finalSpans, e := availabilitySpans(start, final)
	if e != nil {
		return out, e
	}
	if len(finalSpans) < len(spans) {
		return out, errors.New("audit frozen generation evicted before final manifest")
	}
	for i, span := range spans {
		a, b := span[0].(audittransport.Segment), finalSpans[i][0].(audittransport.Segment)
		if a.Generation != b.Generation || a.Anchor != b.Anchor || b.Size < span[2].(int64) {
			return out, errors.New("audit frozen generation changed after read")
		}
	}
	rows, unbound, e := availabilityProjectAudit(raw.Bytes(), w.before, w.p.Fixture.PodName, event)
	if e != nil {
		return out, e
	}
	out.TargetRows = rows
	out.UnboundTargetRows = &unbound
	out.AuditReadElapsedSeconds = time.Since(begin).Seconds()
	if out.AuditReadElapsedSeconds >= 180 {
		return out, errors.New("absolute audit read deadline exhausted")
	}
	out.Status = "COMPLETE"
	out.CoverageComplete = true
	return out, nil
}
