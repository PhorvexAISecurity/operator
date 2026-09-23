/*
 * Phorvex Console (P-DASHBOARD-LIVE) — ATTACK-TIMELINE SSE.
 *
 * GET /api/runs/stream?id=<run-id> (text/event-stream) streams a triggered scenario run in
 * real time: the harness's live "=== scenario=… defender=… trial=N ===" stage headers (from
 * the captured stdout) as {type:"stage"}, and each COMPLETED trial — with the literal attacker
 * command steps the harness ran, the dwell, and whether the attack landed or was disrupted — as
 * {type:"trial"}. It ends with {type:"end"} when the run finishes. Read-only: it only tails the
 * run's own out dir; it triggers nothing and mutates nothing.
 */

package console

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// trialEvent is the per-completed-trial timeline payload — richer than metricRow: it carries the
// literal attack command steps so the UI can render the attack as a visual sequence.
type trialEvent struct {
	Type                   string   `json:"type"` // "trial"
	Scenario               string   `json:"scenario"`
	Defender               string   `json:"defender"`
	Trial                  int      `json:"trial"`
	OracleAchieved         bool     `json:"oracleAchieved"`
	Disruption             float64  `json:"disruption"`
	DwellSeconds           float64  `json:"dwellSeconds"`
	MTDEffect              string   `json:"mtdEffect"`
	Observed               string   `json:"observed"`
	Commands               []string `json:"commands"`
	DefensiveActions       int      `json:"defensiveActions"`
	ScenarioRealism        string   `json:"scenarioRealism,omitempty"`
	ScenarioBenignControl  bool     `json:"scenarioBenignControl"`
	ScenarioClaimLimits    string   `json:"scenarioClaimLimits,omitempty"`
	FunctionalOracleStatus string   `json:"functionalOracleStatus,omitempty"`
	Outcome                string   `json:"outcome"`
	OutcomeReason          string   `json:"outcomeReason"`
	ClaimClass             string   `json:"claimClass"`
	MeasurementStatus      string   `json:"measurementStatus"`
	MeasurementPhase       string   `json:"measurementPhase"`
	ValidityReasons        []string `json:"validityReasons"`
}

func trialEventFromRow(row runMetricRow) trialEvent {
	outcome := row.outcome()
	event := trialEvent{
		Type: "trial", Scenario: row.Scenario, Defender: row.Defender, Trial: row.Trial,
		OracleAchieved: row.OracleAchieved, Disruption: row.DisruptionVsOracle,
		DwellSeconds: row.AttackerDwellSeconds, MTDEffect: row.MTDEffect,
		Observed: row.ObservedState, Commands: row.Commands, DefensiveActions: row.DefensiveActions,
		ScenarioRealism: row.ScenarioRealism, ScenarioBenignControl: row.ScenarioBenignControl,
		ScenarioClaimLimits: row.ScenarioClaimLimits,
		Outcome:             outcome.Outcome, OutcomeReason: outcome.OutcomeReason, ClaimClass: outcome.ClaimClass,
		MeasurementStatus: outcome.MeasurementStatus, MeasurementPhase: outcome.MeasurementPhase,
		ValidityReasons: outcome.ValidityReasons,
	}
	if status, ok, conflict := functionalOracleStatus(row.BenchmarkEvidence); ok && !conflict {
		event.FunctionalOracleStatus = status
	}
	return event
}

var stageLineRe = regexp.MustCompile(`scenario=([a-z0-9-]+)\s+defender=([a-z0-9-]+)\s+trial=(\d+)`)

func (s *Server) runStream(w http.ResponseWriter, r *http.Request) {
	// The id the boundary resolved and authorized — never re-read from the request.
	id := runIDOf(r)
	outDir, ok := s.runs.streamRef(id)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "run not found"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	metricsPath := filepath.Join(s.cfg.runOutputPath(outDir), "metrics.jsonl")
	logPath := filepath.Join(s.cfg.runOutputPath(outDir), "console-run.log")

	send := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
		flusher.Flush()
	}
	provider, targetLabel := s.runs.runMeta(id)
	lastState, lastPos := s.runs.runState(id), s.runs.queuePos(id)
	send(map[string]any{"type": "meta", "id": id, "state": lastState, "queuePos": lastPos, "expectedTrials": s.runs.expectedTrials(id), "provider": provider, "targetLabel": targetLabel})

	var mOff, lOff int64
	ctx := r.Context()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	drain := 0
	for {
		// re-emit meta when the run leaves the queue or advances in it, so the UI shows live
		// "queued (#N)" -> "running" without the client having to poll.
		if cs, cp := s.runs.runState(id), s.runs.queuePos(id); cs != lastState || cp != lastPos {
			lastState, lastPos = cs, cp
			send(map[string]any{"type": "meta", "id": id, "state": cs, "queuePos": cp, "expectedTrials": s.runs.expectedTrials(id), "provider": provider, "targetLabel": targetLabel})
		}
		lOff = tailLines(logPath, lOff, func(line string) {
			if m := stageLineRe.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[3])
				send(map[string]any{"type": "stage", "scenario": m[1], "defender": m[2], "trial": n})
			}
		})
		mOff = tailLines(metricsPath, mOff, func(line string) {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				return
			}
			var row runMetricRow
			if err := json.Unmarshal([]byte(trimmed), &row); err != nil {
				send(map[string]any{"type": "evidence-error", "outcome": outcomeUnverified, "reason": "metric row cannot be decoded: " + err.Error()})
				return
			}
			send(trialEventFromRow(row))
		})
		if st := s.runs.runState(id); st == "done" || st == "partial" || st == "error" || st == "stopped" {
			drain++ // one more pass to flush the final rows, then end cleanly.
			if drain >= 2 {
				send(map[string]any{"type": "end", "state": st})
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tailLines emits each COMPLETE (newline-terminated) line appended past offset and returns the
// new offset, never advancing past a partial final line (so a mid-write read never corrupts).
func tailLines(path string, offset int64, emit func(string)) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() <= offset {
		return offset
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}
	buf := make([]byte, fi.Size()-offset)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	lastNL := bytes.LastIndexByte(buf, '\n')
	if lastNL < 0 {
		return offset // no complete line yet
	}
	for _, line := range strings.Split(strings.TrimRight(string(buf[:lastNL+1]), "\n"), "\n") {
		if line != "" {
			emit(line)
		}
	}
	return offset + int64(lastNL+1)
}
