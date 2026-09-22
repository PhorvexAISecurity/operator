package cataloguecollector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	round64MetricHash = "6891ac8f121924cc87cd3bd3686b137579b03065f6f745571362f04f2a920ae5"
	round64Source     = "005cd3a9e7eb5f4d65da266c59bb675a298d9a00"
)

func TestCollectRound64InstalledSessionEvidence(t *testing.T) {
	dir, rec := fixtureIndex(t)
	report, err := Collect(writeIndex(t, dir, []RunRecord{rec}))
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != ReportSchema || report.ComparisonStatus != "COMPARISON_NOT_ESTABLISHED" || len(report.Runs) != 1 || len(report.Groups) != 1 {
		t.Fatalf("report envelope: %+v", report)
	}
	run := report.Runs[0]
	if run.MeasurementStatus != "DECODED_FUNCTIONAL" || run.ValidTrials != 1 || run.InvalidTrials != 0 || run.ExternalReviewState != "supplied-pass" {
		t.Fatalf("run: %+v", run)
	}
	s := run.InstalledSession
	if s == nil || s.SampleDenominator != 180 || s.KnownApplicationResponse != 180 || s.SessionPresentHTTP200 != 91 || s.PeerWithoutSessionHTTP404 != 89 || s.Unknown != 0 || s.SegmentCount != 5 || s.DefensiveActions != 0 || s.FalseDefensiveActions != -1 || s.ContinuousAvailability {
		t.Fatalf("round64 summary: %+v", s)
	}
	if len(s.InterSegmentGapSeconds) != 4 || !close(s.SampledWindowSeconds, 90.000535, .001) || !close(s.ElapsedSpanSeconds, 113.092033, .001) {
		t.Fatalf("round64 timing: %+v", s)
	}
	var gaps float64
	for _, g := range s.InterSegmentGapSeconds {
		if g <= 0 {
			t.Fatalf("nonpositive gap: %+v", s.InterSegmentGapSeconds)
		}
		gaps += g
	}
	if !close(gaps, 23.091498, .001) {
		t.Fatalf("gaps=%f", gaps)
	}
	if s.PodUIDCounts[s.OriginalPodUID] != 91 || s.PodUIDCounts[s.PeerPodUID] != 89 || s.EffectStatus != "original-state-retained" || s.EffectAttribution != s.OriginalPodUID {
		t.Fatalf("identity/effect: %+v", s)
	}
	md := Markdown(report)
	for _, want := range []string{"91", "89", "Known 404 responses are not session successes", "no continuous-availability"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q: %s", want, md)
		}
	}
}

func TestCollectKeepsMissingAndUnsupportedProfilesVisible(t *testing.T) {
	dir, available := fixtureIndex(t)
	missing := available
	missing.ID = "missing-timer"
	missing.ProfileID = "manager-session-blind-timer"
	missing.State = "missing"
	missing.FailureReason = "trial was not run"
	failed := available
	failed.ID = "failed-installed"
	failed.ProfileID = "manager-session-installed"
	failed.State = "failed"
	failed.FailureReason = "bounded supervisor exited before a complete trial"
	opaqueRaw := metricBytes(t, dir)
	var row map[string]any
	if err := json.Unmarshal(opaqueRaw, &row); err != nil {
		t.Fatal(err)
	}
	row["scenario"] = "c2-nats-jetstream-durability"
	b, _ := json.Marshal(row)
	b = append(b, '\n')
	os.WriteFile(filepath.Join(dir, "nats.jsonl"), b, 0o600)
	opaque := available
	opaque.ID = "nats-control"
	opaque.ProfileID = "nats-no-action"
	opaque.MetricsFile = "nats.jsonl"
	opaque.MetricsSHA256 = sumTest(b)
	opaque.ExternalReviewState = "unreviewed"
	opaque.ExternalReviewReference = "none"
	report, err := Collect(writeIndex(t, dir, []RunRecord{missing, failed, opaque}))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Runs) != 3 || report.Runs[0].MeasurementStatus != "MISSING" || report.Runs[0].FailureReasons[0] != "trial was not run" || report.Runs[1].MeasurementStatus != "FAILED" || report.Runs[2].MeasurementStatus != "UNSUPPORTED_MEASUREMENT_SCHEMA" {
		t.Fatalf("runs: %+v", report.Runs)
	}
}

func TestCollectListsInvalidInstalledRowWithoutDecodingItAsMeasurement(t *testing.T) {
	dir, rec := fixtureIndex(t)
	mutateMetric(t, dir, &rec, func(x map[string]any) {
		x["validity"].(map[string]any)["cleanup"].(map[string]any)["verified"] = false
	})
	report, err := Collect(writeIndex(t, dir, []RunRecord{rec}))
	if err != nil {
		t.Fatal(err)
	}
	run := report.Runs[0]
	if run.MeasurementStatus != "INVALID" || run.InvalidTrials != 1 || run.ValidTrials != 0 || run.InstalledSession != nil || len(run.FailureReasons) != 1 {
		t.Fatalf("invalid run: %+v", run)
	}
}

func TestCollectRejectsCorruptOrAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, *RunRecord)
	}{
		{"hash-mismatch", func(t *testing.T, _ string, r *RunRecord) { r.MetricsSHA256 = strings.Repeat("0", 64) }},
		{"unknown-profile", func(t *testing.T, _ string, r *RunRecord) { r.ProfileID = "unknown" }},
		{"selected-scenario-mismatch", func(t *testing.T, d string, r *RunRecord) {
			mutateMetric(t, d, r, func(x map[string]any) { x["scenario"] = "c2-voice-websocket-continuity" })
		}},
		{"partial-segment-chunks", func(t *testing.T, d string, r *RunRecord) {
			mutateEvidence(t, d, r, func(e map[string]any) { delete(e, "availability.segmentReceiptChunk.001") })
		}},
		{"flattened-observation-differs", func(t *testing.T, d string, r *RunRecord) {
			mutateEvidence(t, d, r, func(e map[string]any) {
				e["availability.observation.000"] = `{"atUTC":"2026-09-22T05:40:14.880949Z","known":true,"category":"application-response","httpStatus":404,"podUID":"00a140c7-0484-4c47-90d5-29b13d316a00"}`
			})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, r := fixtureIndex(t)
			tc.mutate(t, d, &r)
			if _, err := Collect(writeIndex(t, d, []RunRecord{r})); err == nil {
				t.Fatal("accepted corrupt input")
			}
		})
	}
}

func TestCollectRejectsDuplicateKeysAndConflictingMetricReuse(t *testing.T) {
	dir, rec := fixtureIndex(t)
	idx := writeIndex(t, dir, []RunRecord{rec})
	raw := strings.Replace(string(mustRead(t, idx)), `"schema":`, `"schema":"duplicate","schema":`, 1)
	if err := os.WriteFile(idx, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(idx); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate key err=%v", err)
	}
	dir, rec = fixtureIndex(t)
	second := rec
	second.ID = "conflict"
	second.ProfileID = "nats-no-action"
	if _, err := Collect(writeIndex(t, dir, []RunRecord{rec, second})); err == nil || !strings.Contains(err.Error(), "reused by conflicting profiles") {
		t.Fatalf("reuse err=%v", err)
	}
	dir, rec = fixtureIndex(t)
	if _, err := Collect(writeIndex(t, dir, []RunRecord{rec, rec})); err == nil || !strings.Contains(err.Error(), "duplicate or empty record id") {
		t.Fatalf("duplicate id err=%v", err)
	}
}

func fixtureIndex(t *testing.T) (string, RunRecord) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	module := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	dir := t.TempDir()
	copyFile(t, filepath.Join(module, "catalogue/v3/suite.json"), filepath.Join(dir, "suite.json"))
	copyFile(t, filepath.Join(filepath.Dir(file), "testdata/round64/metrics.sanitized.jsonl"), filepath.Join(dir, "metrics.jsonl"))
	suiteRaw := mustRead(t, filepath.Join(dir, "suite.json"))
	metricRaw := mustRead(t, filepath.Join(dir, "metrics.jsonl"))
	if sumTest(metricRaw) != round64MetricHash {
		t.Fatalf("fixture drift %s", sumTest(metricRaw))
	}
	return dir, RunRecord{ID: "round64-no-action", ProfileID: "manager-session-no-action", SuiteFile: "suite.json", SuiteSHA256: sumTest(suiteRaw), SourceRevision: round64Source, HarnessSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), MetricsFile: "metrics.jsonl", MetricsSHA256: sumTest(metricRaw), WorkloadSchedule: "five-18s-segments-500ms-cadence", State: "available", ExternalReviewState: "supplied-pass", ExternalReviewReference: "ROUND64-LEAD-REVIEW/RESULT.json"}
}
func writeIndex(t *testing.T, dir string, recs []RunRecord) string {
	t.Helper()
	b, err := json.MarshalIndent(Index{Schema: IndexSchema, Records: recs}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "index.json")
	if err := os.WriteFile(p, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
func metricBytes(t *testing.T, dir string) []byte {
	t.Helper()
	return mustRead(t, filepath.Join(dir, "metrics.jsonl"))
}
func mutateMetric(t *testing.T, dir string, r *RunRecord, f func(map[string]any)) {
	t.Helper()
	var x map[string]any
	if err := json.Unmarshal(metricBytes(t, dir), &x); err != nil {
		t.Fatal(err)
	}
	f(x)
	b, _ := json.Marshal(x)
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, "mutated.jsonl"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	r.MetricsFile = "mutated.jsonl"
	r.MetricsSHA256 = sumTest(b)
}
func mutateEvidence(t *testing.T, dir string, r *RunRecord, f func(map[string]any)) {
	mutateMetric(t, dir, r, func(x map[string]any) { f(x["benchmarkEvidence"].(map[string]any)) })
}
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.WriteFile(dst, mustRead(t, src), 0o600); err != nil {
		t.Fatal(err)
	}
}
func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func sumTest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func close(a, b, tol float64) bool {
	if a > b {
		return a-b < tol
	}
	return b-a < tol
}
