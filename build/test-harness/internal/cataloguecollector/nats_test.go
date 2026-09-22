package cataloguecollector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

var retainedNATSFixtures = []struct {
	name       string
	profile    string
	mode       string
	metricHash string
	source     string
	wantValid  bool
}{
	{"round57-noaction", "nats-no-action", "no-action", "34950d0a7e246d397dbf4916a4aa746e835d312e606f18c346a047d08423a2e3", "a23c50563aefae4d7fda0472bef83c2800aa8409", false},
	{"round57-restart", "nats-member-restart", "member-restart", "da6a4395d7af655d6e0dfd9d4e43ac42c30a9b371372f07e97db5b179d7fe581", "a23c50563aefae4d7fda0472bef83c2800aa8409", false},
	{"round69-quorum", "nats-quorum-pause", "quorum-pause", "5f1a2b179bbedc1b050896e4a1e929a933ae34c5982067679e6ebf0bf7556bca", "5ea6e29e515626c459de2d8f36014b0536bd87ee", true},
}

func TestDecodeRetainedNATSProducerReceiptsAndScoringBoundary(t *testing.T) {
	for _, tc := range retainedNATSFixtures {
		t.Run(tc.name, func(t *testing.T) {
			dir, rec, row := natsFixtureIndex(t, tc.name, tc.profile, tc.mode, tc.source)
			if rec.MetricsSHA256 != tc.metricHash {
				t.Fatalf("retained fixture hash=%s want %s", rec.MetricsSHA256, tc.metricHash)
			}
			summary, err := decodeNATS(row, tc.profile, rec.NATSIdentity)
			if err != nil {
				t.Fatalf("decode retained producer receipt: %v", err)
			}
			if summary.Mode != tc.mode || summary.ProtocolStatus != "complete" || summary.IdentityAuthority != "supplied-run-index" || summary.CleanupComplete != true || summary.CleanupVerified != true || summary.FinalAckPending != 0 || summary.FinalConsumerPending != 0 || summary.FinalConsumerRedelivered != 0 {
				t.Fatalf("summary: %+v", summary)
			}
			rowErr := functionalRowError(row)
			if (rowErr == nil) != tc.wantValid {
				t.Fatalf("functional validity err=%v wantValid=%t", rowErr, tc.wantValid)
			}
			report, err := Collect(writeIndex(t, dir, []RunRecord{rec}))
			if err != nil {
				t.Fatal(err)
			}
			run := report.Runs[0]
			if tc.wantValid {
				if run.MeasurementStatus != "DECODED_FUNCTIONAL" || run.NATSJetStream == nil || run.ValidTrials != 1 || run.InvalidTrials != 0 {
					t.Fatalf("valid collected run: %+v", run)
				}
			} else if run.MeasurementStatus != "INVALID" || run.NATSJetStream == nil || run.ValidTrials != 0 || run.InvalidTrials != 1 {
				t.Fatalf("legacy scored benign row must remain invalid: %+v", run)
			}
		})
	}
}

func TestCollectNATSQuorumReportsUnknownPublicationWithoutLossClaim(t *testing.T) {
	dir, rec, _ := natsFixtureIndex(t, "round69-quorum", "nats-quorum-pause", "quorum-pause", retainedNATSFixtures[2].source)
	report, err := Collect(writeIndex(t, dir, []RunRecord{rec}))
	if err != nil {
		t.Fatal(err)
	}
	s := report.Runs[0].NATSJetStream
	if s == nil || s.MessageASequence != 1 || s.MessageXSequence != 2 || s.MessageYSequence != 3 || s.FinalMessages != 3 || s.FinalAckFloor != 3 || s.ActionCount != 2 || s.DuringPausePublicationStatus != "unknown" || s.DuringPausePublicationErrorClass != "timeout-unknown" || !s.DuringPausePingReachable || s.QuorumPauseObservedNanos != 3850792958 || s.QuorumPauseMaximumNanos != 10000000000 || len(s.PausedMembers) != 2 {
		t.Fatalf("quorum summary: %+v", s)
	}
	if report.ComparisonStatus != "COMPARISON_NOT_ESTABLISHED" || report.Groups[0].ComparisonStatus != "COMPARISON_NOT_ESTABLISHED" {
		t.Fatalf("comparison status: %+v", report)
	}
	md := Markdown(report)
	for _, forbidden := range []string{"publication loss", "security success", "monetary benefit"} {
		if strings.Contains(strings.ToLower(md), forbidden) {
			t.Fatalf("markdown invents claim %q: %s", forbidden, md)
		}
	}
}

func TestCollectRejectsTamperedNATSProtocolAndIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, *NATSRunIdentity)
	}{
		{"receipt-digest", func(row map[string]any, _ *NATSRunIdentity) {
			row["benchmarkEvidence"].(map[string]any)["quorumReceiptSHA256"] = strings.Repeat("0", 64)
		}},
		{"supplied-pod-identity", func(_ map[string]any, a *NATSRunIdentity) {
			a.PodUIDs[1] = "11111111-1111-4111-8111-111111111111"
		}},
		{"puback-sequence", func(row map[string]any, _ *NATSRunIdentity) {
			mutateNATSReceipt(t, row, func(r map[string]any) { r["messageY"].(map[string]any)["sequence"] = float64(4) })
		}},
		{"consumer-ack-delivery", func(row map[string]any, _ *NATSRunIdentity) {
			mutateNATSReceipt(t, row, func(r map[string]any) { r["deliveryX"].(map[string]any)["deliveries"] = float64(2) })
		}},
		{"final-redelivery", func(row map[string]any, _ *NATSRunIdentity) {
			mutateNATSReceipt(t, row, func(r map[string]any) { r["finalState"].(map[string]any)["consumerRedelivered"] = float64(1) })
		}},
		{"stored-payload", func(row map[string]any, _ *NATSRunIdentity) {
			mutateNATSReceipt(t, row, func(r map[string]any) { r["storedAAfter"].(map[string]any)["payloadSHA256"] = strings.Repeat("0", 64) })
		}},
		{"failed-baseline-replica", func(row map[string]any, _ *NATSRunIdentity) {
			mutateNATSReceipt(t, row, func(r map[string]any) {
				r["baseline"].(map[string]any)["stream"].(map[string]any)["members"].([]any)[0].(map[string]any)["current"] = false
			})
		}},
		{"nanosecond-pause-boundary", func(row map[string]any, _ *NATSRunIdentity) {
			mutateNATSReceipt(t, row, func(r map[string]any) {
				r["pause"].(map[string]any)["members"].([]any)[0].(map[string]any)["stillPausedAtUTC"] = "2026-09-22T06:43:59.000000000Z"
			})
		}},
		{"action-count", func(row map[string]any, _ *NATSRunIdentity) {
			row["benchmarkEvidence"].(map[string]any)["actionCount"] = "1"
		}},
		{"wrong-mode", func(row map[string]any, _ *NATSRunIdentity) {
			row["benchmarkEvidence"].(map[string]any)["mode"] = "member-restart"
		}},
		{"truncated-receipt", func(row map[string]any, _ *NATSRunIdentity) {
			e := row["benchmarkEvidence"].(map[string]any)
			raw := e["oracleReceiptJSON"].(string)[:100]
			e["oracleReceiptJSON"], e["quorumReceiptSHA256"] = raw, sumTest([]byte(raw))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, rec, _ := natsFixtureIndex(t, "round69-quorum", "nats-quorum-pause", "quorum-pause", retainedNATSFixtures[2].source)
			var raw map[string]any
			if err := json.Unmarshal(mustRead(t, filepath.Join(dir, rec.MetricsFile)), &raw); err != nil {
				t.Fatal(err)
			}
			tc.mutate(raw, rec.NATSIdentity)
			writeNATSMutatedMetric(t, dir, &rec, raw)
			if _, err := Collect(writeIndex(t, dir, []RunRecord{rec})); err == nil {
				t.Fatal("accepted tampered NATS evidence")
			}
		})
	}
}

func TestCollectKeepsBadBenignScoringAndLostCleanupInvalid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"scored-true", func(row map[string]any) { row["validity"].(map[string]any)["scored"] = true }},
		{"wrong-unscored-reason", func(row map[string]any) {
			row["validity"].(map[string]any)["unscoredReason"] = "benign"
		}},
		{"security-roi", func(row map[string]any) {
			row["roi"] = map[string]any{"avoidedBreachValueDollars": 1}
		}},
		{"cleanup-unverified", func(row map[string]any) {
			row["validity"].(map[string]any)["cleanup"].(map[string]any)["verified"] = false
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, rec, _ := natsFixtureIndex(t, "round69-quorum", "nats-quorum-pause", "quorum-pause", retainedNATSFixtures[2].source)
			var row map[string]any
			if err := json.Unmarshal(mustRead(t, filepath.Join(dir, rec.MetricsFile)), &row); err != nil {
				t.Fatal(err)
			}
			tc.mutate(row)
			writeNATSMutatedMetric(t, dir, &rec, row)
			report, err := Collect(writeIndex(t, dir, []RunRecord{rec}))
			if err != nil {
				t.Fatal(err)
			}
			if report.Runs[0].MeasurementStatus != "INVALID" || report.Runs[0].NATSJetStream == nil {
				t.Fatalf("bad benign disposition qualified: %+v", report.Runs[0])
			}
		})
	}
}

func TestCollectKeepsMissingNATSRunInDenominatorWithoutInventedRuntimeIdentity(t *testing.T) {
	dir, rec := fixtureIndex(t)
	rec.ID = "missing-nats-quorum"
	rec.ProfileID = "nats-quorum-pause"
	rec.State = "missing"
	rec.FailureReason = "bounded quorum control was not run"
	rec.NATSIdentity = nil
	report, err := Collect(writeIndex(t, dir, []RunRecord{rec}))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Runs) != 1 || report.Runs[0].MeasurementStatus != "MISSING" || report.Runs[0].TrialDenominator != 1 || report.Runs[0].NATSJetStream != nil {
		t.Fatalf("missing NATS denominator: %+v", report.Runs)
	}
}

func natsFixtureIndex(t *testing.T, fixture, profile, mode, source string) (string, RunRecord, coreMetricAlias) {
	t.Helper()
	dir := t.TempDir()
	_, file, _, _ := runtime.Caller(0)
	module := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	copyFile(t, filepath.Join(module, "catalogue/v3/suite.json"), filepath.Join(dir, "suite.json"))
	metrics := filepath.Join(testdataDir(t), fixture, "metrics.raw.jsonl")
	copyFile(t, metrics, filepath.Join(dir, "metrics.jsonl"))
	raw := mustRead(t, filepath.Join(dir, "metrics.jsonl"))
	rows, err := decodeMetrics(raw)
	if err != nil || len(rows) != 1 {
		t.Fatalf("decode fixture rows=%d err=%v", len(rows), err)
	}
	a := natsAuthorityFromEvidence(t, rows[0].BenchmarkEvidence, mode)
	suiteRaw := mustRead(t, filepath.Join(dir, "suite.json"))
	rec := RunRecord{ID: fixture, ProfileID: profile, SuiteFile: "suite.json", SuiteSHA256: sumTest(suiteRaw), SourceRevision: source, HarnessSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), MetricsFile: "metrics.jsonl", MetricsSHA256: sumTest(raw), WorkloadSchedule: "single-bounded-protocol-oracle", State: "available", ExternalReviewState: "supplied-pass", ExternalReviewReference: fixture + "/RESULT.json", NATSIdentity: a}
	return dir, rec, rows[0]
}

// This alias keeps the helper signature readable while preserving the exact
// core.Metric type returned by decodeMetrics.
type coreMetricAlias = core.Metric

func natsAuthorityFromEvidence(t *testing.T, e map[string]string, mode string) *NATSRunIdentity {
	t.Helper()
	a := &NATSRunIdentity{Mode: mode, FixtureNonce: e["fixtureNonce"], NodeName: e["nodeName"], NodeUID: e["nodeUID"], ConnectedMember: e["connectedMember"], StorageClass: e["storageClass"], StorageClassUID: e["storageClassUID"]}
	for i := range 3 {
		a.PodUIDs = append(a.PodUIDs, e["pod"+strconv.Itoa(i)+"UID"])
		a.PVCUIDs = append(a.PVCUIDs, e["pvc"+strconv.Itoa(i)+"UID"])
		a.PVUIDs = append(a.PVUIDs, e["pv"+strconv.Itoa(i)+"UID"])
		a.StorePathSHA256s = append(a.StorePathSHA256s, e["store"+strconv.Itoa(i)+"PathSHA256"])
		a.InitialServerIDs = append(a.InitialServerIDs, e["server"+strconv.Itoa(i)+"ID"])
	}
	return a
}

func mutateNATSReceipt(t *testing.T, row map[string]any, mutate func(map[string]any)) {
	t.Helper()
	e := row["benchmarkEvidence"].(map[string]any)
	var receipt map[string]any
	if err := json.Unmarshal([]byte(e["oracleReceiptJSON"].(string)), &receipt); err != nil {
		t.Fatal(err)
	}
	mutate(receipt)
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	e["oracleReceiptJSON"] = string(raw)
	e["quorumReceiptSHA256"] = sumTest(raw)
}

func writeNATSMutatedMetric(t *testing.T, dir string, rec *RunRecord, row map[string]any) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join(dir, "mutated-nats.jsonl")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	rec.MetricsFile, rec.MetricsSHA256 = "mutated-nats.jsonl", sumTest(raw)
}
