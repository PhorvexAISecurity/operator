package console

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
)

func vllmWatchRows(t *testing.T, now time.Time) (audit.Record, audit.Record) {
	t.Helper()
	selectedTrace := caseTraceValidTrace(now.Add(2*time.Second), true, true)
	noopTrace := caseTraceValidTrace(now.Add(6*time.Second), false, true)
	noopTrace.DecisionID, noopTrace.TickID = "decision-2", "tick-2"
	for _, trace := range []*model.DecisionTraceV2{selectedTrace, noopTrace} {
		if err := trace.Validate(); err != nil {
			t.Fatalf("invalid decision trace fixture: %v", err)
		}
	}
	event := genericCaseEvent("event-uid", "pod-uid", "trusted")
	selected := audit.Record{Kind: "phorvex.decision", Time: now.Add(2 * time.Second),
		Namespace: "demo", Pod: "demo-0", Action: "rotate", Selected: true, Actuated: true,
		DispatchOutcome: model.DispatchEmitted, DecisionTrace: selectedTrace,
		Events: []model.EventEvidence{event}}
	noop := audit.Record{Kind: "phorvex.decision", Time: now.Add(6 * time.Second),
		Namespace: "demo", Pod: "demo-0", Action: "noop", DecisionTrace: noopTrace,
		DispatchOutcome: model.DispatchNotAttempted, Events: []model.EventEvidence{event}}
	return selected, noop
}

func vllmWatchRecord(now time.Time) *attackRecord {
	return &attackRecord{
		FiredAt: now.Format(time.RFC3339Nano), Namespace: "demo", Pod: "demo-0",
		TargetUID: "pod-uid", EvidenceKind: "vllm-in-place-effect", AttackID: "kvcache",
		ObservationStart: now.Format(time.RFC3339Nano),
		ObservationEnd:   now.Add(8 * time.Second).Format(time.RFC3339Nano),
		OutcomeClass:     "effect-only",
		StimulusEvidence: &attackStimulusEvidence{Observed: true, TargetUID: "pod-uid",
			EventName: "owned-signal", EventUID: "event-uid",
			EventCreatedAt: now.Add(time.Second).Format(time.RFC3339Nano), EventRule: "Panic"},
	}
}

func TestVLLMDecisionWatchRetainsSelectedAfterLaterNoops(t *testing.T) {
	now := time.Date(2026, 9, 27, 14, 18, 10, 0, time.UTC)
	selected, noop := vllmWatchRows(t, now)
	path := writeDecisionAudit(t, selected)
	s := NewServer(Config{AuditPath: path, Now: func() time.Time { return now.Add(9 * time.Second) }})
	record := vllmWatchRecord(now)
	s.fillReasoning("", record)
	if record.DecisionEvidence == nil || record.DecisionEvidence.Action != "rotate" ||
		record.DecisionEvidence.DecisionID != "decision-1" || record.DecisionEvidence.EventUID != "event-uid" {
		t.Fatalf("initial selected decision missing: %+v", record.DecisionEvidence)
	}

	wrongEvent := selected
	wrongEvent.Time = now.Add(4 * time.Second)
	wrongEvent.DecisionTrace = nil
	wrongEvent.Events = []model.EventEvidence{genericCaseEvent("foreign-event", "pod-uid", "trusted")}
	wrongPod := selected
	wrongPod.Time = now.Add(5 * time.Second)
	wrongPod.DecisionTrace = nil
	wrongPod.Events = []model.EventEvidence{genericCaseEvent("event-uid", "foreign-pod", "trusted")}
	replacement := writeDecisionAudit(t, wrongEvent, wrongPod, noop)
	raw, err := os.ReadFile(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s.fillReasoning("", record)
	s.fillReasoning("", record) // overlapping polls must not duplicate the same NOOP
	if record.DecisionEvidence == nil || record.DecisionEvidence.DecisionID != "decision-1" ||
		record.DecisionEvidence.Action != "rotate" || !record.DecisionEvidence.Selected ||
		len(record.DecisionTraceEvidence) != 2 || record.DecisionTraceEvidence[1].Action != "noop" {
		t.Fatalf("selected decision lost or foreign rows admitted: summary=%+v history=%+v",
			record.DecisionEvidence, record.DecisionTraceEvidence)
	}
	if record.Outcome != "" || record.Actuated || record.OutcomeClass != "effect-only" {
		t.Fatalf("decision evidence incorrectly promoted mechanism to defense: %+v", record)
	}
	fresh := vllmWatchRecord(now)
	s.fillReasoning("", fresh)
	if fresh.DecisionEvidence == nil || fresh.DecisionEvidence.Action != "noop" ||
		len(fresh.DecisionTraceEvidence) != 1 {
		t.Fatalf("foreign selected row gained fresh exact authority: %+v", fresh)
	}
	record.StimulusEvidence.EventUID = "replacement-event"
	s.fillReasoning("", record)
	if record.DecisionEvidence != nil && record.DecisionEvidence.Correlation == "exact-event-uid" ||
		len(record.DecisionTraceEvidence) != 0 {
		t.Fatalf("stale selected evidence survived event identity change: %+v", record)
	}
}

func TestVLLMDecisionWatchSamplesBeforeAndAfterEffectAcrossRotation(t *testing.T) {
	start := time.Date(2026, 9, 27, 14, 18, 10, 0, time.UTC)
	selected, noop := vllmWatchRows(t, start)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	selectedFile := writeDecisionAudit(t, selected)
	selectedBytes, err := os.ReadFile(selectedFile)
	if err != nil {
		t.Fatal(err)
	}
	wrong := selected
	wrong.Time = start.Add(4 * time.Second)
	wrong.DecisionTrace = nil
	wrong.Events = []model.EventEvidence{genericCaseEvent("wrong-event", "pod-uid", "trusted")}
	lateFile := writeDecisionAudit(t, wrong, noop)
	lateBytes, err := os.ReadFile(lateFile)
	if err != nil {
		t.Fatal(err)
	}
	current := start
	steps := 0
	r := vllmWatchRecord(start)
	r.ID, r.Status, r.started, r.accepted = "atk-watch", "running", start, start
	// This is a direct watcher test, not a server-startup reconciliation test.
	// Leaving StateDir unset prevents the startup reconciler from sharing and
	// advancing this watcher's deterministic clock in a background goroutine.
	s := NewServer(Config{AuditPath: path,
		Now: func() time.Time { return current },
		Sleep: func(d time.Duration) {
			current = current.Add(d)
			steps++
			switch steps {
			case 2: // after an initial empty poll, the manager selects the action
				if err := os.WriteFile(path, selectedBytes, 0600); err != nil {
					t.Fatal(err)
				}
			case 3: // effect is observed after selection, without causing a verdict
				r.EffectEvidence = &attackEffectEvidence{Observed: true, TargetUID: "pod-uid"}
			case 4: // an unavailable generation is disclosed as a sampling gap
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case 5:
				if err := os.WriteFile(path, selectedBytes, 0600); err != nil {
					t.Fatal(err)
				}
			case 6: // audit rotates, leaving only later exact NOOP and wrong-event rows
				if err := os.WriteFile(path, lateBytes, 0600); err != nil {
					t.Fatal(err)
				}
			}
		},
	})
	s.watchAttackUntil("", r, start.Add(8*time.Second), time.Second)
	if steps < 6 || r.DecisionEvidence == nil || r.DecisionEvidence.DecisionID != "decision-1" ||
		len(r.DecisionTraceEvidence) != 2 || r.DecisionTraceEvidence[1].Action != "noop" ||
		r.Outcome != "" || r.Actuated || !r.DecisionAuditReadGap || r.DecisionAuditCoverage != "sampled-live-tail" {
		t.Fatalf("watch lost selected/NOOP evidence or promoted defense: steps=%d record=%+v", steps, r)
	}
}

func TestVLLMDecisionWindowReadsRotatedAuthenticatedSelection(t *testing.T) {
	now := time.Date(2026, 9, 27, 14, 18, 10, 0, time.UTC)
	selected, noop := vllmWatchRows(t, now)
	dir := t.TempDir()
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	path := filepath.Join(dir, "audit.jsonl")
	writeRow := func(name string, row audit.Record) {
		t.Helper()
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeRow(path, selected)
	serverConfig := audittransport.ServerConfig{AuditPath: path, CertFile: sc, KeyFile: sk,
		CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 2}
	server := httptest.NewUnstartedServer(serverConfig.Handler())
	server.TLS = serverConfig.TLSConfig()
	server.StartTLS()
	defer server.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: server.URL,
		ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{AuditSource: client, Now: func() time.Time { return now.Add(9 * time.Second) }})
	record := vllmWatchRecord(now)
	s.fillReasoning("", record)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeRow(path, noop)
	rows, err := s.readDecisionWindow(context.Background(), "")
	if err != nil || len(rows) != 1 || rows[0].Action != "noop" {
		t.Fatalf("live tail should contain only later NOOP: rows=%v err=%v", rows, err)
	}
	s.fillReasoning("", record)
	if record.DecisionEvidence == nil || record.DecisionEvidence.Action != "rotate" ||
		record.DecisionEvidence.DecisionID != "decision-1" || len(record.DecisionTraceEvidence) != 2 ||
		record.Outcome != "" || record.Actuated {
		t.Fatalf("rotated decision missing or overstated: %+v", record)
	}
}

func TestVLLMDecisionEvidenceChronologyAndPriorBounds(t *testing.T) {
	a := decisionEvidence{Time: "2026-09-27T14:18:10Z", DecisionID: "a"}
	b := decisionEvidence{Time: "2026-09-27T14:18:10.1Z", DecisionID: "b"}
	if !decisionEvidenceTime(a).Before(decisionEvidenceTime(b)) {
		t.Fatal("RFC3339Nano evidence times must be compared chronologically")
	}
	a.PolicyUID = "policy-1"
	b.Time, b.DecisionID, b.PolicyUID = a.Time, a.DecisionID, "policy-2"
	if sameDecisionEvidence(a, b) {
		t.Fatal("different policy incarnations collapsed")
	}
	r := vllmWatchRecord(time.Date(2026, 9, 27, 14, 18, 10, 0, time.UTC))
	prior := decisionEvidence{Correlation: "exact-event-uid", Source: "generic-event-evidence",
		Time: "2026-09-27T14:18:12Z", EventName: "owned-signal", EventUID: "event-uid",
		EventRule: "Panic", TargetUID: "pod-uid", TrustVerdict: "trusted",
		CreatorIdentity: "system:serviceaccount:demo:detector"}
	if !validPriorDecisionEvidence(r, prior, time.Date(2026, 9, 27, 14, 18, 19, 0, time.UTC)) {
		t.Fatal("valid prior row refused")
	}
	prior.Time = "2026-09-27T14:18:22Z"
	if validPriorDecisionEvidence(r, prior, time.Date(2026, 9, 27, 14, 18, 29, 0, time.UTC)) {
		t.Fatal("out-of-window prior row retained")
	}
	prior.Time, prior.CreatorIdentity = "2026-09-27T14:18:12Z", "unknown-creator"
	if validPriorDecisionEvidence(r, prior, time.Date(2026, 9, 27, 14, 18, 19, 0, time.UTC)) {
		t.Fatal("bad creator retained")
	}
}
