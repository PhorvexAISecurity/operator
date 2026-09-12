/*
 * Phorvex — M-18 disclosure scope: the Phoenix forensic payload reaches the operator's
 * raw record path and MUST NOT reach the customer/owner projection.
 */

package console

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func m018Record() audit.Record {
	return audit.Record{
		Kind: "phorvex.decision", Tenant: "team-a", Namespace: "ns", Pod: "p1",
		Action: "rotate", Selected: true, Actuated: true,
		Time: time.Unix(1700000000, 0).UTC(),
		Phoenix: &model.PhoenixForensics{
			AMTDName: "phorvex-ns-team-a", AMTDNamespace: "ns",
			EventName: "phorvex-rotate-vdn2f",
			EventUID:  "3f7c1e02-9a4b-4c1d-8e55-1b2a3c4d5e6f",
			RuleType:  "PhorvexRotate", RuleThreatLevel: "high", RuleSource: "phorvex",
		},
	}
}

// The owner projection is an explicit whitelist and M-18 does not widen it. This is the
// disclosure guard: internal Phoenix resource identities must not become customer-visible.
func TestM018OwnerProjectionDoesNotExposeForensicPayload(t *testing.T) {
	b, err := json.Marshal(ToOwnerEvent(m018Record()))
	if err != nil {
		t.Fatalf("marshal owner event: %v", err)
	}
	got := string(b)
	for _, leaked := range []string{
		"phoenix", "amtdName", "amtdNamespace", "eventName", "eventUID",
		"ruleType", "ruleThreatLevel", "ruleSource",
		"phorvex-ns-team-a", "phorvex-rotate-vdn2f",
		"3f7c1e02-9a4b-4c1d-8e55-1b2a3c4d5e6f",
	} {
		if strings.Contains(got, leaked) {
			t.Errorf("owner projection leaked %q: %s", leaked, got)
		}
	}
	// The projection still works — this is a whitelist, not an empty payload.
	if !strings.Contains(got, `"tenant":"team-a"`) {
		t.Fatalf("owner projection lost its own fields: %s", got)
	}
}

// The operator/investor lens streams the RAW record (live.go: payload = rec), so the
// payload an investigator needs must survive that path unchanged.
func TestM018RawOperatorPathRetainsForensicPayload(t *testing.T) {
	b, err := json.Marshal(m018Record())
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	var back audit.Record
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if back.Phoenix == nil {
		t.Fatalf("raw operator path lost the payload: %s", b)
	}
	if back.Phoenix.EventUID != "3f7c1e02-9a4b-4c1d-8e55-1b2a3c4d5e6f" {
		t.Errorf("eventUID changed: %q", back.Phoenix.EventUID)
	}
}

// Console replay reads saved JSONL back into audit.Record; the payload must survive that
// reader too, since that is how an investigator actually inspects a retained audit.
func TestM018ConsoleReplayRetainsForensicPayload(t *testing.T) {
	line, err := json.Marshal(m018Record())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var seen []audit.Record
	replayAudit(path, 10,
		func(rec audit.Record) bool { return rec.Kind == "phorvex.decision" },
		func(rec audit.Record) { seen = append(seen, rec) },
		func(string) {})

	if len(seen) != 1 {
		t.Fatalf("replayed %d records, want 1", len(seen))
	}
	if seen[0].Phoenix == nil {
		t.Fatal("console replay dropped the forensic payload")
	}
	if seen[0].Phoenix.EventName != "phorvex-rotate-vdn2f" {
		t.Errorf("eventName changed through replay: %q", seen[0].Phoenix.EventName)
	}
}
