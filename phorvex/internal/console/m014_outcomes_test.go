package console

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM014OutcomeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		selected, emitted, dry bool
		dispatch, reason, want string
	}{
		{name: "legacy-emitted", emitted: true, want: "emitted-unconfirmed"},
		{name: "selected", selected: true, want: "selected"},
		{name: "missing", want: "unknown"},
		{name: "dry", selected: true, dry: true, want: "dry-run"},
		{name: "contradictory-dry", emitted: true, dry: true, want: "unknown"},
		{name: "error", selected: true, dispatch: model.DispatchError, want: "unknown"},
		{name: "partial", emitted: true, dispatch: model.DispatchError, want: "unknown"},
		{name: "not-attempted", selected: true, dispatch: model.DispatchNotAttempted, want: "not-attempted"},
		{name: "ambiguous-false", selected: true, dispatch: model.DispatchEmittedFalse, want: "unknown"},
		{name: "verified-refusal", selected: true, dispatch: model.DispatchEmittedFalse, reason: "Rotation not performed: ownerless", want: "not-emitted"},
		{name: "bad-new-vocabulary", emitted: true, dispatch: "confirmed", want: "unknown"},
		{name: "contradictory-emitted", dispatch: model.DispatchEmitted, want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := audit.Record{Action: "rotate", Selected: tc.selected, Actuated: tc.emitted, DryRun: tc.dry, DecisionTrace: &model.DecisionTraceV2{DispatchOutcome: tc.dispatch, DispatchReason: tc.reason}}
			got := ToOwnerEvent(rec)
			if got.OutcomeEvidence != tc.want || got.AttackPrevented || got.WorkPreserved || got.SLOKept || got.Why == "" {
				t.Fatalf("%+v", got)
			}
			if again := ToOwnerEvent(rec); again.Why != got.Why {
				t.Fatal("nondeterministic narrative")
			}
		})
	}
	for _, a := range model.MutatingActions {
		got := ToOwnerEvent(audit.Record{Action: string(a), Selected: true, Actuated: true})
		if got.AttackPrevented || got.WorkPreserved || got.SLOKept {
			t.Fatalf("unsupported claim flags: %+v", got)
		}
	}
	// Unrecognized confirmation fields, including identity/attempt mismatches, are
	// ignored by the real existing decoder. No confirmation branch is implemented.
	for _, confirmation := range []string{`true`, `{"action":"wrong","attempt":"old","policy":"other","uid":"replacement"}`, `"malformed"`} {
		var rec audit.Record
		if err := json.Unmarshal([]byte(`{"action":"rotate","actuated":true,"confirmation":`+confirmation+`}`), &rec); err != nil {
			t.Fatal(err)
		}
		if got := ToOwnerEvent(rec); got.OutcomeEvidence != "emitted-unconfirmed" || !strings.Contains(got.Why, "not confirmed") {
			t.Fatal(got)
		}
	}
}

func TestM014OwnerHTTPReplay(t *testing.T) {
	var records []audit.Record
	for _, a := range []string{"rotate", "quarantine", "kv-reset"} {
		records = append(records, audit.Record{Kind: "phorvex.decision", Time: time.Now(), Tenant: "acme", Namespace: "ns", Pod: "target<script>", Action: a, Selected: true, Actuated: true})
	}
	records = append(records, audit.Record{Kind: "phorvex.decision", Time: time.Now(), Tenant: "acme", Namespace: "ns", Pod: "uncertain", Action: "rotate", Selected: true, DecisionTrace: &model.DecisionTraceV2{DispatchOutcome: model.DispatchError, DispatchReason: "SECRET-private-other-tenant"}})
	records = append(records, audit.Record{Kind: "phorvex.decision", Time: time.Now(), Tenant: "other", Namespace: "other", Pod: "DO-NOT-DISCLOSE", Action: "rotate", Actuated: true})
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var body []byte
	for _, r := range records {
		b, _ := json.Marshal(r)
		body = append(body, append(b, '\n')...)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AuditPath: path}).Handler()
	req := httptest.NewRequest("GET", "/api/owner/events?tenant=acme", nil)
	req.Header.Set("X-Phorvex-Lens", "owner")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var payload struct {
		Events []OwnerEvent   `json:"events"`
		Rollup map[string]int `json:"rollup"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Events) != 4 || payload.Rollup["dispatched"] != 3 || payload.Rollup["isolationAttempts"] != 1 {
		t.Fatal(w.Body.String())
	}
	for _, key := range []string{"attacksPrevented", "workPreserved", "sloKept"} {
		if payload.Rollup[key] != 0 {
			t.Fatal("unsupported rollup", key)
		}
	}
	if strings.Contains(w.Body.String(), "SECRET-private") || strings.Contains(w.Body.String(), "DO-NOT-DISCLOSE") {
		t.Fatal("unsafe disclosure")
	}
	if dest := os.Getenv("M014_OWNER_FIXTURE"); dest != "" {
		if err := os.WriteFile(dest, w.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("synthetic audit -> real owner HTTP projection: 4 visible outcomes, 3 dispatch reports, 1 isolation attempt, zero success claims, tenant filter preserved")
}
