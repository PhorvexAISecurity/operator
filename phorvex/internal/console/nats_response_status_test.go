package console

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNATSResponseStartRefusesMalformedRetainedRunLedger(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "run-events.jsonl"), []byte("{broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rm := NewRunManager(Config{StateDir: state})
	if rm.loadErr == nil {
		t.Fatal("malformed prior run ledger was treated as empty")
	}
	before, err := os.ReadFile(filepath.Join(state, "run-events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dest := runDestination{ScopeTenant: "nats", ScopeTarget: "owned-context", SuiteSHA256: strings.Repeat("a", 64),
		Tenants: []string{"nats", natsFixtureNamespace}, Targets: []string{hostTargetID, "owned-context"}}
	_, err = rm.Start(natsResponseConfig, false, "now", "operator", dest)
	if err == nil || !strings.Contains(err.Error(), "prior NATS run state unavailable") {
		t.Fatalf("unknown prior one-use run did not block launch: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(state, "run-events.jsonl"))
	if err != nil || string(after) != string(before) || rm.seq != 0 || len(rm.runs) != 0 {
		t.Fatalf("refused launch changed retained state: err=%v seq=%d runs=%d", err, rm.seq, len(rm.runs))
	}
}

func TestNATSResponseStatusKeepsOneUseRiskSeparateFromFixtureCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, wantState, wantCleanup string
		result                       NATSResponseResult
		processErr                   error
	}{
		{name: "accepted quarantine with protected capacity debt", wantState: "done", wantCleanup: "VERIFIED",
			result: NATSResponseResult{Accepted: true, CleanupVerified: true, CapacityReservationStatus: "UNRECONCILED_POSSIBLE", Repeatability: "UNKNOWN"}},
		{name: "incomplete packet with verified fixture cleanup", wantState: "partial", wantCleanup: "VERIFIED",
			result:     NATSResponseResult{CleanupVerified: true, CapacityReservationStatus: "UNRECONCILED_POSSIBLE", Repeatability: "UNKNOWN"},
			processErr: errors.New("M1 absent")},
		{name: "unknown effect and cleanup", wantState: "partial", wantCleanup: "UNVERIFIED",
			result:     NATSResponseResult{CapacityReservationStatus: "UNKNOWN", Repeatability: "UNKNOWN"},
			processErr: errors.New("effect uncertain")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &RunStatus{Config: natsResponseConfig}
			finishNATSResponseStatus(st, tc.result, nil, nil, tc.processErr, nil)
			if st.State != tc.wantState || st.CleanupStatus != tc.wantCleanup || !st.UnsafeToRetry {
				t.Fatalf("fixture cleanup falsely cleared one-use risk: %+v", st)
			}
			if st.State == "partial" && st.CleanupStatus == "VERIFIED" && !strings.Contains(st.Error, "repeatability remains unverified") {
				t.Fatalf("partial cleanup message hid protected capacity risk: %+v", st)
			}
		})
	}
}

func TestNATSResponseCompletedCapacityDebtSurvivesRestart(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	rm := NewRunManager(cfg)
	st := &RunStatus{ID: "run-1", Config: natsResponseConfig, Namespace: natsFixtureNamespace}
	finishNATSResponseStatus(st, NATSResponseResult{Accepted: true, CleanupVerified: true,
		CapacityReservationStatus: "UNRECONCILED_POSSIBLE", Repeatability: "UNKNOWN"}, nil, nil, nil, nil)
	if st.State != "done" || st.CleanupStatus != "VERIFIED" || !st.UnsafeToRetry {
		t.Fatalf("completed fixture state lost capacity risk: %+v", st)
	}
	if err := rm.persistStatus(st, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	reloaded := NewRunManager(cfg)
	if reloaded.loadErr != nil || reloaded.runs[st.ID] == nil || !reloaded.runs[st.ID].UnsafeToRetry || reloaded.runs[st.ID].CleanupStatus != "VERIFIED" {
		t.Fatalf("retained one-use risk lost at restart: load=%v status=%+v", reloaded.loadErr, reloaded.runs[st.ID])
	}
	dest := runDestination{ScopeTenant: "nats", ScopeTarget: "owned-context", SuiteSHA256: strings.Repeat("a", 64),
		Tenants: []string{"nats", natsFixtureNamespace}, Targets: []string{hostTargetID, "owned-context"}}
	if _, err := reloaded.Start(natsResponseConfig, false, "now", "operator", dest); err == nil ||
		!strings.Contains(err.Error(), "one-use response repeatability") {
		t.Fatalf("restarted response accepted despite retained capacity debt: %v", err)
	}
}
