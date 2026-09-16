package console

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type fakeExperimentCluster struct {
	live experimentPolicy
	sets int
}

func (f *fakeExperimentCluster) Policy(context.Context, string) (experimentPolicy, error) {
	return f.live, nil
}
func (f *fakeExperimentCluster) SetPolicyMode(_ context.Context, old experimentPolicy, mode, op string, clear bool) (experimentPolicy, error) {
	f.sets++
	if old.UID != f.live.UID || old.ResourceVersion != f.live.ResourceVersion {
		return experimentPolicy{}, context.Canceled
	}
	f.live.Mode = mode
	f.live.ResourceVersion = "rv-restored"
	f.live.SpecHash = specHashWithMode(f.live, mode)
	if clear {
		f.live.Marker = ""
	} else {
		f.live.Marker = op
	}
	return f.live, nil
}
func (*fakeExperimentCluster) DeletePod(context.Context, string, string, string, string) error {
	return nil
}

func testExperimentPolicy(mode, rv, marker string) experimentPolicy {
	p := experimentPolicy{Namespace: "voice", Name: "policy", UID: "uid-1", ResourceVersion: rv, Mode: mode, Marker: marker, SpecJSON: `{"mode":"` + mode + `","tenant":"voice"}`, MetadataHash: "meta"}
	p.SpecHash = specHashWithMode(p, mode)
	return p
}

func TestM168OutcomeClaimsRequirePersistedGroundTruth(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  armEvidence
		want string
	}{
		{"missing", armEvidence{Error: "stimulus failed"}, "unknown"},
		{"landed", armEvidence{ObservationPersisted: true, Outcome: "LANDED", Containment: "landed", DwellOngoing: true, AttackID: "a"}, "no"},
		{"neighbor quarantine", armEvidence{ObservationPersisted: true, Outcome: "DEFENDED", Containment: "foothold-active", DwellOngoing: true, AttackID: "a"}, "no"},
		{"evicted", armEvidence{ObservationPersisted: true, Outcome: "DEFENDED", Containment: "evicted", Action: "rotate", AttackID: "a"}, "yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := evidenceVerdict(tc.arm)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestM168RecoverPatchBeforeAckOnlyWhenOwnedFingerprintMatches(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir}
	base := testExperimentPolicy("active", "rv-1", "")
	live := testExperimentPolicy("dryRun", "rv-2", "op-1")
	e := experimentEvent{Operation: "op-1", Phase: "transition-intent", Namespace: "voice", Policy: base, OriginalMode: "active", OwnedMode: "dryRun", OwnedSpecHash: live.SpecHash, OwnedMetadataHash: live.MetadataHash}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	f := &fakeExperimentCluster{live: live}
	s.experimentAPI = f
	if err := s.appendExperiment(e); err != nil {
		t.Fatal(err)
	}
	s.recoverExperiments()
	if f.sets != 1 || f.live.Mode != "active" || f.live.Marker != "" {
		t.Fatalf("owned recovery not completed: sets=%d live=%+v", f.sets, f.live)
	}
}

func TestM168RecoveryRefusesConcurrentSpecEdit(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir}
	base := testExperimentPolicy("active", "rv-1", "")
	expected := testExperimentPolicy("dryRun", "rv-2", "op-1")
	live := expected
	live.SpecHash = "concurrent-edit"
	e := experimentEvent{Operation: "op-1", Phase: "transition-intent", Namespace: "voice", Policy: base, OriginalMode: "active", OwnedMode: "dryRun", OwnedSpecHash: expected.SpecHash, OwnedMetadataHash: expected.MetadataHash}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	f := &fakeExperimentCluster{live: live}
	s.experimentAPI = f
	if err := s.appendExperiment(e); err != nil {
		t.Fatal(err)
	}
	s.recoverExperiments()
	if f.sets != 0 {
		t.Fatal("concurrent edit was overwritten")
	}
	if len(s.unresolvedExperiments()) != 1 {
		t.Fatal("recovery conflict was not retained")
	}
}

func TestM168MalformedJournalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "experiment-events.jsonl"), []byte("not-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: dir}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	s.experimentAPI = &fakeExperimentCluster{}
	s.recoverExperiments()
	if ok, _ := s.stateStatus(); ok {
		t.Fatal("malformed journal did not fail closed")
	}
}
