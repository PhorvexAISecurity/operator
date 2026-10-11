package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeExperimentCluster struct {
	mu              sync.Mutex
	live            experimentPolicy
	sets            int
	podUID          string
	podFound        bool
	podErr          error
	podReadHook     func()
	eventUID        string
	eventToken      string
	eventFound      bool
	eventRetained   bool
	eventCreateErr  error
	deletedEventUID string
	deletedEvents   int
	eventSeq        int
	deploymentUID   string
	deploymentState string
	targetReads     int
	replaceAtRead   int
}

func (f *fakeExperimentCluster) Policy(context.Context, string) (experimentPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live, nil
}
func (f *fakeExperimentCluster) SetPolicyMode(_ context.Context, old experimentPolicy, mode, op string, clear bool) (experimentPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
func (f *fakeExperimentCluster) DeletePod(_ context.Context, _, _, uid, rv string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if uid != f.podUID || rv != "pod-rv" {
		return errors.New("pod precondition")
	}
	f.podUID = "pod-uid-blind"
	return nil
}
func (f *fakeExperimentCluster) PodUID(context.Context, string, string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.podReadHook != nil {
		f.podReadHook()
	}
	return f.podUID, f.podFound, f.podErr
}
func (f *fakeExperimentCluster) CreateEvent(_ context.Context, _, token, _, _ string) (createdSignalIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eventCreateErr != nil {
		return createdSignalIdentity{}, f.eventCreateErr
	}
	f.eventSeq++
	f.eventUID = fmt.Sprintf("event-%d", f.eventSeq)
	f.eventToken = token
	f.eventFound = true
	if f.live.Mode == "active" {
		f.podUID = fmt.Sprintf("pod-uid-active-%d", f.eventSeq)
	}
	return createdSignalIdentity{UID: f.eventUID, CreatedAt: time.Now().UTC()}, nil
}
func (f *fakeExperimentCluster) EventIdentity(context.Context, string, string) (string, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.eventUID, f.eventToken, f.eventFound, nil
}
func (f *fakeExperimentCluster) DeleteEvent(_ context.Context, _, _, uid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedEventUID = uid
	if !f.eventRetained {
		f.eventFound = false
	}
	f.deletedEvents++
	return nil
}

func (f *fakeExperimentCluster) exec(_ time.Duration, _ string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(joined, "get pod -l r6th.io/rotation-target=true"):
		f.targetReads++
		if f.replaceAtRead > 0 && f.targetReads == f.replaceAtRead {
			f.deploymentUID = "replacement-deploy-uid"
		}
		return fmt.Sprintf("voice-0|%s|pod-rv|ReplicaSet|voice-rs|rs-uid|||True\n", f.podUID), nil
	case strings.Contains(joined, "get replicaset voice-rs"):
		return "rs-uid|Deployment|voice|" + f.currentDeploymentUID(), nil
	case strings.Contains(joined, "get deployment voice") && strings.Contains(joined, "observedGeneration"):
		return f.currentDeploymentUID() + "|" + f.currentDeploymentState(), nil
	case strings.Contains(joined, "get deploy -o name"):
		return "deployment.apps/voice", nil
	case strings.Contains(joined, "get deploy voice --ignore-not-found"):
		return "1|1", nil
	case strings.Contains(joined, "status.readyReplicas}|{.status.replicas"):
		return "1|1", nil
	case strings.Contains(joined, "metadata.uid") && strings.Contains(joined, "get pod voice-0"):
		return f.podUID, nil
	case strings.Contains(joined, "create -f") || strings.Contains(joined, "apply -f"):
		b, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "name:") {
				f.eventSeq++
				f.eventUID = fmt.Sprintf("event-%d", f.eventSeq)
			}
			if strings.HasPrefix(line, "phorvex.ai/console-experiment:") {
				f.eventToken = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "phorvex.ai/console-experiment:")), "\"")
			}
		}
		f.eventFound = true
		if f.live.Mode == "active" {
			f.podUID = fmt.Sprintf("pod-uid-active-%d", f.eventSeq)
		}
		return "created", nil
	default:
		return "", nil
	}
}

func (f *fakeExperimentCluster) currentDeploymentUID() string {
	if f.deploymentUID == "" {
		return "deploy-uid"
	}
	return f.deploymentUID
}

func (f *fakeExperimentCluster) currentDeploymentState() string {
	if f.deploymentState == "" {
		return "1|1|1|1|1|1|1"
	}
	return f.deploymentState
}

func testExperimentPolicy(mode, rv, marker string) experimentPolicy {
	p := experimentPolicy{Namespace: "voice", Name: "policy", UID: "uid-1", ResourceVersion: rv, Mode: mode, Marker: marker, SpecJSON: `{"mode":"` + mode + `","tenant":"voice","actions":{"enabled":["rotate"]}}`, MetadataHash: "meta"}
	p.SpecHash = specHashWithMode(p, mode)
	return p
}

func TestM168TargetResponseDoesNotTreatReadFailureAsReplacement(t *testing.T) {
	s := &Server{cfg: Config{StateDir: t.TempDir()}, runs: NewRunManager(Config{StateDir: t.TempDir()})}
	for _, tc := range []struct {
		name, live string
		found      bool
		err        error
		want       bool
	}{
		{"same UID", "u", true, nil, false}, {"replacement", "u2", true, nil, true}, {"not found", "", false, nil, true}, {"forbidden", "", false, errors.New("forbidden"), false}, {"empty UID", "", true, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeExperimentCluster{podUID: tc.live, podFound: tc.found, podErr: tc.err}
			s.experimentAPI = f
			got, err := s.targetUIDReplaced("voice", "voice-0", "u")
			wantErr := tc.err != nil || tc.name == "empty UID"
			if got != tc.want || wantErr != (err != nil) {
				t.Fatalf("got %v err=%v want %v error=%v", got, err, tc.want, wantErr)
			}
		})
	}
}

func TestM168SyntheticWatcherSeparatesResponseFromAttackerClaims(t *testing.T) {
	resetM168AttackMemory()
	defer resetM168AttackMemory()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	cfg := Config{StateDir: t.TempDir(), Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) }, Exec: (&fakeExperimentCluster{}).exec}
	f := &fakeExperimentCluster{podUID: "replacement", podFound: true}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
	r := &attackRecord{ID: "signal-response", Namespace: "voice", Service: "voice", Deploy: "voice", Pod: "voice-0", TargetUID: "original", AttackID: "foothold", EvidenceKind: "synthetic-detector-signal", UptimeBefore: 100, started: t0, accepted: t0}
	s.watchAttackUntil("", r, t0.Add(5*time.Millisecond), time.Millisecond)
	if r.Status != "done" || !r.ResponseObserved || r.ResponseAction != "rotate" || r.Outcome != "" || r.Action != "" || r.Containment != "" || r.DwellSec != 0 || r.DwellOngoing {
		t.Fatalf("synthetic response overstated attacker evidence: %+v", r)
	}
	if r.Cost != (attackCost{}) || len(realAttackSnapshots(testOwnerPrincipal("voice"))) != 0 {
		t.Fatalf("synthetic signal leaked into attack/cost reporting: cost=%+v real=%+v", r.Cost, realAttackSnapshots(testOwnerPrincipal("voice")))
	}
}

func TestM168SyntheticWatcherRejectsReadCrossingWindow(t *testing.T) {
	resetM168AttackMemory()
	defer resetM168AttackMemory()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	f := &fakeExperimentCluster{podUID: "replacement", podFound: true}
	f.podReadHook = func() { now = now.Add(10 * time.Millisecond) }
	cfg := Config{StateDir: t.TempDir(), Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) }, Exec: f.exec}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
	r := &attackRecord{ID: "late-response", Namespace: "voice", Service: "voice", Deploy: "voice", Pod: "voice-0", TargetUID: "original", AttackID: "foothold", EvidenceKind: "synthetic-detector-signal", UptimeBefore: 100, started: t0, accepted: t0}
	s.watchAttackUntil("", r, t0.Add(5*time.Millisecond), time.Millisecond)
	if r.Status != "partial" || r.ResponseObserved || r.ObservationError == "" || r.Outcome != "" {
		t.Fatalf("out-of-window response was accepted: %+v", r)
	}
}

func TestM168SignalCleanupRequiresOperationAndUIDIdentity(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	f := &fakeExperimentCluster{eventUID: "ev-1", eventToken: "op-1", eventFound: true}
	s.experimentAPI = f
	if err := s.cleanupExperimentSignal("voice", experimentStimulusReceipt{Event: "sig", EventUID: "ev-1", Token: "op-1"}); err != nil || f.deletedEventUID != "ev-1" {
		t.Fatalf("owned cleanup failed: %v uid=%s", err, f.deletedEventUID)
	}
	f.deletedEventUID = ""
	f.eventUID = "replacement"
	f.eventFound = true
	if err := s.cleanupExperimentSignal("voice", experimentStimulusReceipt{Event: "sig", EventUID: "ev-1", Token: "op-1"}); err == nil || f.deletedEventUID != "" {
		t.Fatal("same-name replacement was deleted")
	}
	f.eventUID = "ev-1"
	f.eventToken = "other"
	f.eventFound = true
	if err := s.cleanupExperimentSignal("voice", experimentStimulusReceipt{Event: "sig", Token: "op-1"}); err == nil || f.deletedEventUID != "" {
		t.Fatal("foreign operation signal was deleted")
	}
}

func TestM168SignalCleanupDeleteAckRequiresObservedAbsence(t *testing.T) {
	cfg := Config{StateDir: t.TempDir(), Sleep: func(time.Duration) {}}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	f := &fakeExperimentCluster{eventUID: "ev-1", eventToken: "op-1", eventFound: true, eventRetained: true}
	s.experimentAPI = f
	r := experimentStimulusReceipt{Event: "sig", EventUID: "ev-1", Token: "op-1"}
	if err := s.cleanupExperimentSignal("voice", r); err == nil || !f.eventFound {
		t.Fatalf("retained event was accepted as cleaned: err=%v found=%v", err, f.eventFound)
	}
	f.eventRetained = false
	if err := s.cleanupExperimentSignal("voice", r); err != nil || f.eventFound {
		t.Fatalf("event absence was not established: err=%v found=%v", err, f.eventFound)
	}
}

func TestM168OutcomeClaimsRequirePersistedGroundTruth(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  armEvidence
		want string
	}{
		{"missing", armEvidence{Error: "stimulus failed"}, "unknown"},
		{"landed", armEvidence{StimulusAccepted: true, TargetUID: "u", ObservationPersisted: true, Outcome: "LANDED", Containment: "landed", DwellOngoing: true, AttackID: "a"}, "no"},
		{"neighbor quarantine", armEvidence{StimulusAccepted: true, TargetUID: "u", ObservationPersisted: true, Outcome: "DEFENDED", Containment: "foothold-active", DwellOngoing: true, AttackID: "a"}, "no"},
		{"evicted", armEvidence{StimulusAccepted: true, TargetUID: "u", ObservationPersisted: true, Outcome: "DEFENDED", Containment: "evicted", Action: "rotate", AttackID: "a"}, "yes"},
		{"synthetic response remains unknown", armEvidence{StimulusAccepted: true, TargetUID: "u", TargetPod: "p", DefendedPod: "p", SignalKind: "synthetic-detector-signal", ObservationPersisted: true, ResponseObserved: true, Action: "rotate", AttackID: "a"}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := evidenceVerdict(tc.arm)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestM168AvailabilityRequiresFullOrderedCoverage(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ts := func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339Nano) }
	full := []uptimeSample{{T: ts(0), NS: "voice", Workload: "voice", Desired: 1, Ready: 1}, {T: ts(5 * time.Second), NS: "voice", Workload: "voice", Desired: 1, Ready: 0}, {T: ts(10 * time.Second), NS: "voice", Workload: "voice", Desired: 1, Ready: 1}, {T: ts(15 * time.Second), NS: "voice", Workload: "voice", Desired: 1, Ready: 1}, {T: ts(20 * time.Second), NS: "voice", Workload: "voice", Desired: 1, Ready: 1}}
	start, end := t0.Format(time.RFC3339), t0.Add(20*time.Second).Format(time.RFC3339)
	if got := measureArm(full, "voice", "voice", "a", "A", start, end, "unknown", "", 1); !got.Complete || got.ObservedSeconds < 20 {
		t.Fatalf("full coverage incomplete: %+v", got)
	}
	if got := measureArm(full[:2], "voice", "voice", "a", "A", start, end, "unknown", "", 1); got.Complete {
		t.Fatalf("gapped coverage complete: %+v", got)
	}
	bad := append([]uptimeSample(nil), full...)
	bad[2].Ready = 2
	if got := measureArm(bad, "voice", "voice", "a", "A", start, end, "unknown", "", 1); got.Complete {
		t.Fatalf("impossible replicas complete: %+v", got)
	}
}

func TestM168AvailabilityCompletionRequiresDistinctCorrelatedArmIdentity(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func([]armEvidence)
		bad    map[int]bool
	}{
		{name: "missing target UID", mutate: func(arms []armEvidence) { arms[0].TargetUID = "" }, bad: map[int]bool{0: true}},
		{name: "duplicate attack IDs", mutate: func(arms []armEvidence) { arms[1].AttackID = arms[0].AttackID }, bad: map[int]bool{0: true, 1: true}},
		{name: "foreign deployment owner", mutate: func(arms []armEvidence) { arms[2].TargetOwnerUID = "replacement-deploy-uid" }, bad: map[int]bool{2: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f := &fakeExperimentCluster{podUID: "pod-uid-1"}
			cfg := Config{StateDir: dir, Exec: f.exec}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
			op := "op-correlated"
			if err := s.appendExperiment(experimentEvent{Operation: op, Phase: "complete", Namespace: "voice", Deployment: "voice", DeploymentUID: "deploy-uid"}); err != nil {
				t.Fatal(err)
			}
			arms := make([]armEvidence, 3)
			for i := range arms {
				start := t0.Add(time.Duration(i) * 20 * time.Second)
				arms[i] = armEvidence{ID: fmt.Sprintf("arm-%d", i), Label: fmt.Sprintf("Arm %d", i), Start: start.Format(time.RFC3339Nano), End: start.Add(10 * time.Second).Format(time.RFC3339Nano), ObservationSeconds: 10, StimulusAccepted: true, AttackID: fmt.Sprintf("attack-%d", i), TargetPod: "voice-0", TargetUID: fmt.Sprintf("pod-%d", i), TargetOwnerUID: "deploy-uid", ObservationPersisted: true, BaselineReady: true, SignalKind: "synthetic-detector-signal"}
				for _, at := range []time.Time{start, start.Add(5 * time.Second), start.Add(10 * time.Second)} {
					b, _ := json.Marshal(uptimeSample{T: at.Format(time.RFC3339Nano), NS: "voice", Workload: "voice", Desired: 1, Ready: 1})
					if err := cfg.appendState(uptimePath(cfg), b); err != nil {
						t.Fatal(err)
					}
				}
			}
			tc.mutate(arms)
			b, _ := json.Marshal(armExperiment{Operation: op, RunAt: t0.Format(time.RFC3339), Namespace: "voice", Deploy: "voice", Attack: "foothold", Arms: arms, Restored: true})
			if err := cfg.appendState(armsPath(cfg), b); err != nil {
				t.Fatal(err)
			}
			req := withTestPrincipal(httptest.NewRequest("GET", "/api/availability-arms?ns=voice", nil), testOwnerPrincipal("voice"))
			rw := httptest.NewRecorder()
			s.availabilityArms(rw, req)
			var rendered armsResponse
			if err := json.Unmarshal(rw.Body.Bytes(), &rendered); err != nil {
				t.Fatal(err)
			}
			if len(rendered.Runs) != 1 || len(rendered.Runs[0].Arms) != 3 {
				t.Fatalf("unexpected response: %s", rw.Body.String())
			}
			for i, arm := range rendered.Runs[0].Arms {
				wantComplete := !tc.bad[i]
				if arm.Complete != wantComplete {
					t.Fatalf("arm %d completion=%v, want %v", i, arm.Complete, wantComplete)
				}
			}
		})
	}
}

func resetM168AttackMemory() {
	attackMu.Lock()
	attackList = nil
	attackLoaded = false
	attackMu.Unlock()
}

func TestM168ArmsWorkerUsesProductionSignalWatcherAndLedger(t *testing.T) {
	resetM168AttackMemory()
	defer resetM168AttackMemory()
	dir := t.TempDir()
	f := &fakeExperimentCluster{live: testExperimentPolicy("active", "rv-1", ""), podUID: "pod-uid-1", podFound: true}
	cfg := Config{StateDir: dir, Exec: f.exec, AttackWatchDuration: 30 * time.Millisecond, AttackWatchInterval: 2 * time.Millisecond, BlindRotationDelay: 8 * time.Millisecond}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
	op := experimentEvent{Operation: "op-all", Phase: "prepared", Actor: "tester", Namespace: "voice", Attack: "foothold", Deployment: "voice", DeploymentUID: "deploy-uid", Policy: f.live, OriginalMode: "active", OwnedMode: "active", OwnedSpecHash: f.live.SpecHash, OwnedMetadataHash: f.live.MetadataHash}
	if err := s.appendExperiment(op); err != nil {
		t.Fatal(err)
	}
	// A controller status write may advance resourceVersion without changing the
	// user-controlled spec/metadata fingerprints. The worker must fresh-read and
	// CAS that version instead of rejecting a benign status-only update.
	f.live.ResourceVersion = "rv-status-only"
	s.armsWorker(op, "voice")
	b, err := readStateLedger(armsPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var run armExperiment
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if err = json.Unmarshal([]byte(line), &run); err != nil {
			t.Fatal(err)
		}
	}
	if !run.Restored || len(run.Arms) != 3 {
		t.Fatalf("incomplete run: %+v", run)
	}
	ids := map[string]bool{}
	for _, a := range run.Arms {
		start, _ := time.Parse(time.RFC3339Nano, a.Start)
		end, _ := time.Parse(time.RFC3339Nano, a.End)
		if end.Sub(start) != 30*time.Millisecond || a.ObservationSeconds != 0.03 {
			t.Errorf("%s unequal registered window: %s / %v", a.ID, end.Sub(start), a.ObservationSeconds)
		}
		if !a.StimulusAccepted || !a.ObservationPersisted || a.AttackID == "" || a.TargetUID == "" || a.EventUID == "" {
			t.Errorf("%s missing correlation: %+v", a.ID, a)
		}
		if ids[a.AttackID] {
			t.Errorf("duplicate attack ID %s", a.AttackID)
		}
		ids[a.AttackID] = true
		stopped, _ := evidenceVerdict(a)
		if stopped != "unknown" {
			t.Errorf("synthetic arm claimed attacker stopped: %s", stopped)
		}
	}
	attackMu.Lock()
	records := make([]*attackRecord, len(attackList))
	for i := range attackList {
		records[i] = cloneAttackRecord(attackList[i])
	}
	attackMu.Unlock()
	if len(records) == 0 {
		t.Fatal("voice observations missing")
	}
	for _, record := range records {
		if record.StimulusEvidence == nil || !record.StimulusEvidence.Observed || record.StimulusEvidence.EventUID == "" ||
			record.StimulusEvidence.TargetUID == "" || record.StimulusEvidence.EventCreatedAt == "" || record.StimulusEvidence.BehavioralExecuted ||
			record.ProducerRoute != "/api/workload/attack" || record.ResultSchema != "synthetic-detector-signal-v2" {
			t.Fatalf("voice attack record dropped typed event identity: %+v", record)
		}
		if record.LiveFire {
			t.Fatalf("a comparison arm must not join the Live observation view: %+v", record.ID)
		}
	}
	if run.Arms[0].Outcome != "" || run.Arms[0].ResponseObserved || !run.Arms[1].ResponseObserved || !run.Arms[2].ResponseObserved || run.Arms[1].DefendedPod != run.Arms[1].TargetPod || run.Arms[2].DefendedPod != run.Arms[2].TargetPod {
		t.Fatalf("unexpected identity-bound responses: %+v", run.Arms)
	}
	for _, a := range run.Arms {
		for _, at := range []string{a.Start, a.End} {
			sample, _ := json.Marshal(uptimeSample{T: at, NS: "voice", Workload: "voice", Desired: 1, Ready: 1})
			if err := cfg.appendState(uptimePath(cfg), sample); err != nil {
				t.Fatal(err)
			}
		}
	}
	req := withTestPrincipal(httptest.NewRequest("GET", "/api/availability-arms?ns=voice", nil), testOwnerPrincipal("voice"))
	rw := httptest.NewRecorder()
	s.availabilityArms(rw, req)
	var rendered armsResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &rendered); err != nil {
		t.Fatal(err)
	}
	if len(rendered.Runs) != 1 || len(rendered.Runs[0].Arms) != 3 {
		t.Fatalf("renderer omitted arms: %s", rw.Body.String())
	}
	for i, a := range rendered.Runs[0].Arms {
		if !a.Complete || a.AttackerStopped != "unknown" {
			t.Errorf("rendered arm %d overclaimed/incomplete: %+v", i, a)
		}
		if a.ResponseObserved != (i > 0) {
			t.Errorf("rendered arm %d response=%v", i, a.ResponseObserved)
		}
	}
	f.mu.Lock()
	deletes, mode, marker := f.deletedEvents, f.live.Mode, f.live.Marker
	f.mu.Unlock()
	if deletes != 3 || mode != "active" || marker != "" {
		t.Fatalf("cleanup/restoration: deletes=%d mode=%s marker=%s", deletes, mode, marker)
	}
}

func TestM168ResettableTargetRequiresFullyObservedDesiredReplicas(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		wantErr     bool
	}{
		{name: "stable", state: "4|4|3|3|3|3|3"},
		{name: "under desired", state: "4|4|3|1|1|1|1", wantErr: true},
		{name: "stale generation", state: "4|3|3|3|3|3|3", wantErr: true},
		{name: "malformed count", state: "4|4|3|3|bad|3|3", wantErr: true},
		{name: "unavailable replica", state: "4|4|3|3|3|3|2", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeExperimentCluster{podUID: "pod-uid-1", deploymentState: tc.state}
			cfg := Config{StateDir: t.TempDir(), Exec: f.exec}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
			_, err := s.resettableTarget("voice")
			if (err != nil) != tc.wantErr {
				t.Fatalf("resettableTarget error=%v, want error=%v", err, tc.wantErr)
			}
		})
	}
}

func TestM168ArmsWorkerRejectsDeploymentReplacementBetweenArms(t *testing.T) {
	resetM168AttackMemory()
	defer resetM168AttackMemory()
	dir := t.TempDir()
	f := &fakeExperimentCluster{live: testExperimentPolicy("active", "rv-1", ""), podUID: "pod-uid-1", podFound: true, replaceAtRead: 4}
	cfg := Config{StateDir: dir, Exec: f.exec, AttackWatchDuration: 500 * time.Millisecond, AttackWatchInterval: 10 * time.Millisecond, BlindRotationDelay: 4 * time.Millisecond}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
	op := experimentEvent{Operation: "op-replaced-deploy", Phase: "prepared", Actor: "tester", Namespace: "voice", Attack: "foothold", Deployment: "voice", DeploymentUID: "deploy-uid", Policy: f.live, OriginalMode: "active", OwnedMode: "active", OwnedSpecHash: f.live.SpecHash, OwnedMetadataHash: f.live.MetadataHash}
	if err := s.appendExperiment(op); err != nil {
		t.Fatal(err)
	}
	s.armsWorker(op, "voice")
	if _, err := os.Stat(armsPath(cfg)); !os.IsNotExist(err) {
		t.Fatalf("deployment replacement produced a comparable result: %v", err)
	}
	latest, err := retainedExperimentEvents(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := latest[op.Operation]; got.Phase != "incomplete-restored" || !strings.Contains(got.Error, "deployment identity changed") {
		t.Fatalf("replacement was not retained as incomplete: %+v", got)
	}
}

func TestM168ArmsWorkerRequiresDurableResultAndCompletionMarker(t *testing.T) {
	for _, tc := range []struct {
		name            string
		failResult      bool
		failFinalMarker bool
		wantResult      bool
	}{
		{name: "result write failure", failResult: true},
		{name: "final marker failure", failFinalMarker: true, wantResult: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetM168AttackMemory()
			defer resetM168AttackMemory()
			dir := t.TempDir()
			f := &fakeExperimentCluster{live: testExperimentPolicy("active", "rv-1", ""), podUID: "pod-uid-1", podFound: true}
			failed := false
			cfg := Config{StateDir: dir, Exec: f.exec, AttackWatchDuration: 20 * time.Millisecond, AttackWatchInterval: time.Millisecond, BlindRotationDelay: 4 * time.Millisecond}
			cfg.StateAppend = func(path string, record []byte) error {
				if !failed && tc.failResult && path == armsPath(cfg) {
					failed = true
					return errors.New("result fsync failed")
				}
				if !failed && tc.failFinalMarker && path == experimentEventsPath(cfg) {
					var e experimentEvent
					if json.Unmarshal(record, &e) == nil && e.Phase == "complete" {
						failed = true
						return errors.New("completion fsync failed")
					}
				}
				return appendState(path, record)
			}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
			op := experimentEvent{Operation: "op-durability", Phase: "prepared", Actor: "tester", Namespace: "voice", Attack: "foothold", Deployment: "voice", DeploymentUID: "deploy-uid", Policy: f.live, OriginalMode: "active", OwnedMode: "active", OwnedSpecHash: f.live.SpecHash, OwnedMetadataHash: f.live.MetadataHash}
			if err := s.appendExperiment(op); err != nil {
				t.Fatal(err)
			}
			s.armsWorker(op, "voice")
			if !failed {
				t.Fatal("configured persistence failure was not reached")
			}
			latest, err := retainedExperimentEvents(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := latest[op.Operation]; got.Phase != "incomplete-restored" {
				t.Fatalf("persistence failure was marked terminally complete: %+v", got)
			}
			b, readErr := readStateLedger(armsPath(cfg))
			if tc.wantResult != (readErr == nil && len(b) > 0) {
				t.Fatalf("result presence=%v, want %v (err=%v)", readErr == nil && len(b) > 0, tc.wantResult, readErr)
			}
			if !tc.wantResult {
				return
			}
			var run armExperiment
			if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &run); err != nil {
				t.Fatal(err)
			}
			for _, a := range run.Arms {
				for _, at := range []string{a.Start, a.End} {
					sample, _ := json.Marshal(uptimeSample{T: at, NS: "voice", Workload: "voice", Desired: 1, Ready: 1})
					if err := cfg.appendState(uptimePath(cfg), sample); err != nil {
						t.Fatal(err)
					}
				}
			}
			req := withTestPrincipal(httptest.NewRequest("GET", "/api/availability-arms?ns=voice", nil), testOwnerPrincipal("voice"))
			rw := httptest.NewRecorder()
			s.availabilityArms(rw, req)
			var rendered armsResponse
			if err := json.Unmarshal(rw.Body.Bytes(), &rendered); err != nil {
				t.Fatal(err)
			}
			if len(rendered.Runs) != 1 || len(rendered.Runs[0].Arms) != 3 {
				t.Fatalf("retained result was not rendered as evidence: %s", rw.Body.String())
			}
			for _, a := range rendered.Runs[0].Arms {
				if a.Complete {
					t.Fatalf("arm was complete without durable final marker: %+v", a)
				}
			}
		})
	}
}

func TestM168ArmsWorkerFailureRestoresOriginalMode(t *testing.T) {
	resetM168AttackMemory()
	defer resetM168AttackMemory()
	dir := t.TempDir()
	f := &fakeExperimentCluster{live: testExperimentPolicy("active", "rv-1", ""), podUID: "pod-uid-1", podFound: true}
	f.eventCreateErr = errors.New("create failed")
	cfg := Config{StateDir: dir, Exec: f.exec, AttackWatchDuration: 5 * time.Millisecond, AttackWatchInterval: time.Millisecond}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
	op := experimentEvent{Operation: "op-fail", Phase: "prepared", Actor: "tester", Namespace: "voice", Attack: "foothold", Deployment: "voice", DeploymentUID: "deploy-uid", Policy: f.live, OriginalMode: "active", OwnedMode: "active", OwnedSpecHash: f.live.SpecHash, OwnedMetadataHash: f.live.MetadataHash}
	_ = s.appendExperiment(op)
	s.armsWorker(op, "voice")
	f.mu.Lock()
	mode, marker := f.live.Mode, f.live.Marker
	f.mu.Unlock()
	if mode != "active" || marker != "" {
		t.Fatalf("failure stranded policy: mode=%s marker=%s", mode, marker)
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

func TestM168RecoveryRefusesConcurrentMetadataEdit(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir}
	base := testExperimentPolicy("active", "rv-1", "")
	expected := testExperimentPolicy("dryRun", "rv-2", "op-1")
	live := expected
	live.MetadataHash = "concurrent-user-metadata"
	e := experimentEvent{Operation: "op-1", Phase: "transition-intent", Namespace: "voice", Policy: base, OriginalMode: "active", OwnedMode: "dryRun", OwnedSpecHash: expected.SpecHash, OwnedMetadataHash: expected.MetadataHash}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	f := &fakeExperimentCluster{live: live}
	s.experimentAPI = f
	if err := s.appendExperiment(e); err != nil {
		t.Fatal(err)
	}
	s.recoverExperiments()
	if f.sets != 0 || len(s.unresolvedExperiments()) != 1 {
		t.Fatalf("concurrent metadata edit was overwritten or released: sets=%d unresolved=%+v", f.sets, s.unresolvedExperiments())
	}
}

func TestM168RecoveryRestoresPolicyButRetainsCleanupFailureUntilNextRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir, Sleep: func(time.Duration) {}}
	base := testExperimentPolicy("active", "rv-1", "")
	live := testExperimentPolicy("dryRun", "rv-2", "op-1")
	e := experimentEvent{Operation: "op-1", Phase: "stimulus-accepted", Namespace: "voice", Policy: base, OriginalMode: "active", OwnedMode: "dryRun", OwnedSpecHash: live.SpecHash, OwnedMetadataHash: live.MetadataHash, Arm: &armEvidence{Event: "sig", EventUID: "event-1"}}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	f := &fakeExperimentCluster{live: live, eventUID: "event-1", eventToken: "op-1", eventFound: true, eventRetained: true}
	s.experimentAPI = f
	if err := s.appendExperiment(e); err != nil {
		t.Fatal(err)
	}
	s.recoverExperiments()
	if f.live.Mode != "active" || f.live.Marker != "" || len(s.unresolvedExperiments()) != 1 {
		t.Fatalf("first restart did not restore safely and retain cleanup ownership: live=%+v unresolved=%+v", f.live, s.unresolvedExperiments())
	}
	f.eventRetained = false
	s.recoverExperiments()
	if len(s.unresolvedExperiments()) != 0 || f.eventFound {
		t.Fatalf("second restart did not finish owned cleanup: unresolved=%+v found=%v", s.unresolvedExperiments(), f.eventFound)
	}
}

func TestM168AbortRestoresPolicyButDoesNotTerminalizeUncertainCleanup(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir, Sleep: func(time.Duration) {}}
	base := testExperimentPolicy("active", "rv-1", "")
	live := testExperimentPolicy("dryRun", "rv-2", "op-1")
	op := experimentEvent{Operation: "op-1", Phase: "stimulus-accepted", Namespace: "voice", Policy: base, OriginalMode: "active", OwnedMode: "dryRun", OwnedSpecHash: live.SpecHash, OwnedMetadataHash: live.MetadataHash}
	f := &fakeExperimentCluster{live: live, eventUID: "event-1", eventToken: "op-1", eventFound: true, eventRetained: true}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
	err := s.abortExperiment(&op, []experimentStimulusReceipt{{Event: "sig", EventUID: "event-1", Token: "op-1"}})
	if err == nil || op.Phase != "recovery-required" || f.live.Mode != "active" || f.live.Marker != "" {
		t.Fatalf("abort lost cleanup ownership or restoration: phase=%s err=%v live=%+v", op.Phase, err, f.live)
	}
	if err = s.appendExperiment(op); err != nil {
		t.Fatal(err)
	}
	if len(s.unresolvedExperiments()) != 1 {
		t.Fatal("uncertain cleanup no longer blocks duplicate experiment")
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

func TestM168RunEntryRefusesJournalCorruptionBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "experiment-events.jsonl"), []byte("not-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeExperimentCluster{live: testExperimentPolicy("active", "rv-1", ""), podUID: "pod-uid-1", podFound: true}
	cfg := Config{StateDir: dir, Exec: f.exec}
	// Construct directly so corruption is first discovered by this request rather
	// than by NewServer's startup recovery pass.
	s := &Server{cfg: cfg, runs: NewRunManager(cfg), experimentAPI: f}
	req := withTestPrincipal(httptest.NewRequest("POST", "/api/availability-arms/run", strings.NewReader(`{"namespace":"voice","attack":"foothold"}`)), testOwnerPrincipal("voice"))
	rw := httptest.NewRecorder()
	s.runArmsExperiment(rw, req)
	if rw.Code != 503 || !strings.Contains(rw.Body.String(), "experiment state unavailable") {
		t.Fatalf("corrupt journal response = %d %s", rw.Code, rw.Body.String())
	}
	f.mu.Lock()
	sets, events := f.sets, f.eventSeq
	f.mu.Unlock()
	if sets != 0 || events != 0 {
		t.Fatalf("corrupt journal allowed effects: policy sets=%d events=%d", sets, events)
	}
}
