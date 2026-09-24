package cataloguev1

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type voiceRecorder struct {
	mu      sync.Mutex
	intents []Intent
	events  []Event
}

func (r *voiceRecorder) Intent(value Intent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.intents = append(r.intents, value)
	return nil
}
func (r *voiceRecorder) Event(value Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, value)
	return nil
}
func (*voiceRecorder) Metric(Metric) error             { return nil }
func (*voiceRecorder) MetricRaw(json.RawMessage) error { return nil }
func (*voiceRecorder) Result(Result) error             { return nil }

type fakeVoiceDriver struct {
	mu               sync.Mutex
	baseline         VoiceSnapshot
	recovered        VoiceSnapshot
	replacementAfter bool
	eviction         VoiceEviction
	evictions        int
	cleanup          VoiceCleanup
	source           string
	mediaError       string
	mediaDelay       time.Duration
}

func (f *fakeVoiceDriver) Snapshot(context.Context, VoiceConfig) (VoiceSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.replacementAfter {
		return f.recovered, nil
	}
	return f.baseline, nil
}
func (f *fakeVoiceDriver) SourceSHA256(context.Context, VoiceConfig, VoicePod) (string, error) {
	return f.source, nil
}
func (f *fakeVoiceDriver) CanEvict(context.Context, VoiceConfig) error { return nil }
func (f *fakeVoiceDriver) RunMedia(ctx context.Context, _ VoiceConfig, _ VoicePod, session VoiceSession, _ []byte, interrupt func(context.Context) (VoiceEviction, error)) VoiceSession {
	if f.mediaDelay > 0 {
		time.Sleep(f.mediaDelay)
	}
	session.TelephoneCalls, session.StartSent, session.IdlePingPong = 0, true, true
	session.MediaFramesSent, session.MediaFramesReceived, session.MediaBytesReceived = 683, 2, 640
	session.ReceivedAudioSHA256 = strings.Repeat("a", 64)
	session.FirstAudioSeconds = 0.5
	session.ForwardClosed = true
	if interrupt == nil {
		session.StopSent, session.CloseWasTestInitiated, session.CloseCode = true, true, 1000
	} else {
		receipt, err := interrupt(ctx)
		if err != nil {
			session.Error = err.Error()
			return session
		}
		session.Eviction = &receipt
		session.ImmediatePreEvictionPingPong = true
		if receipt.Disposition != EvictionAccepted {
			session.CloseWasTestInitiated = true
		}
	}
	if f.mediaError != "" {
		session.Error = f.mediaError
	}
	return session
}
func (f *fakeVoiceDriver) Evict(context.Context, VoiceConfig, VoicePod) VoiceEviction {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evictions++
	if f.eviction.Disposition == EvictionAccepted {
		f.replacementAfter = true
	}
	return f.eviction
}
func (f *fakeVoiceDriver) CleanupTranscripts(_ context.Context, _ VoiceConfig, _ VoicePod, callSIDs []string, onIntent func(TranscriptRef) error, onResult func(TranscriptRef) error) VoiceCleanup {
	for i, sid := range callSIDs {
		ref := TranscriptRef{CallSID: sid, ObjectID: "507f1f77bcf86cd79943901" + string(rune('0'+i)), ContentSHA256: strings.Repeat("b", 64)}
		if err := onIntent(ref); err != nil {
			return VoiceCleanup{Status: "FAIL", UnsafeToRetry: true, Error: err.Error()}
		}
		if err := onResult(ref); err != nil {
			return VoiceCleanup{Status: "FAIL", UnsafeToRetry: true, Error: err.Error()}
		}
	}
	return f.cleanup
}

func testVoiceConfig(mode VoiceMode) VoiceConfig {
	return VoiceConfig{SchemaVersion: "phorvex.catalogue.voice.v1", Mode: mode, OperationID: "v1run-7", OwnerDigest: strings.Repeat("a", 64), Namespace: "voice", DeploymentName: "voice-bot", ServiceName: "voice-bot", PDBName: "voice-bot", ContainerName: "bot", Port: 8080, ExpectedReplicas: 3, MinimumReady: 2, ExpectedImageDigest: voiceExpectedImage, BotSourcePath: "/app/bot.py", BotSourceSHA256: voiceExpectedSourceSHA, AudioSHA256: VoiceAudioSHA256}
}

func testVoiceSnapshot(replacement bool) VoiceSnapshot {
	pods := []VoicePod{
		{Name: "voice-bot-a", UID: "pod-a", ResourceVersion: "10", ReplicaSetName: "voice-bot-rs", ReplicaSetUID: "rs-1", Ready: true, Started: true, ImageID: "registry/voice@" + voiceExpectedImage, ContainerID: "containerd://a"},
		{Name: "voice-bot-b", UID: "pod-b", ResourceVersion: "11", ReplicaSetName: "voice-bot-rs", ReplicaSetUID: "rs-1", Ready: true, Started: true, ImageID: "registry/voice@" + voiceExpectedImage, ContainerID: "containerd://b"},
		{Name: "voice-bot-c", UID: "pod-c", ResourceVersion: "12", ReplicaSetName: "voice-bot-rs", ReplicaSetUID: "rs-1", Ready: true, Started: true, ImageID: "registry/voice@" + voiceExpectedImage, ContainerID: "containerd://c"},
	}
	if replacement {
		pods[0] = VoicePod{Name: "voice-bot-d", UID: "pod-d", ResourceVersion: "20", ReplicaSetName: "voice-bot-rs", ReplicaSetUID: "rs-1", Ready: true, Started: true, ImageID: "registry/voice@" + voiceExpectedImage, ContainerID: "containerd://d"}
	}
	return VoiceSnapshot{At: time.Now(), NamespaceUID: "ns-1", DeploymentUID: "dep-1", DeploymentGeneration: 18, DeploymentObservedGeneration: 18, DeploymentSpecSHA256: strings.Repeat("1", 64), ReplicaSetUID: "rs-1", ReplicaSetGeneration: 1, ReplicaSetSpecSHA256: strings.Repeat("2", 64), ServiceUID: "svc-1", ServiceSpecSHA256: strings.Repeat("3", 64), PDBUID: "pdb-1", PDBGeneration: 1, PDBObservedGeneration: 1, PDBSpecSHA256: strings.Repeat("4", 64), PDBDisruptionsAllowed: 1, PDBCurrentHealthy: 3, PDBDesiredHealthy: 2, PDBExpectedPods: 3, DeploymentReplicas: 3, DeploymentUpdatedReplicas: 3, DeploymentReadyReplicas: 3, DeploymentAvailableReplicas: 3, ReplicaSetReplicas: 3, ReplicaSetReadyReplicas: 3, ReplicaSetAvailableReplicas: 3, ReadyEndpointUIDs: []string{pods[0].UID, pods[1].UID, pods[2].UID}, Pods: pods}
}

func TestVoiceNormalResultIncludesDeferredCleanup(t *testing.T) {
	driver := &fakeVoiceDriver{baseline: testVoiceSnapshot(false), recovered: testVoiceSnapshot(false), source: voiceExpectedSourceSHA, cleanup: VoiceCleanup{Status: "PASS", ForwardsClosed: true}}
	recorder := &voiceRecorder{}
	result := runVoice(context.Background(), testVoiceConfig(VoiceNormalMedia), driver, recorder)
	if result.Outcome != VoiceOutcomeMediaPass || result.Cleanup.Status != "PASS" || result.FinishedAt.IsZero() || len(result.Sessions) != 1 {
		t.Fatalf("result did not retain terminal cleanup: %#v", result)
	}
	if driver.evictions != 0 {
		t.Fatalf("normal media dispatched %d evictions", driver.evictions)
	}
	projected := projectVoiceResult(NewVoiceMediaHandler().Definition(), result, time.Now())
	identity := projected.Evidence
	if result.Target == nil || result.Target.UID != "pod-a" || identity["targetPodUID"] != "pod-a" ||
		identity["targetImageID"] != driver.baseline.Pods[0].ImageID || identity["targetContainerID"] != driver.baseline.Pods[0].ContainerID ||
		identity["podSourceFileSHA256"] != voiceExpectedSourceSHA ||
		identity["session1.callSID"] != result.Sessions[0].CallSID || identity["session1.streamSID"] != result.Sessions[0].StreamSID ||
		result.sessionIntentsRecorded != 1 {
		t.Fatalf("durable synthetic session and serving identity projection differs: %#v", identity)
	}
	if _, exposed := identity["session1.accountSID"]; exposed {
		t.Fatal("synthetic account identity leaked to run evidence")
	}
	foundIntent := false
	for _, intent := range recorder.intents {
		if intent.Step == "voice.session" && intent.Identity["callSID"] == identity["session1.callSID"] && intent.Identity["streamSID"] == identity["session1.streamSID"] {
			foundIntent = true
		}
	}
	if !foundIntent {
		t.Fatal("projected synthetic session lacks its durable intent")
	}
}

func TestVoiceProjectionRequiresSessionIntentAndObservedSource(t *testing.T) {
	result := VoiceResult{Outcome: VoiceOutcomeIncomplete, Sessions: []VoiceSession{
		{Phase: "interrupted", CallSID: "CA-first", StreamSID: "MZ-first"},
		{Phase: "recovery", CallSID: "CA-unrecorded", StreamSID: "MZ-unrecorded"},
	}, sessionIntentsRecorded: 1}
	projected := projectVoiceResult(NewVoiceRecoveryHandler().Definition(), result, time.Now())
	if projected.Evidence["session1.callSID"] != "CA-first" {
		t.Fatal("persisted first session identity absent")
	}
	for _, key := range []string{"session2.callSID", "session2.streamSID", "podSourceFileSHA256", "targetPodUID"} {
		if _, exposed := projected.Evidence[key]; exposed {
			t.Fatalf("unrecorded or unobserved identity projected: %s", key)
		}
	}
	driver := &fakeVoiceDriver{baseline: testVoiceSnapshot(false), source: strings.Repeat("0", 64)}
	unverified := runVoice(context.Background(), testVoiceConfig(VoiceNormalMedia), driver, &voiceRecorder{})
	if unverified.PodSourceFileSHA256 != "" || unverified.Target != nil || len(unverified.Sessions) != 0 {
		t.Fatalf("source mismatch exposed target/session identity: %#v", unverified)
	}
}

func TestVoiceCleanupFailureDemotesSuccessfulMedia(t *testing.T) {
	driver := &fakeVoiceDriver{baseline: testVoiceSnapshot(false), source: voiceExpectedSourceSHA, cleanup: VoiceCleanup{Status: "FAIL", ForwardsClosed: true, UnsafeToRetry: true}}
	result := runVoice(context.Background(), testVoiceConfig(VoiceNormalMedia), driver, &voiceRecorder{})
	if result.Outcome != VoiceOutcomeIncomplete || !result.RecoveryRequired || !result.Cleanup.UnsafeToRetry {
		t.Fatalf("cleanup failure was not retained: %#v", result)
	}
}

func TestVoiceRecoveryDispatchesExactlyOnceAndUsesReplacementForCleanup(t *testing.T) {
	driver := &fakeVoiceDriver{baseline: testVoiceSnapshot(false), recovered: testVoiceSnapshot(true), source: voiceExpectedSourceSHA, eviction: VoiceEviction{Disposition: EvictionAccepted, Dispatched: true}, cleanup: VoiceCleanup{Status: "PASS", ForwardsClosed: true}, mediaDelay: 1100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runVoice(ctx, testVoiceConfig(VoiceReplacementRecovery), driver, &voiceRecorder{})
	if result.Outcome != VoiceOutcomeRecoveryPass || result.EvictionDispatches != 1 || driver.evictions != 1 || result.Replacement == nil || result.Replacement.UID != "pod-d" || result.Cleanup.Status != "PASS" {
		t.Fatalf("recovery result differs: %#v, evictions=%d", result, driver.evictions)
	}
}

func TestVoiceUnknownEvictionIsNeverRetried(t *testing.T) {
	driver := &fakeVoiceDriver{baseline: testVoiceSnapshot(false), source: voiceExpectedSourceSHA, eviction: VoiceEviction{Disposition: EvictionUnknown, Dispatched: true}, cleanup: VoiceCleanup{Status: "PASS", ForwardsClosed: true}}
	result := runVoice(context.Background(), testVoiceConfig(VoiceReplacementRecovery), driver, &voiceRecorder{})
	if result.Outcome != VoiceOutcomeEvictionUnknown || !result.RecoveryRequired || result.EvictionDispatches != 1 || driver.evictions != 1 {
		t.Fatalf("unknown eviction disposition differs: %#v, evictions=%d", result, driver.evictions)
	}
}

func TestVoiceHandlerProjectsCleanupFailure(t *testing.T) {
	h := NewVoiceMediaHandler().(*voiceHandler)
	driver := &fakeVoiceDriver{baseline: testVoiceSnapshot(false), source: voiceExpectedSourceSHA, cleanup: VoiceCleanup{Status: "FAIL", UnsafeToRetry: true}}
	h.newRuntime = func(Runtime) (VoiceDriver, error) { return driver, nil }
	job := Job{RunID: "v1run-8", OwnerDigest: strings.Repeat("c", 64)}
	result := h.Run(context.Background(), JobContext{Job: job, Runtime: Runtime{Voice: VoiceRuntime{Enabled: true, Namespace: "voice", Deployment: "voice-bot", Service: "voice-bot", PDB: "voice-bot", Container: "bot", ServicePort: 8080, TranscriptPodSelector: "app=voice-bot", TranscriptContainer: "bot"}}, Recorder: &voiceRecorder{}})
	if result.Outcome != OutcomeTestFailed || !result.UnsafeToRetry || result.Cleanup.Verified {
		t.Fatalf("handler false-success: %#v", result)
	}
}

func TestVoiceReconcileDoesNotReplayEvictionOrSession(t *testing.T) {
	driver := &fakeVoiceDriver{baseline: testVoiceSnapshot(false), source: voiceExpectedSourceSHA, cleanup: VoiceCleanup{Status: "PASS", ForwardsClosed: true}}
	recorder := &voiceRecorder{}
	journal := Journal{Records: []JournalRecord{{Kind: "intent", Intent: &Intent{Step: "voice.session", Identity: map[string]string{"callSID": "CA" + strings.Repeat("1", 32)}}}, {Kind: "intent", Intent: &Intent{Step: "voice.eviction", Mutation: true, Identity: map[string]string{"podUID": "pod-a"}}}}}
	cleanup := reconcileVoice(context.Background(), testVoiceConfig(VoiceReplacementRecovery), driver, recorder, journal)
	if !cleanup.Verified || !cleanup.UnsafeToRetry || cleanup.Status != "cleanup-pass-effect-unknown" || driver.evictions != 0 {
		t.Fatalf("reconciliation replayed an effect or failed: %#v, evictions=%d", cleanup, driver.evictions)
	}
}

func TestVoiceConfigRejectsDrift(t *testing.T) {
	cfg := testVoiceConfig(VoiceNormalMedia)
	cfg.Namespace = "other"
	if err := cfg.Validate(); err == nil {
		t.Fatal("namespace drift accepted")
	}
	cfg = testVoiceConfig(VoiceNormalMedia)
	cfg.AudioSHA256 = strings.Repeat("0", 64)
	if err := cfg.Validate(); err == nil {
		t.Fatal("audio drift accepted")
	}
}

func TestParseTranscriptRefsRejectsForeignAndDuplicates(t *testing.T) {
	good := `OWNED_TRANSCRIPTS=[{"callSid":"CA1","objectID":"507f1f77bcf86cd799439011","contentSHA256":"` + strings.Repeat("a", 64) + `"}]`
	if refs, err := parseTranscriptRefs(good, []string{"CA1"}); err != nil || len(refs) != 1 {
		t.Fatalf("valid refs rejected: %v %#v", err, refs)
	}
	if _, err := parseTranscriptRefs(strings.Replace(good, "CA1", "CA2", 1), []string{"CA1"}); err == nil {
		t.Fatal("foreign CallSID accepted")
	}
	duplicate := `OWNED_TRANSCRIPTS=[{"callSid":"CA1","objectID":"same","contentSHA256":"` + strings.Repeat("a", 64) + `"},{"callSid":"CA1","objectID":"same","contentSHA256":"` + strings.Repeat("a", 64) + `"}]`
	if _, err := parseTranscriptRefs(duplicate, []string{"CA1"}); err == nil {
		t.Fatal("duplicate transcript accepted")
	}
}

func TestVoiceAuthorityRefusesPodIdentityDrift(t *testing.T) {
	before := testVoiceSnapshot(false)
	after := before
	after.Pods = append([]VoicePod(nil), before.Pods...)
	after.Pods[0].ContainerID = "containerd://changed"
	if voiceSameAuthority(before, after, false) {
		t.Fatal("Pod identity drift accepted")
	}
	if err := validateVoiceReady(testVoiceConfig(VoiceNormalMedia), after); err != nil {
		t.Fatalf("ready projection should remain valid: %v", err)
	}
}
