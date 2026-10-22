package console

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

func admissionObservedFixture() (voiceAdmissionReply, voiceAdmissionSnapshot, string, string) {
	run := "admissiona1"
	pod := "44444444-4444-4444-4444-444444444444"
	now := time.Now().UnixMilli()
	r := voiceadmissionpolicy.Rule{Version: 1, DeploymentUID: "11111111-1111-1111-1111-111111111111", SecurityPolicyUID: "22222222-2222-2222-2222-222222222222", WrapperCMUID: "33333333-3333-3333-3333-333333333333",
		AdmissionSourceSHA256: strings.Repeat("a", 64), LegacyBundleSHA256: strings.Repeat("b", 64), AuthProfileSHA256: strings.Repeat("c", 64), Mode: voiceadmissionpolicy.ModeObserve}
	snap := voiceAdmissionSnapshot{DeploymentUID: r.DeploymentUID, Rule: r, RuleSHA256: r.SHA256()}
	session := voiceAdmissionSession{Version: 1, SessionID: "55555555-5555-5555-5555-555555555555", RunSHA256: voiceMCPStringSHA(run), CallSIDHash: voiceAdmissionCallHash(run, "unsigned"), PodUID: pod, DeploymentUID: r.DeploymentUID,
		AdmissionSourceSHA256: r.AdmissionSourceSHA256, LegacyBundleSHA256: r.LegacyBundleSHA256, AuthProfileSHA256: r.AuthProfileSHA256, AdmissionRuleSHA256: r.SHA256(), ConnectedAtUnixMs: now - 1000, ObservedAtUnixMs: now,
		Stage: "pipeline-observed", ReceivedAudioFrames: 40, SentAudioFrames: 20, SentAudioBytes: 3200}
	provider := voiceAdmissionProvider{Version: 1, SessionID: session.SessionID, RunSHA256: session.RunSHA256, CallSIDHash: session.CallSIDHash, PodUID: pod, DeploymentUID: r.DeploymentUID,
		AdmissionSourceSHA256: r.AdmissionSourceSHA256, LegacyBundleSHA256: r.LegacyBundleSHA256, AuthProfileSHA256: r.AuthProfileSHA256, ObservedAtUnixMs: now,
		STTFrames: 1, ModelTextFrames: 8, ModelCompletions: 1, TTSAudioFrames: 20, TTSAudioBytes: 3200, STTTextSHA256: voiceMCPStringSHA("what promotions are available"), ModelTextSHA256: voiceMCPStringSHA("SAVE10 is available")}
	reply := voiceAdmissionReply{Version: 1, Operation: "observe", RunSHA256: session.RunSHA256, Loss: &voiceAdmissionLoss{Session: session, Provider: provider},
		Client: voiceAdmissionClient{Version: 1, RunSHA256: session.RunSHA256, UnsignedSessionID: session.SessionID, UnsignedFrames: 20, UnsignedBytes: 3200}}
	return reply, snap, pod, run
}
func TestAdmissionFirstLossRequiresCorrelatedActualProviderAndWireAudio(t *testing.T) {
	first, snap, pod, run := admissionObservedFixture()
	if _, ok := voiceAdmissionFirstLoss(first, snap, pod, run); !ok {
		t.Fatal("source-owned correlated pipeline evidence rejected")
	}
	tests := map[string]func(*voiceAdmissionReply){
		"no provider":                func(r *voiceAdmissionReply) { r.Loss.Provider = voiceAdmissionProvider{} },
		"callback only":              func(r *voiceAdmissionReply) { r.Loss.Session.SentAudioFrames = 0; r.Loss.Session.SentAudioBytes = 0 },
		"control frame only":         func(r *voiceAdmissionReply) { r.Client.UnsignedFrames = 0; r.Client.UnsignedBytes = 0 },
		"no actual STT":              func(r *voiceAdmissionReply) { r.Loss.Provider.STTFrames = 0 },
		"no actual model completion": func(r *voiceAdmissionReply) { r.Loss.Provider.ModelCompletions = 0 },
		"no actual TTS":              func(r *voiceAdmissionReply) { r.Loss.Provider.TTSAudioBytes = 0 },
		"empty transcription":        func(r *voiceAdmissionReply) { r.Loss.Provider.STTTextSHA256 = voiceMCPStringSHA("") },
		"different provider session": func(r *voiceAdmissionReply) { r.Loss.Provider.SessionID = "66666666-6666-6666-6666-666666666666" },
		"different call metadata":    func(r *voiceAdmissionReply) { r.Loss.Provider.CallSIDHash = strings.Repeat("d", 64) },
		"wrong Pod":                  func(r *voiceAdmissionReply) { r.Loss.Session.PodUID = "66666666-6666-6666-6666-666666666666" },
		"wrong wrapper":              func(r *voiceAdmissionReply) { r.Loss.Session.AdmissionSourceSHA256 = strings.Repeat("e", 64) },
		"wrong active rule":          func(r *voiceAdmissionReply) { r.Loss.Session.AdmissionRuleSHA256 = strings.Repeat("e", 64) },
		"signed source":              func(r *voiceAdmissionReply) { r.Loss.Session.Authenticated = true },
		"historical closed source":   func(r *voiceAdmissionReply) { r.Loss.Session.DisconnectedAtUnixMs = time.Now().UnixMilli() },
		"stale loss": func(r *voiceAdmissionReply) {
			r.Loss.Session.ConnectedAtUnixMs = time.Now().Add(-time.Minute).UnixMilli()
			r.Loss.Session.ObservedAtUnixMs = r.Loss.Session.ConnectedAtUnixMs
		},
		"client lifetime elapsed": func(r *voiceAdmissionReply) { r.Client.Done = true },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(first)
			var reply voiceAdmissionReply
			_ = json.Unmarshal(raw, &reply)
			change(&reply)
			if _, ok := voiceAdmissionFirstLoss(reply, snap, pod, run); ok {
				t.Fatal("incomplete/cross-session evidence earned first loss")
			}
		})
	}
	snap.Rule.Revision = 1
	snap.Rule.Mode = voiceadmissionpolicy.ModeEnforce
	snap.Rule.OperationID = strings.Repeat("f", 64)
	if _, ok := voiceAdmissionFirstLoss(first, snap, pod, run); ok {
		t.Fatal("permanent enforcement manufactured a first loss")
	}
}
func TestAdmissionBarrierRequiresExactServingSetAndZeroUnsigned(t *testing.T) {
	_, before, _, _ := admissionObservedFixture()
	before.Pins = []voiceAgencyPodPin{{UID: "44444444-4444-4444-4444-444444444444"}, {UID: "55555555-5555-5555-5555-555555555555"}}
	after := before
	desired, _ := voiceadmissionpolicy.Enforce(before.Rule, strings.Repeat("f", 64))
	after.Rule = desired
	after.RuleSHA256 = desired.SHA256()
	after.States = []voiceadmissionpolicy.State{{PodUID: before.Pins[0].UID, Settled: true}, {PodUID: before.Pins[1].UID, Settled: true}}
	receipt := voiceadmissionpolicy.Receipt{OperationID: desired.OperationID, Desired: desired, PodReceipts: append([]voiceadmissionpolicy.State{}, after.States...)}
	if !voiceAdmissionBarrier(before, after, receipt) {
		t.Fatal("complete settled serving barrier rejected")
	}
	receipt.PodReceipts = receipt.PodReceipts[:1]
	if voiceAdmissionBarrier(before, after, receipt) {
		t.Fatal("missing serving Pod accepted")
	}
	receipt.PodReceipts = append([]voiceadmissionpolicy.State{}, after.States...)
	after.States[1].PendingUnsigned = 1
	if voiceAdmissionBarrier(before, after, receipt) {
		t.Fatal("pending unsigned session accepted as settled")
	}
	after.States[1].PendingUnsigned = 0
	after.States[1].TransitionPending = true
	if voiceAdmissionBarrier(before, after, receipt) {
		t.Fatal("unfinished transition accepted")
	}
}
func TestAdmissionProfileStrictPinnedAndDisabledByDefault(t *testing.T) {
	if _, e := loadVoiceAdmissionProfile(Config{}); e == nil {
		t.Fatal("default disabled trial armed")
	}
	_, snap, _, _ := admissionObservedFixture()
	p := voiceAdmissionProfile{Version: 1, DeploymentUID: snap.DeploymentUID, PolicyCMUID: "77777777-7777-7777-7777-777777777777", AdmissionSourceSHA256: snap.Rule.AdmissionSourceSHA256,
		LegacyBundleSHA256: snap.Rule.LegacyBundleSHA256, AuthProfileSHA256: snap.Rule.AuthProfileSHA256, WrapperConfigMapName: "voice-admission-source-000000000000", LegacyConfigMapName: "voice-memory-source-" + snap.Rule.LegacyBundleSHA256[:12], ProbeSHA256: voiceAdmissionProbeSHA(), AudioSHA256: voiceAdmissionAudioSHA,
		EventCreator: eventtrust.Injector(), AuditSourceIdentity: "https://audit.invalid:8445|audit.invalid", MaxRunSeconds: 900}
	raw := voiceAdmissionCanonical(p)
	if _, e := parseVoiceAdmissionProfile(raw); e != nil {
		t.Fatal(e)
	}
	for name, changed := range map[string][]byte{"duplicate": append([]byte(`{"version":1,`), raw[1:]...), "missing": []byte(`{"version":1}`), "unknown": append(raw[:len(raw)-1], []byte(`,"other":true}`)...)} {
		t.Run(name, func(t *testing.T) {
			if _, e := parseVoiceAdmissionProfile(changed); e == nil {
				t.Fatal("malformed profile accepted")
			}
		})
	}
	p.ProbeSHA256 = strings.Repeat("f", 64)
	if _, e := parseVoiceAdmissionProfile(voiceAdmissionCanonical(p)); e == nil {
		t.Fatal("unreviewed probe accepted")
	}
}

func TestAdmissionResultVisibleAndIsolated(t *testing.T) {
	probe := &voiceAdmissionProbeResult{Status: "UNKNOWN", Issues: []string{"initial"}}
	record := &attackRecord{EvidenceKind: "voice-admission-live", VoiceAdmissionProbe: probe}
	cloned := cloneAttackRecord(record)
	probe.Status = "DEFENDED"
	probe.Issues[0] = "changed"
	if cloned.VoiceAdmissionProbe.Status != "UNKNOWN" || cloned.VoiceAdmissionProbe.Issues[0] != "initial" {
		t.Fatal("published admission evidence shared with worker")
	}
	if !visibleAttackRecord(record, false) {
		t.Fatal("reviewed admission result hidden from live report")
	}
}
