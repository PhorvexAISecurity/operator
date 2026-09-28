package voiceadmissionpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

const testUID = "11111111-1111-4111-8111-111111111111"

func testRule() Rule {
	sha := strings.Repeat("a", 64)
	return Rule{Version: 1, DeploymentUID: testUID, SecurityPolicyUID: testUID, WrapperCMUID: testUID, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, Mode: ModeObserve}
}

func TestCanonicalRuleAndOneWayTransition(t *testing.T) {
	r := testRule()
	if _, err := Parse(string(r.Bytes())); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		string(r.Bytes()) + " ", strings.Replace(string(r.Bytes()), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(r.Bytes()), `"version":1`, `"version":null`, 1),
		strings.Replace(string(r.Bytes()), `"version":1`, `"extra":1,"version":1`, 1),
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted rule drift: %s", raw)
		}
	}
	next, err := Enforce(r, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision != 1 || next.Mode != ModeEnforce || next.DeploymentUID != r.DeploymentUID {
		t.Fatal("transition changed authority")
	}
	if _, err := Enforce(next, strings.Repeat("c", 64)); err == nil {
		t.Fatal("enforced rule allowed second operation")
	}
	if _, err := OperationID(testUID, testUID, testUID, 1, testUID, "tick\x00suffix", "decision", r.SHA256()); err == nil {
		t.Fatal("operation boundary allowed NUL")
	}
}

func testState() State {
	r, _ := Enforce(testRule(), strings.Repeat("b", 64))
	return State{Version: 1, PodUID: testUID, DeploymentUID: testUID, PolicyCMUID: testUID, PolicyResourceVersion: "1", RuleSHA256: r.SHA256(), Revision: 1, Mode: ModeEnforce, OperationID: r.OperationID, AdmissionSourceSHA256: r.AdmissionSourceSHA256, LegacyBundleSHA256: r.LegacyBundleSHA256, AuthProfileSHA256: r.AuthProfileSHA256, ObservedAtUnixMs: 1, Settled: true, DelegatesCompleted: 9, DisconnectsDelivered: 1}
}

func TestStateBarrierAndIndependentLifecycleCounters(t *testing.T) {
	s := testState()
	if _, err := ParseState(CanonicalBytes(s)); err != nil {
		t.Fatalf("natural delegate completions must remain valid: %v", err)
	}
	for _, mutate := range []func(*State){func(s *State) { s.ActiveUnsigned = 1 }, func(s *State) { s.PendingUnsigned = 1 }, func(s *State) { s.TransitionPending = true }, func(s *State) { s.Revision = 0; s.Mode = ModeObserve; s.OperationID = "" }, func(s *State) { s.PodUID = "claimed" }} {
		bad := s
		mutate(&bad)
		if _, err := ParseState(CanonicalBytes(bad)); err == nil {
			t.Fatal("accepted unproven settled barrier")
		}
	}
	raw := strings.Replace(string(CanonicalBytes(s)), `"settled":true,`, "", 1)
	if _, err := ParseState([]byte(raw)); err == nil {
		t.Fatal("missing true/false boundary was manufactured")
	}
}

func testExposure() (Evidence, EventAssertion) {
	r := testRule()
	sha := r.AdmissionSourceSHA256
	s := SessionReceipt{Version: 1, SessionID: testUID, RunSHA256: sha, CallSIDHash: sha, PodUID: testUID, DeploymentUID: testUID, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, AdmissionRuleSHA256: r.SHA256(), ConnectedAtUnixMs: 1, ObservedAtUnixMs: 2, Stage: "pipeline-observed", ReceivedAudioFrames: 1, SentAudioFrames: 1, SentAudioBytes: 320}
	p := ProviderEvidence{Version: 1, SessionID: testUID, RunSHA256: sha, CallSIDHash: sha, PodUID: testUID, DeploymentUID: testUID, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, ObservedAtUnixMs: 2, STTFrames: 1, ModelTextFrames: 1, ModelCompletions: 1, TTSAudioFrames: 1, TTSAudioBytes: 320, STTTextSHA256: sha, ModelTextSHA256: sha}
	a := EventAssertion{Version: 1, ScenarioID: ScenarioID, CaseID: "actual-audio", RunSHA256: sha, SessionID: testUID, DeploymentUID: testUID, PodUID: testUID, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, PolicyCMUID: testUID, PolicyResourceVersion: "1", RuleSHA256: r.SHA256(), SecurityPolicyUID: testUID, SecurityPolicyGeneration: 1, ObservedAtUnixMs: 2, EvidenceSource: "TEST_INJECTED", Observed: true, SentAudioFrames: 1, SentAudioBytes: 320, ReceiptSHA256: Digest(CanonicalBytes(s)), ProviderEvidenceSHA256: Digest(CanonicalBytes(p))}
	return Evidence{Session: s, Provider: p}, a
}

func TestEvidenceRequiresActualProducerAndImmutableExposure(t *testing.T) {
	e, a := testExposure()
	if err := ValidateEvidence(e, a); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Evidence){func(e *Evidence) { e.Provider.STTFrames = 0 }, func(e *Evidence) { e.Provider.ModelCompletions = 0 }, func(e *Evidence) { e.Provider.TTSAudioBytes = 0 }, func(e *Evidence) { e.Session.Authenticated = true }, func(e *Evidence) { e.Session.DelegateCompleted = true }, func(e *Evidence) { e.Session.Stage = "closed" }, func(e *Evidence) { e.Provider.SessionID = "22222222-2222-4222-8222-222222222222" }} {
		bad := e
		mutate(&bad)
		changed := a
		changed.ReceiptSHA256 = Digest(CanonicalBytes(bad.Session))
		changed.ProviderEvidenceSHA256 = Digest(CanonicalBytes(bad.Provider))
		if err := ValidateEvidence(bad, changed); err == nil {
			t.Fatal("accepted fabricated or already-completed exposure")
		}
	}
	raw, _ := json.Marshal(e)
	if _, err := ParseEvidence(raw); err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1))
	if _, err := ParseEvidence(raw); err == nil {
		t.Fatal("nested duplicate producer/session key accepted")
	}
	missing := e.Session
	missing.CallSIDHash = ""
	missing.Stage = "pending"
	missing.ReceivedAudioFrames = 0
	missing.SentAudioFrames = 0
	missing.SentAudioBytes = 0
	if _, err := ParseSession(CanonicalBytes(missing)); err != nil {
		t.Fatalf("pending pre-start receipt invalid: %v", err)
	}
}
