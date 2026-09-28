package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

type voiceAdmissionProbeResult struct {
	Schema                   string   `json:"schema"`
	Status                   string   `json:"status"`
	ScenarioID               string   `json:"scenarioId"`
	CaseID                   string   `json:"caseId"`
	RunSHA256                string   `json:"runSHA256"`
	DefenseScope             string   `json:"defenseScope"`
	SignalMode               string   `json:"signalMode"`
	TargetPodUID             string   `json:"targetPodUID,omitempty"`
	DeploymentUID            string   `json:"deploymentUID,omitempty"`
	FirstLanded              bool     `json:"firstLanded"`
	FirstSTTFrames           uint64   `json:"firstSTTFrames"`
	FirstModelCompletions    uint64   `json:"firstModelCompletions"`
	FirstTTSAudioBytes       uint64   `json:"firstTTSAudioBytes"`
	FirstSentAudioFrames     uint64   `json:"firstSentAudioFrames"`
	FirstSentAudioBytes      uint64   `json:"firstSentAudioBytes"`
	ReceiptSHA256            string   `json:"receiptSHA256,omitempty"`
	ProviderEvidenceSHA256   string   `json:"providerEvidenceSHA256,omitempty"`
	EventUID                 string   `json:"eventUID,omitempty"`
	SelectedAction           string   `json:"selectedAction,omitempty"`
	SelectedDecisionID       string   `json:"selectedDecisionId,omitempty"`
	SelectedTickID           string   `json:"selectedTickId,omitempty"`
	NoopReason               string   `json:"noopReason,omitempty"`
	ActionExclusion          string   `json:"actionExclusion,omitempty"`
	OperationID              string   `json:"operationId,omitempty"`
	ProtectedJournalTerminal bool     `json:"protectedJournalTerminal"`
	EveryServingPodSettled   bool     `json:"everyServingPodSettled"`
	UnsignedSessionsEnded    bool     `json:"unsignedSessionsEnded"`
	EveryPodReplayRejected   bool     `json:"everyPodReplayRejected"`
	ServiceReplayRejected    bool     `json:"serviceReplayRejected"`
	MalformedReplayRejected  bool     `json:"malformedReplayRejected"`
	SignedSurvivorAudio      bool     `json:"signedSurvivorAudio"`
	NewSignedAudio           bool     `json:"newSignedAudio"`
	Cleanup                  string   `json:"cleanup"`
	Issues                   []string `json:"issues"`
}

func (s *Server) voiceAdmissionLiveFire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var input struct {
		Scenario string `json:"scenario"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || input.Scenario != voiceAdmissionScenario {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "fixed admission scenario required"})
		return
	}
	p, e := loadVoiceAdmissionProfile(s.cfg)
	if e != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "reviewed admission installation unavailable"})
		return
	}
	if !voiceMemoryRunning.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "one Voice Live run already active"})
		return
	}
	run, e := voiceMemoryID()
	if e != nil {
		voiceMemoryRunning.Store(false)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run identity unavailable"})
		return
	}
	if e = s.persistEffectIntent(voiceAdmissionRoute, actorOf(r), "voice", voiceAdmissionScenario); e != nil {
		voiceMemoryRunning.Store(false)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Fire intent unavailable"})
		return
	}
	started := s.cfg.now().UTC()
	id := "voice-admission-" + run
	probe := &voiceAdmissionProbeResult{Schema: "voice-admission-live-v1", Status: "UNKNOWN", ScenarioID: voiceAdmissionScenario, CaseID: id, RunSHA256: voiceMCPStringSHA(run),
		DefenseScope: "bounded unsigned Voice media admission and local session teardown; signed synthetic audio controls; telephone leg and stolen-signature replay untested", SignalMode: "NONE", Cleanup: "not-started", Issues: []string{}}
	record := &attackRecord{ID: id, FiredAt: started.Format(time.RFC3339Nano), Service: "voice-bot", Namespace: "voice", Attack: "Unauthenticated Voice media admission", AttackID: voiceAdmissionScenario, Expected: voiceAdmissionAction,
		EvidenceKind: "voice-admission-live", OutcomeClass: "voice-admission-UNKNOWN", Status: "running", ProducerRoute: voiceAdmissionRoute, ResultSchema: "voice-admission-live-v1", ObservationStart: started.Format(time.RFC3339Nano), ObservationEnd: started.Add(900 * time.Second).Format(time.RFC3339Nano), VoiceAdmissionProbe: probe, started: started, accepted: started}
	publishAttack(record)
	go s.runVoiceAdmissionLive(record, p, run)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "attackId": id, "scenario": voiceAdmissionScenario, "status": "running", "message": "A bounded signed control and unsigned real-provider trial will emit a test-generated event only after observed STT/model/TTS and actual outbound audio. Permanent enforcement is never reset."})
}
func voiceAdmissionPoll(ctx context.Context, pin voiceAgencyPodPin, run string, predicate func(voiceAdmissionReply) bool) (voiceAdmissionReply, error) {
	deadline := time.NewTimer(100 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		reply, e := voiceAdmissionProbe(ctx, pin, "observe", run, "", "")
		if e == nil && predicate(reply) {
			return reply, nil
		}
		if e == nil && reply.Client.Done {
			return reply, errors.New("bounded admission client ended before evidence")
		}
		select {
		case <-ctx.Done():
			return reply, ctx.Err()
		case <-deadline.C:
			return reply, errors.New("actual admission evidence incomplete")
		case <-ticker.C:
		}
	}
}
func (s *Server) runVoiceAdmissionLive(record *attackRecord, p voiceAdmissionProfile, run string) {
	defer voiceMemoryRunning.Store(false)
	probe := record.VoiceAdmissionProbe
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.MaxRunSeconds)*time.Second)
	defer cancel()
	privateDir, e := voiceMCPPrivateDir(s.cfg, record.ID)
	if e != nil {
		probe.Issues = append(probe.Issues, "private evidence unavailable")
		s.finishVoiceAdmissionLive(record)
		return
	}
	var pin voiceAgencyPodPin
	started := false
	defer func() {
		if started {
			cleanCtx, stop := context.WithTimeout(context.Background(), 40*time.Second)
			clean, e := voiceAdmissionProbe(cleanCtx, pin, "cleanup", run, "", "")
			stop()
			if e == nil && clean.Cleaned && voiceMemorySavePrivate(privateDir, "cleanup.json", clean) == nil {
				probe.Cleanup = "run-owned-client-and-receipts-removed"
			} else {
				probe.Cleanup = "unresolved-run-owned-client-or-receipts"
				probe.Issues = append(probe.Issues, "bounded client/receipt cleanup unconfirmed")
				if probe.Status == "DEFENDED" {
					probe.Status = "UNKNOWN"
					record.Outcome = "LANDED"
					record.Containment = ""
				}
			}
		}
		s.finishVoiceAdmissionLive(record)
	}()
	before, e := s.voiceAdmissionSnapshot(ctx, p)
	if e != nil || len(before.Pins) == 0 {
		probe.Issues = append(probe.Issues, "current source, owner, rule, routing or authenticated state unavailable")
		return
	}
	pin = before.Pins[0]
	record.Pod, record.TargetUID, record.Deploy, record.OwnerUID = pin.Name, pin.UID, "voice-bot", before.DeploymentUID
	probe.TargetPodUID, probe.DeploymentUID = pin.UID, before.DeploymentUID
	if before.Rule.Mode == voiceadmissionpolicy.ModeEnforce {
		probe.Status = "ALREADY_PROTECTED"
		probe.Issues = append(probe.Issues, "permanent admission authentication already active; no unsigned first-loss trial or rearm performed")
		return
	}
	if voiceMemorySavePrivate(privateDir, "before.json", before) != nil {
		probe.Issues = append(probe.Issues, "before authority not retained")
		return
	}
	// Mark attempted before invocation: an ambiguous child launch must be reconciled.
	started = true
	launch, e := voiceAdmissionProbe(ctx, pin, "start", run, "", "")
	if e != nil || !launch.Started || voiceMemorySavePrivate(privateDir, "launch.json", launch) != nil {
		probe.Issues = append(probe.Issues, "bounded client launch ambiguous")
		return
	}
	first, e := voiceAdmissionPoll(ctx, pin, run, func(reply voiceAdmissionReply) bool {
		_, landed := voiceAdmissionFirstLoss(reply, before, pin.UID, run)
		return landed && voiceadmissionpolicy.ValidUID(reply.Client.PendingSessionID)
	})
	retentionErr := voiceMemorySavePrivate(privateDir, "first.json", first)
	when, landed := voiceAdmissionFirstLoss(first, before, pin.UID, run)
	if landed {
		probe.FirstLanded = true
		record.Outcome = "LANDED"
		probe.FirstSTTFrames, probe.FirstModelCompletions, probe.FirstTTSAudioBytes = first.Loss.Provider.STTFrames, first.Loss.Provider.ModelCompletions, first.Loss.Provider.TTSAudioBytes
		probe.FirstSentAudioFrames, probe.FirstSentAudioBytes = first.Loss.Session.SentAudioFrames, first.Loss.Session.SentAudioBytes
		probe.ReceiptSHA256, probe.ProviderEvidenceSHA256 = voiceMCPSHA(voiceAdmissionCanonical(first.Loss.Session)), voiceMCPSHA(voiceAdmissionCanonical(first.Loss.Provider))
	}
	if e != nil || retentionErr != nil || !landed || !voiceAdmissionSignedControl(first, before, pin.UID, run, "signed") {
		probe.Issues = append(probe.Issues, "signed audio control or real unsigned STT/model/TTS evidence incomplete; no event emitted")
		return
	}
	current, e := s.voiceAdmissionSnapshot(ctx, p)
	if e != nil || !voiceAdmissionSame(before, current, true) {
		probe.Issues = append(probe.Issues, "source, serving identity or rule changed before signal; loss remains visible")
		return
	}
	event, e := s.createVoiceAdmissionEvent(ctx, privateDir, record.ID, run, before.Pods[0], before, first, when)
	record.StimulusEvidence = event
	if event != nil {
		probe.EventUID = event.EventUID
	}
	if e != nil {
		probe.SignalMode = "TEST_INJECTED_ADMISSION_UNKNOWN"
		probe.Issues = append(probe.Issues, "observed event admission ambiguous; no recreate")
		return
	}
	probe.SignalMode = "TEST_INJECTED_AFTER_REAL_UNSIGNED_PROVIDER_USE"
	decision, e := s.waitVoiceAdmissionDecision(ctx, record, before, event.EventUID)
	probe.SelectedAction, probe.SelectedDecisionID, probe.SelectedTickID = decision.Action, decision.DecisionID, decision.TickID
	probe.NoopReason, probe.ActionExclusion = decision.NoopReason, decision.ActionExclusion
	if decision.TickID != "" && voiceMemorySavePrivate(privateDir, "brain-decision.json", decision) != nil {
		probe.Issues = append(probe.Issues, "brain evidence not retained")
		return
	}
	record.Action = decision.Action
	if e != nil || decision.Action != voiceAdmissionAction || !decision.Selected {
		probe.Issues = append(probe.Issues, "normal brain did not select admission enforcement")
		return
	}
	after, journal, e := s.waitVoiceAdmissionEffect(ctx, p, before, decision, event, first, record)
	if e != nil || voiceMemorySavePrivate(privateDir, "terminal-journal.json", journal) != nil || voiceMemorySavePrivate(privateDir, "after.json", after) != nil {
		probe.Issues = append(probe.Issues, "protected terminal journal or every-serving-Pod settled barrier unconfirmed")
		return
	}
	probe.ProtectedJournalTerminal, probe.EveryServingPodSettled, probe.OperationID = true, true, journal.OperationID
	ended, e := voiceAdmissionPoll(ctx, pin, run, func(reply voiceAdmissionReply) bool { return voiceAdmissionSessionsEnded(reply, first) })
	if e != nil || voiceMemorySavePrivate(privateDir, "unsigned-ended.json", ended) != nil {
		probe.Issues = append(probe.Issues, "pending/active unsigned disconnect and delegate completion unconfirmed")
		return
	}
	probe.UnsignedSessionsEnded = true
	probe.EveryPodReplayRejected = true
	probe.MalformedReplayRejected = true
	for _, target := range after.Pins {
		for _, phase := range []string{"unsigned", "malformed"} {
			reply, e := voiceAdmissionProbe(ctx, target, "replay", run, phase, "pod")
			if e != nil || reply.HTTPStatus != 403 || voiceMemorySavePrivate(privateDir, "replay-"+target.UID+"-"+phase+".json", reply) != nil {
				if phase == "unsigned" {
					probe.EveryPodReplayRejected = false
				} else {
					probe.MalformedReplayRejected = false
				}
				probe.Issues = append(probe.Issues, "fresh unsigned/malformed replay not rejected on every serving Pod")
				return
			}
		}
	}
	service, e := voiceAdmissionProbe(ctx, pin, "replay", run, "unsigned", "service")
	if e != nil || service.HTTPStatus != 403 || voiceMemorySavePrivate(privateDir, "service-replay.json", service) != nil {
		probe.Issues = append(probe.Issues, "Service-path fresh unsigned replay not rejected")
		return
	}
	probe.ServiceReplayRejected = true
	beforeSigned, _, ok := voiceAdmissionFind(first, first.Client.SignedSessionID)
	if !ok {
		probe.Issues = append(probe.Issues, "original signed control identity incomplete")
		return
	}
	if _, e = voiceAdmissionProbe(ctx, pin, "survivor", run, "", ""); e != nil {
		probe.Issues = append(probe.Issues, "signed continuation request unconfirmed")
		return
	}
	survivor, e := voiceAdmissionPoll(ctx, pin, run, func(reply voiceAdmissionReply) bool {
		v, provider, ok := voiceAdmissionFind(reply, first.Client.SignedSessionID)
		_, priorProvider, priorOK := voiceAdmissionFind(first, first.Client.SignedSessionID)
		return ok && priorOK && reply.Client.SurvivorComplete && !v.DelegateCompleted && v.DisconnectedAtUnixMs == 0 && voiceAdmissionSessionMatches(v, before, pin.UID, probe.RunSHA256, beforeSigned.CallSIDHash, true) && voiceAdmissionProviderMatches(provider, v) && provider.STTFrames > priorProvider.STTFrames && provider.ModelCompletions > priorProvider.ModelCompletions && provider.TTSAudioBytes > priorProvider.TTSAudioBytes && reply.Client.SignedAfterFrames > reply.Client.SignedBeforeFrames && reply.Client.SignedAfterBytes > reply.Client.SignedBeforeBytes
	})
	if e != nil || voiceMemorySavePrivate(privateDir, "signed-survivor.json", survivor) != nil {
		probe.Issues = append(probe.Issues, "ongoing signed real audio did not survive enforcement")
		return
	}
	probe.SignedSurvivorAudio = true
	fresh, e := voiceAdmissionProbe(ctx, pin, "new-signed", run, "", "")
	if e != nil || !voiceAdmissionSignedControl(fresh, after, pin.UID, run, "new") || fresh.AudioFrames == 0 || fresh.AudioBytes == 0 || voiceMemorySavePrivate(privateDir, "new-signed.json", fresh) != nil {
		probe.Issues = append(probe.Issues, "new signed real STT/model/TTS audio unconfirmed")
		return
	}
	probe.NewSignedAudio = true
	final, e := s.voiceAdmissionSnapshot(ctx, p)
	if e != nil || !voiceAdmissionSame(after, final, true) || !voiceAdmissionBarrier(before, final, journal) {
		probe.Issues = append(probe.Issues, "final permanent rule/serving identity drift")
		return
	}
	probe.Status = "DEFENDED"
	record.Outcome = "DEFENDED"
	record.Containment = "require-production-twilio-signature-with-local-unsigned-session-teardown"
}
func (s *Server) finishVoiceAdmissionLive(record *attackRecord) {
	probe := record.VoiceAdmissionProbe
	if probe == nil {
		return
	}
	if probe.Status != "DEFENDED" && probe.FirstLanded {
		record.Outcome = "LANDED"
	}
	record.OutcomeClass = "voice-admission-" + probe.Status
	record.Actuated = probe.Status == "DEFENDED" && probe.ProtectedJournalTerminal && probe.EveryServingPodSettled
	record.Status = "done"
	if e := s.persistAttack(record); e != nil {
		probe.Issues = append(probe.Issues, "durable terminal record unavailable")
		probe.Status = "UNKNOWN"
		record.OutcomeClass = "voice-admission-UNKNOWN"
		record.Actuated = false
		record.Containment = ""
		record.PersistenceError = "Voice admission persistence unavailable"
		record.Status = "partial"
		if probe.FirstLanded {
			record.Outcome = "LANDED"
		} else {
			record.Outcome = ""
		}
	}
	publishAttack(record)
}
