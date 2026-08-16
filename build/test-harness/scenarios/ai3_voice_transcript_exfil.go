package scenarios

// ─────────────────────────────────────────────────────────────────────────────
// ai3_voice_transcript_exfil.go — call-transcript theft from the voice agent's
// data-plane store. A type-2 (R6CannotRespond) attack: the differentiator gap.
//
// Models the live phorvex-voice-agent deployment: a Pipecat voice bot writes each
// finished call's transcript to a store that lives OUTSIDE the bot pod (MongoDB on
// a PVC, in a separate namespace). Here the store is a SEPARATE, non-rotation-target
// pod; the "voice-bot" is the rotation target.
//
// Kill-chain:
//   1. (precondition) finished calls have persisted transcripts to the store.
//   2. exfil: the attacker dumps the store — every call, keyed by call_sid.
//   3. trigger: a detector fires; Phorvex rotates the voice-bot (its only actuator).
//   4. oracle: the transcripts are STILL in the store. Rotation moved the bot pod;
//      it never touched the data plane. The theft is not remediated.
//
// Why R6CannotRespond: no matcher/rotation path reaches at-rest data in a different
// pod (and, in prod, on a PVC that survives even the store's own rotation). The
// correct controls are data-layer — field encryption, DLP on egress, short-lived DB
// creds, or QUARANTINING the store — none of which are the pod-rotation actuator.
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&aiVoiceTranscriptExfil{}) }

// TranscriptMarker tags every planted transcript record so the oracle can count
// survivors unambiguously.
const TranscriptMarker = "R6TH-VOICE-TRANSCRIPT"

// transcriptDir is where the store pod holds the "collection" (one file per call,
// standing in for one Mongo document per call_sid).
const transcriptDir = "/tmp/transcripts"

// nCalls is how many finished-call transcripts pre-exist in the store.
const nCalls = 5

type aiVoiceTranscriptExfil struct {
	botApp   string   // the rotation-target voice bot
	storeApp string   // the data-plane transcript store (NOT a rotation target)
	botPod0  string   // bot pod name observed at Execute (to detect rotation)
	callIDs  []string // the call_sids we persisted
	stolen   int      // records the attacker exfiltrated in Execute
}

func (s *aiVoiceTranscriptExfil) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:     "ai3-voice-transcript-exfil",
		Category: core.CategoryModernUnsupported,
		Source: "phorvex-voice-agent: Pipecat bot persists call transcripts to a store (Mongo/PVC) " +
			"outside the pod; data-plane exfil that survives bot rotation",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1213", "T1530"}, // data from info repositories, data from cloud/at-rest store
		R6Justification: "Transcripts persist in a store OUTSIDE the rotation target (Mongo on a PVC). " +
			"Rotating the voice-bot neither deletes nor detaches the data; identity/pod rotation cannot " +
			"reach third-party at-rest data. Phorvex may act correctly on the bot and still remediate nothing. " +
			"The real controls are data-layer (field encryption, DLP, short-lived creds) or quarantining the store.",
	}
}

func (s *aiVoiceTranscriptExfil) Setup(ctx context.Context, env *core.Env) error {
	s.botApp = "vt-voicebot"      // rotation target (Phorvex guards this)
	s.storeApp = "vt-transcripts" // data plane — deliberately NOT a rotation target
	if _, err := deployTarget(ctx, env, s.botApp, "", nil); err != nil {
		return err
	}
	// The store lives outside the bot: a plain pod the MTD arms do not rotate,
	// standing in for MongoDB in the document-store namespace.
	if _, err := deployPlain(ctx, env, s.storeApp); err != nil {
		return err
	}
	return nil
}

// Execute — persist finished-call transcripts to the store, then exfiltrate them,
// then trigger Phorvex against the bot (the runner's defender arm performs the
// actual rotation; here we only ensure transcripts exist and are stolen).
func (s *aiVoiceTranscriptExfil) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	store, err := runningPodByApp(ctx, env, s.storeApp)
	if err != nil {
		return core.AttackResult{}, err
	}
	storeC := firstContainer(store)

	// (1) Precondition: the voice bot has written call transcripts to the store.
	// One file per call_sid — plaintext, exactly like the live bot's _save_transcript.
	var b strings.Builder
	b.WriteString("mkdir -p " + transcriptDir + "; ")
	s.callIDs = nil
	for i := 1; i <= nCalls; i++ {
		id := fmt.Sprintf("CA%04d", i)
		s.callIDs = append(s.callIDs, id)
		// content stands in for the Mongo doc: marker + call_sid + sensitive caller PII.
		line := fmt.Sprintf("%s call_sid=%s caller PII: card 4111-1111-1111-1111 says <redacted>", TranscriptMarker, id)
		b.WriteString(fmt.Sprintf("printf '%%s' '%s' > %s/%s; ", line, transcriptDir, id))
	}
	b.WriteString("echo persisted")
	persist := env.Exec(ctx, store.Name, storeC, []string{"sh", "-c", b.String()})
	env.Log.Logf("persisted %d transcripts to store: exit=%d", nCalls, persist.ExitCode)

	// (2) Exfil: the attacker dumps the whole collection and counts what it stole.
	dump := env.Exec(ctx, store.Name, storeC, []string{"sh", "-c", "cat " + transcriptDir + "/* 2>/dev/null"})
	s.stolen = strings.Count(dump.Stdout, TranscriptMarker)
	env.Log.Logf("attacker exfiltrated %d/%d transcript records", s.stolen, nCalls)

	// Record the bot pod we expect Phorvex to rotate, so the oracle can confirm the
	// rotation actually happened (and yet changed nothing about the stolen data).
	if bot, err := runningPodByApp(ctx, env, s.botApp); err == nil {
		s.botPod0 = bot.Name
	}

	return core.AttackResult{
		Stages: []string{
			"collection: finished-call transcripts persisted to data-plane store",
			"exfiltration: dump transcript store, all calls by call_sid (T1213/T1530)",
			"trigger: detector signals Phorvex to rotate the voice-bot",
		},
		Commands: []string{
			"sh -c 'cat " + transcriptDir + "/*'  # exfiltrate transcripts",
		},
		Notes: map[string]string{
			"stolenRecords": fmt.Sprintf("%d/%d", s.stolen, nCalls),
			"storePod":      store.Name,
			"botPod":        s.botPod0,
		},
	}, nil
}

// SuccessOracle — after Phorvex's response window, are the transcripts STILL in the
// store? Achieved iff the data-plane records survived (theft not remediated). We
// also record whether the bot was rotated, to show Phorvex acted yet changed nothing.
func (s *aiVoiceTranscriptExfil) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	time.Sleep(8 * time.Second) // give a rotating defender time to act on the bot

	// Did Phorvex rotate the voice-bot? (evidence only — not the success condition)
	botRotated := "unknown"
	if bot, err := runningPodByApp(ctx, env, s.botApp); err == nil {
		if s.botPod0 != "" && bot.Name != s.botPod0 {
			botRotated = fmt.Sprintf("yes (%s -> %s)", s.botPod0, bot.Name)
		} else {
			botRotated = "no (same pod)"
		}
	} else {
		botRotated = "no running bot pod"
	}

	// The store was never a rotation target, so it is still here holding the data.
	store, err := runningPodByApp(ctx, env, s.storeApp)
	if err != nil {
		return core.OracleResult{
			Achieved:      false,
			ObservedState: "transcript store pod unexpectedly gone — cannot confirm survival",
		}, nil
	}
	res := env.Exec(ctx, store.Name, firstContainer(store), []string{"sh", "-c", "cat " + transcriptDir + "/* 2>/dev/null"})
	survivors := strings.Count(res.Stdout, TranscriptMarker)
	achieved := survivors >= 1

	return core.OracleResult{
		Achieved: achieved,
		ObservedState: fmt.Sprintf(
			"%d/%d transcripts survived in the store after Phorvex responded (bot rotation: %s) — rotation cannot reach the data plane",
			survivors, nCalls, botRotated),
		Evidence: map[string]string{
			"transcriptsSurvived": fmt.Sprintf("%d/%d", survivors, nCalls),
			"stolenAtExec":        fmt.Sprintf("%d/%d", s.stolen, nCalls),
			"botRotated":          botRotated,
			"storePod":            store.Name,
		},
	}, nil
}

func (s *aiVoiceTranscriptExfil) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.botApp, s.storeApp)
}
