package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

//go:embed voice_output_probe.py voice_output_attack.ulaw voice_output_benign.ulaw
var voiceOutputAssets embed.FS

const (
	voiceOutputAttackClipSHA256 = "eeb77c21eb175368c0a0658525bc81487d77344d1821bef95fecdf45e30ecaa4"
	voiceOutputBenignClipSHA256 = "bbc1efce2f7380b634726666e884fafae5716482cacf510ee4f164dfbb357d9d"
	voiceOutputSourceAnnotation = "phorvex.ai/voice-output-source-sha256"
)

type voiceOutputReceipt struct {
	Version          int    `json:"version"`
	Stage            string `json:"stage"`
	Sequence         int    `json:"sequence"`
	CallSIDHash      string `json:"callSIDHash"`
	ObservedAtUnixMs int64  `json:"observedAtUnixMs"`
	SourceSHA256     string `json:"sourceSHA256"`
	PodUID           string `json:"podUID"`
	RawSHA256        string `json:"rawSHA256,omitempty"`
	OutputSHA256     string `json:"outputSHA256,omitempty"`
	MarkerSHA256     string `json:"markerSHA256,omitempty"`
	MarkerObserved   bool   `json:"markerObserved,omitempty"`
	Blocked          bool   `json:"blocked,omitempty"`
	PolicyReady      bool   `json:"policyReady,omitempty"`
	Revision         uint64 `json:"revision,omitempty"`
	OperationID      string `json:"operationId,omitempty"`
	AudioFrames      int    `json:"audioFrames,omitempty"`
	AudioSHA256      string `json:"audioSHA256,omitempty"`
	AssistantSHA256  string `json:"assistantSHA256,omitempty"`
	Persisted        bool   `json:"persisted,omitempty"`
	AssistantPresent bool   `json:"assistantPresent,omitempty"`
}

type voiceOutputState struct {
	Version            int    `json:"version"`
	PodUID             string `json:"podUID"`
	ConfigMapUID       string `json:"configMapUID"`
	DeploymentUID      string `json:"deploymentUID"`
	PolicyUID          string `json:"policyUID"`
	SourceSHA256       string `json:"sourceSHA256"`
	RuleSHA256         string `json:"ruleSHA256"`
	Revision           uint64 `json:"revision"`
	OperationID        string `json:"operationId"`
	EntryCount         int    `json:"entryCount"`
	MarkerSHA256       string `json:"markerSHA256"`
	Active             bool   `json:"active"`
	MatchedOperationID string `json:"matchedOperationId"`
	Ready              bool   `json:"ready"`
}

type voiceOutputProbeReply struct {
	Version          int                          `json:"version"`
	Operation        string                       `json:"operation"`
	Phase            string                       `json:"phase"`
	RunSHA256        string                       `json:"runSHA256"`
	CallSIDHash      string                       `json:"callSIDHash"`
	CallerSHA256     string                       `json:"callerSHA256"`
	ClipSHA256       string                       `json:"clipSHA256"`
	MediaFrames      int                          `json:"mediaFrames"`
	ReceivedFrames   int                          `json:"receivedFrames"`
	ObservedAtUnixMs int64                        `json:"observedAtUnixMs"`
	Receipts         []voiceOutputReceipt         `json:"receipts"`
	Status           int                          `json:"status"`
	Body             voiceOutputState             `json:"body"`
	Proofs           []voiceOutputTranscriptProof `json:"proofs"`
	Cleaned          bool                         `json:"cleaned"`
}

type voiceOutputTranscriptProof struct {
	Phase            string `json:"phase"`
	CallSIDHash      string `json:"callSIDHash"`
	AssistantSHA256  string `json:"assistantSHA256"`
	MarkerObserved   bool   `json:"markerObserved"`
	MarkerSHA256     string `json:"markerSHA256"`
	AssistantPresent bool   `json:"assistantPresent"`
}

func voiceOutputSHA(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func voiceOutputMarker(run string) string {
	sum := sha256.Sum256([]byte("phorvex-voice-output-v1:" + run))
	return "PHORVEX_INTERNAL_" + strings.ToUpper(hex.EncodeToString(sum[:])[:32])
}
func voiceOutputCallSID(run, phase string) string {
	sum := sha256.Sum256([]byte(run + ":output:" + phase))
	return "CA" + strings.ToUpper(hex.EncodeToString(sum[:])[:32])
}
func voiceOutputProbeSource() (string, string, error) {
	raw, err := voiceOutputAssets.ReadFile("voice_output_probe.py")
	if err != nil || len(raw) == 0 || len(raw) > 24<<10 {
		return "", "", errors.New("reviewed Voice output probe unavailable")
	}
	return string(raw), voiceAgencyDigest(raw), nil
}
func voiceOutputClip(phase string) ([]byte, string, error) {
	name, expected := "", ""
	switch phase {
	case "attack", "replay":
		name, expected = "voice_output_attack.ulaw", voiceOutputAttackClipSHA256
	case "benign":
		name, expected = "voice_output_benign.ulaw", voiceOutputBenignClipSHA256
	default:
		return nil, "", errors.New("Voice output phase invalid")
	}
	raw, err := voiceOutputAssets.ReadFile(name)
	if err != nil || len(raw) == 0 || len(raw) > 65536 || voiceAgencyDigest(raw) != expected {
		return nil, "", errors.New("reviewed Voice output audio differs")
	}
	return raw, expected, nil
}

func voiceOutputProbe(ctx context.Context, pin voiceAgencyPodPin, operation, run, phase, source, markerSHA string) (voiceOutputProbeReply, error) {
	var empty voiceOutputProbeReply
	script, _, err := voiceOutputProbeSource()
	if err != nil {
		return empty, err
	}
	input := map[string]any{"operation": operation, "run": run}
	switch operation {
	case "session":
		clip, _, e := voiceOutputClip(phase)
		if e != nil {
			return empty, e
		}
		input["phase"], input["audio"] = phase, base64.StdEncoding.EncodeToString(clip)
	case "receipts":
		if phase != "attack" && phase != "replay" && phase != "benign" || !staticSHA256.MatchString(source) {
			return empty, errors.New("Voice output receipt scope invalid")
		}
		input["phase"], input["sourceSHA256"] = phase, source
	case "state":
		if !staticSHA256.MatchString(markerSHA) {
			return empty, errors.New("Voice output marker digest invalid")
		}
		input["markerSHA256"] = markerSHA
	case "baseline", "cleanup":
	case "transcript":
		if phase != "attack" && phase != "replay" && phase != "benign" {
			return empty, errors.New("Voice output transcript phase invalid")
		}
		input["phase"] = phase
	default:
		return empty, errors.New("Voice output operation invalid")
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return empty, err
	}
	pin.SourceAnnotation = voiceOutputSourceAnnotation
	raw, err := voiceAgencyPodTransport(ctx, pin, script, encoded)
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return empty, errors.New("Voice output Pod probe unresolved")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var reply voiceOutputProbeReply
	if dec.Decode(&reply) != nil || dec.Decode(new(any)) != io.EOF || reply.Version != 1 || reply.Operation != operation ||
		(operation != "state" && reply.RunSHA256 != voiceOutputSHA(run)) ||
		((operation == "session" || operation == "receipts") && (reply.Phase != phase || reply.CallSIDHash != voiceOutputSHA(voiceOutputCallSID(run, phase)))) ||
		(operation == "transcript" && reply.Phase != phase) {
		return empty, errors.New("Voice output Pod reply identity differs")
	}
	return reply, nil
}
