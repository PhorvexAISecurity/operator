package console

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

//go:embed voice_admission_probe.py voice_mcp_benign.ulaw
var voiceAdmissionAssets embed.FS

const voiceAdmissionAudioSHA = voiceMCPBenignAudioSHA

type voiceAdmissionSession = voiceadmissionpolicy.SessionReceipt
type voiceAdmissionProvider = voiceadmissionpolicy.ProviderEvidence
type voiceAdmissionLoss = voiceadmissionpolicy.Evidence
type voiceAdmissionClient struct {
	Version            int    `json:"version"`
	RunSHA256          string `json:"runSHA256"`
	PID                int    `json:"pid"`
	Done               bool   `json:"done"`
	Error              string `json:"error"`
	SignedSIDHash      string `json:"signedSIDHash"`
	UnsignedSIDHash    string `json:"unsignedSIDHash"`
	SignedSessionID    string `json:"signedSessionID"`
	UnsignedSessionID  string `json:"unsignedSessionID"`
	PendingSessionID   string `json:"pendingSessionID"`
	SignedBeforeFrames uint64 `json:"signedBeforeFrames"`
	SignedBeforeBytes  uint64 `json:"signedBeforeBytes"`
	SignedAfterFrames  uint64 `json:"signedAfterFrames"`
	SignedAfterBytes   uint64 `json:"signedAfterBytes"`
	UnsignedFrames     uint64 `json:"unsignedFrames"`
	UnsignedBytes      uint64 `json:"unsignedBytes"`
	UnsignedClosed     bool   `json:"unsignedClosed"`
	PendingClosed      bool   `json:"pendingClosed"`
	SurvivorRequested  bool   `json:"survivorRequested"`
	SurvivorComplete   bool   `json:"survivorComplete"`
}
type voiceAdmissionReply struct {
	Version     int                        `json:"version"`
	Operation   string                     `json:"operation"`
	RunSHA256   string                     `json:"runSHA256"`
	Started     bool                       `json:"started,omitempty"`
	Client      voiceAdmissionClient       `json:"client,omitempty"`
	Sessions    []voiceAdmissionSession    `json:"sessions,omitempty"`
	Providers   []voiceAdmissionProvider   `json:"providers,omitempty"`
	Loss        *voiceAdmissionLoss        `json:"loss,omitempty"`
	Status      int                        `json:"status,omitempty"`
	State       voiceadmissionpolicy.State `json:"state,omitempty"`
	Phase       string                     `json:"phase,omitempty"`
	Route       string                     `json:"route,omitempty"`
	HTTPStatus  int                        `json:"httpStatus,omitempty"`
	AudioFrames uint64                     `json:"audioFrames,omitempty"`
	AudioBytes  uint64                     `json:"audioBytes,omitempty"`
	Cleaned     bool                       `json:"cleaned,omitempty"`
}

func voiceAdmissionCanonical(v any) []byte { return voiceadmissionpolicy.CanonicalBytes(v) }
func voiceAdmissionProbeSHA() string {
	script, _ := voiceAdmissionAssets.ReadFile("voice_admission_probe.py")
	return voiceMCPStringSHA(string(script))
}
func voiceAdmissionCallHash(run, phase string) string {
	return voiceMCPStringSHA("CA" + strings.ToUpper(voiceMCPStringSHA("voice-admission:" + run + ":" + phase)[:32]))
}
func voiceAdmissionProbe(ctx context.Context, pin voiceAgencyPodPin, op, run, phase, route string) (voiceAdmissionReply, error) {
	var reply voiceAdmissionReply
	script, e := voiceAdmissionAssets.ReadFile("voice_admission_probe.py")
	if e != nil || len(script) > 24<<10 {
		return reply, errors.New("fixed admission probe unavailable")
	}
	input := map[string]any{"operation": op, "run": run}
	switch op {
	case "start", "new-signed":
		audio, e := voiceAdmissionAssets.ReadFile("voice_mcp_benign.ulaw")
		if e != nil || voiceMCPSHA(audio) != voiceAdmissionAudioSHA {
			return reply, errors.New("admission audio differs")
		}
		input["audio"] = base64.StdEncoding.EncodeToString(audio)
	case "replay":
		input["phase"] = phase
		input["route"] = route
	case "observe", "state", "survivor", "finish", "cleanup":
	default:
		return reply, errors.New("fixed admission operation invalid")
	}
	raw, _ := json.Marshal(input)
	out, e := voiceAgencyPodTransport(ctx, pin, string(script), raw)
	if e != nil {
		return reply, e
	}
	if rejectNATSNestedDuplicates(out) != nil {
		return reply, errors.New("admission duplicate receipt")
	}
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if d.Decode(&reply) != nil || d.Decode(new(any)) != io.EOF || reply.Version != 1 || reply.Operation != op || reply.RunSHA256 != voiceMCPStringSHA(run) {
		return voiceAdmissionReply{}, errors.New("admission probe scope differs")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(out, &envelope) != nil {
		return reply, errors.New("admission envelope invalid")
	}
	if op == "state" {
		state, err := voiceadmissionpolicy.ParseState(envelope["state"])
		if err != nil {
			return reply, err
		}
		reply.State = state
	}
	if len(envelope["loss"]) > 0 {
		loss, err := voiceadmissionpolicy.ParseEvidence(envelope["loss"])
		if err != nil {
			return reply, err
		}
		reply.Loss = &loss
	}
	for _, key := range []string{"sessions", "providers"} {
		if len(envelope[key]) == 0 {
			continue
		}
		var rows []json.RawMessage
		if json.Unmarshal(envelope[key], &rows) != nil {
			return reply, errors.New("admission rows invalid")
		}
		for _, row := range rows {
			if key == "sessions" {
				var v voiceAdmissionSession
				if voiceadmissionpolicy.ExactDecode(row, &v) != nil {
					return reply, errors.New("admission session fields incomplete")
				}
			} else {
				var v voiceAdmissionProvider
				if voiceadmissionpolicy.ExactDecode(row, &v) != nil {
					return reply, errors.New("admission provider fields incomplete")
				}
			}
		}
	}
	if len(reply.Sessions) > 8 || len(reply.Providers) > 8 {
		return reply, errors.New("admission evidence count exceeds bound")
	}
	return reply, nil
}
