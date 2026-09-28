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
	"fmt"
	"io"
	"strings"
)

//go:embed voice_agency_probe.py voice_agency_attack.ulaw voice_agency_benign.ulaw voice_agency_own_control.ulaw
var voiceAgencyAssets embed.FS

const voiceAgencyOwnClipSHA256 = "deebe76b65645a0d320387e6732a31e3c0d4758fb45cef6a037c3d5eaa73a0c2"

type voiceAgencyReply struct {
	Version              int                        `json:"version"`
	Operation            string                     `json:"operation"`
	Phase                string                     `json:"phase"`
	RunSHA256            string                     `json:"runSHA256"`
	CallerSHA256         string                     `json:"callerSHA256"`
	OwnOrderSHA256       string                     `json:"ownOrderSHA256"`
	OtherOrderSHA256     string                     `json:"otherOrderSHA256"`
	Ready                bool                       `json:"ready"`
	OwnRefundIDs         []string                   `json:"ownRefundIDs"`
	CrossRefundIDs       []string                   `json:"crossRefundIDs"`
	Cleaned              bool                       `json:"cleaned"`
	AccountCount         int                        `json:"accountCount"`
	OrderCount           int                        `json:"orderCount"`
	RefundCount          int                        `json:"refundCount"`
	TranscriptCount      int                        `json:"transcriptCount"`
	CallSIDHash          string                     `json:"callSIDHash"`
	ClipSHA256           string                     `json:"clipSHA256"`
	MediaFrames          int                        `json:"mediaFrames"`
	ReceivedFrames       int                        `json:"receivedFrames"`
	ReceivedAudioFrames  int                        `json:"receivedAudioFrames"`
	ReceivedAudioBytes   int                        `json:"receivedAudioBytes"`
	ReceivedAudioSHA256  string                     `json:"receivedAudioSHA256"`
	ObservedAtUnixMs     int64                      `json:"observedAtUnixMs"`
	Refund               []voiceAgencyRefundReceipt `json:"refund"`
	Read                 []voiceAgencyReadReceipt   `json:"read"`
	ExpectedStatusSHA256 string                     `json:"expectedStatusSHA256"`
	Status               int                        `json:"status"`
	Body                 voiceAgencyState           `json:"body"`
}

type voiceAgencyRefundReceipt struct {
	Version             int    `json:"version"`
	CallSIDHash         string `json:"callSIDHash"`
	CallerSHA256        string `json:"callerSHA256"`
	SourceSHA256        string `json:"sourceSHA256"`
	PodUID              string `json:"podUID"`
	Tool                string `json:"tool"`
	Sequence            int    `json:"sequence"`
	Stage               string `json:"stage"`
	OrderSHA256         string `json:"orderSHA256"`
	AmountCents         int    `json:"amountCents"`
	CRMIssued           bool   `json:"crmIssued"`
	DenialReason        string `json:"denialReason"`
	RefundIDSHA256      string `json:"refundIDSHA256"`
	ResponseOrderSHA256 string `json:"responseOrderSHA256"`
	ObservedAtUnixMs    int64  `json:"observedAtUnixMs"`
}

type voiceAgencyReadReceipt struct {
	Version          int    `json:"version"`
	CallSIDHash      string `json:"callSIDHash"`
	CallerSHA256     string `json:"callerSHA256"`
	SourceSHA256     string `json:"sourceSHA256"`
	PodUID           string `json:"podUID"`
	Tool             string `json:"tool"`
	Sequence         int    `json:"sequence"`
	Stage            string `json:"stage"`
	ArgumentSHA256   string `json:"argumentSHA256"`
	ResponseSHA256   string `json:"responseSHA256"`
	ObservedAtUnixMs int64  `json:"observedAtUnixMs"`
}

type voiceAgencyState struct {
	Version       int    `json:"version"`
	PodUID        string `json:"podUID"`
	DeploymentUID string `json:"deploymentUID"`
	PolicyUID     string `json:"policyUID"`
	SourceSHA256  string `json:"sourceSHA256"`
	RuleSHA256    string `json:"ruleSHA256"`
	Revision      uint64 `json:"revision"`
	OperationID   string `json:"operationId"`
	EntryCount    int    `json:"entryCount"`
	Ready         bool   `json:"ready"`
}

func voiceAgencyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func voiceAgencyStringDigest(value string) string { return voiceAgencyDigest([]byte(value)) }
func voiceAgencyCallSID(run, phase string) string {
	sum := sha256.Sum256([]byte(run + ":" + phase))
	return "CA" + strings.ToUpper(hex.EncodeToString(sum[:])[:32])
}

func voiceAgencyScript() (string, string, error) {
	raw, err := voiceAgencyAssets.ReadFile("voice_agency_probe.py")
	if err != nil || len(raw) > 24<<10 {
		return "", "", errors.New("reviewed Voice agency probe source unavailable")
	}
	return string(raw), voiceAgencyDigest(raw), nil
}

func voiceAgencyClip(phase string) ([]byte, string, error) {
	file, want := "", ""
	switch phase {
	case "attack", "replay":
		file = "voice_agency_attack.ulaw"
		want = "be4b83510ff1f0a194938432f27821366ef2ef07ec64c140d96e33259fe4a81f"
	case "benign":
		file = "voice_agency_benign.ulaw"
		want = "99e1c867196a96fcdcbb09a5488b847fec2f137d0e3e70c5f903595347397630"
	case "own-control":
		file = "voice_agency_own_control.ulaw"
		want = voiceAgencyOwnClipSHA256
	default:
		return nil, "", errors.New("Voice agency phase invalid")
	}
	raw, err := voiceAgencyAssets.ReadFile(file)
	if err != nil || len(raw) == 0 || len(raw) > 65536 || voiceAgencyDigest(raw) != want {
		return nil, "", errors.New("reviewed Voice agency clip differs")
	}
	return raw, want, nil
}

func voiceAgencyDecodeReply(raw []byte, operation, run string) (voiceAgencyReply, error) {
	var reply voiceAgencyReply
	if len(raw) == 0 || len(raw) > 64<<10 {
		return reply, errors.New("Voice agency reply outside bound")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&reply) != nil || dec.Decode(new(any)) != io.EOF || reply.Version != 1 || reply.Operation != operation ||
		(reply.RunSHA256 != "" && reply.RunSHA256 != voiceAgencyStringDigest(run)) {
		return reply, errors.New("Voice agency reply identity or schema differs")
	}
	return reply, nil
}

func voiceAgencyProbe(ctx context.Context, pin voiceAgencyPodPin, operation, run, phase string, refundIDs []string, sourceSHA string) (voiceAgencyReply, error) {
	var empty voiceAgencyReply
	script, _, err := voiceAgencyScript()
	if err != nil {
		return empty, err
	}
	input := map[string]any{"operation": operation, "run": run}
	switch operation {
	case "seed", "observe", "state":
	case "cleanup":
		input["refundIDs"] = refundIDs
	case "session":
		clip, _, e := voiceAgencyClip(phase)
		if e != nil {
			return empty, e
		}
		input["phase"] = phase
		input["audio"] = base64.StdEncoding.EncodeToString(clip)
	case "receipts":
		if !staticSHA256.MatchString(sourceSHA) {
			return empty, errors.New("Voice agency source identity unavailable")
		}
		input["phase"] = phase
		input["callSID"] = voiceAgencyCallSID(run, phase)
		input["callerSHA256"] = voiceAgencyCallerSHA(run)
		input["sourceSHA256"] = sourceSHA
	default:
		return empty, errors.New("Voice agency operation invalid")
	}
	raw, e := json.Marshal(input)
	if e != nil {
		return empty, e
	}
	out, e := voiceAgencyPodTransport(ctx, pin, script, raw)
	if e != nil {
		return empty, e
	}
	answer, e := voiceAgencyDecodeReply(out, operation, run)
	if e != nil {
		return empty, e
	}
	if operation == "session" && (answer.Phase != phase || answer.CallSIDHash != voiceAgencyStringDigest(voiceAgencyCallSID(run, phase))) {
		return empty, fmt.Errorf("Voice agency session identity differs")
	}
	if operation == "receipts" && (answer.Phase != phase || answer.CallSIDHash != voiceAgencyStringDigest(voiceAgencyCallSID(run, phase))) {
		return empty, fmt.Errorf("Voice agency receipt call differs")
	}
	return answer, nil
}

func voiceAgencyPhone(run, side string) string {
	a := sha256.Sum256([]byte(run + ":A"))
	b := sha256.Sum256([]byte(run + ":" + side))
	var av, bv uint64
	for i := 0; i < 8; i++ {
		av = av<<8 | uint64(a[i])
		bv = bv<<8 | uint64(b[i])
	}
	av %= 10000000
	bv %= 10000000
	if side == "B" && bv == av {
		bv = (bv + 1) % 10000000
	}
	return fmt.Sprintf("+1555%07d", bv)
}
func voiceAgencyCallerSHA(run string) string {
	return voiceAgencyStringDigest(voiceAgencyPhone(run, "A"))
}
