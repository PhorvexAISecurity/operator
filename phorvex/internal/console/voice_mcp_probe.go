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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

//go:embed voice_mcp_probe.py voice_mcp_attack.ulaw voice_mcp_benign.ulaw
var voiceMCPAssets embed.FS

const (
	voiceMCPAttackAudioSHA = "843b6fce61bae1a62ab069c889352b55e271bfb32ca23b6bba2d63461ce22b90"
	voiceMCPBenignAudioSHA = "6b634936283ce28c2e25b71fa3575d0e23c69839999eed6e917fb52d8d176e37"
	voiceMCPProbeSHA       = "6367541895bcc5af8bdccec2bab0540d828c83e617d5ead1b41a692c411d7dd3"
)

type voiceMCPMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type voiceMCPAppReceipt struct {
	Version                   int    `json:"version"`
	RunSHA256                 string `json:"runSHA256"`
	Phase                     string `json:"phase"`
	CallSID                   string `json:"callSid"`
	PodUID                    string `json:"podUID"`
	SourceSHA256              string `json:"sourceSHA256"`
	MCPSourceSHA256           string `json:"mcpSourceSHA256"`
	ObservedDescriptorSHA256  string `json:"observedDescriptorSHA256"`
	EffectiveDescriptorSHA256 string `json:"effectiveDescriptorSHA256"`
	PolicyRevision            uint64 `json:"policyRevision"`
	PolicyRuleSHA256          string `json:"policyRuleSHA256"`
	PolicyOperationID         string `json:"policyOperationId"`
	State                     string `json:"state"`
	FetchObserved             bool   `json:"fetchObserved"`
}

type voiceMCPToolCall struct {
	Version         int    `json:"version"`
	RunSHA256       string `json:"runSHA256"`
	Phase           string `json:"phase"`
	CallSID         string `json:"callSid"`
	PodUID          string `json:"podUID"`
	SourceSHA256    string `json:"sourceSHA256"`
	MCPSourceSHA256 string `json:"mcpSourceSHA256"`
	ToolName        string `json:"toolName"`
	ResponseSHA256  string `json:"responseSHA256"`
	Success         bool   `json:"success"`
	CallObserved    bool   `json:"callObserved"`
}

type voiceMCPProbeReply struct {
	Version             int                `json:"version"`
	Operation           string             `json:"operation"`
	Phase               string             `json:"phase"`
	RunSHA256           string             `json:"runSHA256"`
	CallSIDHash         string             `json:"callSidSHA256"`
	AudioSHA256         string             `json:"audioSHA256"`
	MediaFrames         int                `json:"mediaFrames"`
	ReceivedFrames      int                `json:"receivedFrames"`
	ReceivedAudioFrames int                `json:"receivedAudioFrames"`
	ReceivedAudioBytes  int                `json:"receivedAudioBytes"`
	ReceivedAudioSHA256 string             `json:"receivedAudioSHA256"`
	AudioQuietObserved  bool               `json:"audioQuietObserved"`
	Receipt             voiceMCPAppReceipt `json:"receipt"`
	Messages            []voiceMCPMessage  `json:"messages"`
	ToolCalls           []voiceMCPToolCall `json:"toolCalls"`
	TranscriptSHA256    string             `json:"transcriptSHA256"`
	ObservedAtUnixMs    int64              `json:"observedAtUnixMs"`
	Cleaned             bool               `json:"cleaned"`
	Empty               bool               `json:"empty"`
	Status              int                `json:"status"`
	StateBody           voiceMCPState      `json:"stateBody"`
}

func voiceMCPToolExecuted(observed voiceMCPProbeReply, tool string) bool {
	wantResponseSHA := ""
	if tool == "check_promotions" {
		wantResponseSHA = voiceMCPStringSHA("Current promo: use code SAVE10 for 10% off orders over $50. Free shipping over $75.")
	}
	if tool == "store_directory" {
		wantResponseSHA = voiceMCPStringSHA("All stores open 9am-9pm daily; the support line is 9am-6pm Pacific, Mon-Fri.")
	}
	for _, call := range observed.ToolCalls {
		if call.Version == 1 && call.RunSHA256 == observed.RunSHA256 && call.Phase == observed.Phase &&
			voiceMCPStringSHA(call.CallSID) == observed.CallSIDHash && call.PodUID == observed.Receipt.PodUID &&
			call.SourceSHA256 == observed.Receipt.SourceSHA256 && call.MCPSourceSHA256 == observed.Receipt.MCPSourceSHA256 &&
			call.ToolName == tool && call.ResponseSHA256 == wantResponseSHA && call.Success && call.CallObserved {
			return true
		}
	}
	return false
}

type voiceMCPState struct {
	Version              int    `json:"version"`
	PodUID               string `json:"podUID"`
	DeploymentUID        string `json:"deploymentUID"`
	PolicyUID            string `json:"policyUID"`
	SourceSHA256         string `json:"sourceSHA256"`
	RuleSHA256           string `json:"ruleSHA256"`
	Revision             uint64 `json:"revision"`
	OperationID          string `json:"operationId"`
	EntryCount           int    `json:"entryCount"`
	Ready                bool   `json:"ready"`
	GoodDescriptorSHA256 string `json:"goodDescriptorSHA256"`
}

func voiceMCPSHA(b []byte) string       { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func voiceMCPStringSHA(s string) string { return voiceMCPSHA([]byte(s)) }
func voiceMCPCallSID(run, phase string) string {
	return "CA" + strings.ToUpper(voiceMCPStringSHA("voice-mcp:" + run + ":" + phase)[:32])
}
func voiceMCPNonce(run string) string {
	return strings.ToUpper(voiceMCPStringSHA("voice-mcp-nonce:" + run)[:12])
}

func voiceMCPAsset(phase string) ([]byte, error) {
	name, want := "voice_mcp_attack.ulaw", voiceMCPAttackAudioSHA
	if phase == "benign" {
		name, want = "voice_mcp_benign.ulaw", voiceMCPBenignAudioSHA
	}
	if phase != "attack" && phase != "replay" && phase != "benign" {
		return nil, errors.New("MCP phase invalid")
	}
	raw, err := voiceMCPAssets.ReadFile(name)
	if err != nil || len(raw) == 0 || len(raw) > 65536 || voiceMCPSHA(raw) != want {
		return nil, errors.New("reviewed MCP audio unavailable")
	}
	return raw, nil
}

func voiceMCPProbe(ctx context.Context, pin voiceAgencyPodPin, operation, run, phase, sourceSHA string) (voiceMCPProbeReply, error) {
	var answer voiceMCPProbeReply
	script, err := voiceMCPAssets.ReadFile("voice_mcp_probe.py")
	if err != nil || len(script) > 24<<10 || voiceMCPSHA(script) != voiceMCPProbeSHA {
		return answer, errors.New("reviewed MCP probe source unavailable")
	}
	if operation != "session" && operation != "observe" && operation != "cleanup" && operation != "state" && operation != "baseline" {
		return answer, errors.New("MCP probe operation invalid")
	}
	input := map[string]any{"operation": operation, "run": run, "phase": phase}
	if operation == "session" {
		clip, e := voiceMCPAsset(phase)
		if e != nil {
			return answer, e
		}
		input["audio"] = base64.StdEncoding.EncodeToString(clip)
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return answer, err
	}
	out, err := voiceMCPPodTransport(ctx, pin, string(script), raw)
	if err != nil {
		return answer, err
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if dec.Decode(&answer) != nil || dec.Decode(new(any)) != io.EOF || answer.Version != 1 || answer.Operation != operation ||
		answer.Phase != phase || answer.RunSHA256 != voiceMCPStringSHA(run) || answer.CallSIDHash != voiceMCPStringSHA(voiceMCPCallSID(run, phase)) {
		return voiceMCPProbeReply{}, errors.New("MCP probe reply scope differs")
	}
	if operation == "session" {
		_, e := voiceMCPAsset(phase)
		if e != nil {
			return answer, e
		}
		want := voiceMCPAttackAudioSHA
		if phase == "benign" {
			want = voiceMCPBenignAudioSHA
		}
		if answer.AudioSHA256 != want || answer.MediaFrames < 1 {
			return voiceMCPProbeReply{}, errors.New("MCP session audio not delivered")
		}
	}
	if operation == "observe" && (answer.Receipt.Version != 1 || !answer.Receipt.FetchObserved ||
		answer.Receipt.RunSHA256 != answer.RunSHA256 || answer.Receipt.Phase != phase ||
		answer.Receipt.CallSID != voiceMCPCallSID(run, phase) || answer.Receipt.PodUID != pin.UID ||
		answer.Receipt.SourceSHA256 != sourceSHA || answer.TranscriptSHA256 == "" || len(answer.Messages) == 0) {
		return voiceMCPProbeReply{}, fmt.Errorf("MCP SDK receipt or real Voice transcript unavailable")
	}
	if operation == "state" && (answer.Status != 200 || answer.StateBody.Version != 1 || !answer.StateBody.Ready ||
		answer.StateBody.PodUID != pin.UID || answer.StateBody.SourceSHA256 != sourceSHA) {
		return voiceMCPProbeReply{}, errors.New("MCP authenticated current Pod readback unavailable")
	}
	return answer, nil
}

func voiceMCPExactPod(p *corev1.Pod, pin voiceAgencyPodPin) bool {
	if p == nil || p.Namespace != "voice" || p.Name != pin.Name || string(p.UID) != pin.UID ||
		p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || pin.ContainerID == "" ||
		pin.ImageID == "" || pin.SourceSHA256 == "" ||
		p.Annotations["phorvex.ai/voice-mcp-source-sha256"] != pin.SourceSHA256 {
		return false
	}
	ready := false
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	count := 0
	for _, status := range p.Status.ContainerStatuses {
		if status.Name == "bot" && status.Ready && status.ContainerID == pin.ContainerID &&
			status.ImageID == pin.ImageID && status.RestartCount == pin.RestartCount {
			count++
		}
	}
	return ready && count == 1
}

func voiceMCPPodTransport(ctx context.Context, pin voiceAgencyPodPin, script string, input []byte) ([]byte, error) {
	if len(script) == 0 || len(script) > 24<<10 || len(input) == 0 || len(input) > 128<<10 {
		return nil, errors.New("MCP probe source or input exceeds bound")
	}
	config, err := restConfigFor("")
	if err != nil {
		return nil, err
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	before, err := kube.CoreV1().Pods("voice").Get(bounded, pin.Name, metav1.GetOptions{})
	if err != nil || !voiceMCPExactPod(before, pin) {
		return nil, errors.New("MCP Pod identity changed before probe")
	}
	out, invokeErr := voiceAgencySPDYExec(bounded, config, kube, pin.Name, script, input)
	after, afterErr := kube.CoreV1().Pods("voice").Get(bounded, pin.Name, metav1.GetOptions{})
	if afterErr != nil || !voiceMCPExactPod(after, pin) {
		return nil, errors.New("MCP Pod identity changed after ambiguous probe")
	}
	if invokeErr != nil || len(out) == 0 || len(out) > 64<<10 {
		return nil, errors.New("MCP Pod probe unresolved")
	}
	return out, nil
}
