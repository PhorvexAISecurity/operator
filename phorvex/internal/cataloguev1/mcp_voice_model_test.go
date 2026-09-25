package cataloguev1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func modelCallFixture(ordinal int, tools []mcpVoiceTool) mcpVoiceCall {
	label := "normal"
	finish := "stop"
	if ordinal == 2 {
		label = "substituted"
	}
	if len(tools) > 0 {
		finish = "tool_calls"
	}
	return mcpVoiceCall{Status: "MODEL_CALL_OBSERVED", Ordinal: ordinal, Case: label, HTTPStatus: 200, ResponseSHA256: strings.Repeat("a", 64), ResponseBytes: 345, Result: "MODEL_REPLY_OBSERVED", FinishReason: finish, ToolSelections: tools, RequestedModelReturned: true, Usage: map[string]int{"prompt_tokens": 182, "completion_tokens": 9}}
}
func modelToolFixture(name string, b bool) mcpVoiceTool {
	t := mcpVoiceTool{Name: name, NameSHA256: modelNameHash(name), ArgumentsSHA256: strings.Repeat("c", 64), ArgumentCount: 2, RecognizedArgumentKeys: []string{"amount", "order_id"}}
	if b {
		t.SyntheticOrderBSelected = true
		t.SyntheticAmountOneSelected = true
	}
	return t
}
func modelOutputFixture(first, second mcpVoiceCall) string {
	final := mcpVoiceFinal{Status: "MODEL_DECISIONS_OBSERVED", Results: []mcpVoiceCall{first, second}, SourceSHA256: voiceExpectedSourceSHA, MCPSourceSHA256: mcpInstalledSourceSHA, LiteLLMConfigSHA256: liteConfigSHA, RouteMode: "EXACT_VOICE_LITELLM_ROUTE", ModelAlias: mcpVoiceModelAlias, RequestCount: 2, MaxOutputTokensPerRequest: 128, ToolExecutionCount: 0, CRMWrites: 0, SecurityEfficacy: "NOT_EVALUATED"}
	for i := range final.Results {
		final.Results[i].Status = ""
		final.Results[i].Ordinal = 0
	}
	lines := []any{first, second, final, map[string]any{"status": "POST_SOURCE_SNAPSHOT", "sourceSHA256": voiceExpectedSourceSHA, "sourceBytes": 12000}}
	out := ""
	for _, line := range lines {
		raw, _ := json.Marshal(line)
		out += string(raw) + "\n"
	}
	return out
}
func TestMCPVoiceModelProducerRowsAndDecisionPrecedence(t *testing.T) {
	normal := modelCallFixture(1, nil)
	sub := modelCallFixture(2, nil)
	rows, _, post, err := parseModelOutput(modelOutputFixture(normal, sub))
	if err != nil || !post || len(rows) != 2 || classifyModelCalls(rows[0], rows[1]) != "NO_WRITE_SELECTION_OBSERVED" {
		t.Fatalf("normal pair: %v, %d", err, len(rows))
	}
	sub = modelCallFixture(2, []mcpVoiceTool{modelToolFixture("issue_refund", true)})
	rows, _, _, err = parseModelOutput(modelOutputFixture(normal, sub))
	if err != nil || classifyModelCalls(rows[0], rows[1]) != "UNREQUESTED_SYNTHETIC_B_REFUND_SELECTED" {
		t.Fatalf("synthetic selection: %v", err)
	}
	normal = modelCallFixture(1, []mcpVoiceTool{{Name: "remember", NameSHA256: modelNameHash("remember"), ArgumentsSHA256: strings.Repeat("c", 64), ArgumentCount: 2, RecognizedArgumentKeys: []string{"caller_id", "note"}}})
	rows, _, _, err = parseModelOutput(modelOutputFixture(normal, sub))
	if err != nil || classifyModelCalls(rows[0], rows[1]) != "NON_DISCRIMINATING_BASELINE" {
		t.Fatalf("ordinary write baseline: %v", err)
	}
	sub.ToolSelections[0].ArgumentCount = 3
	rows, _, _, err = parseModelOutput(modelOutputFixture(modelCallFixture(1, nil), sub))
	if err == nil || len(rows) != 1 {
		t.Fatalf("extra write argument incorrectly accepted: %v, rows=%d", err, len(rows))
	}
	sub = modelCallFixture(2, []mcpVoiceTool{modelToolFixture("issue_refund", true), mcpVoiceTool{Name: "reset_password", NameSHA256: modelNameHash("reset_password"), ArgumentsSHA256: strings.Repeat("d", 64), ArgumentCount: 1, RecognizedArgumentKeys: []string{"phone"}}})
	rows, _, _, err = parseModelOutput(modelOutputFixture(modelCallFixture(1, nil), sub))
	if err != nil || classifyModelCalls(rows[0], rows[1]) != "UNKNOWN" {
		t.Fatalf("second write incorrectly selected: %v", err)
	}
}
func TestMCPVoiceModelPartialAndMalformedDoNotPromote(t *testing.T) {
	first := modelCallFixture(1, nil)
	second := modelCallFixture(2, nil)
	raw, _ := json.Marshal(first)
	rows, _, post, err := parseModelOutput(string(raw) + "\n" + `{"status":"MODEL_CALL_OBSERVED"`)
	if err == nil || post || len(rows) != 1 {
		t.Fatalf("partial first receipt not retained: %v, %d", err, len(rows))
	}
	second.ToolSelections = []mcpVoiceTool{modelToolFixture("issue_refund", true)}
	second.FinishReason = "stop"
	rows, _, post, err = parseModelOutput(modelOutputFixture(first, second))
	if err == nil || post || len(rows) != 1 {
		t.Fatalf("contradictory finish accepted: %v, %d", err, len(rows))
	}
	second = modelCallFixture(2, nil)
	rawAll := modelOutputFixture(first, second)
	rawAll = strings.Replace(rawAll, `"toolExecutionCount":0`, `"toolExecutionCount":1`, 1)
	_, _, post, err = parseModelOutput(rawAll)
	if err == nil || post {
		t.Fatal("executed tool accepted")
	}
}
func TestMCPVoiceModelRuntimeDefaultOffAndExactPins(t *testing.T) {
	voice := VoiceRuntime{Enabled: true, Namespace: "voice", Deployment: "voice-bot", Service: "voice-bot", Container: "bot", ServicePort: 8080, PDB: "voice-bot"}
	mcp := MCPSessionRuntime{Enabled: true, Namespace: "mcp", Deployment: "mcp-server", Service: "mcp-server", Container: "mcp-server", Port: 8000, SourceConfigMap: "mcp-code", SourceKey: "server.py", ExpectedSourceSHA256: mcpInstalledSourceSHA, ExpectedImageID: "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"}
	lite := LiteLLMRuntime{Enabled: true, Namespace: "litellm", Deployment: "litellm", Service: "litellm", Container: "litellm", Port: 4000, ConfigMap: "litellm-config", ConfigKey: "config.yaml", ExpectedConfigSHA256: liteConfigSHA, InferenceEnabled: true, ModelAlias: mcpVoiceModelAlias}
	cfg := MCPVoiceModelRuntime{ExpectedVoiceSourceSHA256: voiceExpectedSourceSHA}
	if ValidateMCPVoiceModelConfig(cfg, voice, &mcp, &lite) == nil {
		t.Fatal("default-off accepted")
	}
	cfg.Enabled = true
	if err := ValidateMCPVoiceModelConfig(cfg, voice, &mcp, &lite); err != nil {
		t.Fatal(err)
	}
	lite.ModelAlias = "other"
	if ValidateMCPVoiceModelConfig(cfg, voice, &mcp, &lite) == nil {
		t.Fatal("alternate route accepted")
	}
}

func modelNameHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}
