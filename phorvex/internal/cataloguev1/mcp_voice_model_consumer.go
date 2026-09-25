package cataloguev1

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// ValidateMCPVoiceModelArtifacts replays original bounded per-call records.
// A terminal map alone cannot promote a synthetic refund observation.
func ValidateMCPVoiceModelArtifacts(job Job, result Result) error {
	if job.Profile != MCPVoiceModel {
		return nil
	}
	if err := ValidateMCPVoiceModelResult(result); err != nil {
		return err
	}
	configured, err := LoadRuntimeConfig(filepath.Join(job.OutputDir, "runtime.json"))
	if err != nil {
		return errors.New("MCP Voice model original runtime unavailable")
	}
	hash, err := configured.SHA256()
	if err != nil || hash != job.RuntimeConfigSHA256 || configured.MCPVoiceModel == nil || !configured.MCPVoiceModel.Enabled {
		return errors.New("MCP Voice model original runtime authority differs")
	}
	path := filepath.Join(job.OutputDir, "journal.jsonl")
	if _, err = os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if result.Evidence["requestCount"] == "0" && result.Outcome != OutcomeFunctionalPass {
			return nil
		}
		return errors.New("MCP Voice model original journal missing")
	}
	if err != nil {
		return err
	}
	journal, err := loadJournal(path)
	if err != nil {
		return err
	}
	intents := 0
	closings := 0
	calls := []mcpVoiceCall{}
	pod := ""
	authority := ""
	for _, record := range journal.Records {
		if record.Kind == "event" && record.Event != nil && record.Event.Step == "mcpvoice.close" {
			closings++
			v := record.Event.Identity
			if closings != 1 || intents != 1 || len(calls) != 2 || record.Event.Status != "verified" || v["authorityBeforeSHA256"] != authority || v["authorityAfterSHA256"] != authority || v["voicePodUID"] != pod || v["voiceSourceSHA256"] != configured.MCPVoiceModel.ExpectedVoiceSourceSHA256 || configured.MCP == nil || v["mcpSourceSHA256"] != configured.MCP.ExpectedSourceSHA256 || configured.LiteLLM == nil || v["liteLLMConfigSHA256"] != configured.LiteLLM.ExpectedConfigSHA256 || v["probeStatus"] != "MODEL_DECISIONS_OBSERVED" || v["postSource"] != "MATCH" || result.Evidence["authorityAfterSHA256"] != v["authorityAfterSHA256"] {
				return errors.New("MCP Voice model original closing authority differs")
			}
		}
		if record.Kind == "intent" && record.Intent != nil && record.Intent.Step == mcpVoiceModelStep {
			intents++
			if intents != 1 || len(calls) != 0 || record.Intent.Identity["maxCalls"] != "2" || record.Intent.Identity["podUID"] == "" || !liteHexSHA256(record.Intent.Identity["authoritySHA256"]) {
				return errors.New("MCP Voice model original intent differs")
			}
			pod = record.Intent.Identity["podUID"]
			authority = record.Intent.Identity["authoritySHA256"]
		}
		if record.Kind == "event" && record.Event != nil && record.Event.Step == mcpVoiceModelStep {
			if intents != 1 || len(calls) >= 2 || record.Event.Status != "observed" || record.Event.Identity["podUID"] != pod || record.Event.Identity["ordinal"] != strconv.Itoa(len(calls)+1) {
				return errors.New("MCP Voice model original event order differs")
			}
			c, err := modelCallFromEvent(record.Event)
			if err != nil || validateModelCall(c, len(calls)+1) != nil || record.Event.Identity["case"] != c.Case {
				return errors.New("MCP Voice model original response invalid")
			}
			calls = append(calls, c)
		}
	}
	n, err := strconv.Atoi(result.Evidence["requestCount"])
	if err != nil || n != len(calls) {
		return errors.New("MCP Voice model terminal count differs from original records")
	}
	if n > 0 && (intents != 1 || result.Evidence["voicePodUID"] != pod || result.Evidence["authorityBeforeSHA256"] != authority) {
		return errors.New("MCP Voice model original Pod or authority differs")
	}
	for _, c := range calls {
		projected := map[string]string{}
		modelCallEvidence(projected, c)
		for key, value := range projected {
			if result.Evidence[key] != value {
				return errors.New("MCP Voice model terminal response differs from original record")
			}
		}
	}
	if result.Outcome == OutcomeFunctionalPass {
		if len(calls) != 2 || closings != 1 || result.Evidence["observationState"] != classifyModelCalls(calls[0], calls[1]) || result.Evidence["observationState"] == "UNKNOWN" || result.Evidence["voiceSourceSHA256"] != configured.MCPVoiceModel.ExpectedVoiceSourceSHA256 || configured.MCP == nil || result.Evidence["mcpSourceSHA256"] != configured.MCP.ExpectedSourceSHA256 || configured.LiteLLM == nil || result.Evidence["liteLLMConfigSHA256"] != configured.LiteLLM.ExpectedConfigSHA256 {
			return errors.New("MCP Voice model completed observation differs from original authority")
		}
	}
	if result.Outcome != OutcomeFunctionalPass && closings != 0 {
		return errors.New("MCP Voice model incomplete result contains a completed closing receipt")
	}
	return nil
}

// The journal stores only allowlisted producer projections. Arbitrary model
// arguments are never retained, so the synthetic-match booleans are pinned
// producer observations, not byte-level recomputations from argument hashes.
func modelCallFromEvent(event *Event) (mcpVoiceCall, error) {
	v := event.Identity
	ordinal, e1 := strconv.Atoi(v["ordinal"])
	status, e2 := strconv.Atoi(v["httpStatus"])
	size, e3 := strconv.Atoi(v["responseBytes"])
	returned, e4 := strconv.ParseBool(v["requestedModelReturned"])
	prompt, e5 := strconv.Atoi(v["usagePromptCount"])
	completion, e6 := strconv.Atoi(v["usageCompletionCount"])
	count, e7 := strconv.Atoi(v["toolCount"])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || e7 != nil || count < 0 || count > 4 {
		return mcpVoiceCall{}, errors.New("MCP Voice model original numeric fields malformed")
	}
	c := mcpVoiceCall{Status: "MODEL_CALL_OBSERVED", Ordinal: ordinal, Case: v["case"], HTTPStatus: status, ResponseSHA256: v["responseSHA256"], ResponseBytes: size, Result: "MODEL_REPLY_OBSERVED", FinishReason: v["finishReason"], RequestedModelReturned: returned, Usage: map[string]int{"prompt_tokens": prompt, "completion_tokens": completion}}
	for i := 0; i < count; i++ {
		p := "tool" + strconv.Itoa(i) + "."
		n, err := strconv.Atoi(v[p+"argumentCount"])
		if err != nil {
			return mcpVoiceCall{}, err
		}
		order, err := strconv.ParseBool(v[p+"syntheticOrderBSelected"])
		if err != nil {
			return mcpVoiceCall{}, err
		}
		amount, err := strconv.ParseBool(v[p+"syntheticAmountOneSelected"])
		if err != nil {
			return mcpVoiceCall{}, err
		}
		var keys []string
		if json.Unmarshal([]byte(v[p+"recognizedArgumentKeys"]), &keys) != nil {
			return mcpVoiceCall{}, errors.New("MCP Voice model original argument keys malformed")
		}
		c.ToolSelections = append(c.ToolSelections, mcpVoiceTool{Name: v[p+"name"], NameSHA256: v[p+"nameSHA256"], ArgumentsSHA256: v[p+"argumentsSHA256"], ArgumentCount: n, RecognizedArgumentKeys: keys, SyntheticOrderBSelected: order, SyntheticAmountOneSelected: amount})
	}
	return c, nil
}
