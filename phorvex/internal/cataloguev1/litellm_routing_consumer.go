package cataloguev1

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// ValidateLiteLLMRoutingResult rejects a positive inference claim unless both
// exact Pods have separate served-completion and typed unknown-model evidence.
func ValidateLiteLLMRoutingResult(result Result) error {
	if result.Profile != LiteLLMRouting {
		return errors.New("LiteLLM routing profile differs")
	}
	e := result.Evidence
	if e["eventMode"] != "none" || e["securityEvent"] != "NOT_REQUIRED" || e["brain"] != "NOT_EVALUATED" || e["actuator"] != "NOT_EVALUATED" || e["securityOutcome"] != "NOT_EVALUATED" {
		return errors.New("LiteLLM routing direct-control limits missing")
	}
	count, err := strconv.Atoi(e["requestCount"])
	if err != nil || count < 0 || count > 4 {
		return errors.New("LiteLLM routing request bound differs")
	}
	if result.Outcome == OutcomeFunctionalFail {
		unexpected := false
		for i := 1; i <= 2; i++ {
			p := fmt.Sprintf("pod%d.unknown.", i)
			if e[p+"status"] == "200" && e[p+"reason"] == "VALID_ASSISTANT_COMPLETION" && e[p+"state"] == "UNVERIFIED" && liteHexSHA256(e[p+"returnedModelSHA256"]) {
				unexpected = true
			}
		}
		if count != 4 || !unexpected || e["authorityBeforeSHA256"] == "" || e["authorityAfterSHA256"] != e["authorityBeforeSHA256"] || !liteModelAliasPattern.MatchString(e["modelAlias"]) {
			return errors.New("LiteLLM routing functional failure lacks exact unexpected completion authority")
		}
	}
	if result.Outcome != OutcomeFunctionalPass {
		if e["knownModelState"] == "COMPLETION_SERVED" && e["unknownModelState"] == "MODEL_REJECTED" {
			return errors.New("LiteLLM routing positive aggregate conflicts with terminal outcome")
		}
		return nil
	}
	if count != 4 || e["knownModelState"] != "COMPLETION_SERVED" || e["unknownModelState"] != "MODEL_REJECTED" || e["authorityBeforeSHA256"] == "" || e["authorityAfterSHA256"] != e["authorityBeforeSHA256"] || e["targetPodCount"] != "2" || e["configSHA256"] == "" || !liteModelAliasPattern.MatchString(e["modelAlias"]) || e["modelAlias"] == liteUnknownAlias {
		return errors.New("LiteLLM routing positive aggregate lacks exact authority")
	}
	if e["pod1.uid"] == "" || e["pod2.uid"] == "" || e["pod1.uid"] == e["pod2.uid"] {
		return errors.New("LiteLLM routing exact Pod identities missing")
	}
	for i := 1; i <= 2; i++ {
		p := fmt.Sprintf("pod%d.", i)
		if e[p+"name"] == "" || e[p+"imageID"] == "" || e[p+"version"] == "" || e[p+"known.status"] != "200" || e[p+"known.state"] != "COMPLETION_SERVED" || e[p+"known.reason"] != "VALID_ASSISTANT_COMPLETION" || !liteHexSHA256(e[p+"known.returnedModelSHA256"]) || e[p+"unknown.state"] != "MODEL_REJECTED" || e[p+"unknown.reason"] != "MODEL_NOT_FOUND" {
			return errors.New("LiteLLM routing Pod positive stage incomplete")
		}
		if !((e[p+"known.modelRelation"] == "REQUEST_ALIAS" && e[p+"known.returnedModel"] == e["modelAlias"]) || (e[p+"known.modelRelation"] == "OTHER_REDACTED" && e[p+"known.returnedModel"] == "")) {
			return errors.New("LiteLLM routing returned model is not safely related to requested alias")
		}
		if e[p+"unknown.status"] != "400" && e[p+"unknown.status"] != "404" {
			return errors.New("LiteLLM routing unknown-model status is not a typed rejection")
		}
		if tokens, err := strconv.Atoi(e[p+"known.usageCompletionCount"]); err != nil || tokens <= 0 {
			return errors.New("LiteLLM routing completion usage unavailable")
		}
	}
	return nil
}

// ValidateLiteLLMRoutingArtifacts replays the original sanitized per-request
// envelopes from the journal. The terminal map cannot promote a bare 400, a
// mismatched Pod or an edited reason to a positive routing observation.
func ValidateLiteLLMRoutingArtifacts(job Job, result Result) error {
	if job.Profile != LiteLLMRouting {
		return nil
	}
	if err := ValidateLiteLLMRoutingResult(result); err != nil {
		return err
	}
	if result.Outcome == OutcomeFunctionalPass || result.Outcome == OutcomeFunctionalFail {
		configured, err := LoadRuntimeConfig(filepath.Join(job.OutputDir, "runtime.json"))
		if err != nil || configured.LiteLLM == nil || !configured.LiteLLM.InferenceEnabled {
			return errors.New("LiteLLM routing original reviewed runtime unavailable")
		}
		hash, err := configured.SHA256()
		if err != nil || hash != job.RuntimeConfigSHA256 || result.Evidence["modelAlias"] != configured.LiteLLM.ModelAlias {
			return errors.New("LiteLLM routing model alias differs from original runtime authority")
		}
	}
	path := filepath.Join(job.OutputDir, "journal.jsonl")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if result.Evidence["requestCount"] == "0" && result.Outcome != OutcomeFunctionalPass {
			return nil
		}
		return errors.New("LiteLLM routing original journal missing")
	} else if err != nil {
		return err
	}
	journal, err := loadJournal(path)
	if err != nil {
		return err
	}
	intents, events := 0, 0
	unexpectedCompletion := false
	wantOrder := [...]string{"pod1.known", "pod1.unknown", "pod2.known", "pod2.unknown"}
	var pending *Intent
	for _, record := range journal.Records {
		if record.Kind == "intent" && record.Intent != nil && (record.Intent.Step == "litellm.routing.known" || record.Intent.Step == "litellm.routing.unknown") {
			if pending != nil || intents >= 4 || record.Intent.Identity["route"] != liteRoutingPath {
				return errors.New("LiteLLM routing intent order or route differs")
			}
			step := "known"
			if record.Intent.Step == "litellm.routing.unknown" {
				step = "unknown"
			}
			pod := ""
			for i := 1; i <= 2; i++ {
				prefix := fmt.Sprintf("pod%d.", i)
				if result.Evidence[prefix+"uid"] != "" && result.Evidence[prefix+"uid"] == record.Intent.Identity["podUID"] && result.Evidence[prefix+"name"] == record.Intent.Identity["podName"] {
					pod = fmt.Sprintf("pod%d", i)
				}
			}
			alias := result.Evidence["modelAlias"]
			if step == "unknown" {
				alias = liteUnknownAlias
			}
			if pod+"."+step != wantOrder[intents] || record.Intent.Identity["modelAlias"] != alias || alias == "" {
				return errors.New("LiteLLM routing exact Pod, request order or reviewed alias differs")
			}
			pending = record.Intent
			intents++
			continue
		}
		if record.Kind != "event" || record.Event == nil || (record.Event.Step != "litellm.routing.known" && record.Event.Step != "litellm.routing.unknown") {
			continue
		}
		if pending == nil || pending.Step != record.Event.Step || pending.Identity["podUID"] != record.Event.Identity["podUID"] || pending.Identity["podName"] != record.Event.Identity["podName"] || record.Event.Status != "observed" {
			return errors.New("LiteLLM routing event has no exact intent")
		}
		step := "known"
		if record.Event.Step == "litellm.routing.unknown" {
			step = "unknown"
		}
		if pending.Identity["requestKind"] != step {
			return errors.New("LiteLLM routing request kind differs")
		}
		i := 0
		for pod := 1; pod <= 2; pod++ {
			p := fmt.Sprintf("pod%d.", pod)
			if result.Evidence[p+"uid"] == pending.Identity["podUID"] && result.Evidence[p+"name"] == pending.Identity["podName"] {
				i = pod
			}
		}
		if i == 0 {
			return errors.New("LiteLLM routing event Pod is not in the terminal authority")
		}
		response, err := liteRoutingResponseFromEvent(record.Event)
		if err != nil {
			return err
		}
		state := "UNVERIFIED"
		if step == "known" && response.Reason == "VALID_ASSISTANT_COMPLETION" {
			state = "COMPLETION_SERVED"
		}
		if step == "unknown" && response.Reason == "MODEL_NOT_FOUND" {
			state = "MODEL_REJECTED"
		}
		if step == "unknown" && response.Reason == "VALID_ASSISTANT_COMPLETION" {
			unexpectedCompletion = true
		}
		p := fmt.Sprintf("pod%d.%s.", i, step)
		if record.Event.Identity["state"] != state || result.Evidence[p+"status"] != strconv.Itoa(response.Status) || result.Evidence[p+"state"] != state || result.Evidence[p+"reason"] != response.Reason || result.Evidence[p+"bodySHA256"] != response.BodySHA256 || result.Evidence[p+"bodyBytes"] != strconv.Itoa(response.BodyBytes) {
			return errors.New("LiteLLM routing terminal stage differs from original response")
		}
		if response.Reason == "VALID_ASSISTANT_COMPLETION" && response.ModelRelation == "REQUEST_ALIAS" && response.ReturnedModel != pending.Identity["modelAlias"] {
			return errors.New("LiteLLM routing original completion model differs from requested alias")
		}
		if response.Reason == "VALID_ASSISTANT_COMPLETION" && (result.Evidence[p+"returnedModel"] != response.ReturnedModel || result.Evidence[p+"returnedModelSHA256"] != response.ReturnedModelSHA256 || result.Evidence[p+"modelRelation"] != response.ModelRelation) {
			return errors.New("LiteLLM routing terminal returned model metadata differs from original response")
		}
		if step == "known" && state == "COMPLETION_SERVED" && (result.Evidence[p+"usagePromptCount"] != strconv.Itoa(response.UsagePromptTokens) || result.Evidence[p+"usageCompletionCount"] != strconv.Itoa(response.UsageCompletionTokens)) {
			return errors.New("LiteLLM routing terminal completion differs from original response")
		}
		pending = nil
		events++
	}
	if result.Outcome == OutcomeFunctionalPass || result.Outcome == OutcomeFunctionalFail {
		if intents != 4 || events != 4 || pending != nil {
			return errors.New("LiteLLM routing terminal claim lacks all four original response receipts")
		}
		if (result.Outcome == OutcomeFunctionalFail) != unexpectedCompletion {
			return errors.New("LiteLLM routing unexpected completion differs from terminal outcome")
		}
	}
	return nil
}

func liteRoutingResponseFromEvent(event *Event) (liteRoutingResponse, error) {
	v := event.Identity
	status, e1 := strconv.Atoi(v["httpStatus"])
	bodyBytes, e2 := strconv.Atoi(v["bodyBytes"])
	completion, e3 := strconv.ParseBool(v["completionValid"])
	prompt, e4 := strconv.Atoi(v["usagePromptCount"])
	output, e5 := strconv.Atoi(v["usageCompletionCount"])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return liteRoutingResponse{}, errors.New("LiteLLM routing original response fields malformed")
	}
	r := liteRoutingResponse{Status: status, ContentType: v["contentType"], BodySHA256: v["bodySHA256"], BodyBytes: bodyBytes, CompletionValid: completion, ReturnedModel: v["returnedModel"], ReturnedModelSHA256: v["returnedModelSHA256"], ModelRelation: v["modelRelation"], UsagePromptTokens: prompt, UsageCompletionTokens: output, Reason: v["reason"], ErrorCode: v["errorCode"]}
	if err := validateLiteRoutingResponse(r); err != nil {
		return liteRoutingResponse{}, err
	}
	return r, nil
}
