package console

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

const (
	voiceSourceSHA = "23b2e6e72912b11a545e06f54af4159789dc3a79f0aaed74cd2ec636cbb371cf"
	voiceImageSHA  = "sha256:c9c598c406ed517eebf17f92a36863b39a15d9a7875cfcb2710f7b084dd539b8"
)

var voiceSID = regexp.MustCompile(`^(AC|CA|MZ)[0-9a-f]{32}$`)
var voiceUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var voiceHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The reviewed Voice result producers project only these fields. Optional
// fields may be absent on a failing run, but extra effect claims must not
// silently widen the predecessor's possible footprint.
var priorVoiceEvidenceKeys = map[string]bool{
	"voiceOutcome": true, "operationID": true, "sessions": true, "evictionDispatches": true,
	"sampleCount": true, "error": true, "authoritySHA256": true,
	"targetPodName": true, "targetPodUID": true, "targetImageID": true,
	"targetContainerID": true, "podSourceFileSHA256": true, "replacementPodUID": true,
	"evictionDisposition": true, "evictionRequestSHA256": true,
	"availabilityMinimumReadyPods": true, "availabilityMinimumReadyEndpoints": true,
	"availabilityMaximumSampleGapSeconds": true, "availabilityScope": true,
	"session1.callSID": true, "session1.streamSID": true, "session1.phase": true,
	"session1.mediaFramesSent": true, "session1.mediaFramesReceived": true,
	"session1.mediaBytesReceived": true, "session1.receivedAudioSHA256": true,
	"session1.closeCode": true, "session1.stopSent": true, "session1.forwardClosed": true,
	"session2.callSID": true, "session2.streamSID": true, "session2.phase": true,
	"session2.mediaFramesSent": true, "session2.mediaFramesReceived": true,
	"session2.mediaBytesReceived": true, "session2.receivedAudioSHA256": true,
	"session2.closeCode": true, "session2.stopSent": true, "session2.forwardClosed": true,
}

var priorVoiceCleanupKeys = map[string]bool{
	"forwardsClosed": true, "documentsFound": true, "documentsRemaining": true,
}

var priorVoiceJournalKeys = map[string][]string{
	"intent/voice.prepare":           {"operationID", "ownerDigest", "mode", "namespace"},
	"event/voice.authority":          {"authoritySHA256", "namespaceUID", "deploymentUID", "replicaSetUID", "serviceUID", "pdbUID"},
	"event/voice.eviction-authority": {"namespace", "resource", "verb"},
	"intent/voice.session":           {"phase", "accountSID", "callSID", "streamSID"},
	"event/voice.session":            {"phase", "callSID", "streamSID", "framesSent", "framesReceived", "bytesReceived", "audioSHA256", "closeCode", "stopSent", "forwardClosed", "error"},
	"intent/voice.eviction":          {"dispatchOrdinal", "pod", "podUID", "resourceVersion", "requestSHA256", "authoritySHA256"},
	"event/voice.eviction":           {"dispatched", "reason", "requestSHA256"},
	"event/voice.availability":       {"samples", "minimumReadyPods", "minimumReadyEndpoints", "maximumGapSeconds", "scope"},
	"intent/voice.transcript-delete": {"callSID", "objectID", "contentSHA256"},
	"event/voice.transcript-delete":  {"callSID", "objectID", "contentSHA256"},
	"event/voice.cleanup":            {"remaining", "forwardsClosed"},
	"event/voice.terminal":           {"operationID", "unsafeToRetry"},
}

// This allowlist covers only the reviewed fixed producers. A Voice cleanup
// failure is retained unchanged; this classifies its possible resource effects.
func disjointVoiceCandidate(profile cataloguev1.ProfileID) bool {
	switch profile {
	case cataloguev1.ChromaOwnedVector, cataloguev1.LiteLLMHealth, cataloguev1.LiteLLMCredential,
		cataloguev1.LiteLLMRouting, cataloguev1.CRMRefund, cataloguev1.CRMReset,
		cataloguev1.GuardrailCalibration, cataloguev1.MCPSessionBaseline:
		return true
	default:
		return false
	}
}

func (rm *RunManager) disjointVoiceAdmissionLocked(profile cataloguev1.ProfileID, destination runDestination, prior *RunStatus) bool {
	if !disjointVoiceCandidate(profile) || prior == nil || prior.ExecutionKind != "fixed-suite" ||
		(prior.Config != string(cataloguev1.VoiceMedia) && prior.Config != string(cataloguev1.VoiceRecovery)) ||
		prior.State != "partial" || prior.Outcome != string(cataloguev1.OutcomeTestFailed) ||
		prior.CleanupStatus != "FAIL" || !prior.UnsafeToRetry || prior.Finished == "" || prior.Owner == "" ||
		prior.ScopeTarget != defaultTargetID || destination.ScopeTarget != defaultTargetID ||
		rm.procs[prior.ID] != nil || rm.stopping[prior.ID] ||
		strings.Contains(prior.Error, "reconciliation pending") || !cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(prior.ID)) {
		return false
	}
	voiceTenant := strings.TrimSpace(rm.cfg.CatalogueV1.VoiceNamespace)
	if voiceTenant != "voice" || prior.ScopeTenant != voiceTenant || destination.ScopeTenant == voiceTenant {
		return false
	}
	switch profile {
	case cataloguev1.ChromaOwnedVector:
		if destination.ScopeTenant != "document-store" || rm.cfg.CatalogueV1.ChromaNamespace != "document-store" {
			return false
		}
	case cataloguev1.LiteLLMHealth, cataloguev1.LiteLLMCredential, cataloguev1.LiteLLMRouting:
		if destination.ScopeTenant != "litellm" || rm.cfg.CatalogueV1.LiteLLMNamespace != "litellm" {
			return false
		}
	case cataloguev1.CRMRefund, cataloguev1.CRMReset:
		if destination.ScopeTenant != rm.cfg.CatalogueV1.CRMNamespace || destination.ScopeTenant == "crm" ||
			// The installed console lives in phorvex-system. The chart also
			// rejects its release namespace, while this direct Config path
			// must reject the installed console namespace itself.
			destination.ScopeTenant == "phorvex-system" ||
			destination.ScopeTenant == rm.cfg.CatalogueV1.AllowedTenant ||
			rm.cfg.CatalogueV1.CRMNamespaceUID == "" || rm.cfg.CatalogueV1.CRMServiceAccountName == "" {
			return false
		}
	case cataloguev1.GuardrailCalibration:
		runtime := rm.cfg.catalogueV1RuntimeConfig().Guardrail
		if destination.ScopeTenant != "vllm" || rm.cfg.CatalogueV1.GuardrailNamespace != "vllm" ||
			runtime == nil || cataloguev1.ValidateGuardrailCalibrationRuntime(*runtime) != nil {
			return false
		}
	case cataloguev1.MCPSessionBaseline:
		runtime := rm.cfg.catalogueV1RuntimeConfig().MCP
		if destination.ScopeTenant != "mcp" || rm.cfg.CatalogueV1.MCPNamespace != "mcp" ||
			runtime == nil || cataloguev1.ValidateMCPSessionRuntime(*runtime) != nil {
			return false
		}
	}
	return rm.validatePriorVoiceFiles(prior) == nil
}

// validatePriorVoiceFiles is local, bounded file I/O under rm.mu. No Kubernetes
// or Mongo request occurs here. Each admission GET and launch POST re-reads the
// original private bytes; no cached status flag can authorize a later launch.
func (rm *RunManager) validatePriorVoiceFiles(prior *RunStatus) error {
	if prior == nil {
		return errors.New("missing prior Voice status")
	}
	dir := rm.cfg.runOutputPath(prior.ID)
	if dir == "" || filepath.Base(dir) != prior.ID {
		return errors.New("prior Voice run directory differs")
	}
	return validatePriorVoiceFilesAt(prior, dir, dir, rm.cfg.StateDir)
}

// The split between storageDir and expectedDir lets a private offline capture
// exercise the identical validator while retaining the original job path as
// the authority. Production always passes the same directory for both.
func validatePriorVoiceFilesAt(prior *RunStatus, storageDir, expectedDir, stateDir string) error {
	if prior == nil || expectedDir != filepath.Join(filepath.Clean(stateDir), "runs", prior.ID) || filepath.Base(storageDir) == "." {
		return errors.New("prior Voice artifact location differs")
	}
	limits := map[string]int64{"job.json": 64 << 10, "runtime.json": 64 << 10,
		"result.json": 64 << 10, "metrics.jsonl": (1 << 20) + 1, "journal.jsonl": 256 * (64 << 10)}
	raw := make(map[string][]byte, len(limits))
	for name, limit := range limits {
		var err error
		raw[name], err = cataloguev1.ReadPrivateArtifact(filepath.Join(storageDir, name), limit)
		if err != nil {
			return fmt.Errorf("prior Voice %s: %w", name, err)
		}
	}
	job, err := cataloguev1.LoadJob(filepath.Join(storageDir, "job.json"), stateDir)
	var capturedJob cataloguev1.Job
	if json.Unmarshal(raw["job.json"], &capturedJob) != nil || !reflect.DeepEqual(job, capturedJob) {
		return errors.New("prior Voice job changed during validation")
	}
	if err != nil || job.RunID != prior.ID || job.OutputDir != expectedDir || string(job.Profile) != prior.Config ||
		job.ResolvedTarget != prior.ScopeTarget || job.ResolvedTenant != prior.ScopeTenant {
		return errors.New("prior Voice job identity differs")
	}
	owner := sha256.Sum256([]byte(prior.Owner))
	if job.OwnerDigest != hex.EncodeToString(owner[:]) {
		return errors.New("prior Voice owner differs")
	}
	definition, err := cataloguev1.DefinitionFor(job.Profile)
	if err != nil {
		return err
	}
	definitionSHA, err := cataloguev1.DefinitionSHA256(definition)
	if err != nil || definitionSHA != job.DefinitionSHA256 || definition.FixedTarget != prior.ScopeTarget || definition.FixedTenant != prior.ScopeTenant {
		return errors.New("prior Voice definition differs")
	}
	runtime, err := cataloguev1.LoadRuntimeConfig(filepath.Join(storageDir, "runtime.json"))
	if err != nil {
		return err
	}
	var capturedRuntime cataloguev1.RuntimeConfig
	if json.Unmarshal(raw["runtime.json"], &capturedRuntime) != nil || !reflect.DeepEqual(runtime, capturedRuntime) {
		return errors.New("prior Voice runtime changed during validation")
	}
	runtimeSHA, err := runtime.SHA256()
	if err != nil || runtimeSHA != job.RuntimeConfigSHA256 || runtime.StateDir != stateDir ||
		!validPriorVoiceRuntime(runtime.Voice, prior.ScopeTenant) {
		return errors.New("prior Voice runtime or source contract differs")
	}
	var result cataloguev1.Result
	if err := json.Unmarshal(raw["result.json"], &result); err != nil {
		return err
	}
	if err := cataloguev1.ValidateResult(job, result); err != nil {
		return err
	}
	for key := range result.Evidence {
		if !priorVoiceEvidenceKeys[key] {
			return errors.New("prior Voice result has an unknown evidence field")
		}
	}
	for key := range result.Cleanup.Details {
		if !priorVoiceCleanupKeys[key] {
			return errors.New("prior Voice result has an unknown cleanup field")
		}
	}
	if err := cataloguev1.ValidateTerminalArtifactBytes(job, result, raw["metrics.jsonl"]); err != nil {
		return err
	}
	legacy, err := priorVoiceProjectionShape(job.Profile, result.Evidence)
	if err != nil {
		return err
	}
	if result.Outcome != cataloguev1.OutcomeTestFailed || result.Cleanup.Status != "FAIL" || result.Cleanup.Verified ||
		!(result.UnsafeToRetry || result.Cleanup.UnsafeToRetry) || result.FinishedAt.IsZero() ||
		result.Evidence["operationID"] != job.RunID || !voiceHex.MatchString(result.Evidence["authoritySHA256"]) ||
		!voiceUID.MatchString(result.Evidence["targetPodUID"]) {
		return errors.New("prior Voice terminal source, target, or cleanup differs")
	}
	if !legacy && (result.Evidence["podSourceFileSHA256"] != voiceSourceSHA ||
		!strings.HasPrefix(result.Evidence["targetContainerID"], "containerd://") ||
		!strings.HasSuffix(result.Evidence["targetImageID"], "@"+voiceImageSHA)) {
		return errors.New("prior Voice current projection source or container differs")
	}
	if err := validatePriorVoiceJournal(job, result, raw["journal.jsonl"], legacy); err != nil {
		return err
	}
	// A concurrent edit or path substitution during parsing is not a valid
	// original. Re-read all five through the same no-follow private-file gate.
	for name, limit := range limits {
		again, err := cataloguev1.ReadPrivateArtifact(filepath.Join(storageDir, name), limit)
		if err != nil || !bytes.Equal(again, raw[name]) {
			return errors.New("prior Voice original artifact changed during admission")
		}
	}
	return nil
}

// The pre-d5a81fe7 VoiceRecovery producer projected Pod UIDs and session
// phases but left these later-added fields absent. Its reviewed effect path
// still checked every baseline Pod's bot source before recording the eviction
// authority event. A mixed projection is never accepted as either version.
func priorVoiceProjectionShape(profile cataloguev1.ProfileID, evidence map[string]string) (legacy bool, err error) {
	fields := []string{"podSourceFileSHA256", "targetPodName", "targetImageID", "targetContainerID", "session1.callSID", "session1.streamSID"}
	if profile == cataloguev1.VoiceRecovery {
		fields = append(fields, "session2.callSID", "session2.streamSID")
	}
	present := 0
	for _, field := range fields {
		if _, ok := evidence[field]; ok {
			present++
		}
	}
	switch {
	case present == len(fields):
		return false, nil
	case present == 0 && profile == cataloguev1.VoiceRecovery:
		return true, nil
	default:
		return false, errors.New("prior Voice result has an unsupported or mixed producer projection")
	}
}

func validPriorVoiceRuntime(v cataloguev1.VoiceRuntime, tenant string) bool {
	return v.Enabled && tenant == "voice" && v.Namespace == tenant && v.Deployment == "voice-bot" &&
		v.Service == "voice-bot" && v.PDB == "voice-bot" && v.Container == "bot" && v.ServicePort == 8080 &&
		v.TranscriptPodSelector == "app=voice-bot" && v.TranscriptContainer == "bot"
}

func validatePriorVoiceJournal(job cataloguev1.Job, result cataloguev1.Result, raw []byte, legacy bool) error {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return errors.New("prior Voice journal is incomplete")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	count := map[string]int{}
	intents := map[string]map[string]string{}
	events := map[string]map[string]string{}
	deletes := map[string]bool{}
	seenDeletes := map[string]bool{}
	var sequence []string
	for scanner.Scan() {
		if len(sequence) >= 256 || len(scanner.Bytes()) == 0 {
			return errors.New("prior Voice journal record count or blank row differs")
		}
		var record cataloguev1.JournalRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return err
		}
		var step, key string
		var identity map[string]string
		if record.Kind == "intent" && record.Intent != nil && record.Event == nil {
			step, identity = record.Intent.Step, record.Intent.Identity
			key = "intent/" + step
		} else if record.Kind == "event" && record.Event != nil && record.Intent == nil {
			step, identity = record.Event.Step, record.Event.Identity
			key = "event/" + step
		} else {
			return errors.New("prior Voice journal kind differs")
		}
		wantKeys, known := priorVoiceJournalKeys[key]
		if !known || len(identity) != len(wantKeys) {
			return fmt.Errorf("prior Voice journal has unknown operation %q", key)
		}
		for _, field := range wantKeys {
			if _, ok := identity[field]; !ok {
				return fmt.Errorf("prior Voice journal %q lacks field %q", key, field)
			}
		}
		if record.Intent != nil && record.Intent.Mutation != (step == "voice.eviction" || step == "voice.transcript-delete") {
			return errors.New("prior Voice journal mutation classification differs")
		}
		count[key]++
		sequence = append(sequence, key)
		for k, v := range identity {
			if k == "" || len(k) > 64 || len(v) > 512 || strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "secret") {
				return errors.New("prior Voice journal identity is invalid")
			}
		}
		if key == "intent/voice.session" || key == "event/voice.session" {
			phase := identity["phase"]
			if (phase != "normal" && phase != "interrupted" && phase != "recovery") ||
				!voiceSID.MatchString(identity["callSID"]) || !strings.HasPrefix(identity["callSID"], "CA") ||
				!voiceSID.MatchString(identity["streamSID"]) || !strings.HasPrefix(identity["streamSID"], "MZ") {
				return errors.New("prior Voice session SID or phase differs")
			}
			if key == "intent/voice.session" {
				if !strings.HasPrefix(identity["accountSID"], "AC") || !voiceSID.MatchString(identity["accountSID"]) || intents[phase] != nil {
					return errors.New("prior Voice session intent differs")
				}
				intents[phase] = identity
			} else {
				if events[phase] != nil || (record.Event.Status != "complete" && record.Event.Status != "incomplete") {
					return errors.New("prior Voice session result differs")
				}
				events[phase] = identity
			}
		}
		if key == "intent/voice.transcript-delete" || key == "event/voice.transcript-delete" {
			ref := identity["callSID"] + "/" + identity["objectID"] + "/" + identity["contentSHA256"]
			if !voiceHex.MatchString(identity["contentSHA256"]) || len(identity["objectID"]) != 24 ||
				!voiceSID.MatchString(identity["callSID"]) || !strings.HasPrefix(identity["callSID"], "CA") {
				return errors.New("prior Voice transcript effect identity differs")
			}
			if key == "intent/voice.transcript-delete" {
				if !record.Intent.Mutation || deletes[ref] || seenDeletes[ref] {
					return errors.New("prior Voice transcript intent is duplicated or nonmutating")
				}
				deletes[ref] = true
				seenDeletes[ref] = true
			} else if !deletes[ref] || record.Event.Status != "accepted" {
				return errors.New("prior Voice transcript receipt is ambiguous")
			} else {
				delete(deletes, ref)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(sequence) < 5 || sequence[0] != "intent/voice.prepare" || sequence[1] != "event/voice.authority" ||
		sequence[len(sequence)-2] != "event/voice.cleanup" || sequence[len(sequence)-1] != "event/voice.terminal" || len(deletes) != 0 ||
		count["intent/voice.prepare"] != 1 || count["event/voice.authority"] != 1 || count["event/voice.cleanup"] != 1 || count["event/voice.terminal"] != 1 ||
		count["intent/voice.session"] != count["event/voice.session"] || count["intent/voice.session"] == 0 {
		return errors.New("prior Voice journal sequence or effect receipts differ")
	}
	var prepare, authority, evictionAuthority, availability, cleanup, terminal *cataloguev1.JournalRecord
	// Scan the small validated journal again for exact terminal joins.
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		var record cataloguev1.JournalRecord
		_ = json.Unmarshal(line, &record)
		switch {
		case record.Intent != nil && record.Intent.Step == "voice.prepare":
			prepare = &record
		case record.Event != nil && record.Event.Step == "voice.authority":
			authority = &record
		case record.Event != nil && record.Event.Step == "voice.eviction-authority":
			evictionAuthority = &record
		case record.Event != nil && record.Event.Step == "voice.availability":
			availability = &record
		case record.Event != nil && record.Event.Step == "voice.cleanup":
			cleanup = &record
		case record.Event != nil && record.Event.Step == "voice.terminal":
			terminal = &record
		}
	}
	mode := "normal-media"
	phase := "normal"
	if job.Profile == cataloguev1.VoiceRecovery {
		mode, phase = "replacement-recovery", "interrupted"
	}
	if prepare == nil || authority == nil || cleanup == nil || terminal == nil ||
		prepare.Intent.Identity["operationID"] != job.RunID || prepare.Intent.Identity["ownerDigest"] != job.OwnerDigest ||
		prepare.Intent.Identity["mode"] != mode || prepare.Intent.Identity["namespace"] != job.ResolvedTenant ||
		authority.Event.Status != "ready" || authority.Event.Identity["authoritySHA256"] != result.Evidence["authoritySHA256"] ||
		!voiceUID.MatchString(authority.Event.Identity["namespaceUID"]) || !voiceUID.MatchString(authority.Event.Identity["deploymentUID"]) ||
		!voiceUID.MatchString(authority.Event.Identity["replicaSetUID"]) || !voiceUID.MatchString(authority.Event.Identity["serviceUID"]) ||
		!voiceUID.MatchString(authority.Event.Identity["pdbUID"]) || cleanup.Event.Status != "FAIL" ||
		cleanup.Event.Identity["remaining"] != result.Cleanup.Details["documentsRemaining"] ||
		cleanup.Event.Identity["forwardsClosed"] != result.Cleanup.Details["forwardsClosed"] ||
		terminal.Event.Identity["operationID"] != job.RunID || terminal.Event.Identity["unsafeToRetry"] != "true" ||
		terminal.Event.Status != result.Evidence["voiceOutcome"] {
		return errors.New("prior Voice journal source, authority, or terminal differs")
	}
	if intents[phase] == nil || events[phase] == nil ||
		intents[phase]["callSID"] != events[phase]["callSID"] || intents[phase]["streamSID"] != events[phase]["streamSID"] ||
		result.Evidence["session1.phase"] != phase ||
		(!legacy && (result.Evidence["session1.callSID"] != intents[phase]["callSID"] ||
			result.Evidence["session1.streamSID"] != intents[phase]["streamSID"])) {
		return errors.New("prior Voice first session differs")
	}
	for ref := range seenDeletes {
		sid := strings.SplitN(ref, "/", 2)[0]
		owned := false
		for _, session := range intents {
			owned = owned || session["callSID"] == sid
		}
		if !owned {
			return errors.New("prior Voice transcript effect targets a foreign SID")
		}
	}
	if job.Profile == cataloguev1.VoiceMedia {
		if len(intents) != 1 || len(events) != 1 || count["intent/voice.eviction"] != 0 || count["event/voice.eviction"] != 0 ||
			count["event/voice.eviction-authority"] != 0 || count["event/voice.availability"] != 0 ||
			result.Evidence["sessions"] != "1" || !voiceJournalOrder(sequence, false) {
			return errors.New("prior Voice media journal contains recovery effect")
		}
		return nil
	}
	if len(intents) != 2 || len(events) != 2 || intents["recovery"] == nil || events["recovery"] == nil ||
		intents["recovery"]["callSID"] != events["recovery"]["callSID"] ||
		intents["recovery"]["streamSID"] != events["recovery"]["streamSID"] ||
		intents["recovery"]["callSID"] == intents["interrupted"]["callSID"] ||
		result.Evidence["session2.phase"] != "recovery" ||
		(!legacy && (result.Evidence["session2.callSID"] != intents["recovery"]["callSID"] ||
			result.Evidence["session2.streamSID"] != intents["recovery"]["streamSID"])) ||
		result.Evidence["sessions"] != "2" || count["event/voice.eviction-authority"] != 1 ||
		count["intent/voice.eviction"] != 1 || count["event/voice.eviction"] != 1 ||
		count["event/voice.availability"] != 1 || !voiceUID.MatchString(result.Evidence["replacementPodUID"]) ||
		result.Evidence["replacementPodUID"] == result.Evidence["targetPodUID"] {
		return errors.New("prior Voice recovery session or eviction shape differs")
	}
	var evictionIntent *cataloguev1.Intent
	var evictionEvent *cataloguev1.Event
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		var record cataloguev1.JournalRecord
		_ = json.Unmarshal(line, &record)
		if record.Intent != nil && record.Intent.Step == "voice.eviction" {
			evictionIntent = record.Intent
		}
		if record.Event != nil && record.Event.Step == "voice.eviction" {
			evictionEvent = record.Event
		}
	}
	if evictionIntent == nil || evictionEvent == nil || !evictionIntent.Mutation ||
		evictionIntent.Identity["podUID"] != result.Evidence["targetPodUID"] ||
		(!legacy && evictionIntent.Identity["pod"] != result.Evidence["targetPodName"]) ||
		(legacy && !strings.HasPrefix(evictionIntent.Identity["pod"], "voice-bot-")) ||
		evictionIntent.Identity["dispatchOrdinal"] != "1" || evictionIntent.Identity["resourceVersion"] == "" ||
		evictionIntent.Identity["authoritySHA256"] != result.Evidence["authoritySHA256"] ||
		!voiceHex.MatchString(evictionIntent.Identity["requestSHA256"]) ||
		evictionEvent.Status != "accepted" || evictionEvent.Identity["dispatched"] != "true" ||
		evictionEvent.Identity["requestSHA256"] != evictionIntent.Identity["requestSHA256"] ||
		result.Evidence["evictionDisposition"] != "accepted" || result.Evidence["evictionRequestSHA256"] != evictionIntent.Identity["requestSHA256"] ||
		result.Evidence["evictionDispatches"] != "1" || evictionAuthority == nil ||
		evictionAuthority.Event.Status != "allowed" || evictionAuthority.Event.Identity["namespace"] != job.ResolvedTenant ||
		evictionAuthority.Event.Identity["resource"] != "pods/eviction" || evictionAuthority.Event.Identity["verb"] != "create" ||
		availability == nil || availability.Event.Status != "observed" || availability.Event.Identity["scope"] != "sparse-samples" ||
		!voiceJournalOrder(sequence, true) {
		return errors.New("prior Voice recovery eviction receipt differs")
	}
	if n, err := strconv.Atoi(cleanup.Event.Identity["remaining"]); err != nil || n < 0 {
		return errors.New("prior Voice cleanup remaining count is invalid")
	}
	return nil
}

func voiceJournalOrder(sequence []string, recovery bool) bool {
	index := func(key string) int {
		for i, step := range sequence {
			if step == key {
				return i
			}
		}
		return -1
	}
	firstIntent, firstEvent := index("intent/voice.session"), index("event/voice.session")
	if firstIntent <= 1 || firstEvent <= firstIntent || firstEvent >= len(sequence)-2 {
		return false
	}
	minDeleteIndex := firstEvent
	if recovery {
		authority, evictionIntent, evictionEvent, availability := index("event/voice.eviction-authority"), index("intent/voice.eviction"), index("event/voice.eviction"), index("event/voice.availability")
		if authority != 2 || firstIntent <= authority || evictionIntent <= firstIntent || evictionEvent <= evictionIntent || firstEvent <= evictionEvent || availability <= firstEvent {
			return false
		}
		secondIntent, secondEvent := -1, -1
		for i := firstIntent + 1; i < len(sequence); i++ {
			if sequence[i] == "intent/voice.session" {
				secondIntent = i
				break
			}
		}
		for i := firstEvent + 1; i < len(sequence); i++ {
			if sequence[i] == "event/voice.session" {
				secondEvent = i
				break
			}
		}
		if secondIntent <= firstEvent || secondEvent <= secondIntent || availability <= secondEvent {
			return false
		}
		minDeleteIndex = availability
	}
	for i, step := range sequence {
		if (step == "intent/voice.transcript-delete" || step == "event/voice.transcript-delete") &&
			(i <= minDeleteIndex || i >= len(sequence)-2) {
			return false
		}
	}
	return true
}
