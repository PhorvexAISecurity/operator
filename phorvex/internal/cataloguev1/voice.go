package cataloguev1

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	voiceExpectedSourceSHA = "23b2e6e72912b11a545e06f54af4159789dc3a79f0aaed74cd2ec636cbb371cf"
	voiceExpectedImage     = "sha256:c9c598c406ed517eebf17f92a36863b39a15d9a7875cfcb2710f7b084dd539b8"
	voiceCleanupMax        = 2 * time.Minute
)

//go:embed testdata/voice_hello_8khz.ulaw
var voiceAssets embed.FS

type voiceHandler struct {
	profile    ProfileID
	mode       VoiceMode
	newRuntime func(Runtime) (VoiceDriver, error)
}

func NewVoiceMediaHandler() Handler {
	return &voiceHandler{profile: VoiceMedia, mode: VoiceNormalMedia, newRuntime: newKubeVoiceRuntime}
}

func NewVoiceRecoveryHandler() Handler {
	return &voiceHandler{profile: VoiceRecovery, mode: VoiceReplacementRecovery, newRuntime: newKubeVoiceRuntime}
}

func (h *voiceHandler) Definition() Definition {
	definition, err := DefinitionFor(h.profile)
	if err != nil {
		panic(err)
	}
	return definition
}

func (h *voiceHandler) Validate(runtime Runtime) error {
	if !runtime.Voice.Enabled {
		return errors.New("installed Voice functional profile is disabled")
	}
	if runtime.RESTConfig == nil || runtime.Kube == nil {
		return errors.New("installed Voice Kubernetes clients are unavailable")
	}
	v := runtime.Voice
	if v.Namespace != "voice" || v.Deployment != "voice-bot" || v.Service != "voice-bot" || v.PDB != "voice-bot" || v.Container != "bot" || v.ServicePort != 8080 {
		return errors.New("installed Voice fixture identity differs from the reviewed contract")
	}
	if strings.TrimSpace(v.TranscriptPodSelector) == "" || v.TranscriptContainer != "bot" {
		return errors.New("installed Voice transcript cleanup identity is incomplete")
	}
	return nil
}

func (h *voiceHandler) config(jc JobContext) VoiceConfig {
	return VoiceConfig{
		SchemaVersion: "phorvex.catalogue.voice.v1", Mode: h.mode, OperationID: jc.Job.RunID,
		OwnerDigest: jc.Job.OwnerDigest, Namespace: jc.Runtime.Voice.Namespace,
		DeploymentName: jc.Runtime.Voice.Deployment, ServiceName: jc.Runtime.Voice.Service,
		PDBName: jc.Runtime.Voice.PDB, ContainerName: jc.Runtime.Voice.Container,
		Port: jc.Runtime.Voice.ServicePort, ExpectedReplicas: 3, MinimumReady: 2,
		ExpectedImageDigest: voiceExpectedImage, BotSourcePath: "/app/bot.py",
		BotSourceSHA256: voiceExpectedSourceSHA, AudioSHA256: VoiceAudioSHA256,
	}
}

func (h *voiceHandler) Run(ctx context.Context, jc JobContext) Result {
	started := time.Now().UTC()
	result := Result{Outcome: OutcomeTestFailed, Summary: "Voice functional worker did not complete", StartedAt: started,
		Cleanup: Cleanup{Status: "not-started"}, Evidence: map[string]string{}, Limits: []string{h.Definition().ClaimLimits}}
	cfg := h.config(jc)
	if err := cfg.Validate(); err != nil {
		result.Summary, result.FinishedAt = err.Error(), time.Now().UTC()
		return result
	}
	runtime, err := h.newRuntime(jc.Runtime)
	if err != nil {
		result.Summary, result.FinishedAt = err.Error(), time.Now().UTC()
		return result
	}
	voiceResult := runVoice(ctx, cfg, runtime, jc.Recorder)
	return projectVoiceResult(h.Definition(), voiceResult, started)
}

func (h *voiceHandler) Reconcile(ctx context.Context, jc JobContext, journal Journal) Cleanup {
	cfg := h.config(jc)
	if err := cfg.Validate(); err != nil {
		return Cleanup{Attempted: true, Status: "invalid-config", UnsafeToRetry: true, Details: map[string]string{"error": err.Error()}}
	}
	runtime, err := h.newRuntime(jc.Runtime)
	if err != nil {
		return Cleanup{Attempted: true, Status: "runtime-unavailable", UnsafeToRetry: true, Details: map[string]string{"error": err.Error()}}
	}
	return reconcileVoice(ctx, cfg, runtime, jc.Recorder, journal)
}

func projectVoiceResult(def Definition, vr VoiceResult, started time.Time) Result {
	out := Result{StartedAt: started, FinishedAt: vr.FinishedAt, Summary: vr.Outcome, Limits: []string{def.ClaimLimits},
		Evidence: map[string]string{"voiceOutcome": vr.Outcome, "operationID": vr.OperationID,
			"sessions": strconv.Itoa(len(vr.Sessions)), "evictionDispatches": strconv.Itoa(vr.EvictionDispatches),
			"sampleCount": strconv.Itoa(len(vr.Availability))},
		Cleanup: Cleanup{Attempted: true, Verified: vr.Cleanup.Status == "PASS", Status: vr.Cleanup.Status,
			UnsafeToRetry: vr.Cleanup.UnsafeToRetry, Details: map[string]string{
				"forwardsClosed":     strconv.FormatBool(vr.Cleanup.ForwardsClosed),
				"documentsFound":     strconv.Itoa(vr.Cleanup.DocumentsFound),
				"documentsRemaining": strconv.Itoa(vr.Cleanup.DocumentsRemaining),
			}},
		UnsafeToRetry: vr.RecoveryRequired || vr.Cleanup.UnsafeToRetry,
	}
	if vr.Error != "" {
		out.Evidence["error"] = vr.Error
	}
	out.Evidence["authoritySHA256"] = vr.AuthoritySHA256
	if vr.Target != nil {
		out.Evidence["targetPodUID"] = vr.Target.UID
	}
	if vr.Replacement != nil {
		out.Evidence["replacementPodUID"] = vr.Replacement.UID
	}
	if vr.Eviction != nil {
		out.Evidence["evictionDisposition"] = string(vr.Eviction.Disposition)
		out.Evidence["evictionRequestSHA256"] = vr.Eviction.RequestSHA256
	}
	for i, session := range vr.Sessions {
		prefix := "session" + strconv.Itoa(i+1) + "."
		out.Evidence[prefix+"phase"] = session.Phase
		out.Evidence[prefix+"mediaFramesSent"] = strconv.Itoa(session.MediaFramesSent)
		out.Evidence[prefix+"mediaFramesReceived"] = strconv.Itoa(session.MediaFramesReceived)
		out.Evidence[prefix+"mediaBytesReceived"] = strconv.Itoa(session.MediaBytesReceived)
		out.Evidence[prefix+"receivedAudioSHA256"] = session.ReceivedAudioSHA256
		out.Evidence[prefix+"closeCode"] = strconv.Itoa(session.CloseCode)
		out.Evidence[prefix+"stopSent"] = strconv.FormatBool(session.StopSent)
		out.Evidence[prefix+"forwardClosed"] = strconv.FormatBool(session.ForwardClosed)
	}
	if len(vr.Availability) > 0 {
		minPods, minEndpoints, maxGap := availabilityEvidence(vr.Availability)
		out.Evidence["availabilityMinimumReadyPods"] = strconv.Itoa(minPods)
		out.Evidence["availabilityMinimumReadyEndpoints"] = strconv.Itoa(minEndpoints)
		out.Evidence["availabilityMaximumSampleGapSeconds"] = strconv.FormatFloat(maxGap, 'f', 6, 64)
		out.Evidence["availabilityScope"] = "sparse-samples-not-continuous-availability"
	}
	switch vr.Outcome {
	case VoiceOutcomeMediaPass, VoiceOutcomeRecoveryPass:
		out.Outcome = OutcomeFunctionalPass
	case VoiceOutcomeEvictionRefused:
		out.Outcome, out.Summary = OutcomeFunctionalFail, "PDB eviction was definitely refused without an observed effect"
	case VoiceOutcomeEvictionUnknown:
		out.Outcome, out.Summary = OutcomeInconclusive, "PDB eviction outcome is uncertain and was not retried"
	default:
		out.Outcome = OutcomeTestFailed
		if vr.Error != "" {
			out.Summary = vr.Error
		}
	}
	if !out.Cleanup.Verified && out.Outcome == OutcomeFunctionalPass {
		out.Outcome, out.Summary, out.UnsafeToRetry = OutcomeTestFailed, "Voice oracle completed but exact cleanup was not verified", true
	}
	return out
}

func runVoice(ctx context.Context, cfg VoiceConfig, runtime VoiceDriver, recorder Recorder) (result VoiceResult) {
	result = VoiceResult{SchemaVersion: "phorvex.catalogue.voice.result.v1", OperationID: cfg.OperationID, Mode: cfg.Mode,
		StartedAt: time.Now().UTC(), Outcome: VoiceOutcomeIncomplete, Cleanup: VoiceCleanup{Status: "NOT_STARTED"}}
	if err := recorder.Intent(Intent{Step: "voice.prepare", Identity: map[string]string{"operationID": cfg.OperationID, "ownerDigest": cfg.OwnerDigest, "mode": string(cfg.Mode), "namespace": cfg.Namespace}}); err != nil {
		voiceFailure(&result, fmt.Errorf("persist Voice preparation intent: %w", err))
		result.FinishedAt = time.Now().UTC()
		return result
	}
	baseline, err := runtime.Snapshot(ctx, cfg)
	if err != nil {
		voiceFailure(&result, fmt.Errorf("read Voice authority: %w", err))
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if err = validateVoiceReady(cfg, baseline); err != nil {
		voiceFailure(&result, err)
		result.FinishedAt = time.Now().UTC()
		return result
	}
	authoritySHA, err := voiceAuthoritySHA(baseline)
	if err != nil {
		voiceFailure(&result, err)
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.AuthoritySHA256 = authoritySHA
	if err = recorder.Event(Event{Step: "voice.authority", Status: "ready", Identity: map[string]string{"authoritySHA256": authoritySHA, "namespaceUID": baseline.NamespaceUID, "deploymentUID": baseline.DeploymentUID, "replicaSetUID": baseline.ReplicaSetUID, "serviceUID": baseline.ServiceUID, "pdbUID": baseline.PDBUID}}); err != nil {
		voiceFailure(&result, err)
		result.FinishedAt = time.Now().UTC()
		return result
	}
	for _, pod := range baseline.Pods {
		got, sourceErr := runtime.SourceSHA256(ctx, cfg, pod)
		if sourceErr != nil || got != cfg.BotSourceSHA256 {
			voiceFailure(&result, voiceErr("Voice Pod %s source identity differs", pod.Name))
			result.FinishedAt = time.Now().UTC()
			return result
		}
	}
	if cfg.Mode == VoiceReplacementRecovery {
		if err = runtime.CanEvict(ctx, cfg); err != nil {
			voiceFailure(&result, fmt.Errorf("Voice eviction authority unavailable: %w", err))
			result.FinishedAt = time.Now().UTC()
			return result
		}
		if err = recorder.Event(Event{Step: "voice.eviction-authority", Status: "allowed", Identity: map[string]string{"namespace": cfg.Namespace, "resource": "pods/eviction", "verb": "create"}}); err != nil {
			voiceFailure(&result, err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
	}
	audio, err := voiceAssets.ReadFile("testdata/voice_hello_8khz.ulaw")
	if err != nil || len(audio) < 8000 || len(audio) > 80000 {
		voiceFailure(&result, errors.New("embedded Voice audio is unavailable or outside bounds"))
		result.FinishedAt = time.Now().UTC()
		return result
	}

	var sessions []VoiceSession
	cleanupPod := baseline.Pods[0]
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), voiceCleanupMax)
		defer cancel()
		if current, currentErr := runtime.Snapshot(cleanupCtx, cfg); currentErr == nil {
			for _, candidate := range current.Pods {
				if candidate.Ready && candidate.Started && !candidate.Terminating && candidate.ReplicaSetUID == current.ReplicaSetUID {
					cleanupPod = candidate
					break
				}
			}
		}
		callSIDs := make([]string, 0, len(sessions))
		for _, session := range sessions {
			if session.CallSID != "" {
				callSIDs = append(callSIDs, session.CallSID)
			}
		}
		if len(callSIDs) == 0 {
			result.Cleanup = VoiceCleanup{Status: "PASS", ForwardsClosed: true}
		} else {
			result.Cleanup = runtime.CleanupTranscripts(cleanupCtx, cfg, cleanupPod, callSIDs,
				func(ref TranscriptRef) error {
					return recorder.Intent(Intent{Step: "voice.transcript-delete", Mutation: true, Identity: map[string]string{"callSID": ref.CallSID, "objectID": ref.ObjectID, "contentSHA256": ref.ContentSHA256}})
				}, func(ref TranscriptRef) error {
					return recorder.Event(Event{Step: "voice.transcript-delete", Status: "accepted", Identity: map[string]string{"callSID": ref.CallSID, "objectID": ref.ObjectID, "contentSHA256": ref.ContentSHA256}})
				})
		}
		for _, session := range sessions {
			if session.StartSent && !session.ForwardClosed {
				result.Cleanup.ForwardsClosed = false
				result.Cleanup.Status, result.Cleanup.UnsafeToRetry = "FAIL", true
			}
		}
		if result.Cleanup.Status != "PASS" {
			result.Outcome, result.RecoveryRequired = VoiceOutcomeIncomplete, true
			if result.Error == "" {
				result.Error = "owned Voice cleanup was not verified"
			}
		}
		if eventErr := recorder.Event(Event{Step: "voice.cleanup", Status: result.Cleanup.Status, Identity: map[string]string{"remaining": strconv.Itoa(result.Cleanup.DocumentsRemaining), "forwardsClosed": strconv.FormatBool(result.Cleanup.ForwardsClosed)}}); eventErr != nil {
			result.Outcome, result.RecoveryRequired = VoiceOutcomeIncomplete, true
			result.Cleanup.Status, result.Cleanup.UnsafeToRetry = "FAIL", true
			result.Error = "persist Voice cleanup result: " + eventErr.Error()
		}
		result.FinishedAt = time.Now().UTC()
		if eventErr := recorder.Event(Event{Step: "voice.terminal", Status: result.Outcome, Identity: map[string]string{"operationID": cfg.OperationID, "unsafeToRetry": strconv.FormatBool(result.RecoveryRequired || result.Cleanup.UnsafeToRetry)}}); eventErr != nil {
			result.Outcome, result.RecoveryRequired = VoiceOutcomeIncomplete, true
			result.Cleanup.Status, result.Cleanup.UnsafeToRetry = "FAIL", true
			result.Error = "persist Voice terminal result: " + eventErr.Error()
		}
	}()

	if cfg.Mode == VoiceNormalMedia {
		session, newErr := newVoiceSession("normal")
		if newErr != nil {
			voiceFailure(&result, newErr)
			return result
		}
		sessions = append(sessions, session)
		if err = recordSessionIntent(recorder, session); err != nil {
			voiceFailure(&result, err)
			return result
		}
		sessions[0] = runtime.RunMedia(ctx, cfg, baseline.Pods[0], session, audio, nil)
		result.Sessions = sessions
		if err = recordSessionResult(recorder, sessions[0]); err != nil {
			voiceFailure(&result, err)
			result.RecoveryRequired = true
			return result
		}
		if err = validateSession(sessions[0], false); err != nil {
			voiceFailure(&result, err)
			return result
		}
		after, afterErr := runtime.Snapshot(ctx, cfg)
		if afterErr != nil || !voiceSameAuthority(baseline, after, false) {
			voiceFailure(&result, errors.New("installed Voice authority changed during normal media"))
			return result
		}
		result.Outcome = VoiceOutcomeMediaPass
		return result
	}

	return runVoiceRecovery(ctx, cfg, runtime, recorder, baseline, authoritySHA, audio, &result, &sessions, &cleanupPod)
}

func runVoiceRecovery(ctx context.Context, cfg VoiceConfig, runtime VoiceDriver, recorder Recorder, baseline VoiceSnapshot, authoritySHA string, audio []byte, result *VoiceResult, sessions *[]VoiceSession, cleanupPod *VoicePod) (out VoiceResult) {
	target := baseline.Pods[0]
	result.Target = &target
	first, err := newVoiceSession("interrupted")
	if err != nil {
		voiceFailure(result, err)
		return *result
	}
	second, err := newVoiceSession("recovery")
	if err != nil {
		voiceFailure(result, err)
		return *result
	}
	*sessions = append(*sessions, first, second)
	if err = recordSessionIntent(recorder, first); err != nil {
		voiceFailure(result, err)
		return *result
	}

	watchCtx, stopWatch := context.WithCancel(ctx)
	var watchWG sync.WaitGroup
	var availability []AvailabilitySample
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		availability = watchVoiceAvailability(watchCtx, cfg, runtime)
	}()
	defer func() {
		stopWatch()
		watchWG.Wait()
		out.Availability = availability
		minPods, minEndpoints, maxGap := availabilityEvidence(availability)
		if eventErr := recorder.Event(Event{Step: "voice.availability", Status: "observed", Identity: map[string]string{"samples": strconv.Itoa(len(availability)), "minimumReadyPods": strconv.Itoa(minPods), "minimumReadyEndpoints": strconv.Itoa(minEndpoints), "maximumGapSeconds": strconv.FormatFloat(maxGap, 'f', 6, 64), "scope": "sparse-samples"}}); eventErr != nil {
			voiceFailure(&out, fmt.Errorf("persist Voice availability result: %w", eventErr))
			out.RecoveryRequired = true
			return
		}
		if out.Outcome == VoiceOutcomeRecoveryPass {
			if len(availability) < 2 {
				voiceFailure(&out, errors.New("Voice availability sampling did not retain two observations"))
				return
			}
			for _, sample := range availability {
				if !sample.Known || sample.ReadyPods < int(cfg.MinimumReady) || sample.ReadyEndpoints < int(cfg.MinimumReady) {
					voiceFailure(&out, errors.New("Voice sampled availability floor was not preserved"))
					return
				}
			}
		}
	}()

	dispatches := 0
	interrupt := func(effectCtx context.Context) (VoiceEviction, error) {
		current, readErr := runtime.Snapshot(effectCtx, cfg)
		if readErr != nil || !voiceSameAuthority(baseline, current, false) {
			return VoiceEviction{}, errors.New("Voice authority changed before eviction")
		}
		currentTarget, ok := current.FindPod(target.UID)
		if !ok || currentTarget != target {
			return VoiceEviction{}, errors.New("Voice target identity changed before eviction")
		}
		if dispatches != 0 {
			return VoiceEviction{}, errors.New("Voice eviction retry forbidden")
		}
		request := map[string]any{"apiVersion": "policy/v1", "kind": "Eviction", "metadata": map[string]string{"name": target.Name, "namespace": cfg.Namespace}, "deleteOptions": map[string]any{"preconditions": map[string]string{"uid": target.UID, "resourceVersion": target.ResourceVersion}}}
		requestSHA, hashErr := voiceCanonicalSHA(request)
		if hashErr != nil {
			return VoiceEviction{}, hashErr
		}
		if err := recorder.Intent(Intent{Step: "voice.eviction", Mutation: true, Identity: map[string]string{"dispatchOrdinal": "1", "pod": target.Name, "podUID": target.UID, "resourceVersion": target.ResourceVersion, "requestSHA256": requestSHA, "authoritySHA256": authoritySHA}}); err != nil {
			return VoiceEviction{}, err
		}
		dispatches++
		receipt := runtime.Evict(effectCtx, cfg, target)
		receipt.RequestSHA256 = requestSHA
		if eventErr := recorder.Event(Event{Step: "voice.eviction", Status: string(receipt.Disposition), Identity: map[string]string{"dispatched": strconv.FormatBool(receipt.Dispatched), "reason": receipt.Reason, "requestSHA256": requestSHA}}); eventErr != nil {
			return receipt, fmt.Errorf("persist Voice eviction result after dispatch: %w", eventErr)
		}
		return receipt, nil
	}
	(*sessions)[0] = runtime.RunMedia(ctx, cfg, target, first, audio, interrupt)
	result.Sessions, result.EvictionDispatches = *sessions, dispatches
	if err = recordSessionResult(recorder, (*sessions)[0]); err != nil {
		voiceFailure(result, err)
		result.RecoveryRequired = dispatches > 0
		return *result
	}
	if dispatches != 1 {
		voiceFailure(result, errors.New("Voice recovery did not dispatch exactly one eviction"))
		return *result
	}
	result.Eviction = (*sessions)[0].Eviction
	disposition := EvictionUnknown
	if result.Eviction != nil {
		disposition = result.Eviction.Disposition
	} else {
		result.Eviction = &VoiceEviction{Disposition: EvictionUnknown, Dispatched: true}
	}
	if disposition != EvictionAccepted {
		post, postErr := runtime.Snapshot(ctx, cfg)
		_, same := post.FindPod(target.UID)
		if disposition == EvictionRefused && postErr == nil && same {
			result.Outcome = VoiceOutcomeEvictionRefused
		} else {
			result.Outcome, result.RecoveryRequired = VoiceOutcomeEvictionUnknown, true
		}
		return *result
	}
	if result.Eviction == nil || !result.Eviction.Dispatched {
		voiceFailure(result, errors.New("Voice accepted eviction receipt is incomplete"))
		result.RecoveryRequired = true
		return *result
	}
	if err = validateSession((*sessions)[0], true); err != nil {
		voiceFailure(result, err)
		result.RecoveryRequired = true
		return *result
	}
	recovered, replacement, err := waitVoiceRecovery(ctx, cfg, runtime, baseline, target.UID)
	if err != nil {
		voiceFailure(result, err)
		return *result
	}
	if !voiceSameAuthority(baseline, recovered, true) {
		voiceFailure(result, errors.New("Voice workload authority changed across replacement"))
		return *result
	}
	got, sourceErr := runtime.SourceSHA256(ctx, cfg, replacement)
	if sourceErr != nil || got != cfg.BotSourceSHA256 {
		voiceFailure(result, errors.New("replacement Voice source identity differs"))
		return *result
	}
	*cleanupPod = replacement
	result.Replacement = &replacement
	if err = recordSessionIntent(recorder, second); err != nil {
		voiceFailure(result, err)
		return *result
	}
	(*sessions)[1] = runtime.RunMedia(ctx, cfg, replacement, second, audio, nil)
	result.Sessions = *sessions
	if err = recordSessionResult(recorder, (*sessions)[1]); err != nil {
		voiceFailure(result, err)
		result.RecoveryRequired = true
		return *result
	}
	if err = validateSession((*sessions)[1], false); err != nil {
		voiceFailure(result, err)
		return *result
	}
	final, finalErr := runtime.Snapshot(ctx, cfg)
	if finalErr != nil || !voiceSameAuthority(recovered, final, false) {
		voiceFailure(result, errors.New("Voice replacement identity changed during recovery session"))
		return *result
	}
	result.Outcome = VoiceOutcomeRecoveryPass
	return *result
}

func recordSessionIntent(recorder Recorder, session VoiceSession) error {
	return recorder.Intent(Intent{Step: "voice.session", Identity: map[string]string{"phase": session.Phase, "accountSID": session.AccountSID, "callSID": session.CallSID, "streamSID": session.StreamSID}})
}

func recordSessionResult(recorder Recorder, session VoiceSession) error {
	status := "complete"
	if session.Error != "" {
		status = "incomplete"
	}
	return recorder.Event(Event{Step: "voice.session", Status: status, Identity: map[string]string{
		"phase": session.Phase, "callSID": session.CallSID, "streamSID": session.StreamSID,
		"framesSent": strconv.Itoa(session.MediaFramesSent), "framesReceived": strconv.Itoa(session.MediaFramesReceived),
		"bytesReceived": strconv.Itoa(session.MediaBytesReceived), "audioSHA256": session.ReceivedAudioSHA256,
		"closeCode": strconv.Itoa(session.CloseCode), "stopSent": strconv.FormatBool(session.StopSent),
		"forwardClosed": strconv.FormatBool(session.ForwardClosed), "error": session.Error,
	}})
}

func availabilityEvidence(samples []AvailabilitySample) (minPods, minEndpoints int, maxGap float64) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	minPods, minEndpoints = int(^uint(0)>>1), int(^uint(0)>>1)
	for i, sample := range samples {
		if !sample.Known {
			minPods, minEndpoints = 0, 0
		} else {
			if sample.ReadyPods < minPods {
				minPods = sample.ReadyPods
			}
			if sample.ReadyEndpoints < minEndpoints {
				minEndpoints = sample.ReadyEndpoints
			}
		}
		if i > 0 {
			gap := sample.At.Sub(samples[i-1].At).Seconds()
			if gap > maxGap {
				maxGap = gap
			}
		}
	}
	return minPods, minEndpoints, maxGap
}

func newVoiceSession(phase string) (VoiceSession, error) {
	makeID := func(prefix string) (string, error) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return prefix + hex.EncodeToString(b), nil
	}
	account, err := makeID("AC")
	if err != nil {
		return VoiceSession{}, err
	}
	call, err := makeID("CA")
	if err != nil {
		return VoiceSession{}, err
	}
	stream, err := makeID("MZ")
	if err != nil {
		return VoiceSession{}, err
	}
	return VoiceSession{Phase: phase, AccountSID: account, CallSID: call, StreamSID: stream}, nil
}

func validateVoiceReady(cfg VoiceConfig, state VoiceSnapshot) error {
	if state.NamespaceUID == "" || state.DeploymentUID == "" || state.ReplicaSetUID == "" || state.ServiceUID == "" || state.PDBUID == "" {
		return errors.New("Voice authority identity is incomplete")
	}
	if len(state.Pods) != int(cfg.ExpectedReplicas) || state.DeploymentGeneration != state.DeploymentObservedGeneration || state.DeploymentReplicas != cfg.ExpectedReplicas || state.DeploymentUpdatedReplicas != cfg.ExpectedReplicas || state.DeploymentReadyReplicas != cfg.ExpectedReplicas || state.DeploymentAvailableReplicas != cfg.ExpectedReplicas || state.ReplicaSetReplicas != cfg.ExpectedReplicas || state.ReplicaSetReadyReplicas != cfg.ExpectedReplicas || state.ReplicaSetAvailableReplicas != cfg.ExpectedReplicas {
		return errors.New("Voice workload is not exactly three Ready replicas")
	}
	ready := map[string]bool{}
	for _, pod := range state.Pods {
		if pod.UID == "" || pod.ResourceVersion == "" || pod.ReplicaSetUID != state.ReplicaSetUID || !pod.Ready || !pod.Started || pod.Terminating || pod.RestartCount != 0 || !strings.HasSuffix(pod.ImageID, "@"+cfg.ExpectedImageDigest) {
			return errors.New("Voice Pod identity/readiness differs")
		}
		ready[pod.UID] = true
	}
	if len(state.ReadyEndpointUIDs) != len(ready) {
		return errors.New("Voice EndpointSlice membership differs")
	}
	for _, uid := range state.ReadyEndpointUIDs {
		if !ready[uid] {
			return errors.New("Voice EndpointSlice contains a foreign or non-ready Pod")
		}
	}
	if state.PDBGeneration != state.PDBObservedGeneration || state.PDBExpectedPods != cfg.ExpectedReplicas || state.PDBCurrentHealthy != cfg.ExpectedReplicas || state.PDBDesiredHealthy != cfg.MinimumReady || state.PDBDisruptionsAllowed < 1 {
		return errors.New("Voice PDB has no eviction headroom")
	}
	return nil
}

type voiceAuthority struct {
	NamespaceUID, DeploymentUID, DeploymentSpecSHA256, ReplicaSetUID, ReplicaSetSpecSHA256, ServiceUID, ServiceSpecSHA256, PDBUID, PDBSpecSHA256 string
	DeploymentGeneration, ReplicaSetGeneration, PDBGeneration                                                                                    int64
	Pods                                                                                                                                         []VoicePod
}

func voiceAuthorityOf(s VoiceSnapshot, omitPods bool) voiceAuthority {
	a := voiceAuthority{NamespaceUID: s.NamespaceUID, DeploymentUID: s.DeploymentUID, DeploymentGeneration: s.DeploymentGeneration, DeploymentSpecSHA256: s.DeploymentSpecSHA256,
		ReplicaSetUID: s.ReplicaSetUID, ReplicaSetGeneration: s.ReplicaSetGeneration, ReplicaSetSpecSHA256: s.ReplicaSetSpecSHA256,
		ServiceUID: s.ServiceUID, ServiceSpecSHA256: s.ServiceSpecSHA256, PDBUID: s.PDBUID, PDBGeneration: s.PDBGeneration, PDBSpecSHA256: s.PDBSpecSHA256}
	if !omitPods {
		a.Pods = append([]VoicePod(nil), s.Pods...)
		for i := range a.Pods {
			a.Pods[i].ResourceVersion = ""
		}
		sort.Slice(a.Pods, func(i, j int) bool { return a.Pods[i].UID < a.Pods[j].UID })
	}
	return a
}

func voiceAuthoritySHA(s VoiceSnapshot) (string, error) {
	return voiceCanonicalSHA(voiceAuthorityOf(s, false))
}

func voiceSameAuthority(before, after VoiceSnapshot, permitPodReplacement bool) bool {
	a, b := voiceAuthorityOf(before, permitPodReplacement), voiceAuthorityOf(after, permitPodReplacement)
	ah, _ := voiceCanonicalSHA(a)
	bh, _ := voiceCanonicalSHA(b)
	return ah != "" && ah == bh
}

func waitVoiceRecovery(ctx context.Context, cfg VoiceConfig, runtime VoiceDriver, baseline VoiceSnapshot, oldUID string) (VoiceSnapshot, VoicePod, error) {
	original := map[string]bool{}
	for _, pod := range baseline.Pods {
		original[pod.UID] = true
	}
	deadline := time.NewTimer(150 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return VoiceSnapshot{}, VoicePod{}, ctx.Err()
		case <-deadline.C:
			return VoiceSnapshot{}, VoicePod{}, voiceErr("Voice replacement recovery not established: %s", last)
		case <-ticker.C:
			state, err := runtime.Snapshot(ctx, cfg)
			if err != nil {
				last = err.Error()
				continue
			}
			if err = validateVoiceReady(cfg, state); err != nil {
				last = err.Error()
				continue
			}
			if _, present := state.FindPod(oldUID); present {
				last = "old UID remains"
				continue
			}
			var replacement []VoicePod
			for _, pod := range state.Pods {
				if !original[pod.UID] {
					replacement = append(replacement, pod)
				}
			}
			if len(replacement) == 1 {
				return state, replacement[0], nil
			}
			last = "distinct replacement is not unique"
		}
	}
}

func watchVoiceAvailability(ctx context.Context, cfg VoiceConfig, runtime VoiceDriver) []AvailabilitySample {
	var samples []AvailabilitySample
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for len(samples) < 420 {
		select {
		case <-ctx.Done():
			return samples
		case <-ticker.C:
			state, err := runtime.Snapshot(ctx, cfg)
			sample := AvailabilitySample{At: time.Now().UTC(), Known: err == nil}
			if err != nil {
				sample.Error = err.Error()
			} else {
				for _, pod := range state.Pods {
					if pod.Ready && pod.Started && !pod.Terminating {
						sample.ReadyPods++
					}
				}
				sample.ReadyEndpoints = len(state.ReadyEndpointUIDs)
			}
			samples = append(samples, sample)
		}
	}
	return samples
}

func reconcileVoice(ctx context.Context, cfg VoiceConfig, runtime VoiceDriver, recorder Recorder, journal Journal) Cleanup {
	callSIDs := []string{}
	var cleanupPod VoicePod
	evictionIntent, evictionDefinite := false, false
	for _, record := range journal.Records {
		if record.Intent != nil && record.Intent.Step == "voice.session" {
			if sid := record.Intent.Identity["callSID"]; sid != "" {
				callSIDs = append(callSIDs, sid)
			}
		}
		if record.Intent != nil && record.Intent.Step == "voice.eviction" {
			evictionIntent = true
		}
		if record.Event != nil && record.Event.Step == "voice.eviction" && (record.Event.Status == string(EvictionAccepted) || record.Event.Status == string(EvictionRefused)) {
			evictionDefinite = true
		}
	}
	if len(callSIDs) == 0 {
		unsafe := evictionIntent && !evictionDefinite
		status := "nothing-owned"
		if unsafe {
			status = "nothing-owned-effect-unknown"
		}
		return Cleanup{Attempted: true, Verified: true, Status: status, UnsafeToRetry: unsafe, Details: map[string]string{"sessions": "0", "workloadEffectsReplayed": "false"}}
	}
	state, err := runtime.Snapshot(ctx, cfg)
	if err != nil || len(state.Pods) == 0 {
		return Cleanup{Attempted: true, Status: "authority-unavailable", UnsafeToRetry: true, Details: map[string]string{"error": fmt.Sprint(err)}}
	}
	for _, pod := range state.Pods {
		if pod.Ready && pod.Started && !pod.Terminating {
			cleanupPod = pod
			break
		}
	}
	if cleanupPod.UID == "" {
		return Cleanup{Attempted: true, Status: "no-ready-cleanup-pod", UnsafeToRetry: true}
	}
	clean := runtime.CleanupTranscripts(ctx, cfg, cleanupPod, callSIDs,
		func(ref TranscriptRef) error {
			return recorder.Intent(Intent{Step: "voice.transcript-delete", Mutation: true, Identity: map[string]string{"callSID": ref.CallSID, "objectID": ref.ObjectID, "contentSHA256": ref.ContentSHA256}})
		}, func(ref TranscriptRef) error {
			return recorder.Event(Event{Step: "voice.transcript-delete", Status: "accepted", Identity: map[string]string{"callSID": ref.CallSID, "objectID": ref.ObjectID, "contentSHA256": ref.ContentSHA256}})
		})
	unsafe := clean.UnsafeToRetry || evictionIntent && !evictionDefinite
	status := clean.Status
	if clean.Status == "PASS" && unsafe {
		status = "cleanup-pass-effect-unknown"
	}
	return Cleanup{Attempted: true, Verified: clean.Status == "PASS", Status: status, UnsafeToRetry: unsafe,
		Details: map[string]string{"documentsFound": strconv.Itoa(clean.DocumentsFound), "documentsRemaining": strconv.Itoa(clean.DocumentsRemaining), "workloadEffectsReplayed": "false"}}
}
