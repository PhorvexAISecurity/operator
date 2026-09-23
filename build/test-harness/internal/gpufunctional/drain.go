package gpufunctional

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

type DrainOwner struct {
	Tenant       string `json:"tenant"`
	NamespaceUID string `json:"namespace_uid"`
	PolicyUID    string `json:"policy_uid"`
	PodUID       string `json:"pod_uid"`
	ServiceUID   string `json:"service_uid"`
}

type DrainQueue struct {
	Waiting []string `json:"waiting"`
	Running []string `json:"running"`
	Swapped []string `json:"swapped"`
	Cached  []string `json:"cached"`
}

type DrainObservation struct {
	Nonce    string                `json:"nonce"`
	Sequence string                `json:"sequence"`
	Queues   map[string]DrainQueue `json:"queues"`
	Hash     string                `json:"hash"`
}

type DrainOperation struct {
	Schema                    string                    `json:"schema"`
	OperationID               string                    `json:"operation_id"`
	OperationGeneration       string                    `json:"operation_generation"`
	Attempt                   int                       `json:"attempt"`
	OwnerDigest               string                    `json:"owner_digest"`
	BackendIncarnationDigest  string                    `json:"backend_incarnation_digest"`
	Revision                  string                    `json:"revision"`
	State                     string                    `json:"state"`
	Admission                 string                    `json:"admission"`
	AdmissionGeneration       string                    `json:"admission_generation"`
	EngineBootID              string                    `json:"engine_boot_id"`
	VirtualEngineIDs          []int                     `json:"virtual_engine_ids"`
	EngineSnapshot            map[string]DrainQueue     `json:"engine_snapshot"`
	TerminalDispositions      map[string]string         `json:"terminal_dispositions"`
	ProxySnapshot             map[string]map[string]int `json:"proxy_snapshot"`
	Observations              []DrainObservation        `json:"observations"`
	Deadline                  string                    `json:"deadline"`
	CancellationGraceDeadline string                    `json:"cancellation_grace_deadline"`
	TransitionReason          string                    `json:"transition_reason"`
	CancelBoundaryRevision    string                    `json:"cancel_boundary_revision"`
	LastTransition            string                    `json:"last_transition"`
	QueryNonce                *string                   `json:"query_nonce"`
	ReceiptSHA256             string                    `json:"receipt_sha256"`
}

type LateAdmission struct {
	Observation Observation `json:"observation"`
	Refused     bool        `json:"refused"`
}

type DrainReceipt struct {
	Mode                           string                 `json:"mode"`
	Baseline                       Inference              `json:"baseline"`
	Capability                     Capability             `json:"capability"`
	CapabilityObservation          Observation            `json:"capabilityObservation"`
	FirstIdle                      *Metrics               `json:"firstIdle,omitempty"`
	SecondIdle                     *Metrics               `json:"secondIdle,omitempty"`
	ActiveMetrics                  *Metrics               `json:"activeMetrics,omitempty"`
	Cohort                         StreamCohortReceipt    `json:"cohort"`
	Anchor                         *DrainAnchor           `json:"anchor,omitempty"`
	SnapshotBindings               []DrainSnapshotBinding `json:"snapshotBindings,omitempty"`
	UnattributedSnapshotIDs        []string               `json:"unattributedSnapshotIDs,omitempty"`
	FullCohortAttributed           bool                   `json:"fullCohortAttributed"`
	AttributionScope               string                 `json:"attributionScope,omitempty"`
	Create                         *DrainOperation        `json:"create,omitempty"`
	CreateObservation              *Observation           `json:"createObservation,omitempty"`
	Late                           *LateAdmission         `json:"late,omitempty"`
	FirstObservation               *DrainOperation        `json:"firstObservation,omitempty"`
	FirstObservationSource         *Observation           `json:"firstObservationSource,omitempty"`
	SecondObservation              *DrainOperation        `json:"secondObservation,omitempty"`
	SecondObservationSource        *Observation           `json:"secondObservationSource,omitempty"`
	Reopen                         *DrainOperation        `json:"reopen,omitempty"`
	ReopenObservation              *Observation           `json:"reopenObservation,omitempty"`
	CleanupObservations            []Observation          `json:"cleanupObservations,omitempty"`
	RecoveredCapability            *Capability            `json:"recoveredCapability,omitempty"`
	RecoveredCapabilityObservation *Observation           `json:"recoveredCapabilityObservation,omitempty"`
	PostInference                  *Inference             `json:"postInference,omitempty"`
}

type DrainSnapshotBinding struct {
	SnapshotRequestID string `json:"snapshotRequestID"`
	StreamOrdinal     int    `json:"streamOrdinal"`
	ProducerRequestID string `json:"producerRequestID"`
}

type DrainAnchor struct {
	StreamOrdinal      int    `json:"streamOrdinal"`
	ProducerRequestID  string `json:"producerRequestID"`
	EngineRequestID    string `json:"engineRequestID,omitempty"`
	FirstEventAtUTC    string `json:"firstEventAtUTC"`
	SelectedAtUTC      string `json:"selectedAtUTC"`
	CreateStartedAtUTC string `json:"createStartedAtUTC"`
}

type createOperation struct {
	Schema                    string     `json:"schema"`
	OperationID               string     `json:"operation_id"`
	OperationGeneration       string     `json:"operation_generation"`
	Attempt                   int        `json:"attempt"`
	Owner                     DrainOwner `json:"owner"`
	ExpectedIncarnationDigest string     `json:"expected_incarnation_digest"`
	Deadline                  string     `json:"deadline"`
	Mode                      string     `json:"mode"`
}

func (c *Client) RunDrain(ctx context.Context, direct bool, owner DrainOwner) (receipt DrainReceipt, retErr error) {
	mode := "no-action"
	if direct {
		mode = "direct"
	}
	receipt = DrainReceipt{Mode: mode, AttributionScope: "not-applicable-no-action"}
	var err error
	receipt.Baseline, err = c.Inference(ctx, "A bounded ordinary GPU functional request.", 1)
	if err != nil {
		return receipt, err
	}
	capability, capObservation, err := c.Capability(ctx)
	receipt.Capability, receipt.CapabilityObservation = capability, capObservation
	if err != nil {
		return receipt, err
	}
	if capability.Admission != "OPEN" {
		return receipt, errors.New("drain fixture admission is not open at baseline")
	}
	if !direct {
		first, err := c.waitMetrics(ctx, 5*time.Second, idle)
		receipt.FirstIdle = &first
		if err != nil {
			return receipt, err
		}
		if err := c.sleep(ctx, time.Millisecond); err != nil {
			return receipt, err
		}
		second, err := c.waitMetrics(ctx, 5*time.Second, idle)
		receipt.SecondIdle = &second
		if err != nil {
			return receipt, err
		}
		if second.Observation.StartedAt == first.Observation.StartedAt {
			return receipt, errors.New("no-action drain samples are not distinct")
		}
		return receipt, nil
	}
	if owner.NamespaceUID == "" || owner.PodUID != capability.PodUID || owner.ServiceUID == "" || owner.Tenant == "" || owner.PolicyUID == "" {
		return receipt, errors.New("drain owner does not bind current capability and fixture identities")
	}
	preIdle, err := c.waitMetrics(ctx, 5*time.Second, idle)
	receipt.FirstIdle = &preIdle
	if err != nil {
		return receipt, err
	}
	cohort := c.startStreamCohort(ctx, streamCohortSize, drainStreamPrompt, drainStreamMaxTokens)
	cohortFinalized := false
	finalizeCohort := func() error {
		if cohortFinalized {
			return nil
		}
		cohortFinalized = true
		err := cohort.stop()
		receipt.Cohort = cohort.receipt()
		return err
	}
	defer func() { retErr = errors.Join(retErr, finalizeCohort()) }()
	if err := cohort.waitSubmitted(ctx, 10*time.Second); err != nil {
		return receipt, err
	}
	if err := cohort.waitResponseHeaders(ctx, 10*time.Second); err != nil {
		return receipt, err
	}
	generation, err := strconv.ParseUint(capability.NextOperationGeneration, 10, 64)
	if err != nil || generation == 0 {
		return receipt, errors.New("next drain generation is invalid")
	}
	operationID, err := randomHex16()
	if err != nil {
		return receipt, err
	}
	payload := createOperation{Schema: "phorvex.drain.v1", OperationID: operationID, OperationGeneration: strconv.FormatUint(generation, 10), Attempt: 1, Owner: owner, ExpectedIncarnationDigest: capability.IncarnationDigest, Deadline: c.now().UTC().Add(120 * time.Second).Format(time.RFC3339Nano), Mode: "abort-and-quiesce"}
	anchor, err := cohort.waitUnfinishedAnchor(ctx, 5*time.Second, c.now)
	if err != nil {
		return receipt, err
	}
	receipt.Anchor = &anchor
	receipt.AttributionScope = "one-late-selected-authenticated-unfinished-anchor; background snapshot IDs may be unattributed"
	if err := cohort.preActionFailure(); err != nil {
		return receipt, err
	}
	rollbackNeeded := true
	operationAttempted := false
	defer func() {
		if !rollbackNeeded || !operationAttempted {
			return
		}
		retErr = errors.Join(retErr, finalizeCohort())
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		reopened, observations, rollbackErr := c.reconcileAndReopen(rollbackCtx, payload, capability)
		receipt.CleanupObservations = append(receipt.CleanupObservations, observations...)
		if reopened.OperationID != "" {
			receipt.Reopen = &reopened
		}
		retErr = errors.Join(retErr, rollbackErr)
	}()
	if !cohort.anchorStillUnfinished(anchor) {
		return receipt, errors.New("selected drain anchor finished before create; operation not sent")
	}
	anchor.CreateStartedAtUTC = c.now().UTC().Format(time.RFC3339Nano)
	receipt.Anchor = &anchor
	operationAttempted = true
	created, createObservation, err := c.createDrain(ctx, payload)
	receipt.Create, receipt.CreateObservation = &created, &createObservation
	if err != nil {
		return receipt, err
	}
	if err := validateDrainIdentity(created, payload, capability, "DRAINING", "CLOSED"); err != nil {
		return receipt, err
	}
	late, err := c.lateAdmission(ctx)
	receipt.Late = &late
	if err != nil {
		return receipt, err
	}
	if err := cohort.waitFinished(ctx, 15*time.Second); err != nil {
		return receipt, err
	}
	receipt.Cohort = cohort.receipt()
	bindings, unknown, full, engineAnchor, err := validateDrainSnapshotAnchor(created.EngineSnapshot, receipt.Cohort, anchor)
	receipt.SnapshotBindings = bindings
	receipt.UnattributedSnapshotIDs = unknown
	receipt.FullCohortAttributed = full
	receipt.Anchor.EngineRequestID = engineAnchor
	if err != nil {
		return receipt, err
	}
	firstNonce, err := randomHex16()
	if err != nil {
		return receipt, err
	}
	secondNonce, err := randomHex16()
	if err != nil {
		return receipt, err
	}
	first, firstObservation, err := c.observeDrain(ctx, payload, firstNonce)
	receipt.FirstObservation = &first
	receipt.FirstObservationSource = &firstObservation
	if err != nil {
		return receipt, err
	}
	second, secondObservation, err := c.observeDrain(ctx, payload, secondNonce)
	receipt.SecondObservation = &second
	receipt.SecondObservationSource = &secondObservation
	if err != nil {
		return receipt, err
	}
	if err := validateTerminalDrain(created, first, second, payload, capability, firstNonce, secondNonce, engineAnchor); err != nil {
		return receipt, err
	}
	reopened, reopenObservation, err := c.intentDrain(ctx, payload, second, "reopen")
	receipt.Reopen = &reopened
	receipt.ReopenObservation = &reopenObservation
	if err != nil {
		return receipt, err
	}
	if err := validateDrainIdentity(reopened, payload, capability, "OPENED", "OPEN"); err != nil {
		return receipt, err
	}
	rollbackNeeded = false
	recovered, recoveredObservation, err := c.Capability(ctx)
	receipt.RecoveredCapability = &recovered
	receipt.RecoveredCapabilityObservation = &recoveredObservation
	if err != nil {
		return receipt, err
	}
	if recovered.EngineBootID != capability.EngineBootID || recovered.IncarnationDigest != capability.IncarnationDigest || recovered.Admission != "OPEN" {
		return receipt, errors.New("drain recovery crossed engine epoch or did not reopen admission")
	}
	post, err := c.Inference(ctx, "A bounded post-drain recovery request.", 1)
	receipt.PostInference = &post
	return receipt, err
}

func (c *Client) createDrain(ctx context.Context, payload createOperation) (DrainOperation, Observation, error) {
	obs, raw, err := c.request(ctx, http.MethodPost, "/v1/drain/operations", payload, true)
	obs.Body = string(raw)
	if err != nil {
		return DrainOperation{}, obs, err
	}
	var operation DrainOperation
	if err := requireJSON(obs, raw, http.StatusCreated, &operation); err != nil {
		return operation, obs, err
	}
	return operation, obs, nil
}

func (c *Client) observeDrain(ctx context.Context, payload createOperation, nonce string) (DrainOperation, Observation, error) {
	path := fmt.Sprintf("/v1/drain/operations/%s/%s?observation_nonce=%s", payload.OperationGeneration, payload.OperationID, nonce)
	obs, raw, err := c.request(ctx, http.MethodGet, path, nil, true)
	obs.Body = string(raw)
	if err != nil {
		return DrainOperation{}, obs, err
	}
	var operation DrainOperation
	if err := requireJSON(obs, raw, http.StatusOK, &operation); err != nil {
		return operation, obs, err
	}
	return operation, obs, nil
}

func (c *Client) intentDrain(ctx context.Context, payload createOperation, prior DrainOperation, intent string) (DrainOperation, Observation, error) {
	body := map[string]string{"owner_digest": prior.OwnerDigest, "expected_incarnation_digest": prior.BackendIncarnationDigest, "expected_revision": prior.Revision}
	path := fmt.Sprintf("/v1/drain/operations/%s/%s/%s", payload.OperationGeneration, payload.OperationID, intent)
	obs, raw, err := c.request(ctx, http.MethodPost, path, body, true)
	obs.Body = string(raw)
	if err != nil {
		return DrainOperation{}, obs, err
	}
	var operation DrainOperation
	if err := requireJSON(obs, raw, http.StatusOK, &operation); err != nil {
		return operation, obs, err
	}
	return operation, obs, nil
}

func (c *Client) lateAdmission(ctx context.Context) (LateAdmission, error) {
	body := map[string]any{"model": modelName, "prompt": "late admission control", "max_tokens": 1, "temperature": 0, "seed": 1}
	obs, raw, err := c.request(ctx, http.MethodPost, "/v1/completions", body, true)
	obs.Body = string(raw)
	result := LateAdmission{Observation: obs}
	if err != nil {
		return result, err
	}
	var envelope struct {
		Error string `json:"error"`
	}
	if err := requireJSON(obs, raw, http.StatusServiceUnavailable, &envelope); err != nil {
		return result, err
	}
	result.Observation = obs
	if envelope.Error != "admission_closed" {
		return result, errors.New("closed drain admission did not return exact refusal")
	}
	result.Refused = true
	return result, nil
}

func validateDrainIdentity(operation DrainOperation, payload createOperation, capability Capability, state, admission string) error {
	if err := validateDrainBinding(operation, payload, capability); err != nil {
		return err
	}
	if operation.State != state || operation.Admission != admission {
		return errors.New("drain receipt identity, epoch, state or admission differs")
	}
	return nil
}

func validateDrainBinding(operation DrainOperation, payload createOperation, capability Capability) error {
	if operation.Schema != payload.Schema || operation.OperationID != payload.OperationID || !hexPattern(32).MatchString(operation.OperationID) || operation.OperationGeneration != payload.OperationGeneration || !canonicalPositiveDecimal(operation.OperationGeneration) || operation.Attempt != payload.Attempt || operation.Attempt != 1 || operation.OwnerDigest != drainOwnerDigest(payload.Owner) || operation.BackendIncarnationDigest != capability.IncarnationDigest || operation.EngineBootID != capability.EngineBootID || len(operation.VirtualEngineIDs) != 1 || operation.VirtualEngineIDs[0] != 0 || !hexPattern(64).MatchString(operation.ReceiptSHA256) {
		return errors.New("drain receipt identity, owner or engine epoch differs")
	}
	if !canonicalPositiveDecimal(operation.Revision) || !canonicalDecimal(operation.AdmissionGeneration) {
		return errors.New("drain receipt revision or admission generation is invalid")
	}
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, operation.Deadline)
	grace, graceErr := time.Parse(time.RFC3339Nano, operation.CancellationGraceDeadline)
	_, transitionErr := time.Parse(time.RFC3339Nano, operation.LastTransition)
	if deadlineErr != nil || graceErr != nil || transitionErr != nil || !strings.HasSuffix(operation.Deadline, "Z") || !strings.HasSuffix(operation.LastTransition, "Z") || operation.TransitionReason != "none" || operation.CancelBoundaryRevision != "0" {
		return errors.New("drain receipt timing or cancellation boundary is invalid")
	}
	expectedGrace := deadline.UTC().Truncate(time.Microsecond).Add(30 * time.Second)
	expectedGraceText := expectedGrace.Format("2006-01-02T15:04:05.000000Z")
	if !grace.Equal(expectedGrace) || operation.CancellationGraceDeadline != expectedGraceText {
		return errors.New("drain receipt timing or cancellation boundary is invalid")
	}
	if err := validateDrainSnapshots(operation); err != nil {
		return err
	}
	if err := validateDrainReceiptDigest(operation); err != nil {
		return err
	}
	return nil
}

func canonicalDecimal(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func canonicalPositiveDecimal(value string) bool {
	if !canonicalDecimal(value) {
		return false
	}
	parsed, _ := strconv.ParseUint(value, 10, 64)
	return parsed > 0
}

func validateDrainSnapshots(operation DrainOperation) error {
	if len(operation.EngineSnapshot) != 1 || len(operation.ProxySnapshot) != 2 || len(operation.Observations) > 2 {
		return errors.New("drain receipt engine/proxy snapshot shape differs")
	}
	engine, ok := operation.EngineSnapshot["0"]
	if !ok || engine.Waiting == nil || engine.Running == nil || engine.Swapped == nil || engine.Cached == nil {
		return errors.New("drain receipt engine zero queues are omitted")
	}
	seenIDs := map[string]bool{}
	for _, ids := range [][]string{engine.Waiting, engine.Running, engine.Swapped, engine.Cached} {
		for _, id := range ids {
			if id == "" || len(id) > 512 || seenIDs[id] {
				return errors.New("drain receipt engine snapshot request identity is invalid")
			}
			seenIDs[id] = true
		}
	}
	before, beforeOK := operation.ProxySnapshot["before_engine_begin"]
	after, afterOK := operation.ProxySnapshot["after_engine_begin"]
	if !beforeOK || !afterOK || len(before) != 1 || before["active"] < 0 || len(after) != 2 || after["cancelled"] < 0 || after["remaining"] != 0 {
		return errors.New("drain receipt proxy snapshot is invalid")
	}
	for _, observation := range operation.Observations {
		if !hexPattern(32).MatchString(observation.Nonce) || !canonicalPositiveDecimal(observation.Sequence) || !hexPattern(64).MatchString(observation.Hash) {
			return errors.New("drain receipt observation identity is invalid")
		}
	}
	return nil
}

func drainOwnerDigest(owner DrainOwner) string {
	canonical, _ := json.Marshal(map[string]string{"namespace_uid": owner.NamespaceUID, "pod_uid": owner.PodUID, "policy_uid": owner.PolicyUID, "service_uid": owner.ServiceUID, "tenant": owner.Tenant})
	digest := sha256.Sum256(append([]byte("phorvex-drain-owner-v1\x00"), canonical...))
	return fmt.Sprintf("%x", digest)
}

func (c *Client) reconcileAndReopen(ctx context.Context, payload createOperation, capability Capability) (DrainOperation, []Observation, error) {
	var latest DrainOperation
	var observations []Observation
	for attempt := 0; attempt < 8; attempt++ {
		nonce, err := randomHex16()
		if err != nil {
			return latest, observations, err
		}
		current, observation, err := c.observeDrain(ctx, payload, nonce)
		observations = append(observations, observation)
		if err != nil {
			return latest, observations, fmt.Errorf("reconcile attempted drain operation: %w", err)
		}
		latest = current
		if err := validateDrainBinding(current, payload, capability); err != nil {
			return latest, observations, fmt.Errorf("refuse drain cleanup for nonmatching operation: %w", err)
		}
		if current.State == "OPENED" && current.Admission == "OPEN" {
			return current, observations, nil
		}
		if current.Admission != "CLOSED" {
			return latest, observations, errors.New("drain cleanup observed an unsupported admission state")
		}
		if current.State == "QUIESCENT" || current.State == "CANCELLED" {
			reopened, observation, err := c.intentDrain(ctx, payload, current, "reopen")
			observations = append(observations, observation)
			if err != nil {
				return reopened, observations, err
			}
			return reopened, observations, validateDrainIdentity(reopened, payload, capability, "OPENED", "OPEN")
		}
		if current.State != "DRAINING" && current.State != "CANCEL_REQUESTED" {
			return latest, observations, fmt.Errorf("drain cleanup cannot reopen state %s", current.State)
		}
		if err := c.sleep(ctx, 250*time.Millisecond); err != nil {
			return latest, observations, err
		}
	}
	return latest, observations, errors.New("drain cleanup could not observe a reopenable terminal state")
}

func validateTerminalDrain(created, first, second DrainOperation, payload createOperation, capability Capability, firstNonce, secondNonce, anchorEngineID string) error {
	if err := validateDrainIdentity(first, payload, capability, "DRAINING", "CLOSED"); err != nil {
		return fmt.Errorf("first terminal observation: %w", err)
	}
	if err := validateDrainIdentity(second, payload, capability, "QUIESCENT", "CLOSED"); err != nil {
		return fmt.Errorf("second terminal observation: %w", err)
	}
	if err := validateTerminalSequence(created, first, second, firstNonce, secondNonce); err != nil {
		return err
	}
	if anchorEngineID == "" || first.TerminalDispositions[anchorEngineID] != "aborted" || second.TerminalDispositions[anchorEngineID] != "aborted" {
		return errors.New("exact selected drain anchor lacks aborted disposition in both terminal observations")
	}
	requestIDs := map[string]bool{}
	for _, queues := range created.EngineSnapshot {
		for _, ids := range [][]string{queues.Waiting, queues.Running, queues.Swapped, queues.Cached} {
			for _, id := range ids {
				requestIDs[id] = true
			}
		}
	}
	if len(requestIDs) == 0 || len(second.TerminalDispositions) != len(requestIDs) {
		return errors.New("drain terminal dispositions do not cover admitted request snapshot")
	}
	for id := range requestIDs {
		disposition, ok := second.TerminalDispositions[id]
		if !ok || disposition != "aborted" && disposition != "completed-before-abort" {
			return errors.New("drain terminal disposition is absent or unsupported")
		}
	}
	return nil
}

func validateTerminalSequence(created, first, second DrainOperation, firstNonce, secondNonce string) error {
	if first.State != "DRAINING" || first.Admission != "CLOSED" || second.State != "QUIESCENT" || second.Admission != "CLOSED" {
		return errors.New("drain observations do not follow DRAINING then QUIESCENT")
	}
	if first.QueryNonce == nil || *first.QueryNonce != firstNonce || second.QueryNonce == nil || *second.QueryNonce != secondNonce || len(first.Observations) != 1 || len(second.Observations) != 2 || firstNonce == secondNonce || first.Observations[0].Nonce != firstNonce || second.Observations[0].Nonce != firstNonce || second.Observations[1].Nonce != secondNonce {
		return errors.New("drain terminal receipt lacks two exact distinct observations")
	}
	createdRevision, createdErr := strconv.ParseUint(created.Revision, 10, 64)
	firstRevision, firstErr := strconv.ParseUint(first.Revision, 10, 64)
	secondRevision, secondErr := strconv.ParseUint(second.Revision, 10, 64)
	if createdErr != nil || firstErr != nil || secondErr != nil || !(createdRevision < firstRevision && firstRevision < secondRevision) {
		return errors.New("drain observation revisions are not strictly increasing")
	}
	var priorSequence uint64
	for index, observation := range second.Observations {
		sequence, err := strconv.ParseUint(observation.Sequence, 10, 64)
		if err != nil || sequence == 0 || index > 0 && sequence <= priorSequence || !hexPattern(64).MatchString(observation.Hash) {
			return errors.New("drain observation sequence or producer hash is invalid")
		}
		priorSequence = sequence
		if len(observation.Queues) != 1 {
			return errors.New("drain terminal observation has an unexpected engine set")
		}
		queues, ok := observation.Queues["0"]
		if !ok {
			return errors.New("drain terminal observation lacks engine zero")
		}
		if queues.Waiting == nil || queues.Running == nil || queues.Swapped == nil || queues.Cached == nil || len(queues.Waiting)+len(queues.Running)+len(queues.Swapped)+len(queues.Cached) != 0 {
			return errors.New("drain terminal observation retained nonzero or omitted engine queues")
		}
	}
	return nil
}

func validateDrainSnapshotAnchor(snapshot map[string]DrainQueue, cohort StreamCohortReceipt, anchor DrainAnchor) ([]DrainSnapshotBinding, []string, bool, string, error) {
	if cohort.Schema != "phorvex.gpu.stream-cohort.v3" || cohort.Expected != streamCohortSize || len(cohort.Streams) != cohort.Expected || len(snapshot) != 1 {
		return nil, nil, false, "", errors.New("drain cohort or engine snapshot shape differs")
	}
	producer := map[string]StreamLifecycleReceipt{}
	for _, stream := range cohort.Streams {
		if !stream.Finished || stream.FinishedAt == "" || stream.Termination == "running" || stream.Termination == "not-started" || stream.Termination == "join-timeout" {
			return nil, nil, false, "", fmt.Errorf("drain stream %d lacks a retained terminal lifecycle", stream.Ordinal)
		}
		if stream.RequestID == "" || stream.AcceptedAt == "" || stream.EventCount == 0 {
			continue
		}
		if _, exists := producer[stream.RequestID]; exists {
			return nil, nil, false, "", errors.New("drain cohort producer request identity is duplicated")
		}
		producer[stream.RequestID] = stream
	}
	var snapshotIDs []string
	for _, queues := range snapshot {
		for _, ids := range [][]string{queues.Waiting, queues.Running, queues.Swapped, queues.Cached} {
			snapshotIDs = append(snapshotIDs, ids...)
		}
	}
	if len(snapshotIDs) == 0 {
		return nil, nil, false, "", errors.New("drain snapshot contains no admitted cohort request")
	}
	slices.Sort(snapshotIDs)
	anchorStream, anchorExists := producer[anchor.ProducerRequestID]
	if !anchorExists || anchorStream.Ordinal != anchor.StreamOrdinal || anchorStream.AcceptedAt != anchor.FirstEventAtUTC {
		return nil, snapshotIDs, false, "", errors.New("selected drain anchor lacks its exact authenticated producer response")
	}
	bindings := make([]DrainSnapshotBinding, 0, 1)
	unknown := make([]string, 0, len(snapshotIDs))
	anchorEngineID := ""
	for _, snapshotID := range snapshotIDs {
		producerID := snapshotID
		if producerID != anchor.ProducerRequestID && strings.HasSuffix(snapshotID, "-0") {
			producerID = strings.TrimSuffix(snapshotID, "-0")
		}
		if producerID != anchor.ProducerRequestID {
			unknown = append(unknown, snapshotID)
			continue
		}
		if anchorEngineID != "" {
			return bindings, unknown, false, anchorEngineID, fmt.Errorf("drain snapshot request %q duplicates an authenticated cohort identity", snapshotID)
		}
		bindings = append(bindings, DrainSnapshotBinding{SnapshotRequestID: snapshotID, StreamOrdinal: anchorStream.Ordinal, ProducerRequestID: producerID})
		anchorEngineID = snapshotID
	}
	if anchor.ProducerRequestID == "" || anchor.FirstEventAtUTC == "" || anchor.SelectedAtUTC == "" || anchor.CreateStartedAtUTC == "" || anchorEngineID == "" {
		return bindings, unknown, false, anchorEngineID, errors.New("exact late-selected drain anchor is absent from engine snapshot")
	}
	firstAt, firstErr := time.Parse(time.RFC3339Nano, anchor.FirstEventAtUTC)
	selectedAt, selectedErr := time.Parse(time.RFC3339Nano, anchor.SelectedAtUTC)
	createAt, createErr := time.Parse(time.RFC3339Nano, anchor.CreateStartedAtUTC)
	if firstErr != nil || selectedErr != nil || createErr != nil || selectedAt.Before(firstAt) || createAt.Before(selectedAt) {
		return bindings, unknown, false, anchorEngineID, errors.New("drain anchor first-event/selection/create timeline is invalid")
	}
	// This contract deliberately attributes only the late-selected anchor. It
	// never upgrades the surrounding pressure cohort into a full cohort claim.
	return bindings, unknown, false, anchorEngineID, nil
}

func validateDrainReceiptDigest(operation DrainOperation) error {
	body := map[string]any{
		"schema": operation.Schema, "operation_id": operation.OperationID,
		"operation_generation": operation.OperationGeneration, "attempt": operation.Attempt,
		"owner_digest": operation.OwnerDigest, "backend_incarnation_digest": operation.BackendIncarnationDigest,
		"revision": operation.Revision, "state": operation.State, "admission": operation.Admission,
		"admission_generation": operation.AdmissionGeneration, "engine_boot_id": operation.EngineBootID,
		"virtual_engine_ids": operation.VirtualEngineIDs, "engine_snapshot": operation.EngineSnapshot,
		"terminal_dispositions": operation.TerminalDispositions, "proxy_snapshot": operation.ProxySnapshot,
		"observations": operation.Observations, "deadline": operation.Deadline,
		"cancellation_grace_deadline": operation.CancellationGraceDeadline,
		"transition_reason":           operation.TransitionReason, "cancel_boundary_revision": operation.CancelBoundaryRevision,
		"last_transition": operation.LastTransition, "query_nonce": operation.QueryNonce,
	}
	want, err := drainDigest("phorvex-drain-status-v1", body)
	if err != nil {
		return fmt.Errorf("calculate drain status receipt digest: %w", err)
	}
	if operation.ReceiptSHA256 != want {
		return fmt.Errorf("drain status receipt digest mismatch: got %s want %s", operation.ReceiptSHA256, want)
	}
	return nil
}

func drainDigest(domain string, value any) (string, error) {
	raw, err := canonicalDrainJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(append([]byte(domain), 0), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func canonicalDrainJSON(value any) ([]byte, error) {
	input, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	raw := bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'})
	for _, replacement := range []struct{ escaped, utf8 []byte }{
		{[]byte(`\u2028`), []byte("\u2028")}, {[]byte(`\u2029`), []byte("\u2029")},
	} {
		for start := 0; ; {
			index := bytes.Index(raw[start:], replacement.escaped)
			if index < 0 {
				break
			}
			index += start
			slashes := 0
			for cursor := index; cursor >= 0 && raw[cursor] == '\\'; cursor-- {
				slashes++
			}
			if slashes%2 == 1 {
				raw = append(append(append([]byte{}, raw[:index]...), replacement.utf8...), raw[index+len(replacement.escaped):]...)
				start = index + len(replacement.utf8)
			} else {
				start = index + len(replacement.escaped)
			}
		}
	}
	return raw, nil
}
