package actuator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	drainV11Schema        = "phorvex.drain.v1"
	drainV11Capability    = "operation-bound-quiescence-v1"
	drainV11MaxBody       = 32 << 10
	annoDrainProxySource  = "phorvex.ai/drain-proxy-source"
	annoDrainEngineSource = "phorvex.ai/drain-engine-source"
	drainV11CancelGrace   = 30 * time.Second
)

type drainV11CapabilityResponse struct {
	Schema                  string `json:"schema"`
	Capability              string `json:"capability"`
	PodUID                  string `json:"pod_uid"`
	LedgerID                string `json:"ledger_id"`
	ProxyBootID             string `json:"proxy_boot_id"`
	EngineBootID            string `json:"engine_boot_id"`
	IncarnationDigest       string `json:"incarnation_digest"`
	ProxySource             string `json:"proxy_source"`
	EngineSource            string `json:"engine_source"`
	EngineMode              string `json:"engine_mode"`
	VirtualEngineIDs        []int  `json:"virtual_engine_ids"`
	GenerationHighWater     string `json:"generation_high_water"`
	NextOperationGeneration string `json:"next_operation_generation,omitempty"`
	Admission               string `json:"admission"`
	RawSHA256               string `json:"-"`
}

type drainV11Owner struct {
	Tenant       string `json:"tenant"`
	NamespaceUID string `json:"namespace_uid"`
	PolicyUID    string `json:"policy_uid"`
	PodUID       string `json:"pod_uid"`
	ServiceUID   string `json:"service_uid"`
}

type drainV11CreateRequest struct {
	Schema                    string              `json:"schema"`
	OperationID               string              `json:"operation_id"`
	OperationGeneration       string              `json:"operation_generation"`
	Attempt                   int                 `json:"attempt"`
	Owner                     drainV11Owner       `json:"owner"`
	ExpectedIncarnationDigest string              `json:"expected_incarnation_digest"`
	Deadline                  string              `json:"deadline"`
	Mode                      string              `json:"mode"`
	Supersedes                *drainV11Supersedes `json:"supersedes,omitempty"`
}

type drainV11Supersedes struct {
	OperationGeneration string `json:"operation_generation"`
	OperationID         string `json:"operation_id"`
	Revision            string `json:"revision"`
}

type drainV11Queues struct {
	Waiting []string `json:"waiting"`
	Running []string `json:"running"`
	Swapped []string `json:"swapped"`
	Cached  []string `json:"cached"`
}

type drainV11Observation struct {
	Nonce    string                    `json:"nonce"`
	Sequence string                    `json:"sequence"`
	Queues   map[string]drainV11Queues `json:"queues"`
	Hash     string                    `json:"hash"`
}

type drainV11StatusResponse struct {
	Schema                    string                     `json:"schema"`
	OperationID               string                     `json:"operation_id"`
	OperationGeneration       string                     `json:"operation_generation"`
	Attempt                   int                        `json:"attempt"`
	OwnerDigest               string                     `json:"owner_digest"`
	BackendIncarnationDigest  string                     `json:"backend_incarnation_digest"`
	Revision                  string                     `json:"revision"`
	State                     string                     `json:"state"`
	Admission                 string                     `json:"admission"`
	AdmissionGeneration       string                     `json:"admission_generation"`
	EngineBootID              string                     `json:"engine_boot_id"`
	VirtualEngineIDs          []int                      `json:"virtual_engine_ids"`
	EngineSnapshot            map[string]drainV11Queues  `json:"engine_snapshot"`
	TerminalDispositions      map[string]string          `json:"terminal_dispositions"`
	ProxySnapshot             map[string]json.RawMessage `json:"proxy_snapshot"`
	Observations              []drainV11Observation      `json:"observations"`
	Deadline                  string                     `json:"deadline"`
	CancellationGraceDeadline string                     `json:"cancellation_grace_deadline"`
	TransitionReason          string                     `json:"transition_reason"`
	CancelBoundaryRevision    string                     `json:"cancel_boundary_revision"`
	LastTransition            string                     `json:"last_transition"`
	QueryNonce                *string                    `json:"query_nonce"`
	ReceiptSHA256             string                     `json:"receipt_sha256"`
}

type drainV11IntentRequest struct {
	OwnerDigest               string `json:"owner_digest"`
	ExpectedIncarnationDigest string `json:"expected_incarnation_digest"`
	ExpectedRevision          string `json:"expected_revision"`
}

type vLLMDrainV11Client interface {
	DrainV11Capability(context.Context, servingEndpoint) (drainV11CapabilityResponse, error)
	DrainV11Create(context.Context, servingEndpoint, drainV11CreateRequest) (drainV11StatusResponse, error)
	DrainV11Status(context.Context, servingEndpoint, string, string, string) (drainV11StatusResponse, error)
	DrainV11Cancel(context.Context, servingEndpoint, string, string, drainV11IntentRequest) (drainV11StatusResponse, error)
	DrainV11Reopen(context.Context, servingEndpoint, string, string, drainV11IntentRequest) (drainV11StatusResponse, error)
}

func strictDrainV11Decode(body string, target any) error {
	if len(body) == 0 || len(body) > drainV11MaxBody {
		return fmt.Errorf("drain v11 response size must be 1..%d bytes", drainV11MaxBody)
	}
	raw := []byte(body)
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("drain v11 response has trailing data")
	}
	return nil
}

type drainV11Receipt struct {
	OperationID               string                          `json:"operationID"`
	OperationGeneration       string                          `json:"operationGeneration"`
	Attempt                   int                             `json:"attempt"`
	Supersedes                *drainV11Supersedes             `json:"supersedes,omitempty"`
	OwnerDigest               string                          `json:"ownerDigest,omitempty"`
	ExpectedIncarnation       string                          `json:"expectedIncarnation"`
	BackendIncarnation        string                          `json:"backendIncarnation,omitempty"`
	LedgerID                  string                          `json:"ledgerID"`
	ProxyBootID               string                          `json:"proxyBootID"`
	EngineBootID              string                          `json:"engineBootID"`
	Revision                  string                          `json:"revision,omitempty"`
	State                     string                          `json:"state,omitempty"`
	ReceiptSHA256             string                          `json:"receiptSHA256,omitempty"`
	Deadline                  string                          `json:"deadline"`
	CancelNotBefore           string                          `json:"cancelNotBefore"`
	CancellationGraceDeadline string                          `json:"cancellationGraceDeadline"`
	TransitionReason          string                          `json:"transitionReason,omitempty"`
	CancelBoundaryRevision    string                          `json:"cancelBoundaryRevision,omitempty"`
	Owner                     drainV11Owner                   `json:"owner"`
	Aborted                   int                             `json:"aborted,omitempty"`
	CompletedBeforeAbort      int                             `json:"completedBeforeAbort,omitempty"`
	TerminalDigests           []model.DrainRequestDisposition `json:"terminalDigests,omitempty"`
	SnapshotDigests           []string                        `json:"snapshotDigests,omitempty"`
	TargetNamespace           string                          `json:"targetNamespace"`
	TargetName                string                          `json:"targetName"`
	CapabilitySHA256          string                          `json:"capabilitySHA256"`
	ProxySource               string                          `json:"proxySource"`
	EngineSource              string                          `json:"engineSource"`
	OperatorBinding           string                          `json:"operatorBinding"`
	AdmissionGeneration       string                          `json:"admissionGeneration,omitempty"`
	LastTransition            string                          `json:"lastTransition,omitempty"`
	SnapshotWaiting           int                             `json:"snapshotWaiting,omitempty"`
	SnapshotRunning           int                             `json:"snapshotRunning,omitempty"`
	SnapshotSwapped           int                             `json:"snapshotSwapped,omitempty"`
	SnapshotCached            int                             `json:"snapshotCached,omitempty"`
	SnapshotOverlap           int                             `json:"snapshotOverlap,omitempty"`
	ProxyActive               int                             `json:"proxyActive,omitempty"`
	ProxyCancelled            int                             `json:"proxyCancelled,omitempty"`
	ObservationNonces         []string                        `json:"observationNonces,omitempty"`
	ObservationSequences      []string                        `json:"observationSequences,omitempty"`
	ObservationHashes         []string                        `json:"observationHashes,omitempty"`
	CreateRequests            int                             `json:"createRequests,omitempty"`
	StatusRequests            int                             `json:"statusRequests,omitempty"`
	CancelRequests            int                             `json:"cancelRequests,omitempty"`
	ReopenRequests            int                             `json:"reopenRequests,omitempty"`
}

func (r *drainV11Receipt) prepared() bool {
	if r == nil {
		return false
	}
	if len(r.TerminalDigests) > 16 {
		return false
	}
	if len(r.SnapshotDigests) > 16 || len(r.SnapshotDigests) != len(r.TerminalDigests) {
		return false
	}
	for i, row := range r.SnapshotDigests {
		if !validDrainV11Hex(row, sha256.Size) || (i > 0 && r.SnapshotDigests[i-1] >= row) || row != r.TerminalDigests[i].RequestSHA256 {
			return false
		}
	}
	for i, row := range r.TerminalDigests {
		if !validDrainV11Hex(row.RequestSHA256, sha256.Size) ||
			(row.Disposition != "aborted" && row.Disposition != "completed-before-abort") ||
			(i > 0 && r.TerminalDigests[i-1].RequestSHA256 >= row.RequestSHA256) {
			return false
		}
	}
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, r.Deadline)
	cancelAt, cancelErr := time.Parse(time.RFC3339Nano, r.CancelNotBefore)
	grace, graceErr := time.Parse(time.RFC3339Nano, r.CancellationGraceDeadline)
	validAttempt := (r.Attempt == 1 && r.Supersedes == nil) ||
		(r.Attempt == 2 && validDrainV11Supersedes(r.Supersedes))
	validCounters := r.CreateRequests >= 0 && r.CreateRequests <= 1 &&
		r.StatusRequests >= 0 && r.StatusRequests <= 16384 &&
		r.CancelRequests >= 0 && r.CancelRequests <= 1 &&
		r.ReopenRequests >= 0 && r.ReopenRequests <= 1
	return validAttempt && validCounters && validDrainV11Hex(r.OperationID, 16) &&
		validDrainV11Decimal(r.OperationGeneration, true) &&
		validDrainV11Hex(r.ExpectedIncarnation, sha256.Size) &&
		validDrainV11Hex(r.LedgerID, 16) && validDrainV11Hex(r.ProxyBootID, 16) &&
		validDrainV11Hex(r.EngineBootID, 16) && strings.HasSuffix(r.Deadline, "Z") && deadlineErr == nil &&
		strings.HasSuffix(r.CancelNotBefore, "Z") && cancelErr == nil && cancelAt.Before(deadline) &&
		strings.HasSuffix(r.CancellationGraceDeadline, "Z") && graceErr == nil && grace.Equal(deadline.Add(drainV11CancelGrace)) &&
		validDrainV11Owner(r.Owner) && r.TargetNamespace != "" && r.TargetName != "" &&
		validDrainV11Hex(r.CapabilitySHA256, sha256.Size) && validDrainV11Hex(r.OperatorBinding, sha256.Size) &&
		validDrainV11Source(r.ProxySource) && validDrainV11Source(r.EngineSource)
}

func validDrainV11Supersedes(value *drainV11Supersedes) bool {
	return value != nil && validDrainV11Decimal(value.OperationGeneration, true) &&
		validDrainV11Hex(value.OperationID, 16) && validDrainV11Decimal(value.Revision, true)
}

func validDrainV11Owner(owner drainV11Owner) bool {
	for _, value := range []string{owner.Tenant, owner.NamespaceUID, owner.PolicyUID, owner.PodUID, owner.ServiceUID} {
		if value == "" || !utf8.ValidString(value) || len([]byte(value)) > 256 {
			return false
		}
	}
	return true
}

func validDrainV11Source(value string) bool {
	return value != "" && utf8.ValidString(value) && len([]byte(value)) <= 256 &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func (r *drainV11Receipt) confirmed() bool {
	if !r.prepared() || r.State != "QUIESCENT" ||
		!validDrainV11Hex(r.OwnerDigest, sha256.Size) ||
		!validDrainV11Hex(r.BackendIncarnation, sha256.Size) ||
		!validDrainV11Decimal(r.Revision, true) || !validDrainV11Hex(r.ReceiptSHA256, sha256.Size) ||
		!validDrainV11Decimal(r.AdmissionGeneration, false) || r.LastTransition == "" ||
		r.SnapshotWaiting < 0 || r.SnapshotRunning < 0 || r.SnapshotSwapped < 0 || r.SnapshotCached < 0 ||
		r.SnapshotOverlap < 0 || r.SnapshotOverlap > r.SnapshotCached ||
		r.SnapshotOverlap > r.SnapshotWaiting+r.SnapshotRunning+r.SnapshotSwapped ||
		r.ProxyActive < 0 || r.ProxyCancelled < 0 || r.Aborted < 0 || r.CompletedBeforeAbort < 0 ||
		r.SnapshotWaiting+r.SnapshotRunning+r.SnapshotSwapped+r.SnapshotCached-r.SnapshotOverlap != r.Aborted+r.CompletedBeforeAbort ||
		len(r.ObservationNonces) != 2 || len(r.ObservationSequences) != 2 || len(r.ObservationHashes) != 2 {
		return false
	}
	first, firstErr := strconv.ParseUint(r.ObservationSequences[0], 10, 64)
	second, secondErr := strconv.ParseUint(r.ObservationSequences[1], 10, 64)
	return firstErr == nil && secondErr == nil && first > 0 && second > first &&
		r.ObservationNonces[0] != r.ObservationNonces[1] &&
		validDrainV11Hex(r.ObservationNonces[0], 16) && validDrainV11Hex(r.ObservationNonces[1], 16) &&
		validDrainV11Hex(r.ObservationHashes[0], sha256.Size) && validDrainV11Hex(r.ObservationHashes[1], sha256.Size) &&
		validDrainV11Hex(r.OwnerDigest, sha256.Size) &&
		validDrainV11Hex(r.BackendIncarnation, sha256.Size)
}

func (r *drainV11Receipt) cancelled() bool {
	if r == nil || r.State != "CANCELLED" || r.TransitionReason == "none" ||
		!validDrainV11Decimal(r.CancelBoundaryRevision, true) {
		return false
	}
	state := r.State
	r.State = "QUIESCENT"
	confirmed := r.confirmed()
	r.State = state
	return confirmed
}

// reopened proves that the backend durably reopened admission after retaining
// the complete quiescence proof. The transition reason distinguishes normal
// completion from cancellation without adding a second, weaker proof shape.
func (r *drainV11Receipt) reopened() bool {
	if r == nil || r.State != "OPENED" || r.ReopenRequests != 1 {
		return false
	}
	proof := *r
	if r.TransitionReason == "none" {
		proof.State = "QUIESCENT"
		return proof.confirmed()
	}
	proof.State = "CANCELLED"
	return proof.cancelled()
}

func (r *drainV11Receipt) reopenedAfterCancellation() bool {
	return r != nil && r.TransitionReason != "none" && r.reopened()
}

func bindDrainV11Status(receipt *drainV11Receipt, status drainV11StatusResponse, expectedNonce *string) error {
	if receipt == nil || status.OperationID != receipt.OperationID ||
		status.OperationGeneration != receipt.OperationGeneration ||
		status.Attempt != receipt.Attempt || status.Deadline != receipt.Deadline ||
		status.EngineBootID != receipt.EngineBootID ||
		status.BackendIncarnationDigest != receipt.ExpectedIncarnation ||
		status.CancellationGraceDeadline != receipt.CancellationGraceDeadline {
		return fmt.Errorf("drain v11 status changed the prepared operation binding")
	}
	if err := validateDrainV11Status(status, receipt.OperationID,
		receipt.OperationGeneration, expectedNonce); err != nil {
		return err
	}
	if receipt.Revision != "" {
		prior, _ := strconv.ParseUint(receipt.Revision, 10, 64)
		next, _ := strconv.ParseUint(status.Revision, 10, 64)
		if next < prior {
			return fmt.Errorf("drain v11 status revision regressed")
		}
	}
	if receipt.AdmissionGeneration != "" {
		prior, _ := strconv.ParseUint(receipt.AdmissionGeneration, 10, 64)
		next, _ := strconv.ParseUint(status.AdmissionGeneration, 10, 64)
		if next < prior {
			return fmt.Errorf("drain v11 admission generation regressed")
		}
	}
	if receipt.TransitionReason != "" && receipt.TransitionReason != "none" &&
		(status.TransitionReason != receipt.TransitionReason ||
			status.CancelBoundaryRevision != receipt.CancelBoundaryRevision) {
		return fmt.Errorf("drain v11 cancellation boundary changed")
	}
	wantOwner, err := drainV11OwnerDigest(receipt.Owner)
	if err != nil || status.OwnerDigest != wantOwner {
		return fmt.Errorf("drain v11 owner digest mismatch")
	}
	aborted, completed := 0, 0
	// The response has already been validated against the exact engine snapshot.
	// Retain only a small, sorted digest projection: raw caller-controlled IDs
	// must never be written to a journal or manager audit. Larger snapshots keep
	// the aggregate mechanism result but cannot credit an owned request.
	var terminalDigests []model.DrainRequestDisposition
	var snapshotDigests []string
	if len(status.TerminalDispositions) <= 16 {
		snapshotIDs, _ := drainV11QueueIDs(status.EngineSnapshot, false)
		for id := range snapshotIDs {
			hash := sha256.Sum256([]byte(id))
			snapshotDigests = append(snapshotDigests, hex.EncodeToString(hash[:]))
		}
		sort.Strings(snapshotDigests)
		terminalDigests = make([]model.DrainRequestDisposition, 0, len(status.TerminalDispositions))
		for id, disposition := range status.TerminalDispositions {
			hash := sha256.Sum256([]byte(id))
			terminalDigests = append(terminalDigests, model.DrainRequestDisposition{
				RequestSHA256: hex.EncodeToString(hash[:]), Disposition: disposition})
		}
		sort.Slice(terminalDigests, func(i, j int) bool {
			return terminalDigests[i].RequestSHA256 < terminalDigests[j].RequestSHA256
		})
	}
	for _, disposition := range status.TerminalDispositions {
		switch disposition {
		case "aborted":
			aborted++
		case "completed-before-abort":
			completed++
		default:
			return fmt.Errorf("drain v11 status has an invalid terminal disposition")
		}
	}
	// Mutate the durable receipt only after every response field and proof has
	// been bound. A malformed or cross-operation response preserves recovery.
	receipt.OwnerDigest = status.OwnerDigest
	receipt.BackendIncarnation = status.BackendIncarnationDigest
	receipt.Revision = status.Revision
	receipt.State = status.State
	receipt.ReceiptSHA256 = status.ReceiptSHA256
	receipt.Aborted, receipt.CompletedBeforeAbort = aborted, completed
	receipt.TerminalDigests = terminalDigests
	receipt.SnapshotDigests = snapshotDigests
	receipt.AdmissionGeneration, receipt.LastTransition = status.AdmissionGeneration, status.LastTransition
	receipt.TransitionReason = status.TransitionReason
	receipt.CancelBoundaryRevision = status.CancelBoundaryRevision
	queue := status.EngineSnapshot["0"]
	receipt.SnapshotWaiting, receipt.SnapshotRunning = len(queue.Waiting), len(queue.Running)
	receipt.SnapshotSwapped, receipt.SnapshotCached = len(queue.Swapped), len(queue.Cached)
	receipt.SnapshotOverlap = receipt.SnapshotWaiting + receipt.SnapshotRunning + receipt.SnapshotSwapped + receipt.SnapshotCached - len(status.TerminalDispositions)
	var before struct {
		Active int `json:"active"`
	}
	var after struct {
		Cancelled int `json:"cancelled"`
	}
	_ = json.Unmarshal(status.ProxySnapshot["before_engine_begin"], &before)
	_ = json.Unmarshal(status.ProxySnapshot["after_engine_begin"], &after)
	receipt.ProxyActive, receipt.ProxyCancelled = before.Active, after.Cancelled
	receipt.ObservationNonces = receipt.ObservationNonces[:0]
	receipt.ObservationSequences = receipt.ObservationSequences[:0]
	receipt.ObservationHashes = receipt.ObservationHashes[:0]
	for _, observation := range status.Observations {
		receipt.ObservationNonces = append(receipt.ObservationNonces, observation.Nonce)
		receipt.ObservationSequences = append(receipt.ObservationSequences, observation.Sequence)
		receipt.ObservationHashes = append(receipt.ObservationHashes, observation.Hash)
	}
	return nil
}

func drainV11Digest(domain string, value any) (string, error) {
	raw, err := drainV11CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(append([]byte(domain), 0), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// drainV11CanonicalJSON matches the proxy's ensure_ascii=False, sorted-key,
// compact JSON for the bounded protocol schema. encoding/json always escapes
// U+2028/U+2029, so repair only real one-backslash JSON escapes; a literal
// string containing "\\u2028" has two backslashes and remains unchanged.
func drainV11CanonicalJSON(value any) ([]byte, error) {
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
	if err := validateDrainV11CanonicalValue(normalized); err != nil {
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

func validateDrainV11CanonicalValue(value any) error {
	switch typed := value.(type) {
	case nil, bool, string:
		return nil
	case json.Number:
		parsed, err := strconv.ParseUint(string(typed), 10, 64)
		if err != nil || parsed > (1<<53)-1 {
			return fmt.Errorf("drain v11 JSON number is outside the interoperable integer range")
		}
		return nil
	case []any:
		for _, item := range typed {
			if err := validateDrainV11CanonicalValue(item); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, item := range typed {
			if err := validateDrainV11CanonicalValue(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("drain v11 canonical JSON contains unsupported type %T", value)
	}
}

func drainV11OwnerDigest(owner drainV11Owner) (string, error) {
	return drainV11Digest("phorvex-drain-owner-v1", map[string]string{
		"namespace_uid": owner.NamespaceUID, "pod_uid": owner.PodUID,
		"policy_uid": owner.PolicyUID, "service_uid": owner.ServiceUID,
		"tenant": owner.Tenant,
	})
}

func validateDrainV11ReceiptDigest(status drainV11StatusResponse) error {
	body := map[string]any{
		"schema": status.Schema, "operation_id": status.OperationID,
		"operation_generation": status.OperationGeneration, "attempt": status.Attempt,
		"owner_digest":               status.OwnerDigest,
		"backend_incarnation_digest": status.BackendIncarnationDigest,
		"revision":                   status.Revision, "state": status.State,
		"admission": status.Admission, "admission_generation": status.AdmissionGeneration,
		"engine_boot_id": status.EngineBootID, "virtual_engine_ids": status.VirtualEngineIDs,
		"engine_snapshot":       status.EngineSnapshot,
		"terminal_dispositions": status.TerminalDispositions,
		"proxy_snapshot":        status.ProxySnapshot, "observations": status.Observations,
		"deadline": status.Deadline, "last_transition": status.LastTransition,
		"cancellation_grace_deadline": status.CancellationGraceDeadline,
		"transition_reason":           status.TransitionReason,
		"cancel_boundary_revision":    status.CancelBoundaryRevision,
		"query_nonce":                 status.QueryNonce,
	}
	want, err := drainV11Digest("phorvex-drain-status-v1", body)
	if err != nil || status.ReceiptSHA256 != want {
		return fmt.Errorf("drain v11 status receipt digest mismatch")
	}
	return nil
}

func validDrainV11Decimal(value string, positive bool) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && (!positive || parsed != 0)
}

func validDrainV11Hex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func drainV11QueueIDs(queues map[string]drainV11Queues, requireZero bool) (map[string]struct{}, error) {
	if len(queues) != 1 {
		return nil, fmt.Errorf("drain v11 evidence must contain exactly virtual engine 0")
	}
	queue, ok := queues["0"]
	if !ok {
		return nil, fmt.Errorf("drain v11 evidence lacks virtual engine 0")
	}
	if queue.Waiting == nil || queue.Running == nil || queue.Swapped == nil || queue.Cached == nil {
		return nil, fmt.Errorf("drain v11 evidence omitted a required queue")
	}
	ids := map[string]struct{}{}
	// Scheduler ownership is exclusive across waiting, running and swapped.
	// Cached metadata can describe one of those same requests while its output
	// is in flight; the engine producer unions the four queues by request ID.
	for _, values := range [][]string{queue.Waiting, queue.Running, queue.Swapped} {
		if requireZero && len(values) != 0 {
			return nil, fmt.Errorf("drain v11 quiescence observation has a nonempty queue")
		}
		for _, id := range values {
			if id == "" || len(id) > 512 {
				return nil, fmt.Errorf("drain v11 snapshot has an invalid request ID")
			}
			if _, exists := ids[id]; exists {
				return nil, fmt.Errorf("drain v11 snapshot repeats a request ID")
			}
			ids[id] = struct{}{}
		}
	}
	if requireZero && len(queue.Cached) != 0 {
		return nil, fmt.Errorf("drain v11 quiescence observation has a nonempty queue")
	}
	cached := map[string]struct{}{}
	for _, id := range queue.Cached {
		if id == "" || len(id) > 512 {
			return nil, fmt.Errorf("drain v11 snapshot has an invalid request ID")
		}
		if _, exists := cached[id]; exists {
			return nil, fmt.Errorf("drain v11 snapshot repeats a request ID")
		}
		cached[id] = struct{}{}
		ids[id] = struct{}{}
	}
	return ids, nil
}

func validateDrainV11Evidence(value drainV11StatusResponse) error {
	proofState := value.State == "QUIESCENT" || value.State == "CANCELLED" || value.State == "OPENED"
	startedState := proofState || value.State == "DRAINING" || value.State == "CANCEL_REQUESTED"
	if !startedState {
		return nil
	}
	snapshotIDs, err := drainV11QueueIDs(value.EngineSnapshot, false)
	if err != nil {
		return err
	}
	if len(value.TerminalDispositions) != len(snapshotIDs) {
		return fmt.Errorf("drain v11 terminal dispositions do not cover the engine snapshot")
	}
	for id := range snapshotIDs {
		disposition, ok := value.TerminalDispositions[id]
		if !ok || (disposition != "aborted" && disposition != "completed-before-abort") {
			return fmt.Errorf("drain v11 terminal dispositions do not match the engine snapshot")
		}
	}
	if len(value.ProxySnapshot) != 2 {
		return fmt.Errorf("drain v11 proxy snapshot is incomplete")
	}
	before, beforeOK := value.ProxySnapshot["before_engine_begin"]
	after, afterOK := value.ProxySnapshot["after_engine_begin"]
	if !beforeOK || !afterOK || len(before) == 0 || len(after) == 0 {
		return fmt.Errorf("drain v11 proxy snapshot is incomplete")
	}
	var beforeCounts struct {
		Active *int `json:"active"`
	}
	// The second field has a distinct JSON name; keep it explicit rather than
	// relying on field-name inference in the wire contract.
	var closedCounts struct {
		Cancelled *int `json:"cancelled"`
		Remaining *int `json:"remaining"`
	}
	if err := strictDrainV11Decode(string(before), &beforeCounts); err != nil ||
		beforeCounts.Active == nil || *beforeCounts.Active < 0 || *beforeCounts.Active > (1<<53)-1 {
		return fmt.Errorf("drain v11 proxy pre-begin snapshot is invalid")
	}
	if err := strictDrainV11Decode(string(after), &closedCounts); err != nil ||
		closedCounts.Cancelled == nil || closedCounts.Remaining == nil ||
		*closedCounts.Cancelled < 0 || *closedCounts.Cancelled > (1<<53)-1 ||
		*closedCounts.Remaining != 0 {
		return fmt.Errorf("drain v11 proxy terminal snapshot is invalid")
	}
	if len(value.Observations) > 2 {
		return fmt.Errorf("drain v11 has too many quiescence observations")
	}
	var prior uint64
	nonces := map[string]struct{}{}
	completeProof := len(value.Observations) == 2
	for index, observation := range value.Observations {
		if !validDrainV11Hex(observation.Nonce, 16) || !validDrainV11Hex(observation.Hash, sha256.Size) {
			return fmt.Errorf("drain v11 observation identity is invalid")
		}
		sequence, parseErr := strconv.ParseUint(observation.Sequence, 10, 64)
		if parseErr != nil || sequence == 0 || (index > 0 && sequence <= prior) {
			return fmt.Errorf("drain v11 observation sequence is not strictly increasing")
		}
		prior = sequence
		if _, exists := nonces[observation.Nonce]; exists {
			return fmt.Errorf("drain v11 observation nonce was reused")
		}
		nonces[observation.Nonce] = struct{}{}
		if _, queueErr := drainV11QueueIDs(observation.Queues, true); queueErr != nil {
			completeProof = false
			if proofState {
				return queueErr
			}
		}
	}
	if proofState && !completeProof {
		return fmt.Errorf("drain v11 terminal state lacks two fresh zero-queue observations")
	}
	if !proofState && completeProof {
		return fmt.Errorf("drain v11 nonterminal state already carries a complete quiescence proof")
	}
	return nil
}

func validateDrainV11Capability(value drainV11CapabilityResponse) error {
	if value.Schema != drainV11Schema || value.Capability != drainV11Capability ||
		value.PodUID == "" || !validDrainV11Hex(value.LedgerID, 16) ||
		!validDrainV11Hex(value.ProxyBootID, 16) || !validDrainV11Hex(value.EngineBootID, 16) ||
		!validDrainV11Hex(value.IncarnationDigest, sha256.Size) || value.ProxySource == "" ||
		value.EngineSource == "" || value.EngineMode != "v0-frontend-multiprocessing" ||
		len(value.VirtualEngineIDs) != 1 || value.VirtualEngineIDs[0] != 0 ||
		!validDrainV11Decimal(value.GenerationHighWater, false) ||
		(value.NextOperationGeneration != "" && !validDrainV11Decimal(value.NextOperationGeneration, true)) ||
		(value.Admission != "OPEN" && value.Admission != "CLOSED") ||
		(value.Admission == "OPEN" && value.NextOperationGeneration == "") {
		return fmt.Errorf("drain v11 capability is incomplete, closed, or unsupported")
	}
	return nil
}

func validateDrainV11Status(value drainV11StatusResponse, operationID, generation string, expectedNonce *string) error {
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, value.Deadline)
	grace, graceErr := time.Parse(time.RFC3339Nano, value.CancellationGraceDeadline)
	_, transitionErr := time.Parse(time.RFC3339Nano, value.LastTransition)
	if value.Schema != drainV11Schema || value.OperationID != operationID ||
		value.OperationGeneration != generation || !validDrainV11Hex(value.OperationID, 16) ||
		(value.Attempt != 1 && value.Attempt != 2) || !strings.HasSuffix(value.Deadline, "Z") || deadlineErr != nil ||
		!strings.HasSuffix(value.CancellationGraceDeadline, "Z") || graceErr != nil ||
		!grace.Equal(deadline.Add(drainV11CancelGrace)) ||
		!strings.HasSuffix(value.LastTransition, "Z") || transitionErr != nil ||
		!validDrainV11Decimal(value.OperationGeneration, true) ||
		!validDrainV11Decimal(value.Revision, true) ||
		!validDrainV11Decimal(value.AdmissionGeneration, false) ||
		!validDrainV11Hex(value.OwnerDigest, sha256.Size) ||
		!validDrainV11Hex(value.BackendIncarnationDigest, sha256.Size) ||
		!validDrainV11Hex(value.EngineBootID, 16) || !validDrainV11Hex(value.ReceiptSHA256, sha256.Size) ||
		(value.Admission != "OPEN" && value.Admission != "CLOSED") ||
		((value.State == "OPENED") != (value.Admission == "OPEN")) ||
		len(value.VirtualEngineIDs) != 1 || value.VirtualEngineIDs[0] != 0 ||
		((expectedNonce == nil) != (value.QueryNonce == nil)) ||
		(expectedNonce != nil && *value.QueryNonce != *expectedNonce) {
		return fmt.Errorf("drain v11 status identity or binding is invalid")
	}
	boundaryValid := validDrainV11Decimal(value.CancelBoundaryRevision, false)
	boundarySet := boundaryValid && value.CancelBoundaryRevision != "0"
	if !boundaryValid || (value.TransitionReason != "none" &&
		value.TransitionReason != "deadline-expired" && value.TransitionReason != "operator-requested") ||
		((value.TransitionReason == "none") == boundarySet) ||
		((value.State == "CANCEL_REQUESTED" || value.State == "CANCELLED") && !boundarySet) {
		return fmt.Errorf("drain v11 cancellation boundary is invalid")
	}
	if value.State != "DRAINING" && value.State != "QUIESCENT" && value.State != "CANCEL_REQUESTED" &&
		value.State != "CANCELLED" && value.State != "FAILED" && value.State != "STALE" && value.State != "OPENED" {
		return fmt.Errorf("drain v11 status state is invalid")
	}
	// Once BeginDrain has entered the engine's ordered stream, the engine-owned
	// admission generation is this operation's durable replay generation. A
	// self-consistent response from another generation must never be accepted as
	// progress, terminal quiescence, cancellation, or reopen evidence. FAILED
	// and STALE may precede BeginDrain and therefore retain the prior generation.
	if value.State != "FAILED" && value.State != "STALE" &&
		value.AdmissionGeneration != value.OperationGeneration {
		return fmt.Errorf("drain v11 admission generation changed operation identity")
	}
	if err := validateDrainV11Evidence(value); err != nil {
		return err
	}
	return validateDrainV11ReceiptDigest(value)
}

func newDrainV11ID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func newDrainV11Nonce() (string, error) { return newDrainV11ID() }

func (c *httpVLLM) drainV11Request(ctx context.Context, ep servingEndpoint, method, route string, payload any, target any) (string, error) {
	ep, err := ep.validated()
	if err != nil {
		return "", err
	}
	if !ep.reachable() {
		return "", errStackUnreachable
	}
	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return "", err
		}
	}
	code, response, responseType, err := c.requestWithClientMetadata(ctx, ep.client, method, ep.routeURL(route), ep.token,
		map[bool]string{true: "application/json", false: ""}[payload != nil], body)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK && code != http.StatusCreated {
		return "", fmt.Errorf("drain v11 %s: HTTP %d", method, code)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(responseType)
	if mediaErr != nil || strings.ToLower(mediaType) != "application/json" {
		return "", fmt.Errorf("drain v11 response is not application/json")
	}
	if err := strictDrainV11Decode(response, target); err != nil {
		return "", fmt.Errorf("drain v11 invalid bounded response: %w", err)
	}
	digest := sha256.Sum256([]byte(response))
	return hex.EncodeToString(digest[:]), nil
}

func drainV11Base(ep servingEndpoint) string {
	return strings.TrimSuffix(ep.drainPath, "/")
}

func (c *httpVLLM) DrainV11Capability(ctx context.Context, ep servingEndpoint) (drainV11CapabilityResponse, error) {
	var result drainV11CapabilityResponse
	rawSHA, err := c.drainV11Request(ctx, ep, http.MethodGet, drainV11Base(ep)+"/capability", nil, &result)
	if err == nil {
		result.RawSHA256 = rawSHA
		err = validateDrainV11Capability(result)
	}
	return result, err
}

func (c *httpVLLM) DrainV11Create(ctx context.Context, ep servingEndpoint, request drainV11CreateRequest) (drainV11StatusResponse, error) {
	var result drainV11StatusResponse
	_, err := c.drainV11Request(ctx, ep, http.MethodPost, drainV11Base(ep)+"/operations", request, &result)
	if err == nil {
		err = validateDrainV11Status(result, request.OperationID, request.OperationGeneration, nil)
		if err == nil && result.Attempt != request.Attempt {
			err = fmt.Errorf("drain v11 create response changed the operation attempt")
		}
	}
	return result, err
}

func (c *httpVLLM) DrainV11Status(ctx context.Context, ep servingEndpoint, generation, operationID, nonce string) (drainV11StatusResponse, error) {
	var result drainV11StatusResponse
	route := fmt.Sprintf("%s/operations/%s/%s?observation_nonce=%s", drainV11Base(ep),
		url.PathEscape(generation), url.PathEscape(operationID), url.QueryEscape(nonce))
	_, err := c.drainV11Request(ctx, ep, http.MethodGet, route, nil, &result)
	if err == nil {
		err = validateDrainV11Status(result, operationID, generation, &nonce)
	}
	return result, err
}

func (c *httpVLLM) DrainV11Cancel(ctx context.Context, ep servingEndpoint, generation, operationID string, request drainV11IntentRequest) (drainV11StatusResponse, error) {
	return c.drainV11Intent(ctx, ep, generation, operationID, "cancel", request)
}

func (c *httpVLLM) DrainV11Reopen(ctx context.Context, ep servingEndpoint, generation, operationID string, request drainV11IntentRequest) (drainV11StatusResponse, error) {
	return c.drainV11Intent(ctx, ep, generation, operationID, "reopen", request)
}

func (c *httpVLLM) drainV11Intent(ctx context.Context, ep servingEndpoint, generation, operationID, action string, request drainV11IntentRequest) (drainV11StatusResponse, error) {
	var result drainV11StatusResponse
	route := fmt.Sprintf("%s/operations/%s/%s/%s", drainV11Base(ep),
		url.PathEscape(generation), url.PathEscape(operationID), action)
	_, err := c.drainV11Request(ctx, ep, http.MethodPost, route, request, &result)
	if err == nil {
		err = validateDrainV11Status(result, operationID, generation, nil)
	}
	wantState, wantAdmission := "OPENED", "OPEN"
	if action == "cancel" {
		wantState, wantAdmission = "CANCEL_REQUESTED", "CLOSED"
	}
	if err == nil && (result.Schema != drainV11Schema || result.OperationID != operationID ||
		result.OperationGeneration != generation || result.State != wantState || result.Admission != wantAdmission ||
		result.OwnerDigest != request.OwnerDigest || result.BackendIncarnationDigest != request.ExpectedIncarnationDigest ||
		!validDrainV11Decimal(result.Revision, true) || !validDrainV11Hex(result.ReceiptSHA256, sha256.Size)) {
		err = fmt.Errorf("drain v11 %s was not confirmed", action)
	}
	return result, err
}

func drainV11Deadline(timeout time.Duration) string {
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 3 * time.Minute
	}
	return drainV11Time(time.Now().UTC().Add(timeout))
}

func drainV11Time(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000Z")
}

func drainV11CancellationTimes(timeout time.Duration) (deadline, cancelAt, grace string) {
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 3 * time.Minute
	}
	deadlineTime := time.Now().UTC().Add(timeout)
	reserve := 10 * time.Second
	if timeout < 40*time.Second {
		reserve = timeout / 4
	}
	return drainV11Time(deadlineTime), drainV11Time(deadlineTime.Add(-reserve)),
		drainV11Time(deadlineTime.Add(drainV11CancelGrace))
}
