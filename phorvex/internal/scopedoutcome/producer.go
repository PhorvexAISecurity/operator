// Package scopedoutcome observes one synthetic process-local session across an
// acknowledged native rotation. It produces reporting-only categorical results;
// it does not estimate attacker presence or mutate the decision model.
package scopedoutcome

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	SessionResponseSchemaV1 = "phorvex.synthetic-process-session-response.v1"
	defaultQueueCapacity    = 64
	defaultResultCapacity   = 64
	maxEvidenceBytes        = 64 << 10
	maxHTTPBodyBytes        = 8 << 10
	maxRetainedOperations   = 1024
)

type SessionEndpoint struct {
	URL                 string `json:"url"`
	SessionID           string `json:"sessionID"`
	Challenge           string `json:"challenge"`
	TargetUID           string `json:"targetUID"`
	WorkloadScopeSHA256 string `json:"workloadScopeSHA256"`
}

type SessionResponse struct {
	SchemaVersion       string `json:"schemaVersion"`
	SessionID           string `json:"sessionID"`
	Challenge           string `json:"challenge"`
	Present             bool   `json:"present"`
	TargetUID           string `json:"targetUID"`
	WorkloadScopeSHA256 string `json:"workloadScopeSHA256"`
}

type PrepareConfig struct {
	Policy                        model.PolicyEpoch              `json:"policy"`
	Workload                      model.PersistenceWorkloadScope `json:"workload"`
	TargetUID                     string                         `json:"targetUID"`
	TargetName                    string                         `json:"targetName"`
	TargetTerminationGraceSeconds int64                          `json:"targetTerminationGraceSeconds"`
	Old                           SessionEndpoint                `json:"old"`
	Replacement                   SessionEndpoint                `json:"replacement"`
}

type EvidenceBundle struct {
	SchemaVersion    string                            `json:"schemaVersion"`
	EvidenceID       string                            `json:"evidenceID"`
	Binding          model.PersistenceOperationBinding `json:"binding"`
	Observation      model.PersistenceObservation      `json:"observation"`
	BeforeObservedAt time.Time                         `json:"beforeObservedAt"`
	Before           json.RawMessage                   `json:"before"`
	Action           json.RawMessage                   `json:"action"`
	After            json.RawMessage                   `json:"after"`
}

type EvidenceStore interface {
	Put(context.Context, EvidenceBundle) error
}

type BindingResolver interface {
	Resolve(context.Context, PrepareConfig) (model.PersistenceWorkloadScope, int64, error)
	SnapshotReplacementBoundary(context.Context, PrepareConfig) ([]string, error)
	ResolveReplacement(context.Context, PrepareConfig, []string, string, time.Time) error
}

type preparedSession struct {
	config                     PrepareConfig
	beforeRaw                  []byte
	beforeAt                   time.Time
	preexistingReplacementUIDs []string
}

type trial struct {
	prepared  preparedSession
	binding   model.PersistenceOperationBinding
	actionRaw []byte
}

type authorizedObservation struct {
	observation model.PersistenceObservation
	binding     model.PersistenceOperationBinding
	digest      [sha256.Size]byte
}

type mtlsTransport struct{ *http.Transport }

// Producer is both the exact observation authority and a bounded asynchronous
// observer. RecordNativeRotate only enqueues; network, waiting, and evidence
// persistence happen on the single worker outside the decision tick.
type Producer struct {
	client    *http.Client
	store     EvidenceStore
	resolver  BindingResolver
	now       func() time.Time
	waitUntil func(context.Context, time.Time) bool

	processEpochID string
	ctx            context.Context
	cancel         context.CancelFunc
	jobs           chan trial
	results        chan model.ScopedOutcomeDelivery
	stop           chan struct{}
	done           chan struct{}
	evidenceSlot   chan struct{}

	mu         sync.RWMutex
	prepared   map[string]preparedSession // exact old target UID
	bindings   map[string]model.PersistenceOperationBinding
	allowed    map[string]authorizedObservation
	overflowMu sync.Mutex
	overflow   map[string]model.ScopedOutcomeDelivery
}

func New(client *http.Client, store EvidenceStore, resolver BindingResolver, processEpochID string, now func() time.Time) (*Producer, error) {
	if client == nil {
		return nil, errors.New("scoped outcome producer requires an exact TLS 1.3 mutual-authentication client")
	}
	transport, ok := client.Transport.(*mtlsTransport)
	if !ok || transport.Transport == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil ||
		len(transport.TLSClientConfig.Certificates) != 1 || transport.TLSClientConfig.ServerName == "" ||
		transport.TLSClientConfig.MinVersion < tls.VersionTLS13 {
		return nil, errors.New("scoped outcome producer requires an exact TLS 1.3 mutual-authentication client")
	}
	return newProducer(client, store, resolver, processEpochID, now)
}

func newProducer(client *http.Client, store EvidenceStore, resolver BindingResolver, processEpochID string, now func() time.Time) (*Producer, error) {
	if client == nil || store == nil || resolver == nil || processEpochID == "" || len(processEpochID) > 253 || !utf8.ValidString(processEpochID) {
		return nil, errors.New("scoped outcome producer requires client, evidence store, authority resolver, and process epoch")
	}
	if client.Timeout <= 0 || client.Timeout > 5*time.Second {
		return nil, errors.New("scoped outcome HTTP client requires a timeout no greater than five seconds")
	}
	if client.CheckRedirect == nil {
		return nil, errors.New("scoped outcome HTTP client must explicitly refuse redirects")
	}
	if now == nil {
		now = time.Now
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	p := &Producer{
		client: client, store: store, resolver: resolver, now: now, processEpochID: processEpochID,
		ctx: workerCtx, cancel: workerCancel,
		jobs: make(chan trial, defaultQueueCapacity), results: make(chan model.ScopedOutcomeDelivery, defaultResultCapacity),
		stop: make(chan struct{}), done: make(chan struct{}), prepared: map[string]preparedSession{},
		evidenceSlot: make(chan struct{}, 1),
		bindings:     map[string]model.PersistenceOperationBinding{}, allowed: map[string]authorizedObservation{},
		overflow: map[string]model.ScopedOutcomeDelivery{},
	}
	p.waitUntil = func(ctx context.Context, deadline time.Time) bool {
		delay := time.Until(deadline)
		if delay <= 0 {
			return ctx.Err() == nil
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	go p.run()
	return p, nil
}

// NewMTLSClient constructs the fixture-scoped transport. The caller supplies
// private key material directly; Producer never serializes it into evidence.
func NewMTLSClient(roots *x509.CertPool, certificate tls.Certificate, serverName string, timeout time.Duration) (*http.Client, error) {
	if roots == nil || len(certificate.Certificate) == 0 || serverName == "" || timeout <= 0 || timeout > 5*time.Second {
		return nil, errors.New("scoped outcome mTLS identity, roots, server name, or timeout is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: serverName,
	}}
	return &http.Client{Transport: &mtlsTransport{Transport: transport}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("scoped outcome endpoint redirects are refused")
	}}, nil
}

func (*Producer) Source() string { return model.ScopedSessionCapability }

func (p *Producer) AuthorizeObservation(observation model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	encoded, err := json.Marshal(observation)
	if err != nil {
		return model.PersistenceOperationBinding{}, false
	}
	digest := sha256.Sum256(encoded)
	p.mu.RLock()
	defer p.mu.RUnlock()
	allowed, ok := p.allowed[observation.EvidenceID]
	if !ok || allowed.digest != digest || !reflect.DeepEqual(allowed.observation, observation) {
		return model.PersistenceOperationBinding{}, false
	}
	binding, ok := p.bindings[observation.OperationID]
	if !ok || binding != allowed.binding {
		return model.PersistenceOperationBinding{}, false
	}
	return binding, true
}

// Prepare proves exact old-session access before dispatch. It is called by the
// fixture coordinator, never by the decision tick.
func (p *Producer) Prepare(ctx context.Context, config PrepareConfig) error {
	if err := validatePrepare(config); err != nil {
		return err
	}
	workload, grace, err := p.resolver.Resolve(ctx, config)
	if err != nil || workload != config.Workload || grace != config.TargetTerminationGraceSeconds {
		return errors.New("synthetic session target does not match current policy/workload authority")
	}
	probe, err := p.probe(ctx, config.Old)
	ended := p.now()
	if err != nil {
		return fmt.Errorf("prove old synthetic session: %w", err)
	}
	if probe.status != http.StatusOK || !probe.response.Present {
		return errors.New("old synthetic session was not positively present before dispatch")
	}
	preexisting, err := p.resolver.SnapshotReplacementBoundary(ctx, config)
	if err != nil {
		return fmt.Errorf("snapshot pre-dispatch replacement boundary: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.prepared[config.TargetUID]; exists {
		return errors.New("synthetic target already has a prepared session")
	}
	if len(p.prepared)+len(p.bindings) >= maxRetainedOperations {
		return errors.New("scoped outcome operation store is full")
	}
	p.prepared[config.TargetUID] = preparedSession{config: config, beforeRaw: probe.raw, beforeAt: ended,
		preexistingReplacementUIDs: append([]string(nil), preexisting...)}
	return nil
}

// RecordNativeRotate binds only a previously proved session to the exact
// coherent native result. It performs no network or durable I/O and never
// blocks when the bounded queue is full.
func (p *Producer) RecordNativeRotate(policy model.Policy, view *model.WorkloadView, request actuatorapi.Request, result actuatorapi.Result, acknowledgedAt time.Time) bool {
	if view == nil || acknowledgedAt.IsZero() || request.Action != model.ActionRotate || result.Handler != string(model.ActionRotate) ||
		!result.Emitted || result.Actuator != "native" || result.NoEffect != actuatorapi.NoEffectUnknown || result.MutationKind != "forward-only" ||
		result.RollbackRef != "" || len(result.ObjectsTouched) != 1 || result.ObjectsTouched[0] != "Pod/"+request.Namespace+"/"+request.Pod ||
		request.TargetUID == "" || request.TargetUID != view.Pod.UID ||
		request.PolicyUID != policy.PolicyUID || request.PolicyName != policy.PolicyName || request.Namespace != view.Pod.Namespace || request.Pod != view.Pod.Name {
		return false
	}
	p.mu.Lock()
	prepared, ok := p.prepared[request.TargetUID]
	if !ok || prepared.config.Policy != (model.PolicyEpoch{Namespace: policy.Namespace, Name: policy.PolicyName, UID: policy.PolicyUID, Generation: policy.PolicyGeneration}) ||
		prepared.config.Workload.Namespace != view.Pod.Namespace || prepared.config.TargetName != view.Pod.Name || acknowledgedAt.Before(prepared.beforeAt) {
		p.mu.Unlock()
		return false
	}
	delete(p.prepared, request.TargetUID)
	p.mu.Unlock()
	actionRaw, err := canonicalActionEvidence(request, result, acknowledgedAt)
	if err != nil {
		p.offerUnavailable(prepared.config.Policy, "native rotate receipt could not be canonicalized")
		return false
	}
	actionDigest := sha256.Sum256(actionRaw)
	operationID := hex.EncodeToString(actionDigest[:])
	binding := model.PersistenceOperationBinding{
		Policy: prepared.config.Policy, ProcessEpochID: p.processEpochID, ContractVersion: model.ScopedSessionNativeRotateV1,
		Workload: prepared.config.Workload, OperationID: operationID, TargetUID: prepared.config.TargetUID,
		Capability: model.ScopedSessionCapability, Action: model.ActionRotate, DispatchAcknowledgedAt: acknowledgedAt,
		ObservationNotBefore: acknowledgedAt.Add(60 * time.Second), ObservationDeadline: acknowledgedAt.Add(65 * time.Second),
		TargetTerminationGraceSeconds: prepared.config.TargetTerminationGraceSeconds,
	}
	select {
	case p.jobs <- trial{prepared: prepared, binding: binding, actionRaw: actionRaw}:
		return true
	default:
		p.offerUnavailable(prepared.config.Policy, "scoped outcome observer queue is full")
		return false
	}
}

func (p *Producer) Drain(limit int) []model.ScopedOutcomeDelivery {
	if limit <= 0 {
		return nil
	}
	out := make([]model.ScopedOutcomeDelivery, 0, limit)
	for len(out) < limit {
		select {
		case result := <-p.results:
			out = append(out, result)
		default:
			p.overflowMu.Lock()
			owners := make([]string, 0, len(p.overflow))
			for owner := range p.overflow {
				owners = append(owners, owner)
			}
			sort.Strings(owners)
			for _, owner := range owners {
				delivery := p.overflow[owner]
				out = append(out, delivery)
				delete(p.overflow, owner)
				if len(out) == limit {
					break
				}
			}
			p.overflowMu.Unlock()
			return out
		}
	}
	return out
}

// CheckNoOperation proves that the same old synthetic session remains reachable
// across the declared horizon when no action occurs. It never creates a binding,
// observation, cohort sample, or authority entry.
func (p *Producer) CheckNoOperation(ctx context.Context, endpoint SessionEndpoint) (bool, error) {
	if endpoint.TargetUID == "" {
		return false, errors.New("no-operation control requires an exact target UID")
	}
	before, err := p.probe(ctx, endpoint)
	if err != nil || before.status != http.StatusOK || !before.response.Present {
		return false, errors.New("no-operation control lacked a present before session")
	}
	if !p.waitUntil(ctx, p.now().Add(60*time.Second)) {
		return false, ctx.Err()
	}
	after, err := p.probe(ctx, endpoint)
	if err != nil || after.status != http.StatusOK || !after.response.Present {
		return false, errors.New("no-operation control did not retain the exact session")
	}
	return true, nil
}

func (p *Producer) Close() {
	select {
	case <-p.stop:
		return
	default:
		close(p.stop)
		p.cancel()
		<-p.done
	}
}

func (p *Producer) run() {
	defer close(p.done)
	for {
		select {
		case <-p.stop:
			return
		case job := <-p.jobs:
			p.observe(job)
		}
	}
}

func (p *Producer) observe(job trial) {
	now := p.now()
	if now.Before(job.binding.ObservationNotBefore) {
		if !p.waitUntil(p.ctx, job.binding.ObservationNotBefore) {
			return
		}
	}
	started := p.now()
	outcome := model.PersistenceUnknown
	var afterRaw []byte
	if started.After(job.binding.ObservationDeadline) {
		outcome = model.PersistenceCensored
		afterRaw = []byte(`{"disposition":"missed-60-65-second-window"}`)
	} else {
		deadline := job.binding.ObservationDeadline
		ctx, cancel := context.WithTimeout(p.ctx, deadline.Sub(p.now()))
		oldProbe, oldErr := p.probe(ctx, job.prepared.config.Old)
		if oldErr == nil && oldProbe.status == http.StatusOK && oldProbe.response.Present {
			outcome, afterRaw = model.PersistenceHeld, oldProbe.raw
		} else if oldErr == nil && (oldProbe.status == http.StatusNotFound || oldProbe.status == http.StatusGone) && !oldProbe.response.Present {
			newProbe, newErr := p.probe(ctx, job.prepared.config.Replacement)
			if newErr == nil && newProbe.status == http.StatusOK && newProbe.response.Present {
				if replacementErr := p.resolver.ResolveReplacement(ctx, job.prepared.config,
					job.prepared.preexistingReplacementUIDs, newProbe.response.TargetUID,
					job.binding.DispatchAcknowledgedAt); replacementErr == nil {
					outcome = model.PersistenceRevoked
					afterRaw, _ = json.Marshal(struct {
						Old         json.RawMessage `json:"old"`
						Replacement json.RawMessage `json:"replacement"`
					}{Old: oldProbe.raw, Replacement: newProbe.raw})
				} else {
					afterRaw = boundedDiagnostic("replacement Kubernetes authority unavailable", replacementErr)
				}
			} else {
				afterRaw = boundedDiagnostic("replacement session unavailable", newErr)
			}
		} else {
			afterRaw = boundedDiagnostic("old session outcome unavailable", oldErr)
		}
		cancel()
	}
	ended := p.now()
	if ended.After(job.binding.ObservationDeadline) && outcome != model.PersistenceCensored {
		outcome = model.PersistenceUnknown
		afterRaw = []byte(`{"disposition":"probe-crossed-observation-deadline"}`)
	}
	if len(afterRaw) == 0 {
		afterRaw = []byte(`{"disposition":"empty-observer-result"}`)
	}
	beforeDigest, actionDigest, afterDigest := sha256.Sum256(job.prepared.beforeRaw), sha256.Sum256(job.actionRaw), sha256.Sum256(afterRaw)
	evidenceIDRaw := sha256.Sum256(append(append([]byte(job.binding.OperationID+"\x00"), beforeDigest[:]...), afterDigest[:]...))
	observation := model.PersistenceObservation{
		SchemaVersion: model.ScopedOutcomeObservationSchemaV1, Source: model.ScopedSessionCapability,
		ProcessEpochID: p.processEpochID, ContractVersion: model.ScopedSessionNativeRotateV1, EvidenceID: hex.EncodeToString(evidenceIDRaw[:]),
		Policy: job.binding.Policy, Workload: job.binding.Workload, OperationID: job.binding.OperationID, TargetUID: job.binding.TargetUID,
		Capability: job.binding.Capability, Action: job.binding.Action, BeforeSHA256: hex.EncodeToString(beforeDigest[:]),
		ActionSHA256: hex.EncodeToString(actionDigest[:]), AfterSHA256: hex.EncodeToString(afterDigest[:]),
		ObservationStart: started, ObservationEnd: ended, Outcome: outcome,
	}
	bundle := EvidenceBundle{SchemaVersion: model.ScopedOutcomeObservationSchemaV1, EvidenceID: observation.EvidenceID,
		Binding: job.binding, Observation: observation, BeforeObservedAt: job.prepared.beforeAt,
		Before: cloneRaw(job.prepared.beforeRaw), Action: cloneRaw(job.actionRaw), After: cloneRaw(afterRaw)}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil || len(bundleRaw) > maxEvidenceBytes {
		p.offerUnavailable(job.binding.Policy, "scoped outcome evidence bundle exceeded its bound")
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	err = p.putEvidence(ctx, bundle)
	cancel()
	if err != nil {
		p.offerUnavailable(job.binding.Policy, "scoped outcome evidence retention failed")
		return
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		p.offerUnavailable(job.binding.Policy, "scoped outcome observation encoding failed")
		return
	}
	p.mu.Lock()
	if len(p.allowed) >= maxRetainedOperations {
		p.mu.Unlock()
		p.offerUnavailable(job.binding.Policy, "scoped outcome authority store is full")
		return
	}
	p.bindings[job.binding.OperationID] = job.binding
	p.allowed[observation.EvidenceID] = authorizedObservation{observation: observation, binding: job.binding, digest: sha256.Sum256(encoded)}
	p.mu.Unlock()
	copy := observation
	p.offer(model.ScopedOutcomeDelivery{Policy: observation.Policy, Observation: &copy})
}

// putEvidence keeps producer shutdown bounded even when an EvidenceStore
// implementation fails to honor context cancellation. The buffered result
// channel lets a late Put return without retaining the producer worker.
func (p *Producer) putEvidence(ctx context.Context, bundle EvidenceBundle) error {
	select {
	case p.evidenceSlot <- struct{}{}:
	default:
		return errors.New("scoped outcome evidence store still has an in-flight write")
	}
	result := make(chan error, 1)
	go func() {
		defer func() { <-p.evidenceSlot }()
		result <- p.store.Put(ctx, bundle)
	}()
	select {
	case err := <-result:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type probeResult struct {
	status   int
	response SessionResponse
	raw      []byte
}

func (p *Producer) probe(ctx context.Context, endpoint SessionEndpoint) (probeResult, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return probeResult{}, err
	}
	u, _ := url.Parse(endpoint.URL)
	query := u.Query()
	query.Set("session", endpoint.SessionID)
	query.Set("challenge", endpoint.Challenge)
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return probeResult{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return probeResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes+1))
	if err != nil || len(body) > maxHTTPBodyBytes {
		return probeResult{}, errors.New("synthetic session response exceeded the bounded body")
	}
	if !utf8.Valid(body) {
		return probeResult{}, errors.New("synthetic session response is not valid UTF-8")
	}
	var decoded SessionResponse
	if err := currentinventory.RejectDuplicateFields(body); err != nil {
		return probeResult{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return probeResult{}, err
	}
	presentRaw, ok := fields["present"]
	if !ok {
		return probeResult{}, errors.New("synthetic session response omitted presence")
	}
	presentToken := bytes.TrimSpace(presentRaw)
	if !bytes.Equal(presentToken, []byte("true")) && !bytes.Equal(presentToken, []byte("false")) {
		return probeResult{}, errors.New("synthetic session response presence is not a boolean")
	}
	var explicitPresent bool
	if err := json.Unmarshal(presentToken, &explicitPresent); err != nil {
		return probeResult{}, errors.New("synthetic session response presence is not a boolean")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return probeResult{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return probeResult{}, errors.New("synthetic session response has trailing JSON")
	}
	if decoded.SchemaVersion != SessionResponseSchemaV1 || decoded.SessionID != endpoint.SessionID || decoded.Challenge != endpoint.Challenge ||
		decoded.TargetUID == "" || len(decoded.TargetUID) > 253 || !utf8.ValidString(decoded.TargetUID) ||
		(endpoint.TargetUID != "" && decoded.TargetUID != endpoint.TargetUID) || decoded.WorkloadScopeSHA256 != endpoint.WorkloadScopeSHA256 {
		return probeResult{}, errors.New("synthetic session response identity mismatch")
	}
	if resp.StatusCode == http.StatusOK && !decoded.Present {
		return probeResult{}, errors.New("200 response contradicted session presence")
	}
	if (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) && decoded.Present {
		return probeResult{}, errors.New("absence response contradicted session presence")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusGone {
		return probeResult{}, fmt.Errorf("synthetic session endpoint returned HTTP %d", resp.StatusCode)
	}
	return probeResult{status: resp.StatusCode, response: decoded, raw: append([]byte(nil), body...)}, nil
}

func validatePrepare(config PrepareConfig) error {
	if err := config.Policy.Validate(); err != nil {
		return err
	}
	if err := config.Workload.Validate(); err != nil {
		return err
	}
	if config.Policy.Namespace != config.Workload.Namespace {
		return errors.New("synthetic policy and stable workload namespaces differ")
	}
	if config.TargetUID == "" || config.TargetName == "" || len(config.TargetUID) > 253 || len(config.TargetName) > 253 ||
		!utf8.ValidString(config.TargetUID) || !utf8.ValidString(config.TargetName) ||
		config.TargetTerminationGraceSeconds < 0 || config.TargetTerminationGraceSeconds > 30 {
		return errors.New("synthetic target identity or termination grace is invalid")
	}
	if err := validateEndpoint(config.Old); err != nil {
		return fmt.Errorf("old endpoint: %w", err)
	}
	if err := validateEndpoint(config.Replacement); err != nil {
		return fmt.Errorf("replacement endpoint: %w", err)
	}
	if config.Old.SessionID == config.Replacement.SessionID {
		return errors.New("old and replacement session identities must differ")
	}
	digest, _ := config.Workload.Digest()
	if config.Old.TargetUID != config.TargetUID || config.Old.WorkloadScopeSHA256 != digest || config.Replacement.WorkloadScopeSHA256 != digest ||
		config.Replacement.TargetUID != "" {
		return errors.New("synthetic session endpoints do not bind the exact old and replacement targets")
	}
	return nil
}

func validateEndpoint(endpoint SessionEndpoint) error {
	if endpoint.URL == "" || endpoint.SessionID == "" || endpoint.Challenge == "" || !validDigest(endpoint.WorkloadScopeSHA256) ||
		len(endpoint.URL) > 2048 || len(endpoint.SessionID) > 253 || len(endpoint.Challenge) > 253 || len(endpoint.TargetUID) > 253 ||
		!utf8.ValidString(endpoint.URL) || !utf8.ValidString(endpoint.SessionID) || !utf8.ValidString(endpoint.Challenge) || !utf8.ValidString(endpoint.TargetUID) {
		return errors.New("synthetic session endpoint identity is invalid")
	}
	u, err := url.Parse(endpoint.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return errors.New("synthetic session endpoint must be an exact HTTPS URL without credentials, query, or fragment")
	}
	return nil
}

func canonicalActionEvidence(request actuatorapi.Request, result actuatorapi.Result, acknowledgedAt time.Time) ([]byte, error) {
	return json.Marshal(struct {
		SchemaVersion  string              `json:"schemaVersion"`
		AcknowledgedAt time.Time           `json:"acknowledgedAt"`
		Request        actuatorapi.Request `json:"request"`
		Result         actuatorapi.Result  `json:"result"`
	}{SchemaVersion: "phorvex.native-rotate-ack.v1", AcknowledgedAt: acknowledgedAt, Request: request, Result: result})
}

func boundedDiagnostic(message string, err error) []byte {
	if err != nil {
		message += ": " + err.Error()
	}
	if len(message) > 512 {
		message = message[:512]
	}
	raw, _ := json.Marshal(struct {
		Disposition string `json:"disposition"`
	}{Disposition: message})
	return raw
}

func cloneRaw(raw []byte) json.RawMessage { return append(json.RawMessage(nil), raw...) }

func (p *Producer) offerUnavailable(policy model.PolicyEpoch, reason string) {
	p.offer(model.ScopedOutcomeDelivery{Policy: policy, Disposition: model.PersistenceDispositionUnavailable, Reason: reason})
}

func (p *Producer) offer(delivery model.ScopedOutcomeDelivery) {
	select {
	case p.results <- delivery:
	default:
		// Preserve one explicit unavailable disposition per affected owner. The
		// bounded reporting channel never blocks dispatch or grows without bound.
		p.overflowMu.Lock()
		if len(p.overflow) < defaultResultCapacity || p.overflow[delivery.Policy.Owner()].Policy.UID != "" {
			p.overflow[delivery.Policy.Owner()] = model.ScopedOutcomeDelivery{Policy: delivery.Policy, Disposition: model.PersistenceDispositionUnavailable, Reason: "scoped outcome result queue is full"}
		}
		p.overflowMu.Unlock()
	}
}
