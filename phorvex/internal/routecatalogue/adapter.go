// Package routecatalogue exposes a narrow, evidence-producing catalogue boundary around
// the production native route cutover. It deliberately admits only the two existing
// selector-restitch actions and delegates every cutover and rollback write to NativeActuator.
package routecatalogue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	ConfigSchema   = "phorvex.native-route-catalogue.config.v1"
	ReceiptSchema  = "phorvex.native-route-catalogue.receipt.v1"
	IdentitySchema = "phorvex.native-route-catalogue.identity.v1"

	routeKey               = "phorvex.ai/route-key"
	routeBridgeKey         = "phorvex.ai/route-bridge"
	routeEpochKey          = "phorvex.ai/route-epoch"
	endpointEpochKey       = "phorvex.ai/endpoint-epoch"
	routeServiceAnnotation = "phorvex.ai/route-service"
	operationJournalLabel  = "phorvex.ai/operation-journal"
	routeGuardLabel        = "phorvex.ai/route-target-guard"

	MaxHTTPBodyBytes  = 4096
	MaxHTTPSamples    = 4096
	MaxJournalObjects = 8
	MaxWrites         = 96
)

type Action string

const (
	ActionRouteRotate    Action = "route-rotate"
	ActionEndpointRotate Action = "endpoint-rotate"
)

func (a Action) modelAction() (model.Action, error) {
	switch a {
	case ActionRouteRotate:
		return model.ActionRouteRotate, nil
	case ActionEndpointRotate:
		return model.ActionEndpointRotate, nil
	default:
		return "", fmt.Errorf("route catalogue action %q is not allowed", a)
	}
}

func (a Action) epochKey() string {
	if a == ActionEndpointRotate {
		return endpointEpochKey
	}
	return routeEpochKey
}

func (a Action) otherEpochKey() string {
	if a == ActionEndpointRotate {
		return routeEpochKey
	}
	return endpointEpochKey
}

type Fixture struct {
	Nonce               string `json:"nonce"`
	Tenant              string `json:"tenant"`
	Namespace           string `json:"namespace"`
	NamespaceUID        string `json:"namespaceUID"`
	JournalNamespace    string `json:"journalNamespace"`
	JournalNamespaceUID string `json:"journalNamespaceUID"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	TargetName          string `json:"targetName"`
	TargetUID           string `json:"targetUID"`
	PeerName            string `json:"peerName"`
	PeerUID             string `json:"peerUID"`
	ServiceName         string `json:"serviceName"`
	ServiceUID          string `json:"serviceUID"`
	OperationID         string `json:"operationID"`
}

type ObservationConfig struct {
	TargetURL                  string `json:"targetURL"`
	PeerURL                    string `json:"peerURL"`
	ServiceURL                 string `json:"serviceURL"`
	SampleIntervalMillis       int    `json:"sampleIntervalMillis"`
	RequestTimeoutMillis       int    `json:"requestTimeoutMillis"`
	MinSamplesPerEndpointPhase int    `json:"minSamplesPerEndpointPhase"`
}

type RunConfig struct {
	Schema         string            `json:"schema"`
	SourceRevision string            `json:"sourceRevision"`
	Action         Action            `json:"action"`
	Fixture        Fixture           `json:"fixture"`
	Observation    ObservationConfig `json:"observation"`
}

type HTTPIdentity struct {
	Schema        string `json:"schema"`
	Nonce         string `json:"nonce"`
	Role          string `json:"role"`
	PodUID        string `json:"podUID"`
	ProcessMarker string `json:"processMarker"`
}

type HTTPObservation struct {
	Sequence   int64         `json:"sequence"`
	Phase      string        `json:"phase"`
	Endpoint   string        `json:"endpoint"`
	StartedAt  string        `json:"startedAt"`
	FinishedAt string        `json:"finishedAt"`
	Status     int           `json:"status,omitempty"`
	Bytes      int           `json:"bytes"`
	SHA256     string        `json:"sha256"`
	Body       string        `json:"body,omitempty"`
	Identity   *HTTPIdentity `json:"identity,omitempty"`
	Error      string        `json:"error,omitempty"`
	// TerminalCancellation records the sampler's own bounded shutdown. The row
	// remains evidence, but is not an observed application outage.
	TerminalCancellation bool `json:"terminalCancellation,omitempty"`
}

type WriteObservation struct {
	Sequence   int    `json:"sequence"`
	Method     string `json:"method"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Error      string `json:"error,omitempty"`
}

type PodSnapshot struct {
	Name            string            `json:"name"`
	UID             string            `json:"uid"`
	ResourceVersion string            `json:"resourceVersion"`
	PodIP           string            `json:"podIP"`
	PodIPs          []string          `json:"podIPs"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
	ContainerIDs    map[string]string `json:"containerIDs"`
	RestartCounts   map[string]int32  `json:"restartCounts"`
	Ready           bool              `json:"ready"`
}

type ServiceSnapshot struct {
	Name            string               `json:"name"`
	UID             string               `json:"uid"`
	ResourceVersion string               `json:"resourceVersion"`
	ClusterIP       string               `json:"clusterIP"`
	ClusterIPs      []string             `json:"clusterIPs"`
	Ports           []corev1.ServicePort `json:"ports"`
	Selector        map[string]string    `json:"selector"`
}

type JournalSnapshot struct {
	Name            string            `json:"name"`
	UID             string            `json:"uid"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	DataSHA256      string            `json:"dataSHA256"`
	DataBytes       int               `json:"dataBytes"`
}

type StateSnapshot struct {
	Phase               string            `json:"phase"`
	ObservedAt          string            `json:"observedAt"`
	NamespaceUID        string            `json:"namespaceUID"`
	JournalNamespaceUID string            `json:"journalNamespaceUID"`
	PolicyUID           string            `json:"policyUID"`
	PolicyGeneration    int64             `json:"policyGeneration"`
	Target              PodSnapshot       `json:"target"`
	Peer                PodSnapshot       `json:"peer"`
	Service             ServiceSnapshot   `json:"service"`
	ReadyMembers        []string          `json:"readyMembers"`
	Journal             []JournalSnapshot `json:"journal"`
}

type Receipt struct {
	Schema                  string             `json:"schema"`
	SourceRevision          string             `json:"sourceRevision"`
	Action                  Action             `json:"action"`
	Fixture                 Fixture            `json:"fixture"`
	StartedAt               string             `json:"startedAt"`
	FinishedAt              string             `json:"finishedAt"`
	Status                  string             `json:"status"`
	Baseline                *StateSnapshot     `json:"baseline,omitempty"`
	Forward                 *StateSnapshot     `json:"forward,omitempty"`
	Restored                *StateSnapshot     `json:"restored,omitempty"`
	ForwardResult           *actuator.Result   `json:"forwardResult,omitempty"`
	ReconciliationAttempted bool               `json:"reconciliationAttempted"`
	ReconciliationResult    *actuator.Result   `json:"reconciliationResult,omitempty"`
	ReconciliationError     string             `json:"reconciliationError,omitempty"`
	RollbackAttempted       bool               `json:"rollbackAttempted"`
	RollbackError           string             `json:"rollbackError,omitempty"`
	HTTP                    []HTTPObservation  `json:"http"`
	Writes                  []WriteObservation `json:"writes"`
	WriteJournalSchema      string             `json:"writeJournalSchema,omitempty"`
	WriteJournalSHA256      string             `json:"writeJournalSHA256,omitempty"`
	WriteJournalBytes       int64              `json:"writeJournalBytes,omitempty"`
	AvailabilityInterrupted bool               `json:"availabilityInterrupted"`
	Errors                  []string           `json:"errors,omitempty"`
}

type Adapter struct {
	client  client.Client
	reader  client.Reader
	http    *http.Client
	now     func() time.Time
	journal WriteJournal
}

// WriteJournal durably records every admitted or refused mutation attempt.
// Implementations must append and sync before returning successfully.
type WriteJournal interface {
	Append(WriteObservation) error
}

func New(c client.Client, reader client.Reader, httpClient *http.Client) (*Adapter, error) {
	if c == nil || reader == nil {
		return nil, errors.New("route catalogue requires an authoritative reader and writer")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("HTTP redirect refused") }
	return &Adapter{client: c, reader: reader, http: &copyClient, now: time.Now}, nil
}

func (a *Adapter) SetWriteJournal(journal WriteJournal) error {
	if journal == nil {
		return errors.New("route catalogue write journal is nil")
	}
	a.journal = journal
	return nil
}

func (c RunConfig) validate() error {
	if c.Schema != ConfigSchema {
		return fmt.Errorf("route catalogue config schema must be %q", ConfigSchema)
	}
	if _, err := c.Action.modelAction(); err != nil {
		return err
	}
	if len(c.SourceRevision) != 40 {
		return errors.New("route catalogue sourceRevision must be a 40-character Git SHA")
	}
	if _, err := hex.DecodeString(c.SourceRevision); err != nil {
		return errors.New("route catalogue sourceRevision must be lowercase hexadecimal")
	}
	f := c.Fixture
	values := []string{f.Nonce, f.Tenant, f.Namespace, f.NamespaceUID, f.JournalNamespace, f.JournalNamespaceUID, f.PolicyName, f.PolicyUID, f.TargetName, f.TargetUID, f.PeerName, f.PeerUID, f.ServiceName, f.ServiceUID, f.OperationID}
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 253 {
			return errors.New("route catalogue fixture contains an empty, padded, or oversized identity")
		}
	}
	if f.Namespace == f.JournalNamespace || f.TargetName == f.PeerName || f.TargetUID == f.PeerUID || f.PolicyGeneration < 1 {
		return errors.New("route catalogue fixture identities are not distinct or complete")
	}
	if len(f.OperationID) != sha256.Size*2 {
		return errors.New("route catalogue operationID must be a lowercase SHA-256 value")
	}
	if _, err := hex.DecodeString(f.OperationID); err != nil {
		return errors.New("route catalogue operationID must be lowercase hexadecimal")
	}
	o := c.Observation
	if o.SampleIntervalMillis < 10 || o.SampleIntervalMillis > 1000 || o.RequestTimeoutMillis < 10 || o.RequestTimeoutMillis > 2000 || o.MinSamplesPerEndpointPhase < 1 || o.MinSamplesPerEndpointPhase > 20 {
		return errors.New("route catalogue observation bounds are invalid")
	}
	for _, raw := range []string{o.TargetURL, o.PeerURL, o.ServiceURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.Host == "" || u.Path != "/identity" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("route catalogue observations require exact HTTP /identity URLs")
		}
	}
	if o.TargetURL == o.PeerURL || o.TargetURL == o.ServiceURL || o.PeerURL == o.ServiceURL {
		return errors.New("route catalogue observation endpoints must be distinct")
	}
	return nil
}

func (a *Adapter) Run(ctx context.Context, cfg RunConfig) (receipt Receipt, runErr error) {
	receipt = Receipt{Schema: ReceiptSchema, SourceRevision: cfg.SourceRevision, Action: cfg.Action, Fixture: cfg.Fixture, StartedAt: a.now().UTC().Format(time.RFC3339Nano), Status: "INCOMPLETE"}
	defer func() {
		receipt.FinishedAt = a.now().UTC().Format(time.RFC3339Nano)
		if runErr != nil {
			receipt.Errors = append(receipt.Errors, runErr.Error())
		}
	}()
	if err := cfg.validate(); err != nil {
		return receipt, err
	}
	action, _ := cfg.Action.modelAction()
	bounded := newBoundedClient(a.client, a.reader, cfg.Fixture, a.now, a.journal)
	native := actuator.NewNativeActuator(bounded)
	native.SetBoundaryReader(bounded.reader)
	native.JournalNamespace = cfg.Fixture.JournalNamespace
	native.RouteObservationTimeout = 15 * time.Second
	native.RouteObservationInterval = 100 * time.Millisecond
	native.StrictTenantNamespace = true

	baseline, policy, target, err := a.readState(ctx, cfg, "baseline")
	if err != nil {
		return receipt, err
	}
	if len(baseline.Journal) != 0 {
		return receipt, errors.New("route catalogue protected journal is not empty at baseline")
	}
	receipt.Baseline = &baseline
	if err := native.EnsurePolicy(ctx, actuator.TenantTarget{Tenant: cfg.Fixture.Tenant, Namespace: cfg.Fixture.Namespace, PolicyName: cfg.Fixture.PolicyName, PolicyUID: cfg.Fixture.PolicyUID, Generation: cfg.Fixture.PolicyGeneration, Selector: policy.Spec.Selector.DeepCopy(), EnabledActions: map[model.Action]bool{action: true}, PolicyOwnerCount: 1}); err != nil {
		return receipt, fmt.Errorf("route catalogue policy binding: %w", err)
	}
	if ok, why := native.SupportsAction(ctx, action, actuator.Target{Namespace: target.Namespace, Pod: target.Name, UID: string(target.UID), Labels: copyMap(target.Labels), NodeName: target.Spec.NodeName, PolicyName: policy.Name, PolicyUID: string(policy.UID), ServiceAccount: target.Spec.ServiceAccountName}); !ok {
		return receipt, fmt.Errorf("route catalogue production action unsupported: %s", why)
	}

	sampler := newHTTPSampler(a.http, cfg, a.now)
	sampler.start(ctx)
	defer func() {
		sampler.stop()
		receipt.HTTP = sampler.snapshot()
		for _, observation := range receipt.HTTP {
			if observation.Endpoint == "service" && observation.Error != "" && !observation.TerminalCancellation {
				receipt.AvailabilityInterrupted = true
			}
		}
		receipt.Writes = bounded.snapshot()
	}()
	if err := sampler.waitPhase(ctx, "baseline", cfg.Observation.MinSamplesPerEndpointPhase); err != nil {
		return receipt, err
	}
	markers, err := bindHTTPIdentities(sampler.snapshot(), "baseline", cfg.Fixture)
	if err != nil {
		return receipt, err
	}

	req := actuator.Request{TargetUID: cfg.Fixture.TargetUID, TargetNamespaceUID: cfg.Fixture.NamespaceUID, OperationID: cfg.Fixture.OperationID, PolicyName: cfg.Fixture.PolicyName, PolicyUID: cfg.Fixture.PolicyUID, PolicyGeneration: cfg.Fixture.PolicyGeneration, Tenant: cfg.Fixture.Tenant, Namespace: cfg.Fixture.Namespace, Pod: cfg.Fixture.TargetName, Action: action, Reason: "benign catalogue selector cutover", Score: -1}
	sampler.setPhase("forward-transition")
	result, actErr := native.Actuate(ctx, req)
	receipt.ForwardResult = &result
	if actErr != nil && result.RollbackRef == "" && !actuator.IsNoEffectRefusal(actErr) {
		receipt.ReconciliationAttempted = true
		reconcileCtx, cancel := freshCleanupContext(ctx)
		reconciled, reconcileErr := native.Actuate(reconcileCtx, req)
		cancel()
		receipt.ReconciliationResult = &reconciled
		if reconcileErr != nil {
			receipt.ReconciliationError = reconcileErr.Error()
		}
		if reconciled.RollbackRef != "" {
			result.RollbackRef = reconciled.RollbackRef
		}
	}
	if result.RollbackRef != "" {
		receipt.RollbackAttempted = true
		defer func() {
			if receipt.Restored != nil {
				return
			}
			sampler.setPhase("rollback-transition")
			rollbackCtx, cancel := freshCleanupContext(ctx)
			defer cancel()
			rbErr := native.Rollback(rollbackCtx, req, result.RollbackRef)
			if rbErr != nil {
				if receipt.RollbackError == "" {
					receipt.RollbackError = rbErr.Error()
				}
				probe, _, _, probeErr := a.readState(rollbackCtx, cfg, "restored")
				if probeErr != nil {
					runErr = errors.Join(runErr, fmt.Errorf("route catalogue deferred rollback: %w", rbErr), fmt.Errorf("route catalogue post-rollback authority: %w", probeErr))
					return
				}
				if restoreErr := validateRestored(baseline, probe); restoreErr == nil && len(probe.Journal) == 0 {
					receipt.Restored = &probe
					runErr = errors.Join(runErr, fmt.Errorf("route catalogue deferred rollback: %w", rbErr))
					return
				}
				if len(probe.Journal) == 0 {
					runErr = errors.Join(runErr, fmt.Errorf("route catalogue deferred rollback: %w", rbErr), errors.New("route catalogue state is unrestored without an exact protected receipt; reconciliation refused"))
					return
				}
				// A canceled explicit rollback may have durably moved the protected
				// receipt to its restoring phase before its caller lost the result.
				// Rollback intentionally refuses that superseded phase. Resume it only
				// through the production Actuate reconciliation path, with the same
				// operation authority and a detached bounded context.
				receipt.ReconciliationAttempted = true
				reconciled, reconcileErr := native.Actuate(rollbackCtx, req)
				receipt.ReconciliationResult = &reconciled
				if reconcileErr != nil {
					receipt.ReconciliationError = reconcileErr.Error()
					runErr = errors.Join(runErr, fmt.Errorf("route catalogue deferred rollback: %w", rbErr), fmt.Errorf("route catalogue deferred reconciliation: %w", reconcileErr))
					return
				}
				runErr = errors.Join(runErr, fmt.Errorf("route catalogue deferred rollback: %w", rbErr))
			}
			restored, _, _, err := a.readState(rollbackCtx, cfg, "restored")
			if err != nil {
				runErr = errors.Join(runErr, err)
				return
			}
			if err := validateRestored(baseline, restored); err != nil || len(restored.Journal) != 0 {
				runErr = errors.Join(runErr, err, errors.New("route catalogue detached cleanup did not restore exact state and empty journal"))
				return
			}
			receipt.Restored = &restored
		}()
	}
	if actErr != nil {
		return receipt, fmt.Errorf("route catalogue production actuation: %w", actErr)
	}
	if !result.Emitted || result.Actuator != "native" || result.Handler != string(action) || result.MutationKind != "reversible" || result.RollbackRef == "" {
		return receipt, fmt.Errorf("route catalogue forward result is not a confirmed reversible native effect: %+v", result)
	}

	forward, _, _, err := a.readState(ctx, cfg, "forward")
	if err != nil {
		return receipt, err
	}
	if err := validateForward(baseline, forward, cfg.Action); err != nil {
		return receipt, err
	}
	if len(forward.Journal) != 1 || forward.Journal[0].Labels[operationJournalLabel] != "v1" {
		return receipt, errors.New("route catalogue forward state lacks one exact protected operation receipt")
	}
	receipt.Forward = &forward
	sampler.setPhase("forward-stable")
	if err := sampler.waitPhase(ctx, "forward-stable", cfg.Observation.MinSamplesPerEndpointPhase); err != nil {
		return receipt, err
	}
	if err := validateStableIdentities(sampler.snapshot(), "forward-stable", cfg.Fixture, markers, map[string]bool{cfg.Fixture.TargetUID: true}); err != nil {
		return receipt, err
	}

	sampler.setPhase("rollback-transition")
	receipt.RollbackAttempted = true
	if err := native.Rollback(ctx, req, result.RollbackRef); err != nil {
		receipt.RollbackError = err.Error()
		return receipt, fmt.Errorf("route catalogue production rollback: %w", err)
	}
	restored, _, _, err := a.readState(ctx, cfg, "restored")
	if err != nil {
		return receipt, err
	}
	if err := validateRestored(baseline, restored); err != nil {
		return receipt, err
	}
	if len(restored.Journal) != 0 {
		return receipt, errors.New("route catalogue rollback retained protected journal objects")
	}
	receipt.Restored = &restored
	sampler.setPhase("rollback-stable")
	if err := sampler.waitPhase(ctx, "rollback-stable", cfg.Observation.MinSamplesPerEndpointPhase); err != nil {
		return receipt, err
	}
	if err := validateStableIdentities(sampler.snapshot(), "rollback-stable", cfg.Fixture, markers, map[string]bool{cfg.Fixture.TargetUID: true, cfg.Fixture.PeerUID: true}); err != nil {
		return receipt, err
	}
	receipt.Status = "COMPLETE"
	return receipt, nil
}

func freshCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 20*time.Second)
}

func (a *Adapter) readState(ctx context.Context, cfg RunConfig, phase string) (StateSnapshot, *v1alpha1.PhorvexPolicy, *corev1.Pod, error) {
	f := cfg.Fixture
	s := StateSnapshot{Phase: phase, ObservedAt: a.now().UTC().Format(time.RFC3339Nano)}
	ns, journalNS := &corev1.Namespace{}, &corev1.Namespace{}
	if err := a.reader.Get(ctx, client.ObjectKey{Name: f.Namespace}, ns); err != nil || string(ns.UID) != f.NamespaceUID || ns.DeletionTimestamp != nil {
		return s, nil, nil, fmt.Errorf("route catalogue tenant Namespace authority differs: %w", err)
	}
	if err := a.reader.Get(ctx, client.ObjectKey{Name: f.JournalNamespace}, journalNS); err != nil || string(journalNS.UID) != f.JournalNamespaceUID || journalNS.DeletionTimestamp != nil {
		return s, nil, nil, fmt.Errorf("route catalogue journal Namespace authority differs: %w", err)
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err := a.reader.Get(ctx, client.ObjectKey{Namespace: f.Namespace, Name: f.PolicyName}, policy); err != nil || string(policy.UID) != f.PolicyUID || policy.Generation != f.PolicyGeneration || policy.DeletionTimestamp != nil || policy.Spec.IsDryRun() {
		return s, nil, nil, fmt.Errorf("route catalogue Policy authority differs: %w", err)
	}
	action, _ := cfg.Action.modelAction()
	if !policy.Spec.ActionEnabled(v1alpha1.ActionType(action)) || policy.Spec.EffectiveMinAvailableReplicas() != 1 {
		return s, nil, nil, errors.New("route catalogue Policy action or minAvailable contract differs")
	}
	effectiveTenant := policy.Spec.Tenant
	if effectiveTenant == "" {
		effectiveTenant = policy.Namespace
	}
	if effectiveTenant != f.Tenant {
		return s, nil, nil, errors.New("route catalogue Policy tenant differs")
	}
	target, peer := &corev1.Pod{}, &corev1.Pod{}
	if err := a.reader.Get(ctx, client.ObjectKey{Namespace: f.Namespace, Name: f.TargetName}, target); err != nil || string(target.UID) != f.TargetUID || !podReady(target) || target.DeletionTimestamp != nil {
		return s, nil, nil, fmt.Errorf("route catalogue target authority differs: %w", err)
	}
	if err := a.reader.Get(ctx, client.ObjectKey{Namespace: f.Namespace, Name: f.PeerName}, peer); err != nil || string(peer.UID) != f.PeerUID || !podReady(peer) || peer.DeletionTimestamp != nil {
		return s, nil, nil, fmt.Errorf("route catalogue peer authority differs: %w", err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(target.Labels)) || !selector.Matches(labels.Set(peer.Labels)) {
		return s, nil, nil, fmt.Errorf("route catalogue Policy selector does not retain target and peer: %w", err)
	}
	if target.Annotations[routeServiceAnnotation] != f.ServiceName || peer.Annotations[routeServiceAnnotation] != f.ServiceName {
		return s, nil, nil, errors.New("route catalogue declared Service differs")
	}
	service := &corev1.Service{}
	if err := a.reader.Get(ctx, client.ObjectKey{Namespace: f.Namespace, Name: f.ServiceName}, service); err != nil || string(service.UID) != f.ServiceUID || service.DeletionTimestamp != nil || len(service.Spec.Selector) == 0 {
		return s, nil, nil, fmt.Errorf("route catalogue Service authority differs: %w", err)
	}
	if !selectorMatches(service.Spec.Selector, target.Labels) {
		return s, nil, nil, errors.New("route catalogue Service does not select target")
	}
	services := &corev1.ServiceList{}
	if err := a.reader.List(ctx, services, client.InNamespace(f.Namespace)); err != nil {
		return s, nil, nil, fmt.Errorf("route catalogue Service inventory: %w", err)
	}
	selecting := 0
	for i := range services.Items {
		if services.Items[i].DeletionTimestamp == nil && selectorMatches(services.Items[i].Spec.Selector, target.Labels) {
			selecting++
		}
	}
	if selecting != 1 {
		return s, nil, nil, fmt.Errorf("route catalogue target is selected by %d Services", selecting)
	}
	members, err := endpointMembers(ctx, a.reader, service)
	if err != nil {
		return s, nil, nil, err
	}
	journal, err := readJournal(ctx, a.reader, f)
	if err != nil {
		return s, nil, nil, err
	}
	s.NamespaceUID, s.JournalNamespaceUID, s.PolicyUID, s.PolicyGeneration = string(ns.UID), string(journalNS.UID), string(policy.UID), policy.Generation
	s.Target, s.Peer, s.Service, s.ReadyMembers, s.Journal = podSnapshot(target), podSnapshot(peer), serviceSnapshot(service), members, journal
	return s, policy, target, nil
}

func validateForward(before, after StateSnapshot, action Action) error {
	if !stablePodIdentity(before.Target, after.Target) || !stablePodIdentity(before.Peer, after.Peer) || !reflect.DeepEqual(before.Peer.Labels, after.Peer.Labels) || !reflect.DeepEqual(before.Peer.Annotations, after.Peer.Annotations) {
		return errors.New("route catalogue forward state changed target/peer locator, runtime, or peer metadata")
	}
	if before.Service.UID != after.Service.UID || before.Service.ClusterIP != after.Service.ClusterIP || !reflect.DeepEqual(before.Service.ClusterIPs, after.Service.ClusterIPs) || !reflect.DeepEqual(before.Service.Ports, after.Service.Ports) {
		return errors.New("route catalogue forward state changed the Service locator")
	}
	if after.Target.Labels[routeKey] == "" || after.Target.Labels[routeKey] == before.Target.Labels[routeKey] || after.Service.Selector[routeKey] != after.Target.Labels[routeKey] || after.Target.Labels[routeBridgeKey] != "" || after.Service.Selector[routeBridgeKey] != "" {
		return errors.New("route catalogue forward selector rekey is incomplete")
	}
	if after.Target.Annotations[action.epochKey()] == "" || after.Target.Annotations[action.epochKey()] == before.Target.Annotations[action.epochKey()] || after.Target.Annotations[action.otherEpochKey()] != before.Target.Annotations[action.otherEpochKey()] {
		return errors.New("route catalogue action epoch ownership differs")
	}
	if !equalWithout(before.Target.Labels, after.Target.Labels, routeKey, routeBridgeKey) || !equalWithout(before.Target.Annotations, after.Target.Annotations, action.epochKey()) || !equalWithout(before.Service.Selector, after.Service.Selector, routeKey, routeBridgeKey) {
		return errors.New("route catalogue forward operation changed unrelated metadata")
	}
	if !reflect.DeepEqual(after.ReadyMembers, []string{after.Target.UID}) {
		return fmt.Errorf("route catalogue forward members=%v, want exact target", after.ReadyMembers)
	}
	return nil
}

func validateRestored(before, after StateSnapshot) error {
	if !stablePodIdentity(before.Target, after.Target) || !stablePodIdentity(before.Peer, after.Peer) || !reflect.DeepEqual(before.Target.Labels, after.Target.Labels) || !reflect.DeepEqual(before.Target.Annotations, after.Target.Annotations) || !reflect.DeepEqual(before.Peer.Labels, after.Peer.Labels) || !reflect.DeepEqual(before.Peer.Annotations, after.Peer.Annotations) {
		return errors.New("route catalogue rollback did not restore exact Pod authority")
	}
	if before.Service.UID != after.Service.UID || before.Service.ClusterIP != after.Service.ClusterIP || !reflect.DeepEqual(before.Service.ClusterIPs, after.Service.ClusterIPs) || !reflect.DeepEqual(before.Service.Ports, after.Service.Ports) || !reflect.DeepEqual(before.Service.Selector, after.Service.Selector) {
		return errors.New("route catalogue rollback did not restore exact Service authority")
	}
	want := []string{before.Peer.UID, before.Target.UID}
	sort.Strings(want)
	if !reflect.DeepEqual(after.ReadyMembers, want) {
		return fmt.Errorf("route catalogue rollback members=%v, want exact %v", after.ReadyMembers, want)
	}
	return nil
}

func stablePodIdentity(a, b PodSnapshot) bool {
	return a.Name == b.Name && a.UID == b.UID && a.PodIP == b.PodIP && reflect.DeepEqual(a.PodIPs, b.PodIPs) && reflect.DeepEqual(a.ContainerIDs, b.ContainerIDs) && reflect.DeepEqual(a.RestartCounts, b.RestartCounts) && a.Ready && b.Ready
}

func equalWithout(a, b map[string]string, keys ...string) bool {
	a, b = copyMap(a), copyMap(b)
	for _, key := range keys {
		delete(a, key)
		delete(b, key)
	}
	return reflect.DeepEqual(a, b)
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func podReady(pod *corev1.Pod) bool {
	if pod == nil || pod.UID == "" || pod.ResourceVersion == "" {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func selectorMatches(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func endpointMembers(ctx context.Context, reader client.Reader, service *corev1.Service) ([]string, error) {
	list := &discoveryv1.EndpointSliceList{}
	if err := reader.List(ctx, list, client.InNamespace(service.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: service.Name}); err != nil {
		return nil, fmt.Errorf("route catalogue EndpointSlice inventory: %w", err)
	}
	owned, members := 0, map[string]bool{}
	for i := range list.Items {
		slice := &list.Items[i]
		owner := false
		for _, ref := range slice.OwnerReferences {
			if ref.APIVersion == "v1" && ref.Kind == "Service" && ref.Name == service.Name && ref.UID == service.UID {
				owner = true
			}
		}
		if !owner {
			continue
		}
		owned++
		if slice.UID == "" || slice.ResourceVersion == "" || slice.DeletionTimestamp != nil {
			return nil, errors.New("route catalogue EndpointSlice identity is incomplete")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready || endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				continue
			}
			ref := endpoint.TargetRef
			if ref == nil || ref.Kind != "Pod" || ref.Namespace != service.Namespace || ref.Name == "" || ref.UID == "" || members[string(ref.UID)] {
				return nil, errors.New("route catalogue active EndpointSlice target authority is incomplete or duplicated")
			}
			members[string(ref.UID)] = true
		}
	}
	if owned == 0 {
		return nil, errors.New("route catalogue found no EndpointSlice owned by the exact Service")
	}
	out := make([]string, 0, len(members))
	for uid := range members {
		out = append(out, uid)
	}
	sort.Strings(out)
	return out, nil
}

func podSnapshot(p *corev1.Pod) PodSnapshot {
	out := PodSnapshot{Name: p.Name, UID: string(p.UID), ResourceVersion: p.ResourceVersion, PodIP: p.Status.PodIP, Labels: copyMap(p.Labels), Annotations: copyMap(p.Annotations), ContainerIDs: map[string]string{}, RestartCounts: map[string]int32{}, Ready: podReady(p)}
	for _, ip := range p.Status.PodIPs {
		out.PodIPs = append(out.PodIPs, ip.IP)
	}
	for _, status := range p.Status.ContainerStatuses {
		out.ContainerIDs[status.Name] = status.ContainerID
		out.RestartCounts[status.Name] = status.RestartCount
	}
	return out
}

func serviceSnapshot(s *corev1.Service) ServiceSnapshot {
	return ServiceSnapshot{Name: s.Name, UID: string(s.UID), ResourceVersion: s.ResourceVersion, ClusterIP: s.Spec.ClusterIP, ClusterIPs: append([]string(nil), s.Spec.ClusterIPs...), Ports: append([]corev1.ServicePort(nil), s.Spec.Ports...), Selector: copyMap(s.Spec.Selector)}
}

func readJournal(ctx context.Context, reader client.Reader, fixture Fixture) ([]JournalSnapshot, error) {
	objects := map[types.UID]corev1.ConfigMap{}
	for key, value := range map[string]string{operationJournalLabel: "v1", routeGuardLabel: "v1"} {
		list := &corev1.ConfigMapList{}
		if err := reader.List(ctx, list, client.InNamespace(fixture.JournalNamespace), client.MatchingLabels{key: value}); err != nil {
			return nil, fmt.Errorf("route catalogue journal inventory: %w", err)
		}
		for i := range list.Items {
			objects[list.Items[i].UID] = list.Items[i]
		}
	}
	if len(objects) > MaxJournalObjects {
		return nil, errors.New("route catalogue journal object bound exceeded")
	}
	out := make([]JournalSnapshot, 0, len(objects))
	for _, item := range objects {
		cm := item.DeepCopy()
		if cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || !validFixtureJournalObject(cm.Name, cm.Labels, fixture) {
			serviceReceipt, targetGuard := fixtureJournalNames(fixture)
			return nil, fmt.Errorf("route catalogue journal contains foreign object %s labels=%v (allowed %s or %s)", cm.Name, cm.Labels, serviceReceipt, targetGuard)
		}
		raw, err := json.Marshal(cm.Data)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		out = append(out, JournalSnapshot{Name: cm.Name, UID: string(cm.UID), ResourceVersion: cm.ResourceVersion, Labels: copyMap(cm.Labels), DataSHA256: hex.EncodeToString(sum[:]), DataBytes: len(raw)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func bindHTTPIdentities(observations []HTTPObservation, phase string, fixture Fixture) (map[string]string, error) {
	markers := map[string]string{}
	for _, observation := range observations {
		if observation.Phase != phase || observation.Error != "" || observation.Identity == nil || observation.Endpoint == "service" {
			continue
		}
		identity := observation.Identity
		if identity.Schema != IdentitySchema || identity.Nonce != fixture.Nonce || identity.ProcessMarker == "" {
			return nil, fmt.Errorf("route catalogue %s HTTP identity is malformed", observation.Endpoint)
		}
		wantUID := map[string]string{"target": fixture.TargetUID, "peer": fixture.PeerUID}[observation.Endpoint]
		if wantUID == "" || identity.Role != observation.Endpoint || identity.PodUID != wantUID {
			return nil, fmt.Errorf("route catalogue direct %s identity differs", observation.Endpoint)
		}
		if current := markers[identity.PodUID]; current != "" && current != identity.ProcessMarker {
			return nil, fmt.Errorf("route catalogue direct %s process marker changed within baseline", observation.Endpoint)
		}
		markers[identity.PodUID] = identity.ProcessMarker
	}
	if markers[fixture.TargetUID] == "" || markers[fixture.PeerUID] == "" {
		return nil, errors.New("route catalogue baseline lacks both direct process identities")
	}
	if markers[fixture.TargetUID] == markers[fixture.PeerUID] {
		return nil, errors.New("route catalogue target and peer process markers are not distinct")
	}
	if err := validateStableIdentities(observations, phase, fixture, markers, map[string]bool{fixture.TargetUID: true, fixture.PeerUID: true}); err != nil {
		return nil, err
	}
	return markers, nil
}

func validateStableIdentities(observations []HTTPObservation, phase string, fixture Fixture, markers map[string]string, allowedServiceUIDs map[string]bool) error {
	counts := map[string]int{}
	for _, observation := range observations {
		if observation.Phase != phase || observation.Error != "" || observation.Identity == nil {
			continue
		}
		identity := observation.Identity
		if identity.Schema != IdentitySchema || identity.Nonce != fixture.Nonce || identity.ProcessMarker == "" || markers[identity.PodUID] != identity.ProcessMarker {
			return fmt.Errorf("route catalogue %s HTTP identity is malformed", observation.Endpoint)
		}
		switch observation.Endpoint {
		case "target":
			if identity.Role != "target" || identity.PodUID != fixture.TargetUID {
				return errors.New("route catalogue direct target identity differs")
			}
		case "peer":
			if identity.Role != "peer" || identity.PodUID != fixture.PeerUID {
				return errors.New("route catalogue direct peer identity differs")
			}
		case "service":
			if allowedServiceUIDs[identity.PodUID] && (identity.Role == "target" && identity.PodUID == fixture.TargetUID || identity.Role == "peer" && identity.PodUID == fixture.PeerUID) {
				break
			}
			return errors.New("route catalogue Service returned a foreign application identity")
		default:
			return errors.New("route catalogue observation endpoint is unknown")
		}
		counts[observation.Endpoint]++
	}
	for _, endpoint := range []string{"target", "peer", "service"} {
		if counts[endpoint] == 0 {
			return fmt.Errorf("route catalogue phase %s lacks successful %s identity observation", phase, endpoint)
		}
	}
	return nil
}

type boundedClient struct {
	client.Client
	reader  *boundedReader
	fixture Fixture
	now     func() time.Time
	mu      sync.Mutex
	writes  []WriteObservation
	journal WriteJournal
}

func newBoundedClient(c client.Client, reader client.Reader, fixture Fixture, now func() time.Time, journal ...WriteJournal) *boundedClient {
	var sink WriteJournal
	if len(journal) != 0 {
		sink = journal[0]
	}
	return &boundedClient{Client: c, reader: &boundedReader{Reader: reader, fixture: fixture}, fixture: fixture, now: now, journal: sink}
}

func (c *boundedClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.reader.Get(ctx, key, obj, opts...)
}

func (c *boundedClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.reader.List(ctx, list, opts...)
}

type boundedReader struct {
	client.Reader
	fixture Fixture
}

func (r *boundedReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	f := r.fixture
	allowed := false
	switch obj.(type) {
	case *corev1.Namespace:
		allowed = key.Namespace == "" && (key.Name == f.Namespace || key.Name == f.JournalNamespace)
	case *v1alpha1.PhorvexPolicy:
		allowed = key.Namespace == f.Namespace && key.Name == f.PolicyName
	case *corev1.Pod:
		allowed = key.Namespace == f.Namespace && (key.Name == f.TargetName || key.Name == f.PeerName)
	case *corev1.Service:
		allowed = key.Namespace == f.Namespace && key.Name == f.ServiceName
	case *corev1.ConfigMap:
		allowed = key.Namespace == f.JournalNamespace && validFixtureJournalReadName(key.Name, f)
	case *discoveryv1.EndpointSlice:
		allowed = key.Namespace == f.Namespace && key.Name != ""
	}
	if !allowed {
		return fmt.Errorf("route catalogue refused foreign read GET %T %s/%s", obj, key.Namespace, key.Name)
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func fixtureJournalNames(f Fixture) (serviceReceipt, targetGuard string) {
	serviceSum := sha256.Sum256([]byte("route-service/" + f.ServiceUID))
	targetSum := sha256.Sum256([]byte("route-target/" + f.TargetUID))
	return fmt.Sprintf("phorvex-route-service-%x", serviceSum[:20]), fmt.Sprintf("phorvex-route-target-%x", targetSum[:20])
}

func validFixtureJournalReadName(name string, fixture Fixture) bool {
	serviceReceipt, targetGuard := fixtureJournalNames(fixture)
	return name == serviceReceipt || name == targetGuard
}

func (r *boundedReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	opts := &client.ListOptions{}
	opts.ApplyOptions(options)
	f := r.fixture
	allowed := false
	switch list.(type) {
	case *corev1.PodList, *corev1.ServiceList, *discoveryv1.EndpointSliceList:
		allowed = opts.Namespace == f.Namespace
	case *corev1.ConfigMapList:
		allowed = opts.Namespace == f.JournalNamespace
	}
	if !allowed {
		return fmt.Errorf("route catalogue refused foreign inventory LIST %T namespace=%q", list, opts.Namespace)
	}
	if err := r.Reader.List(ctx, list, options...); err != nil {
		return err
	}
	if pods, ok := list.(*corev1.PodList); ok {
		for i := range pods.Items {
			if pods.Items[i].Name != f.TargetName && pods.Items[i].Name != f.PeerName {
				return fmt.Errorf("route catalogue Pod inventory returned foreign object %s/%s", pods.Items[i].Namespace, pods.Items[i].Name)
			}
		}
	}
	return nil
}

func (c *boundedClient) authorize(method string, obj client.Object) error {
	switch typed := obj.(type) {
	case *corev1.Pod:
		if method == "PATCH" && typed.Namespace == c.fixture.Namespace && typed.Name == c.fixture.TargetName && string(typed.UID) == c.fixture.TargetUID {
			return nil
		}
	case *corev1.Service:
		if method == "UPDATE" && typed.Namespace == c.fixture.Namespace && typed.Name == c.fixture.ServiceName && string(typed.UID) == c.fixture.ServiceUID {
			return nil
		}
	case *corev1.ConfigMap:
		if typed.Namespace == c.fixture.JournalNamespace && validFixtureJournalObject(typed.Name, typed.Labels, c.fixture) {
			switch method {
			case "CREATE", "UPDATE", "DELETE":
				return nil
			}
		}
	}
	return fmt.Errorf("route catalogue refused foreign mutation %s %T %s/%s", method, obj, obj.GetNamespace(), obj.GetName())
}

func validFixtureJournalObject(name string, objectLabels map[string]string, fixture Fixture) bool {
	serviceReceipt, targetGuard := fixtureJournalNames(fixture)
	switch name {
	case serviceReceipt:
		return objectLabels[operationJournalLabel] == "v1" && objectLabels[routeGuardLabel] == ""
	case targetGuard:
		return objectLabels[routeGuardLabel] == "v1" && objectLabels[operationJournalLabel] == ""
	default:
		return false
	}
}

func (c *boundedClient) record(method string, obj client.Object, started time.Time, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	row := WriteObservation{Sequence: len(c.writes) + 1, Method: method, Kind: reflect.TypeOf(obj).String(), Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: string(obj.GetUID()), StartedAt: started.UTC().Format(time.RFC3339Nano), FinishedAt: c.now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		row.Error = err.Error()
	}
	c.writes = append(c.writes, row)
	if c.journal != nil {
		return c.journal.Append(row)
	}
	return nil
}

func (c *boundedClient) before(method string, obj client.Object) (time.Time, error) {
	started := c.now()
	c.mu.Lock()
	n := len(c.writes)
	c.mu.Unlock()
	if n >= MaxWrites {
		err := errors.New("route catalogue mutation bound exceeded")
		journalErr := c.record(method, obj, started, err)
		return started, errors.Join(err, journalErr)
	}
	if err := c.authorize(method, obj); err != nil {
		journalErr := c.record(method, obj, started, err)
		return started, errors.Join(err, journalErr)
	}
	return started, nil
}

func (c *boundedClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	started, err := c.before("CREATE", obj)
	if err != nil {
		return err
	}
	err = c.Client.Create(ctx, obj, opts...)
	return errors.Join(err, c.record("CREATE", obj, started, err))
}

func (c *boundedClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	started, err := c.before("UPDATE", obj)
	if err != nil {
		return err
	}
	err = c.Client.Update(ctx, obj, opts...)
	return errors.Join(err, c.record("UPDATE", obj, started, err))
}

func (c *boundedClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	started, err := c.before("PATCH", obj)
	if err != nil {
		return err
	}
	err = c.Client.Patch(ctx, obj, patch, opts...)
	return errors.Join(err, c.record("PATCH", obj, started, err))
}

func (c *boundedClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	started, err := c.before("DELETE", obj)
	if err != nil {
		return err
	}
	err = c.Client.Delete(ctx, obj, opts...)
	return errors.Join(err, c.record("DELETE", obj, started, err))
}

func (c *boundedClient) DeleteAllOf(context.Context, client.Object, ...client.DeleteAllOfOption) error {
	return errors.New("route catalogue refuses DeleteAllOf")
}

func (c *boundedClient) SubResource(string) client.SubResourceClient {
	return refusingSubresource{}
}

func (c *boundedClient) snapshot() []WriteObservation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]WriteObservation(nil), c.writes...)
}

type refusingSubresource struct{}

func (refusingSubresource) Get(context.Context, client.Object, client.Object, ...client.SubResourceGetOption) error {
	return errors.New("route catalogue refuses subresource get")
}
func (refusingSubresource) Create(context.Context, client.Object, client.Object, ...client.SubResourceCreateOption) error {
	return errors.New("route catalogue refuses subresource create")
}
func (refusingSubresource) Update(context.Context, client.Object, ...client.SubResourceUpdateOption) error {
	return errors.New("route catalogue refuses subresource update")
}
func (refusingSubresource) Patch(context.Context, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
	return errors.New("route catalogue refuses subresource patch")
}

type httpSampler struct {
	client   *http.Client
	cfg      RunConfig
	now      func() time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	phase    atomic.Value
	sequence atomic.Int64
	stopping atomic.Bool
	mu       sync.Mutex
	rows     []HTTPObservation
}

func newHTTPSampler(c *http.Client, cfg RunConfig, now func() time.Time) *httpSampler {
	return &httpSampler{client: c, cfg: cfg, now: now}
}

func (s *httpSampler) start(parent context.Context) {
	s.ctx, s.cancel = context.WithCancel(parent)
	s.phase.Store("baseline")
	for name, endpoint := range map[string]string{"target": s.cfg.Observation.TargetURL, "peer": s.cfg.Observation.PeerURL, "service": s.cfg.Observation.ServiceURL} {
		s.wg.Add(1)
		go s.loop(name, endpoint)
	}
}

func (s *httpSampler) stop() {
	if s.cancel != nil {
		s.stopping.Store(true)
		s.cancel()
	}
	s.wg.Wait()
}

func (s *httpSampler) setPhase(phase string) { s.phase.Store(phase) }

func (s *httpSampler) loop(name, endpoint string) {
	defer s.wg.Done()
	interval := time.Duration(s.cfg.Observation.SampleIntervalMillis) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.sample(name, endpoint)
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *httpSampler) sample(name, endpoint string) {
	s.mu.Lock()
	if len(s.rows) >= MaxHTTPSamples {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	phase, _ := s.phase.Load().(string)
	started := s.now()
	row := HTTPObservation{Sequence: s.sequence.Add(1), Phase: phase, Endpoint: name, StartedAt: started.UTC().Format(time.RFC3339Nano)}
	requestCtx, cancel := context.WithTimeout(s.ctx, time.Duration(s.cfg.Observation.RequestTimeoutMillis)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err == nil {
		var response *http.Response
		response, err = s.client.Do(req)
		if response != nil {
			row.Status = response.StatusCode
			body, readErr := io.ReadAll(io.LimitReader(response.Body, MaxHTTPBodyBytes+1))
			closeErr := response.Body.Close()
			row.Bytes = len(body)
			if len(body) > MaxHTTPBodyBytes {
				body = body[:MaxHTTPBodyBytes]
				err = errors.Join(err, errors.New("HTTP observation exceeded body bound"))
			}
			row.Body = string(body)
			sum := sha256.Sum256(body)
			row.SHA256 = hex.EncodeToString(sum[:])
			err = errors.Join(err, readErr, closeErr)
			if err == nil && response.StatusCode == http.StatusOK {
				var identity HTTPIdentity
				if decodeErr := strictJSON(body, &identity); decodeErr != nil {
					err = decodeErr
				} else {
					row.Identity = &identity
				}
			} else if err == nil {
				err = fmt.Errorf("HTTP status %d", response.StatusCode)
			}
		}
	}
	row.FinishedAt = s.now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		row.Error = err.Error()
		row.TerminalCancellation = s.stopping.Load() && errors.Is(err, context.Canceled)
	}
	s.mu.Lock()
	if len(s.rows) < MaxHTTPSamples {
		s.rows = append(s.rows, row)
	}
	s.mu.Unlock()
}

func (s *httpSampler) waitPhase(ctx context.Context, phase string, minimum int) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		counts := map[string]int{}
		for _, row := range s.snapshot() {
			if row.Phase == phase && row.Error == "" && row.Identity != nil {
				counts[row.Endpoint]++
			}
		}
		if counts["target"] >= minimum && counts["peer"] >= minimum && counts["service"] >= minimum {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("route catalogue HTTP phase %s incomplete: %w", phase, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *httpSampler) snapshot() []HTTPObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]HTTPObservation(nil), s.rows...)
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON observation has trailing content")
	}
	return nil
}

func AddToScheme(scheme *runtime.Scheme) error {
	if scheme == nil {
		return errors.New("nil scheme")
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		return err
	}
	return v1alpha1.AddToScheme(scheme)
}

var _ client.Client = (*boundedClient)(nil)
var _ client.SubResourceClient = refusingSubresource{}
