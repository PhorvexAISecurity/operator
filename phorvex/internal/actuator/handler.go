/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 */

package actuator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// ActionHandler is the native enactment for ONE model.Action — Phorvex's hands for that
// move. Add an action = add ONE handler file with an init() that calls
// HandlerRegistry.Register; the completeness invariant (completeness.go) then PROVES it
// is covered (fails CI + binary startup if a generatable action has no handler). Name()
// returns the model.Action string the handler enacts.
type ActionHandler interface {
	registry.Named
	// Enact performs the native move. It MUST be idempotent (safe to retry) and MUST
	// not be invoked in dry-run: dispatch refuses ec.DryRun before handler lookup. Handler
	// checks may remain as defense in depth for direct internal calls. Native.Rollback has
	// its own central dry-run refusal before rollback lookup/invocation. Enact returns the
	// objects touched + a rollback ref + the mutation kind for the per-action audit.
	Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error)
}

// Rollbacker is the optional compensating-undo surface a reversible/swap handler
// implements. Forward-only/irreversible handlers do not implement it.
type Rollbacker interface {
	Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error
}

// EnactCtx carries the cluster client + the dry-run guard into a handler, plus the optional
// serving-stack / GPU control-plane clients the AI handlers drive. VLLM/MIG default to the real
// implementations when nil (production); tests inject mocks so the handler logic is exercised
// without GPU hardware (see gpu_stack.go).
type EnactCtx struct {
	Reader           client.Reader // authoritative boundary reader
	Client           client.Client
	JournalNamespace string // protected operator namespace; empty refuses recoverable writes
	DryRun           bool
	// Identity-rotate requires affirmative complete-plan authorization, a fresh global
	// brake and an optional test clock, carried separately so identity's destructive
	// SA get/create/delete path cannot borrow another action's authority.
	IdentityAuthz                     *authz.Checker             // affirmative complete-plan SSAR for SA get/create/delete + Secret get/delete
	IdentityKillSwitch                func(context.Context) bool // fresh global brake; nil refuses identity writes
	IdentityNow                       func() time.Time           // test clock for age/cooldown; nil uses time.Now
	VLLM                              vLLMClient                 // serving-stack control plane; nil => real httpVLLM default
	MIG                               migController              // GPU MIG control plane; nil => real nvidia-smi default
	Guardrail                         guardrailController        // safety/guardrail-tier control plane; nil => real default
	KVXfer                            kvTransferController       // disaggregated KV-transfer control plane; nil => real default
	AdapterSources                    AdapterSources
	MIGProfiles                       *MIGProfiles
	ServingSecurity                   *ServingSecurityConfig
	ServingAttempt                    *servingCredentialSnapshot
	ServingTarget                     *corev1.Pod
	ServingRequest                    Request
	OutputPolicyTransport             http.RoundTripper // test-only fixed-Pod-IP readback transport seam
	VoiceMemoryTransport              http.RoundTripper // private fixed-Pod-IP readback seam
	VoiceRefundTransport              http.RoundTripper // private fixed-Pod-IP readback seam
	VoiceMCPTransport                 http.RoundTripper // private fixed-Pod-IP readback seam
	VoiceMCPApprovedImage             string            // operator-configured reviewed MCP repo@sha256; never event-derived
	VoiceOutputTransport              http.RoundTripper // private fixed-Pod-IP readback seam
	VoiceAdmissionTransport           http.RoundTripper // private fixed-Pod-IP readback seam
	VoiceAdmissionEnabled             bool
	LiteLLMStatusTransport            http.RoundTripper // test-only exact PodIP status-readback seam
	CRMRefundTransport                http.RoundTripper // test-only exact PodIP CRM guard-state readback seam
	LiteLLMStatusToken                string            // test-only; runtime reads the fixed mounted Secret path
	EndpointLeaseApprovedSourceSHA256 string            // reviewed five-file proxy source, never event-derived
	EndpointLeaseApprovedProxyImage   string            // reviewed immutable proxy image, never event-derived
	EndpointLeaseApprovedEngineImage  string            // reviewed immutable loopback engine image
	EndpointLeaseStatusTransport      http.RoundTripper // test-only exact Pod-IP TLS status seam
	EndpointLeaseStatusToken          string            // test-only; production uses serving-security admin binding
	OutputPolicyReadbackTimeout       time.Duration
	OutputPolicyReadbackInterval      time.Duration
	// Request-drain observation bounds default to production constants. Tests that
	// emulate an EndpointSlice controller may shorten them without changing behavior.
	DrainObservationTimeout    time.Duration
	DrainObservationInterval   time.Duration
	AdapterObservationTimeout  time.Duration
	AdapterObservationInterval time.Duration
	RouteObservationTimeout    time.Duration
	RouteObservationInterval   time.Duration
}

// HandlerResult is the native effect record.
type HandlerResult struct {
	ObjectsTouched []string
	RollbackRef    string
	// NoEffect is an explicit closed disposition for a reviewed non-emission.
	// Reconciled results may carry prior-operation references. Empty means
	// unknown and is never inferred from Note or MutationKind.
	NoEffect NoEffectDisposition
	// MutationKind: "reversible" | "irreversible" | "forward-only" | "swap" | "declared" | "partial".
	// A partial kind with Emitted=false records an attempted external mutation whose
	// effect is unknown; it is not a confirmed or credited emission.
	MutationKind        string
	GracefulTermination *model.GracefulTerminationReceipt
	DrainOperation      *model.DrainOperationEvidence
	// ControllerStop is the bounded native absence receipt a controller-stop enact
	// returns (owner scaled to zero + exact children removed + observed no-recreation
	// window). nil for every other handler.
	ControllerStop *model.ControllerStopReceipt
	// Emitted is true only for a confirmed mutation or confirmed partial
	// mutation. It stays false for refusal, definite no-effect, and an attempted
	// external mutation whose result is unknown.
	Emitted bool
	Note    string
}

// HandlerRegistry holds every native ActionHandler, one per model.Action it enacts.
var HandlerRegistry = registry.New[ActionHandler]()

// errDryRunGuard is returned centrally by dispatch before handler lookup/invocation and
// by Native.Rollback before rollback lookup/invocation. Individual handler checks protect
// direct internal calls where retained.
var errDryRunGuard = fmt.Errorf("native actuator: handler invoked with DryRun set — refusing to mutate")

// dispatch routes a Request to its registered handler. A miss is a LOUD error (the
// completeness invariant makes a miss impossible for any generatable action, but a
// policy that enabled ActionDisable, or a typo, surfaces here rather than silently
// no-acting).
func dispatch(ctx context.Context, ec EnactCtx, req Request) (Result, error) {
	if ec.DryRun {
		return Result{}, errDryRunGuard
	}
	if req.Action != model.ActionSensitiveOutputPolicyActivate && ec.Reader != nil && ec.JournalNamespace != "" && req.TargetUID != "" {
		_, receipt, fenceErr := outputPolicyJournalGet(ctx, ec, req.TargetUID)
		if fenceErr == nil && receipt.PolicyNamespace == req.Namespace && (receipt.Phase == "prepared" || receipt.Phase == "rollback-intent") {
			return Result{}, fmt.Errorf("native actuator: exact Pod has pending output policy operation")
		}
		if fenceErr != nil && !apierrors.IsNotFound(fenceErr) {
			return Result{}, fenceErr
		}
	}
	if req.Action != model.ActionVoiceSessionAdmissionEnforce && ec.Reader != nil && ec.JournalNamespace != "" && req.TargetUID != "" {
		pending, err := PendingVoiceAdmissionOperation(ctx, ec.Reader, ec.JournalNamespace, req.Namespace, req.Pod, req.TargetUID)
		if err != nil {
			return Result{}, fmt.Errorf("native actuator: Voice admission protected history unavailable: %w", err)
		}
		if pending {
			return Result{}, fmt.Errorf("native actuator: exact Voice Deployment has unresolved admission operation")
		}
	}

	if req.Action != model.ActionVoiceOutputPolicyActivate && ec.Reader != nil && ec.JournalNamespace != "" && req.TargetUID != "" {
		pending, err := PendingVoiceOutputOperation(ctx, ec.Reader, ec.JournalNamespace, req.Namespace, req.Pod, req.TargetUID)
		if err != nil || pending {
			if err != nil {
				return Result{}, fmt.Errorf("native actuator: exact Voice Pod output journal unavailable: %w", err)
			}
			return Result{}, fmt.Errorf("native actuator: exact Voice Pod has unresolved output operation")
		}
	}
	if req.Action != model.ActionEndpointLeaseRevoke && ec.Reader != nil && ec.JournalNamespace != "" && req.TargetUID != "" {
		pending, err := PendingEndpointLeaseOperation(ctx, ec.Reader, ec.JournalNamespace, req.Namespace, req.TargetUID)
		if err != nil || pending {
			if err != nil {
				return Result{}, fmt.Errorf("native actuator: exact endpoint lease journal unavailable: %w", err)
			}
			return Result{}, fmt.Errorf("native actuator: exact Pod has unresolved endpoint lease operation")
		}
	}
	if err := prepareServingAttempt(ctx, &ec, req); err != nil {
		if pending, lookupErr := pendingProtectedServingReceipt(ctx, ec, req); pending {
			return Result{Actuator: "native", Handler: string(req.Action), MutationKind: "partial", Note: "protected serving operation remains pending; preparation failure cannot authorize fallback"}, errors.Join(err, lookupErr)
		}
		return Result{}, err
	}
	h, ok := HandlerRegistry.Get(string(req.Action))
	if !ok {
		return Result{}, fmt.Errorf("native actuator: no handler for action %q (completeness violation)", req.Action)
	}
	hr, err := h.Enact(ctx, ec, req)
	return Result{
		Actuator:            "native",
		Note:                hr.Note,
		NoEffect:            hr.NoEffect,
		Emitted:             hr.Emitted,
		Handler:             string(req.Action),
		ObjectsTouched:      hr.ObjectsTouched,
		RollbackRef:         hr.RollbackRef,
		MutationKind:        hr.MutationKind,
		GracefulTermination: hr.GracefulTermination,
		DrainOperation:      model.CloneDrainOperationEvidence(hr.DrainOperation),
		ControllerStop:      model.CloneControllerStopReceipt(hr.ControllerStop),
	}, err
}

// MissingHandlers returns the mutating actions of the shared vocabulary
// (model.MutatingActions, which the brain generates from) that have NO registered
// native handler — the completeness violation set. Empty = the invariant
// holds. Used by both completeness_test.go (fails CI) and mustCoverAllActions (fails
// binary startup).
func MissingHandlers() []model.Action {
	var missing []model.Action
	for _, a := range model.MutatingActions {
		if _, ok := HandlerRegistry.Get(string(a)); !ok {
			missing = append(missing, a)
		}
	}
	return missing
}

// OrphanHandlers returns registered handlers whose action is neither a mutating action
// nor a recognized declared-only capability (ActionDisable) — a dead hand hiding a typo.
func OrphanHandlers() []string {
	known := map[string]bool{string(model.ActionDisable): true}
	for _, a := range model.MutatingActions {
		known[string(a)] = true
	}
	var orphans []string
	for _, n := range HandlerRegistry.Names() {
		if !known[n] {
			orphans = append(orphans, n)
		}
	}
	sort.Strings(orphans)
	return orphans
}

// mustCoverAllActions is the BINARY-STARTUP backstop: it panics at process init if any
// generatable action lacks a handler, so even a plain binary cannot START with a
// completeness gap (NOTE: this is a runtime/init panic, NOT a compile error — `go build`
// still succeeds; the binary dies on first run. The compile/CI teeth are
// completeness_test.go under `go test`). It is invoked from an init() in the lexically-
// last file (zz_startup.go) so it runs AFTER every handler init() has registered.
func mustCoverAllActions() {
	if missing := MissingHandlers(); len(missing) > 0 {
		panic(fmt.Sprintf("PHORVEX COMPLETENESS VIOLATION at startup: generatable actions have no native handler: %v", missing))
	}
}
