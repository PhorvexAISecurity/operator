/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 */

package actuator

import (
	"context"
	"fmt"
	"sort"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actionset"
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
	VLLM             vLLMClient           // serving-stack control plane; nil => real httpVLLM default
	MIG              migController        // GPU MIG control plane; nil => real nvidia-smi default
	Guardrail        guardrailController  // safety/guardrail-tier control plane; nil => real default
	KVXfer           kvTransferController // disaggregated KV-transfer control plane; nil => real default
	AdapterSources   AdapterSources
	MIGProfiles      *MIGProfiles
}

// HandlerResult is the native effect record.
type HandlerResult struct {
	ObjectsTouched []string
	RollbackRef    string
	// MutationKind: "reversible" | "irreversible" | "forward-only" | "swap" | "declared".
	MutationKind string
	// Emitted is false for a refused/not-performed action (including an
	// already-absent adapter goal); it is true for a confirmed mutation or
	// partial mutation that must remain visible even alongside an error.
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
	if req.Action == model.ActionIdentityRotate {
		return Result{}, fmt.Errorf("native actuator: %s", model.IdentityRotateUnsupportedReason)
	}
	h, ok := HandlerRegistry.Get(string(req.Action))
	if !ok {
		return Result{}, fmt.Errorf("native actuator: no handler for action %q (completeness violation)", req.Action)
	}
	hr, err := h.Enact(ctx, ec, req)
	return Result{
		Actuator:       "native",
		Note:           hr.Note,
		Emitted:        hr.Emitted,
		Handler:        string(req.Action),
		ObjectsTouched: hr.ObjectsTouched,
		RollbackRef:    hr.RollbackRef,
		MutationKind:   hr.MutationKind,
	}, err
}

// MissingHandlers returns the generatable actions (model.MutatingActions) that have NO
// registered native handler — the completeness violation set. Empty = the invariant
// holds. Used by both completeness_test.go (fails CI) and mustCoverAllActions (fails
// binary startup).
func MissingHandlers() []model.Action {
	var missing []model.Action
	for _, a := range actionset.GeneratableActions() {
		if _, ok := HandlerRegistry.Get(string(a)); !ok {
			missing = append(missing, a)
		}
	}
	return missing
}

// OrphanHandlers returns registered handlers whose action is neither generatable nor a
// recognized declared-only capability (ActionDisable) — a dead hand hiding a typo.
func OrphanHandlers() []string {
	known := map[string]bool{string(model.ActionDisable): true}
	for _, a := range actionset.GeneratableActions() {
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
