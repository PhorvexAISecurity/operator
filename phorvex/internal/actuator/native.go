/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 */

package actuator

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/gpudevice"
	"github.com/phorvex/phorvex/internal/model"
)

// NativeActuator is Phorvex's OWN hands (NFR5: "standalone actuation behind an
// interface"). It writes Pods/NetworkPolicies/Services/EndpointSlices/Secrets/
// ephemeral-containers DIRECTLY via client-go — NO Phoenix CRDs installed — dispatching
// each model.Action to its registered native ActionHandler. It is the native PEER of
// PhoenixActuator (which stays byte-unchanged as the optional SSPL integration adapter);
// a deployment selects one by wiring Manager.Actuator. The brain is unchanged — both
// satisfy the same Actuator interface.
//
// License-clean: this package imports ONLY k8s.io/* + sigs.k8s.io/controller-runtime
// (ZERO Phoenix imports); every handler is authored from the published k8s.io API
// contract (clean-room), so the standalone product IP carries no SSPL-derived Go.
type NativeActuator struct {
	Client                   client.Client
	Reader                   client.Reader
	JournalNamespace         string
	RecoveryVLLM             vLLMClient // optional serving-stack seam for recovery tests; nil uses live client
	AdapterSources           AdapterSources
	RouteObservationTimeout  time.Duration
	RouteObservationInterval time.Duration
	migProfiles              *MIGProfiles
	servingSecurity          *ServingSecurityConfig
	// DryRun is a belt-and-suspenders guard (the runner already skips actuation in
	// dry-run); when set, every handler refuses to mutate.
	DryRun bool

	// [P-VCLUSTER O7] Policy bindings authorize an exact policy owner to one immutable
	// tenant/namespace tuple. The legacy tenant map remains available only until owner
	// tracking first activates; all binding state shares one lock.
	bindingMu       sync.RWMutex
	tenantNS        map[string]map[string]bool
	bindingsByUID   map[string]tenantNamespaceBinding
	bindingsTracked bool
	// StrictTenantNamespace fail-CLOSES on a Request whose Tenant has NO binding at all (production
	// posture once every tenant is bound). Default false preserves the legacy single-tenant path.
	StrictTenantNamespace bool
}

type tenantNamespaceBinding struct {
	tenant    string
	namespace string
}

// NewNativeActuator constructs the native actuator over a controller-runtime client.
func NewNativeActuator(c client.Client) *NativeActuator { return &NativeActuator{Client: c} }

// SupportsAction answers package-owned runtime prerequisites. MIG support requires the
// configured transport, an exact operator profile, a current authoritative Pod identity,
// and node-grouped PodResources/inventory evidence; the handler independently revalidates.
func (n *NativeActuator) SupportsAction(ctx context.Context, a model.Action, t Target) (bool, string) {
	// [M-21] Repertoire first, from the SAME handler registry `dispatch` routes through:
	// an unknown action, the noop sentinel, and the declared-not-implemented `disable`
	// are rejected here rather than accepted and then refused at the dispatch boundary.
	if ok, detail := nativeAccepts(a); !ok {
		return false, unsupportedWhy(BackendNative, a, detail)
	}
	if ok, why := n.servingSecurity.supports(a, t); !ok {
		return false, why
	}
	// Transport is checked before its dependent allocation evidence.
	if a == model.ActionMIGRebind && !NodeExecWired() {
		return false, ReasonTransportUnwired
	}
	if a == model.ActionMIGRebind {
		ctx = migCapabilityProbe(ctx)
		rule, err := n.migProfiles.Resolve(t.Namespace, t.MIGResource)
		if err != nil {
			return false, "mig-profile-authority: " + err.Error()
		}
		if n.Reader == nil || t.NodeName == "" || t.UID == "" {
			return false, "mig-allocation-authority: target identity or reader unavailable"
		}
		fresh := &corev1.Pod{}
		if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: t.Pod}, fresh); err != nil || string(fresh.UID) != t.UID || fresh.Spec.NodeName != t.NodeName || gpudevice.MIGResourceName(fresh) != t.MIGResource {
			return false, "mig-allocation-authority: current Pod identity, node or resource changed"
		}
		mig, err := (&nvidiaSMIMIG{run: pkgNodeRunner}).Prepare(ctx, t.NodeName)
		if err != nil {
			return false, "mig-allocation-authority: " + err.Error()
		}
		auth, ok := mig.(migAllocationAuthority)
		if !ok {
			return false, "mig-allocation-authority: prepared runner cannot query PodResources"
		}
		if _, err := auth.BindAllocation(ctx, migAllocationTarget{Namespace: t.Namespace, Pod: t.Pod, UID: t.UID, Node: t.NodeName, Resource: t.MIGResource}, rule); err != nil {
			return false, "mig-allocation-authority: " + err.Error()
		}
	}
	return true, ""
}

// Name implements Actuator.
func (*NativeActuator) Name() string { return "native" }

// CapabilityAdvisory exposes configured insecure compatibility without spending API reads.
func (n *NativeActuator) CapabilityAdvisory(a model.Action, t Target) string {
	if ok, why := n.servingSecurity.supports(a, t); ok {
		return why
	}
	return ""
}

// EnsurePolicy records the tenant→namespace binding (O7) and pre-stages per-tenant native state where a
// handler needs it. The base K8s moves need no standing CR, so beyond the binding this is a no-op.
func (n *NativeActuator) EnsurePolicy(_ context.Context, target TenantTarget) error {
	if target.Selector != nil {
		sel := targetSelector(target)
		if len(sel.MatchLabels)+len(sel.MatchExpressions) == 0 {
			return fmt.Errorf("native actuator: active tenant %q has empty selector", target.Tenant)
		}
		if _, err := metav1.LabelSelectorAsSelector(&sel); err != nil {
			return fmt.Errorf("native actuator: tenant %q invalid selector: %w", target.Tenant, err)
		}
	}
	if target.PolicyUID != "" {
		if target.Tenant == "" || target.Namespace == "" {
			return fmt.Errorf("native actuator: policy UID %q requires a nonempty tenant and namespace", target.PolicyUID)
		}
		n.bindingMu.Lock()
		defer n.bindingMu.Unlock()
		if n.bindingsByUID == nil {
			n.bindingsByUID = map[string]tenantNamespaceBinding{}
		}
		n.bindingsTracked = true
		n.tenantNS = nil
		n.bindingsByUID[target.PolicyUID] = tenantNamespaceBinding{tenant: target.Tenant, namespace: target.Namespace}
		return nil
	}

	n.bindingMu.Lock()
	defer n.bindingMu.Unlock()
	if n.bindingsTracked {
		return fmt.Errorf("native actuator: policy UID is required after owner tracking activates")
	}
	if target.Tenant == "" || target.Namespace == "" {
		return nil
	}
	if n.tenantNS == nil {
		n.tenantNS = map[string]map[string]bool{}
	}
	if n.tenantNS[target.Tenant] == nil {
		n.tenantNS[target.Tenant] = map[string]bool{}
	}
	n.tenantNS[target.Tenant][target.Namespace] = true
	return nil
}

// assertTenantNamespace is the O7 fail-fast: a Request may only act in a namespace bound to its tenant.
func (n *NativeActuator) assertTenantNamespace(req Request) error {
	n.bindingMu.RLock()
	defer n.bindingMu.RUnlock()
	if n.bindingsTracked {
		binding, bound := n.bindingsByUID[req.PolicyUID]
		if req.PolicyUID == "" || !bound {
			return fmt.Errorf("native actuate DENIED (O7): policy owner %q has no active tenant/namespace binding for %s/%s", req.PolicyUID, req.Namespace, req.Pod)
		}
		if binding.tenant != req.Tenant || binding.namespace != req.Namespace {
			return fmt.Errorf("native actuate DENIED (O7): policy owner %q is not bound to tenant %q namespace %q", req.PolicyUID, req.Tenant, req.Namespace)
		}
		return nil
	}
	allowed, bound := n.tenantNS[req.Tenant]
	if !bound {
		if n.StrictTenantNamespace {
			return fmt.Errorf("native actuate DENIED (O7 strict): tenant %q has no namespace binding for %s/%s", req.Tenant, req.Namespace, req.Pod)
		}
		return nil // legacy/single-tenant: unbound tenant allowed; K8s per-namespace RBAC is the backstop
	}
	if !allowed[req.Namespace] {
		return fmt.Errorf("native actuate DENIED (O7): tenant %q is not bound to namespace %q — cross-tenant actuation refused (%s/%s)", req.Tenant, req.Namespace, req.Namespace, req.Pod)
	}
	return nil
}

// RetirePolicyBinding removes exactly one policy owner's local authorization at
// lifecycle completion. Tracking remains sticky after the final owner is removed.
func (n *NativeActuator) RetirePolicyBinding(policyUID string) {
	if policyUID == "" {
		return
	}
	n.bindingMu.Lock()
	defer n.bindingMu.Unlock()
	n.bindingsTracked = true
	n.tenantNS = nil
	delete(n.bindingsByUID, policyUID)
}

// Actuate dispatches the move to its native handler. Implements Actuator.
func (n *NativeActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	if err := n.assertTenantNamespace(req); err != nil {
		return Result{}, err
	}
	return dispatch(ctx, EnactCtx{Client: n.Client, Reader: n.Reader, DryRun: n.DryRun, JournalNamespace: n.JournalNamespace, AdapterSources: n.AdapterSources, MIGProfiles: n.migProfiles, ServingSecurity: n.servingSecurity, RouteObservationTimeout: n.RouteObservationTimeout, RouteObservationInterval: n.RouteObservationInterval}, req)
}

// Rollback runs a handler's compensating undo (used by the rollback proof + a future
// saga coordinator). A handler that is not a Rollbacker (forward-only/irreversible)
// returns a no-op nil.
//
// [M-87] Rollback is the SAME actuation boundary as Actuate: several Rollbackers write Pods
// or call serving APIs, so the O7 tenant-namespace assertion and the central dry-run refusal
// run here too, BEFORE handler lookup or invocation. Tenant first keeps Actuate's error
// precedence; a refusal returns the error and reaches no K8s read/write or serving call.
func (n *NativeActuator) Rollback(ctx context.Context, req Request, ref string) error {
	if err := n.assertTenantNamespace(req); err != nil {
		return err
	}
	return n.rollbackPrepared(ctx, req, ref)
}

// rollbackPrepared performs a rollback after its caller has established the
// applicable authority. Public Rollback performs the live owner check; protected
// administrative recovery supplies its stronger plan/receipt/hold authority.
func (n *NativeActuator) rollbackPrepared(ctx context.Context, req Request, ref string) error {
	if n.DryRun {
		return errDryRunGuard
	}
	h, ok := HandlerRegistry.Get(string(req.Action))
	if !ok {
		return nil
	}
	if rb, ok := h.(Rollbacker); ok {
		ec := EnactCtx{Client: n.Client, Reader: n.Reader, DryRun: n.DryRun, JournalNamespace: n.JournalNamespace, AdapterSources: n.AdapterSources, ServingSecurity: n.servingSecurity, RouteObservationTimeout: n.RouteObservationTimeout, RouteObservationInterval: n.RouteObservationInterval}
		if err := prepareServingAttempt(ctx, &ec, req); err != nil {
			return err
		}
		return rb.Rollback(ctx, ec, req, ref)
	}
	return nil
}

// Compile-time assertions that ALL THREE actuators satisfy the interface (the seam is
// real and Phase-2 cannot drift the contract).
var (
	_ Actuator               = (*PhoenixActuator)(nil)
	_ Actuator               = (*NativeActuator)(nil)
	_ PolicyBindingLifecycle = (*NativeActuator)(nil)
)

func (n *NativeActuator) SetBoundaryReader(r client.Reader) { n.Reader = r }
func (n *NativeActuator) SetAdapterSources(s AdapterSources) {
	n.AdapterSources = copyAdapterSources(s)
}
func (n *NativeActuator) SetMIGProfiles(p *MIGProfiles) { n.migProfiles = snapshotMIGProfiles(p) }
func (n *NativeActuator) SetServingSecurity(c *ServingSecurityConfig) {
	n.servingSecurity = snapshotServingSecurity(c)
}
