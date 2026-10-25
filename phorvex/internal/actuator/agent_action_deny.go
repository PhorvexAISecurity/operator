package actuator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/agentdeny"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// agentDenyFreshness bounds how long after observation a deny may still enact. It is the
// self-limiting window of the agent-action steer; a NEW action may choose a window suited
// to a slower tick+readback cadence without touching any frozen path.
const agentDenyFreshness = 5 * time.Minute

// agentActionCapability gates offer-time: a reader, a target Pod, and a live deny-guard
// with spare capacity in the TARGET's own namespace (parametric — no app-namespace literal).
// There is no protected journal — the guard ledger (StateKey) is the idempotency record.
func agentActionCapability(ctx context.Context, reader client.Reader, t Target) (bool, string) {
	if reader == nil || t.Namespace == "" || t.UID == "" || t.Pod == "" {
		return false, "agent-action-deny: reader or target unavailable"
	}
	live, e := agentdeny.ValidateLive(ctx, reader, t.Namespace, t.UID)
	if e != nil {
		return false, "agent-action-deny: " + e.Error()
	}
	if len(live.State.Entries) >= 256 {
		return false, "agent-action-deny: deny-guard capacity exhausted"
	}
	return true, ""
}

// agentActionAuthority re-establishes, against the authoritative reader, that this exact
// decision is still bound to a live deny-guard, the selecting policy (action enabled), the
// target Pod inside the selector, and a trusted admission-stamped SecurityEvent whose
// observation annotation matches the selection-time observation. Unlike crm-refund-revoke
// it does NOT pin a specific injector identity: any trusted creator (the stamped
// creator-identity echoed in the observation) is honored, which is what makes the detector
// path reproducible inside an isolated lane.
func agentActionAuthority(ctx context.Context, ec EnactCtx, req Request) (agentdeny.Live, error) {
	o := req.AgentActionDenyObservation
	if ec.Reader == nil || ec.Client == nil || req.Action != model.ActionAgentActionDeny ||
		req.Namespace == "" || req.TargetUID == "" || req.Pod == "" || req.PolicyName == "" ||
		req.PolicyUID == "" || req.PolicyGeneration < 1 || req.OperationID == "" || len(req.OperationID) > 128 ||
		o == nil || o.Namespace != req.Namespace || o.TargetPodUID != req.TargetUID ||
		o.EventUID == "" || o.EventName == "" || o.CreatorIdentity == "" ||
		o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration ||
		!agentdeny.ValidID(o.CallerID) || !agentdeny.ValidID(o.ActionID) || !agentdeny.ValidID(o.AgentName) ||
		o.GuardConfigMapUID == "" || o.ServiceUID == "" || o.ObservedAt.IsZero() ||
		time.Since(o.ObservedAt) < 0 || time.Since(o.ObservedAt) >= agentDenyFreshness {
		return agentdeny.Live{}, errors.New("agent-action-deny request/observation authority incomplete")
	}
	live, e := agentdeny.ValidateLive(ctx, ec.Reader, o.Namespace, o.TargetPodUID)
	if e != nil {
		return live, e
	}
	if live.ServiceUID != o.ServiceUID || live.GuardUID != o.GuardConfigMapUID {
		return live, errors.New("agent-action-deny Service or deny-guard identity drift")
	}
	found := false
	for _, pod := range live.Pods {
		if pod.UID == req.TargetUID && pod.Name == req.Pod {
			found = true
		}
	}
	if !found {
		return live, errors.New("agent-action-deny selected Pod name/UID differs")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, policy); e != nil {
		return live, e
	}
	if string(policy.UID) != req.PolicyUID || policy.Generation != req.PolicyGeneration || policy.DeletionTimestamp != nil {
		return live, errors.New("agent-action-deny selecting policy epoch changed")
	}
	enabled := false
	for _, action := range policy.Spec.Actions.Enabled {
		if string(action) == string(model.ActionAgentActionDeny) {
			enabled = true
		}
	}
	if !enabled {
		return live, errors.New("agent-action-deny action absent from selecting policy")
	}
	pod := &corev1.Pod{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); e != nil {
		return live, e
	}
	sel, e := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if e != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) || string(pod.UID) != req.TargetUID {
		return live, errors.New("agent-action-deny target left policy selector")
	}
	event := &amtdv1beta1.SecurityEvent{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); e != nil {
		return live, e
	}
	if event.DeletionTimestamp != nil || string(event.UID) != o.EventUID || event.Spec.Rule.Type != agentdeny.RuleType ||
		event.Spec.Rule.Source == "" || !litellmEventTimeMatches(event.CreationTimestamp.Time, o.ObservedAt, time.Now()) ||
		event.Annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != req.TargetUID ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.Annotations[agentdeny.ObservationAnnotation] == "" {
		return live, errors.New("agent-action-deny trusted exact SecurityEvent changed")
	}
	assertion, e := agentdeny.ParseObservation(event.Annotations[agentdeny.ObservationAnnotation])
	if e != nil || assertion.Namespace != o.Namespace || assertion.CallerID != o.CallerID ||
		assertion.ActionID != o.ActionID || assertion.AgentName != o.AgentName ||
		assertion.GuardConfigMapUID != o.GuardConfigMapUID || assertion.ServiceUID != o.ServiceUID ||
		assertion.TargetPodUID != o.TargetPodUID || assertion.PolicyName != o.PolicyName ||
		assertion.PolicyUID != o.PolicyUID || assertion.PolicyGeneration != o.PolicyGeneration ||
		!assertion.ObservedAt.Equal(o.ObservedAt) {
		return live, errors.New("agent-action-deny SecurityEvent assertion changed after selection")
	}
	return live, nil
}

type agentGuardState struct {
	DeniedAgentActions []string `json:"denied_agent_actions"`
}

// errAgentReadbackPending marks a deny that is written and API-confirmed but not yet
// observed enforced on every serving Pod. The agent app reads the guard from a projected
// ConfigMap volume the kubelet refreshes on its own cadence, so this commonly outlasts the
// bounded wait although the CAS already landed.
var errAgentReadbackPending = errors.New("agent-action-deny all-Pod effective readback deadline")

// agentActionReadback confirms every serving Pod's app reports the (caller,action) pair
// denied via its read-only guard-state endpoint. Success == all Pods enforce.
func agentActionReadback(ctx context.Context, ec EnactCtx, live agentdeny.Live, actionKey string) error {
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 0, DisableKeepAlives: true}
	hc := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("agent-action-deny guard-state redirect refused")
	}}
	for _, pod := range live.Pods {
		if net.ParseIP(pod.IP) == nil {
			return errors.New("agent-action-deny Pod IP invalid")
		}
		url := "http://" + net.JoinHostPort(pod.IP, strconv.Itoa(agentdeny.ServingPort)) + agentdeny.ReadbackPath
		httpReq, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return e
		}
		resp, e := hc.Do(httpReq)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		if e != nil || resp.StatusCode != http.StatusOK {
			return errors.New("agent-action-deny guard state unavailable")
		}
		var st agentGuardState
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&st) != nil {
			return errors.New("agent-action-deny guard state malformed")
		}
		denied := false
		for _, k := range st.DeniedAgentActions {
			if k == actionKey {
				denied = true
			}
		}
		if !denied {
			return errors.New("agent-action-deny pair not yet denied on Pod")
		}
	}
	return nil
}

func agentAwaitReadback(ctx context.Context, ec EnactCtx, live agentdeny.Live, actionKey string) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	var last error
	for {
		if last = agentActionReadback(ctx, ec, live, actionKey); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%w: %w", errAgentReadbackPending, last)
		case <-tick.C:
		}
	}
}

type agentActionDenyHandler struct{}

func (agentActionDenyHandler) Name() string { return string(model.ActionAgentActionDeny) }
func (agentActionDenyHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	live, e := agentActionAuthority(ctx, ec, req)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	o := req.AgentActionDenyObservation
	actionKey := agentdeny.ActionKey(o.CallerID, o.ActionID)
	touched := []string{req.Namespace + "/" + agentdeny.GuardConfigMapName}

	// Idempotency: the ledger is the record. If this pair is already denied, only our own
	// operation may reconcile it; a different operation means an unrelated deny and refuses.
	if entry, exists := live.State.Entry(actionKey); exists {
		if entry.OperationID != req.OperationID {
			return HandlerResult{}, RefusedWithoutEffect(errors.New("agent-action-deny pair already denied by a different decision"))
		}
		if e = agentAwaitReadback(ctx, ec, live, actionKey); e != nil {
			if errors.Is(e, errAgentReadbackPending) {
				return HandlerResult{MutationKind: "partial", Emitted: true, ObjectsTouched: touched,
					Note: fmt.Sprintf("agent-action deny for %s already written; all-Pod readback pending", actionKey)}, nil
			}
			return HandlerResult{MutationKind: "partial"}, e
		}
		return HandlerResult{MutationKind: "forward-only", NoEffect: NoEffectReconciled, ObjectsTouched: touched}, nil
	}

	// Prove the next canonical ledger + app-facing bytes before the CAS.
	next, e := live.State.Append(actionKey, req.OperationID)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	stateEnc, e := agentdeny.EncodeState(next)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	appEnc := next.EncodeAppGuard()

	cm := &corev1.ConfigMap{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: agentdeny.GuardConfigMapName}, cm); e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	priorState := agentdeny.Guard{Version: 2, Entries: []agentdeny.Entry{}}
	if raw := cm.Data[agentdeny.StateKey]; raw != "" {
		priorState, e = agentdeny.ParseState(raw)
		if e != nil {
			return HandlerResult{}, RefusedWithoutEffect(e)
		}
	}
	// One exact resourceVersion CAS against the validated guard. A lost acknowledgement is
	// ambiguous and never retried; the ledger's reused-operation refusal prevents a double
	// deny on a later re-selection of the same decision.
	if string(cm.UID) != live.GuardUID || cm.ResourceVersion != live.GuardRV || len(priorState.Entries) != len(live.State.Entries) {
		return HandlerResult{MutationKind: "partial"}, errors.New("agent-action-deny pre-CAS guard authority changed")
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[agentdeny.StateKey] = stateEnc
	cm.Data[agentdeny.GuardKey] = appEnc
	if e = ec.Client.Update(ctx, cm); e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}

	current, e := agentdeny.ValidateLive(ctx, ec.Reader, o.Namespace, o.TargetPodUID)
	entry, exists := current.State.Entry(actionKey)
	if e != nil || !exists || !entry.Active || entry.OperationID != req.OperationID ||
		current.GuardUID != live.GuardUID || current.ServiceUID != live.ServiceUID {
		return HandlerResult{MutationKind: "partial"}, errors.New("agent-action-deny post-CAS authority not confirmed")
	}
	if e = agentAwaitReadback(ctx, ec, current, actionKey); e != nil {
		if errors.Is(e, errAgentReadbackPending) {
			return HandlerResult{MutationKind: "partial", Emitted: true, ObjectsTouched: touched,
				Note: fmt.Sprintf("agent-action deny for %s written; all-Pod guard readback pending mount sync", actionKey)}, nil
		}
		return HandlerResult{MutationKind: "partial"}, e
	}
	return HandlerResult{MutationKind: "forward-only", Emitted: true, ObjectsTouched: touched,
		Note: fmt.Sprintf("agent-action deny for %s effective on all serving Pods", actionKey)}, nil
}

func init() { HandlerRegistry.Register(agentActionDenyHandler{}) }
