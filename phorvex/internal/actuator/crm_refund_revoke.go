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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const crmConsoleCreator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"

// crmRefundCapability gates offer-time: a reader, a crm-namespace target Pod, and a live
// deny-guard with spare capacity. There is no protected journal — the guard ledger itself
// (StateKey) is the idempotency record, refusing a repeated order or reused operation id.
func crmRefundCapability(ctx context.Context, reader client.Reader, t Target) (bool, string) {
	if reader == nil || t.Namespace != crmrefund.Namespace || t.UID == "" || t.Pod == "" {
		return false, "crm-refund-revoke: reader or target unavailable"
	}
	live, e := crmrefund.ValidateLive(ctx, reader, t.UID, "")
	if e != nil {
		return false, "crm-refund-revoke: " + e.Error()
	}
	if len(live.State.Entries) >= 256 {
		return false, "crm-refund-revoke: deny-guard capacity exhausted"
	}
	return true, ""
}

// crmRefundAuthority re-establishes, against the authoritative reader, that this exact
// decision is still bound to a live deny-guard, the selecting policy (with the action
// enabled), the target Pod inside the selector, and a trusted admission-stamped
// SecurityEvent whose observation annotation matches the selection-time observation.
func crmRefundAuthority(ctx context.Context, ec EnactCtx, req Request) (crmrefund.Live, error) {
	o := req.CRMRefundObservation
	if ec.Reader == nil || ec.Client == nil || req.Action != model.ActionCRMRefundRevoke ||
		req.Namespace != crmrefund.Namespace || req.TargetUID == "" || req.Pod == "" || req.PolicyName == "" ||
		req.PolicyUID == "" || req.PolicyGeneration < 1 || req.OperationID == "" || len(req.OperationID) > 128 ||
		o == nil || o.TargetPodUID != req.TargetUID || o.PeerPodUID == "" || o.TargetPodUID == o.PeerPodUID ||
		o.EventUID == "" || o.EventName == "" || o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID ||
		o.PolicyGeneration != req.PolicyGeneration || !crmrefund.ValidOrderID(o.OrderID) ||
		o.OrderAccountID == "" || o.CallerAccountID == "" || o.OrderAccountID == o.CallerAccountID ||
		o.GuardConfigMapUID == "" || o.ServiceUID == "" || o.ObservedAt.IsZero() ||
		time.Since(o.ObservedAt) < 0 || time.Since(o.ObservedAt) >= 60*time.Second {
		return crmrefund.Live{}, errors.New("crm-refund request/observation authority incomplete")
	}
	live, e := crmrefund.ValidateLive(ctx, ec.Reader, o.TargetPodUID, o.PeerPodUID)
	if e != nil {
		return live, e
	}
	if live.ServiceUID != o.ServiceUID || live.GuardUID != o.GuardConfigMapUID {
		return live, errors.New("crm-refund Service or deny-guard identity drift")
	}
	found := false
	for _, pod := range live.Pods {
		if pod.UID == req.TargetUID && pod.Name == req.Pod {
			found = true
		}
	}
	if !found {
		return live, errors.New("crm-refund selected Pod name/UID differs")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, policy); e != nil {
		return live, e
	}
	if string(policy.UID) != req.PolicyUID || policy.Generation != req.PolicyGeneration || policy.DeletionTimestamp != nil {
		return live, errors.New("crm-refund selecting policy epoch changed")
	}
	enabled := false
	for _, action := range policy.Spec.Actions.Enabled {
		if string(action) == string(model.ActionCRMRefundRevoke) {
			enabled = true
		}
	}
	if !enabled {
		return live, errors.New("crm-refund action absent from selecting policy")
	}
	pod := &corev1.Pod{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); e != nil {
		return live, e
	}
	sel, e := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if e != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) || string(pod.UID) != req.TargetUID {
		return live, errors.New("crm-refund target left policy selector")
	}
	event := &amtdv1beta1.SecurityEvent{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); e != nil {
		return live, e
	}
	if event.DeletionTimestamp != nil || string(event.UID) != o.EventUID || event.Spec.Rule.Type != crmrefund.RuleType ||
		event.Spec.Rule.Source != "redteam" || !litellmEventTimeMatches(event.CreationTimestamp.Time, o.ObservedAt, time.Now()) ||
		event.Annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity ||
		o.CreatorIdentity != crmConsoleCreator ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != req.TargetUID ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.Annotations[crmrefund.ObservationAnnotation] == "" {
		return live, errors.New("crm-refund trusted exact SecurityEvent changed")
	}
	assertion, e := crmrefund.ParseObservation(event.Annotations[crmrefund.ObservationAnnotation])
	if e != nil || assertion.OrderID != o.OrderID || assertion.OrderAccountID != o.OrderAccountID ||
		assertion.CallerAccountID != o.CallerAccountID || assertion.GuardConfigMapUID != o.GuardConfigMapUID ||
		assertion.ServiceUID != o.ServiceUID || assertion.TargetPodUID != o.TargetPodUID ||
		assertion.PeerPodUID != o.PeerPodUID || assertion.PolicyName != o.PolicyName ||
		assertion.PolicyUID != o.PolicyUID || assertion.PolicyGeneration != o.PolicyGeneration ||
		!assertion.ObservedAt.Equal(o.ObservedAt) {
		return live, errors.New("crm-refund SecurityEvent assertion changed after selection")
	}
	return live, nil
}

type crmGuardState struct {
	DeniedOrderIDs []string `json:"denied_order_ids"`
}

// errCRMReadbackPending marks a deny that is written and API-confirmed but not yet
// observed enforced on every serving Pod. The mini-CRM reads the guard from a projected
// ConfigMap volume the kubelet refreshes on its own cadence (~up to ~90s), so this
// commonly outlasts the bounded wait although the CAS already landed.
var errCRMReadbackPending = errors.New("crm-refund all-Pod effective readback deadline")

// crmRefundReadback confirms every serving Pod's app reports the order denied via its
// read-only guard-state endpoint. Success == all Pods enforce; any disagreement errors.
func crmRefundReadback(ctx context.Context, ec EnactCtx, live crmrefund.Live, orderID string) error {
	transport := ec.CRMRefundTransport
	if transport == nil {
		transport = &http.Transport{Proxy: nil, MaxIdleConns: 0, DisableKeepAlives: true}
	}
	hc := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("crm-refund guard-state redirect refused")
	}}
	for _, pod := range live.Pods {
		if net.ParseIP(pod.IP) == nil {
			return errors.New("crm-refund Pod IP invalid")
		}
		url := "http://" + net.JoinHostPort(pod.IP, "8080") + "/phorvex-guard/state"
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return e
		}
		resp, e := hc.Do(req)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		if e != nil || resp.StatusCode != http.StatusOK {
			return errors.New("crm-refund guard state unavailable")
		}
		var st crmGuardState
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&st) != nil {
			return errors.New("crm-refund guard state malformed")
		}
		denied := false
		for _, id := range st.DeniedOrderIDs {
			if id == orderID {
				denied = true
			}
		}
		if !denied {
			return errors.New("crm-refund order not yet denied on Pod")
		}
	}
	return nil
}

func crmAwaitReadback(ctx context.Context, ec EnactCtx, live crmrefund.Live, orderID string) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	var last error
	for {
		if last = crmRefundReadback(ctx, ec, live, orderID); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%w: %w", errCRMReadbackPending, last)
		case <-tick.C:
		}
	}
}

type crmRefundRevokeHandler struct{}

func (crmRefundRevokeHandler) Name() string { return string(model.ActionCRMRefundRevoke) }
func (crmRefundRevokeHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	live, e := crmRefundAuthority(ctx, ec, req)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	o := req.CRMRefundObservation
	touched := []string{req.Namespace + "/" + crmrefund.GuardConfigMapName}

	// Idempotency: the ledger is the record. If this order is already revoked, only our own
	// operation may reconcile it; a different operation means an unrelated revoke and refuses.
	if entry, exists := live.State.Entry(o.OrderID); exists {
		if entry.OperationID != req.OperationID {
			return HandlerResult{}, RefusedWithoutEffect(errors.New("crm-refund order already revoked by a different decision"))
		}
		if e = crmAwaitReadback(ctx, ec, live, o.OrderID); e != nil {
			if errors.Is(e, errCRMReadbackPending) {
				return HandlerResult{MutationKind: "partial", Emitted: true, ObjectsTouched: touched,
					Note: fmt.Sprintf("crm refund deny for order %s already written; all-Pod readback pending", o.OrderID)}, nil
			}
			return HandlerResult{MutationKind: "partial"}, e
		}
		return HandlerResult{MutationKind: "forward-only", NoEffect: NoEffectReconciled, ObjectsTouched: touched}, nil
	}

	// Prove the next canonical ledger + app-facing bytes before the CAS.
	next, e := live.State.Append(o.OrderID, req.OperationID)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	stateEnc, e := crmrefund.EncodeState(next)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	appEnc := next.EncodeAppGuard()

	cm := &corev1.ConfigMap{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: crmrefund.Namespace, Name: crmrefund.GuardConfigMapName}, cm); e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	priorState := crmrefund.Guard{Version: 2, Entries: []crmrefund.Entry{}}
	if raw := cm.Data[crmrefund.StateKey]; raw != "" {
		priorState, e = crmrefund.ParseState(raw)
		if e != nil {
			return HandlerResult{}, RefusedWithoutEffect(e)
		}
	}
	// One exact resourceVersion CAS against the validated guard. A lost acknowledgement is
	// ambiguous and never retried; the ledger's reused-operation refusal prevents a double
	// revoke on a later re-selection of the same decision.
	if string(cm.UID) != live.GuardUID || cm.ResourceVersion != live.GuardRV || len(priorState.Entries) != len(live.State.Entries) {
		return HandlerResult{MutationKind: "partial"}, errors.New("crm-refund pre-CAS guard authority changed")
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[crmrefund.StateKey] = stateEnc
	cm.Data[crmrefund.GuardKey] = appEnc
	if e = ec.Client.Update(ctx, cm); e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}

	current, e := crmrefund.ValidateLive(ctx, ec.Reader, o.TargetPodUID, o.PeerPodUID)
	entry, exists := current.State.Entry(o.OrderID)
	if e != nil || !exists || !entry.Active || entry.OperationID != req.OperationID ||
		current.GuardUID != live.GuardUID || current.ServiceUID != live.ServiceUID {
		return HandlerResult{MutationKind: "partial"}, errors.New("crm-refund post-CAS authority not confirmed")
	}
	if e = crmAwaitReadback(ctx, ec, current, o.OrderID); e != nil {
		if errors.Is(e, errCRMReadbackPending) {
			// The deny is written and API-confirmed above; only the Pods' projected guard
			// readback is outstanding. Report an emitted, unconfirmed effect so the runner
			// counts the actuation; a later re-selection reconciles via the idempotent path.
			return HandlerResult{MutationKind: "partial", Emitted: true, ObjectsTouched: touched,
				Note: fmt.Sprintf("crm refund deny for order %s written; all-Pod guard readback pending mount sync", o.OrderID)}, nil
		}
		return HandlerResult{MutationKind: "partial"}, e
	}
	return HandlerResult{MutationKind: "forward-only", Emitted: true, ObjectsTouched: touched,
		Note: fmt.Sprintf("crm refund deny for order %s effective on all serving Pods", o.OrderID)}, nil
}

func init() { HandlerRegistry.Register(crmRefundRevokeHandler{}) }
