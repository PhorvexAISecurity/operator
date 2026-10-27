package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/servingbudget"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	core "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func throttleCapability(ctx context.Context, r client.Reader, journalNS string, t Target) (bool, string) {
	o := t.ServingRateBudgetObservation
	if r == nil || journalNS == "" || o == nil || o.TargetPodUID != t.UID || o.PolicyName != t.PolicyName || o.PolicyUID != t.PolicyUID || o.PolicyGeneration != t.PolicyGeneration || !throttleObservationWellFormed(o) {
		return false, model.ThrottleUnsupportedReason
	}
	live, e := servingbudget.Validate(ctx, r, t.Namespace, t.Pod, o)
	if e != nil {
		return false, model.ThrottleUnsupportedReason
	}
	if live.Contract.Enabled {
		return false, "throttle: caller already capped"
	}
	var j core.ConfigMap
	if e = r.Get(ctx, client.ObjectKey{Namespace: journalNS, Name: servingbudget.JournalName}, &j); e != nil || j.DeletionTimestamp != nil {
		return false, "throttle: protected journal unavailable"
	}
	var receipt throttleReceipt
	if j.Data[servingbudget.Key] != "" {
		if decodeThrottle(j.Data[servingbudget.Key], &receipt) != nil || receipt.Phase != "rolled-back" {
			return false, "throttle: prior operation unresolved"
		}
	}
	return true, ""
}
func throttleObservationWellFormed(o *model.ServingRateBudgetObservation) bool {
	if o == nil {
		return false
	}
	p := model.Pod{UID: o.TargetPodUID, ControllerUID: o.ControllerUID, ServingRateBudgetObservation: o}
	return p.HasBoundServingRateBudgetObservation() && !o.ObservedAt.After(time.Now()) && time.Since(o.ObservedAt) < servingbudget.Horizon && o.CreatorIdentity == servingbudget.DetectorIdentity && o.WindowSeconds >= 60 && servingbudget.Positive(o.BaselineReqPerSec) && servingbudget.Positive(o.ReservedReqPerSec) && servingbudget.Positive(o.ObservedReqPerSec)
}

func throttleAuthority(ctx context.Context, ec EnactCtx, req Request) (servingbudget.Live, error) {
	o := req.ServingRateBudgetObservation
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.Action != model.ActionThrottle || req.TargetUID == "" || req.OperationID == "" || len(req.OperationID) > 128 || o == nil || o.TargetPodUID != req.TargetUID || o.PolicyUID != req.PolicyUID || o.PolicyName != req.PolicyName || o.PolicyGeneration != req.PolicyGeneration || !throttleObservationWellFormed(o) {
		return servingbudget.Live{}, errors.New("throttle selection authority incomplete")
	}
	l, e := servingbudget.Validate(ctx, ec.Reader, req.Namespace, req.Pod, o)
	if e != nil {
		return l, e
	}
	var ev amtd.SecurityEvent
	if e = ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, &ev); e != nil {
		return l, e
	}
	if string(ev.UID) != o.EventUID || ev.DeletionTimestamp != nil || ev.Spec.Rule.Type != model.AttackVectorServingCostHarvest || ev.Spec.Rule.Source != servingbudget.Source || ev.Spec.Rule.ThreatLevel != "high" || ev.Annotations["phorvex.ai/creator-identity"] != servingbudget.DetectorIdentity || ev.Annotations[model.ConsoleTargetPodUIDAnnotation] != req.TargetUID || len(ev.Spec.Targets) != 1 || ev.Spec.Targets[0] != req.Namespace+"/"+req.Pod || ev.CreationTimestamp.IsZero() || time.Since(ev.CreationTimestamp.Time) < 0 || time.Since(ev.CreationTimestamp.Time) >= servingbudget.Horizon {
		return l, errors.New("throttle admitted detector evidence changed")
	}
	parsed, e := servingbudget.ParseObservation(ev.Annotations[servingbudget.Annotation])
	if e != nil {
		return l, e
	}
	parsed.EventName = ev.Name
	parsed.EventUID = string(ev.UID)
	parsed.CreatorIdentity = servingbudget.DetectorIdentity
	sameTime := parsed.ObservedAt.Equal(o.ObservedAt)
	parsed.ObservedAt = o.ObservedAt
	if !sameTime || !reflect.DeepEqual(parsed, o) || o.ObservedAt.After(ev.CreationTimestamp.Time.Add(time.Second)) || ev.CreationTimestamp.Time.Sub(o.ObservedAt) >= servingbudget.Horizon {
		return l, errors.New("throttle selected evidence payload changed")
	}
	return l, nil
}

type throttleReceipt struct {
	Request     Request                `json:"request"`
	OperationID string                 `json:"operationID"`
	Namespace   string                 `json:"namespace"`
	PolicyUID   string                 `json:"policyUID"`
	ConfigUID   string                 `json:"configUID"`
	Phase       string                 `json:"phase"`
	Before      servingbudget.Contract `json:"before"`
	After       servingbudget.Contract `json:"after"`
}

func throttleJournal(ctx context.Context, ec EnactCtx) (*core.ConfigMap, throttleReceipt, error) {
	var cm core.ConfigMap
	var r throttleReceipt
	e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: servingbudget.JournalName}, &cm)
	if e == nil && cm.DeletionTimestamp != nil {
		e = errors.New("journal deleting")
	}
	if e == nil && cm.Data[servingbudget.Key] != "" {
		e = decodeThrottle(cm.Data[servingbudget.Key], &r)
	}
	return &cm, r, e
}
func saveThrottle(ctx context.Context, ec EnactCtx, cm *core.ConfigMap, r throttleReceipt) error {
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[servingbudget.Key] = servingbudget.Encode(r)
	return ec.Client.Update(ctx, cm)
}
func awaitThrottle(ctx context.Context, ec EnactCtx, ns, uid, proxyUID, bootID string, c servingbudget.Contract) error {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		s, e := servingbudget.ReadStatus(deadline, ec.Reader, ns)
		if e == nil && s.Fresh(time.Now()) && s.ConfigUID == uid && s.PodUID == proxyUID && s.BootID == bootID && s.Contract == c {
			return nil
		}
		select {
		case <-deadline.Done():
			return errors.New("throttle durable mutation pending effective proxy readback")
		case <-ticker.C:
		}
	}
}

type throttleHandler struct{}

func (throttleHandler) Name() string { return string(model.ActionThrottle) }
func (throttleHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	l, e := throttleAuthority(ctx, ec, req)
	if e != nil {
		if ec.Reader != nil && ec.JournalNamespace != "" {
			_, prior, journalErr := throttleJournal(ctx, ec)
			if journalErr != nil {
				return HandlerResult{}, journalErr
			}
			if prior.OperationID == req.OperationID && prior.Phase != "rolled-back" {
				return HandlerResult{}, e
			}
		}
		return HandlerResult{NoEffect: NoEffectRefused, MutationKind: "none", Note: e.Error()}, nil
	}
	j, r, e := throttleJournal(ctx, ec)
	if e != nil {
		return HandlerResult{}, e
	}
	if r.OperationID == req.OperationID {
		if r.Namespace != req.Namespace || r.PolicyUID != req.PolicyUID || r.ConfigUID != string(l.Config.UID) || r.Phase == "rolled-back" {
			return HandlerResult{}, errors.New("throttle operation replay differs")
		}
	} else {
		if r.OperationID != "" && r.Phase != "rolled-back" {
			return HandlerResult{}, errors.New("throttle prior operation unresolved")
		}
		if l.Contract.Enabled || l.Contract.Revision != req.ServingRateBudgetObservation.PriorRevision {
			return HandlerResult{NoEffect: NoEffectRefused, MutationKind: "none"}, nil
		}
		after := l.Contract
		after.Enabled = true
		after.ActivatedAt = time.Now().UTC()
		after.ExpiresAt = after.ActivatedAt.Add(servingbudget.MaxLease)
		after.OperationID = req.OperationID
		after.Revision++
		after.Baseline = req.ServingRateBudgetObservation.BaselineReqPerSec
		after.Reserved = req.ServingRateBudgetObservation.ReservedReqPerSec
		after.Burst = math.Max(1, after.Baseline)
		after.CalibrationStart = l.Status.CalibrationStart
		after.CalibrationEnd = l.Status.CalibrationEnd
		r = throttleReceipt{Request: req, OperationID: req.OperationID, Namespace: req.Namespace, PolicyUID: req.PolicyUID, ConfigUID: string(l.Config.UID), Phase: "prepared", Before: l.Contract, After: after}
		// Write-ahead intent, then exact resourceVersion CAS. Ambiguous errors retain
		// intent; they never become definite no-effect or authorize a fallback move.
		if e = saveThrottle(ctx, ec, j, r); e != nil {
			return HandlerResult{}, e
		}
	}
	mutated := false
	if l.Contract == r.Before {
		l.Config.Data[servingbudget.Key] = servingbudget.Encode(r.After)
		if e = ec.Client.Update(ctx, l.Config); e != nil {
			return HandlerResult{}, e
		}
		mutated = true
	} else if l.Contract != r.After {
		return HandlerResult{}, errors.New("throttle durable state differs from prepared operation")
	}
	if e = awaitThrottle(ctx, ec, req.Namespace, r.ConfigUID, string(l.Proxy.UID), req.ServingRateBudgetObservation.LimiterBootID, r.After); e != nil {
		return HandlerResult{Emitted: mutated, MutationKind: "reversible", RollbackRef: req.OperationID}, e
	}
	j, current, e := throttleJournal(ctx, ec)
	if e != nil || current.OperationID != r.OperationID {
		if e == nil {
			e = errors.New("throttle journal changed")
		}
		return HandlerResult{Emitted: mutated}, e
	}
	r.Phase = "applied"
	if e = saveThrottle(ctx, ec, j, r); e != nil {
		return HandlerResult{Emitted: mutated}, e
	}
	if !mutated {
		return HandlerResult{NoEffect: NoEffectReconciled, MutationKind: "reversible", RollbackRef: req.OperationID}, nil
	}
	return HandlerResult{Emitted: true, ObjectsTouched: []string{"configmap/" + req.Namespace + "/" + servingbudget.ConfigName}, MutationKind: "reversible", RollbackRef: req.OperationID, Note: "authoritative proxy confirms abusive budget and legitimate reservation"}, nil
}
func (throttleHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	if ec.DryRun {
		return errDryRunGuard
	}
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || ref == "" || ref != req.OperationID {
		return errors.New("throttle rollback authority incomplete")
	}
	j, r, e := throttleJournal(ctx, ec)
	if e != nil {
		return e
	}
	if r.OperationID != ref || r.Namespace != req.Namespace || r.PolicyUID != req.PolicyUID {
		return errors.New("throttle rollback ownership differs")
	}
	if r.Phase == "rolled-back" {
		return nil
	}
	var cm core.ConfigMap
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: servingbudget.ConfigName}, &cm); e != nil {
		return e
	}
	if string(cm.UID) != r.ConfigUID {
		return errors.New("throttle rollback ConfigMap recreated")
	}
	c, e := servingbudget.Parse(cm.Data[servingbudget.Key])
	if e != nil {
		return e
	}
	restored := r.Before
	restored.Revision = r.After.Revision + 1
	restored.OperationID = "rollback:" + r.OperationID
	if c != r.After && c != restored && c != r.Before {
		return errors.New("throttle rollback refuses a later writer")
	}
	r.Phase = "rollback-intent"
	if e = saveThrottle(ctx, ec, j, r); e != nil {
		return e
	}
	if c != restored {
		cm.Data[servingbudget.Key] = servingbudget.Encode(restored)
		if e = ec.Client.Update(ctx, &cm); e != nil {
			return e
		}
	}
	status, statusErr := servingbudget.ReadStatus(ctx, ec.Reader, r.Namespace)
	if statusErr != nil || !status.Fresh(time.Now()) || status.ConfigUID != r.ConfigUID {
		return errors.New("rollback effective proxy identity unavailable")
	}
	if e = awaitThrottle(ctx, ec, r.Namespace, r.ConfigUID, status.PodUID, status.BootID, restored); e != nil {
		return e
	}
	j, _, e = throttleJournal(ctx, ec)
	if e != nil {
		return e
	}
	r.Phase = "rolled-back"
	return saveThrottle(ctx, ec, j, r)
}
func init() { HandlerRegistry.Register(throttleHandler{}) }

func decodeThrottle(raw string, v any) error { return json.Unmarshal([]byte(raw), v) }
