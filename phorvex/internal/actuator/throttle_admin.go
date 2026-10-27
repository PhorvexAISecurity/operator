package actuator

import (
	"context"
	"errors"
	api "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/servingbudget"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

// RollbackThrottle is an explicit administrator entrypoint. The exact operation
// and policy UID are mandatory; this never searches for or undoes a newer writer.
func RollbackThrottle(ctx context.Context, c client.Client, operatorNS, operation, policyUID string) error {
	if operatorNS == "" || operation == "" || policyUID == "" {
		return errors.New("exact rollback operation and policy UID required")
	}
	ec := EnactCtx{Reader: c, Client: c, JournalNamespace: operatorNS}
	_, r, e := throttleJournal(ctx, ec)
	if e != nil {
		return e
	}
	if r.OperationID != operation || r.PolicyUID != policyUID || r.Namespace != "costbench-opus" || r.Request.PolicyUID != policyUID || r.Request.OperationID != operation || r.Request.Namespace != r.Namespace || !servingbudget.Approved(r.After) {
		return errors.New("protected rollback receipt differs from administrator scope")
	}
	var p api.PhorvexPolicy
	if e = c.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: r.Request.PolicyName}, &p); e != nil {
		return e
	}
	if string(p.UID) != policyUID {
		return errors.New("selecting policy was recreated")
	}
	return (throttleHandler{}).Rollback(ctx, ec, r.Request, operation)
}

// Cleanup follows the existing protected maintenance path. The proxy lifts the
// data-path cap independently; this CAS rollback closes the exact receipt so a
// later sustained episode can be selected normally. Optional fixture failures are
// reported locally and never fail shared operation inventory.
func recoverThrottleRelease(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) []RecoveryEvent {
	if ec.DryRun || ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" ||
		!servingbudget.SHA(os.Getenv("PHORVEX_THROTTLE_SOURCE_SHA256")) ||
		!servingbudget.ValidImage(os.Getenv("PHORVEX_THROTTLE_PROXY_IMAGE")) || allow != nil && !allow(model.ActionThrottle) {
		return nil
	}
	_, r, err := throttleJournal(ctx, ec)
	if err != nil || r.OperationID == "" || r.Phase == "rolled-back" {
		return nil
	}
	if r.Namespace != "costbench-opus" || r.Request.PolicyName != "cost-defense" || r.Request.Namespace != r.Namespace || r.Request.OperationID != r.OperationID || r.Request.PolicyUID != r.PolicyUID || !servingbudget.Approved(r.After) {
		return nil
	}
	s, err := servingbudget.ReadStatus(ctx, ec.Reader, r.Namespace)
	now := time.Now()
	if err != nil || !s.Fresh(now) || s.ConfigUID != r.ConfigUID || s.Contract != r.After || s.CapActive || s.ReleasedAt.IsZero() || s.ReleasedAt.Before(r.After.ActivatedAt) || s.ReleasedAt.After(now) ||
		s.ReleaseReason != "quiet-window" && s.ReleaseReason != "lease-expired" {
		return nil
	}
	if s.ReleaseReason == "lease-expired" && now.Before(r.After.ExpiresAt) {
		return nil
	}
	ev := RecoveryEvent{Receipt: servingbudget.JournalName, Kind: string(model.ActionThrottle), Phase: r.Phase, Tenant: r.Namespace, PolicyNamespace: r.Namespace, PolicyName: r.Request.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.Request.Pod, TargetUID: r.Request.TargetUID, Outcome: "refused"}
	ev.Err = (throttleHandler{}).Rollback(ctx, ec, r.Request, r.OperationID)
	if ev.Err == nil {
		ev.Outcome, ev.Effect = "recovered", "expired-or-quiet-budget-restored"
	}
	return []RecoveryEvent{ev}
}
