/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"context"
	"os"
	"strings"
	"time"

	core "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/servingbudget"
	amtd "github.com/r6security/phoenix/api/v1beta1"
)

// scopedServingEventTrust is the cost-load detector's dedicated trust route. The
// fixture detector is NEVER a global allowlist member: both its admitted identity AND
// the rule/target/UID/source/limiter-sha/proxy-image must match, so no other generic
// trusted detector can assert the serving-cost-harvest vector, and this detector cannot
// assert any other vector. Trust here is a gate only; servingbudget.Validate is the
// authority that re-reads the live limiter and policy epoch before cover is awarded.
func scopedServingEventTrust(ctx context.Context, r client.Reader, e *amtd.SecurityEvent, now time.Time, inventories ...map[string]string) string {
	if e.Annotations[eventtrust.CreatorIdentityAnnotation] != servingbudget.DetectorIdentity ||
		e.Spec.Rule.Type != model.AttackVectorServingCostHarvest || e.Spec.Rule.Source != servingbudget.Source || e.Spec.Rule.ThreatLevel != "high" ||
		len(e.Spec.Targets) != 1 || !strings.HasPrefix(e.Spec.Targets[0], "costbench-opus/cost-target-") ||
		e.CreationTimestamp.IsZero() || e.DeletionTimestamp != nil || e.CreationTimestamp.Time.After(now) || now.Sub(e.CreationTimestamp.Time) >= servingbudget.Horizon {
		return eventtrust.TrustUntrusted
	}
	o, err := servingbudget.ParseObservation(e.Annotations[servingbudget.Annotation])
	if err != nil || o.PolicyName != "cost-defense" || o.LimiterSourceSHA256 != os.Getenv("PHORVEX_THROTTLE_SOURCE_SHA256") ||
		!servingbudget.SHA(o.LimiterSourceSHA256) || !servingbudget.ValidImage(os.Getenv("PHORVEX_THROTTLE_PROXY_IMAGE")) ||
		o.ObservedAt.After(now) || now.Sub(o.ObservedAt) >= servingbudget.Horizon || e.Annotations[model.ConsoleTargetPodUIDAnnotation] != o.TargetPodUID {
		return eventtrust.TrustUntrusted
	}
	key := e.Spec.Targets[0]
	uid := ""
	if len(inventories) > 0 && inventories[0] != nil {
		uid = inventories[0][key]
	}
	if uid == "" {
		var p core.Pod
		if r.Get(ctx, client.ObjectKey{Namespace: "costbench-opus", Name: strings.TrimPrefix(key, "costbench-opus/")}, &p) == nil && p.Labels["app"] == "cost-target" {
			uid = string(p.UID)
		}
	}
	if uid == "" || uid != o.TargetPodUID {
		return eventtrust.TrustUntrusted
	}
	return eventtrust.TrustTrusted
}

// bindServingRateBudgetObservation attaches the authoritative serving-rate-budget
// witness to the Pod ONLY when a trusted cost-load event carries an observation that
// (a) names THIS exact Pod UID and its single controller, (b) is fresh within the
// detector horizon measured on the snapshot clock, and (c) survives the full live
// limiter/policy-epoch re-validation. Ambiguous scope/epoch assertions across repeated
// fresh events abort the bind. Absent all of this the Pod keeps no observation, so the
// engine never selects THROTTLE for a workload that is not actually being cost-harvested
// through an enforceable, installed limiter.
func bindServingRateBudgetObservation(ctx context.Context, r client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.ServingRateBudgetObservation = nil
	var chosen *model.ServingRateBudgetObservation
	var snapshotNow time.Time
	for _, e := range events {
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorServingCostHarvest || e.CreatorIdentity != servingbudget.DetectorIdentity || e.UID == "" || e.Name == "" || e.TimestampMissing || e.Age < 0 || e.Age >= servingbudget.Horizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		now := e.CreatedAt.Add(e.Age) // Snapshot.Now, never wall time during replay.
		o, err := servingbudget.ParseObservation(e.ServingRateBudgetRaw)
		if err != nil || o.TargetPodUID != p.UID || o.ControllerUID != p.ControllerUID || o.ObservedAt.After(now) || o.ObservedAt.After(e.CreatedAt.Add(time.Second)) || now.Sub(o.ObservedAt) >= servingbudget.Horizon {
			continue
		}
		o.EventName, o.EventUID, o.CreatorIdentity = e.Name, e.UID, e.CreatorIdentity
		// Reject ambiguous scope/epoch assertions before any API reads. Fresh repeated
		// assertions are normal; only the newest can authorize the current snapshot.
		if chosen != nil && (chosen.OffendingCallerScope != o.OffendingCallerScope || chosen.LimiterBootID != o.LimiterBootID || chosen.PolicyUID != o.PolicyUID || chosen.PolicyGeneration != o.PolicyGeneration) {
			return
		}
		if chosen == nil || o.ObservedAt.After(chosen.ObservedAt) || o.ObservedAt.Equal(chosen.ObservedAt) && o.EventName > chosen.EventName {
			chosen, snapshotNow = o, now
		}
	}
	if chosen == nil {
		return
	}
	if _, err := servingbudget.Validate(ctx, r, p.Namespace, p.Name, chosen, snapshotNow); err == nil {
		p.ServingRateBudgetObservation = chosen
	}
}
