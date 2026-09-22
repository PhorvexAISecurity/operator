package defenders

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func init() { core.RegisterDefender(&blindTimer{}) }

// BlindRotationInterval is the DOCUMENTED, realistic-relative fixed rotation period
// for the blind timer arm. It is a SCALED-FOR-TEST value (real production periodic
// rotation is minutes-to-hours; the PRD cites ~hourly) chosen so the RELATIVE ordering
// is honest and not rigged: PX's risk-driven proactive floor (~6s) < a fast attacker's
// objective (~9s) < this blind interval (15s). A fixed cadence that rotates EVERYTHING
// slowly thus arrives too late on a fast attack and yields a high (≈interval) dwell on
// persistence, while PX rotates the HIGH-RISK pod early. The attacker speeds in the
// scenarios are scaled with this interval — the comparison measures timing STRUCTURE,
// not absolute seconds.
const BlindRotationInterval = 15 * time.Second

var targetedBlindRotationInterval = BlindRotationInterval

// blindTimer models R6's reactive design approximated as a BLIND fixed-interval
// rotation with NO telemetry/emitter (a pure TimeBasedTrigger). It caps dwell at
// the interval but cannot target on demand, so it disrupts scenarios only
// OPPORTUNISTICALLY — by landing a rotation during the attack window.
type blindTimer struct {
	eng timerEngine
}

func (b *blindTimer) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:                        "d-r6blindtimer",
		Description:                 "Blind fixed-interval rotation with no telemetry (TimeBasedTrigger approximation). Caps dwell at the interval; disrupts only opportunistically.",
		MeanRotationIntervalSeconds: BlindRotationInterval.Seconds(),
	}
}

func (b *blindTimer) Setup(ctx context.Context, env *core.Env) error {
	// Fixed (deterministic) cadence: every BlindRotationInterval.
	b.eng.nextDelay = func() time.Duration { return BlindRotationInterval }
	return nil
}

func (b *blindTimer) Start(ctx context.Context, env *core.Env) error {
	if scenario, ok := core.LookupScenario(env.ScenarioName); ok {
		if targeted, ok := scenario.(core.TargetedActionScenario); ok && targeted.UsesTargetedActionCoordination() {
			env.Log.Logf("d-r6blindtimer: armed for one exact coordinated target after application state is established")
			return nil
		}
	}
	env.Log.Logf("d-r6blindtimer: arming blind rotation every %s (no emitter)", BlindRotationInterval)
	b.eng.startEngine(ctx, env)
	return nil
}

func (b *blindTimer) CoordinateTargetedAction(ctx context.Context, env *core.Env, request core.TargetedActionRequest) (core.TargetedActionResult, error) {
	result := core.TargetedActionResult{
		SchemaVersion:         "phorvex.targeted-action-result.v1",
		Coordinator:           "d-r6blindtimer",
		StartedAtUTC:          time.Now().UTC().Format(time.RFC3339Nano),
		Disposition:           "unknown",
		TargetName:            request.TargetName,
		TargetUID:             request.TargetUID,
		TargetResourceVersion: request.TargetResourceVersion,
		RequestedGraceSeconds: request.RequestedGraceSeconds,
	}
	finish := func(disposition string, complete bool) core.TargetedActionResult {
		result.Disposition = disposition
		result.AttributionComplete = complete
		result.EndedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		return result
	}
	if request.Objective != env.ScenarioName || request.Namespace != env.Config.Namespace || request.TargetKind != "Pod" || request.TargetName == "" || request.TargetUID == "" || request.TargetResourceVersion == "" || request.OwnerKind != "ReplicaSet" || request.OwnerName == "" || request.OwnerUID == "" || request.TargetLabelKey != RotationTargetLabel || request.TargetLabelValue != "true" || request.RequestedGraceSeconds != 30 || request.AvailabilityPolicyName == "" || request.AvailabilityPolicyUID == "" || request.AvailabilityPolicyResourceVersion == "" || request.AvailabilitySelectorKey == "" || request.AvailabilitySelectorValue == "" || request.InitialMinAvailable != 2 || request.EligibleMinAvailable != 1 {
		return finish("invalid-request", false), errors.New("targeted timer request identity differs")
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineUTC)
	if err != nil || !deadline.After(time.Now()) || time.Until(deadline) < targetedBlindRotationInterval {
		return finish("invalid-request", false), errors.New("targeted timer request deadline cannot contain fixed cadence")
	}
	if err := env.Guard.AssertMutationAllowed(request.Namespace); err != nil {
		return finish("refused", false), err
	}
	uid := types.UID(request.TargetUID)
	pod, err := env.Kube.CoreV1().Pods(request.Namespace).Get(ctx, request.TargetName, metav1.GetOptions{})
	if err != nil || pod == nil || pod.UID != uid || pod.ResourceVersion != request.TargetResourceVersion || pod.DeletionTimestamp != nil || !exactControllerOwner(pod.OwnerReferences, request.OwnerKind, request.OwnerName, types.UID(request.OwnerUID)) || pod.Labels[request.TargetLabelKey] != "" {
		return finish("refused", false), errors.Join(err, errors.New("targeted timer pre-label identity differs"))
	}
	updated := pod.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	updated.Labels[request.TargetLabelKey] = request.TargetLabelValue
	updated, err = env.Kube.CoreV1().Pods(request.Namespace).Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil || updated == nil || updated.UID != uid || updated.ResourceVersion == "" {
		return finish("refused", false), errors.Join(err, errors.New("targeted timer exact label update failed"))
	}
	result.TargetResourceVersion = updated.ResourceVersion
	pdbRV, err := transitionTargetAvailabilityGuard(ctx, env, request)
	if err != nil {
		return finish("refused", false), err
	}
	result.AvailabilityPolicyResourceVersion = pdbRV
	select {
	case <-ctx.Done():
		return finish("unknown", false), fmt.Errorf("targeted timer cancelled: %w", ctx.Err())
	case <-time.After(targetedBlindRotationInterval):
	}
	current, err := env.Kube.CoreV1().Pods(request.Namespace).Get(ctx, request.TargetName, metav1.GetOptions{})
	if err != nil || current == nil || current.UID != uid || current.ResourceVersion != updated.ResourceVersion || current.DeletionTimestamp != nil || current.Labels[request.TargetLabelKey] != request.TargetLabelValue || !exactControllerOwner(current.OwnerReferences, request.OwnerKind, request.OwnerName, types.UID(request.OwnerUID)) {
		return finish("refused", false), errors.Join(err, errors.New("targeted timer pre-delete identity differs"))
	}
	rv := current.ResourceVersion
	grace := request.RequestedGraceSeconds
	env.Log.Command(fmt.Sprintf("kubectl delete pod %s -n %s --grace-period=%d --precondition-uid=%s --precondition-resource-version=%s", request.TargetName, request.Namespace, grace, uid, rv))
	err = env.Kube.CoreV1().Pods(request.Namespace).Delete(ctx, request.TargetName, metav1.DeleteOptions{GracePeriodSeconds: &grace, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
	if err != nil {
		return finish("failed", true), fmt.Errorf("targeted timer exact delete failed: %w", err)
	}
	at := time.Now().UTC()
	result.ActionAtUTC = at.Format(time.RFC3339Nano)
	b.eng.recordAction(at)
	return finish("dispatched-unconfirmed", true), nil
}

func exactControllerOwner(owners []metav1.OwnerReference, kind, name string, uid types.UID) bool {
	matches := 0
	for _, owner := range owners {
		if owner.Controller != nil && *owner.Controller {
			if owner.Kind != kind || owner.Name != name || owner.UID != uid {
				return false
			}
			matches++
		}
	}
	return matches == 1
}

func (b *blindTimer) Stop(ctx context.Context, env *core.Env) error {
	b.eng.stopEngine()
	return nil
}

func (b *blindTimer) Teardown(ctx context.Context, env *core.Env) error {
	b.eng.stopEngine()
	return nil
}

func (b *blindTimer) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	a := b.eng.actions()
	return len(a), a, nil
}
