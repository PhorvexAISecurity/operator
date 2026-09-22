package defenders

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var targetedAvailabilityPollInterval = 250 * time.Millisecond

func transitionTargetAvailabilityGuard(ctx context.Context, env *core.Env, request core.TargetedActionRequest) (string, error) {
	if request.AvailabilityPolicyName == "" || request.AvailabilityPolicyUID == "" || request.AvailabilityPolicyResourceVersion == "" || request.AvailabilitySelectorKey == "" || request.AvailabilitySelectorValue == "" || request.InitialMinAvailable != 2 || request.EligibleMinAvailable != 1 {
		return "", errors.New("targeted availability request identity or fixed floor differs")
	}
	if err := env.Guard.AssertMutationAllowed(request.Namespace); err != nil {
		return "", err
	}
	pdbs := env.Kube.PolicyV1().PodDisruptionBudgets(request.Namespace)
	current, err := pdbs.Get(ctx, request.AvailabilityPolicyName, metav1.GetOptions{})
	if err != nil || !exactTargetAvailability(current, request, request.AvailabilityPolicyResourceVersion, request.InitialMinAvailable, 2, 2, 0) {
		return "", errors.Join(err, errors.New("targeted availability floor differs before transition"))
	}
	updated := current.DeepCopy()
	minimum := intstr.FromInt(request.EligibleMinAvailable)
	updated.Spec.MinAvailable = &minimum
	updated, err = pdbs.Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil || updated == nil || updated.UID != current.UID || updated.ResourceVersion == "" || updated.ResourceVersion == current.ResourceVersion || updated.Spec.MinAvailable == nil || updated.Spec.MinAvailable.Type != intstr.Int || int(updated.Spec.MinAvailable.IntVal) != request.EligibleMinAvailable {
		return "", errors.Join(err, errors.New("targeted availability floor update returned a different identity or unchanged version"))
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		observed, getErr := pdbs.Get(ctx, request.AvailabilityPolicyName, metav1.GetOptions{})
		if getErr == nil && exactTargetAvailability(observed, request, "", request.EligibleMinAvailable, 2, 1, 1) && observed.Generation == updated.Generation && observed.ResourceVersion != request.AvailabilityPolicyResourceVersion {
			return observed.ResourceVersion, nil
		}
		if getErr != nil {
			return "", fmt.Errorf("read targeted availability floor after update: %w", getErr)
		}
		if time.Now().After(deadline) {
			return "", errors.New("targeted availability floor did not converge to exact 2/1 eligible state")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(targetedAvailabilityPollInterval):
		}
	}
}

func exactTargetAvailability(pdb *policyv1.PodDisruptionBudget, request core.TargetedActionRequest, resourceVersion string, minimum, currentHealthy, desiredHealthy, disruptionsAllowed int) bool {
	return pdb != nil &&
		pdb.Name == request.AvailabilityPolicyName &&
		pdb.Namespace == request.Namespace &&
		pdb.UID == types.UID(request.AvailabilityPolicyUID) &&
		pdb.ResourceVersion != "" &&
		(resourceVersion == "" || pdb.ResourceVersion == resourceVersion) &&
		pdb.DeletionTimestamp == nil &&
		pdb.Spec.MinAvailable != nil &&
		pdb.Spec.MinAvailable.Type == intstr.Int &&
		int(pdb.Spec.MinAvailable.IntVal) == minimum &&
		pdb.Spec.Selector != nil &&
		len(pdb.Spec.Selector.MatchLabels) == 1 &&
		pdb.Spec.Selector.MatchLabels[request.AvailabilitySelectorKey] == request.AvailabilitySelectorValue &&
		len(pdb.Spec.Selector.MatchExpressions) == 0 &&
		pdb.Status.ObservedGeneration == pdb.Generation &&
		int(pdb.Status.ExpectedPods) == 2 &&
		int(pdb.Status.CurrentHealthy) == currentHealthy &&
		int(pdb.Status.DesiredHealthy) == desiredHealthy &&
		int(pdb.Status.DisruptionsAllowed) == disruptionsAllowed
}
