/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * registry-rollback — the native image-integrity remediation for an AI supply-chain compromise
 * (a poisoned artifact/image is EXECUTING: the workload's RUNNING container image digest has
 * drifted from the owner-declared trusted pin). This handler resets the owning controller's
 * pod-template image back to the operator-TRUSTED pin carried on the owner's OWN annotation
 * (phorvex.ai/trusted-image-ref), so the controller rolls out clean Pods (running digest == pin).
 * It is the move that invalidates the "poisoned image executing" fact at the SOURCE: a generic
 * rotate respawns the SAME drifted image.
 *
 * Discipline (mirrors k8s-object-revert):
 *   - The write target is re-derived from the LIVE pod's top-level controller (ownership.
 *     ResolveStableWorkloadOwner), never from the flagging event.
 *   - The value it rolls TO is read from the LIVE controller's own trusted-pin annotation at
 *     dispatch, NEVER from the event's bytes — so a detector assertion can never steer what the
 *     workload is rolled to. Forward-only: undoing it would reintroduce the poisoned image.
 *   - It only ever matches a container whose image REPOSITORY equals the pin's repository (so a
 *     sidecar on a different image is never touched) and only patches containers that actually
 *     differ from the pin. A controller already on its pin is a confirmed idempotent no-effect.
 * Clean-room k8s.io API only.
 */

package actuator

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/ownership"
)

// TrustedImageRefAnnotation carries the OPERATOR-TRUSTED image pin on the owning controller. It is
// the only value registry-rollback will ever roll a workload TO; it is read from the live owner at
// dispatch and is never event-derived.
const TrustedImageRefAnnotation = "phorvex.ai/trusted-image-ref"

type registryRollbackHandler struct{}

func (registryRollbackHandler) Name() string { return string(model.ActionRegistryRollback) }

// imageRepo returns the repository portion of an image ref ("[registry[:port]/]repo"), stripping
// any ":tag" and "@digest". It is used to match the drifted container to the pin's repository so a
// co-located sidecar on a different image is never rewritten.
func imageRepo(img string) string {
	if i := strings.IndexByte(img, '@'); i >= 0 {
		img = img[:i]
	}
	slash := strings.LastIndexByte(img, '/')
	seg := img
	if slash >= 0 {
		seg = img[slash+1:]
	}
	if c := strings.IndexByte(seg, ':'); c >= 0 {
		if slash >= 0 {
			return img[:slash+1] + seg[:c]
		}
		return seg[:c]
	}
	return img
}

func (registryRollbackHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	refuse := func(reason string) (HandlerResult, error) {
		disposition := NoEffectRefused
		if reason == "target-already-gone" {
			disposition = NoEffectSatisfied
		}
		return HandlerResult{NoEffect: disposition, MutationKind: "none", Note: "registry-rollback not performed: " + reason}, nil
	}
	if ec.Reader == nil {
		return refuse("authoritative-reader-unavailable")
	}
	if ec.Client == nil {
		return refuse("mutation-client-unavailable")
	}
	if req.TargetUID == "" {
		return refuse("target-uid-unavailable")
	}
	if req.PolicyName == "" || req.PolicyUID == "" {
		return refuse("selecting-policy-identity-unavailable")
	}

	// Confirm the flagged Pod still exists with the exact selecting UID before acting.
	pod, present, err := getPod(ctx, ec.Reader, req.Namespace, req.Pod)
	if err != nil {
		return refuse("target-unavailable")
	}
	if !present {
		return refuse("target-already-gone")
	}
	if string(pod.UID) != req.TargetUID {
		return refuse("target-uid-mismatch")
	}

	// Re-derive the top-level controller from the LIVE pod, authoritatively — the flagging event
	// never chooses the write target. registry-rollback only resets Deployment-owned workloads.
	_, top, err := ownership.ResolveStableWorkloadOwner(ctx, ec.Reader, req.Namespace, req.Pod, req.TargetUID)
	if err != nil {
		return refuse("stable-owner-unavailable")
	}
	if top.Kind != "Deployment" || top.APIVersion != appsv1.SchemeGroupVersion.String() {
		return refuse("owner-is-not-a-deployment")
	}

	var dep appsv1.Deployment
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: top.Name}, &dep); err != nil {
		if apierrors.IsNotFound(err) {
			return refuse("target-already-gone")
		}
		return refuse("deployment-unavailable")
	}
	if string(dep.UID) != top.UID {
		return refuse("owner-uid-mismatch")
	}
	if dep.DeletionTimestamp != nil && !dep.DeletionTimestamp.IsZero() {
		return refuse("owner-being-deleted")
	}

	// The value we roll TO comes ONLY from the owner's own trusted-pin annotation, never the event.
	pin, ok := dep.Annotations[TrustedImageRefAnnotation]
	if !ok || strings.TrimSpace(pin) == "" {
		return refuse("owner-carries-no-trusted-image-pin")
	}
	pinRepo := imageRepo(pin)

	// Patch only containers whose image repository matches the pin's repository and whose image has
	// drifted from the pin. A sidecar on a different repository is never touched.
	var rolled []string
	for i := range dep.Spec.Template.Spec.Containers {
		c := &dep.Spec.Template.Spec.Containers[i]
		if imageRepo(c.Image) != pinRepo {
			continue
		}
		if c.Image == pin {
			continue // already on the pin
		}
		rolled = append(rolled, fmt.Sprintf("%s(%s->%s)", c.Name, c.Image, pin))
		c.Image = pin
	}
	if len(rolled) == 0 {
		// Either no container is on the pin's repository, or every matching container is already on
		// the pin: a confirmed idempotent no-effect (the clean state is already asserted).
		return HandlerResult{
			NoEffect:     NoEffectSatisfied,
			MutationKind: "none",
			Note:         "registry-rollback: owning Deployment already serves the trusted image pin; no new mitigation",
		}, nil
	}

	objTarget := objRef("Deployment", dep.Namespace, dep.Name)
	if err := ec.Client.Update(ctx, &dep); err != nil {
		if apierrors.IsConflict(err) {
			return HandlerResult{MutationKind: "none", Note: "registry-rollback: Deployment changed under us; will retry next tick"}, nil
		}
		return HandlerResult{}, fmt.Errorf("registry-rollback patch deployment %s/%s: %w", dep.Namespace, dep.Name, err)
	}
	return HandlerResult{
		Emitted:        true,
		MutationKind:   "forward-only",
		ObjectsTouched: []string{objTarget},
		Note:           fmt.Sprintf("registry-rollback: reset Deployment %s/%s pod-template image(s) to the operator-trusted pin %s [%s]", dep.Namespace, dep.Name, pin, strings.Join(rolled, ",")),
	}, nil
}

func init() { HandlerRegistry.Register(registryRollbackHandler{}) }
