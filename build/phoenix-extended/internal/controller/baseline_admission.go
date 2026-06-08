/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

// Package controller — the baselineAdmission validating webhook (cap#6, :9443,
// arch §3, decisions D6/D6g). SPLIT FAIL MODE: ADMISSION FAIL-CLOSED.
//
// baselineAdmission is a validating admission handler on the already-running :9443
// webhook server. For a Pod create/update governed by a WorkloadBaseline whose
// DriftPolicy.AdmissionEnforce=true, it DENIES (fail-CLOSED) a pod whose container
// image is:
//
//   - NOT digest-pinned (un-pinned: a tag, not Repository@sha256), OR
//   - drifted off the pinned baseline digest, OR
//   - unsigned/unverifiable when RequireSignature (does not verify against the
//     SignaturePolicy).
//
// This is the SYNCHRONOUS half of the split fail mode (D6): admission fails CLOSED
// so an unsigned/tampered image is never admitted. (The poll/detect side
// fails-to-cached-last-good — see the BaselineDriftReconciler.) When NO governing
// baseline applies (no matching WorkloadBaseline, or AdmissionEnforce=false), the
// handler ALLOWS — it is not a global gate, only the enrolled workloads are
// enforced.
//
// CAVEAT (D6/D11, carried in the denial message): signing proves PROVENANCE, not
// BENIGNITY. A validly-signed-but-backdoored upstream image still passes admission.
//
// LIVE REACHABILITY NOTE (documented honestly): a LOCALLY-run manager's webhook is
// hard for the kind apiserver to reach (host/WSL2 networking), so the live
// admission test is BEST-EFFORT. The HANDLER LOGIC is proven by unit tests
// (TestBaselineAdmission_*). The PRIMARY live proof of cap#6 is the
// reconciler-detect + Regenerate-restore path, which needs no webhook.
package controller

import (
	"context"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// baselineAdmissionPath is the path the ValidatingWebhookConfiguration points at.
const baselineAdmissionPath = "/validate-baseline-pod"

//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch

// BaselineAdmission is the validating admission handler. It reads WorkloadBaselines
// to decide which pods it governs and verifies their images against the pinned
// digests + SignaturePolicy.
type BaselineAdmission struct {
	client   client.Reader
	verifier BaselineVerifier
	decoder  admission.Decoder
}

// NewBaselineAdmission builds the handler. reader lists WorkloadBaselines + resolves
// public keys; verifier proves provenance; decoder decodes the admitted Pod.
func NewBaselineAdmission(reader client.Reader, verifier BaselineVerifier, decoder admission.Decoder) *BaselineAdmission {
	return &BaselineAdmission{client: reader, verifier: verifier, decoder: decoder}
}

// Handle implements admission.Handler. It is FAIL-CLOSED for governed,
// enforcement-on workloads and ALLOW for everything else.
func (a *BaselineAdmission) Handle(ctx context.Context, req admission.Request) admission.Response {
	// Only Pods are validated here.
	pod := &corev1.Pod{}
	if err := a.decoder.Decode(req, pod); err != nil {
		// A decode error must not silently allow a governed pod, but it also must not
		// wedge the whole apiserver for unrelated objects. Return an Errored response
		// (the apiserver treats this per the webhook's failurePolicy; our config sets
		// Fail for the governed-pod path).
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Find a governing WorkloadBaseline (by Selector) with AdmissionEnforce=true.
	wb, governed, err := a.governingBaseline(ctx, pod, req.Namespace)
	if err != nil {
		// Could not list baselines: FAIL-CLOSED only if we cannot determine governance
		// would be unsafe. Be conservative but non-wedging: deny with the reason (the
		// config's failurePolicy decides apiserver behavior). Denying on a list error
		// is the fail-closed choice for the trust gate.
		return admission.Denied(fmt.Sprintf("baselineAdmission: could not evaluate governing WorkloadBaselines (fail-closed): %v", err))
	}
	if !governed {
		// Not governed (no matching enforced baseline) -> ALLOW (not a global gate).
		return admission.Allowed("no enforced WorkloadBaseline governs this pod")
	}

	spec := wb.EffectiveBaselineSpec()
	// Index pins by container name.
	pinByContainer := map[string]amtdv1beta1.ImageDigest{}
	for _, p := range spec.ImageDigests {
		pinByContainer[p.ContainerName] = p
	}

	for i := range pod.Spec.Containers {
		c := pod.Spec.Containers[i]
		pin, pinned := pinByContainer[c.Name]
		if !pinned {
			// The baseline does not pin this container: not enforced for it -> skip.
			continue
		}

		// (1) UN-PINNED image check: the running image must be Repository@sha256:...
		_, observed := splitImageRef(c.Image)
		if observed == "" {
			return admission.Denied(denyMessage(wb.Name, c.Name, fmt.Sprintf("image %q is not digest-pinned (must be Repository@sha256:...)", c.Image)))
		}

		// (2) DRIFT check: the running digest must equal the pinned digest.
		if observed != pin.Digest {
			return admission.Denied(denyMessage(wb.Name, c.Name, fmt.Sprintf("image digest %q does not match the pinned baseline digest %q", observed, pin.Digest)))
		}

		// (3) SIGNATURE check: verify the pin against the SignaturePolicy. A positive
		// mismatch -> DENY. UNAVAILABILITY at admission also DENIES (fail-CLOSED: an
		// unverifiable image must never be admitted; this is the synchronous half of
		// the split fail mode, distinct from the poll side which caches last-good).
		if _, verr := a.verifier.VerifyImage(ctx, pin, spec.Signature); verr != nil {
			return admission.Denied(denyMessage(wb.Name, c.Name, fmt.Sprintf("image failed signature verification (fail-closed): %v", verr)))
		}
	}

	return admission.Allowed("all governed containers are signed + pinned to the verified baseline digest")
}

// governingBaseline returns the first enforced WorkloadBaseline whose Selector
// matches the pod, and whether any governs it.
func (a *BaselineAdmission) governingBaseline(ctx context.Context, pod *corev1.Pod, namespace string) (*amtdv1beta1.WorkloadBaseline, bool, error) {
	list := &amtdv1beta1.WorkloadBaselineList{}
	if err := a.client.List(ctx, list); err != nil {
		return nil, false, err
	}
	for i := range list.Items {
		wb := &list.Items[i]
		spec := wb.EffectiveBaselineSpec()
		if spec.DriftPolicy != nil && !spec.DriftPolicy.EffectiveAdmissionEnforce() {
			continue
		}
		// EffectiveAdmissionEnforce defaults true (nil DriftPolicy => enforce). Match by
		// selector against the pod labels.
		if wb.Spec.Selector == nil {
			continue
		}
		sel, err := labelSelectorMatches(wb.Spec.Selector, pod.Labels)
		if err != nil {
			return nil, false, err
		}
		if sel {
			return wb, true, nil
		}
	}
	return nil, false, nil
}

// denyMessage formats a fail-closed denial carrying the D6/D11 caveat.
func denyMessage(baseline, container, why string) string {
	return fmt.Sprintf("baselineAdmission DENIED (fail-closed) by WorkloadBaseline %q for container %q: %s. NOTE: %s",
		baseline, container, why, amtdv1beta1.VerificationBenignityCaveatMessage)
}

// labelSelectorMatches reports whether a metav1.LabelSelector matches the given
// pod labels. An empty selector matches nothing here (we never want an accidental
// cluster-wide enforcement match).
func labelSelectorMatches(ls *metav1.LabelSelector, podLabels map[string]string) (bool, error) {
	sel, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return false, err
	}
	if sel.Empty() {
		return false, nil
	}
	return sel.Matches(labels.Set(podLabels)), nil
}

// RegisterBaselineAdmission builds the handler from the manager's client/scheme and
// registers it on the existing :9443 webhook server at baselineAdmissionPath. The
// reader is the manager's client (cache-backed) so WorkloadBaseline lookups are
// cheap. It is best-effort reachable from the kind apiserver (see the live note).
func RegisterBaselineAdmission(mgr ctrl.Manager) error {
	reader := mgr.GetClient()
	verifier := NewBaselineVerifier(reader, "")
	decoder := admission.NewDecoder(mgr.GetScheme())
	handler := NewBaselineAdmission(reader, verifier, decoder)
	mgr.GetWebhookServer().Register(baselineAdmissionPath, &admission.Webhook{Handler: handler})
	return nil
}
