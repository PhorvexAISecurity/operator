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

// Package controller — the BaselineDriftReconciler (cap#6, arch §3, decisions
// D6/D6g).
//
// THE RECONCILER EMITS, IT DOES NOT ACT (arch §3 / rule #1, locked). The
// BaselineDriftReconciler:
//
//   - RECORDS the baseline: verifies the pinned digests against the SignaturePolicy
//     and writes Status.LastVerifiedTime + PinnedDigests + the BaselineVerified
//     condition. On a registry/Rekor/key blip (ErrVerificationUnavailable) it sets
//     the VerificationUnavailable condition and REUSES the last verified digest
//     (PinnedDigests) — the SPLIT fail mode's poll-side fail-to-cached-last-good
//     (D6): a transient outage does NOT mass-flag drift.
//
//   - DETECTS drift on the baseline-governed pods (Selector) via the DriftDetector
//     (image-digest comparison surface) and, for each drift, EMITS a cluster-scoped
//     SecurityEvent{Rule.Type:"drift", Source:"FalcoIntegrator", Evidence}. The
//     matcher then routes that event to a Regenerate action (or, by DEFAULT,
//     Quarantine — D6g: auto-Regenerate is restart-loop-DoS-weaponizable). The
//     reconciler NEVER patches/deletes a pod or restores a workload itself — that
//     keeps the class-B/rule-#1 invariant provable.
//
//   - ALWAYS surfaces the VerificationBenignityCaveat condition (D6/D11): signing
//     proves provenance, not benignity.
//
// The SecurityEvent Source is "FalcoIntegrator" to match the arch §2.1/§5
// Regenerate Strategy[] expression {rule:{type:'drift',source:'FalcoIntegrator'}}
// so the existing exact fast-path matcher routes it without any normalization
// (the Source guard is emitter-native; here the BaselineDriftReconciler is the
// drift emitter peer of the Falco Container-Drift rules, D6).
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// driftSecurityEventSource is the Source the emitted drift SecurityEvent carries.
// It matches the arch §2.1/§5 Regenerate Strategy[] expression
// {rule:{type:'drift',source:'FalcoIntegrator'}} so the exact fast-path matcher
// routes the drift event with NO normalization (D6: the BaselineDriftReconciler is
// the drift emitter peer of the Falco Container-Drift rules; the Source guard is
// emitter-native and load-bearing).
const driftSecurityEventSource = "FalcoIntegrator"

// driftSecurityEventType is the Rule.Type the emitted drift SecurityEvent carries.
const driftSecurityEventType = "drift"

// maxRecentDriftRecords bounds WorkloadBaselineStatus.RecentDriftDetections (the
// long tail goes to k8s Events / SecurityEvents, not Status — arch §2.3).
const maxRecentDriftRecords = 10

// BaselineDriftReconciler reconciles a WorkloadBaseline: it records+verifies the
// pinned digests and emits drift SecurityEvents on the governed pods. It NEVER
// acts on a pod directly.
type BaselineDriftReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// OperatorNamespace defaults a namespace-less SignaturePolicy KeyRef when
	// resolving the verification key. Empty => "" (cluster-scoped lookups still work
	// for inline PEMs).
	OperatorNamespace string

	// verifier/detector are injectable for tests; nil => the kind defaults built
	// from this reconciler's client.
	verifier BaselineVerifier
	detector DriftDetector
}

//+kubebuilder:rbac:groups=amtd.r6security.com,resources=workloadbaselines,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=workloadbaselines/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=workloadbaselines/finalizers,verbs=update
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=securityevents,verbs=get;list;watch;create
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=secrets;configmaps,verbs=get;list;watch

// Reconcile records the baseline (verify pinned digests + write Status) then emits
// a drift SecurityEvent for each baseline-governed pod that drifted. It never acts
// on a pod.
func (r *BaselineDriftReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	wb := &amtdv1beta1.WorkloadBaseline{}
	if err := r.Get(ctx, req.NamespacedName, wb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	verifier := r.effectiveVerifier()
	detector := r.effectiveDetector(verifier)
	spec := wb.EffectiveBaselineSpec()

	// ---- RECORD + VERIFY the baseline (split fail mode). --------------------
	verifyState := r.verifyPinnedDigests(ctx, wb, spec, verifier, logger)

	// ---- DETECT drift on governed pods + EMIT (never act). -----------------
	emitted := 0
	if spec != nil && len(spec.ImageDigests) > 0 {
		pods, err := r.governedPods(ctx, wb)
		if err != nil {
			logger.Error(err, "BaselineDrift: failed to list governed pods", "workloadBaseline", wb.Name)
			return ctrl.Result{}, err
		}
		for i := range pods {
			drifts, err := detector.Detect(ctx, &pods[i], spec)
			if err != nil {
				logger.Error(err, "BaselineDrift: detect failed", "pod", pods[i].Name)
				continue
			}
			for _, d := range drifts {
				created, err := r.emitDriftEvent(ctx, wb, &pods[i], d, logger)
				if err != nil {
					logger.Error(err, "BaselineDrift: failed to emit drift SecurityEvent", "pod", pods[i].Name)
					continue
				}
				// Only count + record a NEWLY-created drift event. A re-reconcile that
				// finds the (idempotent) event already present must NOT re-increment
				// DriftDetections — otherwise the For(WorkloadBaseline) self-watch on our
				// own status write would hot-loop the counter (the live run observed this).
				if !created {
					continue
				}
				emitted++
				verifyState.driftRecords = append(verifyState.driftRecords, amtdv1beta1.DriftDetectionRecord{
					PodName:        d.PodName,
					ContainerName:  d.ContainerName,
					ObservedDigest: d.Evidence.ObservedDigest,
					ExpectedDigest: d.Evidence.ExpectedDigest,
					Time:           metav1.Now(),
				})
			}
		}
	}

	// ---- Write the recorded Status (verification + drift accounting). ------
	r.writeStatus(ctx, req.NamespacedName, wb, verifyState, emitted, logger)

	logger.Info("BaselineDrift reconciled (record+verify, detect+emit; does NOT act)",
		"workloadBaseline", wb.Name, "verified", verifyState.verified, "unavailable", verifyState.unavailable, "driftsEmitted", emitted)

	// Honor the optional DetectInterval poll (off by default, D6g).
	if spec != nil && spec.DriftPolicy != nil && spec.DriftPolicy.DetectInterval != nil && spec.DriftPolicy.DetectInterval.Duration > 0 {
		return ctrl.Result{RequeueAfter: spec.DriftPolicy.DetectInterval.Duration}, nil
	}
	return ctrl.Result{}, nil
}

// verifyState carries the outcome of verifying the pinned digests.
type verifyState struct {
	verified     bool                                  // at least one pin verified this cycle
	unavailable  bool                                  // a pin's verification was UNAVAILABLE (split fail mode)
	mismatch     bool                                  // a positive signature/digest mismatch was observed
	unpinnedWarn bool                                  // a pin/ref was not @sha256 pinned (soft warn)
	pinned       []string                              // the Repository@Digest set verified THIS cycle
	detail       string                                // human-readable summary
	driftRecords []amtdv1beta1.DriftDetectionRecord    // appended by the detect loop
}

// verifyPinnedDigests verifies every pinned ImageDigest against the SignaturePolicy
// and computes the verifyState. On unavailability it does NOT clear PinnedDigests
// (the caller reuses the cached last-good).
func (r *BaselineDriftReconciler) verifyPinnedDigests(ctx context.Context, wb *amtdv1beta1.WorkloadBaseline, spec *amtdv1beta1.BaselineSpec, verifier BaselineVerifier, logger logr.Logger) verifyState {
	st := verifyState{}
	if spec == nil || len(spec.ImageDigests) == 0 {
		st.detail = "no pinned ImageDigests"
		return st
	}
	for _, pin := range spec.ImageDigests {
		ref := pin.Repository + "@" + pin.Digest
		if _, dg := splitImageRef(ref); dg == "" || !isSha256Digest(pin.Digest) {
			st.unpinnedWarn = true
		}
		vi, err := verifier.VerifyImage(ctx, pin, spec.Signature)
		switch {
		case err == nil:
			st.verified = true
			st.pinned = append(st.pinned, ref)
		case isVerificationUnavailable(err):
			st.unavailable = true
			logger.Info("BaselineDrift: verification UNAVAILABLE for a pin; reusing last verified digest (split fail mode, fail-to-cached-last-good)",
				"workloadBaseline", wb.Name, "repository", pin.Repository, "reason", err.Error())
		default:
			st.mismatch = true
			logger.Info("BaselineDrift: positive signature/digest MISMATCH on a pin (verification failed)",
				"workloadBaseline", wb.Name, "repository", pin.Repository, "reason", err.Error())
		}
		_ = vi
	}
	st.detail = fmt.Sprintf("verified=%v unavailable=%v mismatch=%v pins=%d", st.verified, st.unavailable, st.mismatch, len(st.pinned))
	return st
}

// governedPods lists the pods matched by the baseline Selector (cluster-wide,
// across namespaces, since a WorkloadBaseline is cluster-scoped). nil Selector =>
// no pods.
func (r *BaselineDriftReconciler) governedPods(ctx context.Context, wb *amtdv1beta1.WorkloadBaseline) ([]corev1.Pod, error) {
	if wb.Spec.Selector == nil {
		return nil, nil
	}
	sel, err := metav1.LabelSelectorAsSelector(wb.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("invalid baseline selector: %w", err)
	}
	if sel.Empty() {
		// An empty selector would match everything; treat as "select nothing" to avoid
		// a cluster-wide accidental match.
		return nil, nil
	}
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, &client.ListOptions{LabelSelector: sel}); err != nil {
		return nil, err
	}
	return podList.Items, nil
}

// emitDriftEvent creates a cluster-scoped Type:"drift" SecurityEvent carrying the
// Evidence for one drifted pod/container. It is idempotent per (baseline,pod,
// observedDigest): the event name is a stable hash so a re-reconcile does not mint
// duplicate events. It returns created=true only when a NEW event was created (so
// the caller does not re-count an idempotent no-op). The reconciler does NOT act —
// the matcher routes this event.
func (r *BaselineDriftReconciler) emitDriftEvent(ctx context.Context, wb *amtdv1beta1.WorkloadBaseline, pod *corev1.Pod, d DriftResult, logger logr.Logger) (bool, error) {
	evName := driftEventName(wb.Name, pod.Namespace, pod.Name, d.ContainerName, d.Evidence.ObservedDigest)

	// Idempotence: if the event already exists, do not re-create it.
	existing := &amtdv1beta1.SecurityEvent{}
	if err := r.Get(ctx, client.ObjectKey{Name: evName}, existing); err == nil {
		logger.V(1).Info("BaselineDrift: drift SecurityEvent already exists; idempotent no-op", "event", evName, "pod", pod.Name)
		return false, nil
	} else if !errors.IsNotFound(err) {
		return false, err
	}

	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			Name: evName,
			Labels: map[string]string{
				"amtd.r6security.com/workload-baseline": wb.Name,
			},
		},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets: []string{pod.Namespace + "/" + pod.Name},
			Rule: amtdv1beta1.Rule{
				Type:        driftSecurityEventType,
				ThreatLevel: "high",
				Source:      driftSecurityEventSource,
			},
			Description: fmt.Sprintf("baseline drift detected by WorkloadBaseline %q: %s", wb.Name, d.Evidence.Detail),
			Evidence: &amtdv1beta1.DriftEvidence{
				ObservedDigest: d.Evidence.ObservedDigest,
				ExpectedDigest: d.Evidence.ExpectedDigest,
				Detail:         d.Evidence.Detail,
			},
		},
	}
	if err := r.Create(ctx, ev); err != nil {
		if errors.IsAlreadyExists(err) {
			return false, nil
		}
		return false, err
	}
	logger.Info("BaselineDrift: emitted Type:'drift' SecurityEvent with Evidence (matcher routes it; reconciler does NOT act)",
		"event", evName, "pod", pod.Name, "observed", d.Evidence.ObservedDigest, "expected", d.Evidence.ExpectedDigest)
	return true, nil
}

// writeStatus records the verification + drift accounting on the WorkloadBaseline
// Status. It re-reads first (avoid clobbering a concurrent LastRegeneration write).
// On the split fail mode it reuses the cached last-good PinnedDigests.
func (r *BaselineDriftReconciler) writeStatus(ctx context.Context, key client.ObjectKey, observed *amtdv1beta1.WorkloadBaseline, st verifyState, emitted int, logger logr.Logger) {
	fresh := &amtdv1beta1.WorkloadBaseline{}
	if err := r.Get(ctx, key, fresh); err != nil {
		logger.Error(err, "BaselineDrift: failed to re-read WorkloadBaseline for status", "workloadBaseline", key.Name)
		return
	}
	before := fresh.Status.DeepCopy()
	fresh.Status.ObservedGeneration = fresh.Generation

	// Verification accounting + the split fail mode. Advance LastVerifiedTime only
	// when the verified pinned-digest set CHANGED (or was never set) — re-stamping
	// metav1.Now() every reconcile would churn the status and, via the
	// For(WorkloadBaseline) self-watch, hot-loop the reconciler (observed live).
	if st.verified && !st.mismatch {
		if fresh.Status.LastVerifiedTime.IsZero() || !stringSlicesEqual(fresh.Status.PinnedDigests, st.pinned) {
			fresh.Status.LastVerifiedTime = metav1.Now()
		}
		fresh.Status.PinnedDigests = st.pinned
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               amtdv1beta1.ConditionBaselineVerified,
			Status:             metav1.ConditionTrue,
			Reason:             "PinnedDigestsVerified",
			Message:            "The pinned digests verified against the SignaturePolicy (key-based, offline-capable).",
			ObservedGeneration: fresh.Generation,
		})
	}
	if st.unavailable {
		// FAIL-TO-CACHED-LAST-GOOD: do NOT advance LastVerifiedTime/PinnedDigests; keep
		// the last verified set so a transient outage does not mass-flag drift (D6).
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               amtdv1beta1.ConditionVerificationUnavailable,
			Status:             metav1.ConditionTrue,
			Reason:             "RegistryOrKeyUnavailable",
			Message:            "Signature verification was temporarily unavailable (registry/Rekor/key blip); reusing the last verified digest (fail-to-cached-last-good). This is NOT drift.",
			ObservedGeneration: fresh.Generation,
		})
	} else {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, amtdv1beta1.ConditionVerificationUnavailable)
	}
	if st.mismatch {
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               amtdv1beta1.ConditionSignatureMismatch,
			Status:             metav1.ConditionTrue,
			Reason:             "SignatureVerificationFailed",
			Message:            "A pinned digest's signature did not verify against the trusted key (positive provenance failure).",
			ObservedGeneration: fresh.Generation,
		})
	} else {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, amtdv1beta1.ConditionSignatureMismatch)
	}
	if st.unpinnedWarn {
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               amtdv1beta1.ConditionDigestUnpinnedWarning,
			Status:             metav1.ConditionTrue,
			Reason:             "ImageNotDigestPinned",
			Message:            "A baseline image reference is not pinned by @sha256 digest (soft warn).",
			ObservedGeneration: fresh.Generation,
		})
	} else {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, amtdv1beta1.ConditionDigestUnpinnedWarning)
	}

	// ALWAYS surface the D6/D11 provenance!=benignity caveat.
	meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
		Type:               amtdv1beta1.ConditionVerificationBenignityCaveat,
		Status:             metav1.ConditionTrue,
		Reason:             "ProvenanceNotBenignity",
		Message:            amtdv1beta1.VerificationBenignityCaveatMessage,
		ObservedGeneration: fresh.Generation,
	})

	// Drift accounting.
	if emitted > 0 {
		fresh.Status.DriftDetections += emitted
		fresh.Status.RecentDriftDetections = appendBoundedDrift(fresh.Status.RecentDriftDetections, st.driftRecords, maxRecentDriftRecords)
	}

	// Skip the write entirely when nothing changed: the For(WorkloadBaseline)
	// self-watch fires on our own status writes, so an unconditional update would
	// hot-loop the reconciler (observed live as DriftDetections inflation).
	if apiequality.Semantic.DeepEqual(before, &fresh.Status) {
		return
	}

	if err := r.Status().Update(ctx, fresh); err != nil {
		logger.Error(err, "BaselineDrift: failed to write status", "workloadBaseline", fresh.Name)
	}
}

// stringSlicesEqual reports whether two string slices are element-wise equal.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// appendBoundedDrift appends the new drift records and bounds the slice to cap.
func appendBoundedDrift(existing, add []amtdv1beta1.DriftDetectionRecord, cap int) []amtdv1beta1.DriftDetectionRecord {
	out := append(existing, add...)
	if len(out) > cap {
		out = out[len(out)-cap:]
	}
	return out
}

func (r *BaselineDriftReconciler) effectiveVerifier() BaselineVerifier {
	if r.verifier != nil {
		return r.verifier
	}
	return NewBaselineVerifier(r.Client, r.OperatorNamespace)
}

func (r *BaselineDriftReconciler) effectiveDetector(v BaselineVerifier) DriftDetector {
	if r.detector != nil {
		return r.detector
	}
	return NewDriftDetector(v)
}

// SetupWithManager wires the reconciler. It watches WorkloadBaselines; the optional
// DetectInterval drives requeue (off by default). Pods are listed on demand (not
// owned), so no Owns() — the reconciler does not manage pod lifecycle.
func (r *BaselineDriftReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&amtdv1beta1.WorkloadBaseline{}).
		Named("baselinedrift").
		Complete(r)
}

// driftEventName builds a stable, idempotent SecurityEvent name for a drift on a
// (baseline,pod,container,observedDigest) so a re-reconcile does not mint
// duplicate events. It is hashed + truncated to a DNS-1123 safe name.
func driftEventName(baseline, ns, pod, container, observed string) string {
	h := sha256.Sum256([]byte(baseline + "|" + ns + "|" + pod + "|" + container + "|" + observed))
	return "drift-" + hex.EncodeToString(h[:])[:16]
}

// isSha256Digest reports whether s looks like a sha256:<hex> digest.
func isSha256Digest(s string) bool {
	const prefix = "sha256:"
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return false
	}
	_, err := hex.DecodeString(s[len(prefix):])
	return err == nil
}

// isVerificationUnavailable branches the split fail mode: a wrapped
// ErrVerificationUnavailable means the poll-side fail-to-cached-last-good.
func isVerificationUnavailable(err error) bool {
	return stderrors.Is(err, ErrVerificationUnavailable)
}
