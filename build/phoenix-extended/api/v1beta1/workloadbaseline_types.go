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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadBaseline is the cap#6 "Immutable Image Registry" as a distinct,
// cluster-scoped, GitOps-friendly kind (arch §2.4 item 3, §3 cap#6, decisions
// D6/D6g). It is the standalone home of the signed-baseline drift-self-heal trust
// surface.
//
// SCOPE = CLUSTER-SCOPED (arch §2.4 item 3): a baseline governs workloads across
// namespaces and is operator-team trust policy, corroborated by SecurityEvent
// itself being cluster-scoped (the integrator-written trust object). The AMTD
// carries only a name-only BaselineRef to it.
//
// REFERENCES ONLY — NEVER TRUST-ROOT SECRET MATERIAL (D6g, locked). The
// WorkloadBaseline holds the pinned ImageDigests[], the SignaturePolicy
// REFERENCES (a PublicKeyRef pointing at a Secret/ConfigMap, a RekorURL, keyless
// identity), and registry references — it NEVER embeds the trust-root private key
// or the signing secret. The trust root lives in the external offline-signed
// registry. This is the load-bearing safety property: tampering the in-cluster
// WorkloadBaseline object cannot make self-heal restore malicious state, because
// the restorer VERIFIES the target digest against the SignaturePolicy
// (verify-before-recreate) using a key resolved from a separately-RBAC'd Secret.
//
// THE D6/D11 CAVEAT (carried honestly, locked): signing proves PROVENANCE /
// INTEGRITY (the image was signed by the trusted key and the digest is pinned),
// NOT BENIGNITY. A validly-signed-but-backdoored upstream image — the
// SolarWinds/SUNBURST shape — still passes verification. The verifier is a
// supply-chain *provenance* gate, not a malware scanner. This is reproduced in
// docs, in a VerificationBenignityCaveat Status condition, and in the Phase-5
// report. The default OnDrift is Quarantine (NOT auto-Regenerate) precisely
// because auto-replace-from-baseline is weaponizable into a restart-loop DoS
// (D6g).

// OnDriftAction enumerates the response the matcher routes a drift SecurityEvent
// to. NOTE the BaselineDriftReconciler itself NEVER acts — it only EMITS a
// Type:"drift" SecurityEvent carrying Evidence; the matcher then selects the
// OnDriftAction-shaped Strategy[] entry. OnDrift is the operator's declared
// DEFAULT preference recorded on the baseline; the actual action is still a
// Strategy[] rule (rule #1).
//
// +kubebuilder:validation:Enum=Regenerate;Quarantine;AlertOnly;Block
type OnDriftAction string

const (
	// OnDriftRegenerate restores the workload from the signed baseline. It is
	// fully supported but inherits the D2 one-shot + D22 guards + D24 budget.
	// It is NOT the default because auto-replace is restart-loop-DoS-weaponizable
	// (D6g).
	OnDriftRegenerate OnDriftAction = "Regenerate"
	// OnDriftQuarantine is the DEFAULT (D6g): deny-all NetworkPolicy + alert on a
	// drift, leaving remediation to a human/GitOps rather than auto-replacing.
	OnDriftQuarantine OnDriftAction = "Quarantine"
	// OnDriftAlertOnly emits the drift SecurityEvent + Evidence and takes no
	// containment action (detection-only).
	OnDriftAlertOnly OnDriftAction = "AlertOnly"
	// OnDriftBlock leans on the synchronous baselineAdmission webhook (fail-CLOSED)
	// to deny the drifted image at admission; the poll path stays advisory.
	OnDriftBlock OnDriftAction = "Block"
)

// HardeningResetScope bounds what a Regenerate's ResetHardeningProfile resets
// (D6g (e)). PodProfileOnly (default) resets pod-local Seccomp/AppArmor/
// securityContext to baseline; IncludeRBAC additionally resets RBAC RoleBindings
// (opt-in, deferred-by-default due to blast radius).
//
// +kubebuilder:validation:Enum=PodProfileOnly;IncludeRBAC
type HardeningResetScope string

const (
	// HardeningResetPodProfileOnly is the DEFAULT: reset Seccomp/AppArmor +
	// securityContext to baseline (pod-local).
	HardeningResetPodProfileOnly HardeningResetScope = "PodProfileOnly"
	// HardeningResetIncludeRBAC additionally resets RBAC RoleBindings (opt-in).
	HardeningResetIncludeRBAC HardeningResetScope = "IncludeRBAC"
)

// Baseline/drift Status condition type constants (arch §2.3 Conditions list +
// D6). They live on WorkloadBaselineStatus.Conditions (and the AMTD Conditions
// list documents VerificationUnavailable too).
const (
	// ConditionBaselineVerified=True means the pinned digests were verified against
	// the SignaturePolicy at LastVerifiedTime.
	ConditionBaselineVerified = "BaselineVerified"
	// ConditionVerificationUnavailable=True is the SPLIT-fail-mode poll-side signal
	// (D6): a registry/Rekor/key blip made verification temporarily impossible, so
	// the reconciler reused the last verified digest (fail-to-cached-last-good)
	// rather than mass-flagging drift. It is NOT a drift.
	ConditionVerificationUnavailable = "VerificationUnavailable"
	// ConditionSignatureMismatch=True means a positive signature/digest mismatch was
	// observed (a real verification FAILURE, distinct from unavailability).
	ConditionSignatureMismatch = "SignatureMismatch"
	// ConditionDigestUnpinnedWarning=True is the soft warn (D6) that a baseline image
	// reference is not pinned by @sha256 digest.
	ConditionDigestUnpinnedWarning = "DigestUnpinnedWarning"
	// ConditionVerificationBenignityCaveat is ALWAYS surfaced (informational) to carry
	// the D6/D11 caveat in cluster state: signing proves provenance, not benignity.
	ConditionVerificationBenignityCaveat = "VerificationBenignityCaveat"
)

// VerificationBenignityCaveatMessage is the locked D6/D11 caveat text surfaced on
// the always-present VerificationBenignityCaveat condition + the admission denial
// audit. Kept as a single constant so docs, Status and the webhook stay identical.
const VerificationBenignityCaveatMessage = "Signature verification proves PROVENANCE/INTEGRITY (the image was signed by the trusted key and the digest is pinned), NOT BENIGNITY: a validly-signed-but-backdoored upstream image (SolarWinds/SUNBURST shape) still passes. The WorkloadBaseline holds references only, so tampering the in-cluster object cannot make self-heal restore malicious state; default OnDrift=Quarantine (not auto-Regenerate)."

// KeyRef references the verification PUBLIC key material. It is a REFERENCE, never
// the private/trust-root key (D6g): the public key lives in a Secret or ConfigMap
// the operator controls (separately RBAC'd from the WorkloadBaseline), or is an
// inline PEM for air-gapped/test convenience. Exactly one of the three is used,
// in the precedence InlinePEM > SecretRef > ConfigMapRef.
type KeyRef struct {
	// +kubebuilder:validation:Optional
	// SecretRef names a Secret (namespace/name) whose Key entry holds the PEM
	// public key. Namespace empty => the operator namespace at resolve time.
	SecretRef *ObjectFieldRef `json:"secretRef,omitempty"`

	// +kubebuilder:validation:Optional
	// ConfigMapRef names a ConfigMap (namespace/name) whose Key entry holds the PEM
	// public key.
	ConfigMapRef *ObjectFieldRef `json:"configMapRef,omitempty"`

	// +kubebuilder:validation:Optional
	// InlinePEM is a PEM-encoded public key carried inline. This is a PUBLIC key
	// (verification only), so inlining it does NOT embed trust-root secret material;
	// it is the offline/air-gapped/test-friendly form. Takes precedence when set.
	InlinePEM string `json:"inlinePEM,omitempty"`
}

// ObjectFieldRef names a Secret/ConfigMap key holding PEM key material.
type ObjectFieldRef struct {
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +kubebuilder:validation:Optional
	// Key is the data key holding the PEM (default "cosign.pub").
	Key string `json:"key,omitempty"`
}

// KeylessIdentity reserves the cosign/Fulcio keyless (OIDC) identity seam (D6).
// It is a documented PRODUCTION extension behind the BaselineVerifier interface —
// the kind realization is key-based (stdlib crypto over the pinned digest). It is
// declared so a SignaturePolicy can express it and a future verifier can honor it
// without an API break; the kind verifier records VerificationUnavailable rather
// than silently passing if RequireSignature && only a KeylessIdentity is given.
type KeylessIdentity struct {
	// +kubebuilder:validation:Optional
	// Issuer is the expected OIDC issuer (e.g. https://token.actions.githubusercontent.com).
	Issuer string `json:"issuer,omitempty"`
	// +kubebuilder:validation:Optional
	// SubjectRegexp is the expected certificate-identity SAN regexp.
	SubjectRegexp string `json:"subjectRegexp,omitempty"`
}

// SignaturePolicy is the cap#6 verification policy (D6). DEFAULT realization is
// cosign KEY-BASED over the pinned DIGEST (offline-capable): the kind
// BaselineVerifier verifies an ecdsa/ed25519 signature over the digest string
// using PublicKeyRef. Keyless (Fulcio/Rekor) is a documented production extension
// behind the interface (RekorURL + KeylessIdentity reserve that seam).
type SignaturePolicy struct {
	// +kubebuilder:validation:Optional
	// PublicKeyRef references the verification public key (Secret/ConfigMap/inline
	// PEM). nil + RequireSignature=true => verification is UNAVAILABLE (the kind
	// verifier cannot key-verify without a key) and the baseline is treated
	// fail-to-cached-last-good with a VerificationUnavailable condition.
	PublicKeyRef *KeyRef `json:"publicKeyRef,omitempty"`

	// +kubebuilder:validation:Optional
	// KeylessIdentity reserves the cosign keyless (OIDC) production seam (see type).
	KeylessIdentity *KeylessIdentity `json:"keylessIdentity,omitempty"`

	// +kubebuilder:validation:Optional
	// RekorURL is the transparency-log URL for keyless/online verification
	// (production extension; the kind key-based path does not contact Rekor).
	RekorURL string `json:"rekorURL,omitempty"`

	// +kubebuilder:validation:Optional
	// RequireSignature, when true, REJECTS an unsigned/unverifiable image (admission
	// fail-CLOSED; verify-before-recreate refuses). Code default TRUE via
	// EffectiveRequireSignature() (D6). nil => true.
	RequireSignature *bool `json:"requireSignature,omitempty"`
}

// ImageDigest pins one container's golden image to an immutable Repository@Digest
// (D6g (a)). It is a REFERENCE into the external signed registry; no image bytes
// or key material are stored.
type ImageDigest struct {
	// +kubebuilder:validation:Required
	// ContainerName is the container the pin applies to (matches the running pod's
	// container name and the owner template).
	ContainerName string `json:"containerName"`

	// +kubebuilder:validation:Required
	// Repository is the immutable image repository (e.g. nvcr.io/nim/secure-nim).
	Repository string `json:"repository"`

	// +kubebuilder:validation:Required
	// Digest is the pinned content digest (e.g. sha256:abc...). The golden reference
	// is Repository@Digest. The drift surface compares the running image digest to
	// this (D6 digest+allowlist surface, NOT full PodSpec).
	Digest string `json:"digest"`

	// +kubebuilder:validation:Optional
	// Signature is the detached signature over the Digest the kind key-based verifier
	// checks against the SignaturePolicy PublicKeyRef. Faithful to cosign key-based
	// (a signature over the image digest), but carried inline on the pin so kind can
	// verify WITHOUT a registry/Rekor. Base64-encoded (std encoding). Empty => the
	// image is unsigned (RequireSignature rejects it).
	Signature string `json:"signature,omitempty"`
}

// DriftPolicy controls drift detection cadence + the default response (D6g (d)).
type DriftPolicy struct {
	// +kubebuilder:validation:Optional
	// DetectInterval is the OPTIONAL periodic re-verify/re-detect poll period. nil/0
	// => poll disabled (off by default, D6g); detection then rides admission + Falco
	// drift events. When set, the reconciler requeues after this interval.
	DetectInterval *metav1.Duration `json:"detectInterval,omitempty"`

	// +kubebuilder:validation:Optional
	// OnDrift is the DEFAULT response preference (Regenerate|Quarantine|AlertOnly|
	// Block). Code default Quarantine via EffectiveOnDrift() (D6g: auto-Regenerate is
	// restart-loop-DoS-weaponizable). The actual action is still a Strategy[] rule.
	OnDrift OnDriftAction `json:"onDrift,omitempty"`

	// +kubebuilder:validation:Optional
	// AdmissionEnforce gates whether the baselineAdmission webhook denies
	// unsigned/unverifiable/un-pinned images (fail-CLOSED) for this baseline. Code
	// default TRUE via EffectiveAdmissionEnforce() (D6g). nil => true.
	AdmissionEnforce *bool `json:"admissionEnforce,omitempty"`

	// +kubebuilder:validation:Optional
	// ResetHardeningProfile bounds a Regenerate's hardening reset
	// (PodProfileOnly|IncludeRBAC). Code default PodProfileOnly via
	// EffectiveResetHardeningProfile() (D6g (e)).
	ResetHardeningProfile HardeningResetScope `json:"resetHardeningProfile,omitempty"`
}

// BaselineSpec is the cap#6 digest-pin minimum, embedded on AMTDSpec AND reused as
// the body of a standalone WorkloadBaseline (arch §2.4 item 3 + the embedded
// block). It holds REFERENCES only (pinned digests, the SignaturePolicy refs, an
// optional PodSpec snapshot ref) — never trust-root secret material (D6g).
type BaselineSpec struct {
	// +kubebuilder:validation:Optional
	// +listType=atomic
	// ImageDigests is the per-container pinned golden Repository@Digest set (D6g (a)).
	ImageDigests []ImageDigest `json:"imageDigests,omitempty"`

	// +kubebuilder:validation:Optional
	// Signature is the verification policy (cosign key-based default, D6). nil => no
	// signature enforcement (digest-allowlist-only; the DigestUnpinnedWarning/benignity
	// caveats still apply).
	Signature *SignaturePolicy `json:"signature,omitempty"`

	// +kubebuilder:validation:Optional
	// PodSpecSnapshotRef references a Phoenix-owned PodSpec snapshot (e.g. a ConfigMap)
	// used to restore curated non-image fields (D6g (b)). Reference only; the kind
	// restorer restores the pinned image (the primary golden state).
	PodSpecSnapshotRef *LocalRef `json:"podSpecSnapshotRef,omitempty"`

	// +kubebuilder:validation:Optional
	// DriftPolicy controls detection cadence + default response (D6g (d)).
	DriftPolicy *DriftPolicy `json:"driftPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	// BaselineRef points the embedded block at a standalone WorkloadBaseline (by
	// name). When set on the embedded AMTDSpec.Baseline, the standalone CRD is the
	// source of truth for the pinned digests + SignaturePolicy (references only); the
	// embedded block then carries policy knobs (DriftPolicy). On a standalone
	// WorkloadBaseline this is unused.
	BaselineRef *LocalRef `json:"baselineRef,omitempty"`
}

// ---------------------------------------------------------------------------
// CODE DEFAULT HELPERS (FLAGGED via code, NOT CRD-default markers, mirroring the
// WarmInferenceSet Effective*() convention). A nil/empty field resolves to the
// design-authored default here so callers never special-case nil.
// ---------------------------------------------------------------------------

// EffectiveRequireSignature returns SignaturePolicy.RequireSignature, default TRUE
// (D6 fail-CLOSED). A nil policy is treated as "no signature policy" => false
// (digest-allowlist-only); callers that need the policy pass a non-nil one.
func (p *SignaturePolicy) EffectiveRequireSignature() bool {
	if p == nil {
		return false
	}
	if p.RequireSignature != nil {
		return *p.RequireSignature
	}
	return true
}

// EffectiveOnDrift returns DriftPolicy.OnDrift, default Quarantine (D6g).
func (d *DriftPolicy) EffectiveOnDrift() OnDriftAction {
	if d != nil && d.OnDrift != "" {
		return d.OnDrift
	}
	return OnDriftQuarantine
}

// EffectiveAdmissionEnforce returns DriftPolicy.AdmissionEnforce, default TRUE (D6g).
func (d *DriftPolicy) EffectiveAdmissionEnforce() bool {
	if d != nil && d.AdmissionEnforce != nil {
		return *d.AdmissionEnforce
	}
	return true
}

// EffectiveResetHardeningProfile returns DriftPolicy.ResetHardeningProfile, default
// PodProfileOnly (D6g (e)).
func (d *DriftPolicy) EffectiveResetHardeningProfile() HardeningResetScope {
	if d != nil && d.ResetHardeningProfile != "" {
		return d.ResetHardeningProfile
	}
	return HardeningResetPodProfileOnly
}

// EffectiveBaselineSpec returns the effective BaselineSpec for a WorkloadBaseline
// (its Spec). It is the body the verifier/detector read.
func (w *WorkloadBaseline) EffectiveBaselineSpec() *BaselineSpec {
	return &w.Spec.BaselineSpec
}

// WorkloadBaselineSpec is the desired state of a WorkloadBaseline. It embeds the
// shared BaselineSpec (references only) so the standalone CRD and the embedded
// AMTDSpec.Baseline share one shape (arch §2.4). It adds a Selector so the
// reconciler can find the baseline-governed pods to detect drift on.
type WorkloadBaselineSpec struct {
	// BaselineSpec is the pinned digests + SignaturePolicy refs + DriftPolicy
	// (references only, D6g). Inlined so a WorkloadBaseline IS a BaselineSpec plus a
	// selector.
	BaselineSpec `json:",inline"`

	// +kubebuilder:validation:Optional
	// Selector matches the baseline-governed pods (by labels). The
	// BaselineDriftReconciler detects drift on these. nil selects nothing (the
	// reconciler verifies the pins + records Status but finds no pods to compare).
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// DriftDetectionRecord is one bounded drift-detection history entry recorded on
// the WorkloadBaseline Status (audit; the long tail goes to k8s Events).
type DriftDetectionRecord struct {
	// +kubebuilder:validation:Optional
	PodName string `json:"podName,omitempty"`
	// +kubebuilder:validation:Optional
	ContainerName string `json:"containerName,omitempty"`
	// +kubebuilder:validation:Optional
	ObservedDigest string `json:"observedDigest,omitempty"`
	// +kubebuilder:validation:Optional
	ExpectedDigest string `json:"expectedDigest,omitempty"`
	// +kubebuilder:validation:Optional
	Time metav1.Time `json:"time,omitempty"`
}

// WorkloadBaselineStatus is the cap#6 verification/drift observability surface
// (arch §2.4 item 3 + §2.3). All fields optional so a baseline created before this
// stage has an empty-but-valid status.
type WorkloadBaselineStatus struct {
	// +kubebuilder:validation:Optional
	// ObservedGeneration is the .metadata.generation the Status reflects.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Optional
	// LastVerifiedTime is when the pinned digests last verified against the
	// SignaturePolicy. On a registry/Rekor/key blip this is NOT advanced (the prior
	// LastVerifiedTime + PinnedDigests are reused = fail-to-cached-last-good).
	LastVerifiedTime metav1.Time `json:"lastVerifiedTime,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=atomic
	// PinnedDigests is the last VERIFIED set of Repository@Digest strings (the cached
	// last-good the split fail mode reuses).
	PinnedDigests []string `json:"pinnedDigests,omitempty"`

	// +kubebuilder:validation:Optional
	// DriftDetections is a monotonically increasing count of drift detections.
	DriftDetections int `json:"driftDetections,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=atomic
	// RecentDriftDetections is a BOUNDED recent-drift history (cap kept small).
	RecentDriftDetections []DriftDetectionRecord `json:"recentDriftDetections,omitempty"`

	// +kubebuilder:validation:Optional
	// LastRegeneration is when a Regenerate last restored a governed workload to the
	// pinned digest. Drift MTTR = LastRegeneration - detection-ts (kind-measurable).
	LastRegeneration metav1.Time `json:"lastRegeneration,omitempty"`

	// +kubebuilder:validation:Optional
	// EffectiveHealer records the single healer (D6g (c) GitOps precedence) when a
	// GitOps owner is detected; empty => Phoenix is the healer.
	EffectiveHealer string `json:"effectiveHealer,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// Conditions carries BaselineVerified, VerificationUnavailable, SignatureMismatch,
	// DigestUnpinnedWarning and the always-present VerificationBenignityCaveat (D6/D11).
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wb
// +kubebuilder:printcolumn:name="LastVerified",type="date",JSONPath=`.status.lastVerifiedTime`
// +kubebuilder:printcolumn:name="Drifts",type=integer,JSONPath=`.status.driftDetections`
// +kubebuilder:printcolumn:name="LastRegeneration",type="date",JSONPath=`.status.lastRegeneration`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// WorkloadBaseline is the Schema for the workloadbaselines API (cap#6, D6/D6g).
// Cluster-scoped, holds REFERENCES only (never trust-root secret material).
type WorkloadBaseline struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkloadBaselineSpec   `json:"spec,omitempty"`
	Status WorkloadBaselineStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WorkloadBaselineList contains a list of WorkloadBaseline.
type WorkloadBaselineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WorkloadBaseline `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WorkloadBaseline{}, &WorkloadBaselineList{})
}
