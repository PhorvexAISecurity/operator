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

// Package controller — cap#6 BaselineVerifier + DriftDetector (arch §3 cap#6,
// decisions D6/D6g).
//
// This file implements the two cap#6 detection interfaces:
//
//  1. BaselineVerifier — proves an image's PROVENANCE: that a pinned
//     Repository@Digest was signed by the trusted key in the SignaturePolicy.
//     The KIND realization is a REAL key-based signature verification over the
//     pinned DIGEST string using stdlib crypto (ecdsa P-256 over SHA-256, or
//     ed25519), faithful to cosign KEY-BASED while being testable WITHOUT a
//     registry/Rekor. The public key is resolved from the SignaturePolicy
//     PublicKeyRef (a Secret/ConfigMap PEM, or an inline PEM). RequireSignature
//     => an unsigned/unverifiable image is REJECTED.
//
//  2. DriftDetector — compares a running pod's per-container image DIGEST to the
//     pinned baseline digest (the D6 comparison surface = digest + an optional
//     curated PodSpec-field allowlist, NOT the full PodSpec). A mismatch is drift
//     and yields Evidence{ObservedDigest, ExpectedDigest, Detail}.
//
// THE PROVENANCE != BENIGNITY CAVEAT (D6/D11, locked). The verifier proves the
// digest was signed by the trusted key; it does NOT prove the image is benign. A
// validly-signed-but-backdoored upstream image (the SolarWinds/SUNBURST shape)
// passes verification. This is carried in code (here), in a Status condition
// (VerificationBenignityCaveat), and in the report. It is the reason the default
// OnDrift is Quarantine (not auto-Regenerate).
//
// PRODUCTION EXTENSION (behind the interface, NOT vendored here). Full cosign /
// sigstore verification — go-containerregistry digest resolution from a live
// registry, cosign signature-layer fetch, Fulcio keyless identity + Rekor
// transparency-log inclusion proofs — is the production realization of this same
// BaselineVerifier interface. It is intentionally NOT vendored (the whole sigstore
// stack is a heavy dependency surface, D6 "do not vendor unless trivial"); the
// interface boundary is exactly where it would be swapped in. The kind verifier
// covers the load-bearing logic (a real cryptographic signature check over the
// pinned digest + RequireSignature fail-closed) that the tests gate on.
package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// defaultPublicKeyDataKey is the Secret/ConfigMap data key the kind verifier reads
// the PEM public key from when KeyRef.Key is empty (cosign convention).
const defaultPublicKeyDataKey = "cosign.pub"

// ErrVerificationUnavailable is returned by VerifyImage when verification could
// NOT be performed (no resolvable public key, an unreadable key Secret, a
// keyless-only policy the kind verifier cannot honor). It is DISTINCT from a
// positive verification FAILURE (a wrong/absent signature): the SPLIT fail mode
// (D6) treats unavailability as fail-to-cached-last-good (poll side) while a
// positive mismatch is a real drift/denial. Callers use errors.Is to branch.
var ErrVerificationUnavailable = errors.New("baseline verification unavailable")

// ErrSignatureMismatch is returned by VerifyImage on a positive verification
// FAILURE: the signature is absent (and RequireSignature) or does not verify
// against the trusted key over the pinned digest. This is a real provenance
// failure (deny at admission / refuse a verify-before-recreate target).
var ErrSignatureMismatch = errors.New("baseline signature verification failed")

// VerifiedImage is the result of a successful (or attempted) provenance check.
type VerifiedImage struct {
	// Repository is the verified image repository.
	Repository string
	// Digest is the verified content digest (sha256:...).
	Digest string
	// Signed reports whether a signature was present AND verified against the
	// trusted key over the digest. False with a nil error means "no SignaturePolicy
	// / RequireSignature=false and unsigned" (digest-allowlist-only, allowed).
	Signed bool
	// KeyType is the verified key algorithm ("ecdsa"|"ed25519"|"") for audit.
	KeyType string
}

// Ref returns the canonical Repository@Digest reference.
func (v VerifiedImage) Ref() string {
	if v.Repository == "" {
		return v.Digest
	}
	return v.Repository + "@" + v.Digest
}

// BaselineVerifier is the cap#6 provenance interface (D6). It proves an image's
// provenance (the pinned digest was signed by the trusted key) — it does NOT
// prove benignity (D6/D11 caveat). The kind realization is key-based stdlib
// crypto; the production realization (cosign/Rekor/keyless) swaps in behind this
// same interface.
type BaselineVerifier interface {
	// VerifyImage verifies the given pinned ImageDigest against the SignaturePolicy.
	// Contract:
	//   - policy nil OR RequireSignature=false AND no signature  -> (Signed:false, nil)
	//     (digest-allowlist-only; provenance not asserted but allowed).
	//   - signature present + verifies over the digest with the trusted key
	//     -> (Signed:true, nil).
	//   - RequireSignature=true + (no signature | does not verify)
	//     -> ErrSignatureMismatch (positive failure: deny / refuse).
	//   - key cannot be resolved / keyless-only policy on the kind verifier
	//     -> ErrVerificationUnavailable (split fail mode: fail-to-cached-last-good).
	VerifyImage(ctx context.Context, img amtdv1beta1.ImageDigest, policy *amtdv1beta1.SignaturePolicy) (VerifiedImage, error)

	// ResolveDigest resolves a (running) image reference to its content digest.
	// KIND realization: a Repository@sha256:... reference is parsed and its digest
	// returned directly (no registry round-trip), and a plain tag is reported
	// unresolved (ErrVerificationUnavailable) because the kind verifier does not
	// contact a registry. PRODUCTION: go-containerregistry resolves the tag against
	// the live registry. This split keeps the kind path offline-capable while the
	// interface stays production-swappable.
	ResolveDigest(ctx context.Context, imageRef string) (digest string, err error)
}

// defaultBaselineVerifier is the kind key-based BaselineVerifier. It reads the
// public key from the SignaturePolicy PublicKeyRef via the injected reader.
type defaultBaselineVerifier struct {
	reader client.Reader
	// operatorNamespace is the namespace used when a KeyRef omits a namespace.
	operatorNamespace string
}

// NewBaselineVerifier returns the kind key-based BaselineVerifier. reader resolves
// PublicKeyRef Secrets/ConfigMaps; operatorNamespace defaults a namespace-less
// KeyRef. reader may be nil if every policy uses an inline PEM (test convenience).
func NewBaselineVerifier(reader client.Reader, operatorNamespace string) BaselineVerifier {
	return &defaultBaselineVerifier{reader: reader, operatorNamespace: operatorNamespace}
}

// VerifyImage implements the BaselineVerifier contract (see the interface doc).
func (v *defaultBaselineVerifier) VerifyImage(ctx context.Context, img amtdv1beta1.ImageDigest, policy *amtdv1beta1.SignaturePolicy) (VerifiedImage, error) {
	out := VerifiedImage{Repository: img.Repository, Digest: img.Digest}

	requireSig := policy.EffectiveRequireSignature() // nil-safe: nil policy => false

	// No signature policy / not required AND unsigned: digest-allowlist-only allow.
	if !requireSig && img.Signature == "" {
		return out, nil
	}

	// A keyless-only policy is a PRODUCTION seam the kind verifier cannot honor.
	// When a signature is required but no key-based material is resolvable, this is
	// UNAVAILABILITY (split fail mode), not a positive mismatch.
	if policy == nil || (policy.PublicKeyRef == nil && policy.KeylessIdentity != nil) {
		if requireSig {
			return out, fmt.Errorf("%w: keyless/online verification (Rekor/Fulcio) is a production extension not realized by the kind key-based verifier", ErrVerificationUnavailable)
		}
		return out, nil
	}

	// Resolve the public key.
	pub, keyType, err := v.resolvePublicKey(ctx, policy.PublicKeyRef)
	if err != nil {
		// No resolvable key => verification is UNAVAILABLE (not a mismatch).
		return out, fmt.Errorf("%w: %v", ErrVerificationUnavailable, err)
	}

	// No signature on a required-signature image is a positive FAILURE (deny).
	if img.Signature == "" {
		return out, fmt.Errorf("%w: image %s@%s carries no signature but RequireSignature=true", ErrSignatureMismatch, img.Repository, img.Digest)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(img.Signature))
	if err != nil {
		return out, fmt.Errorf("%w: signature is not valid base64: %v", ErrSignatureMismatch, err)
	}

	// The signed message is the pinned DIGEST string (cosign key-based signs the
	// image digest; here we sign the digest string directly so kind can verify
	// offline). This is the load-bearing cryptographic check.
	msg := []byte(img.Digest)
	if !verifySignature(pub, keyType, msg, sigBytes) {
		return out, fmt.Errorf("%w: signature over digest %q does not verify against the trusted %s key", ErrSignatureMismatch, img.Digest, keyType)
	}

	out.Signed = true
	out.KeyType = keyType
	return out, nil
}

// ResolveDigest implements the kind offline digest resolution (see interface doc).
func (v *defaultBaselineVerifier) ResolveDigest(ctx context.Context, imageRef string) (string, error) {
	repo, digest := splitImageRef(imageRef)
	if digest != "" {
		return digest, nil
	}
	return "", fmt.Errorf("%w: image reference %q is not digest-pinned and the kind verifier does not resolve tags against a live registry (production: go-containerregistry)", ErrVerificationUnavailable, repo)
}

// resolvePublicKey loads the PEM public key from a KeyRef (inline PEM > Secret >
// ConfigMap) and parses it to an ecdsa/ed25519 public key.
func (v *defaultBaselineVerifier) resolvePublicKey(ctx context.Context, ref *amtdv1beta1.KeyRef) (crypto.PublicKey, string, error) {
	if ref == nil {
		return nil, "", errors.New("no PublicKeyRef in SignaturePolicy")
	}

	var pemBytes []byte
	switch {
	case ref.InlinePEM != "":
		pemBytes = []byte(ref.InlinePEM)
	case ref.SecretRef != nil:
		if v.reader == nil {
			return nil, "", errors.New("PublicKeyRef.SecretRef set but no reader is configured")
		}
		ns := ref.SecretRef.Namespace
		if ns == "" {
			ns = v.operatorNamespace
		}
		sec := &corev1.Secret{}
		if err := v.reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.SecretRef.Name}, sec); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, "", fmt.Errorf("public-key Secret %s/%s not found", ns, ref.SecretRef.Name)
			}
			return nil, "", fmt.Errorf("reading public-key Secret %s/%s: %w", ns, ref.SecretRef.Name, err)
		}
		pemBytes = sec.Data[keyOrDefault(ref.SecretRef.Key)]
	case ref.ConfigMapRef != nil:
		if v.reader == nil {
			return nil, "", errors.New("PublicKeyRef.ConfigMapRef set but no reader is configured")
		}
		ns := ref.ConfigMapRef.Namespace
		if ns == "" {
			ns = v.operatorNamespace
		}
		cm := &corev1.ConfigMap{}
		if err := v.reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.ConfigMapRef.Name}, cm); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, "", fmt.Errorf("public-key ConfigMap %s/%s not found", ns, ref.ConfigMapRef.Name)
			}
			return nil, "", fmt.Errorf("reading public-key ConfigMap %s/%s: %w", ns, ref.ConfigMapRef.Name, err)
		}
		pemBytes = []byte(cm.Data[keyOrDefault(ref.ConfigMapRef.Key)])
	default:
		return nil, "", errors.New("PublicKeyRef has no InlinePEM/SecretRef/ConfigMapRef")
	}

	if len(pemBytes) == 0 {
		return nil, "", errors.New("resolved public-key material is empty")
	}
	return parsePEMPublicKey(pemBytes)
}

// keyOrDefault returns the configured data key or the cosign default.
func keyOrDefault(k string) string {
	if k != "" {
		return k
	}
	return defaultPublicKeyDataKey
}

// parsePEMPublicKey parses a PEM-encoded PKIX public key into an ecdsa/ed25519 key
// and reports its algorithm string.
func parsePEMPublicKey(pemBytes []byte) (crypto.PublicKey, string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", errors.New("public key is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parsing PKIX public key: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return pub, "ecdsa", nil
	case ed25519.PublicKey:
		return pub, "ed25519", nil
	default:
		return nil, "", fmt.Errorf("unsupported public key type %T (kind verifier supports ecdsa/ed25519)", pub)
	}
}

// verifySignature checks sig over msg with the public key. ecdsa verifies over
// SHA-256(msg) (cosign uses ecdsa-P256/SHA-256); ed25519 verifies over msg.
func verifySignature(pub crypto.PublicKey, keyType string, msg, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, h[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(k, msg, sig)
	default:
		return false
	}
}

// splitImageRef splits an image reference into (repository, digest). It recognizes
// the digest-pinned form repo@sha256:.... A tag (repo:tag) or bare repo returns an
// empty digest. The container image as stored on a PodSpec is the value compared.
func splitImageRef(imageRef string) (repo, digest string) {
	if i := strings.Index(imageRef, "@"); i >= 0 {
		return imageRef[:i], imageRef[i+1:]
	}
	return imageRef, ""
}

// ----------------------------------------------------------------------------
// DriftDetector (cap#6, D6 comparison surface)
// ----------------------------------------------------------------------------

// DriftResult is one detected drift on one container of one pod. Evidence carries
// the observed-vs-expected digest the drift SecurityEvent attaches.
type DriftResult struct {
	PodName       string
	ContainerName string
	Evidence      amtdv1beta1.DriftEvidence
}

// DriftDetector compares a running pod against a BaselineSpec's pinned digests and
// returns any drifts. The comparison surface is the image DIGEST per container
// (plus an optional curated allowlist of PodSpec fields), NOT the full PodSpec
// (D6) — comparing the full PodSpec would false-positive on benign controller
// defaulting and fight GitOps.
type DriftDetector interface {
	Detect(ctx context.Context, pod *corev1.Pod, spec *amtdv1beta1.BaselineSpec) ([]DriftResult, error)
}

// defaultDriftDetector is the kind DriftDetector (digest comparison).
type defaultDriftDetector struct {
	verifier BaselineVerifier
}

// NewDriftDetector returns the kind DriftDetector. The verifier is used only to
// resolve a running container image to its digest (offline parse on kind).
func NewDriftDetector(verifier BaselineVerifier) DriftDetector {
	return &defaultDriftDetector{verifier: verifier}
}

// Detect compares each pinned container's running image digest to the baseline
// pin. A running container whose digest differs from the pin (or whose image is
// not digest-pinned at all when the baseline pins it) is drift.
func (d *defaultDriftDetector) Detect(ctx context.Context, pod *corev1.Pod, spec *amtdv1beta1.BaselineSpec) ([]DriftResult, error) {
	if pod == nil || spec == nil {
		return nil, nil
	}
	// Build a container-name -> running image map from the pod spec, and prefer the
	// status image (the resolved digest the kubelet recorded) when present.
	runningImage := map[string]string{}
	for i := range pod.Spec.Containers {
		runningImage[pod.Spec.Containers[i].Name] = pod.Spec.Containers[i].Image
	}
	for i := range pod.Status.ContainerStatuses {
		cs := pod.Status.ContainerStatuses[i]
		if cs.ImageID != "" {
			// ImageID is e.g. "docker-pullable://repo@sha256:...". Extract the digest.
			if _, dg := splitImageRef(cs.ImageID); dg != "" {
				// Only override when the spec image is not already digest-pinned, so a
				// test/manifest that pins spec.image keeps deterministic behavior.
				if _, specDg := splitImageRef(runningImage[cs.Name]); specDg == "" {
					runningImage[cs.Name] = cs.Image + "@" + dg
				}
			}
		}
	}

	var results []DriftResult
	for _, pin := range spec.ImageDigests {
		img, ok := runningImage[pin.ContainerName]
		if !ok {
			// The baseline pins a container the pod does not have: report as drift
			// (the running workload diverged from the pinned shape).
			results = append(results, DriftResult{
				PodName:       pod.Name,
				ContainerName: pin.ContainerName,
				Evidence: amtdv1beta1.DriftEvidence{
					ObservedDigest: "",
					ExpectedDigest: pin.Digest,
					Detail:         fmt.Sprintf("pinned container %q not present in running pod %q", pin.ContainerName, pod.Name),
				},
			})
			continue
		}
		_, observed := splitImageRef(img)
		if observed != pin.Digest {
			detail := fmt.Sprintf("image digest drift on container %q: running=%q expected=%q (repo %s)", pin.ContainerName, observedOrTag(img, observed), pin.Digest, pin.Repository)
			results = append(results, DriftResult{
				PodName:       pod.Name,
				ContainerName: pin.ContainerName,
				Evidence: amtdv1beta1.DriftEvidence{
					ObservedDigest: observed,
					ExpectedDigest: pin.Digest,
					Detail:         detail,
				},
			})
		}
	}
	return results, nil
}

// observedOrTag renders the observed digest for the Detail, falling back to the
// whole reference when the running image is a tag (no digest) so the message is
// still informative.
func observedOrTag(image, observed string) string {
	if observed != "" {
		return observed
	}
	return image + " (not digest-pinned)"
}
