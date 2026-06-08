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

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// testKeyMaterial holds a freshly-generated keypair + a PEM-encoded public key, so
// the verifier tests exercise REAL stdlib crypto (faithful to cosign key-based)
// rather than a hardcoded key.
type testKeyMaterial struct {
	pubPEM  string
	signECD func(digest string) string // base64 ecdsa signature over the digest
}

// newECDSAKey generates an ecdsa P-256 keypair and returns the PEM public key plus
// a signer that signs a digest string (cosign-style: signature over the digest).
func newECDSAKey(t *testing.T) testKeyMaterial {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ecdsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return testKeyMaterial{
		pubPEM: pubPEM,
		signECD: func(digest string) string {
			h := sha256.Sum256([]byte(digest))
			sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			return base64.StdEncoding.EncodeToString(sig)
		},
	}
}

// newED25519Key generates an ed25519 keypair and returns the PEM public key plus a
// digest signer (ed25519 signs the message directly).
func newED25519Key(t *testing.T) (pubPEM string, sign func(digest string) string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return pubPEM, func(digest string) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(digest)))
	}
}

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func requireSigPolicy(pubPEM string) *amtdv1beta1.SignaturePolicy {
	req := true
	return &amtdv1beta1.SignaturePolicy{
		PublicKeyRef:     &amtdv1beta1.KeyRef{InlinePEM: pubPEM},
		RequireSignature: &req,
	}
}

// TestVerifier_ECDSA_CorrectSignatureVerifies proves a correct ecdsa signature over
// the pinned digest verifies (Signed=true, no error) — a REAL key-based check.
func TestVerifier_ECDSA_CorrectSignatureVerifies(t *testing.T) {
	km := newECDSAKey(t)
	v := NewBaselineVerifier(nil, "")
	img := amtdv1beta1.ImageDigest{
		ContainerName: "app", Repository: "registry/app", Digest: testDigest,
		Signature: km.signECD(testDigest),
	}
	vi, err := v.VerifyImage(context.Background(), img, requireSigPolicy(km.pubPEM))
	if err != nil {
		t.Fatalf("expected verify success, got %v", err)
	}
	if !vi.Signed || vi.KeyType != "ecdsa" {
		t.Errorf("VerifiedImage=%+v, want Signed=true KeyType=ecdsa", vi)
	}
}

// TestVerifier_ED25519_CorrectSignatureVerifies proves ed25519 key-based verify.
func TestVerifier_ED25519_CorrectSignatureVerifies(t *testing.T) {
	pubPEM, sign := newED25519Key(t)
	v := NewBaselineVerifier(nil, "")
	img := amtdv1beta1.ImageDigest{
		ContainerName: "app", Repository: "registry/app", Digest: testDigest,
		Signature: sign(testDigest),
	}
	vi, err := v.VerifyImage(context.Background(), img, requireSigPolicy(pubPEM))
	if err != nil {
		t.Fatalf("expected verify success, got %v", err)
	}
	if !vi.Signed || vi.KeyType != "ed25519" {
		t.Errorf("VerifiedImage=%+v, want Signed=true KeyType=ed25519", vi)
	}
}

// TestVerifier_RequireSignature_RejectsUnsigned proves RequireSignature rejects an
// unsigned image with a positive ErrSignatureMismatch (deny, not unavailable).
func TestVerifier_RequireSignature_RejectsUnsigned(t *testing.T) {
	km := newECDSAKey(t)
	v := NewBaselineVerifier(nil, "")
	img := amtdv1beta1.ImageDigest{ContainerName: "app", Repository: "registry/app", Digest: testDigest} // no signature
	_, err := v.VerifyImage(context.Background(), img, requireSigPolicy(km.pubPEM))
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for unsigned+RequireSignature, got %v", err)
	}
}

// TestVerifier_WrongKey_Rejects proves a signature made by a DIFFERENT key does not
// verify against the configured key (ErrSignatureMismatch).
func TestVerifier_WrongKey_Rejects(t *testing.T) {
	signer := newECDSAKey(t)  // signs
	trusted := newECDSAKey(t) // configured (different) public key
	v := NewBaselineVerifier(nil, "")
	img := amtdv1beta1.ImageDigest{
		ContainerName: "app", Repository: "registry/app", Digest: testDigest,
		Signature: signer.signECD(testDigest), // signed by the WRONG key
	}
	_, err := v.VerifyImage(context.Background(), img, requireSigPolicy(trusted.pubPEM))
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for wrong-key signature, got %v", err)
	}
}

// TestVerifier_SignatureOverWrongDigest_Rejects proves a valid signature over a
// DIFFERENT digest does not verify for the pinned digest (tamper detection).
func TestVerifier_SignatureOverWrongDigest_Rejects(t *testing.T) {
	km := newECDSAKey(t)
	v := NewBaselineVerifier(nil, "")
	img := amtdv1beta1.ImageDigest{
		ContainerName: "app", Repository: "registry/app", Digest: testDigest,
		Signature: km.signECD("sha256:deadbeef"), // signs a different digest
	}
	_, err := v.VerifyImage(context.Background(), img, requireSigPolicy(km.pubPEM))
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for wrong-digest signature, got %v", err)
	}
}

// TestVerifier_NoKey_RequireSignature_Unavailable proves that when a signature is
// required but no key-based material is resolvable (keyless-only policy), the result
// is ErrVerificationUnavailable (the SPLIT fail mode's poll-side fail-to-cached-
// last-good), NOT a positive mismatch.
func TestVerifier_NoKey_RequireSignature_Unavailable(t *testing.T) {
	req := true
	policy := &amtdv1beta1.SignaturePolicy{
		KeylessIdentity:  &amtdv1beta1.KeylessIdentity{Issuer: "https://issuer", SubjectRegexp: ".*"},
		RequireSignature: &req,
	}
	v := NewBaselineVerifier(nil, "")
	img := amtdv1beta1.ImageDigest{ContainerName: "app", Repository: "registry/app", Digest: testDigest, Signature: "AAAA"}
	_, err := v.VerifyImage(context.Background(), img, policy)
	if !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("expected ErrVerificationUnavailable for keyless-only policy, got %v", err)
	}
}

// TestVerifier_NoPolicy_Unsigned_Allowed proves digest-allowlist-only mode: a nil
// policy / RequireSignature=false with no signature is allowed (Signed=false, nil).
func TestVerifier_NoPolicy_Unsigned_Allowed(t *testing.T) {
	v := NewBaselineVerifier(nil, "")
	img := amtdv1beta1.ImageDigest{ContainerName: "app", Repository: "registry/app", Digest: testDigest}
	vi, err := v.VerifyImage(context.Background(), img, nil)
	if err != nil {
		t.Fatalf("expected allow for nil policy, got %v", err)
	}
	if vi.Signed {
		t.Errorf("expected Signed=false for digest-allowlist-only, got %+v", vi)
	}
}

// TestDriftDetector_DigestMismatch_ProducesEvidence proves the detector flags a
// running digest that differs from the pin and produces Evidence{Observed!=Expected}.
func TestDriftDetector_DigestMismatch_ProducesEvidence(t *testing.T) {
	v := NewBaselineVerifier(nil, "")
	d := NewDriftDetector(v)
	spec := &amtdv1beta1.BaselineSpec{
		ImageDigests: []amtdv1beta1.ImageDigest{
			{ContainerName: "app", Repository: "registry/app", Digest: testDigest},
		},
	}
	driftedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app", Image: "registry/app@" + driftedDigest},
		}},
	}
	results, err := d.Detect(context.Background(), pod, spec)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 drift result, got %d", len(results))
	}
	ev := results[0].Evidence
	if ev.ObservedDigest != driftedDigest || ev.ExpectedDigest != testDigest {
		t.Errorf("Evidence=%+v, want Observed=%q Expected=%q", ev, driftedDigest, testDigest)
	}
	if ev.ObservedDigest == ev.ExpectedDigest {
		t.Error("Evidence Observed must differ from Expected on a drift")
	}
}

// TestDriftDetector_MatchingDigest_NoDrift proves a running digest equal to the pin
// is NOT drift.
func TestDriftDetector_MatchingDigest_NoDrift(t *testing.T) {
	v := NewBaselineVerifier(nil, "")
	d := NewDriftDetector(v)
	spec := &amtdv1beta1.BaselineSpec{
		ImageDigests: []amtdv1beta1.ImageDigest{
			{ContainerName: "app", Repository: "registry/app", Digest: testDigest},
		},
	}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app", Image: "registry/app@" + testDigest},
		}},
	}
	results, err := d.Detect(context.Background(), pod, spec)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no drift for matching digest, got %d: %+v", len(results), results)
	}
}

// TestEffectiveDefaults proves the code-default helpers (D6g): EffectiveOnDrift ==
// Quarantine, EffectiveAdmissionEnforce == true, EffectiveResetHardeningProfile ==
// PodProfileOnly, EffectiveRequireSignature == true.
func TestEffectiveDefaults(t *testing.T) {
	var dp *amtdv1beta1.DriftPolicy // nil
	if got := dp.EffectiveOnDrift(); got != amtdv1beta1.OnDriftQuarantine {
		t.Errorf("EffectiveOnDrift=%q, want Quarantine", got)
	}
	if !dp.EffectiveAdmissionEnforce() {
		t.Error("EffectiveAdmissionEnforce should default true")
	}
	if got := dp.EffectiveResetHardeningProfile(); got != amtdv1beta1.HardeningResetPodProfileOnly {
		t.Errorf("EffectiveResetHardeningProfile=%q, want PodProfileOnly", got)
	}
	pol := &amtdv1beta1.SignaturePolicy{}
	if !pol.EffectiveRequireSignature() {
		t.Error("EffectiveRequireSignature should default true for a non-nil policy")
	}
}
