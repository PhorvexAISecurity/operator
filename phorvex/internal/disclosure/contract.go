// Package disclosure validates the single, synthetic completed-disclosure
// contract. It does not infer disclosure from generic events or actions.
package disclosure

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	Annotation                  = "phorvex.ai/completed-disclosure-v1"
	AdmissionTimeAnnotation     = "phorvex.ai/completed-disclosure-admitted-at"
	AdmissionContractAnnotation = "phorvex.ai/completed-disclosure-admission-contract"
	BoundaryContract            = "completed-disclosure-boundary-v2"
	BoundaryContractAnnotation  = "phorvex.ai/completed-disclosure-boundary-contract"
	MaxPayloadBytes             = 16 << 10
	MaxResponseBytes            = 8 << 20
)

func validText(s string, max int) bool {
	s = strings.TrimSpace(s)
	return s != "" && len(s) <= max && !strings.ContainsAny(s, "\x00\r\n")
}

func validDigest(s string) bool {
	if len(s) != sha256.Size*2 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func ValidDigest(s string) bool { return validDigest(s) }

func validObject(o model.ObjectIdentity) bool {
	return validText(o.APIVersion, 80) && validText(o.Kind, 80) &&
		validText(o.Name, 253) && validText(o.UID, 256) &&
		(o.Namespace == "" || validText(o.Namespace, 63))
}

// Validate proves the exact completed-response and identity shape. Authority is
// checked separately from API-observed creator, event and owner-chain state.
func Validate(p model.CompletedDisclosureV1) error {
	if p.SchemaVersion != model.CompletedDisclosureSchemaV1 {
		return errors.New("unsupported disclosure schema")
	}
	if !validText(p.EvidenceID, 256) || !validText(p.PolicyEpoch.Namespace, 63) ||
		!validText(p.PolicyEpoch.Name, 253) || !validText(p.PolicyEpoch.UID, 256) || p.PolicyEpoch.Generation <= 0 {
		return errors.New("incomplete policy epoch")
	}
	if !validText(p.DecisionAsset.Namespace, 63) || !validText(p.DecisionAsset.Name, 253) || !validText(p.DecisionAsset.TargetUID, 256) {
		return errors.New("incomplete decision asset")
	}
	if !validObject(p.ImmediateController) || !validObject(p.StableWorkloadOwner) {
		return errors.New("incomplete workload owner identity")
	}
	if p.ImmediateController.Namespace != p.DecisionAsset.Namespace || p.StableWorkloadOwner.Namespace != p.DecisionAsset.Namespace {
		return errors.New("owner namespace does not match target")
	}
	s := p.ProtectedScope
	if !validText(s.Tenant, 253) || !validText(s.Asset, 512) || !validText(s.Version, 256) || !validText(s.Property, 128) {
		return errors.New("incomplete protected scope")
	}
	if !validText(p.Classification.RuleVersion, 128) || !validDigest(p.Classification.RuleDigest) ||
		p.Classification.ObserverClass != model.CompletedDisclosureClass || !validText(p.Classification.ObserverIdentity, 512) {
		return errors.New("invalid disclosure classification")
	}
	o := p.Observation
	if o.StartedAt.IsZero() || o.CompletedAt.IsZero() || o.CompletedAt.Before(o.StartedAt) {
		return errors.New("invalid observation interval")
	}
	if o.StatusCode != 200 || o.ExpectedBytes <= 0 || o.ExpectedBytes > MaxResponseBytes ||
		o.ObservedBytes != o.ExpectedBytes || !o.ReachedEOF {
		return errors.New("response was not an exact completed copy")
	}
	if !validDigest(o.ExpectedSHA256) || !validDigest(o.ObservedSHA256) || o.ExpectedSHA256 != o.ObservedSHA256 {
		return errors.New("response digest mismatch")
	}
	if !p.Synthetic {
		return errors.New("only synthetic disclosure observations are supported")
	}
	return nil
}

// Parse rejects unknown fields, trailing values and oversized annotations.
func Parse(raw string) (model.CompletedDisclosureV1, []byte, string, error) {
	var p model.CompletedDisclosureV1
	if raw == "" || len(raw) > MaxPayloadBytes {
		return p, nil, "", errors.New("missing or oversized disclosure payload")
	}
	dec := json.NewDecoder(io.LimitReader(strings.NewReader(raw), MaxPayloadBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, nil, "", fmt.Errorf("decode disclosure: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return p, nil, "", errors.New("trailing disclosure data")
	}
	if err := Validate(p); err != nil {
		return p, nil, "", err
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return p, nil, "", err
	}
	digest := sha256.Sum256(canonical)
	return p, canonical, hex.EncodeToString(digest[:]), nil
}

func Marshal(p model.CompletedDisclosureV1) (string, string, error) {
	if err := Validate(p); err != nil {
		return "", "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	return string(b), hex.EncodeToString(sum[:]), nil
}

func EqualPayload(a, b string) bool {
	pa, ca, _, ea := Parse(a)
	pb, cb, _, eb := Parse(b)
	return ea == nil && eb == nil && pa.SchemaVersion == pb.SchemaVersion && bytes.Equal(ca, cb)
}
