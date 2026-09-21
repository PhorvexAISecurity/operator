package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

const (
	DecisionParameterManifestV1 = "phorvex.decision-parameters.v1"
	DecisionParameterSetV1      = "phorvex.decision-parameter-set.v1"
	DecisionPolicyOverridesV1   = "phorvex.policy-overrides.v1"

	ParameterDerived            = "derived"
	ParameterMeasured           = "measured-with-evidence"
	ParameterExpertPrior        = "expert-prior"
	ParameterConfigurationBound = "configuration-bound"
	ParameterUnknown            = "unknown"

	// Shared platform witness constants are owned below the platform/decision
	// dependency boundary so the producer and manifest read one source of truth.
	PlatformCoResidencyCap          = 4.0
	PlatformEPSSAggregatePercentile = 0.99
	PlatformRarityMinimum           = 1.0
	PlatformRarityMaximum           = 2.0
)

// DecisionParameter describes one scalar consumed by production decision logic.
// Default is the value read from the named Source at manifest construction time;
// it is not a claim that the value is empirically calibrated.
type DecisionParameter struct {
	Name            string  `json:"name"`
	Group           string  `json:"group"`
	Unit            string  `json:"unit"`
	Domain          string  `json:"domain"`
	Default         float64 `json:"default"`
	Source          string  `json:"source"`
	Provenance      string  `json:"provenance"`
	Limitations     string  `json:"limitations"`
	DependencyGroup string  `json:"dependencyGroup"`
}

// DecisionParameterManifest is exported once per source/configuration set and
// referenced from each decision by identity and canonical hash.
type DecisionParameterManifest struct {
	SchemaVersion string              `json:"schemaVersion"`
	ID            string              `json:"id"`
	Parameters    []DecisionParameter `json:"parameters"`
}

// EffectivePolicyParameter is an exact resolved value used by one policy tick.
// Present preserves optional presence (for example fixed beta absent vs zero).
type EffectivePolicyParameter struct {
	Name    string  `json:"name"`
	Unit    string  `json:"unit"`
	Present bool    `json:"present"`
	Value   float64 `json:"value"`
}

// EffectivePolicyOverrides is independently retainable input to the compact
// hash carried by each decision.
type EffectivePolicyOverrides struct {
	SchemaVersion string                     `json:"schemaVersion"`
	ID            string                     `json:"id"`
	Values        []EffectivePolicyParameter `json:"values"`
}

// ParameterSetReference is the compact per-decision parameter provenance.
// The full manifest and exact effective overrides are exported separately.
type ParameterSetReference struct {
	SchemaVersion       string `json:"schemaVersion"`
	ManifestID          string `json:"manifestId"`
	ManifestHash        string `json:"manifestHash"`
	PolicyOverridesID   string `json:"policyOverridesId"`
	PolicyOverridesHash string `json:"policyOverridesHash"`
}

func canonicalParameters(in []DecisionParameter) []DecisionParameter {
	out := append([]DecisionParameter(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func canonicalOverrides(in []EffectivePolicyParameter) []EffectivePolicyParameter {
	out := append([]EffectivePolicyParameter(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func hashJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Canonical returns a deterministic descriptive ordering. Descriptive order in
// source does not affect the identity.
func (m DecisionParameterManifest) Canonical() DecisionParameterManifest {
	m.Parameters = canonicalParameters(m.Parameters)
	return m
}

// CanonicalHash hashes the complete definitions and exact producer values.
func (m DecisionParameterManifest) CanonicalHash() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	return hashJSON(m.Canonical())
}

func (m DecisionParameterManifest) Validate() error {
	if m.SchemaVersion != DecisionParameterManifestV1 || m.ID == "" || len(m.Parameters) == 0 {
		return fmt.Errorf("invalid decision parameter manifest identity")
	}
	seen := make(map[string]struct{}, len(m.Parameters))
	for _, p := range m.Parameters {
		if p.Name == "" || p.Group == "" || p.Unit == "" || p.Domain == "" || p.Source == "" ||
			p.Provenance == "" || p.Limitations == "" || p.DependencyGroup == "" {
			return fmt.Errorf("parameter %q has incomplete provenance", p.Name)
		}
		if math.IsNaN(p.Default) || math.IsInf(p.Default, 0) {
			return fmt.Errorf("parameter %q has non-finite default", p.Name)
		}
		switch p.Provenance {
		case ParameterDerived, ParameterMeasured, ParameterExpertPrior, ParameterConfigurationBound, ParameterUnknown:
		default:
			return fmt.Errorf("parameter %q has unknown provenance %q", p.Name, p.Provenance)
		}
		if _, exists := seen[p.Name]; exists {
			return fmt.Errorf("duplicate parameter %q", p.Name)
		}
		seen[p.Name] = struct{}{}
	}
	return nil
}

func (o EffectivePolicyOverrides) Canonical() EffectivePolicyOverrides {
	o.Values = canonicalOverrides(o.Values)
	return o
}

func (o EffectivePolicyOverrides) CanonicalHash() (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	return hashJSON(o.Canonical())
}

func (o EffectivePolicyOverrides) Validate() error {
	if o.SchemaVersion != DecisionPolicyOverridesV1 || o.ID == "" || len(o.Values) == 0 {
		return fmt.Errorf("invalid effective policy override identity")
	}
	seen := make(map[string]struct{}, len(o.Values))
	for _, p := range o.Values {
		if p.Name == "" || p.Unit == "" || math.IsNaN(p.Value) || math.IsInf(p.Value, 0) {
			return fmt.Errorf("invalid effective policy parameter %q", p.Name)
		}
		if _, exists := seen[p.Name]; exists {
			return fmt.Errorf("duplicate effective policy parameter %q", p.Name)
		}
		seen[p.Name] = struct{}{}
	}
	return nil
}

func (r ParameterSetReference) Validate() error {
	if r.SchemaVersion != DecisionParameterSetV1 || r.ManifestID == "" || r.PolicyOverridesID == "" ||
		!validSHA256(r.ManifestHash) || !validSHA256(r.PolicyOverridesHash) {
		return fmt.Errorf("invalid decision parameter-set reference")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil
}

// VerifyParameterSet rejects missing or tampered retained material. A nil
// reference is a legacy record whose parameter provenance is unavailable.
func VerifyParameterSet(ref *ParameterSetReference, manifest *DecisionParameterManifest, overrides *EffectivePolicyOverrides) error {
	if ref == nil {
		return fmt.Errorf("parameter provenance unavailable on legacy record")
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if manifest == nil || overrides == nil {
		return fmt.Errorf("parameter manifest and effective overrides are required")
	}
	mh, err := manifest.CanonicalHash()
	if err != nil {
		return err
	}
	oh, err := overrides.CanonicalHash()
	if err != nil {
		return err
	}
	if manifest.ID != ref.ManifestID || mh != ref.ManifestHash || overrides.ID != ref.PolicyOverridesID || oh != ref.PolicyOverridesHash {
		return fmt.Errorf("parameter-set reference does not match retained material")
	}
	return nil
}
