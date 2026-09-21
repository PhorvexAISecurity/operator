package model

import (
	"strings"
	"testing"
)

func parameterFixture() DecisionParameterManifest {
	return DecisionParameterManifest{SchemaVersion: DecisionParameterManifestV1, ID: "fixture", Parameters: []DecisionParameter{
		{Name: "b", Group: "g", Unit: "ratio", Domain: "[0,1]", Default: 0.2, Source: "b.go", Provenance: ParameterExpertPrior, Limitations: "fixture only", DependencyGroup: "g"},
		{Name: "a", Group: "g", Unit: "ratio", Domain: "[0,1]", Default: 0.1, Source: "a.go", Provenance: ParameterDerived, Limitations: "fixture only", DependencyGroup: "g"},
	}}
}

func TestM108CanonicalParameterHashIsOrderStableAndValueSensitive(t *testing.T) {
	manifest := parameterFixture()
	first, err := manifest.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Parameters[0], manifest.Parameters[1] = manifest.Parameters[1], manifest.Parameters[0]
	second, err := manifest.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("descriptive source order changed canonical hash: %s != %s", first, second)
	}
	manifest.Parameters[0].Default += 0.0000001
	changed, err := manifest.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("changed exact producer value did not change manifest hash")
	}
}

func TestM108ParameterReferenceRejectsMissingAndTamperedMaterial(t *testing.T) {
	manifest := parameterFixture().Canonical()
	overrides := EffectivePolicyOverrides{SchemaVersion: DecisionPolicyOverridesV1, ID: "ns/policy@uid:1", Values: []EffectivePolicyParameter{
		{Name: "policy.fixed-beta", Unit: "dimensionless", Present: true, Value: 0},
	}}
	mh, _ := manifest.CanonicalHash()
	oh, _ := overrides.CanonicalHash()
	ref := &ParameterSetReference{SchemaVersion: DecisionParameterSetV1, ManifestID: manifest.ID, ManifestHash: mh,
		PolicyOverridesID: overrides.ID, PolicyOverridesHash: oh}
	if err := VerifyParameterSet(ref, &manifest, &overrides); err != nil {
		t.Fatalf("valid retained material rejected: %v", err)
	}
	if err := VerifyParameterSet(nil, &manifest, &overrides); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy absence not explicit: %v", err)
	}
	if err := VerifyParameterSet(ref, nil, &overrides); err == nil {
		t.Fatal("missing manifest accepted")
	}
	tampered := manifest
	tampered.Parameters = append([]DecisionParameter(nil), manifest.Parameters...)
	tampered.Parameters[0].Default++
	if err := VerifyParameterSet(ref, &tampered, &overrides); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	tamperedOverrides := overrides
	tamperedOverrides.Values = append([]EffectivePolicyParameter(nil), overrides.Values...)
	tamperedOverrides.Values[0].Present = false
	if err := VerifyParameterSet(ref, &manifest, &tamperedOverrides); err == nil {
		t.Fatal("tampered effective overrides accepted")
	}
}

func TestM108EffectiveOverrideHashIsOrderStableAndPresenceSensitive(t *testing.T) {
	overrides := EffectivePolicyOverrides{SchemaVersion: DecisionPolicyOverridesV1, ID: "owner", Values: []EffectivePolicyParameter{
		{Name: "b", Unit: "ratio", Present: false, Value: 0},
		{Name: "a", Unit: "ratio", Present: true, Value: 0},
	}}
	first, err := overrides.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	overrides.Values[0], overrides.Values[1] = overrides.Values[1], overrides.Values[0]
	second, err := overrides.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("override order changed canonical hash: %s != %s", first, second)
	}
	overrides.Values[0].Present = false
	changed, err := overrides.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("explicit presence change did not change effective-policy hash")
	}
}
