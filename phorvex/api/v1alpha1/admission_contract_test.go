package v1alpha1

import (
	"os"
	"path/filepath"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func TestPolicyCRDAdmissionBounds(t *testing.T) {
	path := filepath.Join("..", "..", "config", "crd", "bases", "phorvex.ai_phorvexpolicies.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	if len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Schema == nil || crd.Spec.Versions[0].Schema.OpenAPIV3Schema == nil {
		t.Fatalf("unexpected CRD versions/schema: %+v", crd.Spec.Versions)
	}
	root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	spec := property(t, root, "spec")
	objective := property(t, spec, "objective")
	lambda := property(t, objective, "lambda")
	if lambda.Pattern != `^$|^(0|[1-9][0-9]*)(\.[0-9]+)?$` {
		t.Fatalf("lambda pattern = %q", lambda.Pattern)
	}
	assertValidationRule(t, lambda, `self == '' || double(self) <= 10.0`, "lambda must be between 0 and 10")

	// PHORVEXSEC-189 / M-143 test (f): the exposure-pressure cap is a decimal strictly inside (0,1).
	belief := property(t, spec, "belief")
	capField := property(t, belief, "exposurePressureCap")
	if capField.Type != "string" || capField.Pattern != `^$|^0\.[0-9]+$` {
		t.Fatalf("exposurePressureCap type/pattern = %q/%q", capField.Type, capField.Pattern)
	}
	assertValidationRule(t, capField, `self == '' || (double(self) > 0.0 && double(self) < 1.0)`, "exposurePressureCap must be strictly between 0 and 1")

	budget := property(t, spec, "budget")
	for fieldName, message := range map[string]string{
		"tickInterval":           "tickInterval must be a positive duration",
		"antiOverRotationWindow": "antiOverRotationWindow must be a positive duration",
		"proactiveFloor":         "proactiveFloor must be a positive duration",
	} {
		fieldSchema := property(t, budget, fieldName)
		if fieldSchema.Type != "string" {
			t.Fatalf("%s type = %q, want string", fieldName, fieldSchema.Type)
		}
		assertValidationRule(t, fieldSchema, `duration(self) > duration('0s')`, message)
	}
}

func property(t *testing.T, schema *apiextensionsv1.JSONSchemaProps, name string) *apiextensionsv1.JSONSchemaProps {
	t.Helper()
	value, ok := schema.Properties[name]
	if !ok {
		t.Fatalf("schema property %q is absent", name)
	}
	return &value
}

func assertValidationRule(t *testing.T, schema *apiextensionsv1.JSONSchemaProps, rule, message string) {
	t.Helper()
	for _, got := range schema.XValidations {
		if got.Rule == rule && got.Message == message {
			return
		}
	}
	t.Fatalf("validation rule %q / %q absent from %+v", rule, message, schema.XValidations)
}
