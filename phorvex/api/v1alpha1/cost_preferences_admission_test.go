package v1alpha1

import (
	"os"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func TestCostPreferencesAdmissionContract(t *testing.T) {
	raw, err := os.ReadFile("../../config/crd/bases/phorvex.ai_phorvexpolicies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	obj := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["objective"]
	assertValidationRule(t, &obj, `!has(self.costPreferences) || !has(self.disruptionAversion) || size(self.disruptionAversion) == 0`, "costPreferences and nonempty disruptionAversion are mutually exclusive")
	prefs := property(t, &obj, "costPreferences")
	if prefs.Type != "object" || len(prefs.Required) != 2 {
		t.Fatalf("missing required component contract: %+v", prefs)
	}
	for _, name := range []string{"norm", "flow"} {
		found := false
		for _, required := range prefs.Required {
			found = found || required == name
		}
		if !found {
			t.Fatalf("%s not required", name)
		}
		component := property(t, prefs, name)
		if component.Type != "string" || component.Pattern != `^(0|[1-9][0-9]*)(\.[0-9]+)?$` {
			t.Fatalf("invalid %s schema: %+v", name, component)
		}
		assertValidationRule(t, component, `double(self) <= 10.0`, name+" preference must be between 0 and 10")
	}
}
