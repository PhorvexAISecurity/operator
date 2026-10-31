package console

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

// colonCatalogueIDs are the canonical catalogue IDs that contain ':'. Kubernetes
// label values reject ':', so each must be projected through
// catalogueIDLabelValue before it can be used as a label value.
var colonCatalogueIDs = []string{
	"ASI02:2026", "ASI03:2026", "ASI05:2026", "ASI06:2026", "ASI07:2026",
	"ASI08:2026", "ASI10:2026", "LLM06:2025", "LLM08:2025", "LLM10:2025",
	"MCP01:2025", "MCP02:2025", "MCP05:2025", "MCP09:2025", "MCP10:2025",
}

func TestCatalogueIDLabelValueIsValidForColonIDs(t *testing.T) {
	for _, id := range colonCatalogueIDs {
		value := catalogueIDLabelValue(id)
		if errs := validation.IsValidLabelValue(value); len(errs) != 0 {
			t.Errorf("catalogueIDLabelValue(%q) = %q is not a valid k8s label value: %v", id, value, errs)
		}
		if strings.Contains(value, ":") {
			t.Errorf("catalogueIDLabelValue(%q) = %q still contains a colon", id, value)
		}
		if len(value) > 63 {
			t.Errorf("catalogueIDLabelValue(%q) = %q exceeds 63 characters (%d)", id, value, len(value))
		}
	}
}

func TestCatalogueIDLabelValueIsDeterministic(t *testing.T) {
	for _, id := range colonCatalogueIDs {
		first := catalogueIDLabelValue(id)
		second := catalogueIDLabelValue(id)
		if first != second {
			t.Errorf("catalogueIDLabelValue(%q) is not deterministic: %q != %q", id, first, second)
		}
	}
}

func TestCatalogueIDLabelValueAvoidsSlugCollision(t *testing.T) {
	// Two distinct canonical IDs that slugify identically must still map to
	// different label values; the sha256-derived suffix guarantees this.
	colon := catalogueIDLabelValue("ASI02:2026")
	dash := catalogueIDLabelValue("ASI02-2026")
	if colon == dash {
		t.Fatalf("distinct IDs collided onto the same label value: %q", colon)
	}
	if errs := validation.IsValidLabelValue(colon); len(errs) != 0 {
		t.Fatalf("label value for colon ID invalid: %v", errs)
	}
	if errs := validation.IsValidLabelValue(dash); len(errs) != 0 {
		t.Fatalf("label value for dash ID invalid: %v", errs)
	}
}

func TestCatalogueIDLabelValueBoundsLongPathologicalID(t *testing.T) {
	pathological := strings.Repeat("ASI99:2026-really-long-identifier/", 8)
	value := catalogueIDLabelValue(pathological)
	if len(value) > 63 {
		t.Fatalf("catalogueIDLabelValue(long) = %q exceeds 63 characters (%d)", value, len(value))
	}
	if errs := validation.IsValidLabelValue(value); len(errs) != 0 {
		t.Fatalf("catalogueIDLabelValue(long) = %q is not a valid k8s label value: %v", value, errs)
	}
}

func TestCatalogueIDLabelValueHandlesEmptyAndNonAlphanumeric(t *testing.T) {
	for _, id := range []string{"", ":", "::::", "///"} {
		value := catalogueIDLabelValue(id)
		if errs := validation.IsValidLabelValue(value); len(errs) != 0 {
			t.Errorf("catalogueIDLabelValue(%q) = %q is not a valid k8s label value: %v", id, value, errs)
		}
	}
}
