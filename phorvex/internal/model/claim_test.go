package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestClaimScopeEvidenceBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ids   []string
		known bool
		cap   string
	}{
		{"historical", nil, false, "unknown"},
		{"no trusted detector", []string{}, true, "unknown"},
		{"configured is not measured recall", []string{"b", "a", "b", ""}, true, "detector-bounded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]string(nil), tc.ids...)
			c := NewClaimScope(tc.ids, tc.known, "image:record", "sha-record")
			if c.Scope != "modeled" || c.RecallCap != tc.cap || c.DetectorSetKnown != tc.known || c.DetectorSet == nil {
				t.Fatalf("wrong boundary: %+v", c)
			}
			if !strings.Contains(c.Note, "not confirmation") || c.BrainImage != "image:record" || c.GitSHA != "sha-record" {
				t.Fatalf("missing qualification: %+v", c)
			}
			if len(tc.ids) > 0 {
				if !reflect.DeepEqual(tc.ids, original) || !reflect.DeepEqual(c.DetectorSet, []string{"a", "b"}) {
					t.Fatal("allowlist was mutated or not canonical")
				}
				tc.ids[0] = "changed"
				if c.DetectorSet[1] != "b" {
					t.Fatal("claim aliases live configuration")
				}
			}
		})
	}
	c := NewClaimScope(nil, false, "", "")
	if c.BrainImage != "unavailable" || c.GitSHA != "unavailable" {
		t.Fatal("invented build")
	}
}
