package servingcontext

import (
	"strings"
	"testing"
)

func TestFromAnnotations(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		wantModel   string
		wantPort    int
		want        bool
	}{
		{name: "absent"},
		{name: "model", annotations: map[string]string{ModelIDAnnotation: " model-v1 "}, wantModel: "model-v1", want: true},
		{name: "model whitespace", annotations: map[string]string{ModelIDAnnotation: " \t\n"}},
		{name: "port", annotations: map[string]string{ServingPortAnnotation: " 8000 "}, wantPort: 8000, want: true},
		{name: "minimum port", annotations: map[string]string{ServingPortAnnotation: "1"}, wantPort: 1, want: true},
		{name: "maximum port", annotations: map[string]string{ServingPortAnnotation: "65535"}, wantPort: 65535, want: true},
		{name: "port whitespace", annotations: map[string]string{ServingPortAnnotation: " \t"}},
		{name: "malformed port", annotations: map[string]string{ServingPortAnnotation: "http"}},
		{name: "zero port", annotations: map[string]string{ServingPortAnnotation: "0"}},
		{name: "negative port", annotations: map[string]string{ServingPortAnnotation: "-1"}},
		{name: "overflow port", annotations: map[string]string{ServingPortAnnotation: "65536"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FromAnnotations(tc.annotations)
			if got.ModelID != tc.wantModel || got.Port != tc.wantPort || got.Declared() != tc.want {
				t.Fatalf("declaration = %+v declared=%v, want model=%q port=%d declared=%v", got, got.Declared(), tc.wantModel, tc.wantPort, tc.want)
			}
		})
	}
}

func TestGuardrailRosterOrderedSuccessor(t *testing.T) {
	tests := []struct {
		name, current, raw, next string
		want                     []string
	}{
		{name: "first", current: "v1", raw: " v1, v2, v2, v3 ", next: "v2", want: []string{"v1", "v2", "v3"}},
		{name: "middle", current: "v2", raw: "v1,v2,v3", next: "v3", want: []string{"v1", "v2", "v3"}},
		{name: "wrap", current: "v3", raw: "v1,v2,v3", next: "v1", want: []string{"v1", "v2", "v3"}},
		{name: "trim-current", current: " v2 ", raw: "v1, v2", next: "v1", want: []string{"v1", "v2"}},
		{name: "case-sensitive", current: "v1", raw: "v1,V1", next: "V1", want: []string{"v1", "V1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseGuardrailRoster(tc.current, tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.Current != strings.TrimSpace(tc.current) || got.Next() != tc.next || strings.Join(got.Variants, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("roster=%+v next=%q, want current=%q variants=%v next=%q", got, got.Next(), strings.TrimSpace(tc.current), tc.want, tc.next)
			}
			for _, name := range tc.want {
				if !got.Contains(name) {
					t.Fatalf("roster lost member %q: %+v", name, got)
				}
			}
		})
	}
}

func TestGuardrailRosterRefusesMalformedDeclarations(t *testing.T) {
	oversized := strings.Repeat("x", MaxGuardrailVariantBytes+1)
	for _, tc := range []struct{ name, current, raw string }{
		{name: "missing-current", raw: "v1,v2"},
		{name: "current-outside", current: "v3", raw: "v1,v2"},
		{name: "singleton", current: "v1", raw: "v1"},
		{name: "duplicate-singleton", current: "v1", raw: "v1,v1"},
		{name: "empty-middle", current: "v1", raw: "v1,,v2"},
		{name: "empty-leading", current: "v1", raw: ",v1,v2"},
		{name: "empty-trailing", current: "v1", raw: "v1,v2,"},
		{name: "oversized-current", current: oversized, raw: oversized + ",v2"},
		{name: "oversized-member", current: "v1", raw: "v1," + oversized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseGuardrailRoster(tc.current, tc.raw); err == nil {
				t.Fatalf("malformed roster accepted: %+v", got)
			}
		})
	}
}
