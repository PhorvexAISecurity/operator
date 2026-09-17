package servingcontext

import "testing"

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
