package console

import "testing"

func guardrailMountPod(mounts ...map[string]any) map[string]any {
	list := make([]any, 0, len(mounts))
	for _, m := range mounts {
		list = append(list, m)
	}
	return map[string]any{"spec": map[string]any{"containers": []any{
		map[string]any{"name": "vllm", "volumeMounts": []any{map[string]any{"name": "models", "mountPath": "/models"}}},
		map[string]any{"name": "guardrail", "volumeMounts": list},
	}}}
}

func leaseFileMounts() []map[string]any {
	out := []map[string]any{}
	for _, f := range availabilityLeaseSourceFiles {
		out = append(out, map[string]any{"name": "guardrail-src", "mountPath": "/src/" + f, "subPath": f, "readOnly": true})
	}
	return out
}

// The live vLLM Pod runs the five-file endpoint-lease closure, projecting each reviewed file
// read-only by subPath. The runner must accept exactly that, keep the legacy whole-volume
// rule unchanged, and refuse partial or mixed projections.
func TestGuardrailSourceMountLegacyAndLeaseClosures(t *testing.T) {
	legacy := guardrailMountPod(map[string]any{"name": "guardrail-src", "mountPath": "/src"})
	if !availabilityGuardrailSourceMounted(legacy, "guardrail-src", false) {
		t.Fatal("legacy whole-volume source mount must be accepted")
	}
	if availabilityGuardrailSourceMounted(legacy, "guardrail-src", true) {
		t.Fatal("a lease closure mounted as a whole volume must be refused")
	}
	lease := guardrailMountPod(leaseFileMounts()...)
	if !availabilityGuardrailSourceMounted(lease, "guardrail-src", true) {
		t.Fatal("exact five-file read-only lease projection must be accepted")
	}
	if availabilityGuardrailSourceMounted(lease, "guardrail-src", false) {
		t.Fatal("subPath file mounts are not the legacy whole-volume closure")
	}
	cases := map[string][]map[string]any{
		"missing file":   leaseFileMounts()[:4],
		"duplicate file": append(leaseFileMounts(), map[string]any{"name": "guardrail-src", "mountPath": "/src/dual_server.py", "subPath": "dual_server.py", "readOnly": true}),
		"writable file":  func() []map[string]any { m := leaseFileMounts(); m[2]["readOnly"] = false; return m }(),
		"path mismatch":  func() []map[string]any { m := leaseFileMounts(); m[0]["mountPath"] = "/src/other.py"; return m }(),
		"extra whole":    append(leaseFileMounts(), map[string]any{"name": "guardrail-src", "mountPath": "/opt/src"}),
		"foreign /src":   append(leaseFileMounts(), map[string]any{"name": "other-cm", "mountPath": "/src/sitecustomize.py", "subPath": "x.py", "readOnly": true}),
		"subPathExpr":    append(leaseFileMounts()[:4], map[string]any{"name": "guardrail-src", "mountPath": "/src/drain_v11_init.py", "subPathExpr": "$(X)", "readOnly": true}),
	}
	for name, mounts := range cases {
		if availabilityGuardrailSourceMounted(guardrailMountPod(mounts...), "guardrail-src", true) {
			t.Errorf("%s: lease projection must be refused", name)
		}
	}
	noGuardrail := map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "vllm"}}}}
	if availabilityGuardrailSourceMounted(noGuardrail, "guardrail-src", true) || availabilityGuardrailSourceMounted(noGuardrail, "guardrail-src", false) {
		t.Fatal("a Pod without the guardrail container must be refused")
	}
}
