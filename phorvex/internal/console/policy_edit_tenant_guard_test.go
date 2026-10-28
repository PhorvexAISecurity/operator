package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// policy_edit_tenant_guard_test.go — PHORVEXSEC-205 / M-145.
//
// The console must never rewrite the tenant KEY (spec.tenant) — silently dropping the field
// (old behaviour: unknown JSON fields ignored) is as dishonest as writing it. A write the API
// server rejects must be reported as rejected with the server's message, never {"ok": true}.
// Every attempt is audited.

type execCall struct {
	bin  string
	args []string
}

func guardServer(t *testing.T, out string, err error) (*Server, *[]execCall, string) {
	t.Helper()
	calls := &[]execCall{}
	auditPath := filepath.Join(t.TempDir(), "console-mutations.jsonl")
	s := NewServer(Config{
		MutationAuditPath: auditPath,
		Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
			*calls = append(*calls, execCall{bin: bin, args: args})
			return out, err
		},
	})
	return s, calls, auditPath
}

// postEdit drives the handler as a verified operator with cross-tenant scope. [M-136] The audit
// actor is now that VERIFIED subject rather than the request's lens header.
func postEdit(t *testing.T, s *Server, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := withTestPrincipal(
		httptest.NewRequest(http.MethodPost, "/api/policy/edit", strings.NewReader(body)),
		testOperatorPrincipal(),
	)
	w := httptest.NewRecorder()
	s.policyEdit(w, req)
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %s", w.Body.String())
	}
	return w, resp
}

func auditEntries(t *testing.T, path string) []consoleMutation {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []consoleMutation
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var m consoleMutation
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// (a) a tenant write — top level or nested — is refused with 409 before any kubectl runs, and
// audited. Old code: 400 "no editable field" / silently ignored alongside another field.
func TestPolicyEditRefusesTenantKeyWrite(t *testing.T) {
	for _, body := range []string{
		`{"namespace":"vllm","name":"vllm-defense","tenant":"litellm"}`,
		`{"namespace":"vllm","name":"vllm-defense","spec":{"tenant":"litellm"}}`,
		`{"namespace":"vllm","name":"vllm-defense","mode":"dryRun","tenant":"litellm"}`,
	} {
		s, calls, auditPath := guardServer(t, "", nil)
		w, resp := postEdit(t, s, body)
		if w.Code != 409 {
			t.Fatalf("%s: status %d, want 409 (old code silently dropped the tenant field)", body, w.Code)
		}
		if resp["verdict"] != "rejected-tenant-key-write" || !strings.Contains(resp["error"].(string), "spec.tenant") {
			t.Fatalf("%s: response %v", body, resp)
		}
		if _, ok := resp["ok"]; ok {
			t.Fatalf("%s: a refused write must not carry an ok field: %v", body, resp)
		}
		if len(*calls) != 0 {
			t.Fatalf("%s: kubectl was invoked for a refused write: %+v", body, *calls)
		}
		entries := auditEntries(t, auditPath)
		if len(entries) != 1 || entries[0].Verdict != "rejected-tenant-key-write" || entries[0].Field != "spec.tenant" ||
			entries[0].Policy != "vllm-defense" || entries[0].Namespace != "vllm" ||
			entries[0].Actor != testALBIssuer+"#direct-handler-subject" || entries[0].Kind != "phorvex.console.mutation" {
			t.Fatalf("%s: audit entries = %+v", body, entries)
		}
	}
}

// (c) an edit that does not touch the tenant is unchanged: one merge patch, 200, audited as applied.
func TestPolicyEditWithoutTenantIsUnchangedAndAudited(t *testing.T) {
	s, calls, auditPath := guardServer(t, "phorvexpolicy.phorvex.ai/vllm-defense patched", nil)
	w, resp := postEdit(t, s, `{"namespace":"vllm","name":"vllm-defense","mode":"dryRun","maxMovesPerTick":2}`)
	if w.Code != 200 || resp["ok"] != true {
		t.Fatalf("status %d resp %v", w.Code, resp)
	}
	if len(*calls) != 1 || (*calls)[0].bin != "kubectl" {
		t.Fatalf("calls = %+v", *calls)
	}
	args := strings.Join((*calls)[0].args, " ")
	if !strings.Contains(args, "-n vllm patch phorvexpolicy vllm-defense --type merge -p ") ||
		!strings.Contains(args, `"mode":"dryRun"`) || !strings.Contains(args, `"maxMovesPerTick":2`) || strings.Contains(args, "tenant") {
		t.Fatalf("kubectl args = %s", args)
	}
	entries := auditEntries(t, auditPath)
	if len(entries) != 1 || entries[0].Verdict != "applied" || entries[0].Field != "spec" || !strings.Contains(entries[0].Patch, `"mode":"dryRun"`) {
		t.Fatalf("audit entries = %+v", entries)
	}
}

// Both boolean values are real edits. In particular, false must be present in the merge patch so
// an operator can turn reactive-only OFF and restore proactive exposure-driven decisions.
func TestPolicyEditReactiveOnlyPatchesBothBooleanStates(t *testing.T) {
	for _, reactiveOnly := range []bool{true, false} {
		t.Run(fmt.Sprintf("reactiveOnly=%t", reactiveOnly), func(t *testing.T) {
			s, calls, auditPath := guardServer(t, "phorvexpolicy.phorvex.ai/demo-defense patched", nil)
			body := fmt.Sprintf(`{"namespace":"demo","name":"demo-defense","reactiveOnly":%t}`, reactiveOnly)
			w, resp := postEdit(t, s, body)
			if w.Code != http.StatusOK || resp["ok"] != true {
				t.Fatalf("status %d resp %v", w.Code, resp)
			}
			if len(*calls) != 1 {
				t.Fatalf("calls = %+v", *calls)
			}
			args := strings.Join((*calls)[0].args, " ")
			want := fmt.Sprintf(`"triggers":{"reactiveOnly":%t}`, reactiveOnly)
			if !strings.Contains(args, want) {
				t.Fatalf("kubectl args = %s; want %s", args, want)
			}
			entries := auditEntries(t, auditPath)
			if len(entries) != 1 || entries[0].Verdict != "applied" || !strings.Contains(entries[0].Patch, want) {
				t.Fatalf("audit entries = %+v; want patch %s", entries, want)
			}
		})
	}
}

// (d) a server-side rejection (validation / admission webhook) is returned verbatim as a
// rejection — 422, ok:false — never {"ok": true}; audited as rejected-by-apiserver.
func TestPolicyEditPropagatesAPIServerRejectionVerbatim(t *testing.T) {
	webhook := `Error from server (Forbidden): admission webhook "vphorvexpolicy.phorvex.ai" denied the request: spec.tenant "litellm" is in use by litellm/litellm-defense`
	s, _, auditPath := guardServer(t, webhook, errors.New("exit status 1"))
	w, resp := postEdit(t, s, `{"namespace":"vllm","name":"vllm-defense","mode":"active"}`)
	if w.Code != 422 {
		t.Fatalf("status %d, want 422 for a server-side rejection", w.Code)
	}
	if resp["ok"] != false || resp["verdict"] != "rejected-by-apiserver" || !strings.Contains(resp["error"].(string), `denied the request: spec.tenant "litellm" is in use`) {
		t.Fatalf("rejection not propagated verbatim: %v", resp)
	}
	entries := auditEntries(t, auditPath)
	if len(entries) != 1 || entries[0].Verdict != "rejected-by-apiserver" || !strings.Contains(entries[0].Message, "denied the request") {
		t.Fatalf("audit entries = %+v", entries)
	}

	// A transport/exec failure after dispatch has an unknown effect and is unsafe to retry.
	s2, _, _ := guardServer(t, "Unable to connect to the server: dial tcp: i/o timeout", errors.New("exit status 1"))
	w2, resp2 := postEdit(t, s2, `{"namespace":"vllm","name":"vllm-defense","mode":"active"}`)
	if w2.Code != 502 || resp2["ok"] != false || resp2["verdict"] != "effect-unknown" || resp2["unsafeToRetry"] != true || resp2["effectUnknown"] != true {
		t.Fatalf("transport failure: status %d resp %v", w2.Code, resp2)
	}
}

// (e) a body with nothing editable is still a plain 400 (no kubectl, no audit noise).
func TestPolicyEditNoEditableFieldStillRejected(t *testing.T) {
	s, calls, auditPath := guardServer(t, "", nil)
	w, _ := postEdit(t, s, `{"namespace":"vllm","name":"vllm-defense"}`)
	if w.Code != 400 || len(*calls) != 0 || len(auditEntries(t, auditPath)) != 0 {
		t.Fatalf("status %d calls %d audit %d", w.Code, len(*calls), len(auditEntries(t, auditPath)))
	}
}
