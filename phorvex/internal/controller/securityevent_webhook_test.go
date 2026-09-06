package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/phorvex/phorvex/internal/ingest"
)

// securityevent_webhook_test.go — PHORVEXSEC-193 / M-94: the creator identity is written by
// admission, from the authenticated request, and cannot be self-declared.

const canaryUser = "system:serviceaccount:vllm:detector-kv-canary"

func stampReq(t *testing.T, op admissionv1.Operation, user string, annotations map[string]string) admission.Response {
	t.Helper()
	obj := map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1",
		"kind":       "SecurityEvent",
		"metadata":   map[string]any{"name": "ev-1"},
		"spec":       map[string]any{"targets": []any{"vllm/vllm-0"}},
	}
	if annotations != nil {
		ann := map[string]any{}
		for k, v := range annotations {
			ann[k] = v
		}
		obj["metadata"].(map[string]any)["annotations"] = ann
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return SecurityEventStamper{}.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: op,
			UserInfo:  authenticationv1.UserInfo{Username: user},
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
}

func patchValues(resp admission.Response) string {
	var b strings.Builder
	for _, p := range resp.Patches {
		v, _ := json.Marshal(p.Value)
		b.WriteString(p.Operation + " " + p.Path + " " + string(v) + "\n")
	}
	return b.String()
}

// A created event carries the authenticated creator, not the one the client claims.
func TestStampWritesAuthenticatedCreator(t *testing.T) {
	resp := stampReq(t, admissionv1.Create, canaryUser, nil)
	if !resp.Allowed {
		t.Fatalf("stamp rejected the event: %+v", resp.Result)
	}
	got := patchValues(resp)
	if !strings.Contains(got, canaryUser) || !strings.Contains(got, ingest.CreatorIdentityAnnotation) {
		t.Fatalf("no creator stamp in the patch:\n%s", got)
	}
}

// The self-declared claim is overwritten — this is the whole trust boundary.
func TestStampOverwritesClientSuppliedIdentity(t *testing.T) {
	resp := stampReq(t, admissionv1.Create, canaryUser,
		map[string]string{ingest.CreatorIdentityAnnotation: "system:serviceaccount:vllm:detector-kv-canary-IMPOSTER"})
	got := patchValues(resp)
	if strings.Contains(got, "IMPOSTER") && !strings.Contains(got, canaryUser) {
		t.Fatalf("client claim survived admission:\n%s", got)
	}
	if !strings.Contains(got, canaryUser) {
		t.Fatalf("authenticated identity not written:\n%s", got)
	}
}

// An UPDATE is stamped too: an event cannot be edited later to acquire a trusted creator.
func TestStampAppliesOnUpdate(t *testing.T) {
	resp := stampReq(t, admissionv1.Update, "system:serviceaccount:evil:squatter",
		map[string]string{ingest.CreatorIdentityAnnotation: canaryUser})
	got := patchValues(resp)
	if !strings.Contains(got, "evil:squatter") {
		t.Fatalf("update did not re-stamp the editing identity:\n%s", got)
	}
}

// With no authenticated user the claim is removed, never left standing.
func TestStampRemovesClaimWhenUnauthenticated(t *testing.T) {
	resp := stampReq(t, admissionv1.Create, "", map[string]string{ingest.CreatorIdentityAnnotation: canaryUser})
	got := patchValues(resp)
	if strings.Contains(got, "add") && strings.Contains(got, canaryUser) {
		t.Fatalf("unauthenticated request kept a creator claim:\n%s", got)
	}
	if !strings.Contains(got, "remove") {
		t.Fatalf("expected the annotation to be removed:\n%s", got)
	}
}

// Deletes are not the stamp's business.
func TestStampIgnoresDelete(t *testing.T) {
	resp := SecurityEventStamper{}.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Delete},
	})
	if !resp.Allowed || len(resp.Patches) != 0 {
		t.Fatalf("delete must pass through unpatched: %+v", resp)
	}
}

// Idempotence: stamping an already-correctly-stamped object changes nothing.
func TestStampIsIdempotent(t *testing.T) {
	resp := stampReq(t, admissionv1.Create, canaryUser, map[string]string{ingest.CreatorIdentityAnnotation: canaryUser})
	if len(resp.Patches) != 0 {
		t.Fatalf("re-stamping an identical object produced a patch: %s", patchValues(resp))
	}
}
