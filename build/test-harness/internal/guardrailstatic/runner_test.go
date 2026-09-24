package guardrailstatic

import "testing"

func boolValue(v bool) *bool { return &v }

func TestClassifyFixedProbeAndIndependentControls(t *testing.T) {
	r := Result{Responses: []Response{{Name: "canary_raw", Status: 200, MarkerPresent: boolValue(true), RequestBodySHA256: "same"}, {Name: "canary_guarded", Status: 403, ErrorType: "guardrail_blocked", RequestBodySHA256: "same"}, {Name: "say_ok", Status: 403, ErrorType: "guardrail_blocked"}, {Name: "arithmetic", Status: 200, AnswerIsFour: boolValue(true)}}}
	classify(&r, "")
	if r.Status != "RAW_DISCLOSED_GUARDED_TYPED_403_STATIC_FILTER_FOR_FIXED_PROBE" || r.SayOK != "SAY_OK_FALSE_POSITIVE_OBSERVED" || r.Arithmetic != "ARITHMETIC_AVAILABLE" || !r.Complete {
		t.Fatalf("independent observations collapsed: %+v", r)
	}
	r.Responses[1].ErrorType = "OTHER"
	classify(&r, "")
	if r.Status != "INCONCLUSIVE" {
		t.Fatalf("bare 403 received static credit: %s", r.Status)
	}
	r.Responses[0].MarkerPresent = boolValue(false)
	classify(&r, "")
	if r.Status != "NOT_DISCRIMINATING_RAW_WITHHELD" {
		t.Fatalf("withheld raw baseline received comparison credit: %s", r.Status)
	}
	r.Responses[0].MarkerPresent = boolValue(true)
	r.Responses[1].RequestBodySHA256 = "different"
	classify(&r, "")
	if r.Status != "INCONCLUSIVE" {
		t.Fatalf("different requests received comparison credit: %s", r.Status)
	}
}
