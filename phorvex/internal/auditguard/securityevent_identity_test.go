/*
 * M-94 permanent regression — the shipped SecurityEvent creator-identity guard.
 *
 * The mutating stamp webhook is failurePolicy=Ignore on purpose (Phorvex must never be able
 * to block the cluster's security-event flow). While its endpoint is down the API server
 * stores the object UNCHANGED, so a client-supplied phorvex.ai/creator-identity survives and
 * ingest grants it belief evidence. The ValidatingAdmissionPolicy + Deny binding shipped in
 * templates/securityevent-identity-policy.yaml is what closes that: it runs in-process in the
 * API server, after mutation, and has no endpoint that can be unreachable.
 *
 * WHAT IS REAL HERE
 *   policy/binding  REAL — `helm template` over phorvex/charts/phorvex, parsed from the
 *                          render (not from the template source).
 *   CEL             REAL — github.com/google/cel-go compiles and evaluates the rendered
 *                          spec.variables, spec.validations[].expression and
 *                          messageExpression exactly as rendered.
 *   mutation        REAL — internal/controller.SecurityEventStamper{}.Handle, the shipped
 *                          handler, invoked with an admission.Request carrying UserInfo; its
 *                          RFC6902 patch is applied to the candidate object.
 *   consumer        REAL — internal/ingest.CollectSnapshot, the entry the operator tick
 *                          calls; verdicts from Snapshot.Events[].Trust, belief evidence
 *                          from Snapshot.EventByPod.
 *
 * WHAT IS MODELLED (disclosed, and exercised by negative controls)
 *   - resourceRules matching (apiGroups/apiVersions/resources+subresource/operations/scope)
 *     is this file's implementation of the documented Kubernetes semantics. There is no
 *     apiserver in this test. See TestSecurityEventIdentityPolicyResourceMatching.
 *   - Stamp-endpoint reachability is a parameter, not an induced outage: `reachable=false`
 *     stands for "the webhook Service has no ready endpoint", and failurePolicy=Ignore is
 *     then applied as documented (request proceeds WITHOUT the mutation).
 *   - Ordering (mutating admission, then validating admission) is applied explicitly here
 *     because it is the documented apiserver order.
 *   A passing CEL unit test is NOT evidence of a deployed guard: live activation of the
 *   policy and binding is a separate, recorded step.
 */

package auditguard

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	admissionv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	webhookadm "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	pxv1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/controller"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	seGuardLabel = "securityevent-identity"
	seTrustedSA  = "system:serviceaccount:vllm:detector-kv-canary"
	seAttackSA   = "system:serviceaccount:tenant-a:app"
	seTarget     = "vllm/vllm-0"
	// The version floor the guard's API needs; also what the chart declares.
	seKubeVersion = "1.30.0"
)

// seRender renders the shipped chart with defaults (the identity guard is default-on).
func seRender(t *testing.T, release, namespace string, extra ...string) []object {
	t.Helper()
	docs, err := render(t, release, namespace, seKubeVersion,
		filepath.Join(repository(t), "phorvex/charts/phorvex"), extra...)
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

// seGuardDoc returns the single rendered object of `kind` carrying the guard's policy label.
func seGuardDoc(t *testing.T, docs []object, kind string) object {
	t.Helper()
	var found []object
	for _, doc := range docs {
		if doc["kind"] != kind {
			continue
		}
		labels, _ := doc["metadata"].(object)["labels"].(object)
		if labels["phorvex.ai/policy"] != seGuardLabel {
			continue
		}
		found = append(found, doc)
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s labelled %s, got %d", kind, seGuardLabel, len(found))
	}
	return found[0]
}

func seGuardDocs(t *testing.T, docs []object) (policy, binding object) {
	t.Helper()
	return seGuardDoc(t, docs, "ValidatingAdmissionPolicy"), seGuardDoc(t, docs, "ValidatingAdmissionPolicyBinding")
}

// ---------------------------------------------------------------------------
// REAL cel-go over the rendered variables + validations
// ---------------------------------------------------------------------------

func seCEL(t *testing.T, expression string, activation map[string]any) any {
	t.Helper()
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("variables", cel.DynType),
	)
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("shipped CEL does not compile: %v\n%s", issues.Err(), expression)
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := program.Eval(activation)
	if err != nil {
		// A shipped policy expression must be total: an evaluation error under
		// failurePolicy=Fail rejects the request, including legitimate ones.
		t.Fatalf("shipped CEL must be total, got eval error: %v\n%s", err, expression)
	}
	return out.Value()
}

// seValidate evaluates the RENDERED policy exactly: every spec.variables entry in order,
// then every spec.validations entry. It returns the deny message of the first failing
// validation (evaluated from the rendered messageExpression), or "" when the request passes.
func seValidate(t *testing.T, policy object, obj, old object, username, operation string) (allowed bool, message string) {
	t.Helper()
	request := object{
		"operation": operation,
		"userInfo":  object{"username": username, "groups": []any{"system:authenticated"}},
		"resource":  object{"group": "amtd.r6security.com", "version": "v1beta1", "resource": "securityevents"},
	}
	activation := map[string]any{"object": obj, "oldObject": old, "request": request}

	spec := policy["spec"].(object)
	if _, present := spec["matchConditions"]; present {
		// A matchCondition would make the guard opt-in per object, which is exactly the
		// weakness of the protected-outcomes hook this policy replaces the reliance on.
		t.Fatal("the identity policy must not carry matchConditions: it must match every SecurityEvent")
	}
	vars := object{}
	activation["variables"] = vars
	for _, raw := range spec["variables"].([]any) {
		v := raw.(object)
		vars[v["name"].(string)] = seCEL(t, v["expression"].(string), activation)
	}
	for _, raw := range spec["validations"].([]any) {
		v := raw.(object)
		result, ok := seCEL(t, v["expression"].(string), activation).(bool)
		if !ok {
			t.Fatalf("validation expression must return bool: %s", v["expression"])
		}
		if result {
			continue
		}
		if v["reason"] != "Forbidden" {
			t.Fatalf("a denied creator claim must be Forbidden, got %v", v["reason"])
		}
		msg, ok := seCEL(t, v["messageExpression"].(string), activation).(string)
		if !ok {
			t.Fatalf("messageExpression must return a string: %s", v["messageExpression"])
		}
		return false, msg
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// modelled resourceRules matching (documented k8s semantics; disclosed)
// ---------------------------------------------------------------------------

func seRuleMatches(rule object, group, version, resource, subresource, operation, scope string) bool {
	in := func(key, want string) bool {
		for _, v := range rule[key].([]any) {
			if s := v.(string); s == "*" || s == want {
				return true
			}
		}
		return false
	}
	target := resource
	if subresource != "" {
		target = resource + "/" + subresource
	}
	resourceHit := false
	for _, v := range rule["resources"].([]any) {
		s := v.(string)
		// "*" matches all resources but NOT subresources; "*/*" matches both.
		if s == target || s == "*/*" || (s == "*" && subresource == "") ||
			(subresource != "" && s == resource+"/*") {
			resourceHit = true
		}
	}
	if !resourceHit || !in("apiGroups", group) || !in("apiVersions", version) || !in("operations", operation) {
		return false
	}
	if s, ok := rule["scope"].(string); ok && s != "" && s != "*" && s != scope {
		return false
	}
	return true
}

func seMatchesRequest(policy object, group, version, resource, subresource, operation, scope string) bool {
	for _, raw := range policy["spec"].(object)["matchConstraints"].(object)["resourceRules"].([]any) {
		if seRuleMatches(raw.(object), group, version, resource, subresource, operation, scope) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// fixtures + the real producer and the real consumer
// ---------------------------------------------------------------------------

func seEvent(name string, annotations map[string]string) object {
	meta := object{"name": name, "creationTimestamp": "2026-09-10T11:59:00Z"}
	if annotations != nil {
		a := object{}
		for k, v := range annotations {
			a[k] = v
		}
		meta["annotations"] = a
	}
	return object{
		"apiVersion": "amtd.r6security.com/v1beta1",
		"kind":       "SecurityEvent",
		"metadata":   meta,
		"spec": object{
			"targets":     []any{seTarget},
			"description": "detector observed anomalous KV reuse",
			"rule":        object{"type": "Persistence", "threatLevel": "critical", "source": "SomeDetector"},
		},
	}
}

// seClaim reads the creator-identity annotation off a candidate/stored object. A missing
// annotations map, a missing key and an empty value all read as "" — exactly what ingest
// sees, and exactly the case the policy admits.
func seClaim(event object) string {
	annotations, _ := event["metadata"].(object)["annotations"].(object)
	claim, _ := annotations[ingest.CreatorIdentityAnnotation].(string)
	return claim
}

func seTrustFixture(t *testing.T) {
	t.Helper()
	previous := ingest.EventTrust()
	t.Cleanup(func() { ingest.ConfigureEventTrust(previous) })
	ingest.ConfigureEventTrust(ingest.NewTrustedDetectors([]string{"vllm/detector-kv-canary"}))
}

// seStamp runs the REAL shipped mutating handler and applies its patch, i.e. what the API
// server stores when the stamp endpoint IS reachable.
func seStamp(t *testing.T, candidate, old object, username, operation string) object {
	t.Helper()
	raw, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	request := webhookadm.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Operation(operation),
		Resource:  metav1.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents"},
		Object:    k8sruntime.RawExtension{Raw: raw},
		UserInfo:  authnv1.UserInfo{Username: username},
	}}
	if old != nil {
		oldRaw, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		request.OldObject = k8sruntime.RawExtension{Raw: oldRaw}
	}
	response := controller.SecurityEventStamper{}.Handle(context.Background(), request)
	if !response.Allowed {
		t.Fatalf("the shipped stamper denied a request it must allow: %+v", response.Result)
	}
	return seApplyPatch(t, raw, response.Patches)
}

type sePatchOp struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Value     any    `json:"value,omitempty"`
}

// seApplyPatch applies the RFC6902 operations the handler emitted. Only the shapes the
// stamper produces are implemented; anything else fails loudly rather than mis-modelling.
func seApplyPatch(t *testing.T, raw []byte, patches any) object {
	t.Helper()
	encoded, err := json.Marshal(patches)
	if err != nil {
		t.Fatal(err)
	}
	var ops []sePatchOp
	if err := json.Unmarshal(encoded, &ops); err != nil {
		t.Fatal(err)
	}
	var doc object
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		parts := strings.Split(strings.TrimPrefix(op.Path, "/"), "/")
		for i := range parts {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
		}
		cursor := doc
		for i := 0; i < len(parts)-1; i++ {
			next, ok := cursor[parts[i]].(object)
			if !ok {
				next = object{}
				cursor[parts[i]] = next
			}
			cursor = next
		}
		leaf := parts[len(parts)-1]
		switch op.Operation {
		case "add", "replace":
			cursor[leaf] = op.Value
		case "remove":
			delete(cursor, leaf)
		default:
			t.Fatalf("unmodelled patch op %q on %s", op.Operation, op.Path)
		}
	}
	return doc
}

// seConsume feeds the STORED object to the real ingest entry point.
func seConsume(t *testing.T, stored object) (verdict string, evidence int) {
	t.Helper()
	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	var event amtdv1beta1.SecurityEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	scheme := k8sruntime.NewScheme()
	for _, add := range []func(*k8sruntime.Scheme) error{clientgoscheme.AddToScheme, amtdv1beta1.AddToScheme, pxv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&event).Build()
	snapshot, err := ingest.CollectSnapshot(context.Background(), c,
		time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC), func(*model.Pod) float64 { return 0 })
	if err != nil {
		t.Fatalf("ingest.CollectSnapshot: %v", err)
	}
	for _, e := range snapshot.Events {
		if e.Name == event.Name {
			verdict = e.Trust
		}
	}
	for _, target := range event.Spec.Targets {
		evidence += len(snapshot.EventByPod[target])
	}
	return verdict, evidence
}

// ---------------------------------------------------------------------------
// 1. the shipped manifest: fail-closed policy AND an enforcing Deny binding
// ---------------------------------------------------------------------------

func TestSecurityEventIdentityPolicyShipsFailClosedDenyBinding(t *testing.T) {
	docs := seRender(t, "phorvex", "phorvex-system")
	policy, binding := seGuardDocs(t, docs)

	if policy["apiVersion"] != "admissionregistration.k8s.io/v1" || binding["apiVersion"] != "admissionregistration.k8s.io/v1" {
		t.Fatalf("guard must use the stable API already shipped by this chart: %v / %v",
			policy["apiVersion"], binding["apiVersion"])
	}
	pm, bm := policy["metadata"].(object), binding["metadata"].(object)
	ps, bs := policy["spec"].(object), binding["spec"].(object)

	if pm["name"] != bm["name"] || bs["policyName"] != pm["name"] {
		t.Fatalf("binding must reference this release's policy: %v / %v / %v", pm["name"], bm["name"], bs["policyName"])
	}
	if len(pm["name"].(string)) > 63 {
		t.Fatalf("cluster-scoped policy name is oversized: %s", pm["name"])
	}
	if ps["failurePolicy"] != "Fail" {
		t.Fatalf("the guard must fail closed, got failurePolicy=%v", ps["failurePolicy"])
	}
	if !reflect.DeepEqual(bs["validationActions"], []any{"Deny"}) {
		t.Fatalf("a policy without a Deny binding enforces nothing: validationActions=%v", bs["validationActions"])
	}
	if _, present := bs["matchResources"]; present {
		t.Fatalf("the binding must not narrow or exempt anything the policy matches: %v", bs["matchResources"])
	}
	if _, present := ps["matchConditions"]; present {
		t.Fatal("the policy must match every SecurityEvent, not only objects that opt in via an annotation")
	}
	if pm["annotations"].(object)["argocd.argoproj.io/sync-wave"] != "-2" ||
		bm["annotations"].(object)["argocd.argoproj.io/sync-wave"] != "-1" {
		t.Fatal("policy must be applied before its binding, and both before the Deployment")
	}

	constraints := ps["matchConstraints"].(object)
	want := []any{object{
		"apiGroups":   []any{"amtd.r6security.com"},
		"apiVersions": []any{"*"},
		"operations":  []any{"CREATE", "UPDATE"},
		"resources":   []any{"securityevents"},
		"scope":       "*",
	}}
	if constraints["matchPolicy"] != "Equivalent" || !reflect.DeepEqual(constraints["resourceRules"], want) {
		t.Fatalf("guard must match full-resource SecurityEvent CREATE+UPDATE cluster-wide: %#v", constraints)
	}
	t.Logf("rendered guard %s: failurePolicy=%v validationActions=%v rules=%v",
		pm["name"], ps["failurePolicy"], bs["validationActions"], constraints["resourceRules"])
}

// ---------------------------------------------------------------------------
// 2. group/version/operation/subresource matching, with negative controls
// ---------------------------------------------------------------------------

func TestSecurityEventIdentityPolicyResourceMatching(t *testing.T) {
	policy := seGuardDoc(t, seRender(t, "phorvex", "phorvex-system"), "ValidatingAdmissionPolicy")

	for _, tc := range []struct {
		name                                                    string
		group, version, resource, subresource, operation, scope string
		want                                                    bool
		why                                                     string
	}{
		{"create", "amtd.r6security.com", "v1beta1", "securityevents", "", "CREATE", "Cluster", true,
			"the forged-creation path"},
		{"update", "amtd.r6security.com", "v1beta1", "securityevents", "", "UPDATE", "Cluster", true,
			"the full-resource rewrite path"},
		{"future-served-version", "amtd.r6security.com", "v1beta2", "securityevents", "", "CREATE", "Cluster", true,
			"apiVersions '*': the guard must not lapse when the CRD adds a version"},
		{"namespaced-install", "amtd.r6security.com", "v1beta1", "securityevents", "", "CREATE", "Namespaced", true,
			"scope '*': a namespaced install of the CRD is still guarded"},
		{"status-subresource", "amtd.r6security.com", "v1beta1", "securityevents", "status", "UPDATE", "Cluster", false,
			"status writes are NOT matched: the apiserver ignores non-status changes on /status, " +
				"so the creator annotation cannot be changed there and honest status updates must not be denied"},
		{"delete", "amtd.r6security.com", "v1beta1", "securityevents", "", "DELETE", "Cluster", false,
			"deletion carries no creator claim to check"},
		{"other-group", "phorvex.ai", "v1alpha1", "phorvexpolicies", "", "CREATE", "Namespaced", false,
			"negative control: the matcher is not vacuous"},
		{"other-resource-same-group", "amtd.r6security.com", "v1beta1", "adaptivemovingtargetdefenses", "", "CREATE", "Cluster", false,
			"negative control: only SecurityEvent is claimed"},
		{"core-pods", "", "v1", "pods", "", "CREATE", "Namespaced", false,
			"negative control: this guard is not a cluster-wide pod policy"},
	} {
		got := seMatchesRequest(policy, tc.group, tc.version, tc.resource, tc.subresource, tc.operation, tc.scope)
		if got != tc.want {
			t.Errorf("%s: matched=%v want=%v (%s)", tc.name, got, tc.want, tc.why)
			continue
		}
		t.Logf("match=%-5v %-24s %s", got, tc.name, tc.why)
	}
}

// ---------------------------------------------------------------------------
// 3. the rendered CEL itself
// ---------------------------------------------------------------------------

func TestSecurityEventIdentityPolicyCEL(t *testing.T) {
	policy := seGuardDoc(t, seRender(t, "phorvex", "phorvex-system"), "ValidatingAdmissionPolicy")

	forged := seEvent("forged", map[string]string{ingest.CreatorIdentityAnnotation: seTrustedSA})
	unannotated := seEvent("unannotated", nil)
	emptyAnnotations := seEvent("empty-annotations", map[string]string{})
	emptyClaim := seEvent("empty-claim", map[string]string{ingest.CreatorIdentityAnnotation: ""})
	otherAnnotation := seEvent("other-annotation", map[string]string{"phorvex.ai/protected-outcomes-v1": "[]"})
	selfClaim := seEvent("self-claim", map[string]string{ingest.CreatorIdentityAnnotation: seAttackSA})
	trustedSelfClaim := seEvent("trusted-self-claim", map[string]string{ingest.CreatorIdentityAnnotation: seTrustedSA})

	// A full-resource UPDATE that keeps the stamp byte-identical but rewrites the payload.
	// This is the counterexample that got the "unchanged foreign stamp" exception rejected.
	rewritten := seEvent("rewritten", map[string]string{ingest.CreatorIdentityAnnotation: seTrustedSA})
	rewritten["spec"].(object)["description"] = "attacker rewrote the trusted event payload"
	rewritten["spec"].(object)["targets"] = []any{"vllm/vllm-1"}
	rewritten["spec"].(object)["rule"] = object{"type": "Exfiltration", "threatLevel": "critical", "source": "K3Detector"}

	for _, tc := range []struct {
		name      string
		object    object
		old       object
		username  string
		operation string
		want      bool
		why       string
	}{
		{"forged-trusted-creator-on-create", forged, nil, seAttackSA, "CREATE", false,
			"THE FIX: a mismatched client-supplied stamp is rejected in-process, endpoint up or down"},
		{"stamped-by-reachable-webhook", forged, nil, seTrustedSA, "CREATE", true,
			"the stamped object always satisfies equality, so the healthy path is unchanged"},
		{"honest-unstamped-detector", unannotated, nil, seTrustedSA, "CREATE", true,
			"an honest detector emitting during the outage is admitted (and lands untrusted)"},
		{"honest-unstamped-stranger", unannotated, nil, seAttackSA, "CREATE", true,
			"no claim, no denial: ingestion stays open, belief stays closed"},
		{"empty-annotation-map", emptyAnnotations, nil, seAttackSA, "CREATE", true,
			"an empty annotations map carries no claim"},
		{"empty-claim-value", emptyClaim, nil, seAttackSA, "CREATE", true,
			"an empty claim is no claim; ingest reads it as unstamped"},
		{"unrelated-annotation-only", otherAnnotation, nil, seAttackSA, "CREATE", true,
			"other annotations are none of this policy's business"},
		{"self-claim-untrusted-creator", selfClaim, nil, seAttackSA, "CREATE", true,
			"a caller may assert its OWN username: that grants nothing it did not already hold"},
		{"self-claim-trusted-creator", trustedSelfClaim, nil, seTrustedSA, "CREATE", true,
			"the allowlisted detector may assert its own identity"},
		{"claim-with-no-authenticated-user", forged, nil, "", "CREATE", false,
			"a missing username must never authorise a non-empty claim"},
		{"empty-claim-with-no-authenticated-user", emptyClaim, nil, "", "CREATE", true,
			"...but it also must not block an unstamped object"},
		{"foreign-stamp-carried-over-on-update", forged, forged, seAttackSA, "UPDATE", false,
			"NO unchanged-foreign-stamp exception: retaining another principal's stamp is denied"},
		{"foreign-stamp-with-payload-rewrite", rewritten, forged, seAttackSA, "UPDATE", false,
			"the rejected exception's counterexample: rewriting targets/rule/description under a " +
				"retained trusted stamp"},
		{"own-stamp-on-update", trustedSelfClaim, trustedSelfClaim, seTrustedSA, "UPDATE", true,
			"the legitimate owner updating its own event is unaffected"},
		{"stranger-clearing-the-stamp-on-update", unannotated, forged, seAttackSA, "UPDATE", true,
			"an updater with no claim to the stamp may drop it; the event becomes untrusted"},
		{"stamp-changed-to-foreign-on-update", forged, unannotated, seAttackSA, "UPDATE", false,
			"introducing a foreign stamp on UPDATE is denied"},
	} {
		allowed, message := seValidate(t, policy, tc.object, tc.old, tc.username, tc.operation)
		verdict := "ALLOW"
		if !allowed {
			verdict = "DENY "
		}
		t.Logf("%s %-38s user=%-46s op=%-6s  %s", verdict, tc.name, tc.username, tc.operation, tc.why)
		if allowed != tc.want {
			t.Errorf("%s: allowed=%v want=%v (%s)", tc.name, allowed, tc.want, tc.why)
			continue
		}
		if allowed {
			continue
		}
		claim := seClaim(tc.object)
		if !strings.Contains(message, claim) || !strings.Contains(message, tc.username) {
			t.Errorf("%s: deny message must name the rejected claim and the requester, got %q", tc.name, message)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. the whole chain: real stamper, then the rendered policy, then real ingest
// ---------------------------------------------------------------------------

func TestSecurityEventIdentityGuardAdmissionChain(t *testing.T) {
	seTrustFixture(t)
	docs := seRender(t, "phorvex", "phorvex-system")
	policy := seGuardDoc(t, docs, "ValidatingAdmissionPolicy")

	forged := map[string]string{ingest.CreatorIdentityAnnotation: seTrustedSA}
	own := map[string]string{ingest.CreatorIdentityAnnotation: seAttackSA}

	for _, tc := range []struct {
		name        string
		annotations map[string]string
		username    string
		reachable   bool
		operation   string
		wantStored  bool
		wantTrust   string
		wantEvid    int
		why         string
	}{
		{"positive-control-real-detector-webhook-up", nil, seTrustedSA, true, "CREATE",
			true, ingest.TrustTrusted, 1,
			"POSITIVE CONTROL: the allowlisted detector reaches trusted belief evidence"},
		{"positive-control-real-detector-webhook-down", nil, seTrustedSA, false, "CREATE",
			true, ingest.TrustUnstamped, 0,
			"the honest detector is still admitted during the outage; it just carries no evidence"},
		{"forged-during-outage", forged, seAttackSA, false, "CREATE",
			false, "", 0,
			"THE DEFECT, CLOSED: the request never reaches storage, so ingest never sees it"},
		{"forged-while-webhook-up", forged, seAttackSA, true, "CREATE",
			true, ingest.TrustUntrusted, 0,
			"unchanged behaviour: the stamp is overwritten with the real creator"},
		{"stranger-unstamped-during-outage", nil, seAttackSA, false, "CREATE",
			true, ingest.TrustUnstamped, 0,
			"honest no-evidence behaviour is preserved: admitted, recorded, no belief"},
		{"self-claim-during-outage", own, seAttackSA, false, "CREATE",
			true, ingest.TrustUntrusted, 0,
			"asserting your own identity is allowed and buys nothing"},
		{"payload-rewrite-under-foreign-stamp-during-outage", forged, seAttackSA, false, "UPDATE",
			false, "", 0,
			"the rejected carry-over exception's attack: denied here"},
		{"owner-update-during-outage", forged, seTrustedSA, false, "UPDATE",
			true, ingest.TrustTrusted, 1,
			"the detector updating its own event keeps working while the endpoint is down"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := seEvent("chain-"+tc.name, tc.annotations)
			var old object
			if tc.operation == "UPDATE" {
				old = seEvent("chain-"+tc.name, forged)
				candidate["spec"].(object)["description"] = "payload changed by this update"
			}

			// Mutating admission first (failurePolicy=Ignore: skipped entirely when the
			// endpoint has no ready backend), THEN validating admission.
			stored := candidate
			if tc.reachable {
				stored = seStamp(t, candidate, old, tc.username, tc.operation)
			}
			allowed, message := seValidate(t, policy, stored, old, tc.username, tc.operation)

			if allowed != tc.wantStored {
				t.Fatalf("admitted=%v want=%v (%s) message=%q", allowed, tc.wantStored, tc.why, message)
			}
			if !allowed {
				t.Logf("REJECTED, nothing stored: %s", message)
				return
			}
			trust, evidence := seConsume(t, stored)
			claim := seClaim(stored)
			t.Logf("stored creator-identity=%q -> ingest trust=%q, belief evidence on %s = %d (%s)",
				claim, trust, seTarget, evidence, tc.why)
			if trust != tc.wantTrust || evidence != tc.wantEvid {
				t.Fatalf("got (trust=%q evidence=%d), want (trust=%q evidence=%d)", trust, evidence, tc.wantTrust, tc.wantEvid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. shipped modes: release names, enabled/disabled, and the declared API floor
// ---------------------------------------------------------------------------

func TestSecurityEventIdentityPolicyReleaseNamesAndModes(t *testing.T) {
	t.Run("distinct-stable-names-per-release", func(t *testing.T) {
		seen := map[string]bool{}
		for _, tc := range []struct{ release, namespace string }{
			{"phorvex", "phorvex-system"},
			{"custom-release", "custom-namespace"},
			{"custom-release", "custom-namespace-other"},
			{"same-long-release-prefix-aaaaaaaa", "same-long-namespace-prefix-aaaa"},
			{"same-long-release-prefix-bbbbbbbb", "same-long-namespace-prefix-bbbb"},
		} {
			policy, binding := seGuardDocs(t, seRender(t, tc.release, tc.namespace))
			name := policy["metadata"].(object)["name"].(string)
			if seen[name] || len(name) > 63 {
				t.Fatalf("cluster-scoped name collision or oversized name: %s", name)
			}
			seen[name] = true
			if binding["spec"].(object)["policyName"] != name {
				t.Fatalf("%s: binding points at %v, not %s", tc.release, binding["spec"].(object)["policyName"], name)
			}
			// Rendering the same release twice must produce the same name: the guard must not
			// drift the way a generated certificate does.
			again := seGuardDoc(t, seRender(t, tc.release, tc.namespace), "ValidatingAdmissionPolicy")
			if again["metadata"].(object)["name"] != name {
				t.Fatalf("%s: repeated render drifted to %v", tc.release, again["metadata"].(object)["name"])
			}
			t.Logf("release=%-32s namespace=%-31s policy=%s", tc.release, tc.namespace, name)
		}
	})

	t.Run("enabled-by-default", func(t *testing.T) {
		seGuardDocs(t, seRender(t, "phorvex", "phorvex-system"))
	})

	t.Run("disabled-only-with-an-empty-allowlist", func(t *testing.T) {
		docs := seRender(t, "phorvex", "phorvex-system",
			"--set", "phorvex.eventIdentityPolicy.enabled=false", "--set", "phorvex.trustedDetectors=null")
		for _, doc := range docs {
			labels, _ := doc["metadata"].(object)["labels"].(object)
			if labels["phorvex.ai/policy"] == seGuardLabel {
				t.Fatal("disabled render must not ship the policy")
			}
		}
	})

	t.Run("disabling-the-guard-while-trusting-detectors-is-rejected", func(t *testing.T) {
		_, err := render(t, "phorvex", "phorvex-system", seKubeVersion,
			filepath.Join(repository(t), "phorvex/charts/phorvex"),
			"--set", "phorvex.eventIdentityPolicy.enabled=false")
		if err == nil || !strings.Contains(err.Error(), "phorvex.trustedDetectors") {
			t.Fatalf("trusting a detector without the guard must be refused explicitly, got %v", err)
		}
		t.Logf("refused: %v", err)
	})

	t.Run("unsupported-cluster-api-is-declared-not-silently-omitted", func(t *testing.T) {
		_, err := render(t, "phorvex", "phorvex-system", "1.29.9",
			filepath.Join(repository(t), "phorvex/charts/phorvex"))
		if err == nil || !strings.Contains(err.Error(), "Kubernetes >=1.30") {
			t.Fatalf("an unsupported cluster must fail the render loudly, got %v", err)
		}
		t.Logf("refused: %v", err)
	})
}

// ---------------------------------------------------------------------------
// 6. the pre-existing controls are preserved, not replaced
// ---------------------------------------------------------------------------

func TestSecurityEventStampWebhooksRemainIndependentControls(t *testing.T) {
	docs := seRender(t, "phorvex", "phorvex-system")
	policies := map[string]object{}
	for _, doc := range docs {
		if doc["kind"] != "MutatingWebhookConfiguration" {
			continue
		}
		for _, raw := range doc["webhooks"].([]any) {
			hook := raw.(object)
			policies[hook["name"].(string)] = hook
		}
	}
	general, ok := policies["stamp-securityevent.phorvex.ai"]
	if !ok {
		t.Fatal("the creator-identity stamp webhook must still ship: the policy checks a claim, it does not write one")
	}
	// Deliberately unchanged: Phorvex must never be able to block the cluster's event flow.
	// The in-process policy, not this webhook, is what makes a present claim trustworthy.
	if general["failurePolicy"] != "Ignore" {
		t.Fatalf("the general stamp hook's availability contract changed to %v; that is a separate decision", general["failurePolicy"])
	}
	protected, ok := policies["stamp-protected-outcomes.phorvex.ai"]
	if !ok {
		t.Fatal("the M-99 protected-outcomes hook must be preserved as an additional independent control")
	}
	if protected["failurePolicy"] != "Fail" || len(protected["matchConditions"].([]any)) != 1 {
		t.Fatalf("protected-outcomes hook must stay fail-closed and scoped: %#v", protected)
	}
	t.Logf("preserved: %s(%v), %s(%v)", "stamp-securityevent.phorvex.ai", general["failurePolicy"],
		"stamp-protected-outcomes.phorvex.ai", protected["failurePolicy"])
}
