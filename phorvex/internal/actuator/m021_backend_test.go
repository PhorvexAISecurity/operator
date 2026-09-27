/*
 * Phorvex — M-21 permanent regressions: backend resolution and the adapter boundary.
 *
 * RED at f0348b36e12d751a84ffdac1414c6ff6952d2ee1: PhoenixActuator.SupportsAction returned
 * true for every action including the ones Actuate rejects, and nothing validated
 * PHORVEX_ACTUATOR at all.
 */

package actuator

import (
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

// --- selector resolution ---

// TestResolveBackendAcceptsOnlyExactValues: omission takes the documented default; every
// valid explicit value resolves to itself; and NOTHING else resolves at all. The padded,
// case-altered and whitespace-only rows are the M-21 incident — each of them silently
// meant "phoenix" before, indistinguishable from an omission.
func TestResolveBackendAcceptsOnlyExactValues(t *testing.T) {
	valid := []struct {
		raw     string
		present bool
		want    Backend
		source  BackendSource
	}{
		{"", false, DefaultBackend, SourceDefault}, // unset
		{"", true, DefaultBackend, SourceDefault},  // set empty
		{"phoenix", true, BackendPhoenix, SourceExplicit},
		{"native", true, BackendNative, SourceExplicit},
		{"hybrid", true, BackendHybrid, SourceExplicit},
	}
	for _, tc := range valid {
		res, err := ResolveBackend(tc.raw, tc.present)
		if err != nil {
			t.Fatalf("ResolveBackend(%q, %v): unexpected error %v", tc.raw, tc.present, err)
		}
		if res.Backend != tc.want || res.Source != tc.source {
			t.Fatalf("ResolveBackend(%q, %v) = %s/%s, want %s/%s",
				tc.raw, tc.present, res.Backend, res.Source, tc.want, tc.source)
		}
	}

	// The default must remain PHOENIX. M-21 is explicitly not authorized to change it.
	if DefaultBackend != BackendPhoenix {
		t.Fatalf("the documented default must stay phoenix, got %s", DefaultBackend)
	}

	invalid := []string{
		"phoenixx", "nativ", "hybird", // typos
		" native", "native ", "\tnative", "native\n", // padding
		"NATIVE", "Native", "Phoenix", "HYBRID", // case
		" ", "   ", "\t", "\n", // whitespace-only (NOT empty)
		"kubectl", "true", "1", "phoenix,native", "phoenix native",
	}
	for _, raw := range invalid {
		res, err := ResolveBackend(raw, true)
		if err == nil {
			t.Fatalf("ResolveBackend(%q) must fail, resolved to %s/%s", raw, res.Backend, res.Source)
		}
		if res.Backend != "" {
			t.Fatalf("ResolveBackend(%q) failed but still named backend %q — a rejected value must select nothing", raw, res.Backend)
		}
		var ibe *InvalidBackendError
		if !asInvalidBackend(err, &ibe) {
			t.Fatalf("ResolveBackend(%q) must return *InvalidBackendError, got %T", raw, err)
		}
	}
}

func asInvalidBackend(err error, out **InvalidBackendError) bool {
	e, ok := err.(*InvalidBackendError)
	if ok {
		*out = e
	}
	return ok
}

// TestInvalidBackendErrorIsActionable: the operator must be able to fix the problem from
// the message alone — it names the variable, the rejected value, the accepted set and the
// default, and says that matching is exact.
func TestInvalidBackendErrorIsActionable(t *testing.T) {
	_, err := ResolveBackend("NATIVE", true)
	if err == nil {
		t.Fatal("NATIVE must be rejected")
	}
	msg := err.Error()
	for _, want := range []string{BackendEnvVar, `"NATIVE"`, "phoenix", "native", "hybrid", "default", `did you mean "native"`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message must mention %q; got: %s", want, msg)
		}
	}
	// A long or sensitive mis-wired value is bounded rather than dumped whole.
	long := strings.Repeat("x", 500)
	_, err = ResolveBackend(long, true)
	if err == nil {
		t.Fatal("a 500-byte value must be rejected")
	}
	if strings.Contains(err.Error(), long) {
		t.Fatal("the full 500-byte value must not be echoed into the message")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("a bounded value must say it was truncated; got: %s", err.Error())
	}
}

// TestOriginDistinguishesDefaultFromExplicit: every valid branch is observable, and the
// log line separates "the operator chose this" from "nobody configured anything".
func TestOriginDistinguishesDefaultFromExplicit(t *testing.T) {
	unset, _ := ResolveBackend("", false)
	empty, _ := ResolveBackend("", true)
	explicit, _ := ResolveBackend("phoenix", true)

	if unset.Origin() == empty.Origin() {
		t.Fatal("an unset variable and one set to empty must be distinguishable in the log")
	}
	if !strings.Contains(unset.Origin(), "unset") || !strings.Contains(empty.Origin(), "empty") {
		t.Fatalf("origins must say which: unset=%q empty=%q", unset.Origin(), empty.Origin())
	}
	// The explicit phoenix branch must NOT be reported as the default, even though it
	// selects the same backend the default would.
	if !strings.Contains(explicit.Origin(), string(SourceExplicit)) {
		t.Fatalf("an explicit phoenix must be logged as explicit, got %q", explicit.Origin())
	}
	if explicit.Origin() == unset.Origin() {
		t.Fatal("explicit phoenix and defaulted phoenix must be distinguishable")
	}
}

// TestNewRefusesUnknownBackend: the constructor is checked too, so a caller that bypassed
// the resolver still cannot obtain a silently-substituted backend.
func TestNewRefusesUnknownBackend(t *testing.T) {
	for _, b := range []Backend{"", "phoenixx", "NATIVE", " native"} {
		act, err := New(b, nil)
		if err == nil {
			t.Fatalf("New(%q) must fail, got %T", b, act)
		}
		if act != nil {
			t.Fatalf("New(%q) must return a nil actuator on error, got %T", b, act)
		}
	}
	for _, tc := range []struct {
		b    Backend
		name string
	}{{BackendPhoenix, "phoenix"}, {BackendNative, "native"}, {BackendHybrid, "hybrid"}} {
		act, err := New(tc.b, nil)
		if err != nil {
			t.Fatalf("New(%s): %v", tc.b, err)
		}
		if act.Name() != tc.name {
			t.Fatalf("New(%s) built %q", tc.b, act.Name())
		}
	}
}

// --- adapter boundary: support must match dispatch ---

// TestPhoenixSupportMatchesDispatch is the M-21 kill shot at the adapter boundary. For
// EVERY action in the vocabulary, SupportsAction and Actuate must agree. Before the fix
// they disagreed on all thirteen actions Phoenix cannot enact.
func TestPhoenixSupportMatchesDispatch(t *testing.T) {
	pa := NewPhoenixActuator(fake.NewClientBuilder().WithScheme(newScheme(t)).Build())
	ctx := t.Context()
	for _, a := range append([]model.Action{model.ActionNoop, model.ActionDisable}, model.MutatingActions...) {
		ok, why := pa.SupportsAction(ctx, a, Target{Namespace: "ns", Pod: "p"})
		req := Request{Tenant: "t", Namespace: "ns", Pod: "p", Action: a, Score: 0.9}
		if a == model.ActionRotate {
			req.TargetUID = "pod-uid"
		}
		if a == model.ActionQuarantine {
			// M52's controlled Phoenix route requires the durable reservation envelope.
			// Supply it here so this M21 contract continues to compare backend
			// repertoire with a well-formed dispatch, rather than input validation.
			req.TargetUID = "pod-uid"
			req.TargetNamespaceUID = "namespace-uid"
			req.OperationID = strings.Repeat("a", 40)
		}
		_, err := pa.Actuate(ctx, req)
		dispatches := err == nil
		if ok != dispatches {
			t.Fatalf("phoenix %s: SupportsAction=%v but Actuate accepted=%v (why=%q, err=%v)", a, ok, dispatches, why, err)
		}
		if !ok {
			// The rejection must name the backend, the action and a reason.
			for _, want := range []string{ReasonBackendUnsupported, string(BackendPhoenix), string(a)} {
				if !strings.Contains(why, want) {
					t.Fatalf("phoenix %s rejection must mention %q, got %q", a, want, why)
				}
			}
		}
	}
}

// TestPhoenixAcceptanceStaysQualified: mapped acceptance must NOT be reported as proof of
// execution. Quarantine remains supported but keeps the "unverified" qualification, while
// bounded rotate is explicitly refused because Phoenix cannot carry its policy cap.
func TestPhoenixAcceptanceStaysQualified(t *testing.T) {
	pa := NewPhoenixActuator(fake.NewClientBuilder().WithScheme(newScheme(t)).Build())
	ok, why := pa.SupportsAction(t.Context(), model.ActionQuarantine, Target{})
	if !ok || !strings.HasPrefix(why, "unverified: ") {
		t.Fatalf("phoenix quarantine support=(%v,%q), want qualified acceptance", ok, why)
	}
	if ok, why = pa.SupportsAction(t.Context(), model.ActionRotate, Target{}); ok || !strings.Contains(why, detailGraceCapUnsupported) {
		t.Fatalf("phoenix rotate support=(%v,%q), want explicit grace-cap refusal", ok, why)
	}
}

// TestUnknownActionsAreConservativelyUnsupported: a value outside the vocabulary is not a
// capability. Before the fix Phoenix reported "" and "not-an-action" as supported.
func TestUnknownActionsAreConservativelyUnsupported(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	for _, backend := range Backends() {
		act, err := New(backend, c)
		if err != nil {
			t.Fatalf("New(%s): %v", backend, err)
		}
		for _, a := range []model.Action{"", "not-an-action", "ROTATE", " rotate", "rotate "} {
			if ok, why := act.SupportsAction(t.Context(), a, Target{}); ok {
				t.Fatalf("%s: unknown action %q must not be supported (why=%q)", backend, a, why)
			}
		}
	}
}

// TestNativeSupportMatchesItsRegistry: the native answer is derived from the handler
// registry `dispatch` routes through, so it cannot claim a handler it does not have. The
// noop sentinel and the declared-not-implemented `disable` are not support.
func TestNativeSupportMatchesItsRegistry(t *testing.T) {
	c := fakeC()
	na := NewNativeActuator(c)
	na.SetBoundaryReader(c)
	na.JournalNamespace = "operator"
	na.SetServingSecurity(legacyServingSecurityForTest(t))
	for _, a := range append([]model.Action{model.ActionNoop, model.ActionDisable}, model.MutatingActions...) {
		ok, why := na.SupportsAction(t.Context(), a, Target{UID: "pod-uid"})
		_, registered := HandlerRegistry.Get(string(a))
		switch a {
		case model.ActionNoop:
			if ok {
				t.Fatal("noop is a control sentinel, never an emitted move")
			}
			if !strings.Contains(why, detailSentinel) {
				t.Fatalf("noop rejection must say it is a sentinel, got %q", why)
			}
		case model.ActionDisable:
			if ok {
				t.Fatal("disable is declared-not-implemented, not support")
			}
			if !strings.Contains(why, detailDeclaredOnly) {
				t.Fatalf("disable rejection must say declared-not-implemented, got %q", why)
			}
			if !registered {
				t.Fatal("fixture: disable is expected to keep its registered handler")
			}
		case model.ActionIdentityRotate:
			if ok || !registered || !strings.Contains(why, "declared-only") {
				t.Fatalf("identity-rotate must remain registered for historical rollback but unsupported for new dispatch: ok=%v registered=%v why=%q", ok, registered, why)
			}
		case model.ActionMIGRebind:
			if ok {
				t.Fatal("mig-rebind cannot be supported without target allocation/profile evidence")
			}
			if !NodeExecWired() && why != ReasonTransportUnwired {
				t.Fatalf("unwired reason=%q", why)
			}
		case model.ActionSensitiveOutputPolicyActivate:
			if ok || !registered || why != "output-policy-authority-unavailable" {
				t.Fatalf("output policy requires a target and policy authority: ok=%v registered=%v why=%q", ok, registered, why)
			}
		case model.ActionVoiceMemoryNoteRevoke:
			if ok || !registered || !strings.HasPrefix(why, "voice-memory-scope-unavailable:") {
				t.Fatalf("voice memory requires exact target, policy and private hook authority: ok=%v registered=%v why=%q", ok, registered, why)
			}
		default:
			if ok != registered {
				t.Fatalf("native %s: support=%v but handler registered=%v (%s)", a, ok, registered, why)
			}
		}
	}
}

// TestHybridAsksTheRouteItWouldDispatchTo: the hybrid answer is the ROUTED backend's
// answer — never a union, never a fallback to the other backend because it happens to
// support the action. Support and dispatch read one routing predicate.
func TestHybridAsksTheRouteItWouldDispatchTo(t *testing.T) {
	c := fakeC()
	h := NewHybridActuator(c)
	phoenix, native := NewPhoenixActuator(c), NewNativeActuator(c)
	h.ConfigureNativeJournal(c, "operator")
	native.SetBoundaryReader(c)
	native.JournalNamespace = "operator"
	h.SetServingSecurity(legacyServingSecurityForTest(t))
	native.SetServingSecurity(legacyServingSecurityForTest(t))
	ctx := t.Context()

	for _, a := range append([]model.Action{model.ActionNoop, model.ActionDisable}, model.MutatingActions...) {
		target := Target{UID: "pod-uid"}
		gotOK, gotWhy := h.SupportsAction(ctx, a, target)
		route := RouteFor(BackendHybrid, a)
		var wantOK bool
		var wantWhy string
		if route == BackendPhoenix {
			wantOK, wantWhy = phoenix.SupportsAction(ctx, a, target)
		} else {
			wantOK, wantWhy = native.SupportsAction(ctx, a, target)
		}
		if gotOK != wantOK || gotWhy != wantWhy {
			t.Fatalf("hybrid %s must answer as its %s route (%v,%q), got (%v,%q)", a, route, wantOK, wantWhy, gotOK, gotWhy)
		}
		// The union would be strictly more permissive: assert we did NOT take it.
		// Quarantine routes to Phoenix even though native also has a handler.
		if route == BackendPhoenix {
			if _, nativeHas := HandlerRegistry.Get(string(a)); !nativeHas {
				t.Fatalf("fixture: expected native to also register %s, so the no-union assertion is meaningful", a)
			}
		}
	}
	// And an action phoenix rejects but native implements must still be routed to native,
	// which is the whole reason hybrid exists.
	if ok, why := h.SupportsAction(ctx, model.ActionKVReset, Target{UID: "pod-uid"}); !ok {
		t.Fatalf("hybrid must support kv-reset through its native route, got %q", why)
	}
	if RouteFor(BackendHybrid, model.ActionKVReset) != BackendNative {
		t.Fatal("kv-reset must route to native under hybrid")
	}
	if RouteFor(BackendHybrid, model.ActionRotate) != BackendNative {
		t.Fatal("bounded rotate must route native under hybrid so the policy cap is enforced")
	}
}

// TestRouteForNonHybridIsIdentity: only the hybrid backend routes; a single-backend
// deployment answers for itself and never delegates.
func TestRouteForNonHybridIsIdentity(t *testing.T) {
	for _, b := range []Backend{BackendPhoenix, BackendNative} {
		for _, a := range model.MutatingActions {
			if got := RouteFor(b, a); got != b {
				t.Fatalf("RouteFor(%s, %s) = %s, want %s", b, a, got, b)
			}
		}
	}
}
