/*
 * Phorvex — actuator BACKEND selection and the published per-action repertoire. (M-21)
 *
 * One place resolves PHORVEX_ACTUATOR, one place constructs the selected implementation,
 * and one place derives what that implementation actually accepts. Support reporting and
 * dispatch read the SAME predicates here, so an operator can never be told an action is
 * supported by a backend whose Actuate would refuse it.
 */

package actuator

import (
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/model"
)

// Backend names an actuator backend; see actuatorapi.Backend.
type Backend = actuatorapi.Backend

const (
	BackendPhoenix = actuatorapi.BackendPhoenix
	BackendNative  = actuatorapi.BackendNative
	BackendHybrid  = actuatorapi.BackendHybrid
)

// DefaultBackend is the ESTABLISHED, source-backed default. M-21 deliberately preserves
// it: an omitted selector is a legitimate choice of the documented default, and changing
// it would be a compatibility change this correction is not authorized to make.
const DefaultBackend = BackendPhoenix

// BackendEnvVar is the single environment variable that selects the backend.
const BackendEnvVar = "PHORVEX_ACTUATOR"

// Backends is the accepted set in a stable order (also the order used in messages).
func Backends() []Backend { return []Backend{BackendPhoenix, BackendNative, BackendHybrid} }

// BackendSource records HOW the backend was chosen, so a log line distinguishes "the
// operator asked for this" from "nobody configured anything and the default applied".
type BackendSource string

const (
	// SourceDefault: PHORVEX_ACTUATOR was unset or empty.
	SourceDefault BackendSource = "default"
	// SourceExplicit: PHORVEX_ACTUATOR named this backend exactly.
	SourceExplicit BackendSource = "explicit"
)

// BackendResolution is the outcome of reading the selector exactly once.
type BackendResolution struct {
	Backend Backend
	Source  BackendSource
	// Raw is the configured value verbatim ("" when unset or set empty).
	Raw string
	// Present distinguishes an unset variable from one set to the empty string. Both
	// resolve to the default; only the log line tells them apart.
	Present bool
}

// Origin describes the resolution for a log line, without echoing any other environment.
func (r BackendResolution) Origin() string {
	if r.Source == SourceExplicit {
		return string(SourceExplicit) + " (" + BackendEnvVar + "=" + quoteBounded(r.Raw) + ")"
	}
	if r.Present {
		return string(SourceDefault) + " (" + BackendEnvVar + " set empty)"
	}
	return string(SourceDefault) + " (" + BackendEnvVar + " unset)"
}

// InvalidBackendError is the fail-fast for an explicit value that names no backend. It is
// returned BEFORE any actuator is constructed, so an invalid selector can never reach a
// dispatch path or be silently replaced by the default.
type InvalidBackendError struct {
	// Value is the rejected configuration verbatim (bounded when rendered).
	Value string
}

func (e *InvalidBackendError) Error() string {
	msg := fmt.Sprintf("%s=%s is not a supported actuator; supported values are %s; unset or empty selects the default %q",
		BackendEnvVar, quoteBounded(e.Value), backendList(), DefaultBackend)
	if near := nearestBackend(e.Value); near != "" {
		msg += fmt.Sprintf("; %q is matched exactly — no trimming, no case folding — so did you mean %q?",
			BackendEnvVar, near)
	}
	return msg
}

// ResolveBackend is the PURE resolver: no environment read, no construction, no logging.
//
// Exactly two things resolve to the default: an unset variable and an empty one. Every
// other value must name a backend EXACTLY. Whitespace-only, padded, case-altered and
// unknown values are errors, never a silent fallback — that fallback is the M-21 incident:
// a typo behaved exactly like an omission and the operator was never told.
func ResolveBackend(raw string, present bool) (BackendResolution, error) {
	if raw == "" {
		return BackendResolution{Backend: DefaultBackend, Source: SourceDefault, Raw: raw, Present: present}, nil
	}
	for _, b := range Backends() {
		if raw == string(b) {
			return BackendResolution{Backend: b, Source: SourceExplicit, Raw: raw, Present: present}, nil
		}
	}
	return BackendResolution{Raw: raw, Present: present}, &InvalidBackendError{Value: raw}
}

// ResolveBackendFromEnv reads PHORVEX_ACTUATOR — and nothing else — and resolves it.
func ResolveBackendFromEnv() (BackendResolution, error) {
	raw, present := os.LookupEnv(BackendEnvVar)
	return ResolveBackend(raw, present)
}

// New constructs the named backend over one client. An unknown Backend is an error
// rather than a default, so a caller that bypassed ResolveBackend still cannot start
// execution on a backend nobody chose.
func New(b Backend, c client.Client) (Actuator, error) {
	switch b {
	case BackendPhoenix:
		return NewPhoenixActuator(c), nil
	case BackendNative:
		return NewNativeActuator(c), nil
	case BackendHybrid:
		return NewHybridActuator(c), nil
	default:
		return nil, &InvalidBackendError{Value: string(b)}
	}
}

// backendList renders the accepted values for an operator-facing message.
func backendList() string {
	names := make([]string, 0, len(Backends()))
	for _, b := range Backends() {
		names = append(names, string(b))
	}
	return strings.Join(names, ", ")
}

// nearestBackend names the backend an invalid value differs from ONLY by surrounding
// whitespace or letter case. It exists to make the error actionable; it never causes the
// value to be accepted.
func nearestBackend(raw string) Backend {
	folded := strings.ToLower(strings.TrimSpace(raw))
	for _, b := range Backends() {
		if folded == string(b) {
			return b
		}
	}
	return ""
}

// quoteBounded renders a configured value for a log or error: quoted (so whitespace and
// control characters are visible and escaped) and length-bounded, so an operator who
// mis-wires a large or sensitive value into this variable does not have it dumped whole
// into the logs.
func quoteBounded(v string) string {
	const max = 64
	if len(v) > max {
		return fmt.Sprintf("%q…[%d bytes truncated]", v[:max], len(v)-max)
	}
	return fmt.Sprintf("%q", v)
}

// --- Repertoire: what each backend actually implements -----------------------------

// Rejection reasons. These are the SHARED vocabulary: SupportsAction returns them, the
// capability gate records them as its exclusion detail, and the ActionsSupported message
// renders them, so a condition and a decision record can never disagree about why.
const (
	ReasonBackendUnsupported       = actuatorapi.ReasonBackendUnsupported
	ReasonBackendUnavailable       = actuatorapi.ReasonBackendUnavailable
	ReasonTransportUnwired         = actuatorapi.ReasonTransportUnwired
	ReasonParallelGroupUnavailable = actuatorapi.ReasonParallelGroupUnavailable

	// detailSentinel: the value is a control sentinel, never an emitted move.
	detailSentinel = "control sentinel, not an emitted move"
	// detailDeclaredOnly: a handler exists but declares itself not implemented.
	detailDeclaredOnly = "declared-not-implemented capability"
	// detailNoRuleMapping: Phoenix has no accepted controlled route for this action.
	detailNoRuleMapping = "no accepted Phoenix controlled route; this backend enacts only " +
		string(model.ActionQuarantine)
	// Phoenix's Delete strategy has no typed policy grace-cap input. Accepting a
	// bounded rotate there would silently discard the contract.
	detailGraceCapUnsupported = "Phoenix Delete cannot enforce the selecting policy maxGracePeriodSeconds contract"
	// detailNoHandler: the native dispatcher has no registered handler.
	detailNoHandler = "no registered native handler"
	// detailUnknownAction: the value is not in the Phorvex action vocabulary at all.
	detailUnknownAction = "not a Phorvex action"

	// whyPhoenixUnverified is the ACCEPTED-but-unverified answer for a mapped Phoenix
	// action: the adapter accepts the move, but this layer verifies no target-local AMTD
	// fixture, so acceptance is never reported as proof of execution or effect (P-08).
	whyPhoenixUnverified = "unverified: phoenix-amtd-repertoire — P-08"
)

// unsupportedWhy names the backend, the action and the reason in one string, as the
// support contract requires ("identify the action/backend/reason").
func unsupportedWhy(b Backend, a model.Action, detail string) string {
	return fmt.Sprintf("%s: %s cannot enact %q (%s)", ReasonBackendUnsupported, b, string(a), detail)
}

// KnownAction reports whether a is in the Phorvex action vocabulary at all — the
// generatable set plus the two non-emitted control values. An unknown value is handled
// CONSERVATIVELY everywhere: never supported.
func KnownAction(a model.Action) bool {
	if a == model.ActionNoop || a == model.ActionDisable {
		return true
	}
	for _, m := range model.MutatingActions {
		if m == a {
			return true
		}
	}
	return false
}

// phoenixAccepts is the Phoenix adapter's ACCEPTED set. It deliberately narrows the
// historical RuleTypeFor mapping because Phoenix Delete cannot carry the current
// policy's bounded graceful-termination contract. Support and dispatch read this same
// function so the explicit refusal cannot drift.
func phoenixAccepts(a model.Action) (bool, string) {
	if a == model.ActionRotate {
		return false, detailGraceCapUnsupported
	}
	if RuleTypeFor(a) != "" {
		return true, ""
	}
	switch {
	case a == model.ActionNoop:
		return false, detailSentinel
	case !KnownAction(a):
		return false, detailUnknownAction
	default:
		return false, detailNoRuleMapping
	}
}

// nativeAccepts is the native dispatcher's ACCEPTED set, derived from the SAME handler
// registry `dispatch` routes through. ActionDisable is registered so the completeness
// enumeration stays green, but it declares itself not implemented and enacts nothing, so
// it is not support. Noop is a sentinel and has no handler.
func nativeAccepts(a model.Action) (bool, string) {
	switch {
	case a == model.ActionNoop:
		return false, detailSentinel
	case a == model.ActionDisable:
		return false, detailDeclaredOnly
	case !KnownAction(a):
		return false, detailUnknownAction
	}
	if _, ok := HandlerRegistry.Get(string(a)); !ok {
		return false, detailNoHandler
	}
	return true, ""
}

// RouteFor reports which backend would actually receive a dispatch of action a under
// backend b; see actuatorapi.RouteFor.
func RouteFor(b Backend, a model.Action) Backend { return actuatorapi.RouteFor(b, a) }

// RepertoireVersion is the schema version of the PUBLISHED repertoire matrix. Bump it
// when the meaning of a column changes, so a reader can tell an old copy from a current
// one. It is asserted against the published document by the inventory test.
const RepertoireVersion = 1

// RepertoireEntry is one published (backend, action) row. The four properties are kept
// SEPARATE on purpose: accepting an action is not the same as having its prerequisites,
// which is not the same as having emitted it, which is not the same as having confirmed
// its effect (ticket P4).
type RepertoireEntry struct {
	Backend Backend
	Action  model.Action
	// Route is the backend that actually receives the dispatch.
	Route Backend
	// Accepted is ADAPTER ACCEPTANCE only: this route implements the action.
	Accepted bool
	// Why is the rejection detail when Accepted is false, or the acceptance
	// qualification when the route accepts without verifying a fixture.
	Why string
	// Prerequisite names a runtime precondition this route additionally checks before
	// it will report support ("" = none at this layer).
	Prerequisite string
	// UnverifiedEffect states what acceptance does NOT establish.
	UnverifiedEffect string
}

// Repertoire derives the full published matrix for one backend from the same predicates
// dispatch and SupportsAction use. It is a pure function of the action vocabulary and the
// handler registry: it cannot be a hand-maintained table that drifts from the code.
func Repertoire(b Backend) []RepertoireEntry {
	actions := append([]model.Action{model.ActionNoop, model.ActionDisable}, model.MutatingActions...)
	out := make([]RepertoireEntry, 0, len(actions))
	for _, a := range actions {
		route := RouteFor(b, a)
		e := RepertoireEntry{Backend: b, Action: a, Route: route}
		switch route {
		case BackendPhoenix:
			ok, detail := phoenixAccepts(a)
			e.Accepted = ok
			if ok {
				e.Why = whyPhoenixUnverified
				e.UnverifiedEffect = "Phoenix receives the SecurityEvent; execution and security effect are not verified here"
			} else {
				e.Why = unsupportedWhy(BackendPhoenix, a, detail)
			}
		case BackendNative:
			ok, detail := nativeAccepts(a)
			e.Accepted = ok
			if ok {
				if a == model.ActionMIGRebind {
					e.Prerequisite = ReasonTransportUnwired + " is reported unless the node-exec transport is wired (M-79)"
				}
				if a == model.ActionSensitiveOutputPolicyActivate {
					e.Prerequisite = "exact live Pod, preinstalled rule ConfigMap and operation journal"
				}
				if a == model.ActionVoiceMemoryNoteRevoke {
					e.Prerequisite = "exact live Voice Deployment, owned policy ConfigMap, private readback Secret and operation journal"
				}
				if a == model.ActionVoiceRefundPairDeny {
					e.Prerequisite = "exact live Voice Deployment, owned refund ConfigMap, private readback Secret and operation journal"
				}
				if a == model.ActionVoiceMCPToolPin {
					e.Prerequisite = "reviewed MCP image, exact Voice and MCP sources, owned descriptor ConfigMap, private readback and protected journal"
				}
				if a == model.ActionVoiceOutputPolicyActivate {
					e.Prerequisite = "exact Voice Deployment, owned output rule, authenticated all-Pod readback and fixed protected journal"
				}
				if a == model.ActionVoiceSessionAdmissionEnforce {
					e.Prerequisite = "reviewed immutable admission wrapper, unchanged legacy bundle, canonical production auth profile, exact all-serving-Pod state and protected journal"
				}
				if a == model.ActionLiteLLMClientRevoke {
					e.Prerequisite = "reviewed LiteLLM gateway on two Ready Service Pods, one owned-client observation, policy ConfigMap and protected journal"
				}
				if a == model.ActionCRMRefundRevoke {
					e.Prerequisite = "reviewed mini-CRM on two Ready Service Pods, one cross-record-refund observation and the deny-guard ConfigMap"
				}
				if a == model.ActionEndpointLeaseRevoke {
					e.Prerequisite = "reviewed proxy source and proxy/engine images, exact A/B policy, authenticated Ready proxy status and protected journal"
				}
				if a == model.ActionControllerStop {
					e.Prerequisite = "fresh trusted controller-UID-bound unauthorized-owner observation, reviewed desired-state inventory, attacker-CREATE provenance, scale authority and no dependent legitimate Service/PDB/HPA floor"
				}
				if a == model.ActionModelShardReplace {
					e.Prerequisite = ReasonParallelGroupUnavailable + " for every target declaring phorvex.ai/parallel-group"
					e.UnverifiedEffect = "registered handler supports only controller-owned scalar replacement; full TP/PP group replacement remains unavailable"
				} else if a == model.ActionSensitiveOutputPolicyActivate {
					e.UnverifiedEffect = "support does not verify the authenticated event, CAS activation, mounted projection or proxy effect; dispatch and recovery check these"
				} else if a == model.ActionVoiceMemoryNoteRevoke {
					e.UnverifiedEffect = "support does not verify the observed note, CAS append or per-Pod application effect; dispatch checks these"
				} else if a == model.ActionVoiceRefundPairDeny {
					e.UnverifiedEffect = "support does not verify the observed refund pair, CAS append or per-Pod application effect; dispatch checks these"
				} else if a == model.ActionVoiceMCPToolPin {
					e.UnverifiedEffect = "support does not verify the observed model steering, CAS append or later tool behavior; dispatch checks installed sources and per-Pod projection"
				} else if a == model.ActionVoiceSessionAdmissionEnforce {
					e.UnverifiedEffect = "support does not establish actual first loss, CAS enforcement, local unsigned teardown, fresh denial or useful signed speech; these require native and Console evidence"
				} else if a == model.ActionVoiceOutputPolicyActivate {
					e.UnverifiedEffect = "support does not verify the observed raw output, CAS append, per-Pod projection, or post-action speech suppression"
				} else if a == model.ActionLiteLLMClientRevoke {
					e.UnverifiedEffect = "support does not revoke LiteLLM's master key or undo prior queries; dispatch checks CAS and both gateway readbacks"
				} else if a == model.ActionCRMRefundRevoke {
					e.UnverifiedEffect = "support does not authenticate CRM callers or undo prior refunds; dispatch CASes the deny-guard and checks every serving Pod denies the order"
				} else if a == model.ActionEndpointLeaseRevoke {
					e.UnverifiedEffect = "support does not prove old accepted responses closed or public A denial/B continuity; dispatch checks original proxy drain and console checks public behavior"
				} else if a == model.ActionControllerStop {
					e.UnverifiedEffect = "support does not establish the owner was scaled to zero or the children removed; the runtime receipt confirms only a bounded no-recreation absence window, never permanent erasure"
				} else {
					e.UnverifiedEffect = "handler is registered; per-target fixtures, emission and effect are verified elsewhere"
				}
			} else {
				e.Why = unsupportedWhy(BackendNative, a, detail)
			}
		}
		out = append(out, e)
	}
	return out
}
