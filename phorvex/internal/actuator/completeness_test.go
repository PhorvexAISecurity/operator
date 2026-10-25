/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * THE COMPLETENESS INVARIANT — the CI teeth (the binary-startup teeth are the package-level
 * mustCoverAllActions() init-panic in handler.go). This file fails `go test` (= fails CI) if
 * any generatable action lacks a native handler, if a handler is an orphan, if the action
 * order drifts, or if the feasibility gate returns an unexpected verdict for any action.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT (M-120). These are registry-membership and
 * bounded-verdict unit tests with in-memory fixtures. They prove that every generatable
 * action is dispatchable, that the registry has no dead hands, that the tie-break order is
 * stable, and that the REAL registered feasibility laws (not a mocked verdict or an injected
 * registry) return the expected verdict family for every action under a small, fixed set of
 * fixtures. They do NOT prove that a handler mutates a cluster correctly, that the laws are
 * complete for every runtime input, or "full real-time safety": registry presence is not
 * runtime coverage, and a handler that returns success while doing nothing still satisfies
 * the registration tier. Handler behaviour against genuine API semantics is covered by the
 * local API-server (envtest) tests in this package and internal/runner — TestM47APIServer-
 * Preconditions, TestM038APIServerConditionalDetach, TestM048APIServerLifecycle,
 * TestM048APIServerRestrictedRole, TestM007RestrictedRequests,
 * TestM032CoverageAPIServerReadback, TestM005TwoManagersAndHandoff, TestM013RealEventSink —
 * which the plain unit job skips (KUBEBUILDER_ASSETS blank) and the required go-envtest job
 * executes through tools/envtest_gate.py. envtest is still only a local kube-apiserver/etcd:
 * no kubelet, CNI, garbage collector, cloud API, AI serving backend or physical mitigation.
 * (HONEST: none of this is a compile error — `go build` still produces a binary; the
 * init-panic makes it die on start.)
 */

package actuator

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

// TestCompletenessForward — every generatable action has a registered native handler.
func TestCompletenessForward(t *testing.T) {
	if missing := MissingHandlers(); len(missing) > 0 {
		t.Fatalf("COMPLETENESS VIOLATION: generatable actions have no native handler: %v", missing)
	}
	// Belt-and-suspenders: each is actually dispatchable.
	for _, a := range actionset.GeneratableActions() {
		if _, ok := HandlerRegistry.Get(string(a)); !ok {
			t.Fatalf("COMPLETENESS VIOLATION: action %q not in HandlerRegistry", a)
		}
	}
}

// TestCompletenessSymmetric — no orphan handler (a dead hand hiding a typo). Allowed:
// generatable actions + the declared-only ActionDisable.
func TestCompletenessSymmetric(t *testing.T) {
	if orphans := OrphanHandlers(); len(orphans) > 0 {
		t.Fatalf("ORPHAN HANDLERS (registered but not generatable/declared): %v", orphans)
	}
}

// TestActionOrderDeterminism — MutatingActions must list ActionRotate before
// ActionQuarantine so the engine's strict-`>` net-benefit tie-break stays byte-identical
// to the pre-P-ACTUATOR baseline (the 1.62x + P3 + lead-demo parity rides this order).
func TestActionOrderDeterminism(t *testing.T) {
	idx := map[model.Action]int{}
	for i, a := range model.MutatingActions {
		idx[a] = i
	}
	r, okR := idx[model.ActionRotate]
	q, okQ := idx[model.ActionQuarantine]
	if !okR || !okQ {
		t.Fatalf("MutatingActions must contain rotate and quarantine; got %v", model.MutatingActions)
	}
	if r >= q {
		t.Fatalf("determinism: ActionRotate (idx %d) must precede ActionQuarantine (idx %d) in MutatingActions", r, q)
	}
	// ActionDisable must NOT be generatable (declared-only).
	if _, ok := idx[model.ActionDisable]; ok {
		t.Fatalf("ActionDisable must be EXCLUDED from MutatingActions (declared-not-implemented), but it is present")
	}
}

// feasibilityExpectation is the verdict family one action must receive from the real
// registered laws. "" means feasible; otherwise the Reason must start with the family.
// Exactly one law is meant to decide each row, so every fixture below is otherwise
// unconstrained: a bare pod (DesiredReplicas 0 => availability-floor neutral), no telemetry
// (slo-headroom/tokens-floor neutral), no exposure clocks (anti-over-rotation and
// proactive-cadence fail-open), not stateful, no physics witness (vram/mig-validity
// neutral), a non-system namespace (code-exec-guard neutral) and a zero policy
// (NativeRotate false => native-rotation-owner neutral).
type feasibilityExpectation struct {
	plain string // no GPU, no model id, no MIG device: the kind/plain-workload posture
}

// feasibilityTable is the exact expected verdict per generatable action. It MUST be total:
// TestFeasibilityVerdictsPerAction fails when a GeneratableActions member is missing here
// (a new action needs an explicit expectation) or when a row names an action that is not
// generatable (a stale or misspelled row proves nothing).
var feasibilityTable = map[model.Action]feasibilityExpectation{
	model.ActionRotate:                        {},
	model.ActionQuarantine:                    {},
	model.ActionDebugger:                      {},
	model.ActionCustomInject:                  {},
	model.ActionIdentityRotate:                {},
	model.ActionRouteRotate:                   {},
	model.ActionWarmSwap:                      {plain: "ai-context-required:"},
	model.ActionMIGRebind:                     {plain: "ai-context-required:"},
	model.ActionKVReset:                       {plain: "ai-context-required:"},
	model.ActionEndpointRotate:                {plain: "ai-context-required:"},
	model.ActionModelShardReplace:             {plain: "ai-context-required:"},
	model.ActionAdapterRotate:                 {plain: "ai-context-required:"},
	model.ActionRequestDrain:                  {plain: "ai-context-required:"},
	model.ActionGuardrailRotate:               {plain: "ai-context-required:"},
	model.ActionKVMigrateInvalidate:           {plain: "ai-context-required:"},
	model.ActionSensitiveOutputPolicyActivate: {plain: "ai-context-required:"},
	model.ActionVoiceMemoryNoteRevoke:         {plain: "ai-context-required:"},
	model.ActionVoiceRefundPairDeny:           {plain: "ai-context-required:"},
	model.ActionVoiceOutputPolicyActivate:     {plain: "ai-context-required:"},
	model.ActionVoiceMCPToolPin:               {plain: "ai-context-required:"},
	model.ActionVoiceSessionAdmissionEnforce:  {plain: "ai-context-required:"},
	model.ActionLiteLLMClientRevoke:           {plain: "ai-context-required:"},
	model.ActionEndpointLeaseRevoke:           {plain: "ai-context-required:"},
	model.ActionCRMRefundRevoke:               {plain: "ai-context-required:"},
	// controller-stop is feasibility-neutral on a bare pod: its whole-owner-removal authority
	// (a trusted controller-UID-bound unauthorized-owner observation + exact policy epoch) is
	// enforced by the capability gate, the actionset generator, the backend and the native
	// handler, NOT by a feasibility veto — mirroring identity-rotate. It removes no shared
	// Ready serving replica, so the availability floor does not gate it either.
	model.ActionControllerStop: {},
	// throttle installs a serving-admission budget at an already-present authoritative proxy.
	// Its authority (a trusted serving-rate-budget observation + exact policy epoch) is enforced
	// by the capability gate, the actionset generator, the backend and the native handler, NOT by
	// a feasibility veto — mirroring controller-stop/identity-rotate. It retains every Ready replica,
	// so it is not an AI move and the availability floor does not gate it.
	model.ActionThrottle: {},
}

// plainView is the otherwise-unconstrained plain workload described on feasibilityExpectation.
func plainView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p", UID: "u1"}}
}

// aiView is the same pod with the positive context every AI move requires, including the
// MIG device mig-rebind requires and the exact detector binding adapter-rotate requires.
func aiView() *model.WorkloadView {
	v := plainView()
	v.Pod.Namespace = "litellm"
	v.Pod.HasGPU = true
	v.Pod.ModelID = "llama-3-8b"
	v.Pod.MIGDevice = "MIG-GPU-0/1g.5gb"
	v.Pod.SuspectAdapter = "adapter-a"
	v.Pod.AdapterObservation = &model.AdapterObservation{
		EventName:       "adapter-detected",
		EventUID:        "event-uid",
		CreatorIdentity: "system:serviceaccount:ns:detector",
		TargetPodUID:    v.Pod.UID,
		AdapterName:     v.Pod.SuspectAdapter,
	}
	v.Pod.OutputPolicyConfigMap = "phorvex-output-policy-p"
	v.Pod.OutputPolicyRuleSHA256 = "rule-sha"
	v.Pod.OutputProxySourceSHA256 = "proxy-sha"
	v.Pod.OutputSupportSourceSHA256 = "support-sha"
	v.Pod.OutputEventCreator = "system:serviceaccount:ns:detector"
	v.Pod.OutputPolicyObservation = &model.SensitiveOutputObservation{
		EventName:           "output-detected",
		EventUID:            "output-event-uid",
		CreatorIdentity:     v.Pod.OutputEventCreator,
		TargetPodUID:        v.Pod.UID,
		ConfigMapUID:        "cm-uid",
		PolicyName:          "guardrail-output-fixture",
		PolicyUID:           "policy-uid",
		PolicyGeneration:    1,
		RuleSHA256:          v.Pod.OutputPolicyRuleSHA256,
		ProxySourceSHA256:   v.Pod.OutputProxySourceSHA256,
		SupportSourceSHA256: v.Pod.OutputSupportSourceSHA256,
		ProxyImageID:        "proxy@sha256:1",
		SupportImageID:      "support@sha256:1",
	}
	v.Pod.VoiceMemoryConfigMap = "voice-memory-policy"
	v.Pod.VoiceMemorySourceSHA256 = "source-sha"
	v.Pod.VoiceMemoryDeploymentUID = "deployment-uid"
	v.Pod.VoiceMemoryEventCreator = "system:serviceaccount:ns:detector"
	v.Pod.VoiceMemoryObservation = &model.VoiceMemoryObservation{EventName: "voice-detected", EventUID: "voice-event-uid", CreatorIdentity: v.Pod.VoiceMemoryEventCreator,
		ScenarioID: "voice-live", CaseID: "owned-memory",
		TargetPodUID: v.Pod.UID, DeploymentUID: v.Pod.VoiceMemoryDeploymentUID, ConfigMapUID: "voice-cm-uid", SourceSHA256: v.Pod.VoiceMemorySourceSHA256,
		CallerID: "+15551234567", NoteSHA256: "note-sha", PolicyUID: "policy-uid", PolicyGeneration: 1}
	v.Pod.VoiceRefundConfigMap = "voice-refund-policy"
	v.Pod.VoiceRefundSourceSHA256 = "source-sha"
	v.Pod.VoiceRefundDeploymentUID = "deployment-uid"
	v.Pod.VoiceRefundEventCreator = "system:serviceaccount:ns:detector"
	v.Pod.VoiceRefundObservation = &model.VoiceRefundObservation{EventName: "refund-detected", EventUID: "refund-event-uid", CreatorIdentity: v.Pod.VoiceRefundEventCreator,
		ScenarioID: "voice-agency", CaseID: "owned-refund", TargetPodUID: v.Pod.UID, DeploymentUID: v.Pod.VoiceRefundDeploymentUID,
		ConfigMapUID: "refund-cm-uid", SourceSHA256: v.Pod.VoiceRefundSourceSHA256,
		AssertedCallerSHA256: "caller-sha", OrderSHA256: "order-sha", PolicyUID: "policy-uid", PolicyGeneration: 1}
	v.Pod.LiteLLMClientObservation = &model.LiteLLMClientObservation{
		EventName: "client-observed", EventUID: "client-event-uid", CreatorIdentity: "console-creator",
		TargetPodUID: v.Pod.UID, PeerPodUID: "peer-uid", ClientSHA256: "client-hash",
		ConfigMapUID: "cm-uid", ClientsConfigMapUID: "clients-cm-uid", SeedSHA256: "seed-hash",
		ServiceUID: "service-uid", GatewaySourceSHA256: "source-hash",
		PolicyName: "litellm-policy", PolicyUID: "litellm-policy-uid", PolicyGeneration: 1,
	}
	return v
}

// aiViewForAction supplies the exact Voice namespace and observed output marker only
// for the Voice output action. Other actions retain the shared AI fixture.
func aiViewForAction(action model.Action) *model.WorkloadView {
	v := aiView()
	if action == model.ActionVoiceSessionAdmissionEnforce {
		bound := boundVoiceAdmissionView()
		v.Pod = bound.Pod
		return v
	}
	if action == model.ActionEndpointLeaseRevoke {
		v.Pod.Namespace = "vllm"
		v.Pod.EndpointLeaseObservation = &model.EndpointLeaseObservation{
			EventName: "lease-observed", EventUID: "11111111-1111-4111-8111-111111111111",
			CreatorIdentity: "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
			ScenarioID:      "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED",
			PolicyName: "vllm-defense", PolicyUID: "22222222-2222-4222-8222-222222222222", PolicyGeneration: 1,
			TargetPodUID: v.Pod.UID, ServiceUID: "33333333-3333-4333-8333-333333333333",
			PolicyConfigMapUID: "44444444-4444-4444-8444-444444444444", ProxySourceSHA256: strings.Repeat("a", 64),
			SecretUID: "55555555-5555-4555-8555-555555555555", SeedSHA256: strings.Repeat("b", 64),
			RevokedClientHMAC: strings.Repeat("c", 64), RetainedClientHMAC: strings.Repeat("d", 64),
			AcceptedStatus: 200, AcceptedResponseSHA256: strings.Repeat("e", 64),
			RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: strings.Repeat("f", 64),
			ObservedAt: time.Now().UTC(),
		}
		return v
	}
	if action == model.ActionCRMRefundRevoke {
		v.Pod.Namespace = "crm"
		v.Pod.CRMRefundObservation = &model.CRMRefundObservation{
			EventName: "crm-refund-observed", EventUID: "66666666-6666-4666-8666-666666666666",
			CreatorIdentity: "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
			OrderID:         "OR-5002", OrderAccountID: "AC-1002", CallerAccountID: "AC-1001",
			GuardConfigMapUID: "77777777-7777-4777-8777-777777777777", ServiceUID: "88888888-8888-4888-8888-888888888888",
			TargetPodUID: v.Pod.UID, PeerPodUID: "peer-uid",
			PolicyName: "crm-defense", PolicyUID: "99999999-9999-4999-8999-999999999999", PolicyGeneration: 1,
			ObservedAt: time.Now().UTC(),
		}
		return v
	}
	if action != model.ActionVoiceOutputPolicyActivate && action != model.ActionVoiceMCPToolPin {
		return v
	}
	v.Pod.Namespace = "voice"
	if action == model.ActionVoiceMCPToolPin {
		v.Pod.VoiceMCPConfigMap = "voice-mcp-tool-policy"
		v.Pod.VoiceMCPDeploymentUID = "deployment-uid"
		v.Pod.VoiceMCPSourceSHA256 = "source-sha"
		v.Pod.VoiceMCPEventCreator = "console-creator"
		v.Pod.VoiceMCPObservation = &model.VoiceMCPObservation{EventName: "observed", EventUID: "event-uid", CreatorIdentity: "console-creator",
			ScenarioID: "ai2-mcp-tool-poisoning", RunSHA256: "run-sha", TargetPodUID: v.Pod.UID, DeploymentUID: "deployment-uid",
			ConfigMapUID: "cm-uid", SourceConfigMapUID: "source-cm-uid", SourceSHA256: "source-sha", ToolName: "store_directory", GoodDescriptorSHA256: "good-sha",
			ObservedDescriptorSHA256: "observed-sha", PolicyName: "voice-policy", PolicyUID: "policy-uid", PolicyGeneration: 1,
			MCPServiceName: "mcp-server", MCPServiceUID: "service-uid", MCPPodName: "mcp-pod", MCPPodUID: "mcp-pod-uid", MCPDeploymentUID: "mcp-deployment-uid", MCPConfigMapUID: "mcp-cm-uid", MCPSourceSHA256: "mcp-source-sha"}
		return v
	}
	v.Pod.VoiceOutputConfigMap = "voice-output-policy"
	v.Pod.VoiceOutputDeploymentUID = "deployment-uid"
	v.Pod.VoiceOutputSourceSHA256 = "source-sha"
	v.Pod.VoiceOutputEventCreator = "console-creator"
	v.Pod.VoiceOutputObservation = &model.VoiceOutputObservation{EventName: "observed", EventUID: "event-uid", CreatorIdentity: "console-creator",
		ScenarioID: "ai2-system-prompt-leakage", EvidenceSource: "TEST_INJECTED", TargetPodUID: v.Pod.UID,
		DeploymentUID: "deployment-uid", ConfigMapUID: "cm-uid", SourceSHA256: "source-sha", MarkerSHA256: "marker-sha",
		PolicyName: "voice-policy", PolicyUID: "policy-uid", PolicyGeneration: 1, RawModelMarkerObserved: true, AssistantOutputMarkerObserved: true}
	return v
}

// assertVerdict checks the verdict family for one (fixture, action) pair.
func assertVerdict(t *testing.T, fixture string, a model.Action, got feasibility.Verdict, family string) {
	t.Helper()
	switch {
	case family == "" && !got.Feasible:
		t.Errorf("%s: %q must be FEASIBLE under the real laws, got veto %q", fixture, a, got.Reason)
	case family != "" && got.Feasible:
		t.Errorf("%s: %q must be INFEASIBLE (%s...), got feasible", fixture, a, family)
	case family != "" && !strings.HasPrefix(got.Reason, family):
		t.Errorf("%s: %q vetoed by the wrong law: want reason family %q, got %q", fixture, a, family, got.Reason)
	}
}

// TestFeasibilityVerdictsPerAction — the feasibility gate returns the EXPECTED verdict for
// EVERY generatable action, decided by the real registered laws (feasibility.Registry as
// shipped, not an injected registry and not a mocked final flag). The reachability test this
// replaces discarded the verdict (`_ = feasibility.Evaluate(...)`), so an always-feasible or
// always-infeasible gate passed it; every fixture here catches both stubs: "plain" and
// "fresh clock" fail an always-feasible gate, "ai", "stale clock" and noop fail an
// always-infeasible one (retained as test-only overlays in the T2-M120 fix record).
func TestFeasibilityVerdictsPerAction(t *testing.T) {
	generatable := actionset.GeneratableActions()
	if len(generatable) == 0 {
		t.Fatal("no generatable actions: the invariant would be vacuous")
	}
	seen := map[model.Action]bool{}
	for _, a := range generatable {
		if _, ok := feasibilityTable[a]; !ok {
			t.Errorf("TABLE INCOMPLETE: generatable action %q has no expected verdict; add a row deciding its plain-workload feasibility", a)
		}
		seen[a] = true
	}
	for a := range feasibilityTable {
		if !seen[a] {
			t.Errorf("TABLE STALE: row %q is not a generatable action", a)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	pol := model.Policy{}
	window := 15 * time.Minute
	fresh := model.Policy{AntiOverRotationWindow: window}
	for _, a := range generatable {
		move := model.Move{Action: a}
		want := feasibilityTable[a]
		// Plain workload: AI moves are refused for lack of an inference context; the rest are
		// feasible (nothing else constrains a bare pod under a zero policy).
		assertVerdict(t, "plain workload", a, feasibility.Evaluate(plainView(), move, pol), want.plain)
		// Positive AI context (GPU + model id + MIG device): every action is feasible.
		assertVerdict(t, "ai context", a, feasibility.Evaluate(aiViewForAction(a), move, pol), "")
		// AI context WITHOUT a MIG device: only mig-rebind loses, on the MIG law specifically.
		noMIG := aiViewForAction(a)
		noMIG.Pod.MIGDevice = ""
		family := ""
		if a == model.ActionMIGRebind {
			family = "mig-device-required:"
		}
		assertVerdict(t, "ai context without MIG device", a, feasibility.Evaluate(noMIG, move, pol), family)
		// Anti-over-rotation reads each action's OWN exposure clock: a fresh reset inside the
		// window vetoes, a stale one allows. The clock variable must be mapped (M-23 tripwire).
		clock := feasibility.ExposureVarFor(a)
		if clock == "" {
			t.Errorf("%q has no exposure clock; anti-over-rotation could never govern it", a)
			continue
		}
		vetoed := aiViewForAction(a)
		vetoed.ExposureByVariable = map[string]time.Duration{clock: time.Second}
		got := feasibility.Evaluate(vetoed, move, fresh)
		assertVerdict(t, "fresh clock", a, got, "anti-over-rotation:")
		if !got.Feasible && !strings.Contains(got.Reason, clock) {
			t.Errorf("fresh clock: %q veto %q does not name its own clock %q", a, got.Reason, clock)
		}
		stale := aiViewForAction(a)
		stale.ExposureByVariable = map[string]time.Duration{clock: window + time.Minute}
		assertVerdict(t, "stale clock", a, feasibility.Evaluate(stale, move, fresh), "")
	}
	// noop is always feasible: no context, no clock and no window can veto it.
	allFresh := aiView()
	allFresh.ExposureByVariable = map[string]time.Duration{}
	for _, v := range model.LiveExposureVariables {
		allFresh.ExposureByVariable[v] = time.Second
	}
	noop := model.Move{Action: model.ActionNoop}
	for name, view := range map[string]*model.WorkloadView{"plain": plainView(), "ai": aiView(), "all clocks fresh": allFresh} {
		assertVerdict(t, "noop/"+name, model.ActionNoop, feasibility.Evaluate(view, noop, fresh), "")
	}
}

// TestFeasibilityActionSpecificLaws — the two remaining action-specific laws decide exactly
// their own actions and nothing else: code-exec injection is denied in a system namespace,
// and rotate (only) is refused on a stateful pod.
func TestFeasibilityActionSpecificLaws(t *testing.T) {
	pol := model.Policy{}
	for _, a := range actionset.GeneratableActions() {
		move := model.Move{Action: a}
		system := aiView()
		system.Pod.Namespace = "kube-system"
		family := ""
		if a == model.ActionDebugger || a == model.ActionCustomInject {
			family = "code-exec-guard:"
		}
		if a == model.ActionVoiceSessionAdmissionEnforce || a == model.ActionLiteLLMClientRevoke || a == model.ActionVoiceOutputPolicyActivate || a == model.ActionVoiceMCPToolPin || a == model.ActionEndpointLeaseRevoke || a == model.ActionCRMRefundRevoke {
			family = "ai-context-required:"
		}
		assertVerdict(t, "kube-system", a, feasibility.Evaluate(system, move, pol), family)
		stateful := aiViewForAction(a)
		stateful.Pod.Stateful = true
		family = ""
		if a == model.ActionRotate {
			family = "stateful-integrity:"
		}
		assertVerdict(t, "stateful pod", a, feasibility.Evaluate(stateful, move, pol), family)
	}
}

func boundVoiceAdmissionView() *model.WorkloadView {
	uid := "11111111-1111-4111-8111-111111111111"
	sha := strings.Repeat("a", 64)
	a := voiceadmissionpolicy.EventAssertion{Version: 1, ScenarioID: voiceadmissionpolicy.ScenarioID, CaseID: "unsigned-audio", RunSHA256: sha, SessionID: uid, DeploymentUID: uid, PodUID: uid, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, PolicyCMUID: uid, PolicyResourceVersion: "1", RuleSHA256: sha, SecurityPolicyUID: uid, SecurityPolicyGeneration: 1, ObservedAtUnixMs: 1, EvidenceSource: "TEST_INJECTED", Observed: true, SentAudioFrames: 1, SentAudioBytes: 1, ReceiptSHA256: sha, ProviderEvidenceSHA256: sha}
	return &model.WorkloadView{Pod: model.Pod{Namespace: "voice", Name: "voice", UID: uid, VoiceAdmissionConfigMap: voiceadmissionpolicy.ConfigMapName, VoiceAdmissionDeploymentUID: uid, VoiceAdmissionSourceSHA256: sha, VoiceAdmissionEventCreator: eventtrust.Injector(), VoiceAdmissionObservation: &model.VoiceAdmissionObservation{EventName: "observed", EventUID: uid, CreatorIdentity: eventtrust.Injector(), ScenarioID: voiceadmissionpolicy.ScenarioID, EvidenceSource: "TEST_INJECTED", TargetPodUID: uid, DeploymentUID: uid, ConfigMapUID: uid, ConfigMapResourceVersion: "1", SourceSHA256: sha, RuleSHA256: sha, PolicyName: "voice-defense", PolicyUID: uid, PolicyGeneration: 1, SessionID: uid, Assertion: a}}}
}
