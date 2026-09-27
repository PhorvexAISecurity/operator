/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

// Package capability is the T1-E capability gate: the ONE home for "may this action be
// offered for THIS pod, right now?", evaluated BEFORE scoring. It is imported by BOTH the
// candidate generator (per-candidate eligibility) and the runner's ActionsSupported
// status (per-pod capability), so the two can never drift into the M-20 mirror.
//
// The per-pod predicate is EXTRACTED from the pre-T1-E runner code (it read the model's
// typed capability witnesses); this package de-smears it (per-pod conjunction, not a
// fleet-wide OR of independent ∃'s — the M-20 lie) and precomputes the fleet/pool indices
// ONCE per tick (Index) so a per-candidate lookup is O(1), never an O(fleet) rescan (R1).
//
// Cheapest-first, first-failure-wins, exactly one reason per excluded action:
//
//	1 not-installable  (cluster set)        2 no-cover  (per-asset recon)
//	3 capability-unsupported (model witness + pool index + actuator transport)
//	4 no-rbac          (cached SSAR — LAST; the only network call)
package capability

import (
	"context"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/codeexec"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// The exclusion classes (closed set; mirrored in the decision trace's ExclusionKind).
const (
	ReasonNotInstallable = "not-installable"
	ReasonNoCover        = "no-cover"
	ReasonCapability     = "capability-unsupported"
	ReasonNoRBAC         = "no-rbac"
	// ReasonCodeExec excludes an ephemeral-container injection (debugger/custom-inject) whose
	// API-server admission deny-policy is not currently VERIFIED to be in force for the target
	// namespace (M-6). RBAC-allowed ≠ admission-verified: this is a distinct, attributable
	// class so a code-exec exclusion never masquerades as a generic capability miss.
	ReasonCodeExec = codeexec.ReasonUnverified
)

// AdmissionVerifier is the O(1) cached code-exec admission-capability oracle (M-6). Available
// answers whether the deny-policy is verified in force AND covers the target namespace (from
// its labels). It is satisfied by *codeexec.Verifier; nil ⇒ the code-exec leg is skipped
// (e.g. in unit fixtures that do not wire it), never a silent pass at runtime.
type AdmissionVerifier interface {
	Available(nsLabels map[string]string) (ok bool, reason string)
}

// Pod capability-witness label/role keys (extracted from the pre-T1-E runner).
const (
	labelSwapGroup     = "phorvex.ai/swap-group"
	labelModelShard    = "phorvex.ai/model-shard"
	labelParallelGroup = "phorvex.ai/parallel-group"
	labelRank          = "phorvex.ai/rank"
	labelWarmRole      = "phorvex.ai/role"
	labelModelLoaded   = "phorvex.ai/model-loaded"
	labelLoRAEnabled   = "phorvex.ai/lora-enabled"
	labelGuardrailTier = "phorvex.ai/guardrail-tier"
	labelServing       = "phorvex.ai/serving"
	warmShadowRole     = "warm-shadow"
)

// AICapabilityActions are the actions whose eligibility depends on AI runtime fixtures.
var AICapabilityActions = map[model.Action]bool{
	model.ActionWarmSwap: true, model.ActionMIGRebind: true,
	model.ActionKVReset: true, model.ActionEndpointRotate: true,
	model.ActionModelShardReplace: true, model.ActionAdapterRotate: true,
	model.ActionRequestDrain: true, model.ActionGuardrailRotate: true,
	model.ActionKVMigrateInvalidate:           true,
	model.ActionSensitiveOutputPolicyActivate: true,
	model.ActionVoiceMemoryNoteRevoke:         true,
	model.ActionLiteLLMClientRevoke:           true,
}

// Reason is the gate verdict for one (asset, action): nil = eligible-and-clean.
type Reason struct {
	Excluded    bool   // true = drop from ranking with Kind/Detail
	Kind        string // Reason* class (only when Excluded)
	Detail      string // free-text why (exclusion detail, or the rbac-unknown note)
	RBACUnknown bool   // SSAR errored — NOT excluded, flagged + counted (fail-open, P-NO-FREEZE)
}

// Index is the per-tick precompute: fleet/pool facts bucketed once so per-candidate
// capability is O(1). Built by BuildIndex from the tick snapshot.
type Index struct {
	warmShadowGroups  map[string]bool // "ns\x00swapGroup" -> a ready promotable warm shadow exists
	shardShadow       map[string]bool // "ns\x00shard" -> a ready promotable shadow exists (independent shard)
	scalarPoolShadows map[string]bool // ns/group/RS UID/Service -> configured ready scalar member
	parallelRanks     map[string]int  // "ns\x00shard\x00parallel" -> distinct ready shadow ranks
	servingByNS       map[string][]ingest.ServiceInfo
	readyByService    map[string]int
	schedulableGPU    int
}

func poolKey(parts ...string) string {
	k := ""
	for i, p := range parts {
		if i > 0 {
			k += "\x00"
		}
		k += p
	}
	return k
}

// BuildIndex precomputes the fleet/pool indices from the tick snapshot ONCE (R1).
func BuildIndex(fleet []model.Pod, nodes []ingest.NodeInfo, services []ingest.ServiceInfo) Index {
	idx := Index{
		warmShadowGroups:  map[string]bool{},
		shardShadow:       map[string]bool{},
		scalarPoolShadows: map[string]bool{},
		parallelRanks:     map[string]int{},
		servingByNS:       map[string][]ingest.ServiceInfo{},
		readyByService:    map[string]int{},
	}
	readyByNS := map[string][]model.Pod{}
	declaredRoutes := map[string]bool{}
	for _, pod := range fleet {
		if pod.RouteService != "" {
			declaredRoutes[poolKey(pod.Namespace, pod.RouteService)] = true
		}
		if pod.Ready {
			readyByNS[pod.Namespace] = append(readyByNS[pod.Namespace], pod)
		}
	}
	// Bucket ready promotable shadows once.
	seenRank := map[string]map[string]bool{} // parallelKey -> set of ranks
	for i := range fleet {
		s := &fleet[i]
		if !s.Ready || s.Labels[labelWarmRole] != warmShadowRole || s.Labels[labelModelLoaded] != "true" {
			continue
		}
		if g := s.Labels[labelSwapGroup]; g != "" {
			idx.warmShadowGroups[poolKey(s.Namespace, g)] = true
			if s.WarmPoolConfigured {
				idx.scalarPoolShadows[poolKey(s.Namespace, labelSwapGroup, g, s.WarmPoolOwnerUID, s.RouteService)] = true
			}
		}
		if sh := s.Labels[labelModelShard]; sh != "" {
			if p := s.Labels[labelParallelGroup]; p != "" {
				if r := s.Labels[labelRank]; r != "" {
					pk := poolKey(s.Namespace, sh, p)
					if seenRank[pk] == nil {
						seenRank[pk] = map[string]bool{}
					}
					if !seenRank[pk][r] {
						seenRank[pk][r] = true
						idx.parallelRanks[pk]++
					}
				}
			} else {
				idx.shardShadow[poolKey(s.Namespace, sh)] = true
				if s.WarmPoolConfigured {
					idx.scalarPoolShadows[poolKey(s.Namespace, labelModelShard, sh, s.WarmPoolOwnerUID, s.RouteService)] = true
				}
			}
		}
	}
	for _, n := range nodes {
		if n.Schedulable && hasAllocatableGPU(n) {
			idx.schedulableGPU++
		}
	}
	for _, svc := range services {
		idx.servingByNS[svc.Namespace] = append(idx.servingByNS[svc.Namespace], svc)
		if !declaredRoutes[poolKey(svc.Namespace, svc.Name)] {
			continue
		}
		for _, pod := range readyByNS[svc.Namespace] {
			if selectorMatches(svc.Selector, pod.Labels) {
				idx.readyByService[poolKey(svc.Namespace, svc.Name)]++
			}
		}
	}
	return idx
}

// Witness is built ONCE per tick: the precomputed index + the installability set + the
// SSAR checker + the actuator (for the wiring-only SupportsAction leg). Eligible/Capable
// are then O(1) per candidate apart from the cached SSAR.
type Witness struct {
	ctx        context.Context
	idx        Index
	notInstall model.InstallSet
	az         *authz.Checker
	act        actuator.Actuator
	// M-6 code-exec admission leg (optional; nil = skipped). nsLabels are the tick's
	// per-namespace label sets (already GET-derived observation substrate) so the scope
	// check is O(1) and needs no per-candidate network read.
	codeExec   AdmissionVerifier
	nsLabels   map[string]map[string]string
	policyName string
	policyUID  string
}

// BuildWitness assembles the per-tick witness.
func BuildWitness(ctx context.Context, idx Index, notInstall model.InstallSet, az *authz.Checker, act actuator.Actuator) Witness {
	return Witness{ctx: ctx, idx: idx, notInstall: notInstall, az: az, act: act}
}

// WithCodeExec returns a copy of the witness with the M-6 code-exec admission leg wired.
// Kept separate from BuildWitness so existing callers/fixtures are untouched (a nil verifier
// simply skips the leg — the runtime path always wires a real one).
func (w Witness) WithCodeExec(cev AdmissionVerifier, nsLabels map[string]map[string]string) Witness {
	w.codeExec = cev
	w.nsLabels = nsLabels
	return w
}

// WithPolicyIdentity adds immutable policy configuration already held by the runner.
// It performs no API read and is therefore safe for EligibleObserved counterfactuals.
func (w Witness) WithPolicyIdentity(name, uid string) Witness {
	w.policyName, w.policyUID = name, uid
	return w
}

// isCodeExecAction reports the two in-pod code-execution (ephemeral-container) injections.
func isCodeExecAction(a model.Action) bool {
	return a == model.ActionDebugger || a == model.ActionCustomInject
}

// Eligible runs the full cheapest-first gate for one (asset, action). nil = eligible.
// This is the REAL evaluation: its RBAC leg may issue the (cached) SelfSubjectAccessReview.
func (w Witness) Eligible(v *model.WorkloadView, action model.Action, coverKeys []string) *Reason {
	return w.eligible(v, action, coverKeys, true)
}

// EligibleObserved is Eligible for a COUNTERFACTUAL evaluation (M-163). Every local leg is
// the identical predicate on the identical per-tick witness — the gate is not skipped and is
// not weakened — but the RBAC leg answers from authorization ALREADY REVIEWED instead of
// issuing a review. A shadow therefore cannot spend apiserver budget, cannot cache an answer
// the next production gate would otherwise have re-reviewed, and cannot extend the life of
// one already cached.
//
// Where no current authorization evidence exists the verdict is the existing RBAC-UNKNOWN
// fail-open (flagged, not excluded, P-NO-FREEZE) with a detail naming it unobserved — never
// an invented allow. A cached deny still excludes. The shadow's comparison is therefore
// weaker EVIDENCE than production's on exactly those (namespace, verb) pairs production has
// not reviewed recently, and the record says so.
func (w Witness) EligibleObserved(v *model.WorkloadView, action model.Action, coverKeys []string) *Reason {
	return w.eligible(v, action, coverKeys, false)
}

func (w Witness) eligible(v *model.WorkloadView, action model.Action, coverKeys []string, review bool) *Reason {
	if w.notInstall.Has(action) {
		return &Reason{Excluded: true, Kind: ReasonNotInstallable, Detail: "action not in installed CRD action enum"}
	}
	if action == model.ActionIdentityRotate {
		return &Reason{Excluded: true, Kind: ReasonCapability, Detail: model.IdentityRotateUnsupportedReason}
	}
	if len(coverKeys) == 0 {
		reason := "recon-cover: action invalidates no facts for this asset"
		if action == model.ActionGuardrailRotate {
			reason = model.GuardrailBypassNoCoverReason
		}
		return &Reason{Excluded: true, Kind: ReasonNoCover, Detail: reason}
	}
	if action == model.ActionSensitiveOutputPolicyActivate {
		o := v.Pod.OutputPolicyObservation
		if o == nil || o.PolicyName != w.policyName || o.PolicyUID != w.policyUID || w.policyUID == "" {
			return &Reason{Excluded: true, Kind: ReasonCapability, Detail: "sensitive-output-policy: event policy identity differs from current policy"}
		}
	}
	if action == model.ActionVoiceMemoryNoteRevoke {
		o := v.Pod.VoiceMemoryObservation
		if o == nil || o.PolicyName != w.policyName || o.PolicyUID != w.policyUID || w.policyUID == "" {
			return &Reason{Excluded: true, Kind: ReasonCapability, Detail: "voice-memory-policy: event policy identity differs from current policy"}
		}
	}
	if action == model.ActionLiteLLMClientRevoke {
		o := v.Pod.LiteLLMClientObservation
		if o == nil || o.PolicyName != w.policyName || o.PolicyUID != w.policyUID || w.policyUID == "" {
			return &Reason{Excluded: true, Kind: ReasonCapability, Detail: "litellm-client-revoke: event policy identity differs from current policy"}
		}
	}
	if ok, why := w.Capable(v, action); !ok {
		return &Reason{Excluded: true, Kind: ReasonCapability, Detail: why}
	}
	// M-6 code-exec admission leg: a debugger/custom-inject move is offered ONLY if the
	// API-server deny-policy is verified in force for THIS namespace. Local + cached (no
	// network on the gate path), so it precedes the SSAR. Fail-closed: an unwired verifier
	// at runtime is a boot error, not a silent pass (the runtime always sets one).
	if isCodeExecAction(action) && w.codeExec != nil {
		if ok, why := w.codeExec.Available(w.nsLabels[v.Pod.Namespace]); !ok {
			return &Reason{Excluded: true, Kind: ReasonCodeExec, Detail: why}
		}
	}
	// RBAC is LAST: only a candidate that passed the free local checks reaches an SSAR.
	// Both modes derive the verb set from the SAME resolved-backend requirement plan, so a routing or
	// permission change to that set lands on the reviewing and the observing path together.
	if w.az != nil {
		if verbs := w.requiredVerbs(action); len(verbs) > 0 {
			var (
				allowed bool
				unknown bool
				why     string
			)
			if review {
				allowed, unknown, why = w.az.Allowed(w.ctx, v.Pod.Namespace, verbs)
			} else {
				allowed, unknown, why = w.az.Observed(v.Pod.Namespace, verbs)
			}
			if unknown {
				return &Reason{RBACUnknown: true, Detail: why} // fail-open: NOT excluded, flagged
			}
			if !allowed {
				return &Reason{Excluded: true, Kind: ReasonNoRBAC, Detail: why}
			}
		}
	}
	return nil
}

// Capable is the CAPABILITY leg alone (runtime fixtures), per (pod, action). Used by the
// gate (step 3) and by the runner's ActionsSupported status (∃-aggregation). ok=true for
// any non-AI-capability action. why is the specific missing-fixture reason.
func (w Witness) Capable(v *model.WorkloadView, action model.Action) (bool, string) {
	// AI-capability actions carry per-target CONFIG predicates; the rest do not. Cheapest
	// local checks first, unchanged.
	if AICapabilityActions[action] {
		pod := &v.Pod
		if !actionContextAvailable(pod, action) {
			return false, "pod lacks the action's required GPU, serving, or detector context"
		}
		if why := w.configWhy(pod, action); why != "" {
			return false, why
		}
	}
	if action == model.ActionRouteRotate {
		if why := w.configWhy(&v.Pod, action); why != "" {
			return false, why
		}
	}
	// [M-21] The SELECTED backend is consulted for EVERY action, not only the AI ones.
	// The old early `return true` for non-AI actions meant a backend that cannot enact
	// rotate, identity-rotate or debugger was never even asked, so its inability could
	// not reach the status. This leg answers "does the backend that would actually
	// receive this dispatch implement the action?" — target-independent, and therefore
	// the same answer for every pod, which is precisely why a backend gap flips the
	// whole-fleet condition rather than showing up as a partial one.
	//
	// An ABSENT backend cannot establish affirmative support: with no hands wired there
	// is nothing that could enact the move, so the honest answer is "no", never a
	// default-true. Tests isolating the other legs wire an explicit support double.
	if w.act == nil {
		return false, actuator.ReasonBackendUnavailable + ": no actuator is wired to answer for this action"
	}
	if ok, why := w.act.SupportsAction(w.ctx, action, w.targetFrom(v)); !ok {
		return false, why
	}
	return true, ""
}

func actionContextAvailable(pod *model.Pod, action model.Action) bool {
	if pod == nil {
		return false
	}
	switch action {
	case model.ActionMIGRebind:
		return pod.HasGPU
	case model.ActionAdapterRotate:
		return pod.HasBoundAdapterObservation()
	case model.ActionSensitiveOutputPolicyActivate:
		return pod.HasBoundSensitiveOutputObservation()
	case model.ActionVoiceMemoryNoteRevoke:
		return pod.HasBoundVoiceMemoryObservation()
	case model.ActionLiteLLMClientRevoke:
		return pod.HasBoundLiteLLMClientObservation()
	default:
		return pod.HasServingDeclaration()
	}
}

// CapableAndAuthorized is Capable PLUS the no-rbac leg, per (pod, action) — the check the
// ActionsSupported status uses (M-160) so the condition reflects RBAC exclusions, not only
// runtime fixtures. It mirrors the generator gate's RBAC step (routing-aware verbs via
// the resolved backend requirement plan; the SSAR is the same cached (scope,verb), so no new SSAR volume).
// RBAC-unknown fails OPEN (ok=true): an SSAR error is not a status gap (P-NO-FREEZE),
// matching the gate. On a deny the why is "no-rbac: <detail>" — the same ReasonNoRBAC
// vocabulary the record's exclusionReason carries, so condition and record don't disagree.
func (w Witness) CapableAndAuthorized(v *model.WorkloadView, action model.Action) (bool, string) {
	if ok, why := w.Capable(v, action); !ok {
		return false, why
	}
	if w.az != nil {
		if verbs := w.requiredVerbs(action); len(verbs) > 0 {
			allowed, unknown, why := w.az.Allowed(w.ctx, v.Pod.Namespace, verbs)
			if !unknown && !allowed {
				return false, ReasonNoRBAC + ": " + why
			}
		}
	}
	return true, ""
}

// Advisory returns local configuration posture only. It never performs an API or Secret read.
func (w Witness) Advisory(v *model.WorkloadView, action model.Action) string {
	if w.act == nil || v == nil {
		return ""
	}
	advisory, ok := w.act.(interface {
		CapabilityAdvisory(model.Action, actuator.Target) string
	})
	if !ok {
		return ""
	}
	return advisory.CapabilityAdvisory(action, w.targetFrom(v))
}

// requiredVerbs follows the backend that this witness will actually dispatch through. The
// hybrid fallback preserves compatibility for small test actuators whose Name is not a
// production backend; every production actuator has one of the three exact backend names.
func (w Witness) requiredVerbs(action model.Action) []authz.Verb {
	backend := actuator.BackendHybrid
	if w.act != nil {
		for _, candidate := range actuator.Backends() {
			if w.act.Name() == string(candidate) {
				backend = candidate
				break
			}
		}
	}
	return actuator.RequiredVerbsForBackend(backend, action)
}

// configWhy returns the missing per-target CONFIG fixture for an AI action, from the
// model's typed witnesses + the pool index; "" means the config fixtures are present.
func (w Witness) configWhy(pod *model.Pod, action model.Action) string {
	switch action {
	case model.ActionMIGRebind:
		if !(pod.MIGDevice != "" && pod.Node != "") {
			return "pod has no MIG resource allocation or scheduled node"
		}
	case model.ActionWarmSwap:
		return w.warmPoolWhy(pod, pod.Labels[labelSwapGroup], w.idx.warmShadowGroups, "matching swap-group")
	case model.ActionModelShardReplace:
		return w.shardPoolWhy(pod)
	case model.ActionKVReset, model.ActionKVMigrateInvalidate:
		if !pod.ServingEndpointReady {
			return "pod has no Ready serving endpoint"
		}
	case model.ActionAdapterRotate:
		if !(pod.Labels[labelLoRAEnabled] == "true" && pod.AdapterObservation != nil &&
			pod.AdapterObservation.TargetPodUID == pod.UID && pod.AdapterObservation.AdapterName == pod.SuspectAdapter) {
			return "pod is not LoRA-enabled or has no UID-bound detector adapter observation"
		}
	case model.ActionGuardrailRotate:
		if !(pod.Labels[labelGuardrailTier] == "true" && pod.GuardrailVariants >= 2) {
			return "pod is not a guardrail tier declaring at least 2 distinct variants"
		}
	case model.ActionSensitiveOutputPolicyActivate:
		if !pod.HasBoundSensitiveOutputObservation() || pod.OutputPolicyObservation.PolicyName != w.policyName ||
			pod.OutputPolicyObservation.PolicyUID != w.policyUID || w.policyUID == "" {
			return "pod has no current UID/source-bound sensitive-output observation"
		}
	case model.ActionVoiceMemoryNoteRevoke:
		if !pod.HasBoundVoiceMemoryObservation() || pod.VoiceMemoryObservation.PolicyName != w.policyName ||
			pod.VoiceMemoryObservation.PolicyUID != w.policyUID || w.policyUID == "" {
			return "pod has no current UID/source-bound voice-memory observation"
		}
	case model.ActionLiteLLMClientRevoke:
		if !pod.HasBoundLiteLLMClientObservation() || pod.LiteLLMClientObservation.PolicyName != w.policyName ||
			pod.LiteLLMClientObservation.PolicyUID != w.policyUID || w.policyUID == "" {
			return "pod has no current UID/source-bound LiteLLM owned-client observation"
		}
	case model.ActionEndpointRotate:
		if pod.RouteService == "" {
			return "pod declares no phorvex.ai/route-service"
		}
	case model.ActionRouteRotate:
		if pod.RouteService == "" {
			return "pod declares no phorvex.ai/route-service"
		}
		for _, svc := range w.idx.servingByNS[pod.Namespace] {
			if svc.Name != pod.RouteService {
				continue
			}
			if svc.Selector["phorvex.ai/route-key"] == "" || !selectorMatches(svc.Selector, pod.Labels) {
				return "declared route Service selector does not select the target route-key"
			}
			if !pod.Ready || w.idx.readyByService[poolKey(pod.Namespace, svc.Name)] < 2 {
				return "declared route Service requires target Ready and at least two Ready backends"
			}
			return ""
		}
		return "declared route Service is absent from the namespace"
	case model.ActionRequestDrain:
		if !w.servingServiceSelects(pod) {
			return "no target Service selects on phorvex.ai/serving for this pod"
		}
	}
	return ""
}

func (w Witness) warmPoolWhy(pod *model.Pod, group string, shadows map[string]bool, label string) string {
	if !capabilityTarget(pod) {
		return "pod is a warm shadow or declares no serving context"
	}
	if group == "" {
		return "pod declares no " + label
	}
	if !pod.WarmPoolConfigured || pod.WarmPoolOwnerUID == "" || pod.RouteService == "" {
		return "ReplicaSet warm-pool template/route configuration unverified"
	}
	if !w.idx.scalarPoolShadows[poolKey(pod.Namespace, labelSwapGroup, group, pod.WarmPoolOwnerUID, pod.RouteService)] {
		return "no configured same-ReplicaSet warm shadow"
	}
	if !shadows[poolKey(pod.Namespace, group)] {
		return "no Ready warm shadow exists for a " + label + " pool"
	}
	return ""
}

func (w Witness) shardPoolWhy(pod *model.Pod) string {
	if !capabilityTarget(pod) {
		return "pod is a warm shadow or declares no serving context"
	}
	shard := pod.Labels[labelModelShard]
	if shard == "" {
		return "pod declares no model-shard"
	}
	if parallel := pod.Labels[labelParallelGroup]; parallel != "" {
		return actuator.ReasonParallelGroupUnavailable
	} else if !w.idx.shardShadow[poolKey(pod.Namespace, shard)] {
		return "no Ready warm shadow exists for a matching model-shard pool"
	}
	if pod.Labels[labelParallelGroup] == "" && (!pod.WarmPoolConfigured || !w.idx.scalarPoolShadows[poolKey(pod.Namespace, labelModelShard, shard, pod.WarmPoolOwnerUID, pod.RouteService)]) {
		return "scalar ReplicaSet warm-pool template/route configuration unverified"
	}
	if w.idx.schedulableGPU < 2 {
		return "fewer than 2 schedulable GPU nodes"
	}
	return ""
}

func (w Witness) servingServiceSelects(pod *model.Pod) bool {
	for _, svc := range w.idx.servingByNS[pod.Namespace] {
		if pod.RouteService != "" && svc.Name != pod.RouteService {
			continue
		}
		if _, ok := svc.Selector[labelServing]; !ok || !selectorMatches(svc.Selector, pod.Labels) {
			continue
		}
		return true
	}
	return false
}

func capabilityTarget(pod *model.Pod) bool {
	return pod != nil && pod.Labels[labelWarmRole] != warmShadowRole && pod.HasServingDeclaration()
}

func hasAllocatableGPU(node ingest.NodeInfo) bool {
	if node.AllocatableGPU > 0 {
		return true
	}
	for _, count := range node.MIGResources {
		if count > 0 {
			return true
		}
	}
	return false
}

func selectorMatches(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		actual, present := podLabels[key]
		if !present || actual != value {
			return false
		}
	}
	return true
}

func (w Witness) targetFrom(v *model.WorkloadView) actuator.Target {
	return actuator.Target{
		Namespace: v.Pod.Namespace, Pod: v.Pod.Name, UID: v.Pod.UID,
		Labels: v.Pod.Labels, NodeName: v.Pod.Node, HasGPU: v.Pod.HasGPU, MIGResource: v.Pod.MIGDevice,
		PolicyName: w.policyName, PolicyUID: w.policyUID, ServiceAccount: v.Pod.ServiceAccount,
	}
}
