/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 */

// Package codeexec is the RUNTIME admission-capability verifier for the two in-pod
// code-execution actions (debugger / custom-inject). It answers, fail-closed, one
// question the T1-E capability gate and the actuate boundary both ask:
//
//	"Is the ephemeral-container admission policy (the ValidatingAdmissionPolicy +
//	 Binding phorvex-codeexec-ephemeral) currently PRESENT, its ENTIRE enforcement content
//	 EQUAL to the trusted contract, Deny + failurePolicy:Fail, and does it cover THIS
//	 namespace RIGHT NOW?"
//
// RBAC-allowed is NOT admission-verified, and a matching name/annotation is NOT enforcement:
// a policy whose CEL was gutted (validations replaced by `true`, `newContainers` emptied, a
// match-condition that skips it, a wrong resource group, a binding that excludes the target)
// must be REJECTED. So the verifier compares the complete NORMALIZED spec of the live objects,
// field-for-field, against an embedded trusted contract (config/admission + the rendered chart
// are tested to equal it), tolerating only an explicit, justified set of API-defaulted fields.
// The API-server VAP remains the durable enforcement; this is the operator-side fail-closed gate.
//
// Verification discipline (the M-6 frozen contract §6):
//   - UNCACHED reads via GET-by-resourceName of the two named objects + an SSAR that the
//     minimal read grant is present, all under a single AGGREGATE deadline D.
//   - An independent TTL expiry (a quiet process never refreshes it — no watch).
//   - A process-local, atomically-published invalidationEpoch: ANY observed invalidation
//     — including a timeout or a partial read failure — increments it, and a verification
//     success republishes valid state ONLY if its captured startEpoch still equals the
//     current epoch at completion. A fresh verification after a timeout recovers.
//   - A final pre-submit check that re-verifies the policy AND reads the target namespace's
//     scope LIVE (uncached, by identity) within the aggregate deadline — never a stale label.
//
// Off by default and fail-closed: UNAVAILABLE until the first successful verification.
package codeexec

import (
	"context"
	_ "embed"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// Object identity + version the verifier checks (the installer-owned singleton).
const (
	// PolicyName is the resourceName of both the ValidatingAdmissionPolicy and its Binding.
	PolicyName = "phorvex-codeexec-ephemeral"
	// PolicyVersion is the value of the phorvex.ai/policy-version annotation (a cheap signal,
	// NOT the check — the full spec comparison is). A chart/policy change bumps it.
	PolicyVersion = "m6-1"
	// ManagedLabelKey/Val is the installer-set namespace label the Binding selects on.
	ManagedLabelKey = "phorvex.ai/codeexec-managed"
	ManagedLabelVal = "true"
)

const versionAnnotation = "phorvex.ai/policy-version"

// The §2 exact timing targets (L4 asserts against these; changing them requires a
// recorded contract amendment).
const (
	// DefaultDeadline (D) is the AGGREGATE deadline shared by all reads of one verification.
	DefaultDeadline = 2000 * time.Millisecond
	// DefaultTTL is the independent expiry of a successful verification.
	DefaultTTL = 30 * time.Second
	// DefaultPoll is the periodic re-verify cadence (a GET, not a watch).
	DefaultPoll = 10 * time.Second
)

// ReasonUnverified is the capability-gate / dispatch exclusion reason when code-exec
// admission is not currently verified for the target.
const ReasonUnverified = "codeexec-admission-unverified"

// PolicyReader is the injectable read surface: GET-by-resourceName of the two named objects
// (typed, so NOTHING security-relevant is projected away), an SSAR that the minimal read grant
// is present, and a LIVE namespace-label read for the pre-submit scope check. Every method MUST
// honor the ctx deadline (the aggregate D is applied by the verifier).
type PolicyReader interface {
	// GetPolicy GETs the ValidatingAdmissionPolicy PolicyName. A not-found object returns
	// (nil, nil) — only a read FAILURE returns a non-nil error.
	GetPolicy(ctx context.Context) (*admissionregistrationv1.ValidatingAdmissionPolicy, error)
	// GetBinding GETs the ValidatingAdmissionPolicyBinding PolicyName (same not-found rule).
	GetBinding(ctx context.Context) (*admissionregistrationv1.ValidatingAdmissionPolicyBinding, error)
	// CanRead is the SSAR confirming the operator may `get` both named objects — a positive
	// check the minimal read grant is installed. unknown=true means the SSAR itself errored.
	CanRead(ctx context.Context) (allowed, unknown bool, err error)
	// GetNamespaceLabels reads the CURRENT labels of a namespace (uncached) for the pre-submit
	// scope check. found=false means the namespace is absent (⇒ out of scope, fail-closed).
	GetNamespaceLabels(ctx context.Context, namespace string) (labels map[string]string, found bool, err error)
}

// --- the embedded trusted contract ------------------------------------------------------

//go:embed expected_vap.yaml
var expectedContractYAML []byte

var (
	expectedPolicyNorm  []byte            // normalized spec JSON of the trusted VAP
	expectedBindingNorm []byte            // normalized spec JSON of the trusted Binding
	expectedSelector    map[string]string // the trusted Binding namespaceSelector.matchLabels
)

// ExpectedPolicy / ExpectedBinding return fresh typed copies of the trusted contract (for
// tests that build fixtures from it). They are parsed once from the embedded YAML.
var expectedPolicy = &admissionregistrationv1.ValidatingAdmissionPolicy{}
var expectedBinding = &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}

func init() {
	p, b, err := ParseContract(expectedContractYAML)
	if err != nil {
		panic("codeexec: embedded trusted contract is unparseable: " + err.Error())
	}
	expectedPolicy, expectedBinding = p, b
	expectedPolicyNorm = normalizedPolicySpecJSON(p)
	expectedBindingNorm = normalizedBindingSpecJSON(b)
	if b.Spec.MatchResources != nil && b.Spec.MatchResources.NamespaceSelector != nil {
		expectedSelector = b.Spec.MatchResources.NamespaceSelector.MatchLabels
	}
	if len(expectedSelector) == 0 {
		panic("codeexec: embedded trusted contract has no namespaceSelector matchLabels")
	}
}

// ParseContract splits a two-document (policy---binding) YAML into the typed objects.
func ParseContract(raw []byte) (*admissionregistrationv1.ValidatingAdmissionPolicy, *admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	docs := splitYAMLDocs(raw)
	p := &admissionregistrationv1.ValidatingAdmissionPolicy{}
	b := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	if err := yaml.Unmarshal(docs.policy, p); err != nil {
		return nil, nil, err
	}
	if err := yaml.Unmarshal(docs.binding, b); err != nil {
		return nil, nil, err
	}
	return p, b, nil
}

// ExpectedContract returns fresh deep copies of the trusted policy + binding (for fixtures).
func ExpectedContract() (*admissionregistrationv1.ValidatingAdmissionPolicy, *admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
	return expectedPolicy.DeepCopy(), expectedBinding.DeepCopy()
}

// --- the verifier -----------------------------------------------------------------------

// verifiedState is the immutable published result of one successful verification.
type verifiedState struct {
	valid         bool
	at            time.Time
	epochAtVerify uint64
	selector      map[string]string
	detail        string
}

// Verifier is the process-local, atomically-invalidated admission-capability oracle.
type Verifier struct {
	reader   PolicyReader
	deadline time.Duration
	ttl      time.Duration
	poll     time.Duration
	now      func() time.Time

	epoch atomic.Uint64

	mu    sync.RWMutex
	state verifiedState
}

// Config carries the (all-optional) knobs; zero values fall back to the §2 defaults.
type Config struct {
	Deadline time.Duration
	TTL      time.Duration
	Poll     time.Duration
	Now      func() time.Time
}

// New builds a Verifier in the initial UNAVAILABLE state (fail-closed until first success).
func New(reader PolicyReader, cfg Config) *Verifier {
	v := &Verifier{
		reader:   reader,
		deadline: orDur(cfg.Deadline, DefaultDeadline),
		ttl:      orDur(cfg.TTL, DefaultTTL),
		poll:     orDur(cfg.Poll, DefaultPoll),
		now:      cfg.Now,
	}
	if v.now == nil {
		v.now = time.Now
	}
	v.state = verifiedState{valid: false, detail: "not yet verified"}
	return v
}

func orDur(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Invalidate records an observed invalidation: it increments the epoch (so any in-flight
// success started before now can no longer publish) and marks the published state invalid.
func (v *Verifier) Invalidate(reason string) {
	v.epoch.Add(1)
	v.mu.Lock()
	v.state.valid = false
	v.state.detail = reason
	v.mu.Unlock()
}

// Verify performs one uncached verification under the aggregate deadline D.
func (v *Verifier) Verify(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, v.deadline)
	defer cancel()
	return v.verifyUnder(dctx)
}

// verifyUnder runs one verification using ctx as the (already deadline-bounded) aggregate. On
// success it republishes valid state IFF no invalidation intervened; on any failure it invalidates.
func (v *Verifier) verifyUnder(ctx context.Context) error {
	startEpoch := v.epoch.Load()

	allowed, unknown, err := v.reader.CanRead(ctx)
	if err != nil || unknown {
		return v.fail("ssar-read-check failed (fail-closed)")
	}
	if !allowed {
		return v.fail("minimal read grant absent: operator cannot get the named admission objects")
	}
	policy, err := v.reader.GetPolicy(ctx)
	if err != nil {
		return v.fail("policy read failed (fail-closed): " + err.Error())
	}
	binding, err := v.reader.GetBinding(ctx)
	if err != nil {
		return v.fail("binding read failed (fail-closed): " + err.Error())
	}
	if why := validatePolicyContent(policy); why != "" {
		return v.fail("policy invalid: " + why)
	}
	if why := validateBindingContent(binding); why != "" {
		return v.fail("binding invalid: " + why)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.epoch.Load() != startEpoch {
		v.state.detail = "verification superseded by a concurrent invalidation; discarded"
		return context.Canceled
	}
	v.state = verifiedState{
		valid:         true,
		at:            v.now(),
		epochAtVerify: startEpoch,
		selector:      copyLabels(expectedSelector), // == the verified live selector
		detail:        "verified",
	}
	return nil
}

func (v *Verifier) fail(reason string) error {
	v.Invalidate(reason)
	return verifyError(reason)
}

type verifyError string

func (e verifyError) Error() string { return string(e) }

// globalReady reports whether a valid verification is currently unexpired AND epoch-matched.
func (v *Verifier) globalReady() (bool, string) {
	v.mu.RLock()
	st := v.state
	v.mu.RUnlock()
	if !st.valid {
		if st.detail == "" {
			return false, "not verified"
		}
		return false, st.detail
	}
	if v.now().Sub(st.at) >= v.ttl {
		return false, "verification expired (TTL)"
	}
	if st.epochAtVerify != v.epoch.Load() {
		return false, "verification invalidated"
	}
	return true, "verified"
}

// Available is the O(1) cached gate check for the pre-scoring capability gate: is admission
// verified AND does the verified Binding scope cover the target namespace? nsLabels are the
// tick snapshot's labels (best-effort, cheap; the authoritative live scope check is FinalCheck).
func (v *Verifier) Available(nsLabels map[string]string) (bool, string) {
	ready, why := v.globalReady()
	if !ready {
		return false, ReasonUnverified + ": " + why
	}
	v.mu.RLock()
	sel := v.state.selector
	v.mu.RUnlock()
	if !scopeMatch(sel, nsLabels) {
		return false, ReasonUnverified + ": target namespace not in the verified managed scope (C3)"
	}
	return true, ""
}

// FinalCheck is the pre-submit re-confirmation immediately before an irreversible inject. It
// carries the target namespace IDENTITY (not stale labels): it re-verifies the policy AND reads
// the namespace's CURRENT labels LIVE (uncached), all within one aggregate deadline D, then
// requires unexpired + epoch-matched verification + the live namespace in verified scope. A
// managed label removed since the tick is therefore caught here. ok=false carries ReasonUnverified.
func (v *Verifier) FinalCheck(ctx context.Context, namespace string) (bool, string) {
	dctx, cancel := context.WithTimeout(ctx, v.deadline)
	defer cancel()
	_ = v.verifyUnder(dctx) // fresh verify sharing the aggregate D; failure invalidates

	// Capture the verification TOKEN before the scope I/O.
	ready, why := v.globalReady()
	if !ready {
		return false, ReasonUnverified + ": " + why
	}
	v.mu.RLock()
	tokenEpoch := v.state.epochAtVerify
	tokenAt := v.state.at
	sel := v.state.selector
	v.mu.RUnlock()

	labels, found, err := v.reader.GetNamespaceLabels(dctx, namespace)
	if err != nil {
		// A partial read failure (incl. a deadline) is an observed invalidation: bump the epoch
		// so this and any concurrent gating decision fail closed, not just this call.
		v.Invalidate("live namespace scope read failed for " + namespace + ": " + err.Error())
		return false, ReasonUnverified + ": live namespace scope read failed for " + namespace + " (fail-closed): " + err.Error()
	}
	if !found {
		return false, ReasonUnverified + ": target namespace " + namespace + " not found (out of scope)"
	}

	// RE-CHECK the token AFTER the I/O: an invalidation observed DURING the namespace read (a
	// concurrent poll seeing the policy weakened), a TTL expiry, or a blown aggregate deadline
	// all void this submit. This is distinct from the accepted post-check last-moment race.
	if v.epoch.Load() != tokenEpoch {
		return false, ReasonUnverified + ": verification invalidated during the final scope read"
	}
	if v.now().Sub(tokenAt) >= v.ttl {
		return false, ReasonUnverified + ": verification expired during the final scope read (TTL)"
	}
	if dctx.Err() != nil {
		return false, ReasonUnverified + ": final check exceeded the aggregate deadline: " + dctx.Err().Error()
	}
	if !scopeMatch(sel, labels) {
		return false, ReasonUnverified + ": target namespace " + namespace + " not in the verified managed scope (C3)"
	}
	return true, ""
}

// Run drives the periodic re-verify loop (a GET every poll interval; no watch). Returns on ctx.
func (v *Verifier) Run(ctx context.Context) {
	_ = v.Verify(ctx)
	t := time.NewTicker(v.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = v.Verify(ctx)
		}
	}
}

// Status returns the current availability + detail for boot logs / degraded-status reporting.
func (v *Verifier) Status() (available bool, detail string) {
	return v.globalReady()
}

// --- content validation (full normalized spec vs the trusted contract) ------------------

// validatePolicyContent rejects a live VAP whose annotation, failurePolicy, or ANY normalized
// spec field differs from the trusted contract. The whole spec is compared, so an unexpected
// enforcement change (gutted CEL, emptied variable, added match-condition, wrong resource) is
// caught rather than silently projected away.
func validatePolicyContent(p *admissionregistrationv1.ValidatingAdmissionPolicy) string {
	if p == nil {
		return "ValidatingAdmissionPolicy " + PolicyName + " not found"
	}
	if p.Annotations[versionAnnotation] != PolicyVersion {
		return "phorvex.ai/policy-version annotation is not " + PolicyVersion
	}
	if p.Spec.FailurePolicy == nil || *p.Spec.FailurePolicy != admissionregistrationv1.Fail {
		return "failurePolicy is not Fail"
	}
	if !bytesEqual(normalizedPolicySpecJSON(p), expectedPolicyNorm) {
		return "policy enforcement content does not match the trusted contract (validations/variables/matchConstraints/matchConditions)"
	}
	return ""
}

// validateBindingContent rejects a live Binding whose normalized spec differs from the trusted
// contract — a wrong policyName, a missing Deny, added exclusions, an object selector, or a
// namespace selector (matchLabels OR matchExpressions) that narrows/skips the target.
func validateBindingContent(b *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	if b == nil {
		return "ValidatingAdmissionPolicyBinding " + PolicyName + " not found"
	}
	if b.Spec.PolicyName != PolicyName {
		return "binding.policyName does not reference " + PolicyName
	}
	if !hasDeny(b.Spec.ValidationActions) {
		return "validationActions does not contain Deny"
	}
	if !bytesEqual(normalizedBindingSpecJSON(b), expectedBindingNorm) {
		return "binding enforcement content does not match the trusted contract (validationActions/matchResources/selectors/exclusions)"
	}
	return ""
}

// normalizedPolicySpecJSON deep-copies the spec, FILLS the API-server defaults to their canonical
// values (rather than clearing them), and marshals deterministically. Filling — not clearing — is
// what lets the same canonical form come out of BOTH the raw committed manifest (defaults absent)
// AND the actual server-returned object (defaults populated: matchPolicy=Equivalent, empty
// namespace/object selectors, scope="*"), while a NON-default incompatible value (e.g. scope
// Cluster, or a real narrowing selector) is preserved and so mismatches the trusted contract.
// Every other field participates in the comparison, so nothing security-relevant is dropped.
func normalizedPolicySpecJSON(p *admissionregistrationv1.ValidatingAdmissionPolicy) []byte {
	spec := p.Spec.DeepCopy()
	if spec.MatchConstraints != nil {
		spec.MatchConstraints.MatchPolicy = fillMatchPolicy(spec.MatchConstraints.MatchPolicy)
		spec.MatchConstraints.NamespaceSelector = fillSelector(spec.MatchConstraints.NamespaceSelector)
		spec.MatchConstraints.ObjectSelector = fillSelector(spec.MatchConstraints.ObjectSelector)
		for i := range spec.MatchConstraints.ResourceRules {
			if spec.MatchConstraints.ResourceRules[i].Scope == nil {
				all := admissionregistrationv1.AllScopes // "*" — the server default; a real Cluster/Namespaced stays as-is
				spec.MatchConstraints.ResourceRules[i].Scope = &all
			}
		}
	}
	out, _ := json.Marshal(spec)
	return out
}

func normalizedBindingSpecJSON(b *admissionregistrationv1.ValidatingAdmissionPolicyBinding) []byte {
	spec := b.Spec.DeepCopy()
	if spec.MatchResources != nil {
		spec.MatchResources.MatchPolicy = fillMatchPolicy(spec.MatchResources.MatchPolicy)
		spec.MatchResources.NamespaceSelector = fillSelector(spec.MatchResources.NamespaceSelector)
		spec.MatchResources.ObjectSelector = fillSelector(spec.MatchResources.ObjectSelector)
	}
	out, _ := json.Marshal(spec)
	return out
}

// fillMatchPolicy returns Equivalent (the server default) when unset, else the explicit value.
func fillMatchPolicy(mp *admissionregistrationv1.MatchPolicyType) *admissionregistrationv1.MatchPolicyType {
	if mp == nil {
		eq := admissionregistrationv1.Equivalent
		return &eq
	}
	return mp
}

// fillSelector returns an empty (match-everything) selector when unset — the server default —
// so an absent selector and a server-populated empty selector canonicalize identically. A
// non-empty selector (matchLabels or matchExpressions) is left intact, so a narrowing selector
// still differs from the trusted contract.
func fillSelector(s *metav1.LabelSelector) *metav1.LabelSelector {
	if s == nil {
		return &metav1.LabelSelector{}
	}
	return s
}

func hasDeny(actions []admissionregistrationv1.ValidationAction) bool {
	for _, a := range actions {
		if a == admissionregistrationv1.Deny {
			return true
		}
	}
	return false
}

// scopeMatch reports whether nsLabels satisfy the verified Binding selector (every selector
// label present with the same value). An empty selector never matches (fail-closed).
func scopeMatch(selector, nsLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, val := range selector {
		if nsLabels[k] != val {
			return false
		}
	}
	return true
}

func copyLabels(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type yamlDocs struct{ policy, binding []byte }

// splitYAMLDocs splits a "policy\n---\nbinding" document pair. It splits on a line that is
// exactly "---" so the "---" inside folded scalars/comments is never a separator.
func splitYAMLDocs(raw []byte) yamlDocs {
	lines := splitLines(raw)
	var cur []byte
	var docs [][]byte
	for _, ln := range lines {
		if string(ln) == "---" {
			docs = append(docs, cur)
			cur = nil
			continue
		}
		cur = append(cur, ln...)
		cur = append(cur, '\n')
	}
	docs = append(docs, cur)
	// Keep the two non-empty documents (skip a possible empty leading/trailing doc).
	var nonEmpty [][]byte
	for _, d := range docs {
		if len(trimSpace(d)) > 0 {
			nonEmpty = append(nonEmpty, d)
		}
	}
	out := yamlDocs{}
	if len(nonEmpty) > 0 {
		out.policy = nonEmpty[0]
	}
	if len(nonEmpty) > 1 {
		out.binding = nonEmpty[1]
	}
	return out
}

func splitLines(raw []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' {
			lines = append(lines, raw[start:i])
			start = i + 1
		}
	}
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\n' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}
