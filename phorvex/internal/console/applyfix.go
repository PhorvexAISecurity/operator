/*
 * Phorvex — P-VCLUSTER Pass 2: the SAFE apply-fix write-path. Allowlisted policy-delta ONLY (no
 * free-form YAML), server-side gate-checked (PolicySafetyGate), TWO-KEY (a distinct verified approver),
 * applied via the per-namespace SA, fully audited. This unblocks the [PENDING-P-VCLUSTER] dashboard
 * apply-fix — safely.
 *
 * SECURITY (premortem-driven): EnabledActions is DELIBERATELY NOT in the allowlist — a tenant can never
 * enable an RCE action (debugger/custom-inject) via apply-fix; the gate re-runs on the exact immutable
 * candidate at approval; the tenant/namespace come from the verified identity, never the request body.
 *
 * LIFECYCLE (M-166): a request is an IMMUTABLE record keyed by tenant + caller id and stamped with a
 * server-issued generation that embeds this manager instance's unpredictable identity. Approval names
 * that exact generation. The pending -> applying claim is taken under the manager lock by exactly ONE
 * approver, the external callbacks run OUTSIDE the lock, and the attempt ends in one explicit terminal
 * state (applied / failed / rejected / stale) that is never reopened. An identical approval replay
 * returns the retained outcome without invoking the applier again. A nil applier is reported as
 * "nothing applied", never as applied.
 *
 * SCOPE OF THE GUARANTEE: the request store is this process's memory. It is not a durable or
 * replicated ledger — after a restart every old generation is refused and a resubmission needs a fresh
 * approval — and a returned nil from the applier is the callback's acceptance by its own contract, not
 * a proof of what the cluster holds. One attempt per generation is what this manager guarantees; a
 * physical exactly-once cluster write is not something it can promise.
 */

package console

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// ApplyFixDelta is the ALLOWLISTED, bounded set of policy parameters apply-fix may change. Pointers ⇒
// only SET fields are applied (a partial delta). NOTE the absence of EnabledActions / any action set.
type ApplyFixDelta struct {
	NormSparsity      *float64 `json:"normSparsity,omitempty"`
	FlowDisruption    *float64 `json:"flowDisruption,omitempty"`
	MaxMovesPerTick   *int     `json:"maxMovesPerTick,omitempty"`
	ProactiveFloorSec *int     `json:"proactiveFloorSec,omitempty"`
}

// The safe envelope (named bounds, not magic-in-code — a reviewer sees the allowed range).
const (
	afMinNormSparsity, afMaxNormSparsity     = 0.1, 10.0
	afMinFlowDisruption, afMaxFlowDisruption = 0.1, 10.0
	afMinMaxMoves, afMaxMaxMoves             = 1, 50
	afMinFloorSec, afMaxFloorSec             = 60, 24 * 3600
)

func (d ApplyFixDelta) validate() error {
	any := false
	if d.NormSparsity != nil {
		any = true
		if *d.NormSparsity < afMinNormSparsity || *d.NormSparsity > afMaxNormSparsity {
			return fmt.Errorf("normSparsity %.3f out of [%.1f,%.1f]", *d.NormSparsity, afMinNormSparsity, afMaxNormSparsity)
		}
	}
	if d.FlowDisruption != nil {
		any = true
		if *d.FlowDisruption < afMinFlowDisruption || *d.FlowDisruption > afMaxFlowDisruption {
			return fmt.Errorf("flowDisruption %.3f out of [%.1f,%.1f]", *d.FlowDisruption, afMinFlowDisruption, afMaxFlowDisruption)
		}
	}
	if d.MaxMovesPerTick != nil {
		any = true
		if *d.MaxMovesPerTick < afMinMaxMoves || *d.MaxMovesPerTick > afMaxMaxMoves {
			return fmt.Errorf("maxMovesPerTick %d out of [%d,%d]", *d.MaxMovesPerTick, afMinMaxMoves, afMaxMaxMoves)
		}
	}
	if d.ProactiveFloorSec != nil {
		any = true
		if *d.ProactiveFloorSec < afMinFloorSec || *d.ProactiveFloorSec > afMaxFloorSec {
			return fmt.Errorf("proactiveFloorSec %d out of [%d,%d]", *d.ProactiveFloorSec, afMinFloorSec, afMaxFloorSec)
		}
	}
	if !any {
		return fmt.Errorf("empty delta (no allowlisted field set)")
	}
	return nil
}

func (d ApplyFixDelta) applyTo(base model.Policy) model.Policy {
	p := base
	if d.NormSparsity != nil {
		p.NormSparsity = *d.NormSparsity
	}
	if d.FlowDisruption != nil {
		p.FlowDisruption = *d.FlowDisruption
	}
	if d.MaxMovesPerTick != nil {
		p.MaxMovesPerTick = *d.MaxMovesPerTick
	}
	if d.ProactiveFloorSec != nil {
		p.ProactiveFloor = time.Duration(*d.ProactiveFloorSec) * time.Second
	}
	return p
}

// clone copies every SET value behind its pointer, so a caller that keeps mutating its own delta
// after Submit cannot change the staged snapshot or its hash.
func (d ApplyFixDelta) clone() ApplyFixDelta {
	c := ApplyFixDelta{}
	if d.NormSparsity != nil {
		v := *d.NormSparsity
		c.NormSparsity = &v
	}
	if d.FlowDisruption != nil {
		v := *d.FlowDisruption
		c.FlowDisruption = &v
	}
	if d.MaxMovesPerTick != nil {
		v := *d.MaxMovesPerTick
		c.MaxMovesPerTick = &v
	}
	if d.ProactiveFloorSec != nil {
		v := *d.ProactiveFloorSec
		c.ProactiveFloorSec = &v
	}
	return c
}

// equal compares by VALUE (a nil field only equals a nil field).
func (d ApplyFixDelta) equal(o ApplyFixDelta) bool {
	eqF := func(a, b *float64) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
	eqI := func(a, b *int) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
	return eqF(d.NormSparsity, o.NormSparsity) && eqF(d.FlowDisruption, o.FlowDisruption) &&
		eqI(d.MaxMovesPerTick, o.MaxMovesPerTick) && eqI(d.ProactiveFloorSec, o.ProactiveFloorSec)
}

func hashDelta(d ApplyFixDelta) string {
	b, _ := json.Marshal(d)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// clonePolicyData copies the candidate's mutable map fields, so neither the tenant's BasePol source
// nor an applier that receives the candidate can reach into the approved snapshot.
func clonePolicyData(p model.Policy) model.Policy {
	p.DecisionAssets = maps.Clone(p.DecisionAssets)
	p.KillChainSojournScaleSeconds = maps.Clone(p.KillChainSojournScaleSeconds)
	p.EnabledActions = maps.Clone(p.EnabledActions)
	return p
}

// policyFingerprint digests EVERY data field of a candidate (maps included, in key order; the one
// func-typed hook is not data). The approval-time stale-base check compares the whole candidate the
// gate saw and the applier would write — not a hand-picked subset that silently drifts as Policy grows.
func policyFingerprint(p model.Policy) string {
	v := reflect.ValueOf(p)
	h := sha256.New()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Func || !f.CanInterface() {
			continue
		}
		fmt.Fprintf(h, "%s=%#v;", v.Type().Field(i).Name, f.Interface())
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ApplyFixRequest — the tenant/namespace/requester come from the VERIFIED identity, never the body.
type ApplyFixRequest struct {
	ID        string
	Tenant    string
	Namespace string
	Delta     ApplyFixDelta
	Reason    string
	Requester string // verified subject
}

// sameContent is the idempotency test for a repeated submit: identical fixed fields => the earlier
// record is returned; anything else is a conflict, never an overwrite.
func (r ApplyFixRequest) sameContent(o ApplyFixRequest) bool {
	return r.ID == o.ID && r.Tenant == o.Tenant && r.Namespace == o.Namespace &&
		r.Requester == o.Requester && r.Reason == o.Reason && r.Delta.equal(o.Delta)
}

// Applier performs the actual cluster write (patch the tenant's PhorvexPolicy via the PER-NAMESPACE SA).
// Injectable: nil means NO write-path is wired (an approval then reports "nothing applied"); production
// wires the namespaced CRD patch.
type Applier func(tenant, namespace string, candidate model.Policy) error

// ApplyFixState is a request's lifecycle position. pending and applying are open; the rest are
// terminal and are never reopened for the same generation.
type ApplyFixState string

const (
	ApplyFixPending  ApplyFixState = "pending"  // awaiting a distinct approver
	ApplyFixApplying ApplyFixState = "applying" // claimed by exactly one approver; callbacks in flight
	ApplyFixApplied  ApplyFixState = "applied"  // the applier accepted the candidate once
	ApplyFixFailed   ApplyFixState = "failed"   // the applier errored or panicked; its effect is UNKNOWN
	ApplyFixRejected ApplyFixState = "rejected" // the gate refused the immutable candidate at approval
	ApplyFixStale    ApplyFixState = "stale"    // the tenant's base policy moved; the candidate no longer derives from it
)

func (s ApplyFixState) terminal() bool { return s != ApplyFixPending && s != ApplyFixApplying }

// Sentinel errors the HTTP layer maps to explicit statuses. All are wrapped with %w.
var (
	ErrApplyFixNotFound    = errors.New("apply-fix: no such request for this tenant")
	ErrApplyFixGeneration  = errors.New("apply-fix: generation does not match this request (stale, foreign, or from a previous console instance)")
	ErrApplyFixConflict    = errors.New("apply-fix: request id already exists for this tenant with different content")
	ErrApplyFixCapacity    = errors.New("apply-fix: request store at capacity; refusing a new request")
	ErrApplyFixTwoKey      = errors.New("apply-fix TWO-KEY VIOLATION: approver must differ from the requester")
	ErrApplyFixInProgress  = errors.New("apply-fix: an apply attempt by another approval is already in progress")
	ErrApplyFixTerminal    = errors.New("apply-fix: request already reached a terminal outcome")
	ErrApplyFixNoApplier   = errors.New("apply-fix: no applier is wired in this deployment (record-only); nothing was applied")
	ErrApplyFixGateRefused = errors.New("apply-fix re-check FAILED at approval; nothing was applied")
	ErrApplyFixStaleBase   = errors.New("apply-fix: the tenant's base policy changed since submit; the candidate is stale and was not applied")
	ErrApplyFixApplyFailed = errors.New("apply-fix apply (per-namespace SA) FAILED; the cluster effect is unknown — reconcile before submitting again")
)

// DefaultMaxApplyFixRecords bounds the per-process request store. Terminal records are kept as
// tombstones (so an id cannot be reused for different content), so the bound covers them too.
const DefaultMaxApplyFixRecords = 1000

// ApplyFixManager runs the safe submit→approve→apply lifecycle.
type ApplyFixManager struct {
	mu       sync.Mutex
	records  map[applyKey]*applyRecord
	instance string // unpredictable per-process identity embedded in every generation
	seq      uint64
	trail    []AuditEntry                     // bounded in-memory audit ring (the UI reads it; external Audit still fires)
	BasePol  func(tenant string) model.Policy // the tenant's current base policy
	Gate     func(candidate model.Policy) error
	Apply    Applier
	Audit    func(event string, fields map[string]any)
	// ApplierMode is the label the UI shows: "record-only" until a deployment wires the production
	// namespaced-CRD-patch Applier (then "live"). It is a LABEL: whether an approval applies anything
	// is decided by Apply being non-nil, never by this string.
	ApplierMode string
	// MaxRecords is the finite size of the request store (open + terminal). A NEW tenant/id at the
	// limit fails closed with ErrApplyFixCapacity; nothing is evicted to make room.
	MaxRecords int
}

type applyKey struct{ tenant, id string }

// applyRecord is immutable after Submit except for the lifecycle fields guarded by ApplyFixManager.mu.
type applyRecord struct {
	req         ApplyFixRequest // delta already cloned
	generation  string
	candidate   model.Policy // snapshot the gate approved (maps cloned)
	fingerprint string       // policyFingerprint(candidate) for the stale-base check
	seq         uint64
	state       ApplyFixState
	approver    string // the ONE approver that claimed the attempt
	detail      string // sanitized terminal detail, stable across retries
}

const auditRingMax = 500

// PendingInfo is the UI-safe view of an open submission (no policy internals). Generation is what an
// approval must echo back; State tells the UI whether an attempt is already in flight.
type PendingInfo struct {
	ID         string        `json:"id"`
	Tenant     string        `json:"tenant"`
	Namespace  string        `json:"namespace"`
	Requester  string        `json:"requester"`
	Reason     string        `json:"reason"`
	DeltaHash  string        `json:"deltaHash"`
	Generation string        `json:"generation"`
	State      ApplyFixState `json:"state"`
	Approver   string        `json:"approver,omitempty"` // set while applying
}

// AuditEntry is one recorded apply-fix lifecycle event (UI-safe).
type AuditEntry struct {
	Event  string         `json:"event"`
	Fields map[string]any `json:"fields"`
}

// SubmitResult is what a submit resolved to: a new record, or (Existing) the identical earlier one.
type SubmitResult struct {
	ID         string
	Tenant     string
	Generation string
	State      ApplyFixState
	Existing   bool
}

// ApproveResult is the outcome of ONE approval call. State is the record's lifecycle state after the
// call; Retry reports that an identical earlier approval's retained outcome was returned and the
// applier was NOT invoked again.
type ApproveResult struct {
	ID         string
	Tenant     string
	Generation string
	Approver   string
	State      ApplyFixState
	Retry      bool
	Detail     string
}

// Pending returns the OPEN submissions (pending or applying) in submission order, tenant-filtered.
func (m *ApplyFixManager) Pending(tenant string) []PendingInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := make([]*applyRecord, 0, len(m.records))
	for _, r := range m.records {
		if r.state.terminal() || (tenant != "" && r.req.Tenant != tenant) {
			continue
		}
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].seq < recs[j].seq })
	out := make([]PendingInfo, 0, len(recs))
	for _, r := range recs {
		out = append(out, PendingInfo{ID: r.req.ID, Tenant: r.req.Tenant, Namespace: r.req.Namespace, Requester: r.req.Requester,
			Reason: r.req.Reason, DeltaHash: hashDelta(r.req.Delta), Generation: r.generation, State: r.state, Approver: r.approver})
	}
	return out
}

// AuditTrail returns the recent apply-fix lifecycle events, tenant-filtered (newest last). Field maps
// are copies: the caller cannot reach the ring.
func (m *ApplyFixManager) AuditTrail(tenant string) []AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []AuditEntry{}
	for _, e := range m.trail {
		if tenant != "" {
			if t, _ := e.Fields["tenant"].(string); t != tenant {
				continue
			}
		}
		out = append(out, AuditEntry{Event: e.Event, Fields: maps.Clone(e.Fields)})
	}
	return out
}

func NewApplyFixManager(base func(string) model.Policy, apply Applier, audit func(string, map[string]any)) *ApplyFixManager {
	if base == nil {
		base = func(string) model.Policy {
			return model.Policy{NormSparsity: 1, FlowDisruption: 1, MaxMovesPerTick: 2, ProactiveFloor: 2 * time.Hour}
		}
	}
	var inst [8]byte
	_, _ = rand.Read(inst[:]) // never fails on Go ≥ 1.24 (it aborts the process instead)
	return &ApplyFixManager{records: map[applyKey]*applyRecord{}, instance: hex.EncodeToString(inst[:]),
		BasePol: base, Gate: PolicySafetyGate, Apply: apply, Audit: audit, ApplierMode: "record-only", MaxRecords: DefaultMaxApplyFixRecords}
}

// emit appends to the ring and fires the external Audit hook. It takes the manager lock itself, so
// callers must NOT hold it.
func (m *ApplyFixManager) emit(event string, req ApplyFixRequest, extra map[string]any) {
	f := map[string]any{"id": req.ID, "tenant": req.Tenant, "namespace": req.Namespace, "requester": req.Requester, "deltaHash": hashDelta(req.Delta), "reason": req.Reason}
	for k, v := range extra {
		f[k] = v
	}
	// bounded in-memory ring for the UI audit trail.
	m.mu.Lock()
	m.trail = append(m.trail, AuditEntry{Event: event, Fields: f})
	if len(m.trail) > auditRingMax {
		m.trail = m.trail[len(m.trail)-auditRingMax:]
	}
	m.mu.Unlock()
	if m.Audit != nil {
		m.Audit(event, maps.Clone(f))
	}
}

// GatePreview runs the allowlist + the server-side safety gate on a candidate WITHOUT staging or
// applying it — so the UI can show "will this pass 1.62×/P3/no-harm?" before the tenant commits to a
// submit. Read-only; uses the same proven PolicySafetyGate.
func (m *ApplyFixManager) GatePreview(tenant string, delta ApplyFixDelta) (bool, string) {
	if err := delta.validate(); err != nil {
		return false, "allowlist: " + err.Error()
	}
	if err := m.Gate(delta.applyTo(m.BasePol(tenant))); err != nil {
		return false, err.Error()
	}
	return true, "passes the safety gate (efficacy 1.62×, proactivity P3, no-harm)"
}

// Submit validates the allowlist + bounds, runs the server-side gate-check, and stores an IMMUTABLE
// record keyed by tenant + id under a fresh generation, PENDING a distinct approver. A delta that
// fails the allowlist or the gate is REJECTED here. A repeat of an identical submission returns the
// existing record; a same-id submission with different content is a conflict (nothing is overwritten,
// and a terminal record is never recycled).
func (m *ApplyFixManager) Submit(req ApplyFixRequest) (SubmitResult, error) {
	if req.Tenant == "" || req.Requester == "" || req.ID == "" {
		return SubmitResult{}, fmt.Errorf("apply-fix: missing verified identity / id")
	}
	req.Delta = req.Delta.clone() // detach from the caller's pointers before anything reads them twice
	if err := req.Delta.validate(); err != nil {
		m.emit("apply-fix.rejected.allowlist", req, map[string]any{"error": err.Error()})
		return SubmitResult{}, fmt.Errorf("apply-fix allowlist: %w", err)
	}
	candidate := clonePolicyData(req.Delta.applyTo(m.BasePol(req.Tenant)))
	if err := m.Gate(candidate); err != nil {
		m.emit("apply-fix.rejected.gate", req, map[string]any{"error": err.Error()})
		return SubmitResult{}, fmt.Errorf("apply-fix REJECTED by safety gate: %w", err)
	}
	key := applyKey{req.Tenant, req.ID}
	m.mu.Lock()
	if existing := m.records[key]; existing != nil {
		res := SubmitResult{ID: req.ID, Tenant: req.Tenant, Generation: existing.generation, State: existing.state, Existing: true}
		same := existing.req.sameContent(req)
		m.mu.Unlock()
		if same {
			return res, nil
		}
		m.emit("apply-fix.rejected.conflict", req, map[string]any{"existingGeneration": existing.generation, "existingState": string(existing.state)})
		return SubmitResult{}, fmt.Errorf("%w: id %q (generation %s, %s)", ErrApplyFixConflict, req.ID, existing.generation, existing.state)
	}
	limit := m.MaxRecords
	if limit <= 0 {
		limit = DefaultMaxApplyFixRecords
	}
	if len(m.records) >= limit {
		m.mu.Unlock()
		m.emit("apply-fix.rejected.capacity", req, map[string]any{"limit": limit})
		return SubmitResult{}, fmt.Errorf("%w (limit %d)", ErrApplyFixCapacity, limit)
	}
	m.seq++
	rec := &applyRecord{req: req, generation: fmt.Sprintf("%s-%d", m.instance, m.seq), candidate: candidate,
		fingerprint: policyFingerprint(candidate), seq: m.seq, state: ApplyFixPending}
	m.records[key] = rec
	m.mu.Unlock()
	m.emit("apply-fix.submitted", req, map[string]any{"generation": rec.generation})
	return SubmitResult{ID: req.ID, Tenant: req.Tenant, Generation: rec.generation, State: ApplyFixPending}, nil
}

// Approve is ONE apply attempt for the exact tenant/id/generation, by a DISTINCT verified approver
// (two-key). Under the lock it either claims pending -> applying or refuses (unknown, wrong generation,
// in progress, already terminal, same principal). With the claim held it re-checks that the tenant's
// base has not moved, re-runs the gate on the exact immutable candidate, invokes the applier ONCE
// outside the lock, and records the terminal outcome. Same-principal approval is REFUSED. An
// identical approval replay returns the retained outcome and does not touch the applier.
func (m *ApplyFixManager) Approve(tenant, requestID, generation, approver string) (ApproveResult, error) {
	if approver == "" {
		return ApproveResult{}, fmt.Errorf("apply-fix: approver identity required")
	}
	if tenant == "" || requestID == "" || generation == "" {
		return ApproveResult{}, fmt.Errorf("apply-fix: tenant, id and generation are required")
	}
	m.mu.Lock()
	rec := m.records[applyKey{tenant, requestID}]
	if rec == nil {
		m.mu.Unlock()
		return ApproveResult{ID: requestID, Tenant: tenant, Generation: generation, Approver: approver}, fmt.Errorf("%w: %q", ErrApplyFixNotFound, requestID)
	}
	res := ApproveResult{ID: requestID, Tenant: tenant, Generation: rec.generation, Approver: rec.approver, State: rec.state, Detail: rec.detail}
	if rec.generation != generation {
		m.mu.Unlock()
		res.Generation, res.Approver = generation, approver
		return res, fmt.Errorf("%w: %q", ErrApplyFixGeneration, generation)
	}
	switch {
	case rec.state == ApplyFixApplying:
		m.mu.Unlock()
		return res, ErrApplyFixInProgress
	case rec.state.terminal():
		m.mu.Unlock()
		if rec.approver == approver {
			res.Retry = true
			return res, terminalError(rec.state, rec.detail)
		}
		return res, fmt.Errorf("%w: %s by %q", ErrApplyFixTerminal, rec.state, rec.approver)
	}
	if approver == rec.req.Requester {
		m.mu.Unlock()
		m.emit("apply-fix.rejected.twokey", rec.req, map[string]any{"approver": approver, "generation": rec.generation})
		res.Approver = approver
		return res, fmt.Errorf("%w (%q)", ErrApplyFixTwoKey, approver)
	}
	if m.Apply == nil {
		// Nothing is wired to apply: refuse BEFORE claiming, so the request stays pending and is
		// never reported as applied because of a label.
		m.mu.Unlock()
		m.emit("apply-fix.apply.unavailable", rec.req, map[string]any{"approver": approver, "generation": rec.generation, "applierMode": m.ApplierMode})
		res.Approver = approver
		return res, ErrApplyFixNoApplier
	}
	// The claim: exactly one approver moves pending -> applying. Everything below runs unlocked.
	rec.state, rec.approver = ApplyFixApplying, approver
	req, candidate, fingerprint := rec.req, clonePolicyData(rec.candidate), rec.fingerprint
	m.mu.Unlock()
	res.Approver, res.State = approver, ApplyFixApplying
	m.emit("apply-fix.applying", req, map[string]any{"approver": approver, "generation": rec.generation})

	// Stale-base check: the approved snapshot must still be what the delta derives from the tenant's
	// CURRENT base. If the base moved, applying the snapshot would write fields nobody approved.
	if policyFingerprint(clonePolicyData(req.Delta.applyTo(m.BasePol(req.Tenant)))) != fingerprint {
		return m.finish(rec, res, ApplyFixStale, "base policy changed since submit", "apply-fix.rejected.stale")
	}
	// Re-check the gate on the EXACT immutable candidate, immediately before the write.
	if err := m.Gate(candidate); err != nil {
		return m.finish(rec, res, ApplyFixRejected, err.Error(), "apply-fix.rejected.gate")
	}
	if err := m.invokeApply(req.Tenant, req.Namespace, candidate); err != nil {
		return m.finish(rec, res, ApplyFixFailed, err.Error(), "apply-fix.apply.error")
	}
	return m.finish(rec, res, ApplyFixApplied, "", "apply-fix.applied")
}

// invokeApply runs the external callback with a recovery scoped to that boundary only: a panicking
// applier becomes a terminal failure with an unknown effect, never a reopened attempt.
func (m *ApplyFixManager) invokeApply(tenant, namespace string, candidate model.Policy) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("applier panicked: %v", r)
		}
	}()
	return m.Apply(tenant, namespace, candidate)
}

// finish records the ONE terminal outcome of a claimed attempt and audits it.
func (m *ApplyFixManager) finish(rec *applyRecord, res ApproveResult, state ApplyFixState, detail, event string) (ApproveResult, error) {
	m.mu.Lock()
	rec.state, rec.detail = state, detail
	m.mu.Unlock()
	res.State, res.Detail = state, detail
	extra := map[string]any{"approver": res.Approver, "generation": rec.generation}
	if detail != "" {
		extra["error"] = detail
	}
	m.emit(event, rec.req, extra)
	return res, terminalError(state, detail)
}

// terminalError maps a terminal state to its sentinel (nil for applied), so a replay reports the same
// error kind as the original attempt.
func terminalError(state ApplyFixState, detail string) error {
	switch state {
	case ApplyFixApplied:
		return nil
	case ApplyFixFailed:
		return fmt.Errorf("%w: %s", ErrApplyFixApplyFailed, detail)
	case ApplyFixRejected:
		return fmt.Errorf("%w: %s", ErrApplyFixGateRefused, detail)
	case ApplyFixStale:
		return fmt.Errorf("%w: %s", ErrApplyFixStaleBase, detail)
	}
	return fmt.Errorf("apply-fix: unexpected terminal state %q", state)
}
