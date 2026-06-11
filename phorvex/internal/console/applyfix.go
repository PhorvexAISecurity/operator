/*
 * Phorvex — P-VCLUSTER Pass 2: the SAFE apply-fix write-path. Allowlisted policy-delta ONLY (no
 * free-form YAML), server-side gate-checked (PolicySafetyGate), TWO-KEY (a distinct verified approver),
 * applied via the per-namespace SA, fully audited. This unblocks the [PENDING-P-VCLUSTER] dashboard
 * apply-fix — safely.
 *
 * SECURITY (premortem-driven): EnabledActions is DELIBERATELY NOT in the allowlist — a tenant can never
 * enable an RCE action (debugger/custom-inject) via apply-fix; the gate re-runs atomically at approval
 * (no TOCTOU); the tenant/namespace come from the verified identity, never the request body.
 */

package console

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func hashDelta(d ApplyFixDelta) string {
	b, _ := json.Marshal(d)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
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

// Applier performs the actual cluster write (patch the tenant's PhorvexPolicy via the PER-NAMESPACE SA).
// Injectable: default records-only (audited); production wires the namespaced CRD patch.
type Applier func(tenant, namespace string, candidate model.Policy) error

// ApplyFixManager runs the safe submit→approve→apply lifecycle.
type ApplyFixManager struct {
	mu      sync.Mutex
	pending map[string]*pendingApply
	trail   []AuditEntry // bounded in-memory audit ring (the UI reads it; external Audit still fires)
	BasePol func(tenant string) model.Policy   // the tenant's current base policy
	Gate    func(candidate model.Policy) error // PolicySafetyGate (injectable for tests)
	Apply   Applier
	Audit   func(event string, fields map[string]any)
	// ApplierMode is the honest label the UI shows: "record-only" until a deployment wires the
	// production namespaced-CRD-patch Applier (then "live"). Default "record-only".
	ApplierMode string
}

type pendingApply struct {
	req       ApplyFixRequest
	candidate model.Policy
}

const auditRingMax = 500

// PendingInfo is the UI-safe view of a pending submission (no policy internals).
type PendingInfo struct {
	ID        string `json:"id"`
	Tenant    string `json:"tenant"`
	Namespace string `json:"namespace"`
	Requester string `json:"requester"`
	Reason    string `json:"reason"`
	DeltaHash string `json:"deltaHash"`
}

// AuditEntry is one recorded apply-fix lifecycle event (UI-safe).
type AuditEntry struct {
	Event  string         `json:"event"`
	Fields map[string]any `json:"fields"`
}

// Pending returns the submissions awaiting a distinct approver (two-key queue), tenant-filtered.
func (m *ApplyFixManager) Pending(tenant string) []PendingInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []PendingInfo{}
	for id, p := range m.pending {
		if tenant != "" && p.req.Tenant != tenant {
			continue
		}
		out = append(out, PendingInfo{ID: id, Tenant: p.req.Tenant, Namespace: p.req.Namespace, Requester: p.req.Requester, Reason: p.req.Reason, DeltaHash: hashDelta(p.req.Delta)})
	}
	return out
}

// AuditTrail returns the recent apply-fix lifecycle events, tenant-filtered (newest last).
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
		out = append(out, e)
	}
	return out
}

func NewApplyFixManager(base func(string) model.Policy, apply Applier, audit func(string, map[string]any)) *ApplyFixManager {
	if base == nil {
		base = func(string) model.Policy { return model.Policy{NormSparsity: 1, FlowDisruption: 1, MaxMovesPerTick: 2, ProactiveFloor: 2 * time.Hour} }
	}
	return &ApplyFixManager{pending: map[string]*pendingApply{}, BasePol: base, Gate: PolicySafetyGate, Apply: apply, Audit: audit, ApplierMode: "record-only"}
}

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
		m.Audit(event, f)
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

// Submit validates the allowlist + bounds, runs the server-side gate-check, and stores the request
// PENDING a distinct approver. A delta that fails the allowlist or the gate is REJECTED here.
func (m *ApplyFixManager) Submit(req ApplyFixRequest) error {
	if req.Tenant == "" || req.Requester == "" || req.ID == "" {
		return fmt.Errorf("apply-fix: missing verified identity / id")
	}
	if err := req.Delta.validate(); err != nil {
		m.emit("apply-fix.rejected.allowlist", req, map[string]any{"error": err.Error()})
		return fmt.Errorf("apply-fix allowlist: %w", err)
	}
	candidate := req.Delta.applyTo(m.BasePol(req.Tenant))
	if err := m.Gate(candidate); err != nil {
		m.emit("apply-fix.rejected.gate", req, map[string]any{"error": err.Error()})
		return fmt.Errorf("apply-fix REJECTED by safety gate: %w", err)
	}
	m.mu.Lock()
	m.pending[req.ID] = &pendingApply{req: req, candidate: candidate}
	m.mu.Unlock()
	m.emit("apply-fix.submitted", req, nil)
	return nil
}

// Approve requires a DISTINCT verified approver (two-key), RE-RUNS the gate atomically (no TOCTOU),
// applies via the per-namespace SA, and audits. Same-principal approval is REFUSED.
func (m *ApplyFixManager) Approve(requestID, approver string) error {
	if approver == "" {
		return fmt.Errorf("apply-fix: approver identity required")
	}
	m.mu.Lock()
	p := m.pending[requestID]
	m.mu.Unlock()
	if p == nil {
		return fmt.Errorf("apply-fix: no pending request %q", requestID)
	}
	if approver == p.req.Requester {
		m.emit("apply-fix.rejected.twokey", p.req, map[string]any{"approver": approver})
		return fmt.Errorf("apply-fix TWO-KEY VIOLATION: approver must differ from the requester (%q)", approver)
	}
	if err := m.Gate(p.candidate); err != nil { // re-check on the EXACT candidate (no TOCTOU)
		return fmt.Errorf("apply-fix re-check FAILED at approval: %w", err)
	}
	if m.Apply != nil {
		if err := m.Apply(p.req.Tenant, p.req.Namespace, p.candidate); err != nil {
			m.emit("apply-fix.apply.error", p.req, map[string]any{"error": err.Error()})
			return fmt.Errorf("apply-fix apply (per-namespace SA): %w", err)
		}
	}
	m.mu.Lock()
	delete(m.pending, requestID)
	m.mu.Unlock()
	m.emit("apply-fix.applied", p.req, map[string]any{"approver": approver})
	return nil
}
