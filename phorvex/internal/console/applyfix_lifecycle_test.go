/*
 * Phorvex — M-166: the apply-fix approval lifecycle against the REAL ApplyFixManager. Every
 * concurrency case uses a blocking callback barrier, never a sleep: the test observes which side of
 * the claim each approver landed on. Run under -race.
 */

package console

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// barrierApplier is an Applier that signals entry and blocks until released, counting calls.
type barrierApplier struct {
	calls   int32
	entered chan struct{}
	release chan struct{}
	err     error
}

func newBarrierApplier(capacity int) *barrierApplier {
	return &barrierApplier{entered: make(chan struct{}, capacity), release: make(chan struct{})}
}

func (b *barrierApplier) apply(_, _ string, _ model.Policy) error {
	atomic.AddInt32(&b.calls, 1)
	b.entered <- struct{}{}
	<-b.release
	return b.err
}

func (b *barrierApplier) count() int32 { return atomic.LoadInt32(&b.calls) }

// auditCounter is an Audit hook that counts events by name under its own lock.
type auditCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newAuditCounter() *auditCounter { return &auditCounter{counts: map[string]int{}} }

func (a *auditCounter) hook(event string, _ map[string]any) {
	a.mu.Lock()
	a.counts[event]++
	a.mu.Unlock()
}

func (a *auditCounter) n(event string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counts[event]
}

func mustSubmit(t *testing.T, m *ApplyFixManager, id, tenant, requester string, delta ApplyFixDelta) SubmitResult {
	t.Helper()
	res, err := m.Submit(ApplyFixRequest{ID: id, Tenant: tenant, Namespace: tenant, Requester: requester, Delta: delta, Reason: "tune"})
	if err != nil {
		t.Fatalf("submit %s/%s: %v", tenant, id, err)
	}
	return res
}

// Several DISTINCT valid approvers race one pending generation: exactly one claims it and reaches the
// applier; every other call returns in-progress WITHOUT entering the callback, while the first is
// still inside it. After the terminal outcome, a further approver gets the terminal conflict.
func TestApplyFixLifecycle_ConcurrentApproversClaimOnce(t *testing.T) {
	ap := newBarrierApplier(8)
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, ap.apply, audit.hook)
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})

	const racers = 5
	type outcome struct {
		who string
		res ApproveResult
		err error
	}
	results := make(chan outcome, racers)
	for i := 0; i < racers; i++ {
		who := "approver-" + string(rune('a'+i))
		go func() {
			res, err := m.Approve("acme", "r1", sub.Generation, who)
			results <- outcome{who, res, err}
		}()
	}
	<-ap.entered // one approver is inside the callback, holding the claim
	// The other racers must all come back while the claim is held — none may enter.
	var losers []outcome
	for len(losers) < racers-1 {
		select {
		case o := <-results:
			losers = append(losers, o)
		case <-ap.entered:
			t.Fatal("a second approver entered the applier while the first held the claim")
		}
	}
	for _, o := range losers {
		if !errors.Is(o.err, ErrApplyFixInProgress) || o.res.State != ApplyFixApplying {
			t.Errorf("%s while in flight: want ErrApplyFixInProgress/applying, got %v / %+v", o.who, o.err, o.res)
		}
	}
	close(ap.release)
	winner := <-results
	if winner.err != nil || winner.res.State != ApplyFixApplied || winner.res.Retry {
		t.Fatalf("winner: %+v %v", winner.res, winner.err)
	}
	if ap.count() != 1 {
		t.Fatalf("applier entered %d times; want exactly 1", ap.count())
	}
	if audit.n("apply-fix.applied") != 1 || audit.n("apply-fix.applying") != 1 {
		t.Errorf("audit: applying=%d applied=%d; want 1/1", audit.n("apply-fix.applying"), audit.n("apply-fix.applied"))
	}
	// A late, different approver: terminal conflict, no new attempt.
	res, err := m.Approve("acme", "r1", sub.Generation, "late")
	if !errors.Is(err, ErrApplyFixTerminal) || res.State != ApplyFixApplied || res.Approver != winner.who {
		t.Errorf("late approver: want ErrApplyFixTerminal with the winner recorded, got %v / %+v", err, res)
	}
	if ap.count() != 1 || len(m.Pending("acme")) != 0 {
		t.Errorf("terminal record must be closed: calls=%d pending=%d", ap.count(), len(m.Pending("acme")))
	}
}

// Replays before, during and after the attempt: unknown/foreign generations fail before the callback;
// an in-flight retry is in-progress; an identical retry after success returns the retained outcome
// without a second callback or a second applied audit record.
func TestApplyFixLifecycle_ReplayReturnsRetainedOutcome(t *testing.T) {
	ap := newBarrierApplier(2)
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, ap.apply, audit.hook)
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})

	if _, err := m.Approve("acme", "nope", sub.Generation, "bob"); !errors.Is(err, ErrApplyFixNotFound) {
		t.Errorf("unknown id: want ErrApplyFixNotFound, got %v", err)
	}
	if _, err := m.Approve("globex", "r1", sub.Generation, "bob"); !errors.Is(err, ErrApplyFixNotFound) {
		t.Errorf("foreign tenant: want ErrApplyFixNotFound, got %v", err)
	}
	if _, err := m.Approve("acme", "r1", sub.Generation+"-forged", "bob"); !errors.Is(err, ErrApplyFixGeneration) {
		t.Errorf("wrong generation: want ErrApplyFixGeneration, got %v", err)
	}
	if _, err := m.Approve("acme", "r1", "", "bob"); err == nil {
		t.Error("empty generation must be refused")
	}
	if ap.count() != 0 {
		t.Fatalf("refusals reached the applier %d time(s)", ap.count())
	}

	done := make(chan ApproveResult, 1)
	go func() {
		res, _ := m.Approve("acme", "r1", sub.Generation, "bob")
		done <- res
	}()
	<-ap.entered
	// bob's own retry while bob's attempt is in flight (client timeout + resend).
	if res, err := m.Approve("acme", "r1", sub.Generation, "bob"); !errors.Is(err, ErrApplyFixInProgress) || res.Approver != "bob" {
		t.Errorf("in-flight retry: want ErrApplyFixInProgress by bob, got %v / %+v", err, res)
	}
	close(ap.release)
	if first := <-done; first.State != ApplyFixApplied {
		t.Fatalf("first attempt: %+v", first)
	}
	retry, err := m.Approve("acme", "r1", sub.Generation, "bob")
	if err != nil || !retry.Retry || retry.State != ApplyFixApplied || retry.Approver != "bob" {
		t.Errorf("identical retry after success: want retained applied outcome with Retry, got %v / %+v", err, retry)
	}
	if ap.count() != 1 || audit.n("apply-fix.applied") != 1 {
		t.Errorf("retry must not re-apply or re-audit: calls=%d applied-audit=%d", ap.count(), audit.n("apply-fix.applied"))
	}
	if res, err := m.Approve("acme", "r1", sub.Generation, "carol"); !errors.Is(err, ErrApplyFixTerminal) || res.Retry {
		t.Errorf("another approver after success: want ErrApplyFixTerminal, got %v / %+v", err, res)
	}
}

// An applier error may follow a real side effect: the generation ends FAILED, a retry returns the same
// failure without invoking the applier again, and nobody else can re-run it.
func TestApplyFixLifecycle_ApplyErrorIsTerminalNeverRetried(t *testing.T) {
	var calls int32
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error {
		atomic.AddInt32(&calls, 1)
		return errors.New("patch timed out after the request was sent")
	}, audit.hook)
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})

	res, err := m.Approve("acme", "r1", sub.Generation, "bob")
	if !errors.Is(err, ErrApplyFixApplyFailed) || res.State != ApplyFixFailed || !strings.Contains(res.Detail, "timed out") {
		t.Fatalf("want terminal failed with detail, got %v / %+v", err, res)
	}
	retry, err2 := m.Approve("acme", "r1", sub.Generation, "bob")
	if !errors.Is(err2, ErrApplyFixApplyFailed) || !retry.Retry || retry.Detail != res.Detail {
		t.Errorf("retry: want the same retained failure, got %v / %+v", err2, retry)
	}
	if _, err := m.Approve("acme", "r1", sub.Generation, "carol"); !errors.Is(err, ErrApplyFixTerminal) {
		t.Errorf("other approver after failure: want ErrApplyFixTerminal, got %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("a failed generation was retried: applier calls=%d", calls)
	}
	if audit.n("apply-fix.applied") != 0 || audit.n("apply-fix.apply.error") != 1 {
		t.Errorf("audit: applied=%d error=%d; want 0/1", audit.n("apply-fix.applied"), audit.n("apply-fix.apply.error"))
	}
	if len(m.Pending("acme")) != 0 {
		t.Error("a failed generation must not be listed as open")
	}
}

// A panicking applier leaves an explicit terminal failure (effect unknown) — the attempt is not
// reopened and the panic does not escape the manager.
func TestApplyFixLifecycle_PanicIsTerminalFailure(t *testing.T) {
	var calls int32
	m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error {
		atomic.AddInt32(&calls, 1)
		panic("client nil pointer")
	}, nil)
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	res, err := m.Approve("acme", "r1", sub.Generation, "bob")
	if !errors.Is(err, ErrApplyFixApplyFailed) || res.State != ApplyFixFailed || !strings.Contains(res.Detail, "panicked") {
		t.Fatalf("want terminal failed (panicked), got %v / %+v", err, res)
	}
	if _, err := m.Approve("acme", "r1", sub.Generation, "carol"); !errors.Is(err, ErrApplyFixTerminal) {
		t.Errorf("after a panic the generation must stay terminal, got %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("applier calls=%d; want 1", calls)
	}
}

// Generations embed the manager instance: a fresh manager (restart) issues different generations for
// the same request, and an approval carrying the old generation is refused before any callback.
func TestApplyFixLifecycle_GenerationBoundToInstance(t *testing.T) {
	var calls int32
	apply := func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }
	m1 := NewApplyFixManager(safeBase, apply, nil)
	m2 := NewApplyFixManager(safeBase, apply, nil)
	g1 := mustSubmit(t, m1, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)}).Generation
	g2 := mustSubmit(t, m2, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)}).Generation
	if g1 == "" || g1 == g2 {
		t.Fatalf("generations must be unique per instance: %q vs %q", g1, g2)
	}
	if !strings.HasPrefix(g1, m1.instance+"-") || !strings.HasPrefix(g2, m2.instance+"-") || m1.instance == m2.instance {
		t.Fatalf("generation must embed its own instance identity: %q %q", g1, g2)
	}
	if _, err := m2.Approve("acme", "r1", g1, "bob"); !errors.Is(err, ErrApplyFixGeneration) {
		t.Errorf("old generation on a new instance: want ErrApplyFixGeneration, got %v", err)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("a refused generation reached the applier")
	}
	if res, err := m2.Approve("acme", "r1", g2, "bob"); err != nil || res.State != ApplyFixApplied {
		t.Errorf("control: the current generation applies: %v / %+v", err, res)
	}
}

// The staged snapshot is immutable: a caller that keeps mutating the pointer it submitted through
// cannot change the approved delta, its hash, or what the applier receives.
func TestApplyFixLifecycle_SnapshotImmuneToCallerMutation(t *testing.T) {
	var got model.Policy
	m := NewApplyFixManager(safeBase, func(_, _ string, c model.Policy) error { got = c; return nil }, nil)
	ns := 1.5
	req := ApplyFixRequest{ID: "r1", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: &ns}}
	sub, err := m.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	before := m.Pending("acme")[0].DeltaHash
	ns = 0 // caller mutates AFTER submit: out of bounds and gate-starving if it were honoured
	if after := m.Pending("acme")[0].DeltaHash; after != before {
		t.Fatalf("delta hash moved with the caller's pointer: %s -> %s", before, after)
	}
	if res, err := m.Approve("acme", "r1", sub.Generation, "bob"); err != nil || res.State != ApplyFixApplied {
		t.Fatalf("approve: %v / %+v", err, res)
	}
	if got.NormSparsity != 1.5 {
		t.Errorf("applier received NormSparsity=%v; want the approved 1.5", got.NormSparsity)
	}
}

// Candidate maps are copied on both sides: the snapshot is independent of what BasePol returned and of
// what the applier does to the candidate it is handed.
func TestApplyFixLifecycle_CandidateMapsAreCopies(t *testing.T) {
	shared := map[string]string{"crown": "db"}
	base := func(string) model.Policy {
		p := safeBase("")
		p.DecisionAssets = shared
		return p
	}
	var received model.Policy
	m := NewApplyFixManager(base, func(_, _ string, c model.Policy) error {
		received = c
		c.DecisionAssets["injected"] = "by-applier"
		return nil
	}, nil)
	m.Gate = func(model.Policy) error { return nil }
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	m.mu.Lock()
	snap := m.records[applyKey{"acme", "r1"}].candidate
	m.mu.Unlock()
	if &snap.DecisionAssets == &shared || snap.DecisionAssets["crown"] != "db" {
		t.Fatal("snapshot must hold its own copy of the base maps")
	}
	shared["crown"] = "mutated-after-submit" // BasePol's map moves: that is a base change, not a snapshot change
	m.mu.Lock()
	still := m.records[applyKey{"acme", "r1"}].candidate.DecisionAssets["crown"]
	m.mu.Unlock()
	if still != "db" {
		t.Fatalf("snapshot followed BasePol's map mutation: %q", still)
	}
	shared["crown"] = "db" // restore so the stale-base check passes; the applier-side copy is what is under test now
	if res, err := m.Approve("acme", "r1", sub.Generation, "bob"); err != nil || res.State != ApplyFixApplied {
		t.Fatalf("approve: %v / %+v", err, res)
	}
	m.mu.Lock()
	leaked := m.records[applyKey{"acme", "r1"}].candidate.DecisionAssets["injected"]
	m.mu.Unlock()
	if leaked != "" || received.DecisionAssets["injected"] != "by-applier" {
		t.Errorf("applier mutation reached the retained snapshot (leaked=%q)", leaked)
	}
}

// policyFingerprint covers every data field: a map entry change is detected, and an identical policy
// with an independent func hook fingerprints identically.
func TestPolicyFingerprint_CoversDataNotFuncs(t *testing.T) {
	a := safeBase("")
	a.DecisionAssets = map[string]string{"k": "v"}
	a.AssetWeightFromLabels = func(map[string]string) float64 { return 1 }
	b := clonePolicyData(a)
	b.AssetWeightFromLabels = func(map[string]string) float64 { return 2 }
	if policyFingerprint(a) != policyFingerprint(b) {
		t.Fatal("func hooks are not data; identical data must fingerprint identically")
	}
	b.DecisionAssets["k"] = "changed"
	if policyFingerprint(a) == policyFingerprint(b) {
		t.Fatal("a changed map entry must change the fingerprint")
	}
	c := a
	c.TickInterval++
	if policyFingerprint(a) == policyFingerprint(c) {
		t.Fatal("a changed scalar must change the fingerprint")
	}
}

// If the tenant's base policy moved so that the delta would now derive a DIFFERENT candidate, the
// approval is refused as stale (terminal, no callback). A base move the delta fully overrides is not
// a candidate change and still applies.
func TestApplyFixLifecycle_StaleBaseRefused(t *testing.T) {
	var mu sync.Mutex
	base := safeBase("")
	basePol := func(string) model.Policy { mu.Lock(); defer mu.Unlock(); return base }
	var calls int32
	audit := newAuditCounter()
	m := NewApplyFixManager(basePol, func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }, audit.hook)

	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	mu.Lock()
	base.FlowDisruption = 2 // not in the delta: the approved candidate no longer derives from the base
	mu.Unlock()
	res, err := m.Approve("acme", "r1", sub.Generation, "bob")
	if !errors.Is(err, ErrApplyFixStaleBase) || res.State != ApplyFixStale {
		t.Fatalf("want ErrApplyFixStaleBase/stale, got %v / %+v", err, res)
	}
	if atomic.LoadInt32(&calls) != 0 || audit.n("apply-fix.rejected.stale") != 1 || audit.n("apply-fix.applied") != 0 {
		t.Errorf("stale must not apply: calls=%d stale-audit=%d applied-audit=%d", calls, audit.n("apply-fix.rejected.stale"), audit.n("apply-fix.applied"))
	}
	if _, err := m.Approve("acme", "r1", sub.Generation, "carol"); !errors.Is(err, ErrApplyFixTerminal) {
		t.Errorf("stale is terminal for the generation: got %v", err)
	}

	// Control: a base move on a field the delta OVERRIDES leaves the candidate identical => applies.
	sub2 := mustSubmit(t, m, "r2", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	mu.Lock()
	base.NormSparsity = 7
	mu.Unlock()
	if res, err := m.Approve("acme", "r2", sub2.Generation, "bob"); err != nil || res.State != ApplyFixApplied {
		t.Errorf("control: overridden base field is not a candidate change: %v / %+v", err, res)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("control applier calls=%d; want 1", calls)
	}
}

// A gate refusal at approval is an explicit terminal rejection: no callback, never applied, and a
// retry returns the same rejection.
func TestApplyFixLifecycle_GateRefusalAtApprovalIsTerminal(t *testing.T) {
	var calls int32
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }, audit.hook)
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	m.Gate = func(model.Policy) error { return errGateBreak }
	res, err := m.Approve("acme", "r1", sub.Generation, "bob")
	if !errors.Is(err, ErrApplyFixGateRefused) || res.State != ApplyFixRejected {
		t.Fatalf("want ErrApplyFixGateRefused/rejected, got %v / %+v", err, res)
	}
	retry, err := m.Approve("acme", "r1", sub.Generation, "bob")
	if !errors.Is(err, ErrApplyFixGateRefused) || !retry.Retry {
		t.Errorf("retry: want retained rejection, got %v / %+v", err, retry)
	}
	if atomic.LoadInt32(&calls) != 0 || audit.n("apply-fix.applied") != 0 || audit.n("apply-fix.rejected.gate") != 1 {
		t.Errorf("gate refusal must not apply: calls=%d applied=%d gate=%d", calls, audit.n("apply-fix.applied"), audit.n("apply-fix.rejected.gate"))
	}
}

// With no applier wired the approval is an explicit non-applied failure, whatever the mode label says.
// The request stays pending (nothing was consumed) and applies once an applier exists.
func TestApplyFixLifecycle_NilApplierIsNeverApplied(t *testing.T) {
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, nil, audit.hook)
	m.ApplierMode = "live" // a lying label must not matter
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	res, err := m.Approve("acme", "r1", sub.Generation, "bob")
	if !errors.Is(err, ErrApplyFixNoApplier) || res.State != ApplyFixPending {
		t.Fatalf("want ErrApplyFixNoApplier with the request still pending, got %v / %+v", err, res)
	}
	if audit.n("apply-fix.applied") != 0 || audit.n("apply-fix.apply.unavailable") != 1 {
		t.Errorf("audit: applied=%d unavailable=%d; want 0/1", audit.n("apply-fix.applied"), audit.n("apply-fix.apply.unavailable"))
	}
	if p := m.Pending("acme"); len(p) != 1 || p[0].State != ApplyFixPending || p[0].Approver != "" {
		t.Fatalf("request must remain pending and unclaimed: %+v", p)
	}
	var calls int32
	m.Apply = func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }
	if res, err := m.Approve("acme", "r1", sub.Generation, "bob"); err != nil || res.State != ApplyFixApplied || calls != 1 {
		t.Errorf("once wired, the still-pending request applies once: %v / %+v calls=%d", err, res, calls)
	}
}

// Same tenant/id: identical content is idempotent (same generation, one record, one submitted audit);
// different content conflicts and never overwrites; a terminal record is a tombstone, not a free slot;
// the same id in another tenant is a separate record.
func TestApplyFixLifecycle_SameIDIdempotentConflictAndTenantIsolation(t *testing.T) {
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { return nil }, audit.hook)
	first := mustSubmit(t, m, "shared", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	again := mustSubmit(t, m, "shared", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	if !again.Existing || again.Generation != first.Generation || again.State != ApplyFixPending {
		t.Fatalf("identical resubmit must return the existing record: %+v vs %+v", first, again)
	}
	if audit.n("apply-fix.submitted") != 1 {
		t.Errorf("identical resubmit audited submitted %d times; want 1", audit.n("apply-fix.submitted"))
	}
	_, err := m.Submit(ApplyFixRequest{ID: "shared", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(2.5)}, Reason: "tune"})
	if !errors.Is(err, ErrApplyFixConflict) {
		t.Fatalf("different delta under the same id: want ErrApplyFixConflict, got %v", err)
	}
	_, err = m.Submit(ApplyFixRequest{ID: "shared", Tenant: "acme", Namespace: "acme", Requester: "mallory", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}, Reason: "tune"})
	if !errors.Is(err, ErrApplyFixConflict) {
		t.Fatalf("different requester under the same id: want ErrApplyFixConflict, got %v", err)
	}
	if p := m.Pending("acme"); len(p) != 1 || p[0].Generation != first.Generation || p[0].Requester != "alice" {
		t.Fatalf("the original record must be untouched: %+v", p)
	}
	other := mustSubmit(t, m, "shared", "globex", "dave", ApplyFixDelta{NormSparsity: fptr(2.5)})
	if other.Existing || other.Generation == first.Generation || len(m.Pending("acme")) != 1 || len(m.Pending("globex")) != 1 {
		t.Fatalf("same id in another tenant must be independent: %+v", other)
	}
	if _, err := m.Approve("globex", "shared", first.Generation, "eve"); !errors.Is(err, ErrApplyFixGeneration) {
		t.Errorf("acme's generation must not select globex's record: %v", err)
	}
	if res, err := m.Approve("acme", "shared", first.Generation, "bob"); err != nil || res.State != ApplyFixApplied {
		t.Fatalf("approve acme: %v / %+v", err, res)
	}
	// The applied record is a tombstone: identical content reports it, different content conflicts.
	done := mustSubmit(t, m, "shared", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	if !done.Existing || done.State != ApplyFixApplied {
		t.Errorf("identical resubmit after apply must report the applied record: %+v", done)
	}
	if _, err := m.Submit(ApplyFixRequest{ID: "shared", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.6)}, Reason: "tune"}); !errors.Is(err, ErrApplyFixConflict) {
		t.Errorf("an applied id must not be recycled for new content: %v", err)
	}
	if len(m.Pending("globex")) != 1 {
		t.Error("globex's record must be unaffected by acme's lifecycle")
	}
}

// The store is finite and fails closed: at MaxRecords a NEW key is refused, identical resubmits still
// resolve, and terminal records are not evicted to make room.
func TestApplyFixLifecycle_CapacityFailsClosed(t *testing.T) {
	m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { return nil }, nil)
	m.MaxRecords = 2
	a := mustSubmit(t, m, "a", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	mustSubmit(t, m, "b", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	if _, err := m.Submit(ApplyFixRequest{ID: "c", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}}); !errors.Is(err, ErrApplyFixCapacity) {
		t.Fatalf("third key: want ErrApplyFixCapacity, got %v", err)
	}
	if res := mustSubmit(t, m, "a", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)}); !res.Existing || res.Generation != a.Generation {
		t.Errorf("identical resubmit at capacity must still resolve: %+v", res)
	}
	if res, err := m.Approve("acme", "a", a.Generation, "bob"); err != nil || res.State != ApplyFixApplied {
		t.Fatalf("approve a: %v / %+v", err, res)
	}
	if _, err := m.Submit(ApplyFixRequest{ID: "c", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}}); !errors.Is(err, ErrApplyFixCapacity) {
		t.Errorf("a terminal record must not be evicted to admit a new key: %v", err)
	}
	if _, err := m.Submit(ApplyFixRequest{ID: "a", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.6)}}); !errors.Is(err, ErrApplyFixConflict) {
		t.Errorf("the applied tombstone must still refuse reuse: %v", err)
	}
}

// An applier that calls back into the manager (listing, a competing approval of the same generation,
// a new submit) must neither deadlock nor obtain a second attempt.
func TestApplyFixLifecycle_CallbackReentrancy(t *testing.T) {
	var m *ApplyFixManager
	var calls int32
	var innerErr error
	var innerPending []PendingInfo
	m = NewApplyFixManager(safeBase, func(tenant, _ string, _ model.Policy) error {
		atomic.AddInt32(&calls, 1)
		innerPending = m.Pending(tenant)
		_, innerErr = m.Approve(tenant, "r1", innerPending[0].Generation, "inner-approver")
		if _, err := m.Submit(ApplyFixRequest{ID: "from-callback", Tenant: tenant, Namespace: tenant, Requester: "cb", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}}); err != nil {
			return err
		}
		return nil
	}, nil)
	sub := mustSubmit(t, m, "r1", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	finished := make(chan struct{})
	var res ApproveResult
	var err error
	go func() { res, err = m.Approve("acme", "r1", sub.Generation, "bob"); close(finished) }()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("reentrant callback deadlocked the manager")
	}
	if err != nil || res.State != ApplyFixApplied {
		t.Fatalf("outer approve: %v / %+v", err, res)
	}
	if !errors.Is(innerErr, ErrApplyFixInProgress) {
		t.Errorf("reentrant approval of the claimed generation: want ErrApplyFixInProgress, got %v", innerErr)
	}
	if len(innerPending) != 1 || innerPending[0].State != ApplyFixApplying || innerPending[0].Approver != "bob" {
		t.Errorf("listing from inside the callback must show the claim: %+v", innerPending)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("applier calls=%d; want 1", calls)
	}
	if p := m.Pending("acme"); len(p) != 1 || p[0].ID != "from-callback" {
		t.Errorf("the submit from inside the callback must be the only open record: %+v", p)
	}
}

// Concurrent submits and approvals: identical submits of one key converge on one generation, differing
// submits admit exactly one, and N distinct requests approved concurrently produce exactly N callbacks.
func TestApplyFixLifecycle_ConcurrentSubmitAndApprove(t *testing.T) {
	var calls int32
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }, audit.hook)
	m.Gate = func(model.Policy) error { return nil } // keep the shadow engine out of a tight concurrency loop

	const n = 16
	var wg sync.WaitGroup
	results := make([]SubmitResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = m.Submit(ApplyFixRequest{ID: "same", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}, Reason: "tune"})
		}(i)
	}
	wg.Wait()
	created := 0
	for _, r := range results {
		if r.Generation != results[0].Generation {
			t.Fatalf("identical concurrent submits diverged: %+v", results)
		}
		if !r.Existing {
			created++
		}
	}
	if created != 1 || audit.n("apply-fix.submitted") != 1 {
		t.Errorf("identical concurrent submits: created=%d submitted-audit=%d; want 1/1", created, audit.n("apply-fix.submitted"))
	}

	var okCount, conflicts int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := m.Submit(ApplyFixRequest{ID: "contested", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1 + float64(i)*0.1)}})
			switch {
			case err == nil:
				atomic.AddInt32(&okCount, 1)
			case errors.Is(err, ErrApplyFixConflict):
				atomic.AddInt32(&conflicts, 1)
			default:
				t.Errorf("unexpected submit error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if okCount != 1 || conflicts != n-1 {
		t.Errorf("contested key: ok=%d conflicts=%d; want 1/%d", okCount, conflicts, n-1)
	}

	// N distinct requests, each approved by 3 racing approvers => exactly N callbacks.
	gens := make([]string, n)
	for i := 0; i < n; i++ {
		gens[i] = mustSubmit(t, m, "d"+string(rune('a'+i)), "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)}).Generation
	}
	for i := 0; i < n; i++ {
		for _, who := range []string{"bob", "carol", "dan"} {
			wg.Add(1)
			go func(i int, who string) {
				defer wg.Done()
				m.Approve("acme", "d"+string(rune('a'+i)), gens[i], who)
			}(i, who)
		}
	}
	wg.Wait()
	if atomic.LoadInt32(&calls) != n || audit.n("apply-fix.applied") != n {
		t.Errorf("distinct requests: calls=%d applied-audit=%d; want %d/%d", calls, audit.n("apply-fix.applied"), n, n)
	}
}

// Pending is in submission order and AuditTrail hands out copies: mutating a returned map cannot
// alter the ring.
func TestApplyFixLifecycle_ViewsAreOrderedCopies(t *testing.T) {
	m := NewApplyFixManager(safeBase, nil, nil)
	m.Gate = func(model.Policy) error { return nil }
	for _, id := range []string{"z", "m", "a"} {
		mustSubmit(t, m, id, "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	}
	for i := 0; i < 3; i++ {
		var ids []string
		for _, p := range m.Pending("acme") {
			ids = append(ids, p.ID)
		}
		if strings.Join(ids, ",") != "z,m,a" {
			t.Fatalf("pending order must be submission order, got %v", ids)
		}
	}
	trail := m.AuditTrail("acme")
	if len(trail) != 3 {
		t.Fatalf("trail: %d entries", len(trail))
	}
	trail[0].Fields["id"] = "tampered"
	if again := m.AuditTrail("acme"); again[0].Fields["id"] != "z" {
		t.Errorf("audit ring was mutated through a returned view: %v", again[0].Fields)
	}
}

// R1.1 — an identical resubmission is answered from the stored immutable request, not from today's
// gate: after the gate turns refusing (or unavailable), a byte-identical retry of a pending AND of an
// already-applied request returns the retained generation and state, while a NEW request is still
// refused by that gate. The retained record is never re-judged, so an accepted (possibly applied)
// request cannot be reported as rejected.
func TestApplyFixLifecycle_IdenticalResubmitIgnoresCurrentGate(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		name := map[bool]string{false: "pending", true: "applied"}[terminal]
		t.Run(name, func(t *testing.T) {
			var calls, gateCalls int32
			audit := newAuditCounter()
			m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }, audit.hook)
			req := ApplyFixRequest{ID: "r1", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}, Reason: "tune"}
			first, err := m.Submit(req)
			if err != nil {
				t.Fatal(err)
			}
			if terminal {
				if res, err := m.Approve("acme", "r1", first.Generation, "bob"); err != nil || res.State != ApplyFixApplied {
					t.Fatalf("approve: %v / %+v", err, res)
				}
			}
			m.Gate = func(model.Policy) error { atomic.AddInt32(&gateCalls, 1); return errors.New("safety gate unavailable") }
			m.BasePol = func(string) model.Policy {
				t.Error("BasePol must not be consulted for a stored request")
				return safeBase("")
			}
			again, err := m.Submit(req)
			if err != nil || !again.Existing || again.Generation != first.Generation {
				t.Fatalf("identical retry must return the retained record: %v / %+v (first %+v)", err, again, first)
			}
			m.BasePol = safeBase // the positive-control NEW request below legitimately derives a candidate
			wantState := ApplyFixPending
			if terminal {
				wantState = ApplyFixApplied
			}
			if again.State != wantState {
				t.Errorf("retained state %q; want %q", again.State, wantState)
			}
			if atomic.LoadInt32(&gateCalls) != 0 || audit.n("apply-fix.rejected.gate") != 0 || audit.n("apply-fix.submitted") != 1 {
				t.Errorf("stored request was re-judged: gateCalls=%d gate-audit=%d submitted-audit=%d", gateCalls, audit.n("apply-fix.rejected.gate"), audit.n("apply-fix.submitted"))
			}
			// Positive control: a NEW request under the same refusing gate is refused, and a same-id
			// DIFFERENT request is a conflict — the store answers before the gate is consulted.
			if _, err := m.Submit(ApplyFixRequest{ID: "fresh", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}}); err == nil || errors.Is(err, ErrApplyFixConflict) {
				t.Errorf("new request must be refused by the current gate, got %v", err)
			}
			if _, err := m.Submit(ApplyFixRequest{ID: "r1", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.6)}, Reason: "tune"}); !errors.Is(err, ErrApplyFixConflict) {
				t.Errorf("different content under a stored id must conflict regardless of the gate, got %v", err)
			}
			if atomic.LoadInt32(&calls) != map[bool]int32{false: 0, true: 1}[terminal] {
				t.Errorf("applier calls=%d", calls)
			}
		})
	}
}

// R1.2 — the Gate callback judges its OWN copy of the candidate. A gate that mutates the maps it is
// handed (at submit, at approval, or in preview) changes neither the retained snapshot, nor the
// fingerprint the stale-base check relies on, nor the candidate the applier receives, nor BasePol's map.
func TestApplyFixLifecycle_GateCannotMutateCandidateOrApplierInput(t *testing.T) {
	baseMap := map[string]string{"crown": "original"}
	base := func(s string) model.Policy {
		p := safeBase(s)
		p.DecisionAssets = baseMap
		return p
	}
	var received model.Policy
	m := NewApplyFixManager(base, func(_, _ string, p model.Policy) error { received = clonePolicyData(p); return nil }, nil)
	var gateCalls int32
	m.Gate = func(p model.Policy) error {
		n := atomic.AddInt32(&gateCalls, 1)
		p.DecisionAssets["crown"] = fmt.Sprintf("unapproved-%d", n) // every gate call tries to smuggle a value
		p.DecisionAssets["extra"] = "x"
		return nil
	}
	if pass, _ := m.GatePreview("acme", ApplyFixDelta{NormSparsity: fptr(1.5)}); !pass || baseMap["crown"] != "original" || len(baseMap) != 1 {
		t.Fatalf("preview must not let the gate reach BasePol's map: pass=%v map=%v", pass, baseMap)
	}
	sub := mustSubmit(t, m, "immutable", "acme", "alice", ApplyFixDelta{NormSparsity: fptr(1.5)})
	m.mu.Lock()
	rec := m.records[applyKey{"acme", "immutable"}]
	stored, fp := rec.candidate.DecisionAssets["crown"], rec.fingerprint
	m.mu.Unlock()
	if stored != "original" || fp != policyFingerprint(clonePolicyData(ApplyFixDelta{NormSparsity: fptr(1.5)}.applyTo(base("acme")))) {
		t.Fatalf("submit-time gate mutation reached the retained snapshot: crown=%q", stored)
	}
	res, err := m.Approve("acme", "immutable", sub.Generation, "bob")
	if err != nil || res.State != ApplyFixApplied {
		t.Fatalf("approve: %v / %+v", err, res)
	}
	if received.DecisionAssets["crown"] != "original" || len(received.DecisionAssets) != 1 {
		t.Errorf("approval-time gate mutation reached the applier input: %v", received.DecisionAssets)
	}
	m.mu.Lock()
	after := rec.candidate.DecisionAssets["crown"]
	m.mu.Unlock()
	if after != "original" || baseMap["crown"] != "original" {
		t.Errorf("retained snapshot or BasePol map mutated: snapshot=%q base=%q", after, baseMap["crown"])
	}
	if atomic.LoadInt32(&gateCalls) != 3 {
		t.Errorf("gate must have run for preview, submit and approval: %d", gateCalls)
	}
}

// Related concurrency review — identical submits, differing submits and approvals of ONE key race
// under the race detector. Invariants: exactly one record is created, by either content; every
// answer about it carries that record's generation and a real lifecycle state; every submit that
// did not create it is Existing (identical content) or a conflict (different content); the applier
// runs at most once.
func TestApplyFixLifecycle_ConcurrentSubmitConflictAndApproveOneKey(t *testing.T) {
	var calls int32
	audit := newAuditCounter()
	m := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }, audit.hook)
	m.Gate = func(model.Policy) error { return nil }
	same := ApplyFixRequest{ID: "hot", Tenant: "acme", Namespace: "acme", Requester: "alice", Delta: ApplyFixDelta{NormSparsity: fptr(1.5)}, Reason: "tune"}
	const n = 12
	var wg sync.WaitGroup
	var created, existing, identConflict, diffConflict, approved, otherApprove int32
	var mu sync.Mutex
	generations := map[string]int{}
	states := map[ApplyFixState]int{}
	for i := 0; i < n; i++ {
		wg.Add(3)
		go func() { // identical submit
			defer wg.Done()
			res, err := m.Submit(same)
			switch {
			case errors.Is(err, ErrApplyFixConflict):
				atomic.AddInt32(&identConflict, 1)
			case err != nil:
				t.Errorf("identical submit: %v", err)
			case res.Existing:
				atomic.AddInt32(&existing, 1)
				mu.Lock()
				generations[res.Generation]++
				states[res.State]++
				mu.Unlock()
			default:
				atomic.AddInt32(&created, 1)
				mu.Lock()
				generations[res.Generation]++
				mu.Unlock()
			}
		}()
		go func(i int) { // differing submit under the same key
			defer wg.Done()
			d := same
			d.Delta = ApplyFixDelta{NormSparsity: fptr(2 + float64(i)*0.1)}
			res, err := m.Submit(d)
			switch {
			case errors.Is(err, ErrApplyFixConflict):
				atomic.AddInt32(&diffConflict, 1)
			case err != nil:
				t.Errorf("differing submit: unexpected %v", err)
			case res.Existing:
				t.Errorf("a differing submit can never be Existing: %+v", res)
			default:
				atomic.AddInt32(&created, 1)
			}
		}(i)
		go func(i int) { // approval of whatever generation the listing shows
			defer wg.Done()
			for _, p := range m.Pending("acme") {
				res, err := m.Approve("acme", "hot", p.Generation, "approver-"+string(rune('a'+i)))
				switch {
				case err == nil && res.State == ApplyFixApplied && !res.Retry:
					atomic.AddInt32(&approved, 1)
				case errors.Is(err, ErrApplyFixInProgress), errors.Is(err, ErrApplyFixTerminal), errors.Is(err, ErrApplyFixGeneration):
					atomic.AddInt32(&otherApprove, 1)
				default:
					t.Errorf("approve: unexpected %v / %+v", err, res)
				}
			}
		}(i)
	}
	wg.Wait()
	t.Logf("created=%d existing=%d identConflict=%d diffConflict=%d approved=%d otherApprove=%d applier=%d", created, existing, identConflict, diffConflict, approved, otherApprove, calls)
	if created != 1 || audit.n("apply-fix.submitted") != 1 {
		t.Errorf("created=%d submitted-audit=%d; want exactly one record", created, audit.n("apply-fix.submitted"))
	}
	identicalWon := identConflict == 0 && existing == n-1 && diffConflict == n
	differingWon := identConflict == n && existing == 0 && diffConflict == n-1
	if !identicalWon && !differingWon {
		t.Errorf("submit outcomes are not one consistent winner: existing=%d identConflict=%d diffConflict=%d", existing, identConflict, diffConflict)
	}
	if len(generations) > 1 {
		t.Errorf("answers about one record reported %d generations: %v", len(generations), generations)
	}
	for st := range states {
		if st != ApplyFixPending && st != ApplyFixApplying && st != ApplyFixApplied {
			t.Errorf("impossible state reported to a submitter: %q", st)
		}
	}
	if atomic.LoadInt32(&calls) > 1 || approved > 1 || audit.n("apply-fix.applied") > 1 {
		t.Errorf("applier calls=%d approved=%d applied-audit=%d; want at most 1", calls, approved, audit.n("apply-fix.applied"))
	}
}
