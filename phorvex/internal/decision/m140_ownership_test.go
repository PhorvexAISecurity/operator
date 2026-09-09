/*
 * M-140 head regressions (engine side). Each test asserts the FIXED behaviour and fails
 * against the pinned baseline aa5cfeffbe2348f2fea53bd5bacb5f350858df2d. The baseline
 * characterization forms are retained under
 * workflow/fixes/M-140/evidence/baseline/claude-baseline-decision_test.go.txt.
 *
 * Producers are real: CoverageEngine.Decide is the entrypoint the runner calls, and
 * ObserveRotation is the real deferred rotation-feedback path.
 */

package decision

import (
	"errors"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
)

func m140Pol(tenant, uid string, lambda float64) model.Policy {
	p := covPolicy(2)
	p.Tenant = tenant
	p.PolicyUID = uid
	p.Lambda = lambda
	return p
}

func m140Fleet() []*model.WorkloadView {
	return []*model.WorkloadView{
		covView("crown", true, 3*time.Hour, false),
		lowValueView("cheap1"),
	}
}

func m140Train(e *CoverageEngine, owner string, n int) {
	for i := 0; i < n; i++ {
		e.ObserveRotation(owner, covView("crown", true, 3*time.Hour, false), 0.5)
	}
}

// A recreate under a NEW policy UID is a new economic unit: it consumes the new seed and
// starts from initial RLS/conformal/prior. On baseline the bucket was name-keyed and the
// 5.0 seed survived; this is the core defect.
func TestM140_RecreateUnderNewUIDIsFresh(t *testing.T) {
	e := NewCoverageEngine()
	old := m140Pol("pxv1t", "uid-A", 5.0)

	e.Decide(m140Fleet(), old)
	m140Train(e, old.Owner(), 5)
	if got := e.costByOwner[old.Owner()].RLS.Updates(); got != 5 {
		t.Fatalf("precondition: training did not land, RLS updates = %d", got)
	}
	if got := e.costByOwner[old.Owner()].Dual.Lambda(); got < 4.9 {
		t.Fatalf("precondition: first apply must consume the 5.0 seed, got %v", got)
	}

	e.ForgetOwner(old.Owner()) // the runner's drain performs exactly this

	fresh := m140Pol("pxv1t", "uid-B", 0.1) // same display name, new identity
	e.Decide(m140Fleet(), fresh)
	c := e.costByOwner[fresh.Owner()]

	if c == nil {
		t.Fatal("recreate produced no bucket")
	}
	if got := c.Dual.Lambda(); got > 0.1 {
		t.Fatalf("recreate did not consume the new seed: lambda = %v, want <= 0.1", got)
	}
	if got := c.RLS.Updates(); got != 0 {
		t.Fatalf("recreate inherited RLS state: updates = %d, want 0", got)
	}
	if c.RLS.Primed() {
		t.Fatal("recreate inherited a primed RLS")
	}
	if _, stale := e.costByOwner[old.Owner()]; stale {
		t.Fatal("removed owner's bucket survived")
	}
}

// The legacy e.Cost alias must be RETIRED when its holder is removed, including while other
// buckets still exist. Baseline reused the singleton object and carried its trained RLS and
// conformal state into the next owner, so a prune-only fix passed the lambda assertion and
// failed this one.
func TestM140_SingletonAliasRetiredOnRemoval(t *testing.T) {
	e := NewCoverageEngine()
	first := m140Pol("alias-holder", "uid-first", 5.0)
	other := m140Pol("co-resident", "uid-other", 0.5)

	e.Decide(m140Fleet(), first) // takes the legacy alias
	e.Decide(m140Fleet(), other) // a second, co-resident bucket
	m140Train(e, first.Owner(), 4)
	trained := e.costByOwner[first.Owner()].RLS.Updates()
	otherBefore := e.costByOwner[other.Owner()].RLS.Updates()
	if trained != 4 {
		t.Fatalf("precondition: alias holder training = %d, want 4", trained)
	}

	e.ForgetOwner(first.Owner()) // removed while `other` still lives

	if e.costByOwner[other.Owner()].RLS.Updates() != otherBefore {
		t.Fatal("removing the alias holder disturbed a co-resident bucket")
	}

	// Empty the map entirely, then recreate: the retired alias must not come back.
	e.ForgetOwner(other.Owner())
	if len(e.costByOwner) != 0 {
		t.Fatalf("precondition: expected an empty bucket map, got %d", len(e.costByOwner))
	}
	next := m140Pol("alias-holder", "uid-next", 0.1)
	e.Decide(m140Fleet(), next)
	c := e.costByOwner[next.Owner()]
	if got := c.RLS.Updates(); got != 0 {
		t.Fatalf("retired alias still carried RLS state: updates = %d, want 0", got)
	}
	if c == e.Cost {
		t.Fatal("a new owner was handed the retired legacy singleton")
	}
}

// calibrationFrozen must still reach buckets built through the constructor branch once the
// alias is retired; identity isolation does not change the PHVX-2 off-switch.
func TestM140_RetiredAliasStillInheritsCalibrationFrozen(t *testing.T) {
	e := NewCoverageEngine()
	holder := m140Pol("t", "uid-holder", 0.6)
	e.Decide(m140Fleet(), holder)
	e.SetCostCalibrationFrozen(true)
	e.ForgetOwner(holder.Owner())

	next := m140Pol("t", "uid-next", 0.6)
	e.Decide(m140Fleet(), next)
	if !e.costByOwner[next.Owner()].RLS.Frozen() {
		t.Fatal("bucket created after alias retirement did not inherit calibrationFrozen")
	}
}

// Deferred rotation feedback that lands after removal must be dropped, not lazily recreate
// the bucket at DefaultLambdaSeed. Baseline resurrected it at 0.6.
func TestM140_LateFeedbackDoesNotResurrectRemovedOwner(t *testing.T) {
	e := NewCoverageEngine()
	pol := m140Pol("pxv1t", "uid-A", 5.0)
	live := m140Pol("other", "uid-live", 0.3)

	e.Decide(m140Fleet(), pol)
	e.Decide(m140Fleet(), live)
	e.SetOwnerLive(pol.Owner(), true)
	e.SetOwnerLive(live.Owner(), true)

	e.ForgetOwner(pol.Owner()) // drain completes the removal

	// A rotation emitted before the delete completes its observation afterwards.
	e.ObserveRotation(pol.Owner(), covView("crown", true, 3*time.Hour, false), 0.5)

	if c, revived := e.costByOwner[pol.Owner()]; revived {
		t.Fatalf("late feedback resurrected a removed owner at lambda %v", c.Dual.Lambda())
	}
	// The positive control: a live owner still learns.
	before := e.costByOwner[live.Owner()].RLS.Updates()
	e.ObserveRotation(live.Owner(), covView("crown", true, 3*time.Hour, false), 0.5)
	if e.costByOwner[live.Owner()].RLS.Updates() != before+1 {
		t.Fatal("liveness gating also blocked a live owner; the guard is too broad")
	}
}

// The belief prior is owner-keyed and dropped on removal. Baseline had no forget path at all.
func TestM140_BeliefPriorForgottenOnRemoval(t *testing.T) {
	e := NewCoverageEngine()
	pol := m140Pol("pxv1t", "uid-A", 0.6)
	defaultMean := e.Killchain.Memory.PriorMean(model.OwnerKey(model.OwnerKindUID, "never-seen"))

	for i := 0; i < 20; i++ {
		e.Killchain.Memory.Observe(pol.Owner(), 0.4)
	}
	if e.Killchain.Memory.PriorMean(pol.Owner()) == defaultMean {
		t.Fatal("precondition: evidence did not move the prior")
	}

	e.ForgetOwner(pol.Owner())

	if got := e.Killchain.Memory.PriorMean(pol.Owner()); got != defaultMean {
		t.Fatalf("prior survived removal: %v, want the default %v", got, defaultMean)
	}
}

// PRESERVED behaviour, and this one passes on baseline too: a PATCH keeps the same identity,
// so learning continues and the configured seed is NOT reconsumed.
func TestM140_PatchKeepsIdentityAndDoesNotReseed(t *testing.T) {
	e := NewCoverageEngine()
	pol := m140Pol("pxv1t", "uid-A", 5.0)
	e.Decide(m140Fleet(), pol)
	m140Train(e, pol.Owner(), 3)
	lambdaBefore := e.costByOwner[pol.Owner()].Dual.Lambda()

	patched := m140Pol("pxv1t", "uid-A", 0.1) // same UID, new spec.lambda
	if patched.Owner() != pol.Owner() {
		t.Fatal("a PATCH changed the owner identity")
	}
	e.Decide(m140Fleet(), patched)

	c := e.costByOwner[patched.Owner()]
	if got := c.RLS.Updates(); got != 3 {
		t.Fatalf("PATCH reset learning: RLS updates = %d, want 3", got)
	}
	if c.Dual.Lambda() >= lambdaBefore {
		t.Fatalf("expected the ordinary non-binding decay, got %v then %v", lambdaBefore, c.Dual.Lambda())
	}
	if c.Dual.Lambda() <= 0.1 {
		t.Fatalf("PATCH reseeded the dual to the new spec value: %v", c.Dual.Lambda())
	}
}

// Creation metadata is captured once and is the only truthful evidence that a seed was
// actually consumed: LambdaConfiguredSeed re-reads the live spec every tick.
func TestM140_BucketMetadataRecordsConsumedSeedAndCreation(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0).UTC()
	e := NewCoverageEngine()
	e.Now = func() time.Time { return clock }

	pol := m140Pol("pxv1t", "uid-A", 5.0)
	e.Decide(m140Fleet(), pol)
	meta, ok := e.BucketMetaFor(pol.Owner())
	if !ok {
		t.Fatal("no creation record for a priced owner")
	}
	if meta.LambdaSeedConsumed != 5.0 {
		t.Fatalf("consumed seed = %v, want 5.0", meta.LambdaSeedConsumed)
	}
	if meta.KeyKind != model.OwnerKindUID {
		t.Fatalf("keyKind = %q, want %q", meta.KeyKind, model.OwnerKindUID)
	}
	if !meta.BucketCreatedAt.Equal(clock) {
		t.Fatalf("bucketCreatedAt = %v, want the injected clock %v", meta.BucketCreatedAt, clock)
	}

	// A PATCH must not rewrite the creation record, even though the spec seed changed.
	e.Decide(m140Fleet(), m140Pol("pxv1t", "uid-A", 0.1))
	after, _ := e.BucketMetaFor(pol.Owner())
	if after != meta {
		t.Fatalf("PATCH rewrote the creation record: %+v -> %+v", meta, after)
	}

	// A recreate produces new metadata. The clock is deliberately NOT advanced: causality is
	// carried by the creation event, not by requiring wall time to move between calls.
	e.ForgetOwner(pol.Owner())
	next := m140Pol("pxv1t", "uid-B", 0.1)
	e.Decide(m140Fleet(), next)
	fresh, ok := e.BucketMetaFor(next.Owner())
	if !ok {
		t.Fatal("no creation record after recreate")
	}
	if fresh.LambdaSeedConsumed != 0.1 {
		t.Fatalf("recreate consumed seed = %v, want 0.1", fresh.LambdaSeedConsumed)
	}
	if fresh.CreationEvent <= meta.CreationEvent {
		t.Fatalf("creation event did not advance: %d then %d", meta.CreationEvent, fresh.CreationEvent)
	}
	if fresh.OwnerKey == meta.OwnerKey {
		t.Fatal("recreate reused the previous owner key")
	}
}

// Offline/legacy producers with no API object keep working through the name-kind fallback,
// and their key space is disjoint from production UIDs.
func TestM140_OfflineProducerUsesDisjointNameKey(t *testing.T) {
	offline := covPolicy(2)
	offline.Tenant = "shared-string"
	offline.PolicyUID = ""

	production := covPolicy(2)
	production.Tenant = "anything"
	production.PolicyUID = "shared-string" // identical string, different identity space

	if offline.Owner() == production.Owner() {
		t.Fatalf("offline name key collided with a production UID: %q", offline.Owner())
	}
	if offline.OwnerKind() != model.OwnerKindName || production.OwnerKind() != model.OwnerKindUID {
		t.Fatalf("owner kinds wrong: %q / %q", offline.OwnerKind(), production.OwnerKind())
	}

	e := NewCoverageEngine()
	e.Decide(m140Fleet(), offline)
	e.Decide(m140Fleet(), production)
	if len(e.costByOwner) != 2 {
		t.Fatalf("expected two disjoint buckets, got %d", len(e.costByOwner))
	}
	if _, ok := e.BucketMetaFor(offline.Owner()); !ok {
		t.Fatal("offline producer got no bucket")
	}
	_ = cost.DefaultLambdaSeed
}

// R1.1 — removing the LAST owner leaves an empty live set. That must still reject stale
// producers: an empty tracked set is not the same as offline mode, where liveness was never
// registered at all. The earlier positive control kept a survivor and so never exercised
// this arm.
func TestM140_LastOwnerRemovalStillRejectsLateFeedback(t *testing.T) {
	e := NewCoverageEngine()
	only := m140Pol("last", "uid-last", 0.1)
	e.SetOwnerLive(only.Owner(), true)
	e.Decide(m140Fleet(), only)

	e.ForgetOwner(only.Owner()) // the set is now empty, not untracked
	e.ObserveRotation(only.Owner(), m140Fleet()[0], 0.5)

	if _, resurrected := e.BucketMetaFor(only.Owner()); resurrected {
		t.Fatal("late feedback resurrected the last owner once the live set emptied")
	}
	if len(e.costByOwner) != 0 {
		t.Fatalf("expected no buckets after the last owner left, got %d", len(e.costByOwner))
	}
}

// The offline arm of the same distinction: a producer that never registers liveness keeps
// working exactly as before, so the guard cannot break ablation/benchmark/calib-soak.
func TestM140_UntrackedOfflineProducerStillCreatesBuckets(t *testing.T) {
	e := NewCoverageEngine()
	offline := covPolicy(2)
	offline.Tenant = "offline"
	offline.PolicyUID = "" // no API object, so no liveness registration

	e.Decide(m140Fleet(), offline)
	if _, ok := e.BucketMetaFor(offline.Owner()); !ok {
		t.Fatal("liveness guard blocked an offline producer that never registered")
	}
	e.ObserveRotation(offline.Owner(), m140Fleet()[0], 0.5)
	if e.costByOwner[offline.Owner()].RLS.Updates() != 1 {
		t.Fatal("offline producer could not train")
	}
}

// R1.2 — a decision captured before removal must be REJECTED, not panic and not allocate.
// costFor returns nil for a retired owner, so an unguarded caller dereferences nil.
func TestM140_DecisionForRetiredOwnerIsRejectedNotPanicked(t *testing.T) {
	e := NewCoverageEngine()
	retired := m140Pol("retired", "uid-retired", 0.1)
	survivor := m140Pol("live", "uid-live", 0.1)
	e.SetOwnerLive(retired.Owner(), true)
	e.SetOwnerLive(survivor.Owner(), true)
	e.Decide(m140Fleet(), retired)
	e.Decide(m140Fleet(), survivor)
	e.ForgetOwner(retired.Owner())

	decisions, err := e.DecideChecked(m140Fleet(), retired)
	if err == nil {
		t.Fatal("a decision for a retired owner was accepted")
	}
	if !errors.Is(err, ErrOwnerRetired) {
		t.Fatalf("unexpected rejection reason: %v", err)
	}
	if len(decisions) != 0 {
		t.Fatalf("retired owner produced %d decisions", len(decisions))
	}
	if _, allocated := e.BucketMetaFor(retired.Owner()); allocated {
		t.Fatal("rejecting the decision still allocated state for the retired owner")
	}

	// AssembleSet is a separate public entrypoint and must reject the same way.
	set, ctx := e.AssembleSet(m140Fleet(), retired)
	if len(set.Candidates) != 0 || len(ctx) != 0 {
		t.Fatal("AssembleSet priced a retired owner")
	}
	if _, allocated := e.BucketMetaFor(retired.Owner()); allocated {
		t.Fatal("AssembleSet allocated state for a retired owner")
	}

	// The survivor is unaffected: the guard is narrow.
	if _, err := e.DecideChecked(m140Fleet(), survivor); err != nil {
		t.Fatalf("survivor decision rejected: %v", err)
	}
}
