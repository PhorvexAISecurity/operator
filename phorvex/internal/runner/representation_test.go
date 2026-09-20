package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/representation"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type post25CountingContext struct {
	checks      int
	cancelAfter int
}

func (c *post25CountingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *post25CountingContext) Done() <-chan struct{}       { return nil }
func (c *post25CountingContext) Value(any) any               { return nil }
func (c *post25CountingContext) Err() error {
	c.checks++
	if c.checks > c.cancelAfter {
		return context.Canceled
	}
	return nil
}

func TestPost25M137RepresentationPreparationHonorsPreEffectCancellation(t *testing.T) {
	p := model.Policy{Tenant: "tenant", TickID: "tick"}
	c := model.NewClaimScope(nil, true, "image", "sha")
	decisions := []model.Decision{{Namespace: "ns", Pod: "one"}, {Namespace: "ns", Pod: "two"}, {Namespace: "ns", Pod: "three"}}
	versions := map[string]string{"ns/one": "uid-1", "ns/two": "uid-2", "ns/three": "uid-3"}
	ctx := &post25CountingContext{cancelAfter: 1}
	got, complete := representationSnapshotsBeforeEffect(ctx, decisions, p, versions, c, nil)
	if complete || got != nil || ctx.checks != 2 {
		t.Fatalf("canceled preparation returned complete=%v snapshots=%d checks=%d", complete, len(got), ctx.checks)
	}

	got, complete = representationSnapshotsBeforeEffect(context.Background(), decisions, p, versions, c, nil)
	if !complete || len(got) != len(decisions) {
		t.Fatalf("healthy preparation returned complete=%v snapshots=%d", complete, len(got))
	}
	for i, snapshot := range got {
		if snapshot.Scope.Version != versions[decisions[i].Namespace+"/"+decisions[i].Pod] {
			t.Fatalf("snapshot %d lost authoritative workload version", i)
		}
	}
}

func TestM100SourceAdapterFrozenUnboundOutcomesAndDispatch(t *testing.T) {
	c := model.NewClaimScope([]string{"old-detector"}, true, "build", "sha")
	p := model.Policy{Tenant: "t", TickID: "tick", PolicyUID: "policy", DecisionAssets: map[string]string{"ns/p": "uid"}}
	d := model.Decision{Tenant: "t", Namespace: "ns", Pod: "p", Selected: true, Action: model.ActionRotate, PHold: 1, Stage: "model-theft", MutationKind: "irreversible", Trace: &model.DecisionTraceV2{DecisionID: "decision", Facts: []model.DecisionFactV2{{FactKey: "private-fact", FactType: "credential", FinalWeight: 42}}}}
	inventory := outcomeInventory([]model.SecurityEventInfo{{Name: "event", Source: "trusted-looking", Trust: "trusted", CreatorIdentity: "creator", Outcomes: []model.ProtectedOutcome{{ID: "outcome", PolicyUID: "policy", DecisionAsset: "ns/p", DecisionAssetUID: "uid", ProtectedAsset: "password=private-outcome-secret", Version: "v", Property: "token=private-property-secret", LossState: "already-lost", StateBasis: "claimed", ClassBasis: "claimed"}}}}, p)
	frozen := representationSnapshotV1(d, p, "uid", c, inventory)
	c.DetectorSet[0] = "new-detector"
	d.Trace.Facts[0].FactKey = "changed-after-snapshot"
	inventory.Records[0].Outcome.ID = "changed"
	d.Actuated = true
	appendRepresentation(&d, frozen)
	if d.Representation.KnownLossCount != 0 || d.Representation.LossAssessment != "unavailable" || d.Representation.LossHistoryStatus != "unavailable" || d.Representation.CoverageShare.Share.Present {
		t.Fatal("unbound source upgraded")
	}
	if d.Representation.EffectEvidence != "dispatch-only-unconfirmed" || d.Representation.Snapshot.Claim.DetectorSet[0] != "old-detector" || d.Representation.FactStates[0].Key != "private-fact" {
		t.Fatal("frozen input lost")
	}
	if len(d.Representation.UnknownEntries) < 2 {
		t.Fatal("outcome gap ignored")
	}
	var sink bytes.Buffer
	log := audit.New(logr.Discard(), &sink)
	log.Record(d)
	for _, secret := range []string{"private-outcome-secret", "private-property-secret"} {
		if strings.Contains(sink.String(), secret) {
			t.Fatal("secret reached audit")
		}
	}
	if strings.Contains(d.Representation.UnknownEntries[0].Scope.Asset, "private-outcome-secret") {
		t.Fatal("structured representation not redacted")
	}
}

func TestT15M100OptimizerLegacyIdentity(t *testing.T) {
	for _, name := range []string{"nats", "mixed-fleet", "ai-gpu"} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
			p := model.Policy{Tenant: "t", TickID: "tick", PolicyUID: "policy", PolicyName: name, TraceEnabled: true, BrainImage: "fixture-build", GitSHA: "fixture-sha", DryRun: true, Lambda: .4, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, MaxMovesPerTick: 2, ProactiveFloor: time.Hour, AntiOverRotationWindow: 5 * time.Minute, MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true}}
			views := []*model.WorkloadView{}
			for i, pod := range []string{"a", "b"} {
				clocks := map[string]time.Duration{}
				for _, v := range model.LiveExposureVariables {
					clocks[v] = 2 * time.Hour
				}
				views = append(views, &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: pod, UID: "uid-" + pod, Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, MountedSecrets: []string{"secret-ref"}, Stateful: name == "nats", HasGPU: name == "ai-gpu" || (name == "mixed-fleet" && i == 1)}, Phase: model.PhaseWarm, BlastRadius: .6, ExposureByVariable: clocks})
			}
			e := decision.NewCoverageEngine()
			e.Now = func() time.Time { return now }
			ds, err := e.DecideChecked(views, p)
			if err != nil || len(ds) != 2 {
				t.Fatalf("fixture: %v %d", err, len(ds))
			}
			selected := 0
			for _, d := range ds {
				if d.Selected {
					selected++
				}
			}
			t.Logf("%s: %d optimizer decisions, %d selected; 3 reporting states x 2 trust configurations", name, len(ds), selected)
			for _, d := range ds {
				beforeDecision, _ := json.Marshal(d)
				beforeRecord, _ := json.Marshal(audit.ToRecord(d))
				for variant := 0; variant < 6; variant++ {
					var ids []string
					if variant%2 == 1 {
						ids = []string{"fixture-detector"}
					}
					c := model.NewClaimScope(ids, true, "fixture-build", "fixture-sha")
					frozen := representationSnapshotV1(d, p, "uid-"+d.Pod, c, nil)
					if variant/2 > 0 {
						frozen = syntheticStateForLegacyTest(frozen, variant/2 == 2)
					}
					copyD := d
					appendRepresentation(&copyD, frozen)
					if variant/2 == 1 && copyD.Representation.FactStates[0].State != model.RepresentationAtRisk {
						t.Fatal("fixture must exercise at-risk state")
					}
					if variant/2 == 2 && copyD.Representation.FactStates[0].State != model.RepresentationAlreadyLost {
						t.Fatal("fixture must exercise lost state")
					}
					copyD.Representation = nil
					afterDecision, _ := json.Marshal(copyD)
					if !bytes.Equal(beforeDecision, afterDecision) {
						t.Fatal("changed existing Decision fields")
					}
					appendRepresentation(&copyD, frozen)
					rec := audit.ToRecord(copyD)
					rec.Representation = nil
					afterRecord, _ := json.Marshal(rec)
					if !bytes.Equal(beforeRecord, afterRecord) {
						t.Fatal("changed existing audit bytes")
					}
				}
			}
		})
	}
}

func TestReviewDispatchSnapshotReplaysActualReport(t *testing.T) {
	c := model.NewClaimScope(nil, true, "b", "s")
	d := model.Decision{Tenant: "t", Namespace: "ns", Pod: "p", Actuated: true}
	frozen := representationSnapshotV1(d, model.Policy{Tenant: "t", TickID: "tick"}, "v", c, nil)
	appendRepresentation(&d, frozen)
	if frozen.DispatchEvidence != "" {
		t.Fatal("frozen source mutated")
	}
	b, _ := json.Marshal(d.Representation)
	var retained model.Representation
	if e := json.Unmarshal(b, &retained); e != nil {
		t.Fatal(e)
	}
	replayed, _ := json.Marshal(representation.Build(retained.Snapshot))
	if !bytes.Equal(b, replayed) || retained.EffectEvidence != "dispatch-only-unconfirmed" {
		t.Fatal("dispatch replay mismatch")
	}
}

// Synthetic reporting states on a fixed real optimizer output. These bindings
// are deliberately NOT supplied by the production adapter.
func syntheticStateForLegacyTest(s model.RepresentationSnapshot, lost bool) model.RepresentationSnapshot {
	scope := s.Scope
	scope.Property = "fixture-property"
	s.InventoryComplete = true
	s.ClassificationComplete = true
	s.Facts = []model.RepresentationFact{{Key: "fixture-key", Scope: scope, RuleVersion: "fixture-current-v1", ObservationRef: "fixture-observation", ReversibleCondition: "fixture-reversible-condition"}}
	if lost {
		s.LossAssessment = "available"
		s.LossMappingVersion = "fixture-loss-mapping-v1"
		s.Witnesses = []model.LossWitness{{Scope: scope, EventRef: "fixture-event", EventTime: "2026-09-08T00:00:00Z", IngestionTime: "2026-09-08T00:00:01Z", AuthenticatedIdentity: "fixture-creator", TrustAtIngestionRef: "fixture-stamp", RuleVersion: "fixture-loss-v1", PayloadPredicateRef: "fixture-predicate", CompletedUnauthorizedOutcomeRef: "fixture-completed-outcome", IrreversibilitySemantics: "fixture-nonrecoverable-outcome", ClassificationRef: "fixture-classification"}}
	}
	return s
}

func TestM100RunnerConformanceSample(t *testing.T) {
	p := model.Policy{Tenant: "fixture-tenant", TickID: "fixture-tick", PolicyUID: "fixture-policy"}
	c := model.NewClaimScope(nil, true, "fixture-build", "fixture-sha")
	d := model.Decision{Tenant: p.Tenant, Namespace: "fixture-ns", Pod: "fixture-pod", Selected: true, Actuated: true, Action: model.ActionRotate}
	s := representationSnapshotV1(d, p, "fixture-uid", c, &model.ExistentialInventory{Records: []model.OutcomeAssertion{{Event: "fixture-event", Outcome: model.ProtectedOutcome{ID: "fixture-outcome", ProtectedAsset: "fixture-protected-asset", Version: "fixture-protected-version", Property: "disclosure", LossState: "already-lost", StateBasis: "detector-supplied-unvalidated"}}}})
	appendRepresentation(&d, s)
	if d.Representation.KnownLossCount != 0 || d.Representation.CoverageShare.Share.Present || len(d.Representation.UnknownEntries) != 1 {
		t.Fatal("source sample invented positive evidence")
	}
	if dir := os.Getenv("M100_EXAMPLES_DIR"); dir != "" {
		b, e := json.MarshalIndent(struct {
			EvidenceKind string                `json:"evidenceKind"`
			Report       *model.Representation `json:"report"`
		}{"synthetic-runner-adapter-fixture-not-live", d.Representation}, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, "runner-unavailable.json"), append(b, '\n'), 0644); e != nil {
			t.Fatal(e)
		}
	}
}
