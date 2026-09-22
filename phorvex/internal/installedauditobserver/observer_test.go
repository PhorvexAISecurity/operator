package installedauditobserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
)

type memorySource struct {
	manifest audittransport.Manifest
	data     map[string][]byte
	material map[string][]byte
	err      error
}

type lateFailureSource struct {
	*memorySource
	failAt int64
}

type failAfterOneTransportChunk struct {
	Source
	cursorSize int64
	dataCalls  int
}

func (s *failAfterOneTransportChunk) Chunk(ctx context.Context, seg audittransport.Segment, off int64) ([]byte, error) {
	if seg.Size > s.cursorSize && off >= s.cursorSize {
		if s.dataCalls > 0 {
			return nil, context.Canceled
		}
		s.dataCalls++
	}
	return s.Source.Chunk(ctx, seg, off)
}

func (s *lateFailureSource) Chunk(ctx context.Context, seg audittransport.Segment, off int64) ([]byte, error) {
	if off >= s.failAt {
		return nil, context.Canceled
	}
	b, err := s.memorySource.Chunk(ctx, seg, off)
	if err != nil {
		return nil, err
	}
	if off+int64(len(b)) > s.failAt {
		b = b[:s.failAt-off]
	}
	return b, nil
}

func (s *memorySource) Manifest(context.Context) (audittransport.Manifest, error) {
	return s.manifest, s.err
}
func (s *memorySource) Chunk(_ context.Context, seg audittransport.Segment, off int64) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	b := s.data[seg.Generation]
	if off < 0 || off > seg.Size || seg.Size > int64(len(b)) {
		return nil, errors.New("range")
	}
	end := min(seg.Size, off+audittransport.ChunkBytes)
	return append([]byte(nil), b[off:end]...), nil
}
func (s *memorySource) ParameterMaterial(_ context.Context, kind, hash string) ([]byte, error) {
	b, ok := s.material[kind+"/"+hash]
	if !ok {
		return nil, errors.New("missing material")
	}
	return append([]byte(nil), b...), nil
}

func material(t *testing.T) (model.ParameterSetReference, map[string][]byte) {
	t.Helper()
	m := model.DecisionParameterManifest{SchemaVersion: model.DecisionParameterManifestV1, ID: "test-manifest", Parameters: []model.DecisionParameter{{Name: "grace", Group: "native", Unit: "seconds", Domain: "[1,300]", Default: 30, Source: "fixture", Provenance: model.ParameterConfigurationBound, Limitations: "synthetic", DependencyGroup: "native"}}}
	o := model.EffectivePolicyOverrides{SchemaVersion: model.DecisionPolicyOverridesV1, ID: "bench/policy@policy-uid:7", Values: []model.EffectivePolicyParameter{{Name: "grace", Unit: "seconds", Present: true, Value: 30}}}
	mh, err := m.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	oh, err := o.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	mr, _ := json.Marshal(m.Canonical())
	or, _ := json.Marshal(o.Canonical())
	return model.ParameterSetReference{SchemaVersion: model.DecisionParameterSetV1, ManifestID: m.ID, ManifestHash: mh, PolicyOverridesID: o.ID, PolicyOverridesHash: oh}, map[string][]byte{audit.ParameterMaterialManifest + "/" + mh: mr, audit.ParameterMaterialPolicyOverrides + "/" + oh: or}
}

func producerRow(t *testing.T, at time.Time, ref model.ParameterSetReference) []byte {
	t.Helper()
	trace := &model.DecisionTraceV2{SchemaVersion: model.DecisionTraceSchemaV2, DecisionID: "decision-1", TickID: "tick-1", Timestamp: at.Format(time.RFC3339Nano), BrainImage: "registry.test/phorvex@sha256:abc", GitSHA: "abcdef1", DecisionEngine: "p1-coverage", PolicyNamespace: "bench", PolicyName: "policy", PolicyUID: "policy-uid", AssetNamespace: "bench", AssetName: "target", AssetUID: "pod-uid", SelectedAction: string(model.ActionNoop), TieBreakReason: "notApplicable", NoopReason: "availability-floor", DispatchOutcome: model.DispatchNotAttempted}
	rec := audit.Record{SchemaVersion: audit.SchemaVersionCurrent, Kind: "phorvex.decision", Time: at, Namespace: "bench", Pod: "target", Action: string(model.ActionNoop), ParameterSet: &ref, ParameterMaterialStatus: "retained", DecisionTrace: trace}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func producerRotateRow(t *testing.T, at time.Time, ref model.ParameterSetReference) []byte {
	t.Helper()
	trace := &model.DecisionTraceV2{SchemaVersion: model.DecisionTraceSchemaV2, DecisionID: "decision-rotate", TickID: "tick-rotate", Timestamp: at.Format(time.RFC3339Nano), BrainImage: "registry.test/phorvex@sha256:abc", GitSHA: "abcdef1", DecisionEngine: "p1-coverage", PolicyNamespace: "bench", PolicyName: "policy", PolicyUID: "policy-uid", AssetNamespace: "bench", AssetName: "target", AssetUID: "pod-uid", SelectedAction: string(model.ActionRotate), DispatchOutcome: model.DispatchEmitted}
	rec := audit.Record{SchemaVersion: audit.SchemaVersionCurrent, Kind: "phorvex.decision", Time: at, Namespace: "bench", Pod: "target", Action: string(model.ActionRotate), Selected: true, Feasible: true, Actuated: true, DispatchOutcome: model.DispatchEmitted, Handler: string(model.ActionRotate), ObjectsTouched: []string{"Pod/bench/target"}, MutationKind: "forward-only", ParameterSet: &ref, ParameterMaterialStatus: "retained", DecisionTrace: trace, GracefulTermination: &model.GracefulTerminationReceipt{PolicyNamespace: "bench", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 7, PolicyGraceCapSeconds: 30, WorkloadGraceSeconds: 30, WorkloadGraceExplicit: true, EffectiveGracePeriodSeconds: 30, PodUID: "pod-uid", PodResourceVersion: "123", TerminationStatus: "unconfirmed"}}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func baseFixture(t *testing.T) (*memorySource, Cursor, Config, []byte) {
	t.Helper()
	at := time.Date(2026, 9, 21, 23, 30, 0, 0, time.UTC)
	ref, materials := material(t)
	row := producerRow(t, at, ref)
	prefix := []byte("{}\n")
	all := append(append([]byte(nil), prefix...), append(row, '\n')...)
	sum := sha256.Sum256(prefix)
	s := &memorySource{manifest: audittransport.Manifest{FetchedAt: at.Add(time.Second).UnixNano(), Segments: []audittransport.Segment{{ID: "live", Generation: "gen-1", Size: int64(len(all)), Anchor: "11111111111111111111111111111111"}}}, data: map[string][]byte{"gen-1": all}, material: materials}
	cursor := Cursor{SchemaVersion: CursorSchema, CapturedAt: at.Add(-time.Second), Segment: audittransport.Segment{ID: "live", Generation: "gen-1", Size: int64(len(prefix)), Anchor: hex.EncodeToString(sum[:16])}, Offset: int64(len(prefix))}
	cfg := Config{PolicyNamespace: "bench", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 7, TargetNamespace: "bench", TargetName: "target", TargetUID: "pod-uid", ExpectedTraceSchema: model.DecisionTraceSchemaV2, ExpectedBrainImage: "registry.test/phorvex@sha256:abc", ExpectedGitSHA: "abcdef1", ExpectedManifestID: ref.ManifestID, ExpectedManifestHash: ref.ManifestHash, ExpectedOverridesHash: ref.PolicyOverridesHash, NotBefore: at.Add(-time.Second), NotAfter: at.Add(time.Second)}
	return s, cursor, cfg, row
}

func TestActualAuditProducerRoundTripProjectsOnlyAllowlistedFields(t *testing.T) {
	s, c, cfg, _ := baseFixture(t)
	receipts, summary, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != "complete" || summary.Attribution != "observed" || len(receipts) != 1 {
		t.Fatalf("summary=%+v receipts=%d", summary, len(receipts))
	}
	r := receipts[0]
	if r.DecisionID != "decision-1" || r.Policy.Generation != 7 || r.DispatchOutcome != model.DispatchNotAttempted || r.BrainImageSHA256 == "" || len(r.SourceRanges) != 1 || r.SourceRanges[0].SHA256 == "" {
		t.Fatalf("receipt=%+v", r)
	}
	out, _ := json.Marshal(r)
	for _, forbidden := range []string{"availability-floor", "registry.test/phorvex@", "reason", "inputs"} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("receipt leaked %q: %s", forbidden, out)
		}
	}
}

func TestFreshPolicyEpochDiscoversAndVerifiesOverridesHash(t *testing.T) {
	s, c, cfg, _ := baseFixture(t)
	cfg.ExpectedOverridesHash = ""
	receipts, summary, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err != nil || len(receipts) != 1 || summary.Status != "complete" || receipts[0].ParameterEpoch.PolicyOverridesHash == "" {
		t.Fatalf("receipts=%d summary=%+v err=%v", len(receipts), summary, err)
	}
	for key := range s.material {
		if strings.HasPrefix(key, audit.ParameterMaterialPolicyOverrides+"/") {
			s.material[key] = []byte(`{"schemaVersion":"phorvex.policy-overrides.v1","id":"tampered","values":[]}`)
		}
	}
	if _, _, err = Collect(context.Background(), s, c, cfg, time.Now); err == nil {
		t.Fatal("tampered discovered override material accepted")
	}
}

func TestFreshPolicyEpochRejectsASecondVerifiedOverridesHash(t *testing.T) {
	s, c, cfg, first := baseFixture(t)
	cfg.ExpectedOverridesHash = ""
	ref, _ := material(t)
	overrides := model.EffectivePolicyOverrides{SchemaVersion: model.DecisionPolicyOverridesV1, ID: ref.PolicyOverridesID,
		Values: []model.EffectivePolicyParameter{{Name: "grace", Unit: "seconds", Present: true, Value: 29}}}
	secondHash, err := overrides.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	secondMaterial, err := json.Marshal(overrides.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	s.material[audit.ParameterMaterialPolicyOverrides+"/"+secondHash] = secondMaterial
	ref.PolicyOverridesHash = secondHash
	second := bytesReplaceDecisionID(producerRow(t, cfg.NotBefore.Add(time.Second), ref), "decision-2")
	s.data["gen-1"] = append([]byte("{}\n"), append(first, append([]byte{'\n'}, append(second, '\n')...)...)...)
	s.manifest.Segments[0].Size = int64(len(s.data["gen-1"]))

	receipts, summary, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err == nil || !strings.Contains(err.Error(), "multiple parameter epochs") || len(receipts) != 1 ||
		summary.Status != "invalid" || summary.ErrorClass != "parameter-epoch" {
		t.Fatalf("receipts=%d summary=%+v err=%v", len(receipts), summary, err)
	}
}

func TestMatchingRowsRequireExplicitBooleanEvidence(t *testing.T) {
	s, c, cfg, row := baseFixture(t)
	mutations := map[string]func(map[string]any){
		"missing-selected": func(x map[string]any) { delete(x, "selected") },
		"null-selected":    func(x map[string]any) { x["selected"] = nil },
		"missing-feasible": func(x map[string]any) { delete(x, "feasible") },
		"null-feasible":    func(x map[string]any) { x["feasible"] = nil },
		"missing-dry-run":  func(x map[string]any) { delete(x, "dryRun") },
		"null-dry-run":     func(x map[string]any) { x["dryRun"] = nil },
		"missing-actuated": func(x map[string]any) { delete(x, "actuated") },
		"null-actuated":    func(x map[string]any) { x["actuated"] = nil },
		"missing-trace-dry-run": func(x map[string]any) {
			delete(x["decisionTrace"].(map[string]any), "dryRun")
		},
		"null-trace-dry-run": func(x map[string]any) {
			x["decisionTrace"].(map[string]any)["dryRun"] = nil
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var object map[string]any
			if err := json.Unmarshal(row, &object); err != nil {
				t.Fatal(err)
			}
			mutate(object)
			bad, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			s2 := *s
			s2.data = map[string][]byte{"gen-1": append([]byte("{}\n"), append(bad, '\n')...)}
			s2.manifest.Segments[0].Size = int64(len(s2.data["gen-1"]))
			if _, _, err := Collect(context.Background(), &s2, c, cfg, time.Now); err == nil || !strings.Contains(err.Error(), "required boolean evidence") {
				t.Fatalf("missing/null boolean accepted: %v", err)
			}
		})
	}
}

func TestCurrentV6FlatIdentityShapeAndFailureControls(t *testing.T) {
	s, c, cfg, row := baseFixture(t)
	var obj map[string]any
	if err := json.Unmarshal(row, &obj); err != nil {
		t.Fatal(err)
	}
	trace := obj["decisionTrace"].(map[string]any)
	trace["schemaVersion"] = model.DecisionTraceSchemaV6
	trace["actionStatus"] = []map[string]any{{"action": "rotate", "status": "infeasible", "exclusionKind": "feasibility"}}
	cfg.ExpectedTraceSchema = model.DecisionTraceSchemaV6
	row, _ = json.Marshal(obj)
	s.data["gen-1"] = append([]byte("{}\n"), append(row, '\n')...)
	s.manifest.Segments[0].Size = int64(len(s.data["gen-1"]))
	if got, _, err := Collect(context.Background(), s, c, cfg, time.Now); err != nil || len(got) != 1 {
		t.Fatalf("real-v6-shaped projection failed receipts=%d err=%v", len(got), err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"wrong-policy-uid": func(x map[string]any) { x["decisionTrace"].(map[string]any)["policyUID"] = "replacement" },
		"wrong-target-uid": func(x map[string]any) { x["decisionTrace"].(map[string]any)["assetUID"] = "replacement" },
		"wrong-source":     func(x map[string]any) { x["decisionTrace"].(map[string]any)["gitSHA"] = "deadbee" },
		"missing-material": func(x map[string]any) { delete(x, "parameterSet") },
	} {
		t.Run(name, func(t *testing.T) {
			var x map[string]any
			_ = json.Unmarshal(row, &x)
			mutate(x)
			bad, _ := json.Marshal(x)
			s2 := *s
			s2.data = map[string][]byte{"gen-1": append([]byte("{}\n"), append(bad, '\n')...)}
			s2.manifest.Segments[0].Size = int64(len(s2.data["gen-1"]))
			if _, sum, err := Collect(context.Background(), &s2, c, cfg, time.Now); err == nil || sum.Status != "invalid" {
				t.Fatalf("accepted bad row summary=%+v err=%v", sum, err)
			}
		})
	}
}

func TestAvailabilityRefusalProjectsOnlyExactProducerReason(t *testing.T) {
	positive := rawActionDisposition{Action: string(model.ActionRotate), Status: model.ActionStatusInfeasible, ExclusionKind: model.ExclusionFeasibility, Reason: "availability: ready=2-1 < minAvailable=2"}
	if got := projectAvailabilityRefusal(positive); got == nil || *got != (AvailabilityRefusal{Ready: 2, Removed: 1, MinAvailable: 2}) {
		t.Fatalf("availability refusal=%+v", got)
	}
	for name, reason := range map[string]string{
		"anti-over":             "anti-over-rotation: podIdentity unchanged for 1s < window=1m0s (evidence-retention guard)",
		"stateful":              "stateful-integrity: rotate would destroy single-writer/long-running state; prefer quarantine",
		"malformed":             "availability: ready=2 < minAvailable=2",
		"contradictory-numeric": "availability: ready=3-1 < minAvailable=2",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := positive
			candidate.Reason = reason
			if got := projectAvailabilityRefusal(candidate); got != nil {
				t.Fatalf("unrelated/invalid reason granted availability refusal: %+v", got)
			}
		})
	}

	s, c, cfg, row := baseFixture(t)
	var object map[string]any
	if err := json.Unmarshal(row, &object); err != nil {
		t.Fatal(err)
	}
	trace := object["decisionTrace"].(map[string]any)
	trace["schemaVersion"] = model.DecisionTraceSchemaV6
	trace["actionStatus"] = []map[string]any{{"action": "rotate", "status": "infeasible", "exclusionKind": "feasibility", "reason": positive.Reason, "scored": false}}
	cfg.ExpectedTraceSchema = model.DecisionTraceSchemaV6
	row, _ = json.Marshal(object)
	s.data["gen-1"] = append([]byte("{}\n"), append(row, '\n')...)
	s.manifest.Segments[0].Size = int64(len(s.data["gen-1"]))
	receipts, _, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err != nil || len(receipts) != 1 || receipts[0].ActionDisposition == nil || receipts[0].ActionDisposition.AvailabilityRefusal == nil || *receipts[0].ActionDisposition.AvailabilityRefusal != (AvailabilityRefusal{Ready: 2, Removed: 1, MinAvailable: 2}) {
		t.Fatalf("projected receipts=%+v err=%v", receipts, err)
	}
	encoded, _ := json.Marshal(receipts[0])
	if strings.Contains(string(encoded), positive.Reason) || strings.Contains(string(encoded), `"reason"`) {
		t.Fatalf("private reason leaked: %s", encoded)
	}
}

func TestActualProducerNativeRotateRequiresExactWireAuthority(t *testing.T) {
	s, c, cfg, _ := baseFixture(t)
	ref, _ := material(t)
	at := cfg.NotBefore.Add(time.Second)
	row := producerRotateRow(t, at, ref)
	s.data["gen-1"] = append([]byte("{}\n"), append(row, '\n')...)
	s.manifest.Segments[0].Size = int64(len(s.data["gen-1"]))
	cfg.AllowedObjectsTouched = []string{"Pod/bench/target"}
	cfg.ExpectedPodResourceVersion = "123"
	grace := int64(30)
	cfg.ExpectedGraceSeconds = &grace
	got, _, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err != nil || len(got) != 1 || got[0].GracefulTermination == nil {
		t.Fatalf("rotate receipt=%+v err=%v", got, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"actuated-false": func(x map[string]any) { x["actuated"] = false },
		"wrong-resource-version": func(x map[string]any) {
			x["gracefulTermination"].(map[string]any)["podResourceVersion"] = "replacement"
		},
		"wrong-object":  func(x map[string]any) { x["objectsTouched"] = []string{"Pod/bench/other"} },
		"missing-grace": func(x map[string]any) { delete(x, "gracefulTermination") },
	} {
		t.Run(name, func(t *testing.T) {
			var x map[string]any
			_ = json.Unmarshal(row, &x)
			mutate(x)
			bad, _ := json.Marshal(x)
			s2 := *s
			s2.data = map[string][]byte{"gen-1": append([]byte("{}\n"), append(bad, '\n')...)}
			s2.manifest.Segments[0].Size = int64(len(s2.data["gen-1"]))
			if _, _, err := Collect(context.Background(), &s2, c, cfg, time.Now); err == nil {
				t.Fatal("invalid producer evidence accepted")
			}
		})
	}
}

func TestConflictingDuplicateAndBoundsRetainPartialReceipts(t *testing.T) {
	s, c, cfg, row := baseFixture(t)
	second := bytesReplaceDecisionID(row, "decision-2")
	conflict := bytesReplaceDecisionID(row, "decision-1")
	var conflictObject map[string]any
	if err := json.Unmarshal(conflict, &conflictObject); err != nil {
		t.Fatal(err)
	}
	conflictObject["feasible"] = true
	conflict, _ = json.Marshal(conflictObject)
	s.data["gen-1"] = append([]byte("{}\n"), append(row, append([]byte{'\n'}, append(second, append([]byte{'\n'}, append(conflict, '\n')...)...)...)...)...)
	s.manifest.Segments[0].Size = int64(len(s.data["gen-1"]))
	got, sum, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err == nil || len(got) != 2 || sum.Status != "invalid" {
		t.Fatalf("partial receipts=%d summary=%+v err=%v", len(got), sum, err)
	}
	dup := []byte(`{"kind":"phorvex.decision","kind":"phorvex.decision"}`)
	if err := rejectDuplicateFields(dup); err == nil {
		t.Fatal("duplicate field accepted")
	}
}

func TestWindowBoundsGenerationAndPartialRecordsFailClosed(t *testing.T) {
	s, c, cfg, row := baseFixture(t)
	t.Run("window-not-complete", func(t *testing.T) {
		s2 := *s
		s2.manifest.FetchedAt = cfg.NotAfter.Add(-time.Nanosecond).UnixNano()
		if _, summary, err := Collect(context.Background(), &s2, c, cfg, time.Now); err == nil || summary.Status != "invalid" {
			t.Fatalf("summary=%+v err=%v", summary, err)
		}
	})
	t.Run("wrong-generation", func(t *testing.T) {
		bad := cfg
		bad.PolicyGeneration++
		if _, _, err := Collect(context.Background(), s, c, bad, time.Now); err == nil {
			t.Fatal("wrong policy generation accepted")
		}
	})
	t.Run("byte-bound", func(t *testing.T) {
		bad := cfg
		bad.MaxBytes = int64(len(row) - 1)
		if _, _, err := Collect(context.Background(), s, c, bad, time.Now); err == nil {
			t.Fatal("byte bound overrun accepted")
		}
	})
	t.Run("valid-row-then-partial-tail", func(t *testing.T) {
		s2 := *s
		s2.data = map[string][]byte{"gen-1": append([]byte("{}\n"), append(row, []byte("\n{\"kind\":\"phorvex.decision\"")...)...)}
		s2.manifest.Segments[0].Size = int64(len(s2.data["gen-1"]))
		got, summary, err := Collect(context.Background(), &s2, c, cfg, time.Now)
		if err == nil || len(got) != 1 || summary.Receipts != 1 {
			t.Fatalf("receipts=%d summary=%+v err=%v", len(got), summary, err)
		}
	})
	t.Run("canceled-source", func(t *testing.T) {
		s2 := *s
		s2.err = context.Canceled
		if _, summary, err := Collect(context.Background(), &s2, c, cfg, time.Now); !errors.Is(err, context.Canceled) || summary.ErrorClass != "canceled" {
			t.Fatalf("summary=%+v err=%v", summary, err)
		}
	})
}

func TestMixedValidAndMissingRichTraceInvalidatesAttribution(t *testing.T) {
	s, c, cfg, row := baseFixture(t)
	var obj map[string]any
	if err := json.Unmarshal(row, &obj); err != nil {
		t.Fatal(err)
	}
	delete(obj, "decisionTrace")
	raw, _ := json.Marshal(obj)
	s.data["gen-1"] = append([]byte("{}\n"), append(row, append([]byte{'\n'}, append(raw, '\n')...)...)...)
	s.manifest.Segments[0].Size = int64(len(s.data["gen-1"]))
	got, summary, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err == nil || len(got) != 1 || summary.Status != "invalid" || summary.Receipts != 1 {
		t.Fatalf("receipts=%d summary=%+v err=%v", len(got), summary, err)
	}
}

func TestLaterSourceFailureRetainsEarlierCompleteReceipt(t *testing.T) {
	s, c, cfg, row := baseFixture(t)
	second := bytesReplaceDecisionID(row, "decision-2")
	s.data["gen-1"] = append([]byte("{}\n"), append(row, append([]byte{'\n'}, append(second, '\n')...)...)...)
	s.manifest.Segments[0].Size = int64(len(s.data["gen-1"]))
	failAt := c.Offset + int64(len(row)) + 1
	got, summary, err := Collect(context.Background(), &lateFailureSource{memorySource: s, failAt: failAt}, c, cfg, time.Now)
	if !errors.Is(err, context.Canceled) || len(got) != 1 || summary.Receipts != 1 || summary.BytesRead != failAt-c.Offset || summary.ErrorClass != "canceled" {
		t.Fatalf("receipts=%d summary=%+v err=%v", len(got), summary, err)
	}
}

func bytesReplaceDecisionID(raw []byte, id string) []byte {
	return []byte(strings.Replace(string(raw), `"decisionID":"decision-1"`, `"decisionID":"`+id+`"`, 1))
}

func TestRotationContinuityAndMissingCursorRefusal(t *testing.T) {
	s, c, cfg, row := baseFixture(t)
	prefix := []byte("{}\n")
	s.data = map[string][]byte{"gen-1": append(prefix, append(row, '\n')...), "gen-2": []byte{}}
	s.manifest.Segments = []audittransport.Segment{{ID: "live", Generation: "gen-2", Size: 0, Anchor: "e3b0c44298fc1c149afbf4c8996fb924"}, {ID: "backup-1", Generation: "gen-1", Size: int64(len(s.data["gen-1"])), Anchor: "22222222222222222222222222222222"}}
	got, _, err := Collect(context.Background(), s, c, cfg, time.Now)
	if err != nil || len(got) != 1 {
		t.Fatalf("rotation receipts=%d err=%v", len(got), err)
	}
	s.manifest.Segments = s.manifest.Segments[:1]
	if _, _, err = Collect(context.Background(), s, c, cfg, time.Now); err == nil {
		t.Fatal("lost cursor generation accepted")
	}
}

func TestCursorDecoderRejectsDuplicateAndUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"schemaVersion":"phorvex.installed-audit-cursor.v1","schemaVersion":"phorvex.installed-audit-cursor.v1"}`,
		`{"schemaVersion":"phorvex.installed-audit-cursor.v1","unknown":true}`,
	} {
		if _, err := DecodeCursor([]byte(raw)); err == nil {
			t.Fatalf("invalid cursor accepted: %s", raw)
		}
	}
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk})
}

func write0600(t *testing.T, path string, b []byte) string {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestActualMutualTLSTransportCursorAndObservation(t *testing.T) {
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "observer-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caRaw, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caRaw)
	if err != nil {
		t.Fatal(err)
	}
	caFile := write0600(t, filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caRaw}))
	serverCert, serverKey := testLeaf(t, ca, caKey, "audit-source.test")
	clientCert, clientKey := testLeaf(t, ca, caKey, "audit-client.test")
	sc := write0600(t, filepath.Join(dir, "server.pem"), serverCert)
	sk := write0600(t, filepath.Join(dir, "server.key"), serverKey)
	cc := write0600(t, filepath.Join(dir, "client.pem"), clientCert)
	ck := write0600(t, filepath.Join(dir, "client.key"), clientKey)
	auditPath := filepath.Join(dir, "audit", "live.jsonl")
	if err = os.MkdirAll(filepath.Dir(auditPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(auditPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ref, _ := material(t)
	manifest := model.DecisionParameterManifest{SchemaVersion: model.DecisionParameterManifestV1, ID: "test-manifest", Parameters: []model.DecisionParameter{{Name: "grace", Group: "native", Unit: "seconds", Domain: "[1,300]", Default: 30, Source: "fixture", Provenance: model.ParameterConfigurationBound, Limitations: "synthetic", DependencyGroup: "native"}}}
	overrides := model.EffectivePolicyOverrides{SchemaVersion: model.DecisionPolicyOverridesV1, ID: "bench/policy@policy-uid:7", Values: []model.EffectivePolicyParameter{{Name: "grace", Unit: "seconds", Present: true, Value: 30}}}
	store, err := audit.NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Store(&ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	serverCfg := audittransport.ServerConfig{AuditPath: auditPath, CertFile: sc, KeyFile: sk, CAFile: caFile, ClientDNSName: "audit-client.test", MaxBackups: 2}
	ts := httptest.NewUnstartedServer(serverCfg.Handler())
	ts.TLS = serverCfg.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := CaptureCursor(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	at := cursor.CapturedAt.Add(time.Nanosecond)
	row := producerRow(t, at, ref)
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	payload := append(row, '\n')
	for i := 0; i < 3; i++ {
		payload = append(payload, []byte(`{"padding":"`)...)
		payload = append(payload, []byte(strings.Repeat("x", 350000))...)
		payload = append(payload, []byte("\"}\n")...)
	}
	if _, err = f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := Config{PolicyNamespace: "bench", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 7, TargetNamespace: "bench", TargetName: "target", TargetUID: "pod-uid", ExpectedTraceSchema: model.DecisionTraceSchemaV2, ExpectedBrainImage: "registry.test/phorvex@sha256:abc", ExpectedGitSHA: "abcdef1", ExpectedManifestID: ref.ManifestID, ExpectedManifestHash: ref.ManifestHash, ExpectedOverridesHash: ref.PolicyOverridesHash, NotBefore: cursor.CapturedAt.Add(time.Nanosecond), NotAfter: at.Add(time.Nanosecond)}
	receipts, summary, err := Collect(context.Background(), client, cursor, cfg, time.Now)
	if err != nil || len(receipts) != 1 || summary.Status != "complete" {
		t.Fatalf("mTLS observation receipts=%d summary=%+v err=%v", len(receipts), summary, err)
	}
	broken := &failAfterOneTransportChunk{Source: client, cursorSize: cursor.Offset}
	partial, partialSummary, partialErr := Collect(context.Background(), broken, cursor, cfg, time.Now)
	if !errors.Is(partialErr, context.Canceled) || len(partial) != 1 || partialSummary.Receipts != 1 || partialSummary.BytesRead != audittransport.ChunkBytes {
		t.Fatalf("mTLS partial receipts=%d summary=%+v err=%v", len(partial), partialSummary, partialErr)
	}
	bad, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "wrong.test", CertFile: cc, KeyFile: ck, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CaptureCursor(context.Background(), bad); err == nil {
		t.Fatal("wrong TLS server identity accepted")
	}
}
