package brainclient_test

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainclient"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/brainsvc"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/wire"
)

var testConfig = brainapi.DecisionConfig{Engine: "p1-coverage", ReconProfile: "ucw-recon", GPUEnvelopeMax: 1}

// serve runs brain behind a gRPC server on an in-memory listener and returns a
// connection to it. interceptor may be nil.
func serve(t *testing.T, brain brainapi.Brain, configSHA256 string, interceptor grpc.UnaryServerInterceptor) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	var opts []grpc.ServerOption
	if interceptor != nil {
		opts = append(opts, grpc.UnaryInterceptor(interceptor))
	}
	srv := grpc.NewServer(opts...)
	brainpb.RegisterBrainServiceServer(srv, brainsvc.NewServer(brain, configSHA256))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///brain",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func connect(t *testing.T, brain brainapi.Brain, interceptor grpc.UnaryServerInterceptor) *brainclient.Client {
	t.Helper()
	client, err := brainclient.New(context.Background(), serve(t, brain, testConfig.SHA256(), interceptor), brainclient.Options{Config: testConfig})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type memorySink struct {
	mu    sync.Mutex
	items []mathlab.Pending
}

func (m *memorySink) Enqueue(p mathlab.Pending) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, p)
	return true
}

func allClocks(d time.Duration) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, v := range model.LiveExposureVariables {
		out[v] = d
	}
	return out
}

// fleet is the Math Lab fixture tick: a measured-load pod with a trusted event, a
// pod without load telemetry and a pod whose kv-reset the capability gate refuses.
func fleet() []*model.WorkloadView {
	mk := func(name string, exposure time.Duration) *model.WorkloadView {
		return &model.WorkloadView{
			Pod:                model.Pod{Namespace: "vllm", Name: name, UID: "uid-" + name, DesiredReplicas: 3, ReadyReplicas: 3, Ready: true, MountedSecrets: []string{"creds"}},
			Phase:              model.PhaseWarm,
			BlastRadius:        0.5,
			Neighbors:          []model.NeighborRef{{Key: "vllm/crown", Value: 4}},
			ExposureByVariable: allClocks(exposure),
			Telemetry:          model.Telemetry{ReqRate: model.PresentSignal(20, "fixture")},
		}
	}
	hot := mk("hot", 3*time.Hour)
	hot.Events = []model.SecurityEventInfo{{Name: "ev", UID: "ev-1", Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Trust: "trusted", Age: 15 * time.Second}}
	unmeasured := mk("unmeasured", 3*time.Hour)
	unmeasured.Telemetry = model.Telemetry{}
	gated := mk("gated", 3*time.Hour)
	gated.Pod.Labels = map[string]string{"data-class": "restricted"}
	return []*model.WorkloadView{hot, unmeasured, gated}
}

func fixturePolicy() model.Policy {
	return model.Policy{Tenant: "vllm", Namespace: "vllm", PolicyName: "vllm-defense", PolicyUID: "pol-uid", PolicyGeneration: 7,
		Lambda: 0.5, NormSparsity: 0.4, FlowDisruption: 0.6, CostCeiling: 1.2, WeightSecrets: 0.8, BlastRadiusFromGraph: true,
		MaxMovesPerTick: 1, ProactiveFloor: 15 * time.Minute, AntiOverRotationWindow: 90 * time.Second, MinAvailableReplicas: 1,
		P99Ms: 500, TraceEnabled: true, BrainImage: "img:test", GitSHA: "deadbeef", TickID: "tick-1",
		AssetWeights:   model.AssetLabelWeights{ByLabel: map[string]map[string]float64{"data-class": {"restricted": 1}}, Default: 0.4},
		EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true, model.ActionKVReset: true}}
}

var fixtureEpoch = model.PolicyEpoch{Namespace: "vllm", Name: "vllm-defense", UID: "pol-uid", Generation: 7}

// question is one gate question as the dispatcher's gate received it.
type question struct {
	Gate             string
	Asset            string
	HasEventEvidence bool
	Action           model.Action
	CoverKeys        []string
}

type gateLog struct {
	mu        sync.Mutex
	questions []question
}

func (g *gateLog) add(gate string, v *model.WorkloadView, a model.Action, keys []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(keys) == 0 {
		keys = nil
	}
	g.questions = append(g.questions, question{gate, v.Pod.Namespace + "/" + v.Pod.Name, v.HasEventEvidence, a, append([]string(nil), keys...)})
}

func (g *gateLog) take() []question {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.questions
	g.questions = nil
	return out
}

func verdict(v *model.WorkloadView, a model.Action) *model.Eligibility {
	switch {
	case v.Pod.Name == "gated" && a == model.ActionKVReset:
		return &model.Eligibility{Excluded: true, Kind: "capability-unsupported", Detail: "fixture: no serving stack"}
	case v.Pod.Name == "unmeasured" && a == model.ActionRotate:
		return &model.Eligibility{RBACUnknown: true, Detail: "fixture: access review errored"}
	}
	return nil
}

func (g *gateLog) gate() brainapi.Gate {
	return brainapi.Gate{
		Capability: func(v *model.WorkloadView, a model.Action, keys []string) *model.Eligibility {
			g.add("capability", v, a, keys)
			return verdict(v, a)
		},
		ShadowCapability: func(v *model.WorkloadView, a model.Action, keys []string) *model.Eligibility {
			g.add("shadow", v, a, keys)
			return verdict(v, a)
		},
		FailureExclusion: func(v *model.WorkloadView, a model.Action) (string, bool) {
			g.add("failure", v, a, nil)
			if v.Pod.Name == "hot" && a == model.ActionKVReset {
				return "fixture: open cooldown", true
			}
			return "", false
		},
	}
}

// fixtureAuthority is the dispatcher's observed-outcome authority: it never
// authenticates an observation, so admission stops at its answer.
type fixtureAuthority struct{ asked int }

func (*fixtureAuthority) Source() string { return model.ScopedSessionCapability }
func (a *fixtureAuthority) AuthorizeObservation(model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	a.asked++
	return model.PersistenceOperationBinding{}, false
}

// side is one way of running the brain: in process, or behind the gRPC service.
type side struct {
	brain brainapi.Brain
	ce    *decision.CoverageEngine
	sink  *memorySink
	gates gateLog
}

func newEngineSide(t *testing.T) (*decision.CoverageEngine, *memorySink, *brainsvc.Local) {
	t.Helper()
	ce := decision.NewCoverageEngine()
	sink := &memorySink{}
	recorder, err := mathlab.NewRecorder(mathlab.Config{Policies: []string{"vllm/vllm-defense"}, GPUEnvelopeMax: cost.GPUEnvelopeMax(),
		ProcessConfig: map[string]string{"gpu-envelope-max": "1"}}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ce, sink, brainsvc.NewLocal(ce, recorder)
}

func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func window(b []byte, at int) []byte {
	return b[max(0, at-200):min(len(b), at+200)]
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// recordingContent decodes a Math Lab stream (inputs, outcome, final decisions)
// and re-encodes it deterministically.
func recordingContent(t *testing.T, stream []byte) []byte {
	t.Helper()
	dec := gob.NewDecoder(bytes.NewReader(stream))
	var inputs mathlab.Inputs
	var outcome mathlab.Outcome
	var final mathlab.Final
	for _, v := range []any{&inputs, &outcome, &final} {
		if err := dec.Decode(v); err != nil {
			t.Fatalf("recording stream: %v", err)
		}
	}
	raw, err := wire.Encode([]any{inputs, outcome, final})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestRemoteBrainMatchesInProcess drives the same ticks through the in-process
// brain and the gRPC service and requires identical decisions, gate questions,
// event-evidence stamps, learning state and Math Lab recordings.
func TestRemoteBrainMatchesInProcess(t *testing.T) {
	recon.Registry.SetDefault("ucw-recon")
	localCE, localSink, localBrain := newEngineSide(t)
	remoteCE, remoteSink, remoteBrain := newEngineSide(t)
	client := connect(t, remoteBrain, nil)
	local := &side{brain: localBrain, ce: localCE, sink: localSink}
	remote := &side{brain: client, ce: remoteCE, sink: remoteSink}
	sides := []*side{local, remote}

	// Each engine names its own process epoch; reports carry it once an authority is set.
	localEpoch, remoteEpoch := []byte(localBrain.ScopedOutcomeProcessEpochID()), []byte(client.ScopedOutcomeProcessEpochID())
	if len(remoteEpoch) == 0 || string(remoteEpoch) != remoteBrain.ScopedOutcomeProcessEpochID() {
		t.Fatalf("client reports process epoch %q, brain %q", remoteEpoch, remoteBrain.ScopedOutcomeProcessEpochID())
	}
	same := func(what string, l, r []byte) {
		t.Helper()
		r = bytes.ReplaceAll(r, remoteEpoch, localEpoch)
		if !bytes.Equal(l, r) {
			t.Fatalf("%s differs at byte %d:\nlocal:  %q\nremote: %q", what, firstDiff(l, r), window(l, firstDiff(l, r)), window(r, firstDiff(l, r)))
		}
	}
	if client.Name() != localBrain.Name() || client.GatesCandidates() != localBrain.GatesCandidates() ||
		client.LearnsRotationCost() != localBrain.LearnsRotationCost() || client.PersistenceObservations() != localBrain.PersistenceObservations() {
		t.Fatal("client reports other capabilities than the brain")
	}

	pol := fixturePolicy()
	spec := v1alpha1.PhorvexPolicySpec{}
	base := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	authority := &fixtureAuthority{}
	stamped := false
	for tick := 0; tick < 5; tick++ {
		now := base.Add(time.Duration(tick) * 10 * time.Second)
		decisions := make([][]model.Decision, len(sides))
		views := make([][]*model.WorkloadView, len(sides))
		for i, s := range sides {
			s.ce.Now = func() time.Time { return now }
			s.brain.RegisterOwnerEpochs([]model.PolicyEpoch{fixtureEpoch})
			s.brain.SetPersistenceAuthority(authority)
			s.brain.SetCostCalibrationFrozen(false)

			shadow, supported, err := s.brain.DecideShadow(brainapi.DecideRequest{Views: fleet(), Policy: pol, Gate: s.gates.gate()})
			if !supported {
				t.Fatal("shadow evaluation unsupported")
			}
			decisions[i] = append(shadow, model.Decision{Reason: "shadow error: " + errorText(err)})

			views[i] = fleet()
			committed, rec, err := s.brain.Decide(brainapi.DecideRequest{Views: views[i], Policy: pol, Gate: s.gates.gate(),
				Capture: &brainapi.Capture{Spec: spec, CapturedAt: now}})
			decisions[i] = append(decisions[i], committed...)
			decisions[i] = append(decisions[i], model.Decision{Reason: "error: " + errorText(err)})
			final := append([]model.Decision(nil), committed...)
			for j := range final {
				final[j].DryRun = true
			}
			rec.Finalize(final)
			rec.Close()
			s.brain.ObserveRotation(pol.Owner(), fleet()[0], 0.35+0.02*float64(tick))
			s.brain.RetainStageClock(pol.Owner(), map[string]struct{}{"vllm/hot": {}, "vllm/gated": {}})
		}
		same(fmt.Sprintf("tick %d decisions", tick), mustJSON(t, decisions[0]), mustJSON(t, decisions[1]))
		if l, r := local.gates.take(), remote.gates.take(); !reflect.DeepEqual(l, r) || len(l) == 0 {
			t.Fatalf("tick %d gate questions differ:\nlocal:  %+v\nremote: %+v", tick, l, r)
		}
		if !reflect.DeepEqual(views[0], views[1]) {
			t.Fatalf("tick %d views after the evaluation differ:\nlocal:  %s\nremote: %s", tick, mustJSON(t, views[0]), mustJSON(t, views[1]))
		}
		for _, v := range views[1] {
			stamped = stamped || v.HasEventEvidence
		}
		same(fmt.Sprintf("tick %d calibration", tick), mustJSON(t, local.brain.CalibrationState()), mustJSON(t, remote.brain.CalibrationState()))
	}
	if !stamped {
		t.Fatal("fixture never stamped event evidence; the stamp path is untested")
	}

	client.Flush()
	if len(localSink.items) != 5 || len(remoteSink.items) != 5 {
		t.Fatalf("recordings: local %d, remote %d", len(localSink.items), len(remoteSink.items))
	}
	for i := range localSink.items {
		l, r := localSink.items[i], remoteSink.items[i]
		if !r.Header.Finalized {
			t.Fatalf("remote recording %d was not finalized", i)
		}
		// Gob writes maps in iteration order, so the streams are compared by content.
		same(fmt.Sprintf("recording %d content", i), recordingContent(t, l.Stream), recordingContent(t, bytes.ReplaceAll(r.Stream, remoteEpoch, localEpoch)))
		same(fmt.Sprintf("recording %d selection", i), mustJSON(t, l.Header.Selected), mustJSON(t, r.Header.Selected))
	}

	alternatives := make([][]byte, len(sides))
	for i, s := range sides {
		alternative, found := s.brain.SelectAlternative(pol.Owner(), "vllm/hot", model.ActionRotate)
		reserved := found && s.brain.ReserveAlternative(pol.Owner(), "vllm/hot", model.ActionRotate, alternative.Action)
		alternatives[i] = mustJSON(t, []any{alternative, found, reserved})
	}
	same("alternative", alternatives[0], alternatives[1])

	observation := model.PersistenceObservation{SchemaVersion: "v1", Source: model.ScopedSessionCapability, EvidenceID: "evidence-1",
		Policy: fixtureEpoch, OperationID: "op-1", Action: model.ActionRotate, Outcome: model.PersistenceHeld,
		ObservationStart: base, ObservationEnd: base.Add(time.Minute)}
	results := make([][]byte, len(sides))
	for i, s := range sides {
		o := observation
		o.ProcessEpochID = s.brain.ScopedOutcomeProcessEpochID()
		results[i] = mustJSON(t, []any{
			s.brain.AdmitPersistenceObservation(o),
			s.brain.RecordScopedOutcomeUnavailable(fixtureEpoch, "fixture: observer offline"),
		})
	}
	same("persistence results", results[0], results[1])

	forgotten := make([]int, len(sides))
	retired := make([]error, len(sides))
	for i, s := range sides {
		forgotten[i] = s.brain.ForgetOwner(pol.Owner())
		_, rec, err := s.brain.Decide(brainapi.DecideRequest{Views: fleet(), Policy: pol, Gate: s.gates.gate()})
		rec.Close()
		retired[i] = err
	}
	if forgotten[0] != forgotten[1] {
		t.Fatalf("stores cleared: local %d, remote %d", forgotten[0], forgotten[1])
	}
	if errors.Is(retired[0], brainapi.ErrOwnerRetired) != errors.Is(retired[1], brainapi.ErrOwnerRetired) || errorText(retired[0]) != errorText(retired[1]) {
		t.Fatalf("retired-owner evaluation: local %v, remote %v", retired[0], retired[1])
	}
}

// checkedOptimizer returns a fixed evaluation error.
type checkedOptimizer struct{ err error }

func (checkedOptimizer) Name() string { return "test-checked" }
func (checkedOptimizer) Decide([]*model.WorkloadView, model.Policy) []model.Decision {
	return nil
}
func (o checkedOptimizer) DecideChecked([]*model.WorkloadView, model.Policy) ([]model.Decision, error) {
	return nil, o.err
}

func TestEvaluationErrorsKeepTheirIdentity(t *testing.T) {
	collision := model.CrossBlockCollision{Key: "recon/k", ExistingBlock: "vllm/a", ConflictingBlock: "vllm/b"}
	for _, tc := range []struct {
		name  string
		err   error
		check func(error) bool
	}{
		{"owner retired", fmt.Errorf("tick: %w", brainapi.ErrOwnerRetired), func(err error) bool { return errors.Is(err, brainapi.ErrOwnerRetired) }},
		{"collision value", fmt.Errorf("assemble: %w", collision), func(err error) bool {
			var got model.CrossBlockCollision
			return errors.As(err, &got) && got == collision
		}},
		{"collision pointer", &collision, func(err error) bool {
			var got model.CrossBlockCollision
			return errors.As(err, &got) && got == collision
		}},
		{"other", errors.New("structurally invalid action set"), func(err error) bool {
			var got model.CrossBlockCollision
			return err != nil && !errors.Is(err, brainapi.ErrOwnerRetired) && !errors.As(err, &got)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := connect(t, brainsvc.NewLocal(checkedOptimizer{tc.err}, nil), nil)
			_, rec, err := client.Decide(brainapi.DecideRequest{})
			rec.Close()
			if !tc.check(err) {
				t.Fatalf("remote error %v lost its identity", err)
			}
			if err.Error() != tc.err.Error() {
				t.Fatalf("remote error message %q, want %q", err, tc.err)
			}
		})
	}
}

func TestHelloRefusesAnotherContractOrConfiguration(t *testing.T) {
	conn := serve(t, brainsvc.NewLocal(decision.NewCoverageEngine(), nil), testConfig.SHA256(), nil)
	other := testConfig
	other.FlowResidualClasses = []string{"extra"}
	_, err := brainclient.New(context.Background(), conn, brainclient.Options{Config: other})
	if status.Code(errors.Unwrap(err)) != codes.FailedPrecondition {
		t.Fatalf("mismatched configuration accepted or refused oddly: %v", err)
	}
	reordered := testConfig
	reordered.FlowResidualClasses = []string{" b", "a"}
	sameSet := testConfig
	sameSet.FlowResidualClasses = []string{"a", "b"}
	if reordered.SHA256() != sameSet.SHA256() {
		t.Fatal("flow-residual classes must compare as a set")
	}
	resp, err := brainpb.NewBrainServiceClient(conn).Hello(context.Background(),
		&brainpb.HelloRequest{ContractVersion: brainapi.ContractVersion + 1, DecisionConfigSha256: testConfig.SHA256()})
	if status.Code(err) != codes.FailedPrecondition || resp != nil {
		t.Fatalf("another contract version accepted: %v", err)
	}
}

// TestUnacknowledgedOwnerRemovalIsReplayedBeforeTheNextEvaluation: a removal the
// brain never saw would let it keep deciding for a retired owner.
func TestUnacknowledgedOwnerRemovalIsReplayedBeforeTheNextEvaluation(t *testing.T) {
	var mu sync.Mutex
	failForget := true
	var calls []string
	interceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		mu.Lock()
		method := info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:]
		fail := failForget && method == "ForgetOwner"
		calls = append(calls, fmt.Sprintf("%s:%v", method, fail))
		mu.Unlock()
		if fail {
			return nil, status.Error(codes.Unavailable, "fixture: brain restarting")
		}
		return handler(ctx, req)
	}
	client := connect(t, brainsvc.NewLocal(checkedOptimizer{}, nil), interceptor)
	if cleared := client.ForgetOwner("uid:gone"); cleared != 0 {
		t.Fatalf("unacknowledged removal reported %d stores cleared", cleared)
	}
	if _, rec, err := client.Decide(brainapi.DecideRequest{}); err == nil || !strings.Contains(err.Error(), "owner removal not acknowledged") {
		rec.Close()
		t.Fatalf("evaluation ran before the removal was acknowledged: %v", err)
	}
	mu.Lock()
	failForget = false
	mu.Unlock()
	_, rec, err := client.Decide(brainapi.DecideRequest{})
	rec.Close()
	if err != nil {
		t.Fatalf("evaluation after the replayed removal: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"Hello:false", "ForgetOwner:true", "ForgetOwner:true", "ForgetOwner:false"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

// TestProvenanceAndRejectedRecordsMatchInProcess pins the two audit calls: the
// parameter provenance and a rejected tick's M99 records come from the brain,
// and read the same remotely as in process, a policy's refusal included.
func TestProvenanceAndRejectedRecordsMatchInProcess(t *testing.T) {
	_, _, local := newEngineSide(t)
	client := connect(t, local, nil)
	pol := fixturePolicy()
	invalid := fixturePolicy()
	invalid.WeightSecrets = -1

	for name, p := range map[string]model.Policy{"valid": pol, "invalid": invalid} {
		got, gotErr := client.ParameterSet(p)
		want, wantErr := local.ParameterSet(p)
		if errorText(gotErr) != errorText(wantErr) || !bytes.Equal(mustJSON(t, got), mustJSON(t, want)) {
			t.Fatalf("%s parameter set = %s (%v), want %s (%v)", name, mustJSON(t, got), gotErr, mustJSON(t, want), wantErr)
		}
	}
	if set, err := client.ParameterSet(pol); err != nil || set.Reference == nil {
		t.Fatalf("a valid policy has no parameter set: %+v, %v", set, err)
	}

	// A view carrying a qualified M99 outcome is recorded uncontainable.
	protected := fleet()[0]
	pol.TrustBoundaryReady = true
	key := protected.Pod.Namespace + "/" + protected.Pod.Name
	outcome := model.ProtectedOutcome{ID: "r", PolicyUID: pol.PolicyUID, DecisionAsset: key, DecisionAssetUID: protected.Pod.UID,
		ProtectedAsset: "dataset", Version: "v1", Portion: "undisclosed-records", Property: "confidentiality", Outcome: "unauthorized-disclosure",
		ClassBasis: "protected customer data", ScopeBasis: "this scope contains every relevant copy", LossState: "at-risk",
		StateBasis: "trusted detector confirms preventable exfiltration", RequiredKeys: []string{"e"}, MappingComplete: true,
		MappingBasis: "invalidation interrupts this scoped channel"}
	protected.OutcomeEvents = []model.SecurityEventInfo{{Name: "detector-evidence", Trust: "trusted", CreatorIdentity: "system:serviceaccount:vllm:detector",
		ResolvedTargets: []string{key}, TargetsPod: true, Outcomes: []model.ProtectedOutcome{outcome}}}
	if !model.HasQualifiedOutcome(protected, pol) {
		t.Fatal("fixture: the view carries no qualified outcome")
	}
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	for name, p := range map[string]model.Policy{"valid": pol, "invalid": invalid} {
		tick := brainapi.RejectedTick{Views: []*model.WorkloadView{protected, fleet()[1]}, Policy: p, Reason: "cross-block-collision", Now: now}
		got, gotErr := client.RejectedDecisions(tick)
		want, wantErr := local.RejectedDecisions(tick)
		if errorText(gotErr) != errorText(wantErr) || !bytes.Equal(mustJSON(t, got), mustJSON(t, want)) {
			t.Fatalf("%s rejected records = %s (%v), want %s (%v)", name, mustJSON(t, got), gotErr, mustJSON(t, want), wantErr)
		}
	}
	records, err := client.RejectedDecisions(brainapi.RejectedTick{Views: []*model.WorkloadView{protected}, Policy: pol, Reason: "cross-block-collision", Now: now})
	if err != nil || len(records) != 1 || records[0].Existential == nil || records[0].Existential.Result != "uncontainable" || records[0].ParameterSet == nil {
		t.Fatalf("rejected records = %+v, %v", records, err)
	}
}
