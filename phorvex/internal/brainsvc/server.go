package brainsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/wire"
)

// recordingTTL bounds how long the server keeps a recording the dispatcher never
// closed (for example after the dispatcher restarted mid-tick).
const recordingTTL = 15 * time.Minute

// Server serves a brainapi.Brain over gRPC (brainpb.BrainService).
type Server struct {
	brainpb.UnimplementedBrainServiceServer

	brain        brainapi.Brain
	configSHA256 string
	snapshots    audittransport.MathLabSnapshotSource
	now          func() time.Time

	mu         sync.Mutex
	recordings map[string]heldRecording

	// authorityMu serializes authority changes with admissions, so the answer the
	// dispatcher resolved is the one the brain consults for that observation.
	authorityMu sync.Mutex
	authority   *remoteAuthority
}

type heldRecording struct {
	rec     brainapi.Recording
	expires time.Time
}

var _ brainpb.BrainServiceServer = (*Server)(nil)

// NewServer serves brain. configSHA256 is this process's DecisionConfig hash; a
// client presenting another is refused.
func NewServer(brain brainapi.Brain, configSHA256 string, options ...ServerOption) *Server {
	s := &Server{brain: brain, configSHA256: configSHA256, now: time.Now, recordings: map[string]heldRecording{}}
	for _, option := range options {
		option(s)
	}
	return s
}

func (s *Server) Hello(_ context.Context, req *brainpb.HelloRequest) (*brainpb.HelloResponse, error) {
	if req.GetContractVersion() != brainapi.ContractVersion {
		return nil, status.Errorf(codes.FailedPrecondition, "brain contract version %d, client %d", brainapi.ContractVersion, req.GetContractVersion())
	}
	if req.GetDecisionConfigSha256() != s.configSHA256 {
		return nil, status.Errorf(codes.FailedPrecondition, "decision configuration differs: brain %s, client %s", s.configSHA256, req.GetDecisionConfigSha256())
	}
	return &brainpb.HelloResponse{
		ContractVersion:             brainapi.ContractVersion,
		DecisionConfigSha256:        s.configSHA256,
		Name:                        s.brain.Name(),
		GatesCandidates:             s.brain.GatesCandidates(),
		LearnsRotationCost:          s.brain.LearnsRotationCost(),
		PersistenceObservations:     s.brain.PersistenceObservations(),
		ScopedOutcomeProcessEpochId: s.brain.ScopedOutcomeProcessEpochID(),
		SnapshotsEnabled:            s.snapshots != nil,
	}, nil
}

func (s *Server) Decide(stream brainpb.BrainService_DecideServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "decide stream must open with start")
	}
	var views []*model.WorkloadView
	var pol model.Policy
	if err := wire.Decode(start.GetViews(), &views); err != nil {
		return status.Errorf(codes.InvalidArgument, "views: %v", err)
	}
	if err := wire.Decode(start.GetPolicy(), &pol); err != nil {
		return status.Errorf(codes.InvalidArgument, "policy: %v", err)
	}
	req := brainapi.DecideRequest{Views: views, Policy: pol}
	if raw := start.GetCapture(); len(raw) > 0 {
		var capture brainapi.Capture
		if err := wire.Decode(raw, &capture); err != nil {
			return status.Errorf(codes.InvalidArgument, "capture: %v", err)
		}
		req.Capture = &capture
	}
	asker := &gateAsker{stream: stream, index: viewIndex(views)}
	if start.GetCapabilityGate() {
		req.Gate.Capability = asker.capability(false)
	}
	if start.GetShadowCapabilityGate() {
		req.Gate.ShadowCapability = asker.capability(true)
	}
	if start.GetFailureGate() {
		req.Gate.FailureExclusion = asker.failure
	}

	result := &brainpb.DecideResult{}
	var decisions []model.Decision
	var decideErr error
	if start.GetShadow() {
		decisions, result.Supported, decideErr = s.brain.DecideShadow(req)
	} else {
		var rec brainapi.Recording
		decisions, rec, decideErr = s.brain.Decide(req)
		if asker.err != nil {
			rec.Close()
		} else {
			result.RecordingId = s.hold(rec)
		}
		result.Supported = true
		result.HasEventEvidence = make([]bool, len(views))
		for i, v := range views {
			result.HasEventEvidence[i] = v != nil && v.HasEventEvidence
		}
	}
	if asker.err != nil {
		// The client is gone; every question after the failure was answered closed.
		return asker.err
	}
	if result.Decisions, err = wire.Encode(decisions); err != nil {
		s.release(result.RecordingId)
		return status.Errorf(codes.Internal, "decisions: %v", err)
	}
	result.Error = decideError(decideErr)
	if err := stream.Send(&brainpb.DecideResponse{Message: &brainpb.DecideResponse_Result{Result: result}}); err != nil {
		s.release(result.RecordingId)
		return err
	}
	return nil
}

// viewIndex keys views by namespace/name, the identity the engine also uses; a
// shadow evaluation hands the gate per-view copies, so pointers do not match.
func viewIndex(views []*model.WorkloadView) map[string]uint32 {
	out := make(map[string]uint32, len(views))
	for i, v := range views {
		if v != nil {
			out[viewKey(v)] = uint32(i)
		}
	}
	return out
}

func viewKey(v *model.WorkloadView) string { return v.Pod.Namespace + "/" + v.Pod.Name }

// gateAsker carries the brain's gate questions to the client on the Decide stream.
// The engine asks synchronously from the stream's goroutine, so each question is
// sent and answered in generation order. Once the stream fails, every further
// question is answered closed: excluded, never eligible.
type gateAsker struct {
	stream brainpb.BrainService_DecideServer
	index  map[string]uint32
	next   uint64
	err    error
}

// GateUnavailable is the exclusion kind of a gate question the brain could not
// put to the dispatcher.
const GateUnavailable = "brain-gate-unavailable"

func gateClosed(detail string) *model.Eligibility {
	return &model.Eligibility{Excluded: true, Kind: GateUnavailable, Detail: detail}
}

func (a *gateAsker) capability(shadow bool) func(*model.WorkloadView, model.Action, []string) *model.Eligibility {
	return func(v *model.WorkloadView, action model.Action, coverKeys []string) *model.Eligibility {
		if a.err != nil {
			return gateClosed("capability question could not be sent")
		}
		idx, ok := a.index[viewKey(v)]
		if !ok {
			return gateClosed("capability question names an asset outside the request")
		}
		a.next++
		q := &brainpb.CapabilityQuestion{Id: a.next, Shadow: shadow, ViewIndex: idx, HasEventEvidence: v.HasEventEvidence,
			Action: string(action), CoverKeys: coverKeys}
		if a.err = a.stream.Send(&brainpb.DecideResponse{Message: &brainpb.DecideResponse_Capability{Capability: q}}); a.err != nil {
			return gateClosed("capability question could not be sent")
		}
		msg, err := a.stream.Recv()
		answer := msg.GetCapability()
		switch {
		case err != nil:
			a.err = err
		case answer == nil || answer.GetId() != q.GetId():
			a.err = status.Error(codes.InvalidArgument, "capability answer out of order")
		}
		if a.err != nil {
			return gateClosed("capability answer unavailable")
		}
		if answer.GetClean() {
			return nil
		}
		return &model.Eligibility{Excluded: answer.GetExcluded(), Kind: answer.GetKind(), Detail: answer.GetDetail(), RBACUnknown: answer.GetRbacUnknown()}
	}
}

const failureClosed = GateUnavailable + ": failure cooldown unknown"

func (a *gateAsker) failure(v *model.WorkloadView, action model.Action) (string, bool) {
	if a.err != nil {
		return failureClosed, true
	}
	idx, ok := a.index[viewKey(v)]
	if !ok {
		return failureClosed, true
	}
	a.next++
	q := &brainpb.FailureQuestion{Id: a.next, ViewIndex: idx, HasEventEvidence: v.HasEventEvidence, Action: string(action)}
	if a.err = a.stream.Send(&brainpb.DecideResponse{Message: &brainpb.DecideResponse_Failure{Failure: q}}); a.err != nil {
		return failureClosed, true
	}
	msg, err := a.stream.Recv()
	answer := msg.GetFailure()
	switch {
	case err != nil:
		a.err = err
	case answer == nil || answer.GetId() != q.GetId():
		a.err = status.Error(codes.InvalidArgument, "failure answer out of order")
	}
	if a.err != nil {
		return failureClosed, true
	}
	return answer.GetDetail(), answer.GetExcluded()
}

// decideError reports an evaluation error in a form the client turns back into the
// same error values (ErrOwnerRetired, ErrShadowCapabilityUnavailable,
// CrossBlockCollision).
func decideError(err error) *brainpb.DecideError {
	if err == nil {
		return nil
	}
	out := &brainpb.DecideError{Kind: brainpb.DecideErrorKind_DECIDE_ERROR_KIND_OTHER, Message: err.Error()}
	var collision model.CrossBlockCollision
	var collisionPointer *model.CrossBlockCollision
	switch {
	case errors.Is(err, brainapi.ErrOwnerRetired):
		out.Kind = brainpb.DecideErrorKind_DECIDE_ERROR_KIND_OWNER_RETIRED
	case errors.Is(err, brainapi.ErrShadowCapabilityUnavailable):
		out.Kind = brainpb.DecideErrorKind_DECIDE_ERROR_KIND_SHADOW_CAPABILITY_UNAVAILABLE
	case errors.As(err, &collision):
		out.Kind = brainpb.DecideErrorKind_DECIDE_ERROR_KIND_CROSS_BLOCK_COLLISION
	case errors.As(err, &collisionPointer) && collisionPointer != nil:
		out.Kind, collision = brainpb.DecideErrorKind_DECIDE_ERROR_KIND_CROSS_BLOCK_COLLISION, *collisionPointer
	}
	if out.Kind == brainpb.DecideErrorKind_DECIDE_ERROR_KIND_CROSS_BLOCK_COLLISION {
		out.CollisionKey, out.CollisionExistingBlock, out.CollisionConflictingBlock = collision.Key, collision.ExistingBlock, collision.ConflictingBlock
	}
	return out
}

// hold keeps a recording until the dispatcher closes it and returns its id; a
// recording that captures nothing is not held.
func (s *Server) hold(rec brainapi.Recording) string {
	if _, none := rec.(noRecording); none || rec == nil {
		return ""
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		rec.Close()
		return ""
	}
	id := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, held := range s.recordings {
		if now.After(held.expires) {
			held.rec.Close()
			delete(s.recordings, key)
		}
	}
	s.recordings[id] = heldRecording{rec: rec, expires: now.Add(recordingTTL)}
	return id
}

func (s *Server) take(id string) (brainapi.Recording, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.recordings[id]
	delete(s.recordings, id)
	return held.rec, ok
}

// release closes a held recording the client never learned about.
func (s *Server) release(id string) {
	if rec, ok := s.take(id); ok {
		rec.Close()
	}
}

func (s *Server) CloseRecording(_ context.Context, req *brainpb.CloseRecordingRequest) (*brainpb.CloseRecordingResponse, error) {
	var decisions []model.Decision
	if req.GetFinalized() {
		if err := wire.Decode(req.GetDecisions(), &decisions); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decisions: %v", err)
		}
	}
	rec, ok := s.take(req.GetRecordingId())
	if !ok {
		return nil, status.Error(codes.NotFound, "recording not held")
	}
	if req.GetFinalized() {
		rec.Finalize(decisions)
	}
	rec.Close()
	return &brainpb.CloseRecordingResponse{}, nil
}

func (s *Server) SelectAlternative(_ context.Context, req *brainpb.SelectAlternativeRequest) (*brainpb.SelectAlternativeResponse, error) {
	alternative, found := s.brain.SelectAlternative(req.GetOwner(), req.GetTarget(), model.Action(req.GetFailedAction()))
	out := &brainpb.SelectAlternativeResponse{Found: found}
	if found {
		raw, err := wire.Encode(alternative)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "alternative: %v", err)
		}
		out.Alternative = raw
	}
	return out, nil
}

func (s *Server) ReserveAlternative(_ context.Context, req *brainpb.ReserveAlternativeRequest) (*brainpb.ReserveAlternativeResponse, error) {
	reserved := s.brain.ReserveAlternative(req.GetOwner(), req.GetTarget(), model.Action(req.GetFailedAction()), model.Action(req.GetChosenAction()))
	return &brainpb.ReserveAlternativeResponse{Reserved: reserved}, nil
}

func (s *Server) ParameterSet(_ context.Context, req *brainpb.ParameterSetRequest) (*brainpb.ParameterSetResponse, error) {
	var policy model.Policy
	if err := wire.Decode(req.GetPolicy(), &policy); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "policy: %v", err)
	}
	set, err := s.brain.ParameterSet(policy)
	if err != nil {
		return &brainpb.ParameterSetResponse{Error: err.Error()}, nil
	}
	raw, err := wire.Encode(set)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "parameter set: %v", err)
	}
	return &brainpb.ParameterSetResponse{ParameterSet: raw}, nil
}

func (s *Server) RejectedDecisions(_ context.Context, req *brainpb.RejectedDecisionsRequest) (*brainpb.RejectedDecisionsResponse, error) {
	var tick brainapi.RejectedTick
	if err := wire.Decode(req.GetTick(), &tick); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tick: %v", err)
	}
	decisions, err := s.brain.RejectedDecisions(tick)
	if err != nil {
		return &brainpb.RejectedDecisionsResponse{Error: err.Error()}, nil
	}
	raw, err := wire.Encode(decisions)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decisions: %v", err)
	}
	return &brainpb.RejectedDecisionsResponse{Decisions: raw}, nil
}

func (s *Server) ObserveRotation(_ context.Context, req *brainpb.ObserveRotationRequest) (*brainpb.ObserveRotationResponse, error) {
	var view *model.WorkloadView
	if err := wire.Decode(req.GetView(), &view); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "view: %v", err)
	}
	s.brain.ObserveRotation(req.GetOwner(), view, req.GetMeasuredFlow())
	return &brainpb.ObserveRotationResponse{}, nil
}

func (s *Server) GetCalibrationState(context.Context, *brainpb.GetCalibrationStateRequest) (*brainpb.GetCalibrationStateResponse, error) {
	out := &brainpb.GetCalibrationStateResponse{}
	if state := s.brain.CalibrationState(); state != nil {
		out.Tenants = make(map[string]*brainpb.CostCalibrationState, len(state))
		for tenant, st := range state {
			out.Tenants[tenant] = &brainpb.CostCalibrationState{Primed: st.Primed, Updates: int64(st.Updates)}
		}
	}
	return out, nil
}

func (s *Server) SetCostCalibrationFrozen(_ context.Context, req *brainpb.SetCostCalibrationFrozenRequest) (*brainpb.SetCostCalibrationFrozenResponse, error) {
	s.brain.SetCostCalibrationFrozen(req.GetFrozen())
	return &brainpb.SetCostCalibrationFrozenResponse{}, nil
}

func (s *Server) RegisterOwnerEpochs(_ context.Context, req *brainpb.RegisterOwnerEpochsRequest) (*brainpb.RegisterOwnerEpochsResponse, error) {
	var epochs []model.PolicyEpoch
	if err := wire.Decode(req.GetEpochs(), &epochs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "epochs: %v", err)
	}
	s.brain.RegisterOwnerEpochs(epochs)
	return &brainpb.RegisterOwnerEpochsResponse{}, nil
}

func (s *Server) ForgetOwner(_ context.Context, req *brainpb.ForgetOwnerRequest) (*brainpb.ForgetOwnerResponse, error) {
	return &brainpb.ForgetOwnerResponse{StoresCleared: int64(s.brain.ForgetOwner(req.GetOwner()))}, nil
}

func (s *Server) RetainStageClock(_ context.Context, req *brainpb.RetainStageClockRequest) (*brainpb.RetainStageClockResponse, error) {
	keep := make(map[string]struct{}, len(req.GetKeep()))
	for _, key := range req.GetKeep() {
		keep[key] = struct{}{}
	}
	s.brain.RetainStageClock(req.GetOwner(), keep)
	return &brainpb.RetainStageClockResponse{}, nil
}

func (s *Server) SetPersistenceAuthority(_ context.Context, req *brainpb.SetPersistenceAuthorityRequest) (*brainpb.SetPersistenceAuthorityResponse, error) {
	s.authorityMu.Lock()
	defer s.authorityMu.Unlock()
	if !req.GetPresent() {
		s.authority = nil
		s.brain.SetPersistenceAuthority(nil)
	} else {
		s.authority = &remoteAuthority{source: req.GetSource()}
		s.brain.SetPersistenceAuthority(s.authority)
	}
	return &brainpb.SetPersistenceAuthorityResponse{}, nil
}

func (s *Server) AdmitPersistenceObservation(_ context.Context, req *brainpb.AdmitPersistenceObservationRequest) (*brainpb.AdmitPersistenceObservationResponse, error) {
	var observation model.PersistenceObservation
	if err := wire.Decode(req.GetObservation(), &observation); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "observation: %v", err)
	}
	var answer *resolvedAnswer
	if req.GetResolved() {
		answer = &resolvedAnswer{observation: observation, authorized: req.GetAuthorized()}
		if err := wire.Decode(req.GetBinding(), &answer.binding); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "binding: %v", err)
		}
	}
	s.authorityMu.Lock()
	if s.authority != nil {
		s.authority.answer = answer
	}
	result := s.brain.AdmitPersistenceObservation(observation)
	if s.authority != nil {
		s.authority.answer = nil
	}
	s.authorityMu.Unlock()
	raw, err := wire.Encode(result)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "result: %v", err)
	}
	return &brainpb.AdmitPersistenceObservationResponse{Result: raw}, nil
}

func (s *Server) RecordScopedOutcomeUnavailable(_ context.Context, req *brainpb.RecordScopedOutcomeUnavailableRequest) (*brainpb.RecordScopedOutcomeUnavailableResponse, error) {
	var policy model.PolicyEpoch
	if err := wire.Decode(req.GetPolicy(), &policy); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "policy: %v", err)
	}
	raw, err := wire.Encode(s.brain.RecordScopedOutcomeUnavailable(policy, req.GetReason()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "result: %v", err)
	}
	return &brainpb.RecordScopedOutcomeUnavailableResponse{Result: raw}, nil
}

// remoteAuthority stands in for the dispatcher's observed-outcome authority. It
// reports the authority's source and, while one observation is being admitted,
// replays the answer the dispatcher resolved for exactly that observation; any
// other observation is unauthorized.
type remoteAuthority struct {
	source string
	answer *resolvedAnswer // guarded by Server.authorityMu
}

type resolvedAnswer struct {
	observation model.PersistenceObservation
	binding     model.PersistenceOperationBinding
	authorized  bool
}

func (r *remoteAuthority) Source() string { return r.source }

func (r *remoteAuthority) AuthorizeObservation(o model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	if r.answer == nil || o != r.answer.observation {
		return model.PersistenceOperationBinding{}, false
	}
	return r.answer.binding, r.answer.authorized
}
