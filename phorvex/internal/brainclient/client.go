// Package brainclient is the dispatcher's side of the brain service (ADR-0001): a
// brainapi.Brain that runs every call on a separate brain over gRPC.
//
// The client keeps the in-process contract. The brain asks its capability and
// failure questions back over the Decide stream; the client answers each from its
// own gate, in generation order, and applies the event-evidence stamps the brain
// wrote on its views. Evaluation errors come back as the same values
// (brainapi.ErrOwnerRetired, model.CrossBlockCollision). A call that fails where
// the contract returns an error fails the tick closed; one that cannot return an
// error is logged, and owner removals the brain has not acknowledged are replayed
// before the next evaluation.
package brainclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"

	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/wire"
)

const (
	defaultCallTimeout   = 5 * time.Second
	defaultDecideTimeout = time.Minute
)

// Options configures a Client.
type Options struct {
	// Config is the dispatcher's decision configuration. The brain refuses a client
	// whose configuration differs from its own.
	Config brainapi.DecisionConfig
	// CallTimeout bounds each unary call. Zero means 5 seconds.
	CallTimeout time.Duration
	// DecideTimeout bounds one evaluation, gate questions included. Zero means one
	// minute.
	DecideTimeout time.Duration
	// Log receives failures of calls whose contract has no error to return.
	Log logr.Logger
}

// Client is a brainapi.Brain served by a remote brain.
type Client struct {
	rpc   brainpb.BrainServiceClient
	opt   Options
	hello *brainpb.HelloResponse

	mu            sync.Mutex
	authority     model.PersistenceObservationAuthority
	pendingForget map[string]struct{}

	closing sync.WaitGroup
}

var _ brainapi.Brain = (*Client)(nil)

// New checks the brain's contract version and decision configuration over conn,
// waiting for the brain until ctx ends. It fails when the brain cannot be reached
// or refuses the client.
func New(ctx context.Context, conn grpc.ClientConnInterface, opt Options) (*Client, error) {
	if opt.CallTimeout <= 0 {
		opt.CallTimeout = defaultCallTimeout
	}
	if opt.DecideTimeout <= 0 {
		opt.DecideTimeout = defaultDecideTimeout
	}
	c := &Client{rpc: brainpb.NewBrainServiceClient(conn), opt: opt, pendingForget: map[string]struct{}{}}
	hello, err := c.rpc.Hello(ctx, &brainpb.HelloRequest{
		ContractVersion: brainapi.ContractVersion, DecisionConfigSha256: opt.Config.SHA256(),
	}, grpc.WaitForReady(true))
	if err != nil {
		return nil, fmt.Errorf("brain service hello: %w", err)
	}
	c.hello = hello
	return c, nil
}

// Flush waits until every closed recording has been handed to the brain.
func (c *Client) Flush() { c.closing.Wait() }

func (c *Client) call() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.opt.CallTimeout)
}

func (c *Client) Name() string                  { return c.hello.GetName() }
func (c *Client) GatesCandidates() bool         { return c.hello.GetGatesCandidates() }
func (c *Client) LearnsRotationCost() bool      { return c.hello.GetLearnsRotationCost() }
func (c *Client) PersistenceObservations() bool { return c.hello.GetPersistenceObservations() }
func (c *Client) ScopedOutcomeProcessEpochID() string {
	return c.hello.GetScopedOutcomeProcessEpochId()
}

func (c *Client) Decide(req brainapi.DecideRequest) ([]model.Decision, brainapi.Recording, error) {
	decisions, result, err := c.decide(req, false)
	if err != nil {
		return nil, noRecording{}, err
	}
	stamps := result.GetHasEventEvidence()
	if len(stamps) != len(req.Views) {
		c.closeRecording(result.GetRecordingId(), nil, false)
		return nil, noRecording{}, fmt.Errorf("brain service: %d event-evidence stamps for %d views", len(stamps), len(req.Views))
	}
	for i, v := range req.Views {
		if v != nil {
			v.HasEventEvidence = stamps[i]
		}
	}
	var rec brainapi.Recording = noRecording{}
	if id := result.GetRecordingId(); id != "" {
		rec = &recording{c: c, id: id}
	}
	return decisions, rec, resultError(result.GetError())
}

func (c *Client) DecideShadow(req brainapi.DecideRequest) ([]model.Decision, bool, error) {
	req.Capture = nil
	decisions, result, err := c.decide(req, true)
	if err != nil {
		return nil, true, err
	}
	if !result.GetSupported() {
		return nil, false, nil
	}
	return decisions, true, resultError(result.GetError())
}

// decide runs one evaluation on the brain, answering its gate questions from
// req.Gate.
func (c *Client) decide(req brainapi.DecideRequest, shadow bool) ([]model.Decision, *brainpb.DecideResult, error) {
	if err := c.flushForgets(); err != nil {
		return nil, nil, fmt.Errorf("brain service: owner removal not acknowledged: %w", err)
	}
	start := &brainpb.DecideStart{
		Shadow:               shadow,
		CapabilityGate:       req.Gate.Capability != nil,
		ShadowCapabilityGate: req.Gate.ShadowCapability != nil,
		FailureGate:          req.Gate.FailureExclusion != nil,
	}
	var err error
	if start.Views, err = wire.Encode(req.Views); err != nil {
		return nil, nil, fmt.Errorf("brain service: views: %w", err)
	}
	if start.Policy, err = wire.Encode(req.Policy); err != nil {
		return nil, nil, fmt.Errorf("brain service: policy: %w", err)
	}
	if req.Capture != nil {
		if start.Capture, err = wire.Encode(req.Capture); err != nil {
			return nil, nil, fmt.Errorf("brain service: capture: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.opt.DecideTimeout)
	defer cancel()
	stream, err := c.rpc.Decide(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("brain service: decide: %w", err)
	}
	if err := stream.Send(&brainpb.DecideRequest{Message: &brainpb.DecideRequest_Start{Start: start}}); err != nil {
		return nil, nil, fmt.Errorf("brain service: decide: %w", streamError(stream, err))
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			return nil, nil, fmt.Errorf("brain service: decide: %w", err)
		}
		var answer *brainpb.DecideRequest
		switch m := msg.GetMessage().(type) {
		case *brainpb.DecideResponse_Capability:
			if answer, err = answerCapability(req, m.Capability); err != nil {
				return nil, nil, fmt.Errorf("brain service: %w", err)
			}
		case *brainpb.DecideResponse_Failure:
			if answer, err = answerFailure(req, m.Failure); err != nil {
				return nil, nil, fmt.Errorf("brain service: %w", err)
			}
		case *brainpb.DecideResponse_Result:
			_ = stream.CloseSend()
			var decisions []model.Decision
			if err := wire.Decode(m.Result.GetDecisions(), &decisions); err != nil {
				c.closeRecording(m.Result.GetRecordingId(), nil, false)
				return nil, nil, fmt.Errorf("brain service: decisions: %w", err)
			}
			return decisions, m.Result, nil
		default:
			return nil, nil, errors.New("brain service: unexpected decide message")
		}
		if err := stream.Send(answer); err != nil {
			return nil, nil, fmt.Errorf("brain service: decide: %w", streamError(stream, err))
		}
	}
}

// streamError returns the status that ended the stream when Send reports only EOF.
func streamError(stream brainpb.BrainService_DecideClient, err error) error {
	if _, recvErr := stream.Recv(); recvErr != nil {
		return recvErr
	}
	return err
}

// questionView is the view a gate question names, as the brain saw it: the brain
// may already have stamped its event evidence.
func questionView(views []*model.WorkloadView, index uint32, hasEventEvidence bool) (*model.WorkloadView, error) {
	if int(index) >= len(views) || views[index] == nil {
		return nil, fmt.Errorf("gate question names view %d of %d", index, len(views))
	}
	v := views[index]
	if v.HasEventEvidence != hasEventEvidence {
		stamped := *v
		stamped.HasEventEvidence = hasEventEvidence
		v = &stamped
	}
	return v, nil
}

func answerCapability(req brainapi.DecideRequest, q *brainpb.CapabilityQuestion) (*brainpb.DecideRequest, error) {
	gate := req.Gate.Capability
	if q.GetShadow() {
		gate = req.Gate.ShadowCapability
	}
	if gate == nil {
		return nil, errors.New("capability question for a gate the client did not wire")
	}
	v, err := questionView(req.Views, q.GetViewIndex(), q.GetHasEventEvidence())
	if err != nil {
		return nil, err
	}
	answer := &brainpb.CapabilityAnswer{Id: q.GetId(), Clean: true}
	if e := gate(v, model.Action(q.GetAction()), q.GetCoverKeys()); e != nil {
		answer = &brainpb.CapabilityAnswer{Id: q.GetId(), Excluded: e.Excluded, Kind: e.Kind, Detail: e.Detail, RbacUnknown: e.RBACUnknown}
	}
	return &brainpb.DecideRequest{Message: &brainpb.DecideRequest_Capability{Capability: answer}}, nil
}

func answerFailure(req brainapi.DecideRequest, q *brainpb.FailureQuestion) (*brainpb.DecideRequest, error) {
	if req.Gate.FailureExclusion == nil {
		return nil, errors.New("failure question for a gate the client did not wire")
	}
	v, err := questionView(req.Views, q.GetViewIndex(), q.GetHasEventEvidence())
	if err != nil {
		return nil, err
	}
	detail, excluded := req.Gate.FailureExclusion(v, model.Action(q.GetAction()))
	answer := &brainpb.FailureAnswer{Id: q.GetId(), Detail: detail, Excluded: excluded}
	return &brainpb.DecideRequest{Message: &brainpb.DecideRequest_Failure{Failure: answer}}, nil
}

// decideFailure is an evaluation error the brain reported: its message, and the
// error value the runner tests for.
type decideFailure struct {
	message string
	is      error
}

func (e decideFailure) Error() string { return e.message }
func (e decideFailure) Unwrap() error { return e.is }

func resultError(e *brainpb.DecideError) error {
	if e == nil {
		return nil
	}
	switch e.GetKind() {
	case brainpb.DecideErrorKind_DECIDE_ERROR_KIND_OWNER_RETIRED:
		return decideFailure{e.GetMessage(), brainapi.ErrOwnerRetired}
	case brainpb.DecideErrorKind_DECIDE_ERROR_KIND_SHADOW_CAPABILITY_UNAVAILABLE:
		return decideFailure{e.GetMessage(), brainapi.ErrShadowCapabilityUnavailable}
	case brainpb.DecideErrorKind_DECIDE_ERROR_KIND_CROSS_BLOCK_COLLISION:
		return decideFailure{e.GetMessage(), model.CrossBlockCollision{
			Key: e.GetCollisionKey(), ExistingBlock: e.GetCollisionExistingBlock(), ConflictingBlock: e.GetCollisionConflictingBlock(),
		}}
	default:
		return errors.New(e.GetMessage())
	}
}

// recording is a Math Lab recording the brain holds. Finalize keeps the audited
// decisions; Close hands both to the brain in the background, so it never blocks
// the tick.
type recording struct {
	c  *Client
	id string

	mu        sync.Mutex
	decisions []byte
	finalized bool
	closed    bool
}

func (r *recording) Finalize(decisions []model.Decision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.finalized {
		return
	}
	raw, err := wire.Encode(decisions)
	if err != nil {
		r.c.opt.Log.Error(err, "math lab recording not finalized", "recording", r.id)
		return
	}
	r.decisions, r.finalized = raw, true
}

func (r *recording) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.c.closeRecording(r.id, r.decisions, r.finalized)
}

func (c *Client) closeRecording(id string, decisions []byte, finalized bool) {
	if id == "" {
		return
	}
	c.closing.Add(1)
	go func() {
		defer c.closing.Done()
		ctx, cancel := c.call()
		defer cancel()
		_, err := c.rpc.CloseRecording(ctx, &brainpb.CloseRecordingRequest{RecordingId: id, Finalized: finalized, Decisions: decisions})
		if err != nil {
			c.opt.Log.Error(err, "math lab recording not handed to the brain", "recording", id)
		}
	}()
}

type noRecording struct{}

func (noRecording) Finalize([]model.Decision) {}
func (noRecording) Close()                    {}

func (c *Client) SelectAlternative(owner, target string, failed model.Action) (model.Alternative, bool) {
	ctx, cancel := c.call()
	defer cancel()
	resp, err := c.rpc.SelectAlternative(ctx, &brainpb.SelectAlternativeRequest{Owner: owner, Target: target, FailedAction: string(failed)})
	if err != nil {
		c.opt.Log.Error(err, "brain service: no alternative selected", "owner", owner, "target", target)
		return model.Alternative{}, false
	}
	if !resp.GetFound() {
		return model.Alternative{}, false
	}
	var alternative model.Alternative
	if err := wire.Decode(resp.GetAlternative(), &alternative); err != nil {
		c.opt.Log.Error(err, "brain service: no alternative selected", "owner", owner, "target", target)
		return model.Alternative{}, false
	}
	return alternative, true
}

func (c *Client) ReserveAlternative(owner, target string, failed, chosen model.Action) bool {
	ctx, cancel := c.call()
	defer cancel()
	resp, err := c.rpc.ReserveAlternative(ctx, &brainpb.ReserveAlternativeRequest{
		Owner: owner, Target: target, FailedAction: string(failed), ChosenAction: string(chosen),
	})
	if err != nil {
		c.opt.Log.Error(err, "brain service: alternative not reserved", "owner", owner, "target", target)
		return false
	}
	return resp.GetReserved()
}

func (c *Client) ObserveRotation(owner string, view *model.WorkloadView, measuredFlow float64) {
	raw, err := wire.Encode(view)
	if err == nil {
		ctx, cancel := c.call()
		defer cancel()
		_, err = c.rpc.ObserveRotation(ctx, &brainpb.ObserveRotationRequest{Owner: owner, View: raw, MeasuredFlow: measuredFlow})
	}
	if err != nil {
		c.opt.Log.Error(err, "brain service: rotation observation dropped", "owner", owner)
	}
}

func (c *Client) CalibrationState() map[string]model.CostCalibrationState {
	ctx, cancel := c.call()
	defer cancel()
	resp, err := c.rpc.GetCalibrationState(ctx, &brainpb.GetCalibrationStateRequest{})
	if err != nil {
		c.opt.Log.Error(err, "brain service: calibration state unavailable")
		return nil
	}
	if resp.GetTenants() == nil {
		return nil
	}
	out := make(map[string]model.CostCalibrationState, len(resp.GetTenants()))
	for tenant, st := range resp.GetTenants() {
		out[tenant] = model.CostCalibrationState{Primed: st.GetPrimed(), Updates: int(st.GetUpdates())}
	}
	return out
}

func (c *Client) SetCostCalibrationFrozen(frozen bool) {
	ctx, cancel := c.call()
	defer cancel()
	if _, err := c.rpc.SetCostCalibrationFrozen(ctx, &brainpb.SetCostCalibrationFrozenRequest{Frozen: frozen}); err != nil {
		c.opt.Log.Error(err, "brain service: calibration switch not applied", "frozen", frozen)
	}
}

func (c *Client) RegisterOwnerEpochs(epochs []model.PolicyEpoch) {
	raw, err := wire.Encode(epochs)
	if err == nil {
		ctx, cancel := c.call()
		defer cancel()
		_, err = c.rpc.RegisterOwnerEpochs(ctx, &brainpb.RegisterOwnerEpochsRequest{Epochs: raw})
	}
	if err != nil {
		c.opt.Log.Error(err, "brain service: owner epochs not registered")
	}
}

// ForgetOwner removes the owner's state from the brain. When the brain does not
// acknowledge it, the removal is replayed before the next evaluation, which fails
// closed until it is.
func (c *Client) ForgetOwner(owner string) int {
	c.mu.Lock()
	c.pendingForget[owner] = struct{}{}
	c.mu.Unlock()
	cleared, err := c.forget(owner)
	if err != nil {
		c.opt.Log.Error(err, "brain service: owner removal pending", "owner", owner)
		return 0
	}
	return cleared
}

func (c *Client) forget(owner string) (int, error) {
	ctx, cancel := c.call()
	defer cancel()
	resp, err := c.rpc.ForgetOwner(ctx, &brainpb.ForgetOwnerRequest{Owner: owner})
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	delete(c.pendingForget, owner)
	c.mu.Unlock()
	return int(resp.GetStoresCleared()), nil
}

func (c *Client) flushForgets() error {
	c.mu.Lock()
	owners := make([]string, 0, len(c.pendingForget))
	for owner := range c.pendingForget {
		owners = append(owners, owner)
	}
	c.mu.Unlock()
	for _, owner := range owners {
		if _, err := c.forget(owner); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) RetainStageClock(owner string, keep map[string]struct{}) {
	keys := make([]string, 0, len(keep))
	for key := range keep {
		keys = append(keys, key)
	}
	ctx, cancel := c.call()
	defer cancel()
	if _, err := c.rpc.RetainStageClock(ctx, &brainpb.RetainStageClockRequest{Owner: owner, Keep: keys}); err != nil {
		c.opt.Log.Error(err, "brain service: stage clock retention not applied", "owner", owner)
	}
}

// SetPersistenceAuthority keeps the authority with the dispatcher; the brain
// learns its source, and the client resolves its answer for each admission.
func (c *Client) SetPersistenceAuthority(authority model.PersistenceObservationAuthority) {
	c.mu.Lock()
	c.authority = authority
	c.mu.Unlock()
	req := &brainpb.SetPersistenceAuthorityRequest{Present: authority != nil}
	if authority != nil {
		req.Source = authority.Source()
	}
	ctx, cancel := c.call()
	defer cancel()
	if _, err := c.rpc.SetPersistenceAuthority(ctx, req); err != nil {
		c.opt.Log.Error(err, "brain service: persistence authority not installed")
	}
}

func (c *Client) AdmitPersistenceObservation(observation model.PersistenceObservation) model.PersistenceObservationResult {
	raw, err := wire.Encode(observation)
	if err != nil {
		return unavailable(observation, err)
	}
	req := &brainpb.AdmitPersistenceObservationRequest{Observation: raw}
	c.mu.Lock()
	authority := c.authority
	c.mu.Unlock()
	if authority != nil {
		binding, authorized := authority.AuthorizeObservation(observation)
		req.Resolved, req.Authorized = true, authorized
		if req.Binding, err = wire.Encode(binding); err != nil {
			return unavailable(observation, err)
		}
	}
	ctx, cancel := c.call()
	defer cancel()
	resp, err := c.rpc.AdmitPersistenceObservation(ctx, req)
	if err != nil {
		return unavailable(observation, err)
	}
	var result model.PersistenceObservationResult
	if err := wire.Decode(resp.GetResult(), &result); err != nil {
		return unavailable(observation, err)
	}
	return result
}

func (c *Client) RecordScopedOutcomeUnavailable(policy model.PolicyEpoch, reason string) model.PersistenceObservationResult {
	raw, err := wire.Encode(policy)
	if err != nil {
		return model.PersistenceObservationResult{Disposition: model.PersistenceDispositionRejected, Reason: err.Error()}
	}
	ctx, cancel := c.call()
	defer cancel()
	resp, err := c.rpc.RecordScopedOutcomeUnavailable(ctx, &brainpb.RecordScopedOutcomeUnavailableRequest{Policy: raw, Reason: reason})
	if err != nil {
		c.opt.Log.Error(err, "brain service: scoped outcome unavailability not recorded", "owner", policy.Owner())
		return model.PersistenceObservationResult{Disposition: model.PersistenceDispositionRejected, Reason: "brain service unavailable: " + err.Error()}
	}
	var result model.PersistenceObservationResult
	if err := wire.Decode(resp.GetResult(), &result); err != nil {
		return model.PersistenceObservationResult{Disposition: model.PersistenceDispositionRejected, Reason: err.Error()}
	}
	return result
}

// unavailable is the result of an observation the brain did not receive: it was
// not applied.
func unavailable(observation model.PersistenceObservation, err error) model.PersistenceObservationResult {
	return model.PersistenceObservationResult{
		Disposition: model.PersistenceDispositionRejected,
		Reason:      "brain service unavailable for evidence " + observation.EvidenceID + ": " + err.Error(),
	}
}
