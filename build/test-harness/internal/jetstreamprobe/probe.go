// Package jetstreamprobe provides bounded, identity-checking JetStream
// operations for the disposable NATS durability fixture. It never discovers or
// adopts streams: callers must supply the exact stream, subject, and consumer.
package jetstreamprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const messageIDHeader = "Nats-Msg-Id"

const (
	ownerMetadataKey  = "fixture.phorvex.ai/owner-nonce"
	schemaMetadataKey = "fixture.phorvex.ai/schema"
	fixtureSchema     = "post25-nats-jetstream-durability-v1"
)

type Config struct {
	URL             string
	Stream          string
	Subject         string
	Consumer        string
	OwnerNonce      string
	Replicas        int
	ConnectTimeout  time.Duration
	RequestTimeout  time.Duration
	FetchTimeout    time.Duration
	AckWait         time.Duration
	DuplicateWindow time.Duration
}

type Message struct {
	ID      string
	Payload []byte
}

type PubAckReceipt struct {
	Stream      string `json:"stream"`
	Sequence    uint64 `json:"sequence"`
	Duplicate   bool   `json:"duplicate"`
	MessageID   string `json:"messageID"`
	PayloadHash string `json:"payloadSHA256"`
}

type DeliveryReceipt struct {
	StreamSequence   uint64 `json:"streamSequence"`
	ConsumerSequence uint64 `json:"consumerSequence"`
	Deliveries       uint64 `json:"deliveries"`
	MessageID        string `json:"messageID"`
	PayloadHash      string `json:"payloadSHA256"`
}

type StoredReceipt struct {
	StreamSequence uint64 `json:"streamSequence"`
	Subject        string `json:"subject"`
	MessageID      string `json:"messageID"`
	PayloadHash    string `json:"payloadSHA256"`
}

type StateReceipt struct {
	Stream              string        `json:"stream"`
	Consumer            string        `json:"consumer"`
	Replicas            int           `json:"replicas"`
	DuplicateWindow     time.Duration `json:"duplicateWindow"`
	Messages            uint64        `json:"messages"`
	FirstSequence       uint64        `json:"firstSequence"`
	LastSequence        uint64        `json:"lastSequence"`
	AckFloor            uint64        `json:"ackFloor"`
	AckPending          int           `json:"ackPending"`
	ConsumerPending     uint64        `json:"consumerPending"`
	ConsumerRedelivered int           `json:"consumerRedelivered"`
}

type ReplicaMemberReceipt struct {
	Name    string `json:"name"`
	Leader  bool   `json:"leader"`
	Current bool   `json:"current"`
	Offline bool   `json:"offline"`
	Lag     uint64 `json:"lag"`
}

type ClusterReceipt struct {
	Cluster  string                 `json:"cluster"`
	Leader   string                 `json:"leader"`
	Members  []ReplicaMemberReceipt `json:"members"`
	Replicas int                    `json:"replicas"`
}

type ReplicationReceipt struct {
	Stream   ClusterReceipt `json:"stream"`
	Consumer ClusterReceipt `json:"consumer"`
}

type RestartBoundaryReceipt struct {
	Member              string `json:"member"`
	ActionAttempted     bool   `json:"actionAttempted"`
	ActionSent          bool   `json:"actionSent"`
	ActionCompleted     bool   `json:"actionCompleted"`
	ElapsedNanos        int64  `json:"elapsedNanos"`
	OldProcessID        string `json:"oldProcessID"`
	NewProcessID        string `json:"newProcessID"`
	WorkloadUIDBefore   string `json:"workloadUIDBefore"`
	WorkloadUIDAfter    string `json:"workloadUIDAfter"`
	VolumeUIDBefore     string `json:"volumeUIDBefore"`
	VolumeUIDAfter      string `json:"volumeUIDAfter"`
	StorePathHashBefore string `json:"storePathHashBefore"`
	StorePathHashAfter  string `json:"storePathHashAfter"`
}

type RestartOracleReceipt struct {
	Baseline             ReplicationReceipt     `json:"baseline"`
	MessageA             PubAckReceipt          `json:"messageA"`
	DeliveryA            DeliveryReceipt        `json:"deliveryA"`
	StoredBefore         StoredReceipt          `json:"storedBefore"`
	Restart              RestartBoundaryReceipt `json:"restart"`
	Recovered            ReplicationReceipt     `json:"recovered"`
	RecoveryElapsedNanos int64                  `json:"recoveryElapsedNanos"`
	StoredAfter          StoredReceipt          `json:"storedAfter"`
	MessageB             PubAckReceipt          `json:"messageB"`
	DeliveryB            DeliveryReceipt        `json:"deliveryB"`
	FinalState           StateReceipt           `json:"finalState"`
}

type NoActionOracleReceipt struct {
	Baseline   ReplicationReceipt `json:"baseline"`
	MessageA   PubAckReceipt      `json:"messageA"`
	DeliveryA  DeliveryReceipt    `json:"deliveryA"`
	StoredA    StoredReceipt      `json:"storedA"`
	MessageB   PubAckReceipt      `json:"messageB"`
	DeliveryB  DeliveryReceipt    `json:"deliveryB"`
	FinalState StateReceipt       `json:"finalState"`
}

type PublishAttemptReceipt struct {
	StartedAtUTC  string         `json:"startedAtUTC"`
	FinishedAtUTC string         `json:"finishedAtUTC"`
	AttemptCount  int            `json:"attemptCount"`
	MessageID     string         `json:"messageID"`
	PayloadHash   string         `json:"payloadSHA256"`
	Acknowledged  bool           `json:"acknowledged"`
	Ack           *PubAckReceipt `json:"ack,omitempty"`
	ErrorClass    string         `json:"errorClass,omitempty"`
	Error         string         `json:"error,omitempty"`
}

type PingReceipt struct {
	StartedAtUTC  string `json:"startedAtUTC"`
	FinishedAtUTC string `json:"finishedAtUTC"`
	Reachable     bool   `json:"reachable"`
	ErrorClass    string `json:"errorClass,omitempty"`
	Error         string `json:"error,omitempty"`
}

type QuorumObservationReceipt struct {
	Publish PublishAttemptReceipt `json:"publish"`
	Ping    PingReceipt           `json:"ping"`
}

type PausedMemberReceipt struct {
	Member                 string `json:"member"`
	ServerIDBefore         string `json:"serverIDBefore"`
	ServerIDAfter          string `json:"serverIDAfter"`
	PID                    int    `json:"pid"`
	PIDStartTimeTicks      uint64 `json:"pidStartTimeTicks"`
	Generation             uint64 `json:"generation"`
	WorkloadUIDBefore      string `json:"workloadUIDBefore"`
	WorkloadUIDAfter       string `json:"workloadUIDAfter"`
	VolumeUIDBefore        string `json:"volumeUIDBefore"`
	VolumeUIDAfter         string `json:"volumeUIDAfter"`
	StorePathHashBefore    string `json:"storePathHashBefore"`
	StorePathHashAfter     string `json:"storePathHashAfter"`
	ResumeArmedBeforePause bool   `json:"resumeArmedBeforePause"`
	PauseAttempted         bool   `json:"pauseAttempted"`
	PauseSent              bool   `json:"pauseSent"`
	PauseConfirmed         bool   `json:"pauseConfirmed"`
	PausedAtUTC            string `json:"pausedAtUTC"`
	StillPausedAtUTC       string `json:"stillPausedAtUTC"`
	ResumeRequested        bool   `json:"resumeRequested"`
	ResumeConfirmed        bool   `json:"resumeConfirmed"`
	ResumedAtUTC           string `json:"resumedAtUTC"`
}

type QuorumPauseReceipt struct {
	ConnectedMember          string                `json:"connectedMember"`
	Members                  []PausedMemberReceipt `json:"members"`
	MaximumPauseNanos        int64                 `json:"maximumPauseNanos"`
	ObservedPauseNanos       int64                 `json:"observedPauseNanos"`
	ObservationStartedAtUTC  string                `json:"observationStartedAtUTC"`
	ObservationFinishedAtUTC string                `json:"observationFinishedAtUTC"`
	ObservationCalls         int                   `json:"observationCalls"`
}

type QuorumOracleReceipt struct {
	Baseline             ReplicationReceipt       `json:"baseline"`
	MessageA             PubAckReceipt            `json:"messageA"`
	DeliveryA            DeliveryReceipt          `json:"deliveryA"`
	StoredABefore        StoredReceipt            `json:"storedABefore"`
	Pause                QuorumPauseReceipt       `json:"pause"`
	DuringPause          QuorumObservationReceipt `json:"duringPause"`
	Recovered            ReplicationReceipt       `json:"recovered"`
	RecoveryElapsedNanos int64                    `json:"recoveryElapsedNanos"`
	StoredAAfter         StoredReceipt            `json:"storedAAfter"`
	ReconciledX          PubAckReceipt            `json:"reconciledX"`
	StoredX              StoredReceipt            `json:"storedX"`
	DeliveryX            DeliveryReceipt          `json:"deliveryX"`
	MessageY             PubAckReceipt            `json:"messageY"`
	StoredY              StoredReceipt            `json:"storedY"`
	DeliveryY            DeliveryReceipt          `json:"deliveryY"`
	FinalState           StateReceipt             `json:"finalState"`
}

type QuorumObservation func(context.Context) (QuorumObservationReceipt, error)
type PauseQuorum func(context.Context, QuorumObservation) (QuorumPauseReceipt, QuorumObservationReceipt, error)

type RestartMember func(context.Context) (RestartBoundaryReceipt, error)

type Probe struct {
	cfg            Config
	nc             *nats.Conn
	js             jetstream.JetStream
	stream         jetstream.Stream
	consumer       jetstream.Consumer
	deleteConsumer func(context.Context, string) error
}

func Open(ctx context.Context, cfg Config) (*Probe, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	nc, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*Probe, error) {
		nc.Close()
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return closeOnError(fmt.Errorf("create JetStream context: %w", err))
	}
	reqCtx, cancel := bounded(ctx, cfg.RequestTimeout)
	_, err = js.Stream(reqCtx, cfg.Stream)
	cancel()
	if err == nil {
		return closeOnError(fmt.Errorf("refusing preexisting stream %q", cfg.Stream))
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return closeOnError(fmt.Errorf("check stream freshness %q: %w", cfg.Stream, err))
	}
	reqCtx, cancel = bounded(ctx, cfg.RequestTimeout)
	stream, err := js.CreateStream(reqCtx, jetstream.StreamConfig{
		Name:       cfg.Stream,
		Subjects:   []string{cfg.Subject},
		Storage:    jetstream.FileStorage,
		Replicas:   cfg.Replicas,
		Duplicates: cfg.DuplicateWindow,
		Metadata:   ownershipMetadata(cfg.OwnerNonce),
	})
	cancel()
	if err != nil {
		return closeOnError(fmt.Errorf("create fresh stream %q: %w", cfg.Stream, err))
	}
	reqCtx, cancel = bounded(ctx, cfg.RequestTimeout)
	streamInfo, err := stream.Info(reqCtx)
	cancel()
	if err != nil {
		return closeOnError(fmt.Errorf("verify newly created stream %q ownership before cleanup authority: %w", cfg.Stream, err))
	}
	if err := validateFreshOwnedStream(streamInfo, cfg); err != nil {
		return closeOnError(err)
	}
	cleanupCreatedStream := func(cause error) (*Probe, error) {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
		defer cleanupCancel()
		cleanupErr := js.DeleteStream(cleanupCtx, cfg.Stream)
		if cleanupErr != nil {
			cause = errors.Join(cause, fmt.Errorf("cleanup newly created stream %q: %w", cfg.Stream, cleanupErr))
		}
		return closeOnError(cause)
	}
	reqCtx, cancel = bounded(ctx, cfg.RequestTimeout)
	_, err = stream.Consumer(reqCtx, cfg.Consumer)
	cancel()
	if err == nil {
		return cleanupCreatedStream(fmt.Errorf("refusing preexisting consumer %q", cfg.Consumer))
	}
	if !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return cleanupCreatedStream(fmt.Errorf("check consumer freshness %q: %w", cfg.Consumer, err))
	}
	reqCtx, cancel = bounded(ctx, cfg.RequestTimeout)
	consumer, err := stream.CreateConsumer(reqCtx, jetstream.ConsumerConfig{
		Durable:       cfg.Consumer,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       cfg.AckWait,
		MaxDeliver:    2,
		FilterSubject: cfg.Subject,
		Metadata:      ownershipMetadata(cfg.OwnerNonce),
	})
	cancel()
	if err != nil {
		return cleanupCreatedStream(fmt.Errorf("create fresh consumer %q: %w", cfg.Consumer, err))
	}
	reqCtx, cancel = bounded(ctx, cfg.RequestTimeout)
	consumerInfo, err := consumer.Info(reqCtx)
	cancel()
	if err != nil {
		return closeOnError(fmt.Errorf("verify newly created consumer %q ownership; cleanup authority withheld: %w", cfg.Consumer, err))
	}
	if err := validateOwnedConsumer(consumerInfo, cfg.Stream, cfg.Subject, cfg.Consumer, cfg.OwnerNonce); err != nil {
		return closeOnError(err)
	}
	p := &Probe{cfg: cfg, nc: nc, js: js, stream: stream, consumer: consumer}
	p.deleteConsumer = stream.DeleteConsumer
	return p, nil
}

type contextDialer struct {
	ctx     context.Context
	timeout time.Duration
}

func (d contextDialer) Dial(network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout}).DialContext(d.ctx, network, address)
}

type connectResult struct {
	nc  *nats.Conn
	err error
}

func connect(ctx context.Context, cfg Config) (*nats.Conn, error) {
	connectCtx, cancel := bounded(ctx, cfg.ConnectTimeout)
	defer cancel()
	result := make(chan connectResult, 1)
	go func() {
		nc, err := nats.Connect(cfg.URL,
			nats.Name("phorvex-jetstream-durability-probe"),
			nats.Timeout(cfg.ConnectTimeout),
			nats.MaxReconnects(0),
			nats.NoCallbacksAfterClientClose(),
			nats.SetCustomDialer(contextDialer{ctx: connectCtx, timeout: cfg.ConnectTimeout}),
		)
		result <- connectResult{nc: nc, err: err}
	}()
	select {
	case got := <-result:
		if err := connectCtx.Err(); err != nil {
			if got.nc != nil {
				got.nc.Close()
			}
			return nil, fmt.Errorf("connect NATS: %w", err)
		}
		if got.err != nil {
			return nil, fmt.Errorf("connect NATS: %w", got.err)
		}
		return got.nc, nil
	case <-connectCtx.Done():
		go func() {
			got := <-result
			if got.nc != nil {
				got.nc.Close()
			}
		}()
		return nil, fmt.Errorf("connect NATS: %w", connectCtx.Err())
	}
}

func (p *Probe) Close() {
	if p != nil && p.nc != nil {
		p.nc.Close()
	}
}

// ConnectedServerID returns the server identity selected by the real NATS
// client connection. Callers use it to prove which fixture member is outside
// the restart boundary; it is not a reconnect/failover claim.
func (p *Probe) ConnectedServerID() string {
	if p == nil || p.nc == nil {
		return ""
	}
	return p.nc.ConnectedServerId()
}

func (p *Probe) State(ctx context.Context) (StateReceipt, error) {
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	streamInfo, err := p.stream.Info(reqCtx)
	cancel()
	if err != nil {
		return StateReceipt{}, fmt.Errorf("read stream state: %w", err)
	}
	reqCtx, cancel = bounded(ctx, p.cfg.RequestTimeout)
	consumerInfo, err := p.consumer.Info(reqCtx)
	cancel()
	if err != nil {
		return StateReceipt{}, fmt.Errorf("read consumer state: %w", err)
	}
	if streamInfo.Config.Name != p.cfg.Stream || len(streamInfo.Config.Subjects) != 1 || streamInfo.Config.Subjects[0] != p.cfg.Subject || streamInfo.Config.Replicas != p.cfg.Replicas || streamInfo.Config.Duplicates != p.cfg.DuplicateWindow || !exactOwnership(streamInfo.Config.Metadata, p.cfg.OwnerNonce) {
		return StateReceipt{}, fmt.Errorf("stream config identity differs: %+v", streamInfo.Config)
	}
	if consumerInfo.Stream != p.cfg.Stream || consumerInfo.Name != p.cfg.Consumer || consumerInfo.Config.FilterSubject != p.cfg.Subject || consumerInfo.Config.AckPolicy != jetstream.AckExplicitPolicy || !exactOwnership(consumerInfo.Config.Metadata, p.cfg.OwnerNonce) {
		return StateReceipt{}, fmt.Errorf("consumer config identity differs: %+v", consumerInfo)
	}
	return StateReceipt{
		Stream:              p.cfg.Stream,
		Consumer:            p.cfg.Consumer,
		Replicas:            streamInfo.Config.Replicas,
		DuplicateWindow:     streamInfo.Config.Duplicates,
		Messages:            streamInfo.State.Msgs,
		FirstSequence:       streamInfo.State.FirstSeq,
		LastSequence:        streamInfo.State.LastSeq,
		AckFloor:            consumerInfo.AckFloor.Stream,
		AckPending:          consumerInfo.NumAckPending,
		ConsumerPending:     consumerInfo.NumPending,
		ConsumerRedelivered: consumerInfo.NumRedelivered,
	}, nil
}

// WaitCurrentReplicas waits until the exact stream and durable consumer each
// report the configured number of distinct current, online, zero-lag members.
// A canceled caller or an expired window is an error and cannot satisfy the
// recovery gate.
func (p *Probe) WaitCurrentReplicas(ctx context.Context, window time.Duration) (ReplicationReceipt, error) {
	if window <= 0 {
		return ReplicationReceipt{}, errors.New("positive replica convergence window is required")
	}
	deadline, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		receipt, err := p.replicationState(deadline)
		if err == nil {
			return receipt, nil
		}
		last = err
		select {
		case <-deadline.Done():
			return ReplicationReceipt{}, fmt.Errorf("replica convergence did not complete: %v: %w", last, deadline.Err())
		case <-ticker.C:
		}
	}
}

// RunRestartOracle proves acknowledged-message storage and sequence continuity
// across one caller-owned member restart. The callback is the only mutation
// boundary; the probe validates that its workload, volume, and store identity
// stayed exact while the process identity changed.
func (p *Probe) RunRestartOracle(ctx context.Context, messageA, messageB Message, restart RestartMember, window time.Duration) (RestartOracleReceipt, error) {
	receipt := RestartOracleReceipt{}
	if restart == nil || messageA.ID == "" || messageB.ID == "" || messageA.ID == messageB.ID {
		return receipt, errors.New("distinct messages and a restart boundary are required")
	}
	baseline, err := p.WaitCurrentReplicas(ctx, window)
	if err != nil {
		return receipt, err
	}
	receipt.Baseline = baseline
	ackA, err := p.Publish(ctx, messageA, false, 0)
	if err != nil {
		return receipt, err
	}
	receipt.MessageA = ackA
	deliveryA, err := p.ConsumeAndAck(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.DeliveryA = deliveryA
	if err := p.RequireNoSameConsumerRedelivery(ctx); err != nil {
		return receipt, err
	}
	storedBefore, err := p.GetStored(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.StoredBefore = storedBefore
	restartStarted := time.Now()
	restartReceipt, err := restart(ctx)
	receipt.Restart = restartReceipt
	receipt.RecoveryElapsedNanos = time.Since(restartStarted).Nanoseconds()
	if err != nil {
		return receipt, fmt.Errorf("restart exact fixture member: %w", err)
	}
	if err := validateRestartBoundary(restartReceipt); err != nil {
		return receipt, err
	}
	if !clusterHasMember(baseline.Stream, restartReceipt.Member) || !sameClusterMembers(baseline.Stream, baseline.Consumer) {
		return receipt, errors.New("restart member or baseline stream/consumer membership differs")
	}
	recovered, err := p.WaitCurrentReplicas(ctx, window)
	receipt.RecoveryElapsedNanos = time.Since(restartStarted).Nanoseconds()
	if err != nil {
		return receipt, err
	}
	receipt.Recovered = recovered
	if baseline.Stream.Cluster != recovered.Stream.Cluster || baseline.Stream.Replicas != recovered.Stream.Replicas || baseline.Consumer.Cluster != recovered.Consumer.Cluster || baseline.Consumer.Replicas != recovered.Consumer.Replicas || !sameClusterMembers(baseline.Stream, recovered.Stream) || !sameClusterMembers(baseline.Consumer, recovered.Consumer) || !sameClusterMembers(recovered.Stream, recovered.Consumer) {
		return receipt, errors.New("replication cluster identity changed across restart")
	}
	storedAfter, err := p.GetStored(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, fmt.Errorf("read message A after restart: %w", err)
	}
	receipt.StoredAfter = storedAfter
	ackB, err := p.Publish(ctx, messageB, false, ackA.Sequence+1)
	if err != nil {
		return receipt, err
	}
	receipt.MessageB = ackB
	deliveryB, err := p.ConsumeAndAck(ctx, messageB, ackB.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.DeliveryB = deliveryB
	if err := p.RequireNoSameConsumerRedelivery(ctx); err != nil {
		return receipt, err
	}
	finalState, err := p.waitExactState(ctx, window, ackA.Sequence, ackB.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.FinalState = finalState
	return receipt, nil
}

// RunNoActionOracle executes the same A/B protocol without a disruption. It is
// a separate receipt so a healthy baseline cannot be relabeled as restart or
// actuator evidence.
func (p *Probe) RunNoActionOracle(ctx context.Context, messageA, messageB Message, window time.Duration) (NoActionOracleReceipt, error) {
	receipt := NoActionOracleReceipt{}
	if messageA.ID == "" || messageB.ID == "" || messageA.ID == messageB.ID {
		return receipt, errors.New("distinct messages are required")
	}
	baseline, err := p.WaitCurrentReplicas(ctx, window)
	if err != nil {
		return receipt, err
	}
	receipt.Baseline = baseline
	ackA, err := p.Publish(ctx, messageA, false, 0)
	if err != nil {
		return receipt, err
	}
	receipt.MessageA = ackA
	deliveryA, err := p.ConsumeAndAck(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.DeliveryA = deliveryA
	if err := p.RequireNoSameConsumerRedelivery(ctx); err != nil {
		return receipt, err
	}
	storedA, err := p.GetStored(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.StoredA = storedA
	ackB, err := p.Publish(ctx, messageB, false, ackA.Sequence+1)
	if err != nil {
		return receipt, err
	}
	receipt.MessageB = ackB
	deliveryB, err := p.ConsumeAndAck(ctx, messageB, ackB.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.DeliveryB = deliveryB
	if err := p.RequireNoSameConsumerRedelivery(ctx); err != nil {
		return receipt, err
	}
	state, err := p.waitExactState(ctx, window, ackA.Sequence, ackB.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.FinalState = state
	return receipt, nil
}

// RunQuorumOracle retains the one-send publication made while two non-client
// members are paused, then reconciles only that exact message ID after replica
// recovery. A request timeout is an unknown commit status, never a rejection.
func (p *Probe) RunQuorumOracle(ctx context.Context, messageA, messageX, messageY Message, pause PauseQuorum, window time.Duration) (QuorumOracleReceipt, error) {
	receipt := QuorumOracleReceipt{}
	if pause == nil || messageA.ID == "" || messageX.ID == "" || messageY.ID == "" || messageA.ID == messageX.ID || messageA.ID == messageY.ID || messageX.ID == messageY.ID {
		return receipt, errors.New("three distinct messages and a quorum-pause boundary are required")
	}
	baseline, err := p.WaitCurrentReplicas(ctx, window)
	if err != nil {
		return receipt, err
	}
	receipt.Baseline = baseline
	ackA, err := p.Publish(ctx, messageA, false, 0)
	if err != nil {
		return receipt, err
	}
	receipt.MessageA = ackA
	receipt.DeliveryA, err = p.ConsumeAndAck(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, err
	}
	if err := p.RequireNoSameConsumerRedelivery(ctx); err != nil {
		return receipt, err
	}
	receipt.StoredABefore, err = p.GetStored(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, err
	}

	observationCalls := 0
	observe := func(observeCtx context.Context) (QuorumObservationReceipt, error) {
		observationCalls++
		if observationCalls != 1 {
			return QuorumObservationReceipt{}, errors.New("quorum observation may run exactly once")
		}
		return p.observeQuorumLoss(observeCtx, messageX), nil
	}
	pauseReceipt, observation, pauseErr := pause(ctx, observe)
	pauseReceipt.ObservationCalls = observationCalls
	pauseReceipt.ObservationStartedAtUTC = observation.Publish.StartedAtUTC
	pauseReceipt.ObservationFinishedAtUTC = observation.Ping.FinishedAtUTC
	receipt.Pause, receipt.DuringPause = pauseReceipt, observation
	if pauseErr != nil {
		return receipt, fmt.Errorf("pause exact non-client members: %w", pauseErr)
	}
	if err := validateQuorumPauseBoundary(pauseReceipt, baseline); err != nil {
		return receipt, err
	}
	if err := validateQuorumObservation(observation, messageX); err != nil {
		return receipt, err
	}
	recoveryStarted := time.Now()
	recovered, err := p.WaitCurrentReplicas(ctx, window)
	receipt.RecoveryElapsedNanos = time.Since(recoveryStarted).Nanoseconds()
	if err != nil {
		return receipt, err
	}
	receipt.Recovered = recovered
	if baseline.Stream.Cluster != recovered.Stream.Cluster || baseline.Consumer.Cluster != recovered.Consumer.Cluster || !sameClusterMembers(baseline.Stream, recovered.Stream) || !sameClusterMembers(baseline.Consumer, recovered.Consumer) || !sameClusterMembers(recovered.Stream, recovered.Consumer) {
		return receipt, errors.New("replication cluster identity changed across quorum pause")
	}
	receipt.StoredAAfter, err = p.GetStored(ctx, messageA, ackA.Sequence)
	if err != nil {
		return receipt, fmt.Errorf("read message A after quorum recovery: %w", err)
	}
	attemptStarted, parseErr := time.Parse(time.RFC3339Nano, observation.Publish.StartedAtUTC)
	if parseErr != nil || !canFinishWithinDuplicateWindow(time.Now(), attemptStarted, p.cfg.DuplicateWindow, p.cfg.RequestTimeout) {
		return receipt, errors.New("same-ID reconciliation cannot begin outside the duplicate window")
	}
	reconciled, err := p.publishReconcile(ctx, messageX, ackA.Sequence+1)
	if err != nil {
		return receipt, err
	}
	if observation.Publish.Acknowledged && observation.Publish.Ack != nil && (!reconciled.Duplicate || reconciled.Sequence != observation.Publish.Ack.Sequence) {
		return receipt, errors.New("same-ID reconciliation differs from the earlier acknowledged publication")
	}
	receipt.ReconciledX = reconciled
	receipt.StoredX, err = p.GetStored(ctx, messageX, reconciled.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.DeliveryX, err = p.ConsumeAndAck(ctx, messageX, reconciled.Sequence)
	if err != nil {
		return receipt, err
	}
	if err := p.RequireNoSameConsumerRedelivery(ctx); err != nil {
		return receipt, err
	}
	receipt.MessageY, err = p.Publish(ctx, messageY, false, reconciled.Sequence+1)
	if err != nil {
		return receipt, err
	}
	receipt.StoredY, err = p.GetStored(ctx, messageY, receipt.MessageY.Sequence)
	if err != nil {
		return receipt, err
	}
	receipt.DeliveryY, err = p.ConsumeAndAck(ctx, messageY, receipt.MessageY.Sequence)
	if err != nil {
		return receipt, err
	}
	if err := p.RequireNoSameConsumerRedelivery(ctx); err != nil {
		return receipt, err
	}
	receipt.FinalState, err = p.waitExactStateCount(ctx, window, ackA.Sequence, receipt.MessageY.Sequence, 3)
	return receipt, err
}

func (p *Probe) observeQuorumLoss(ctx context.Context, message Message) QuorumObservationReceipt {
	return QuorumObservationReceipt{Publish: p.publishAttempt(ctx, message), Ping: p.ping(ctx)}
}

func (p *Probe) publishAttempt(ctx context.Context, message Message) (receipt PublishAttemptReceipt) {
	receipt = PublishAttemptReceipt{StartedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), AttemptCount: 1, MessageID: message.ID, PayloadHash: hash(message.Payload)}
	defer func() { receipt.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano) }()
	if message.ID == "" || len(message.Payload) == 0 {
		receipt.ErrorClass, receipt.Error = "invalid", "message ID and payload are required"
		return receipt
	}
	msg := nats.NewMsg(p.cfg.Subject)
	msg.Header.Set(messageIDHeader, message.ID)
	msg.Data = append([]byte(nil), message.Payload...)
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	ack, err := p.js.PublishMsg(reqCtx, msg)
	cancel()
	if err != nil {
		receipt.ErrorClass, receipt.Error = classifyObservationError(err), boundedError(err)
		return receipt
	}
	if err := validatePubAck(ack, p.cfg.Stream, false, 0); err != nil {
		receipt.ErrorClass, receipt.Error = "invalid-ack", boundedError(err)
		return receipt
	}
	value := PubAckReceipt{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate, MessageID: message.ID, PayloadHash: hash(message.Payload)}
	receipt.Acknowledged, receipt.Ack = true, &value
	return receipt
}

func (p *Probe) ping(ctx context.Context) PingReceipt {
	receipt := PingReceipt{StartedAtUTC: time.Now().UTC().Format(time.RFC3339Nano)}
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	err := p.nc.FlushWithContext(reqCtx)
	cancel()
	receipt.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		receipt.ErrorClass, receipt.Error = classifyObservationError(err), boundedError(err)
		return receipt
	}
	receipt.Reachable = true
	return receipt
}

func (p *Probe) publishReconcile(ctx context.Context, message Message, sequence uint64) (PubAckReceipt, error) {
	msg := nats.NewMsg(p.cfg.Subject)
	msg.Header.Set(messageIDHeader, message.ID)
	msg.Data = append([]byte(nil), message.Payload...)
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	defer cancel()
	ack, err := p.js.PublishMsg(reqCtx, msg)
	if err != nil {
		return PubAckReceipt{}, fmt.Errorf("same-ID reconcile %q: %w", message.ID, err)
	}
	if ack == nil || ack.Stream != p.cfg.Stream || ack.Sequence != sequence {
		return PubAckReceipt{}, fmt.Errorf("same-ID reconcile PubAck differs: got %+v want stream=%q sequence=%d", ack, p.cfg.Stream, sequence)
	}
	return PubAckReceipt{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate, MessageID: message.ID, PayloadHash: hash(message.Payload)}, nil
}

func classifyObservationError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return "timeout-unknown"
	case errors.Is(err, context.Canceled):
		return "canceled-unknown"
	case errors.Is(err, nats.ErrNoResponders):
		return "no-responders"
	default:
		return "transport-or-server-error"
	}
}

func boundedError(err error) string {
	value := err.Error()
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

func validateQuorumObservation(receipt QuorumObservationReceipt, message Message) error {
	if receipt.Publish.AttemptCount != 1 || receipt.Publish.MessageID != message.ID || receipt.Publish.PayloadHash != hash(message.Payload) || receipt.Publish.StartedAtUTC == "" || receipt.Publish.FinishedAtUTC == "" {
		return errors.New("quorum-loss publication attempt identity/count is incomplete")
	}
	if receipt.Publish.Acknowledged != (receipt.Publish.Ack != nil) || receipt.Publish.Acknowledged == (receipt.Publish.ErrorClass != "") {
		return errors.New("quorum-loss publication acknowledgement/error state is contradictory")
	}
	publishStart, startErr := time.Parse(time.RFC3339Nano, receipt.Publish.StartedAtUTC)
	publishFinish, finishErr := time.Parse(time.RFC3339Nano, receipt.Publish.FinishedAtUTC)
	pingStart, pingStartErr := time.Parse(time.RFC3339Nano, receipt.Ping.StartedAtUTC)
	pingFinish, pingFinishErr := time.Parse(time.RFC3339Nano, receipt.Ping.FinishedAtUTC)
	if startErr != nil || finishErr != nil || pingStartErr != nil || pingFinishErr != nil || publishFinish.Before(publishStart) || pingFinish.Before(pingStart) {
		return errors.New("quorum-loss observation timestamps are invalid")
	}
	if receipt.Publish.Ack != nil && (receipt.Publish.Ack.Stream == "" || receipt.Publish.Ack.Sequence == 0 || receipt.Publish.Ack.MessageID != message.ID || receipt.Publish.Ack.PayloadHash != hash(message.Payload)) {
		return errors.New("quorum-loss publication acknowledgement identity differs")
	}
	if !receipt.Ping.Reachable || receipt.Ping.ErrorClass != "" || receipt.Ping.StartedAtUTC == "" || receipt.Ping.FinishedAtUTC == "" {
		return errors.New("connected NATS transport was not proven reachable during quorum loss")
	}
	return nil
}

func canFinishWithinDuplicateWindow(now, attemptStarted time.Time, window, reconcileTimeout time.Duration) bool {
	return !attemptStarted.After(now) && reconcileTimeout > 0 && now.Add(reconcileTimeout).Before(attemptStarted.Add(window))
}

func validateQuorumPauseBoundary(receipt QuorumPauseReceipt, baseline ReplicationReceipt) error {
	if receipt.ConnectedMember == "" || receipt.MaximumPauseNanos <= 0 || receipt.MaximumPauseNanos > int64(10*time.Second) || receipt.ObservedPauseNanos <= 0 || receipt.ObservedPauseNanos > receipt.MaximumPauseNanos+int64(2*time.Second) || receipt.ObservationCalls != 1 || len(receipt.Members) != 2 {
		return errors.New("quorum pause timing, membership, or observation count differs")
	}
	if !clusterHasMember(baseline.Stream, receipt.ConnectedMember) || !sameClusterMembers(baseline.Stream, baseline.Consumer) {
		return errors.New("connected member or baseline member set differs")
	}
	seen := map[string]bool{receipt.ConnectedMember: true}
	observationStart, startErr := time.Parse(time.RFC3339Nano, receiptObservationStart(receipt))
	observationEnd, endErr := time.Parse(time.RFC3339Nano, receiptObservationEnd(receipt))
	if startErr != nil || endErr != nil || observationEnd.Before(observationStart) {
		return errors.New("quorum pause observation timestamps are invalid")
	}
	var overlapStart, overlapEnd time.Time
	for _, member := range receipt.Members {
		if member.Member == "" || seen[member.Member] || !clusterHasMember(baseline.Stream, member.Member) || member.ServerIDBefore == "" || member.ServerIDBefore != member.ServerIDAfter || member.PID <= 1 || member.PIDStartTimeTicks == 0 || member.Generation == 0 || member.WorkloadUIDBefore == "" || member.WorkloadUIDBefore != member.WorkloadUIDAfter || member.VolumeUIDBefore == "" || member.VolumeUIDBefore != member.VolumeUIDAfter || member.StorePathHashBefore == "" || member.StorePathHashBefore != member.StorePathHashAfter || !member.ResumeArmedBeforePause || !member.PauseAttempted || !member.PauseSent || !member.PauseConfirmed || !member.ResumeRequested || !member.ResumeConfirmed {
			return fmt.Errorf("paused member boundary differs: %+v", member)
		}
		paused, pausedErr := time.Parse(time.RFC3339Nano, member.PausedAtUTC)
		stillPaused, stillErr := time.Parse(time.RFC3339Nano, member.StillPausedAtUTC)
		resumed, resumedErr := time.Parse(time.RFC3339Nano, member.ResumedAtUTC)
		if pausedErr != nil || stillErr != nil || resumedErr != nil || paused.After(observationStart) || stillPaused.Before(observationEnd) || resumed.Before(stillPaused) || resumed.Sub(paused) > time.Duration(receipt.MaximumPauseNanos) {
			return fmt.Errorf("paused member did not cover the exact observation window: %+v", member)
		}
		if overlapStart.IsZero() || paused.After(overlapStart) {
			overlapStart = paused
		}
		if overlapEnd.IsZero() || stillPaused.Before(overlapEnd) {
			overlapEnd = stillPaused
		}
		seen[member.Member] = true
	}
	if len(seen) != 3 {
		return errors.New("quorum pause did not bind the exact three-member set")
	}
	if overlapEnd.Sub(overlapStart).Nanoseconds() != receipt.ObservedPauseNanos || receipt.ObservedPauseNanos <= 0 {
		return errors.New("quorum pause overlap duration differs from member receipts")
	}
	return nil
}

// These fields are filled by the pause callback from the actual producer
// receipt passed back to RunQuorumOracle before validation.
func receiptObservationStart(receipt QuorumPauseReceipt) string {
	return receipt.ObservationStartedAtUTC
}
func receiptObservationEnd(receipt QuorumPauseReceipt) string {
	return receipt.ObservationFinishedAtUTC
}

func clusterHasMember(receipt ClusterReceipt, name string) bool {
	for _, member := range receipt.Members {
		if member.Name == name {
			return true
		}
	}
	return false
}

func sameClusterMembers(left, right ClusterReceipt) bool {
	if len(left.Members) != len(right.Members) {
		return false
	}
	for i := range left.Members {
		if left.Members[i].Name != right.Members[i].Name {
			return false
		}
	}
	return true
}

func validateRestartBoundary(receipt RestartBoundaryReceipt) error {
	if !receipt.ActionAttempted || !receipt.ActionSent || !receipt.ActionCompleted || receipt.ElapsedNanos <= 0 {
		return errors.New("restart boundary lacks a completed one-send action")
	}
	if receipt.Member == "" || receipt.OldProcessID == "" || receipt.NewProcessID == "" || receipt.WorkloadUIDBefore == "" || receipt.WorkloadUIDAfter == "" || receipt.VolumeUIDBefore == "" || receipt.VolumeUIDAfter == "" || receipt.StorePathHashBefore == "" || receipt.StorePathHashAfter == "" {
		return errors.New("restart boundary identity is incomplete")
	}
	if receipt.OldProcessID == receipt.NewProcessID {
		return errors.New("restart boundary retained the old process identity")
	}
	if receipt.WorkloadUIDBefore != receipt.WorkloadUIDAfter || receipt.VolumeUIDBefore != receipt.VolumeUIDAfter || receipt.StorePathHashBefore != receipt.StorePathHashAfter {
		return errors.New("restart boundary changed workload, volume, or store identity")
	}
	return nil
}

func (p *Probe) waitExactState(ctx context.Context, window time.Duration, first, last uint64) (StateReceipt, error) {
	return p.waitExactStateCount(ctx, window, first, last, 2)
}

func (p *Probe) waitExactStateCount(ctx context.Context, window time.Duration, first, last, messages uint64) (StateReceipt, error) {
	deadline, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var state StateReceipt
	var lastErr error
	for {
		state, lastErr = p.State(deadline)
		if lastErr == nil && state.Messages == messages && state.FirstSequence == first && state.LastSequence == last && state.AckFloor >= last && state.AckPending == 0 && state.ConsumerPending == 0 && state.ConsumerRedelivered == 0 {
			return state, nil
		}
		select {
		case <-deadline.Done():
			return StateReceipt{}, fmt.Errorf("post-restart state did not converge: state=%+v error=%v: %w", state, lastErr, deadline.Err())
		case <-ticker.C:
		}
	}
}

func (p *Probe) replicationState(ctx context.Context) (ReplicationReceipt, error) {
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	streamInfo, err := p.stream.Info(reqCtx)
	cancel()
	if err != nil {
		return ReplicationReceipt{}, fmt.Errorf("read stream replica state: %w", err)
	}
	reqCtx, cancel = bounded(ctx, p.cfg.RequestTimeout)
	consumerInfo, err := p.consumer.Info(reqCtx)
	cancel()
	if err != nil {
		return ReplicationReceipt{}, fmt.Errorf("read consumer replica state: %w", err)
	}
	stream, err := exactClusterReceipt(streamInfo.Cluster, p.cfg.Replicas)
	if err != nil {
		return ReplicationReceipt{}, fmt.Errorf("stream replica state: %w", err)
	}
	consumer, err := exactClusterReceipt(consumerInfo.Cluster, p.cfg.Replicas)
	if err != nil {
		return ReplicationReceipt{}, fmt.Errorf("consumer replica state: %w", err)
	}
	return ReplicationReceipt{Stream: stream, Consumer: consumer}, nil
}

func exactClusterReceipt(info *jetstream.ClusterInfo, replicas int) (ClusterReceipt, error) {
	if info == nil || info.Name == "" || info.Leader == "" {
		return ClusterReceipt{}, errors.New("cluster or leader identity is absent")
	}
	members := []ReplicaMemberReceipt{{Name: info.Leader, Leader: true, Current: true}}
	seen := map[string]bool{info.Leader: true}
	for _, peer := range info.Replicas {
		if peer == nil || peer.Name == "" || seen[peer.Name] {
			return ClusterReceipt{}, errors.New("replica member identity is absent or duplicated")
		}
		seen[peer.Name] = true
		members = append(members, ReplicaMemberReceipt{Name: peer.Name, Current: peer.Current, Offline: peer.Offline, Lag: peer.Lag})
	}
	if len(members) != replicas {
		return ClusterReceipt{}, fmt.Errorf("member count %d differs from exact replicas %d", len(members), replicas)
	}
	for _, member := range members {
		if !member.Current || member.Offline || member.Lag != 0 {
			return ClusterReceipt{}, fmt.Errorf("member %q is not current online zero-lag", member.Name)
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	return ClusterReceipt{Cluster: info.Name, Leader: info.Leader, Members: members, Replicas: replicas}, nil
}

func (p *Probe) Publish(ctx context.Context, message Message, wantDuplicate bool, wantSequence uint64) (PubAckReceipt, error) {
	if message.ID == "" || len(message.Payload) == 0 {
		return PubAckReceipt{}, errors.New("message ID and payload are required")
	}
	msg := nats.NewMsg(p.cfg.Subject)
	msg.Header.Set(messageIDHeader, message.ID)
	msg.Data = append([]byte(nil), message.Payload...)
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	defer cancel()
	ack, err := p.js.PublishMsg(reqCtx, msg)
	if err != nil {
		return PubAckReceipt{}, fmt.Errorf("publish %q: %w", message.ID, err)
	}
	if err := validatePubAck(ack, p.cfg.Stream, wantDuplicate, wantSequence); err != nil {
		return PubAckReceipt{}, err
	}
	return PubAckReceipt{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate, MessageID: message.ID, PayloadHash: hash(message.Payload)}, nil
}

func (p *Probe) ConsumeAndAck(ctx context.Context, expected Message, sequence uint64) (DeliveryReceipt, error) {
	msg, err := p.fetchOne(ctx, p.consumer, p.cfg.FetchTimeout)
	if err != nil {
		return DeliveryReceipt{}, err
	}
	receipt, err := validateDelivery(msg, expected, p.cfg.Stream, p.cfg.Subject, sequence)
	if err != nil {
		return DeliveryReceipt{}, err
	}
	ackCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	defer cancel()
	if err := msg.DoubleAck(ackCtx); err != nil {
		return DeliveryReceipt{}, fmt.Errorf("ack stream sequence %d: %w", sequence, err)
	}
	if err := p.waitAckFloor(ctx, sequence); err != nil {
		return DeliveryReceipt{}, err
	}
	return receipt, nil
}

func (p *Probe) RequireNoSameConsumerRedelivery(ctx context.Context) error {
	window, cancel := context.WithCancel(ctx)
	defer cancel()
	batch, err := p.consumer.Fetch(1, jetstream.FetchContext(window))
	if err != nil {
		return fmt.Errorf("start no-redelivery fetch: %w", err)
	}
	timer := time.NewTimer(p.cfg.FetchTimeout)
	defer timer.Stop()
	select {
	case msg, ok := <-batch.Messages():
		if !ok {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("no-redelivery observation aborted: %w", err)
			}
			if err := batch.Error(); err != nil {
				return fmt.Errorf("no-redelivery fetch: %w", err)
			}
			return errors.New("no-redelivery observation ended before its complete window")
		}
		return p.unexpectedSameConsumerDelivery(msg)
	case <-timer.C:
		cancel()
		return p.finishNoRedeliveryWindow(ctx, batch)
	case <-ctx.Done():
		cancel()
		return fmt.Errorf("no-redelivery observation aborted: %w", ctx.Err())
	}
}

func (p *Probe) finishNoRedeliveryWindow(ctx context.Context, batch jetstream.MessageBatch) error {
	deadline := time.NewTimer(p.cfg.RequestTimeout)
	defer deadline.Stop()
	for {
		select {
		case msg, ok := <-batch.Messages():
			if ok {
				return p.unexpectedSameConsumerDelivery(msg)
			}
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("no-redelivery observation aborted: %w", err)
			}
			if err := batch.Error(); err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("no-redelivery fetch after completed window: %w", err)
			}
			return nil
		case <-ctx.Done():
			return fmt.Errorf("no-redelivery observation aborted: %w", ctx.Err())
		case <-deadline.C:
			return errors.New("no-redelivery fetch did not quiesce after completed window")
		}
	}
}

func (p *Probe) unexpectedSameConsumerDelivery(msg jetstream.Msg) error {
	meta, err := msg.Metadata()
	if err != nil {
		return fmt.Errorf("unexpected same-consumer delivery with unreadable metadata: %w", err)
	}
	return fmt.Errorf("acknowledged stream sequence %d redelivered to consumer %q", meta.Sequence.Stream, p.cfg.Consumer)
}

func (p *Probe) GetStored(ctx context.Context, expected Message, sequence uint64) (StoredReceipt, error) {
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	defer cancel()
	msg, err := p.stream.GetMsg(reqCtx, sequence)
	if err != nil {
		return StoredReceipt{}, fmt.Errorf("direct get stream sequence %d: %w", sequence, err)
	}
	return validateStored(msg, expected, p.cfg.Subject, sequence)
}

func (p *Probe) ConsumeStoredWithFreshConsumer(ctx context.Context, name string, expected Message, sequence uint64) (DeliveryReceipt, error) {
	if name == "" || name == p.cfg.Consumer {
		return DeliveryReceipt{}, errors.New("fresh consumer must have a distinct nonempty name")
	}
	reqCtx, cancel := bounded(ctx, p.cfg.RequestTimeout)
	_, err := p.stream.Consumer(reqCtx, name)
	cancel()
	if err == nil {
		return DeliveryReceipt{}, fmt.Errorf("refusing preexisting distinct consumer %q", name)
	}
	if !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return DeliveryReceipt{}, fmt.Errorf("check distinct consumer freshness %q: %w", name, err)
	}
	reqCtx, cancel = bounded(ctx, p.cfg.RequestTimeout)
	consumer, err := p.stream.CreateConsumer(reqCtx, jetstream.ConsumerConfig{
		Name:          name,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverByStartSequencePolicy,
		OptStartSeq:   sequence,
		FilterSubject: p.cfg.Subject,
		AckWait:       p.cfg.AckWait,
		MaxDeliver:    1,
		Metadata:      ownershipMetadata(p.cfg.OwnerNonce),
	})
	cancel()
	if err != nil {
		return DeliveryReceipt{}, fmt.Errorf("create distinct consumer %q: %w", name, err)
	}
	reqCtx, cancel = bounded(ctx, p.cfg.RequestTimeout)
	consumerInfo, err := consumer.Info(reqCtx)
	cancel()
	if err != nil {
		return DeliveryReceipt{}, fmt.Errorf("verify distinct consumer %q ownership; cleanup authority withheld: %w", name, err)
	}
	if err := validateOwnedConsumer(consumerInfo, p.cfg.Stream, p.cfg.Subject, name, p.cfg.OwnerNonce); err != nil {
		return DeliveryReceipt{}, err
	}
	receipt, operationErr := func() (DeliveryReceipt, error) {
		msg, err := p.fetchOne(ctx, consumer, p.cfg.FetchTimeout)
		if err != nil {
			return DeliveryReceipt{}, err
		}
		receipt, err := validateDelivery(msg, expected, p.cfg.Stream, p.cfg.Subject, sequence)
		if err != nil {
			return DeliveryReceipt{}, err
		}
		ackCtx, ackCancel := bounded(ctx, p.cfg.RequestTimeout)
		defer ackCancel()
		if err := msg.DoubleAck(ackCtx); err != nil {
			return DeliveryReceipt{}, fmt.Errorf("ack distinct-consumer stream sequence %d: %w", sequence, err)
		}
		return receipt, nil
	}()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), p.cfg.RequestTimeout)
	cleanupErr := p.deleteConsumer(cleanupCtx, name)
	cleanupCancel()
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("cleanup distinct consumer %q: %w", name, cleanupErr)
	}
	return receipt, errors.Join(operationErr, cleanupErr)
}

func (p *Probe) fetchOne(ctx context.Context, consumer jetstream.Consumer, wait time.Duration) (jetstream.Msg, error) {
	window, cancel := context.WithCancel(ctx)
	defer cancel()
	batch, err := consumer.Fetch(1, jetstream.FetchContext(window))
	if err != nil {
		return nil, fmt.Errorf("start bounded fetch: %w", err)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case msg, ok := <-batch.Messages():
		if ok {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("bounded fetch aborted: %w", err)
			}
			return msg, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("bounded fetch aborted: %w", err)
		}
		if err := batch.Error(); err != nil {
			return nil, fmt.Errorf("bounded fetch: %w", err)
		}
		return nil, errors.New("bounded fetch returned no message before its window completed")
	case <-timer.C:
		cancel()
		return nil, errors.New("bounded fetch observation window expired")
	case <-ctx.Done():
		cancel()
		return nil, fmt.Errorf("bounded fetch aborted: %w", ctx.Err())
	}
}

func (p *Probe) waitAckFloor(ctx context.Context, sequence uint64) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline, cancel := bounded(ctx, p.cfg.RequestTimeout)
	defer cancel()
	for {
		info, err := p.consumer.Info(deadline)
		if err != nil {
			return fmt.Errorf("read consumer ACK state: %w", err)
		}
		if info.NumAckPending == 0 && info.AckFloor.Stream >= sequence {
			return nil
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("consumer ACK floor did not reach stream sequence %d: %w", sequence, deadline.Err())
		case <-ticker.C:
		}
	}
}

func validateConfig(cfg Config) error {
	if cfg.URL == "" || cfg.Stream == "" || cfg.Subject == "" || cfg.Consumer == "" || cfg.OwnerNonce == "" {
		return errors.New("URL, stream, subject, consumer, and owner nonce are required")
	}
	if cfg.Replicas < 1 {
		return errors.New("replicas must be positive")
	}
	for name, value := range map[string]time.Duration{"connect timeout": cfg.ConnectTimeout, "request timeout": cfg.RequestTimeout, "fetch timeout": cfg.FetchTimeout, "ACK wait": cfg.AckWait, "duplicate window": cfg.DuplicateWindow} {
		if value <= 0 {
			return fmt.Errorf("%s must be positive", name)
		}
	}
	return nil
}

func ownershipMetadata(nonce string) map[string]string {
	return map[string]string{ownerMetadataKey: nonce, schemaMetadataKey: fixtureSchema}
}

func exactOwnership(metadata map[string]string, nonce string) bool {
	return len(metadata) == 2 && metadata[ownerMetadataKey] == nonce && metadata[schemaMetadataKey] == fixtureSchema
}

func validateFreshOwnedStream(info *jetstream.StreamInfo, cfg Config) error {
	if info == nil || info.Config.Name != cfg.Stream || len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != cfg.Subject || info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != cfg.Replicas || info.Config.Duplicates != cfg.DuplicateWindow || !exactOwnership(info.Config.Metadata, cfg.OwnerNonce) {
		return fmt.Errorf("new stream ownership/config differs; cleanup authority withheld: %+v", info)
	}
	if info.State.Msgs != 0 || info.State.Bytes != 0 || info.State.Consumers != 0 {
		return fmt.Errorf("new stream was not fresh; cleanup authority withheld: %+v", info.State)
	}
	return nil
}

func validateOwnedConsumer(info *jetstream.ConsumerInfo, stream, subject, name, ownerNonce string) error {
	if info == nil || info.Stream != stream || info.Name != name || info.Config.FilterSubject != subject || info.Config.AckPolicy != jetstream.AckExplicitPolicy || !exactOwnership(info.Config.Metadata, ownerNonce) {
		return fmt.Errorf("consumer ownership/config differs; cleanup authority withheld: %+v", info)
	}
	return nil
}

func validatePubAck(ack *jetstream.PubAck, stream string, duplicate bool, sequence uint64) error {
	if ack == nil || ack.Stream != stream || ack.Sequence == 0 || ack.Duplicate != duplicate {
		return fmt.Errorf("PubAck identity differs: got %+v, want stream=%q duplicate=%t nonzero sequence", ack, stream, duplicate)
	}
	if sequence != 0 && ack.Sequence != sequence {
		return fmt.Errorf("PubAck sequence %d differs from exact %d", ack.Sequence, sequence)
	}
	return nil
}

func validateDelivery(msg jetstream.Msg, expected Message, stream, subject string, sequence uint64) (DeliveryReceipt, error) {
	meta, err := msg.Metadata()
	if err != nil {
		return DeliveryReceipt{}, fmt.Errorf("read delivery metadata: %w", err)
	}
	if meta.Stream != stream || msg.Subject() != subject || meta.Sequence.Stream != sequence || msg.Headers().Get(messageIDHeader) != expected.ID || !bytes.Equal(msg.Data(), expected.Payload) {
		return DeliveryReceipt{}, fmt.Errorf("delivery identity differs: stream=%q subject=%q sequence=%d messageID=%q payloadSHA256=%s", meta.Stream, msg.Subject(), meta.Sequence.Stream, msg.Headers().Get(messageIDHeader), hash(msg.Data()))
	}
	return DeliveryReceipt{StreamSequence: meta.Sequence.Stream, ConsumerSequence: meta.Sequence.Consumer, Deliveries: meta.NumDelivered, MessageID: expected.ID, PayloadHash: hash(expected.Payload)}, nil
}

func validateStored(msg *jetstream.RawStreamMsg, expected Message, subject string, sequence uint64) (StoredReceipt, error) {
	if msg == nil || msg.Sequence != sequence || msg.Subject != subject || msg.Header.Get(messageIDHeader) != expected.ID || !bytes.Equal(msg.Data, expected.Payload) {
		return StoredReceipt{}, fmt.Errorf("stored message identity differs at stream sequence %d", sequence)
	}
	return StoredReceipt{StreamSequence: msg.Sequence, Subject: msg.Subject, MessageID: expected.ID, PayloadHash: hash(expected.Payload)}, nil
}

func bounded(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

func hash(value []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(value))
}
