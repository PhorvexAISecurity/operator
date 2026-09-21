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
