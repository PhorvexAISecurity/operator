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
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const messageIDHeader = "Nats-Msg-Id"

type Config struct {
	URL             string
	Stream          string
	Subject         string
	Consumer        string
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

type Probe struct {
	cfg      Config
	nc       *nats.Conn
	js       jetstream.JetStream
	stream   jetstream.Stream
	consumer jetstream.Consumer
}

func Open(ctx context.Context, cfg Config) (*Probe, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	nc, err := nats.Connect(cfg.URL,
		nats.Name("phorvex-jetstream-durability-probe"),
		nats.Timeout(cfg.ConnectTimeout),
		nats.MaxReconnects(0),
		nats.NoCallbacksAfterClientClose(),
	)
	if err != nil {
		return nil, fmt.Errorf("connect NATS: %w", err)
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
	stream, err := js.CreateStream(reqCtx, jetstream.StreamConfig{
		Name:       cfg.Stream,
		Subjects:   []string{cfg.Subject},
		Storage:    jetstream.FileStorage,
		Replicas:   cfg.Replicas,
		Duplicates: cfg.DuplicateWindow,
	})
	cancel()
	if err != nil {
		return closeOnError(fmt.Errorf("create exact stream %q: %w", cfg.Stream, err))
	}
	reqCtx, cancel = bounded(ctx, cfg.RequestTimeout)
	consumer, err := stream.CreateOrUpdateConsumer(reqCtx, jetstream.ConsumerConfig{
		Durable:       cfg.Consumer,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       cfg.AckWait,
		MaxDeliver:    2,
		FilterSubject: cfg.Subject,
	})
	cancel()
	if err != nil {
		return closeOnError(fmt.Errorf("create exact consumer %q: %w", cfg.Consumer, err))
	}
	return &Probe{cfg: cfg, nc: nc, js: js, stream: stream, consumer: consumer}, nil
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
	if streamInfo.Config.Name != p.cfg.Stream || len(streamInfo.Config.Subjects) != 1 || streamInfo.Config.Subjects[0] != p.cfg.Subject || streamInfo.Config.Replicas != p.cfg.Replicas || streamInfo.Config.Duplicates != p.cfg.DuplicateWindow {
		return StateReceipt{}, fmt.Errorf("stream config identity differs: %+v", streamInfo.Config)
	}
	if consumerInfo.Stream != p.cfg.Stream || consumerInfo.Name != p.cfg.Consumer || consumerInfo.Config.FilterSubject != p.cfg.Subject || consumerInfo.Config.AckPolicy != jetstream.AckExplicitPolicy {
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
	batch, err := p.consumer.Fetch(1, jetstream.FetchMaxWait(p.cfg.FetchTimeout))
	if err != nil {
		return fmt.Errorf("start no-redelivery fetch: %w", err)
	}
	for msg := range batch.Messages() {
		meta, metaErr := msg.Metadata()
		if metaErr != nil {
			return fmt.Errorf("unexpected same-consumer delivery with unreadable metadata: %w", metaErr)
		}
		return fmt.Errorf("acknowledged stream sequence %d redelivered to consumer %q", meta.Sequence.Stream, p.cfg.Consumer)
	}
	if err := batch.Error(); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, nats.ErrTimeout) {
		return fmt.Errorf("no-redelivery fetch: %w", err)
	}
	return nil
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
	consumer, err := p.stream.CreateConsumer(reqCtx, jetstream.ConsumerConfig{
		Name:          name,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverByStartSequencePolicy,
		OptStartSeq:   sequence,
		FilterSubject: p.cfg.Subject,
		AckWait:       p.cfg.AckWait,
		MaxDeliver:    1,
	})
	cancel()
	if err != nil {
		return DeliveryReceipt{}, fmt.Errorf("create distinct consumer %q: %w", name, err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), p.cfg.RequestTimeout)
		defer cleanupCancel()
		_ = p.stream.DeleteConsumer(cleanupCtx, name)
	}()
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
}

func (p *Probe) fetchOne(ctx context.Context, consumer jetstream.Consumer, wait time.Duration) (jetstream.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	batch, err := consumer.Fetch(1, jetstream.FetchMaxWait(wait))
	if err != nil {
		return nil, fmt.Errorf("start bounded fetch: %w", err)
	}
	for msg := range batch.Messages() {
		return msg, nil
	}
	if err := batch.Error(); err != nil {
		return nil, fmt.Errorf("bounded fetch: %w", err)
	}
	return nil, errors.New("bounded fetch returned no message")
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
	if cfg.URL == "" || cfg.Stream == "" || cfg.Subject == "" || cfg.Consumer == "" {
		return errors.New("URL, stream, subject, and consumer are required")
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
