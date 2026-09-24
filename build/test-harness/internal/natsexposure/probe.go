// Package natsexposure measures delivery of one owned synthetic JetStream
// message to a separately supplied NATS connection. It creates no client
// identity or subject policy and does not send a Phorvex event.
package natsexposure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	ownerKey       = "fixture.phorvex.ai/owner-nonce"
	schemaKey      = "fixture.phorvex.ai/schema"
	schema         = "nats-owned-exposure-v1"
	maxPayload     = 256
	maxWireBytes   = 512
	maxStreamBytes = 1 << 20
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9_-]{8,96}$`)
var safeSubject = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$`)

// Config names all resources explicitly; none is discovered or adopted.
// The runner must pin the supplied connections to exact broker observations.
type Config struct {
	Nonce                     string
	Stream                    string
	Subject                   string
	Consumer                  string
	ExpectedWriterServerID    string
	ExpectedAdversaryServerID string
	RequestTimeout            time.Duration
	ReceiveTimeout            time.Duration
	AckWait                   time.Duration
	BarrierTimeout            time.Duration
}

// PhaseRecorder must durably persist the supplied receipt before returning.
// A failed intent record aborts the corresponding mutation. It receives no
// credentials or connection URLs.
type PhaseRecorder func(context.Context, Receipt) error

// BeforePublish is the runner's one bounded prepublication decision barrier.
// The callback must independently join any signal/manager evidence; returning
// nil only permits publication and does not assert a brain outcome.
type BeforePublish func(context.Context, Receipt) error

// Receipt contains only synthetic names, server IDs, hashes and outcomes.
// Validity and objective are separate: timeout is never a denial.
type Receipt struct {
	Stream                  string `json:"stream"`
	Subject                 string `json:"subject"`
	Consumer                string `json:"consumer"`
	Nonce                   string `json:"nonce"`
	WriterServerID          string `json:"writerServerID"`
	AdversaryServerID       string `json:"adversaryServerID"`
	SubscriptionFlushed     bool   `json:"subscriptionFlushed"`
	PublishAttempted        bool   `json:"publishAttempted"`
	PubAckSequence          uint64 `json:"pubAckSequence,omitempty"`
	StreamCreatedUTC        string `json:"streamCreatedUTC,omitempty"`
	PayloadSHA256           string `json:"payloadSHA256"`
	AdversaryPayloadSHA256  string `json:"adversaryPayloadSHA256,omitempty"`
	LegitimatePayloadSHA256 string `json:"legitimatePayloadSHA256,omitempty"`
	StoredPayloadSHA256     string `json:"storedPayloadSHA256,omitempty"`
	LegitimateAcked         bool   `json:"legitimateAcked"`
	AdversaryObservation    string `json:"adversaryObservation"`
	Objective               string `json:"objective"`
	Validity                string `json:"validity"`
	Cleanup                 string `json:"cleanup"`
	Phase                   string `json:"phase"`
}

func validate(cfg Config, writer, adversary *nats.Conn, payload []byte) error {
	if writer == nil || adversary == nil || writer == adversary || writer.Status() != nats.CONNECTED || adversary.Status() != nats.CONNECTED {
		return errors.New("two distinct connected NATS actors are required")
	}
	if writer.Opts.MaxReconnect != 0 || adversary.Opts.MaxReconnect != 0 || !adversary.Opts.PermissionErrOnSubscribe {
		return errors.New("actors must disable reconnects and adversary must surface subscription permission errors")
	}
	if !safeName.MatchString(cfg.Nonce) || !safeName.MatchString(cfg.Stream) || !safeName.MatchString(cfg.Consumer) || !safeSubject.MatchString(cfg.Subject) || len(cfg.Subject) > 128 {
		return errors.New("bounded explicit nonce, stream, subject and consumer names are required")
	}
	if !bytes.Contains([]byte(cfg.Stream), []byte(cfg.Nonce)) || !bytes.Contains([]byte(cfg.Subject), []byte(cfg.Nonce)) || !bytes.Contains([]byte(cfg.Consumer), []byte(cfg.Nonce)) || cfg.Stream == cfg.Consumer {
		return errors.New("all resource names must contain the caller nonce")
	}
	if cfg.ExpectedWriterServerID == "" || cfg.ExpectedAdversaryServerID == "" || cfg.RequestTimeout <= 0 || cfg.RequestTimeout > 10*time.Second || cfg.ReceiveTimeout <= 0 || cfg.ReceiveTimeout > 10*time.Second || cfg.AckWait <= 0 || cfg.AckWait > 30*time.Second || cfg.BarrierTimeout <= 0 || cfg.BarrierTimeout > 30*time.Second || len(payload) == 0 || len(payload) > maxPayload {
		return errors.New("server IDs, finite timeouts and one bounded payload are required")
	}
	if writer.ConnectedServerId() != cfg.ExpectedWriterServerID || adversary.ConnectedServerId() != cfg.ExpectedAdversaryServerID {
		return errors.New("actor connection selected a different broker")
	}
	return nil
}

func metadata(nonce string) map[string]string {
	return map[string]string{ownerKey: nonce, schemaKey: schema}
}

func exactStream(info *jetstream.StreamInfo, cfg Config, created time.Time) bool {
	if info == nil || !info.Created.Equal(created) || info.Config.Name != cfg.Stream || len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != cfg.Subject || info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 1 || info.Config.MaxMsgs != 3 || info.Config.MaxBytes != maxStreamBytes || info.Config.MaxAge != 120*time.Second || info.Config.MaxConsumers != 1 || info.Config.MaxMsgSize != maxWireBytes || len(info.Config.Metadata) != 2 {
		return false
	}
	return info.Config.Metadata[ownerKey] == cfg.Nonce && info.Config.Metadata[schemaKey] == schema
}

func requestContext(ctx context.Context, cfg Config) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, cfg.RequestTimeout)
}

// cleanup deletes only the exact stream created by this run. Unknown ownership
// leaves the stream for exact-ID manual review instead of risking another stream.
func cleanup(parent context.Context, cfg Config, js jetstream.JetStream, created time.Time, beforeDelete func() error) string {
	ctx, cancel := context.WithTimeout(parent, cfg.RequestTimeout)
	defer cancel()
	stream, err := js.Stream(ctx, cfg.Stream)
	if err != nil {
		return "WITHHELD_IDENTITY_UNAVAILABLE"
	}
	info, err := stream.Info(ctx)
	if err != nil || !exactStream(info, cfg, created) {
		return "WITHHELD_OWNERSHIP_MISMATCH"
	}
	if beforeDelete == nil || beforeDelete() != nil {
		return "WITHHELD_RECORDER_FAILURE"
	}
	if err := js.DeleteStream(ctx, cfg.Stream); err != nil {
		return "DELETE_AMBIGUOUS_NO_RETRY"
	}
	_, err = js.Stream(ctx, cfg.Stream)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return "CONFIRMED_ABSENT"
	}
	return "DELETE_UNCONFIRMED"
}

// Run makes at most one create, one subscription, one publication and one
// cleanup attempt. A PubAck error is an unknown commit, never retried.
func Run(ctx context.Context, cfg Config, writer, adversary *nats.Conn, payload []byte, recorder PhaseRecorder, beforePublish BeforePublish) (receipt Receipt, runErr error) {
	receipt = Receipt{Stream: cfg.Stream, Subject: cfg.Subject, Consumer: cfg.Consumer, Nonce: cfg.Nonce,
		PayloadSHA256: digest(payload), AdversaryObservation: "NOT_ATTEMPTED", Objective: "UNKNOWN",
		Validity: "INCONCLUSIVE", Cleanup: "NOT_CREATED", Phase: "VALIDATE"}
	if recorder == nil || beforePublish == nil {
		return receipt, errors.New("durable phase recorder and prepublication barrier are required")
	}
	if err := validate(cfg, writer, adversary, payload); err != nil {
		return receipt, err
	}
	recordContext := func(recordCtx context.Context, phase string) error {
		receipt.Phase = phase
		if err := recorder(recordCtx, receipt); err != nil {
			return errors.New("durable phase recorder failed")
		}
		return nil
	}
	record := func(phase string) error { return recordContext(ctx, phase) }
	receipt.WriterServerID = writer.ConnectedServerId()
	receipt.AdversaryServerID = adversary.ConnectedServerId()
	if err := record("ADMITTED"); err != nil {
		return receipt, err
	}
	js, err := jetstream.New(writer)
	if err != nil {
		return receipt, errors.New("writer JetStream context unavailable")
	}
	checkCtx, cancel := requestContext(ctx, cfg)
	_, err = js.Stream(checkCtx, cfg.Stream)
	cancel()
	if err == nil {
		return receipt, errors.New("refusing preexisting stream")
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return receipt, errors.New("stream freshness unknown")
	}
	if err := record("CREATE_INTENT"); err != nil {
		return receipt, err
	}
	createCtx, cancel := requestContext(ctx, cfg)
	stream, err := js.CreateStream(createCtx, jetstream.StreamConfig{
		Name: cfg.Stream, Subjects: []string{cfg.Subject}, Storage: jetstream.FileStorage,
		Replicas: 1, MaxMsgs: 3, MaxBytes: maxStreamBytes, MaxAge: 120 * time.Second,
		MaxConsumers: 1, MaxMsgSize: maxWireBytes,
		Metadata: metadata(cfg.Nonce),
	})
	cancel()
	if err != nil {
		receipt.Cleanup = "WITHHELD_AMBIGUOUS_CREATE"
		_ = record("CREATE_AMBIGUOUS")
		return receipt, errors.New("stream create outcome ambiguous; no retry or deletion")
	}
	// This is the create response's identity. An independent Info cannot be
	// allowed to replace it, even if another same-name stream appears later.
	cached := stream.CachedInfo()
	if cached == nil || cached.Created.IsZero() || !exactStream(cached, cfg, cached.Created) {
		receipt.Cleanup = "WITHHELD_UNVERIFIED_CREATE"
		return receipt, errors.New("create response stream identity unverified")
	}
	created := cached.Created
	receipt.StreamCreatedUTC = created.UTC().Format(time.RFC3339Nano)
	receipt.Cleanup = "WITHHELD_UNVERIFIED_CREATE"
	if err := record("CREATE_RESPONSE"); err != nil {
		return receipt, err
	}
	infoCtx, cancel := requestContext(ctx, cfg)
	info, err := stream.Info(infoCtx)
	cancel()
	if err != nil || info == nil || !exactStream(info, cfg, created) || info.State.Msgs != 0 || info.State.Consumers != 0 {
		receipt.Cleanup = "WITHHELD_UNVERIFIED_CREATE"
		return receipt, errors.New("created stream identity or empty state unverified")
	}
	receipt.Cleanup = "PENDING"
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
		receipt.Cleanup = cleanup(cleanupCtx, cfg, js, created, func() error { return recordContext(cleanupCtx, "DELETE_INTENT") })
		cleanupCancel()
		if receipt.Cleanup != "CONFIRMED_ABSENT" {
			receipt.Validity = "INCONCLUSIVE"
			if runErr == nil {
				runErr = errors.New("exact owned stream cleanup unconfirmed")
			}
		}
		doneCtx, doneCancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
		doneErr := recordContext(doneCtx, "DONE")
		doneCancel()
		if doneErr != nil {
			receipt.Validity = "INCONCLUSIVE"
			if runErr == nil {
				runErr = doneErr
			}
		}
	}()
	if err := record("CREATE_VERIFIED"); err != nil {
		return receipt, err
	}

	if err := record("CONSUMER_INTENT"); err != nil {
		return receipt, err
	}
	consumerCtx, cancel := requestContext(ctx, cfg)
	consumer, err := stream.CreateConsumer(consumerCtx, jetstream.ConsumerConfig{
		Durable: cfg.Consumer, AckPolicy: jetstream.AckExplicitPolicy,
		AckWait: cfg.AckWait, MaxDeliver: 1, FilterSubject: cfg.Subject,
		Metadata: metadata(cfg.Nonce),
	})
	cancel()
	if err != nil {
		return receipt, errors.New("owned consumer creation failed or ambiguous")
	}
	consumerCtx, cancel = requestContext(ctx, cfg)
	consumerInfo, err := consumer.Info(consumerCtx)
	cancel()
	if err != nil || consumerInfo == nil || consumerInfo.Stream != cfg.Stream || consumerInfo.Name != cfg.Consumer || consumerInfo.Config.FilterSubject != cfg.Subject || consumerInfo.Config.AckPolicy != jetstream.AckExplicitPolicy || len(consumerInfo.Config.Metadata) != 2 || consumerInfo.Config.Metadata[ownerKey] != cfg.Nonce || consumerInfo.Config.Metadata[schemaKey] != schema {
		return receipt, errors.New("owned consumer identity unverified")
	}
	if err := record("CONSUMER_VERIFIED"); err != nil {
		return receipt, err
	}

	if err := record("SUBSCRIBE_INTENT"); err != nil {
		return receipt, err
	}
	sub, err := adversary.SubscribeSync(cfg.Subject)
	if err != nil && !errors.Is(err, nats.ErrPermissionViolation) {
		return receipt, errors.New("adversary subscription failed before publication")
	}
	if sub != nil {
		defer sub.Unsubscribe()
	}
	subscribeErr := err
	flushCtx, flushCancel := requestContext(ctx, cfg)
	flushErr := adversary.FlushWithContext(flushCtx)
	flushCancel()
	if flushErr != nil {
		return receipt, errors.New("adversary subscription flush failed; no publication")
	}
	receipt.SubscriptionFlushed = true
	if err := record("SUBSCRIPTION_FLUSHED"); err != nil {
		return receipt, err
	}
	if writer.Status() != nats.CONNECTED || adversary.Status() != nats.CONNECTED || writer.ConnectedServerId() != cfg.ExpectedWriterServerID || adversary.ConnectedServerId() != cfg.ExpectedAdversaryServerID {
		return receipt, errors.New("broker connection changed before publication")
	}
	if err := record("PREPUBLICATION_BARRIER_INTENT"); err != nil {
		return receipt, err
	}
	barrierCtx, barrierCancel := context.WithTimeout(ctx, cfg.BarrierTimeout)
	barrierErr := beforePublish(barrierCtx, receipt)
	deadlineErr := barrierCtx.Err()
	barrierCancel()
	if barrierErr != nil || deadlineErr != nil {
		_ = record("PREPUBLICATION_BARRIER_REFUSED")
		return receipt, errors.New("prepublication barrier refused or failed")
	}
	if err := record("PREPUBLICATION_BARRIER_RETURNED"); err != nil {
		return receipt, err
	}
	if writer.Status() != nats.CONNECTED || adversary.Status() != nats.CONNECTED || writer.ConnectedServerId() != cfg.ExpectedWriterServerID || adversary.ConnectedServerId() != cfg.ExpectedAdversaryServerID {
		return receipt, errors.New("broker connection changed during prepublication barrier")
	}

	if err := record("PUBLISH_INTENT"); err != nil {
		return receipt, err
	}
	message := nats.NewMsg(cfg.Subject)
	message.Header.Set("Nats-Msg-Id", "cat-"+cfg.Nonce)
	message.Data = append([]byte(nil), payload...)
	receipt.PublishAttempted = true
	pubCtx, pubCancel := requestContext(ctx, cfg)
	ack, err := publishOnce(pubCtx, js, message)
	pubCancel()
	if err != nil || ack == nil {
		_ = record("PUBLISH_AMBIGUOUS")
		return receipt, errors.New("publication outcome ambiguous; no replay")
	}
	if ack.Stream != cfg.Stream || ack.Sequence != 1 || ack.Duplicate {
		return receipt, errors.New("PubAck stream/sequence/duplicate identity differs")
	}
	receipt.PubAckSequence = ack.Sequence
	if err := record("PUBACK_VERIFIED"); err != nil {
		return receipt, err
	}

	receipt.Phase = "LEGITIMATE_READBACK"
	batch, err := consumer.Fetch(1, jetstream.FetchMaxWait(cfg.ReceiveTimeout))
	if err != nil {
		return receipt, errors.New("legitimate consumer fetch failed")
	}
	var delivered jetstream.Msg
	for msg := range batch.Messages() {
		if delivered != nil {
			return receipt, errors.New("legitimate consumer received extra message")
		}
		delivered = msg
	}
	if batch.Error() != nil || delivered == nil {
		return receipt, errors.New("legitimate consumer delivery absent or ambiguous")
	}
	meta, err := delivered.Metadata()
	if err != nil || meta.Stream != cfg.Stream || meta.Sequence.Stream != ack.Sequence || delivered.Subject() != cfg.Subject || delivered.Headers().Get("Nats-Msg-Id") != "cat-"+cfg.Nonce || !bytes.Equal(delivered.Data(), payload) {
		return receipt, errors.New("legitimate consumer message identity differs")
	}
	receipt.LegitimatePayloadSHA256 = digest(delivered.Data())
	ackCtx, ackCancel := requestContext(ctx, cfg)
	err = delivered.DoubleAck(ackCtx)
	ackCancel()
	if err != nil {
		return receipt, errors.New("legitimate consumer ACK unconfirmed")
	}
	receipt.LegitimateAcked = true
	if err := record("LEGITIMATE_ACKED"); err != nil {
		return receipt, err
	}
	storedCtx, storedCancel := requestContext(ctx, cfg)
	stored, err := stream.GetMsg(storedCtx, ack.Sequence)
	storedCancel()
	if err != nil || stored == nil || stored.Sequence != ack.Sequence || stored.Subject != cfg.Subject || stored.Header.Get("Nats-Msg-Id") != "cat-"+cfg.Nonce || !bytes.Equal(stored.Data, payload) {
		return receipt, errors.New("independent stored message identity differs")
	}
	receipt.StoredPayloadSHA256 = digest(stored.Data)
	if err := record("LEGITIMATE_READBACK_VERIFIED"); err != nil {
		return receipt, err
	}

	receipt.Phase = "ADVERSARY_OBSERVATION"
	if errors.Is(subscribeErr, nats.ErrPermissionViolation) {
		receipt.AdversaryObservation = "SUBSCRIPTION_DENIED"
		receipt.Objective = "NOT_REACHED"
	} else if sub == nil {
		return receipt, errors.New("adversary subscription identity missing")
	} else {
		if err := observeAdversary(ctx, cfg, sub, payload, &receipt); err != nil {
			return receipt, err
		}
	}
	if writer.ConnectedServerId() != cfg.ExpectedWriterServerID || adversary.ConnectedServerId() != cfg.ExpectedAdversaryServerID {
		return receipt, errors.New("broker connection changed during observation")
	}
	if err := record("ADVERSARY_OBSERVED"); err != nil {
		return receipt, err
	}
	receipt.Validity = "VALID"
	return receipt, nil
}

func publishOnce(ctx context.Context, js jetstream.JetStream, message *nats.Msg) (*jetstream.PubAck, error) {
	return js.PublishMsg(ctx, message, jetstream.WithRetryAttempts(0))
}

func observeAdversary(ctx context.Context, cfg Config, sub *nats.Subscription, payload []byte, receipt *Receipt) error {
	observeCtx, observeCancel := context.WithTimeout(ctx, cfg.ReceiveTimeout)
	defer observeCancel()
	got, err := sub.NextMsgWithContext(observeCtx)
	switch {
	case errors.Is(err, nats.ErrPermissionViolation):
		receipt.AdversaryObservation = "SUBSCRIPTION_DENIED"
		receipt.Objective = "NOT_REACHED"
	case err != nil:
		receipt.AdversaryObservation = "TIMEOUT_OR_TRANSPORT_UNKNOWN"
		return errors.New("adversary delivery unknown, not a denial")
	case got == nil || got.Subject != cfg.Subject || got.Header.Get("Nats-Msg-Id") != "cat-"+cfg.Nonce || !bytes.Equal(got.Data, payload):
		receipt.AdversaryObservation = "WRONG_MESSAGE"
		return errors.New("adversary received non-owned message")
	default:
		receipt.AdversaryPayloadSHA256 = digest(got.Data)
		receipt.AdversaryObservation = "EXACT_PAYLOAD_RECEIVED"
		receipt.Objective = "REACHED"
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CheckOwnership is exported only for runner admission and cleanup review.
// It reports whether a live stream still matches the exact run-owned identity.
func CheckOwnership(info *jetstream.StreamInfo, cfg Config, created time.Time) error {
	if !exactStream(info, cfg, created) {
		return fmt.Errorf("exact stream owner identity differs for %q", cfg.Stream)
	}
	return nil
}
