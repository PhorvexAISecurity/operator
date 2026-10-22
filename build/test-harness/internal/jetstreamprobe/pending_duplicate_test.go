package jetstreamprobe

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// pendingDuplicateJS answers each publication with the next queued acknowledgement.
type pendingDuplicateJS struct {
	jetstream.JetStream
	acks  []*jetstream.PubAck
	calls int
}

func (f *pendingDuplicateJS) PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	ack := f.acks[min(f.calls, len(f.acks)-1)]
	f.calls++
	return ack, nil
}

func TestSameIDReconcileWaitsForAPendingDuplicate(t *testing.T) {
	pending := &jetstream.PubAck{Stream: "DURABILITY", Duplicate: true}
	stored := &jetstream.PubAck{Stream: "DURABILITY", Sequence: 2, Duplicate: true}
	js := &pendingDuplicateJS{acks: []*jetstream.PubAck{pending, pending, stored}}
	p := &Probe{cfg: Config{Stream: "DURABILITY", Subject: "durability.x", RequestTimeout: time.Second}, js: js}
	x := Message{ID: "quorum-x", Payload: []byte("quorum-payload-x")}
	got, err := p.publishReconcile(t.Context(), x, 2)
	if err != nil || got.Sequence != 2 || !got.Duplicate || js.calls != 3 {
		t.Fatalf("reconcile = %+v, %v after %d publications", got, err, js.calls)
	}
	// A duplicate that never reports where it was stored still fails, after a bounded number of tries.
	js = &pendingDuplicateJS{acks: []*jetstream.PubAck{pending}}
	p.js = js
	if _, err := p.publishReconcile(t.Context(), x, 2); err == nil || js.calls != pendingDuplicateAttempts {
		t.Fatalf("an unresolved pending duplicate: err=%v after %d publications", err, js.calls)
	}
}
