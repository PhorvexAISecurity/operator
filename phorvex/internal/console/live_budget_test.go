package console

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ResponseRecorder writes synchronously in memory; expose the production
// deadline API explicitly without pretending it tests network backpressure.
type liveTestRecorder struct{ *httptest.ResponseRecorder }

func (*liveTestRecorder) SetWriteDeadline(time.Time) error { return nil }
func newLiveTestRecorder() *liveTestRecorder               { return &liveTestRecorder{httptest.NewRecorder()} }

type liveUnwrapWriter struct{ http.ResponseWriter }

func (w liveUnwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestLiveSSEWriteRequiresSupportedDeadlineAndUnwraps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if liveSSEWrite(ctx, httptest.NewRecorder(), []byte("cannot safely stream"), cancel, time.Second) || ctx.Err() == nil {
		t.Fatal("unsupported writer accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	w := newLiveTestRecorder()
	if !liveSSEWrite(ctx, liveUnwrapWriter{w}, []byte(": connected\n\n"), cancel, time.Second) || w.Body.Len() == 0 {
		t.Fatal("supported wrapped writer refused")
	}
}
func TestLiveAuditReadQueueCancellationDoesNotOccupyCapacity(t *testing.T) {
	s := NewServer(Config{})
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			done <- s.withLiveAuditRead(context.Background(), func(context.Context) error { entered <- struct{}{}; <-release; return nil })
		}()
	}
	for i := 0; i < 2; i++ {
		<-entered
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := s.withLiveAuditRead(ctx, func(context.Context) error { t.Error("cancelled waiter admitted"); return nil })
	if !errors.Is(err, context.DeadlineExceeded) || len(s.liveReadSlots) != 2 {
		t.Fatalf("queue err=%v active=%d", err, len(s.liveReadSlots))
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if len(s.liveReadSlots) != 0 {
		t.Fatal("work permits leaked")
	}
}

type liveCachedWriter struct {
	*liveTestRecorder
	writes int
}

func (w *liveCachedWriter) Write(body []byte) (int, error) {
	w.writes++
	time.Sleep(15 * time.Millisecond)
	return w.liveTestRecorder.Write(body)
}
func TestLiveCachedEmitHonorsWorkDeadlineAndReleases(t *testing.T) {
	s := NewServer(Config{})
	s.liveReadBudget = 5 * time.Millisecond
	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &liveCachedWriter{liveTestRecorder: newLiveTestRecorder()}
	err := s.withLiveAuditRead(streamCtx, func(readCtx context.Context) error {
		// Already decoded/cached data still has to honor the work deadline.
		for i := 0; i < 10; i++ {
			if !liveSSEWrite(readCtx, writer, []byte("data: cached\n\n"), cancel, time.Second) {
				break
			}
		}
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || streamCtx.Err() == nil || writer.writes != 1 || len(s.liveReadSlots) != 0 {
		t.Fatalf("deadline err=%v stream=%v writes=%d permits=%d", err, streamCtx.Err(), writer.writes, len(s.liveReadSlots))
	}
}

type liveFailedFlushWriter struct{ *liveTestRecorder }

func (*liveFailedFlushWriter) FlushError() error { return errors.New("closed downstream flush") }
func TestLiveSSEFlushFailureCancelsSubscription(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &liveFailedFlushWriter{newLiveTestRecorder()}
	if liveSSEWrite(ctx, writer, []byte("data: real row\n\n"), cancel, time.Second) || ctx.Err() == nil {
		t.Fatal("failed flush retained subscription")
	}
}
