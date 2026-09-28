package audittransport

import (
	"context"
	"errors"
	"testing"
)

func TestPinnedReaderCancellationAlsoRejectsCachedBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &Reader{Ctx: ctx, Segment: Segment{Size: 3}, cacheStart: 0, cache: []byte("abc")}
	target := make([]byte, 3)
	if n, err := reader.ReadAt(target, 0); n != 3 || err != nil {
		t.Fatalf("cached control n=%d err=%v", n, err)
	}
	cancel()
	if n, err := reader.ReadAt(target, 0); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled cache served n=%d err=%v", n, err)
	}
}
