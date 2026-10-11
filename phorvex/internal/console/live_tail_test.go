package console

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func appendLiveRows(t *testing.T, path string, from, to int) {
	t.Helper()
	for i := from; i <= to; i++ {
		row := historyRecord(i, false)
		row.Time = time.Now().UTC()
		row.Tenant = "acme"
		row.Selected, row.Actuated = true, true
		writeHistory(t, path, row)
	}
}

// awaitPods reads the stream until every wanted pod arrived, failing on a duplicate or on a pod
// arriving out of order.
func (s *liveHTTPStream) awaitPods(t *testing.T, pods []string) {
	t.Helper()
	next := 0
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	seen := map[string]bool{}
	for next < len(pods) {
		select {
		case line, ok := <-s.lines:
			if !ok {
				t.Fatalf("stream ended after %d/%d records", next, len(pods))
			}
			if !strings.HasPrefix(line, "data:") || !strings.Contains(line, "phorvex.decision") {
				continue
			}
			for i, pod := range pods {
				if strings.Contains(line, `"`+pod+`"`) {
					if seen[pod] {
						t.Fatalf("%s delivered twice", pod)
					}
					if i != next {
						t.Fatalf("%s arrived before %s", pod, pods[next])
					}
					seen[pod] = true
					next++
				}
			}
		case <-timer.C:
			t.Fatalf("only %d/%d records arrived", next, len(pods))
		}
	}
}

func podNames(from, to int) []string {
	out := []string{}
	for i := from; i <= to; i++ {
		out = append(out, fmt.Sprintf("pod-%04d", i))
	}
	return out
}

// More subscribers must not mean more source polling: one shared reader scans for all of them.
func TestLiveSubscribersShareOneSourceReader(t *testing.T) {
	f := newLiveHTTPFixture(t)
	first := f.open(t, "/api/live?lens=operator&tail=1", "op")
	first.await(t, "pod-0001")
	window := func() int32 {
		time.Sleep(1500 * time.Millisecond) // let replays and startup settle
		before := f.manifests.Load()
		time.Sleep(3 * time.Second)
		return f.manifests.Load() - before
	}
	one := window()
	for i := 0; i < 5; i++ {
		s := f.open(t, "/api/live?lens=operator&tail=1", "op")
		s.await(t, "pod-0001")
	}
	six := window()
	// The old per-subscriber poll added about one manifest read per subscriber per second (~15
	// here). The durable-history indexer polls on its own schedule, so allow a little jitter.
	if six > one+3 {
		t.Fatalf("source manifest reads with 6 subscribers=%d vs 1 subscriber=%d: polling is still per subscriber", six, one)
	}
	appendLiveRows(t, f.path, 2, 3)
	first.awaitPods(t, podNames(2, 3))
}

// A subscriber that joins while the shared reader is running gets its replay, then exactly the
// records after it: no gap, no duplicate. The earlier subscriber is unaffected.
func TestLiveLateJoinerHasNoGapOrDuplicate(t *testing.T) {
	f := newLiveHTTPFixture(t)
	early := f.open(t, "/api/live?lens=operator&tail=1", "op")
	early.await(t, "pod-0001")
	appendLiveRows(t, f.path, 2, 4)
	early.awaitPods(t, podNames(2, 4))
	late := f.open(t, "/api/live?lens=operator&tail=1", "op")
	late.awaitPods(t, podNames(4, 4)) // its one-record replay
	appendLiveRows(t, f.path, 5, 7)
	late.awaitPods(t, podNames(5, 7))
	early.awaitPods(t, podNames(5, 7))
}

// A burst larger than one subscriber's queue must not block the shared reader or lose records:
// the subscriber pauses, then reads the missed range itself, in order, exactly once.
func TestLiveBurstBeyondQueueIsCaughtUpInOrder(t *testing.T) {
	f := newLiveHTTPFixture(t)
	stream := f.open(t, "/api/live?lens=operator&tail=1", "op")
	stream.await(t, "pod-0001")
	n := 3 * liveTailBuffer
	appendLiveRows(t, f.path, 2, n+1)
	stream.awaitPods(t, podNames(2, n+1))
}

// A shared poll that cannot get a read slot within its budget is lag, not the end of every stream.
func TestLiveReadSlotTimeoutIsLagNotStreamEnd(t *testing.T) {
	f := newLiveHTTPFixture(t)
	f.auth.srv.liveReadBudget = 200 * time.Millisecond
	stream := f.open(t, "/api/live?lens=operator&tail=1", "op")
	stream.await(t, "pod-0001")
	// Occupy both read slots well past the poll budget, as concurrent heavy readers would.
	slots := f.auth.srv.liveReadSlots
	slots <- struct{}{}
	slots <- struct{}{}
	appendLiveRows(t, f.path, 2, 2)
	time.Sleep(1500 * time.Millisecond)
	<-slots
	<-slots
	appendLiveRows(t, f.path, 3, 3)
	stream.awaitPods(t, podNames(2, 3))
	if _, err := os.Stat(f.path); err != nil {
		t.Fatal(err)
	}
}
