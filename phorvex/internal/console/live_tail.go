/*
 * Phorvex Console — one shared reader of the remote decision audit for every /api/live subscriber.
 *
 * Each subscriber used to poll the remote audit itself once a second, so the console scanned the
 * same bytes once per subscriber while only two remote reads may run at a time
 * (withLiveAuditRead). Under a handful of subscribers (Live views, benchmark captures, CI) the read
 * slots stayed busy: new subscribers were refused at admission (503 "live audit source
 * unavailable") and running ones ended when a poll waited past its budget.
 *
 * Now one tailer per audit path reads each appended byte once, decodes each record once, and hands
 * it to every subscriber tagged with its generation and byte range. Nothing about access changes:
 * every subscriber still passes every record through its own emitScoped projection (tenant scope,
 * namespace narrowing, owner projection), exactly as before.
 *
 * Joining and lag are handled by position, never by assumption: a subscriber replays its tail,
 * remembers where that replay ended, skips shared records it already holds and, if the shared
 * reader is ahead of it (it joined late or fell behind), reads the missing byte range itself once.
 * Source gaps keep their visible, stream-ending notices; a read-slot timeout is now lag.
 */

package console

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
)

// liveTailBuffer bounds what one subscriber may have queued. Records are shared pointers, so this
// bounds memory per lagging subscriber, not per record copy.
const liveTailBuffer = 64

var errLiveSourceGap = errors.New("live audit poll unavailable")

// liveEvent is one shared record, or a notice for every subscriber.
type liveEvent struct {
	rec        *audit.Record
	generation string
	start, end int64
	notice     string
	fatal      bool
}

type liveSubscription struct {
	events chan liveEvent
	// lagged is closed by the tailer when this subscription's buffer was full; the subscriber then
	// resumes and reads the missed range itself.
	mu     sync.Mutex
	lagged chan struct{}
	paused bool
}

func (sub *liveSubscription) offer(ev liveEvent) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.paused {
		return
	}
	select {
	case sub.events <- ev:
	default:
		// Never block the shared reader on one slow client.
		sub.paused = true
		close(sub.lagged)
	}
}

// resume re-enables delivery before the subscriber catches up, so nothing falls between.
func (sub *liveSubscription) resume() {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	sub.paused = false
	sub.lagged = make(chan struct{})
}

func (sub *liveSubscription) lagSignal() <-chan struct{} {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.lagged
}

type liveTailer struct {
	s    *Server
	path string
	mu   sync.Mutex
	subs map[*liveSubscription]struct{}
	run  bool
}

func (s *Server) liveTailerFor(path string) *liveTailer {
	s.liveTailMu.Lock()
	defer s.liveTailMu.Unlock()
	if s.liveTailers == nil {
		s.liveTailers = map[string]*liveTailer{}
	}
	t := s.liveTailers[path]
	if t == nil {
		t = &liveTailer{s: s, path: path, subs: map[*liveSubscription]struct{}{}}
		s.liveTailers[path] = t
	}
	return t
}

func (t *liveTailer) subscribe() *liveSubscription {
	sub := &liveSubscription{events: make(chan liveEvent, liveTailBuffer), lagged: make(chan struct{})}
	t.mu.Lock()
	t.subs[sub] = struct{}{}
	start := !t.run
	t.run = true
	t.mu.Unlock()
	if start {
		go t.loop()
	}
	return sub
}

func (t *liveTailer) unsubscribe(sub *liveSubscription) {
	t.mu.Lock()
	delete(t.subs, sub)
	t.mu.Unlock()
}

func (t *liveTailer) broadcast(ev liveEvent) {
	t.mu.Lock()
	subs := make([]*liveSubscription, 0, len(t.subs))
	for sub := range t.subs {
		subs = append(subs, sub)
	}
	t.mu.Unlock()
	for _, sub := range subs {
		sub.offer(ev)
	}
}

// loop is the one reader. It starts at the end of the live segment (subscribers replay their own
// tails) and stops when no subscriber remains; the next subscriber starts a fresh reader.
func (t *liveTailer) loop() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-t.s.liveTailStop():
			cancel()
		case <-ctx.Done():
		}
	}()
	source := t.s.cfg.AuditSource
	id := strings.TrimPrefix(t.path, "audit://")
	var live audittransport.Segment
	var offset int64
	var anchor string
	skipping, positioned := false, false
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		t.mu.Lock()
		if len(t.subs) == 0 {
			t.run = false
			t.mu.Unlock()
			return
		}
		t.mu.Unlock()
		emitAt := func(gen string) func(audit.Record, int64, int64) {
			return func(rec audit.Record, start, end int64) {
				r := rec
				t.broadcast(liveEvent{rec: &r, generation: gen, start: start, end: end})
			}
		}
		notice := func(message string) { t.broadcast(liveEvent{notice: message}) }
		fatal := func(message string) error {
			t.broadcast(liveEvent{notice: message, fatal: true})
			return errLiveSourceGap
		}
		err := t.s.withLiveAuditRead(ctx, func(readCtx context.Context) error {
			m, e := source.Manifest(readCtx)
			if e != nil {
				return fatal("Live audit source unavailable; reconnect after recovery.")
			}
			newLive, found := liveSegment(m, id)
			if !found {
				return fatal("Configured provider audit source unavailable.")
			}
			if !positioned {
				live, offset, skipping = newLive, newLive.Size, false
				anchor, _ = auditAnchor(source.Open(readCtx, live), offset)
				positioned = true
				return nil
			}
			if newLive.Generation != live.Generation {
				// Finish any records committed just before rotation from the retained copy,
				// then start the new live file at zero. A missing old segment is a visible
				// retention gap, never an empty verified replay.
				old, retained := audittransport.Segment{}, false
				for _, seg := range m.Segments {
					if seg.Generation == live.Generation && strings.HasPrefix(seg.ID, strings.TrimSuffix(id, "live")+"backup-") {
						old, retained = seg, true
						break
					}
				}
				if !retained {
					return fatal("Audit generation lost before reconnect; refresh retained history.")
				}
				if old.ID != strings.TrimSuffix(id, "live")+"backup-1" {
					return fatal("More than one audit rotation occurred between live polls; refresh paged retained history to recover intervening decisions.")
				}
				oldReader := source.Open(readCtx, old)
				if offset > old.Size {
					return fatal("Audit generation truncated during rotation.")
				}
				offset, _ = streamAuditFileAt(oldReader, offset, &skipping, emitAt(live.Generation), notice)
				if e = oldReader.Verify(); e != nil {
					return fatal("Retained audit generation changed during rotation.")
				}
				live, offset, anchor, skipping = newLive, 0, "", false
			} else if newLive.Size < offset {
				return fatal("Audit truncated; reconnect and refresh history.")
			} else {
				live = newLive
			}
			reader := source.Open(readCtx, live)
			if offset > 0 {
				current, ae := auditAnchor(reader, offset)
				if ae != nil || current != anchor {
					return fatal("Audit append boundary changed; reconnect and refresh history.")
				}
			}
			offset, anchor = streamAuditFileAt(reader, offset, &skipping, emitAt(live.Generation), notice)
			if e = reader.Verify(); e != nil {
				return fatal("Live audit generation changed during read; reconnect.")
			}
			return nil
		})
		if errors.Is(err, errLiveSourceGap) {
			// Every subscriber has the stream-ending notice; a later subscriber starts afresh.
			positioned = false
		}
		// Any other error is a read-slot or budget timeout: lag, retried on the next tick.
		select {
		case <-ctx.Done():
			t.mu.Lock()
			t.run = false
			t.mu.Unlock()
			return
		case <-ticker.C:
		}
	}
}

func liveSegment(m audittransport.Manifest, id string) (audittransport.Segment, bool) {
	for _, seg := range m.Segments {
		if seg.ID == id {
			return seg, true
		}
	}
	return audittransport.Segment{}, false
}

// liveTailStop is closed by Server.Close so shared readers do not outlive the server.
func (s *Server) liveTailStop() <-chan struct{} {
	s.liveTailMu.Lock()
	defer s.liveTailMu.Unlock()
	if s.liveTailDone == nil {
		s.liveTailDone = make(chan struct{})
	}
	return s.liveTailDone
}

func (s *Server) stopLiveTailers() {
	s.liveTailMu.Lock()
	defer s.liveTailMu.Unlock()
	if s.liveTailDone == nil {
		s.liveTailDone = make(chan struct{})
	}
	select {
	case <-s.liveTailDone:
	default:
		close(s.liveTailDone)
	}
}

// remoteLive replays this subscriber's tail, then follows the shared reader.
func (s *Server) remoteLive(r *http.Request, path string, tail int, visible func(audit.Record) bool, emitScoped func(context.Context, audit.Record), noticeScoped func(context.Context, string)) {
	ctx := r.Context()
	source := s.cfg.AuditSource
	id := strings.TrimPrefix(path, "audit://")
	tailer := s.liveTailerFor(path)
	// Subscribe before the replay: everything the shared reader emits from now on is queued, and
	// the replay covers everything before, so the union has no hole.
	sub := tailer.subscribe()
	defer tailer.unsubscribe(sub)

	var generation string
	var position int64
	older := map[string]bool{} // generations already retired when this subscriber joined
	skipping := false
	if err := s.withLiveAuditRead(ctx, func(readCtx context.Context) error {
		emit := func(rec audit.Record) { emitScoped(readCtx, rec) }
		notice := func(message string) { noticeScoped(readCtx, message) }
		m, e := source.Manifest(readCtx)
		if e != nil {
			notice("Live audit source unavailable: " + e.Error())
			return errLiveSourceGap
		}
		live, ok := liveSegment(m, id)
		if !ok {
			notice("Configured provider audit source unavailable.")
			return errLiveSourceGap
		}
		for _, seg := range m.Segments {
			if seg.ID != live.ID {
				older[seg.Generation] = true
			}
		}
		f := source.Open(readCtx, live)
		if tail <= 0 {
			position, _ = streamAuditFile(f, 0, &skipping, emit, notice)
		} else {
			position, _ = replayAuditFile(f, tail, visible, emit, notice)
		}
		if e = f.Verify(); e != nil {
			notice("Live audit replay changed; reconnect to recover history.")
			return errLiveSourceGap
		}
		generation = live.Generation
		return nil
	}); err != nil {
		return
	}

	// catchUp reads [position, end of generation) itself when the shared reader is ahead (a late
	// join or lag). false ends the stream: a source gap (with its notice) or a closed request. A
	// read-slot timeout keeps the stream and the position; the bytes are read on a later attempt.
	catchUp := func() bool {
		for {
			advanced := false
			err := s.withLiveAuditRead(ctx, func(readCtx context.Context) error {
				m, e := source.Manifest(readCtx)
				if e != nil {
					noticeScoped(readCtx, "Live audit source unavailable; reconnect after recovery.")
					return errLiveSourceGap
				}
				var seg audittransport.Segment
				found := false
				for _, candidate := range m.Segments {
					if candidate.Generation == generation && (candidate.ID == id || strings.HasPrefix(candidate.ID, strings.TrimSuffix(id, "live")+"backup-")) {
						seg, found = candidate, true
						break
					}
				}
				if !found || seg.Size < position {
					noticeScoped(readCtx, "Audit generation lost before this stream caught up; refresh retained history.")
					return errLiveSourceGap
				}
				if seg.Size == position {
					return nil
				}
				reader := source.Open(readCtx, seg)
				next, _ := streamAuditFileAt(reader, position, &skipping, func(rec audit.Record, _, _ int64) { emitScoped(readCtx, rec) },
					func(message string) { noticeScoped(readCtx, message) })
				if e = reader.Verify(); e != nil {
					noticeScoped(readCtx, "Live audit generation changed during read; reconnect.")
					return errLiveSourceGap
				}
				advanced = next > position
				position = next
				return nil
			})
			if err != nil {
				return !errors.Is(err, errLiveSourceGap) && ctx.Err() == nil
			}
			if !advanced {
				return true
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.lagSignal():
			sub.resume()
			if !catchUp() {
				return
			}
		case ev := <-sub.events:
			if ev.notice != "" {
				noticeScoped(ctx, ev.notice)
				if ev.fatal {
					return
				}
				continue
			}
			if ev.generation != generation {
				if older[ev.generation] {
					continue // the shared reader is finishing a generation this stream never followed
				}
				// A newer generation. Finish this stream's own generation from the retained copy
				// before following the new file from its start.
				if !catchUp() {
					return
				}
				older[generation] = true
				generation, position, skipping = ev.generation, 0, false
			}
			if ev.end <= position {
				continue // already replayed or caught up
			}
			if ev.start > position {
				if !catchUp() {
					return
				}
				if ev.start > position {
					continue // not readable yet; the next catch-up reads these bytes from the file
				}
			}
			if ev.end <= position {
				continue
			}
			emitScoped(ctx, *ev.rec)
			position = ev.end
		}
	}
}
