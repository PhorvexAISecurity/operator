package console

import (
	"context"
	"net/http"
	"time"
)

const liveAuditWorkTimeout = 30 * time.Second
const liveWriteTimeout = 5 * time.Second

// AuditGate bounds connection admission independently of costly audit work.
// Stream probes share the same pool as replay/polling; healthy connections do
// not reserve a read permit between polls. Short reader bounds stay separate.
func (s *Server) AuditGate(next http.Handler) http.Handler {
	if s.cfg.AuditSource == nil {
		return next
	}
	return BoundedAuditGate(next, s.cfg.AuditSource.ProbeContext, 5*time.Second, 30*time.Second, s.withLiveAuditRead)
}

// BoundedAuditGate admits at most sixteen subscriptions and four short reads.
// streamWork is shared with remoteLive in the production Server.
func BoundedAuditGate(next http.Handler, probe func(context.Context) error, probeTimeout, requestTimeout time.Duration, streamWork func(context.Context, func(context.Context) error) error) http.Handler {
	shortReads := make(chan struct{}, 4)
	streams := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auditDependentRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		limit := shortReads
		stream := r.URL.Path == "/api/live"
		if stream {
			limit = streams
		}
		select {
		case limit <- struct{}{}:
			defer func() { <-limit }()
		case <-r.Context().Done():
			return
		default:
			http.Error(w, "remote audit reader limit reached", http.StatusServiceUnavailable)
			return
		}
		ctx := r.Context()
		cancelRequest := func() {}
		if !stream {
			ctx, cancelRequest = context.WithTimeout(ctx, requestTimeout)
			defer cancelRequest()
		}
		probeCtx, cancelProbe := context.WithTimeout(ctx, probeTimeout)
		var err error
		if stream && streamWork != nil {
			err = streamWork(probeCtx, probe)
		} else {
			err = probe(probeCtx)
		}
		cancelProbe()
		if err != nil {
			http.Error(w, "live audit source unavailable", http.StatusServiceUnavailable)
			return
		}
		if ctx.Err() != nil {
			http.Error(w, "remote audit request timed out", http.StatusServiceUnavailable)
			return
		}
		if stream {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func auditDependentRoute(path string) bool {
	switch path {
	case "/api/live", "/api/live/history", "/api/owner/events", "/api/owner/tenants", "/api/cost-timeseries", "/api/cost", "/api/uptime", "/api/effectiveness", "/api/posture":
		return true
	default:
		return false
	}
}

func (s *Server) withLiveAuditRead(parent context.Context, work func(context.Context) error) error {
	s.liveReadOnce.Do(func() { s.liveReadSlots = make(chan struct{}, 2) })
	budget := s.liveReadBudget
	if budget <= 0 {
		budget = liveAuditWorkTimeout
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.liveReadSlots <- struct{}{}:
		defer func() { <-s.liveReadSlots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := work(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Write deadlines apply only while writing/flushing, never during source work
// or idle waits. Clearing them preserves healthy long-lived subscriptions.
func liveSSEWrite(ctx context.Context, w http.ResponseWriter, body []byte, cancel context.CancelFunc, timeout time.Duration) bool {
	if ctx.Err() != nil {
		cancel()
		return false
	}
	controller := http.NewResponseController(w)
	deadline := time.Now().Add(timeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := controller.SetWriteDeadline(deadline); err != nil {
		cancel()
		return false
	}
	if _, err := w.Write(body); err != nil {
		cancel()
		return false
	}
	if err := controller.Flush(); err != nil {
		cancel()
		return false
	}
	if ctx.Err() != nil {
		cancel()
		return false
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		cancel()
		return false
	}
	return true
}

func liveCanFlush(w http.ResponseWriter) bool {
	for depth := 0; depth < 16; depth++ {
		if _, ok := w.(http.Flusher); ok {
			return true
		}
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = unwrapper.Unwrap()
	}
	return false
}
