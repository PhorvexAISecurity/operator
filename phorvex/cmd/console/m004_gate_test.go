package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteAuditAdmissionBoundsShortReadersAndStreamsSeparately(t *testing.T) {
	entered := make(chan string, 20)
	release := make(chan struct{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- r.URL.Path
		<-release
		w.WriteHeader(http.StatusOK)
	})
	gate := boundedAuditGate(next, func(context.Context) error { return nil }, time.Second, time.Second)
	finished := make(chan struct{}, 20)
	serve := func(path string) {
		go func() {
			gate.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
			finished <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		serve("/api/owner/events")
	}
	for i := 0; i < 4; i++ {
		select {
		case path := <-entered:
			if path != "/api/owner/events" {
				t.Fatal(path)
			}
		case <-time.After(time.Second):
			close(release)
			t.Fatal("short read was not admitted")
		}
	}
	for i := 0; i < 16; i++ {
		serve("/api/live")
	}
	for i := 0; i < 16; i++ {
		select {
		case path := <-entered:
			if path != "/api/live" {
				t.Fatal(path)
			}
		case <-time.After(time.Second):
			close(release)
			t.Fatal("SSE stream was not admitted separately")
		}
	}
	for _, path := range []string{"/api/owner/events", "/api/live"} {
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			close(release)
			t.Fatalf("excess %s was admitted: %d", path, w.Code)
		}
	}
	// Identity/capability calls do not acquire an audit slot or probe the source.
	identity := make(chan struct{}, 1)
	go func() {
		gate.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/session", nil))
		identity <- struct{}{}
	}()
	select {
	case path := <-entered:
		if path != "/api/session" {
			t.Fatal(path)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("session was blocked by audit readers")
	}
	close(release)
	for i := 0; i < 20; i++ {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("audit slot did not release")
		}
	}
	select {
	case <-identity:
	case <-time.After(time.Second):
		t.Fatal("session did not finish")
	}
}

func TestRemoteAuditSlowProbeFailsWithinDeadlineBeforeHandler(t *testing.T) {
	var calls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) })
	gate := boundedAuditGate(next, func(ctx context.Context) error { <-ctx.Done(); return errors.New("slow source") }, 25*time.Millisecond, 100*time.Millisecond)
	started := time.Now()
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/cost-timeseries", nil))
	if w.Code != http.StatusServiceUnavailable || calls.Load() != 0 || time.Since(started) > time.Second {
		t.Fatalf("slow audit source escaped bounded admission: status=%d calls=%d elapsed=%s", w.Code, calls.Load(), time.Since(started))
	}
	// Even while the audit is unavailable, a session request succeeds without a probe.
	w = httptest.NewRecorder()
	gate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if w.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("session blocked on unavailable source: status=%d calls=%d", w.Code, calls.Load())
	}
}
