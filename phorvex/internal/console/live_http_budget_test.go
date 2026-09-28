package console

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
)

type liveHTTPFixture struct {
	auth          *authFixture
	server        *httptest.Server
	path          string
	completed     atomic.Int32
	sourcePeak    atomic.Int32
	sourceActive  atomic.Int32
	workPeak      atomic.Int32
	writeFailures atomic.Int32
	workServer    atomic.Pointer[Server]
}

func newLiveHTTPFixture(t *testing.T) *liveHTTPFixture {
	t.Helper()
	f := &liveHTTPFixture{}
	dir := t.TempDir()
	f.path = filepath.Join(dir, "live.jsonl")
	row := historyRecord(1, false)
	row.Time = time.Now().UTC()
	row.Tenant = "acme"
	row.Selected = true
	row.Actuated = true
	writeHistory(t, f.path, row)
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	cfg := audittransport.ServerConfig{AuditPath: f.path, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 3}
	producer := cfg.Handler()
	source := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := f.workServer.Load(); s != nil {
			active := int32(len(s.liveReadSlots))
			for peak := f.workPeak.Load(); active > peak; peak = f.workPeak.Load() {
				if f.workPeak.CompareAndSwap(peak, active) {
					break
				}
			}
		}
		active := f.sourceActive.Add(1)
		defer f.sourceActive.Add(-1)
		for peak := f.sourcePeak.Load(); active > peak; peak = f.sourcePeak.Load() {
			if f.sourcePeak.CompareAndSwap(peak, active) {
				break
			}
		}
		// Keep producer operations overlapped long enough to exercise admission.
		time.Sleep(5 * time.Millisecond)
		producer.ServeHTTP(w, r)
	}))
	source.TLS = cfg.TLSConfig()
	source.StartTLS()
	t.Cleanup(source.Close)
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: source.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	f.auth = newAuthFixture(t, Config{AuditSource: client, AuditSourceIdentity: source.URL + "|audit-source.test"}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}), ownerGrant("own", []string{"acme"}))
	f.auth.srv.liveReadOnce.Do(func() { f.auth.srv.liveReadSlots = make(chan struct{}, 2) })
	f.workServer.Store(f.auth.srv)
	t.Cleanup(func() { f.auth.srv.Close() })
	gate := f.auth.srv.AuditGate(f.auth.h)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gate.ServeHTTP(liveUnwrapWriter{liveFailureWatchWriter{w, &f.writeFailures}}, r)
		if r.URL.Path == "/api/live" {
			f.completed.Add(1)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *liveHTTPFixture) request(t *testing.T, ctx context.Context, path, subject string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "" {
		req.Header = f.auth.albReqAs(t, http.MethodGet, path, "", subject).Header.Clone()
	}
	return req
}

type liveHTTPStream struct {
	response *http.Response
	lines    chan string
	cancel   context.CancelFunc
	done     chan struct{}
}

func (f *liveHTTPFixture) open(t *testing.T, path, subject string) *liveHTTPStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := f.request(t, ctx, path, subject)
	response, err := f.server.Client().Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		cancel()
		t.Fatalf("stream status=%d body=%s", response.StatusCode, body)
	}
	stream := &liveHTTPStream{response: response, lines: make(chan string, 64), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(stream.done)
		defer close(stream.lines)
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 65536), 2<<20)
		for scanner.Scan() {
			select {
			case stream.lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(stream.close)
	return stream
}
func (s *liveHTTPStream) close() {
	s.cancel()
	s.response.Body.Close()
	select {
	case <-s.done:
	case <-time.After(time.Second):
	}
}
func (s *liveHTTPStream) await(t *testing.T, needle string) string {
	t.Helper()
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				t.Fatalf("stream ended before %s", needle)
			}
			if strings.Contains(line, needle) {
				return line
			}
		case <-timer.C:
			t.Fatalf("no event containing %s", needle)
		}
	}
}
func TestLiveHTTPFiveSubscribersShareBoundedSourceWorkAndRelease(t *testing.T) {
	f := newLiveHTTPFixture(t)
	f.auth.srv.liveWriteBudget = 20 * time.Millisecond
	// Actual public gate, source mTLS producer, auth middleware and route handler.
	// Launch five HTTP clients simultaneously rather than simulating final flags.
	requests := make([]*http.Request, 5)
	cancels := make([]context.CancelFunc, 5)
	for i := range requests {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel
		t.Cleanup(cancel)
		subject, path := "op", "/api/live?lens=operator&tail=80"
		if i == 4 {
			subject, path = "own", "/api/live?lens=investor&tenant=acme&tail=80"
		}
		requests[i] = f.request(t, ctx, path, subject)
	}
	results := make(chan *http.Response, 5)
	failures := make(chan error, 5)
	for _, req := range requests {
		go func(req *http.Request) {
			response, err := f.server.Client().Do(req)
			if err != nil {
				failures <- err
			} else {
				results <- response
			}
		}(req)
	}
	streams := make([]*liveHTTPStream, 0, 5)
	for i := 0; i < 5; i++ {
		select {
		case err := <-failures:
			t.Fatal(err)
		case response := <-results:
			if response.StatusCode != 200 {
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				t.Fatalf("startup status=%d %s", response.StatusCode, body)
			}
			scanCtx, scanCancel := context.WithCancel(context.Background())
			stream := &liveHTTPStream{response: response, lines: make(chan string, 64), done: make(chan struct{}), cancel: scanCancel}
			go func() {
				defer close(stream.done)
				defer close(stream.lines)
				scanner := bufio.NewScanner(stream.response.Body)
				scanner.Buffer(make([]byte, 65536), 2<<20)
				for scanner.Scan() {
					select {
					case stream.lines <- scanner.Text():
					case <-scanCtx.Done():
						return
					}
				}
			}()
			streams = append(streams, stream)
			t.Cleanup(stream.close)
		case <-time.After(6 * time.Second):
			t.Fatal("subscriber startup timed out")
		}
	}
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()
	ownerSeen := false
	for _, stream := range streams {
		line := stream.await(t, "pod-0001")
		if !strings.Contains(line, "phorvex.decision") {
			ownerSeen = true
			if strings.Contains(line, "perDollar") || strings.Contains(line, "decisionTrace") {
				t.Fatal("owner projection leaked internals")
			}
		}
	}
	if !ownerSeen {
		t.Fatal("owner control missing")
	}
	if peak := f.workPeak.Load(); peak != 2 {
		t.Fatalf("expensive stream work concurrency=%d want2", peak)
	}
	if peak := f.sourcePeak.Load(); peak > 4 {
		t.Fatalf("all source concurrency=%d want<=4 (including durable history indexer)", peak)
	}
	// Writer deadlines must be cleared between writes: idle for much longer
	// than the injected deadline and still deliver the next actual audit row.
	time.Sleep(75 * time.Millisecond)
	row := historyRecord(2, false)
	row.Time = time.Now().UTC()
	row.Tenant = "acme"
	row.Selected = true
	row.Actuated = true
	writeHistory(t, f.path, row)
	for _, stream := range streams {
		stream.await(t, "pod-0002")
	}
	// Durable indexing is asynchronous; require its already indexed real
	// initial row to stay readable rather than asserting immediate freshness.
	response, err := f.server.Client().Do(f.request(t, context.Background(), "/api/live/history?lens=operator&limit=5&includeNoop=true", "op"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(string(body), "pod-0001") {
		t.Fatalf("history status=%d body=%s", response.StatusCode, body)
	}
	// The same pinned old-generation remainder/new generation sequence is
	// exercised under five active subscriptions; no committed record is missed.
	row = historyRecord(3, false)
	row.Time = time.Now().UTC()
	row.Tenant = "acme"
	row.Selected = true
	row.Actuated = true
	writeHistory(t, f.path, row)
	if err := os.Rename(f.path, f.path+".1"); err != nil {
		t.Fatal(err)
	}
	row = historyRecord(4, false)
	row.Time = time.Now().UTC()
	row.Tenant = "acme"
	row.Selected = true
	row.Actuated = true
	writeHistory(t, f.path, row)
	for _, stream := range streams {
		stream.await(t, "pod-0003")
		stream.await(t, "pod-0004")
	}
	for i := 0; i < 18; i++ {
		stream := f.open(t, "/api/live?lens=operator&tail=1", "op")
		stream.await(t, "pod-0004")
		stream.close()
	}
	for _, stream := range streams {
		stream.close()
	}
	for _, cancel := range cancels {
		cancel()
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.completed.Load() < 23 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.completed.Load() < 23 {
		t.Fatalf("disconnected handlers did not release: %d", f.completed.Load())
	}
	if len(f.auth.srv.liveReadSlots) != 0 {
		t.Fatal("work permits retained after disconnect")
	}
	response, err = f.server.Client().Do(f.request(t, context.Background(), "/api/live?lens=operator", ""))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 401 || strings.Contains(string(body), "pod-") {
		t.Fatalf("unauthenticated stream=%d %s", response.StatusCode, body)
	}
}

func TestLiveHTTPSlowReaderReleasesWorkAndSubscription(t *testing.T) {
	f := newLiveHTTPFixture(t)
	f.auth.srv.liveWriteBudget = 30 * time.Millisecond
	// Real HTTP backpressure: the client reads only the initial heartbeat and
	// leaves a many-megabyte replay unread until the server's write deadline.
	rows := make([]string, 40)
	for i := range rows {
		rows[i] = fmt.Sprintf(`{"kind":"phorvex.decision","tenant":"acme","pod":"large-%d","reason":"%s"}`+"\n", i, strings.Repeat("x", 250000))
	}
	file, err := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(strings.Join(rows, ""))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response, err := f.server.Client().Do(f.request(t, ctx, "/api/live?lens=operator&tail=80", "op"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("status=%d", response.StatusCode)
	}
	deadline := time.Now().Add(6 * time.Second)
	for f.completed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.completed.Load() == 0 || len(f.auth.srv.liveReadSlots) != 0 || f.writeFailures.Load() == 0 {
		t.Fatalf("slow reader failed release/write-error witness: completed=%d work=%d failures=%d", f.completed.Load(), len(f.auth.srv.liveReadSlots), f.writeFailures.Load())
	}
	// A fresh reader proves the server still admits and can read the producer.
	stream := f.open(t, "/api/live?lens=operator&tail=1", "op")
	stream.await(t, "large-39")
	stream.close()
}

type liveFailureWatchWriter struct {
	http.ResponseWriter
	failures *atomic.Int32
}

func (w liveFailureWatchWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w liveFailureWatchWriter) Write(body []byte) (int, error) {
	n, err := w.ResponseWriter.Write(body)
	if err != nil {
		w.failures.Add(1)
	}
	return n, err
}
func (w liveFailureWatchWriter) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil {
		w.failures.Add(1)
	}
	return err
}
