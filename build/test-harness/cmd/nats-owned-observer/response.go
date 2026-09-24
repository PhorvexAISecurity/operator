package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// This mode is additive: the installed no-signal observer retains its
// one-subject --config wire format and behavior.
const maxResponseConfigBytes = 2048

var podUIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type responseConfig struct {
	BrokerURL             string   `json:"brokerURL"`
	Nonce                 string   `json:"nonce"`
	Subjects              []string `json:"subjects"`
	ExpectedPayloadSHA256 []string `json:"expectedPayloadSHA256"`
	AllowedServerIDs      []string `json:"allowedServerIDs"`
	ConnectTimeoutMillis  int      `json:"connectTimeoutMillis"`
	FlushTimeoutMillis    int      `json:"flushTimeoutMillis"`
	M0TimeoutMillis       int      `json:"m0TimeoutMillis"`
	M1TimeoutMillis       int      `json:"m1TimeoutMillis"`
}

type responseReceipt struct {
	Kind               string `json:"kind"`
	Phase              string `json:"phase"`
	Status             string `json:"status"`
	Subject            string `json:"subject"`
	Nonce              string `json:"nonce"`
	PodUID             string `json:"podUID"`
	ServerID           string `json:"serverID"`
	Flushed            bool   `json:"flushed,omitempty"`
	PayloadBytes       int    `json:"payloadBytes,omitempty"`
	PayloadSHA256      string `json:"payloadSHA256,omitempty"`
	NonceHeaderMatches bool   `json:"nonceHeaderMatches,omitempty"`
	PayloadHashMatches bool   `json:"payloadHashMatches,omitempty"`
}

// The response-mode consumer's Service has a real broker-dependent health
// contract. A process that merely started, or kept a stale TCP socket, is not
// a healthy consumer. The no-signal observer never opens this endpoint.
type responseHealth struct {
	mu       sync.RWMutex
	conn     *nats.Conn
	serverID string
	nonce    string
	podUID   string
	ready    bool
	checks   chan struct{}
}

func (h *responseHealth) set(conn *nats.Conn, serverID string) {
	h.mu.Lock()
	h.conn, h.serverID, h.ready = conn, serverID, true
	h.mu.Unlock()
}

func (h *responseHealth) clear() {
	h.mu.Lock()
	h.ready = false
	h.mu.Unlock()
}

func (h *responseHealth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/ready" || r.URL.RawQuery != "" {
		http.Error(w, "route unavailable", http.StatusNotFound)
		return
	}
	select {
	case h.checks <- struct{}{}:
		defer func() { <-h.checks }()
	default:
		http.Error(w, "health check busy", http.StatusServiceUnavailable)
		return
	}
	h.mu.RLock()
	conn, id, ready := h.conn, h.serverID, h.ready
	h.mu.RUnlock()
	if !ready || conn == nil || conn.Status() != nats.CONNECTED || conn.ConnectedServerId() != id ||
		conn.FlushTimeout(500*time.Millisecond) != nil || conn.Status() != nats.CONNECTED || conn.ConnectedServerId() != id {
		http.Error(w, "broker connection unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"nonce": h.nonce, "podUID": h.podUID, "serverID": id})
}

// Security-relevant keys are checked before struct decoding because
// encoding/json otherwise accepts duplicate and case-insensitive aliases.
func loadResponseConfig(path string) (responseConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return responseConfig{}, errors.New("response config unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxResponseConfigBytes {
		return responseConfig{}, errors.New("response config must be one bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxResponseConfigBytes+1))
	if err != nil || len(raw) > maxResponseConfigBytes {
		return responseConfig{}, errors.New("response config exceeded bound")
	}
	required := map[string]bool{
		"brokerURL": true, "nonce": true, "subjects": true, "expectedPayloadSHA256": true,
		"allowedServerIDs": true, "connectTimeoutMillis": true, "flushTimeoutMillis": true,
		"m0TimeoutMillis": true, "m1TimeoutMillis": true,
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return responseConfig{}, errors.New("response config object required")
	}
	seen := map[string]bool{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || !required[key] || seen[key] {
			return responseConfig{}, errors.New("response config duplicate or unknown key")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return responseConfig{}, errors.New("response config value invalid")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(seen) != len(required) {
		return responseConfig{}, errors.New("response config fields incomplete")
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return responseConfig{}, errors.New("response config trailing data")
	}
	var cfg responseConfig
	if json.Unmarshal(raw, &cfg) != nil || validateResponse(cfg) != nil {
		return responseConfig{}, errors.New("response config invalid")
	}
	return cfg, nil
}

func validateResponse(cfg responseConfig) error {
	if len(cfg.Subjects) != 2 || len(cfg.ExpectedPayloadSHA256) != 2 ||
		cfg.Subjects[0] == cfg.Subjects[1] || cfg.ExpectedPayloadSHA256[0] == cfg.ExpectedPayloadSHA256[1] ||
		cfg.M0TimeoutMillis < 1 || cfg.M0TimeoutMillis > 120000 ||
		cfg.M1TimeoutMillis < 1 || cfg.M1TimeoutMillis > 300000 ||
		cfg.M0TimeoutMillis+cfg.M1TimeoutMillis+cfg.ConnectTimeoutMillis+cfg.FlushTimeoutMillis > 360000 {
		return errors.New("two distinct bounded response phases required")
	}
	for i := 0; i < 2; i++ {
		legacy := config{BrokerURL: cfg.BrokerURL, Nonce: cfg.Nonce, Subject: cfg.Subjects[i],
			AllowedServerIDs: cfg.AllowedServerIDs, ExpectedPayloadSHA256: cfg.ExpectedPayloadSHA256[i],
			ConnectTimeoutMillis: cfg.ConnectTimeoutMillis, FlushTimeoutMillis: cfg.FlushTimeoutMillis,
			ObserveTimeoutMillis: 1000}
		if err := validate(legacy); err != nil {
			return err
		}
		if !strings.HasSuffix(cfg.Subjects[i], []string{".m0", ".m1"}[i]) {
			return errors.New("response phase subject suffix differs")
		}
	}
	return nil
}

func observeResponsePhase(ctx context.Context, nc *nats.Conn, sub *nats.Subscription,
	cfg responseConfig, podUID, serverID string, phase int) responseReceipt {
	label := []string{"M0", "M1"}[phase]
	out := responseReceipt{Kind: "observation", Phase: label, Subject: cfg.Subjects[phase],
		Nonce: cfg.Nonce, PodUID: podUID, ServerID: serverID}
	if nc.Status() != nats.CONNECTED || nc.ConnectedServerId() != serverID {
		out.Status = "TRANSPORT_UNKNOWN"
		return out
	}
	timeout := cfg.M0TimeoutMillis
	if phase == 1 {
		timeout = cfg.M1TimeoutMillis
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	message, err := sub.NextMsgWithContext(waitCtx)
	cancel()
	switch {
	case nc.Status() != nats.CONNECTED || nc.ConnectedServerId() != serverID:
		out.Status = "TRANSPORT_UNKNOWN"
	case errors.Is(err, nats.ErrPermissionViolation):
		out.Status = "PERMISSION_DENIED"
	case err != nil:
		out.Status = "TIMEOUT_UNKNOWN"
	case message == nil || message.Subject != cfg.Subjects[phase]:
		out.Status = "WRONG_SUBJECT"
	case len(message.Data) == 0 || len(message.Data) > 256:
		out.Status = "SIZE_INVALID"
	default:
		out.PayloadBytes = len(message.Data)
		digest := sha256.Sum256(message.Data)
		out.PayloadSHA256 = hex.EncodeToString(digest[:])
		out.NonceHeaderMatches = message.Header.Get("Nats-Msg-Id") == "cat-"+cfg.Nonce
		out.PayloadHashMatches = out.PayloadSHA256 == cfg.ExpectedPayloadSHA256[phase]
		if out.NonceHeaderMatches && out.PayloadHashMatches {
			out.Status = "EXACT_PAYLOAD_RECEIVED"
		} else {
			out.Status = "IDENTITY_MISMATCH"
		}
	}
	return out
}

// observeResponse preflushes both subjects before M0. The same connection and
// Pod container then wait for M1; a missing M1 remains UNKNOWN, never denial.
func observeResponse(ctx context.Context, cfg responseConfig, podUID string, emit func(responseReceipt) error) error {
	return observeResponseWithHealth(ctx, cfg, podUID, emit, nil, 0)
}

func observeResponseWithHealth(ctx context.Context, cfg responseConfig, podUID string, emit func(responseReceipt) error, health *responseHealth, hold time.Duration) error {
	if validateResponse(cfg) != nil || !podUIDPattern.MatchString(podUID) || emit == nil {
		return failedPhase("RESPONSE_IDENTITY_INVALID")
	}
	parsed, _ := url.Parse(cfg.BrokerURL)
	nc, err := nats.Connect(cfg.BrokerURL,
		nats.Name("phorvex-owned-two-phase-observer"),
		nats.Timeout(time.Duration(cfg.ConnectTimeoutMillis)*time.Millisecond),
		nats.NoReconnect(), nats.MaxReconnects(0), nats.RetryOnFailedConnect(false),
		nats.DontRandomize(), nats.SkipHostLookup(),
		nats.SetCustomDialer(fixedDialer{address: parsed.Host,
			timeout: time.Duration(cfg.ConnectTimeoutMillis) * time.Millisecond}),
		nats.PermissionErrOnSubscribe(true), nats.NoCallbacksAfterClientClose(),
		nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}),
	)
	if err != nil {
		return failedPhase("CONNECT_FAILED")
	}
	defer nc.Close()
	serverID := nc.ConnectedServerId()
	if nc.Status() != nats.CONNECTED || !admitted(serverID, cfg.AllowedServerIDs) {
		return failedPhase("BROKER_ID_MISMATCH")
	}
	subs := make([]*nats.Subscription, 2)
	for i := 0; i < 2; i++ {
		sub, err := nc.SubscribeSync(cfg.Subjects[i])
		if err != nil {
			return failedPhase("SUBSCRIBE_FAILED")
		}
		subs[i] = sub
		defer sub.Unsubscribe()
	}
	flushCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.FlushTimeoutMillis)*time.Millisecond)
	err = nc.FlushWithContext(flushCtx)
	cancel()
	if err != nil || nc.Status() != nats.CONNECTED || nc.ConnectedServerId() != serverID {
		return failedPhase("FLUSH_OR_IDENTITY_FAILED")
	}
	for i := 0; i < 2; i++ {
		if err := emit(responseReceipt{Kind: "subscription", Phase: []string{"M0", "M1"}[i],
			Status: "READY", Subject: cfg.Subjects[i], Nonce: cfg.Nonce,
			PodUID: podUID, ServerID: serverID, Flushed: true}); err != nil {
			return failedPhase("SUBSCRIPTION_RECEIPT_FAILED")
		}
	}
	if health != nil {
		health.set(nc, serverID)
		defer health.clear()
	}
	first := observeResponsePhase(ctx, nc, subs[0], cfg, podUID, serverID, 0)
	if err := emit(first); err != nil {
		return failedPhase("M0_RECEIPT_FAILED")
	}
	if first.Status != "EXACT_PAYLOAD_RECEIVED" {
		return failedPhase("M0_NOT_EXACT")
	}
	second := observeResponsePhase(ctx, nc, subs[1], cfg, podUID, serverID, 1)
	if err := emit(second); err != nil {
		return failedPhase("M1_RECEIPT_FAILED")
	}
	if health != nil && hold > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(hold):
		}
	}
	return nil
}

func runResponseMain(path string) {
	cfg, err := loadResponseConfig(path)
	podUID := os.Getenv("POD_UID")
	if err != nil || !podUIDPattern.MatchString(podUID) {
		fmt.Fprintln(os.Stderr, "observer: invalid bounded response config or Pod UID")
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	// The installed Deployment declares this literal env value and a readiness
	// probe. Local protocol probes may omit it; they cannot masquerade as an
	// admitted serviced consumer because the Pod spec is independently checked.
	var health *responseHealth
	hold := time.Duration(0)
	if os.Getenv("NATS_RESPONSE_SERVICE") == "1" {
		listener, listenErr := net.Listen("tcp", ":8080")
		if listenErr != nil {
			fmt.Fprintln(os.Stderr, "observer: HEALTH_BIND_FAILED")
			os.Exit(2)
		}
		health = &responseHealth{nonce: cfg.Nonce, podUID: podUID, checks: make(chan struct{}, 1)}
		server := &http.Server{Handler: health, ReadHeaderTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 1024}
		go func() { _ = server.Serve(listener) }()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
		}()
		// Keep the same first-incarnation process available for the bounded
		// post-M1 Service check and exact Deployment teardown. Deployment Pods
		// may restart after this hold; replacements never become evidence.
		hold = 90 * time.Second
	} else if value := os.Getenv("NATS_RESPONSE_SERVICE"); value != "" {
		fmt.Fprintln(os.Stderr, "observer: HEALTH_MODE_INVALID")
		os.Exit(2)
	}
	if err := observeResponseWithHealth(context.Background(), cfg, podUID,
		func(r responseReceipt) error { return encoder.Encode(r) }, health, hold); err != nil {
		var phase *phaseError
		if errors.As(err, &phase) {
			fmt.Fprintln(os.Stderr, "observer:", phase.code)
		} else {
			fmt.Fprintln(os.Stderr, "observer: RESPONSE_INCOMPLETE")
		}
		os.Exit(1)
	}
}
