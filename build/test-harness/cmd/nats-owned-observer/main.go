// nats-owned-observer is a one-subject, read-only NATS client for an admitted
// synthetic catalogue message. It has no publish or JetStream API path.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const maxConfigBytes = 1024

var noncePattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var subjectPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$`)
var serverIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// phaseError is a fixed diagnostic code. It never formats a broker URL,
// transport error, response body, or credential into stderr.
type phaseError struct{ code string }

func (e *phaseError) Error() string { return e.code }

func failedPhase(code string) error { return &phaseError{code: code} }

type config struct {
	BrokerURL             string   `json:"brokerURL"`
	Subject               string   `json:"subject"`
	Nonce                 string   `json:"nonce"`
	AllowedServerIDs      []string `json:"allowedServerIDs"`
	ExpectedPayloadSHA256 string   `json:"expectedPayloadSHA256"`
	ConnectTimeoutMillis  int      `json:"connectTimeoutMillis"`
	FlushTimeoutMillis    int      `json:"flushTimeoutMillis"`
	ObserveTimeoutMillis  int      `json:"observeTimeoutMillis"`
}

type receipt struct {
	Kind               string `json:"kind"`
	Status             string `json:"status"`
	Subject            string `json:"subject"`
	Nonce              string `json:"nonce"`
	ServerID           string `json:"serverID"`
	Flushed            bool   `json:"flushed,omitempty"`
	PayloadBytes       int    `json:"payloadBytes,omitempty"`
	PayloadSHA256      string `json:"payloadSHA256,omitempty"`
	NonceHeaderMatches bool   `json:"nonceHeaderMatches,omitempty"`
	PayloadHashMatches bool   `json:"payloadHashMatches,omitempty"`
}

// fixedDialer refuses any address learned from broker discovery. nats.go
// v1.47.0 has no IgnoreDiscoveredServers option, so this and NoReconnect
// pin the only possible dial destination to the admitted config URL.
type fixedDialer struct {
	address string
	timeout time.Duration
}

func (d fixedDialer) Dial(network, address string) (net.Conn, error) {
	if address != d.address {
		return nil, errors.New("broker address outside admitted URL")
	}
	return (&net.Dialer{Timeout: d.timeout}).Dial(network, address)
}

func loadConfig(path string) (config, error) {
	file, err := os.Open(path)
	if err != nil {
		return config{}, errors.New("config file unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return config{}, errors.New("config must be one bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(raw) > maxConfigBytes {
		return config{}, errors.New("config exceeded bound")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var cfg config
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, errors.New("config JSON invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return config{}, errors.New("config has trailing data")
	}
	if err := validate(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func validate(cfg config) error {
	parsed, err := url.Parse(cfg.BrokerURL)
	if err != nil || parsed.Scheme != "nats" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Opaque != "" || strings.Contains(cfg.BrokerURL, ",") {
		return errors.New("one credential-free nats:// broker URL is required")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || host == "" || strings.ContainsAny(host, " /@,") {
		return errors.New("broker URL must name one host and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("broker port invalid")
	}
	if !noncePattern.MatchString(cfg.Nonce) || len(cfg.Subject) == 0 || len(cfg.Subject) > 128 || !subjectPattern.MatchString(cfg.Subject) || !strings.Contains(cfg.Subject, cfg.Nonce) {
		return errors.New("concrete bounded subject containing 96-bit nonce is required")
	}
	if len(cfg.AllowedServerIDs) < 1 || len(cfg.AllowedServerIDs) > 3 {
		return errors.New("one to three admitted broker server IDs are required")
	}
	seen := make(map[string]bool)
	for _, id := range cfg.AllowedServerIDs {
		if !serverIDPattern.MatchString(id) || seen[id] {
			return errors.New("broker server IDs must be bounded and unique")
		}
		seen[id] = true
	}
	if len(cfg.ExpectedPayloadSHA256) != 64 {
		return errors.New("expected payload SHA-256 is required")
	}
	if _, err := hex.DecodeString(cfg.ExpectedPayloadSHA256); err != nil || strings.ToLower(cfg.ExpectedPayloadSHA256) != cfg.ExpectedPayloadSHA256 {
		return errors.New("expected payload SHA-256 must be lowercase hex")
	}
	if cfg.ConnectTimeoutMillis < 1 || cfg.ConnectTimeoutMillis > 5000 || cfg.FlushTimeoutMillis < 1 || cfg.FlushTimeoutMillis > 5000 || cfg.ObserveTimeoutMillis < 1 || cfg.ObserveTimeoutMillis > 45000 || cfg.ConnectTimeoutMillis+cfg.FlushTimeoutMillis+cfg.ObserveTimeoutMillis > 45000 {
		return errors.New("finite connect, flush and observation deadlines are required")
	}
	return nil
}

func admitted(id string, allowed []string) bool {
	for _, expected := range allowed {
		if id == expected {
			return true
		}
	}
	return false
}

func observe(ctx context.Context, cfg config, emit func(receipt) error) error {
	parsed, _ := url.Parse(cfg.BrokerURL) // validate ran before observe.
	nc, err := nats.Connect(cfg.BrokerURL,
		nats.Name("phorvex-owned-subject-observer"),
		nats.Timeout(time.Duration(cfg.ConnectTimeoutMillis)*time.Millisecond),
		nats.NoReconnect(), nats.MaxReconnects(0), nats.RetryOnFailedConnect(false), nats.DontRandomize(), nats.SkipHostLookup(),
		nats.SetCustomDialer(fixedDialer{address: parsed.Host, timeout: time.Duration(cfg.ConnectTimeoutMillis) * time.Millisecond}),
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
	sub, subscribeErr := nc.SubscribeSync(cfg.Subject)
	if subscribeErr != nil && !errors.Is(subscribeErr, nats.ErrPermissionViolation) {
		return failedPhase("SUBSCRIBE_FAILED")
	}
	if sub != nil {
		defer sub.Unsubscribe()
	}
	flushCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.FlushTimeoutMillis)*time.Millisecond)
	flushErr := nc.FlushWithContext(flushCtx)
	cancel()
	if flushErr != nil || nc.Status() != nats.CONNECTED || nc.ConnectedServerId() != serverID {
		return failedPhase("FLUSH_OR_IDENTITY_FAILED")
	}
	status := "READY"
	if errors.Is(subscribeErr, nats.ErrPermissionViolation) {
		status = "SUBSCRIPTION_DENIED"
	}
	if err := emit(receipt{Kind: "subscription", Status: status, Subject: cfg.Subject, Nonce: cfg.Nonce, ServerID: serverID, Flushed: true}); err != nil {
		return failedPhase("SUBSCRIPTION_RECEIPT_FAILED")
	}
	if status == "SUBSCRIPTION_DENIED" {
		return emit(receipt{Kind: "observation", Status: "PERMISSION_DENIED", Subject: cfg.Subject, Nonce: cfg.Nonce, ServerID: serverID})
	}
	if sub == nil {
		return failedPhase("SUBSCRIPTION_MISSING")
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, time.Duration(cfg.ObserveTimeoutMillis)*time.Millisecond)
	message, receiveErr := sub.NextMsgWithContext(waitCtx)
	waitCancel()
	if nc.Status() != nats.CONNECTED || nc.ConnectedServerId() != serverID {
		return failedPhase("OBSERVATION_BROKER_DRIFT")
	}
	out := receipt{Kind: "observation", Subject: cfg.Subject, Nonce: cfg.Nonce, ServerID: serverID}
	switch {
	case errors.Is(receiveErr, nats.ErrPermissionViolation):
		out.Status = "PERMISSION_DENIED"
	case receiveErr != nil:
		out.Status = "TIMEOUT_UNKNOWN"
	case message == nil || message.Subject != cfg.Subject:
		out.Status = "WRONG_SUBJECT"
	case len(message.Data) > 256:
		out.Status = "OVERSIZE_INVALID"
	default:
		out.PayloadBytes = len(message.Data)
		payloadHash := sha256.Sum256(message.Data)
		out.PayloadSHA256 = hex.EncodeToString(payloadHash[:])
		out.NonceHeaderMatches = message.Header.Get("Nats-Msg-Id") == "cat-"+cfg.Nonce
		out.PayloadHashMatches = out.PayloadSHA256 == cfg.ExpectedPayloadSHA256
		if out.NonceHeaderMatches && out.PayloadHashMatches {
			out.Status = "EXACT_PAYLOAD_RECEIVED"
		} else {
			out.Status = "IDENTITY_MISMATCH"
		}
	}
	if err := emit(out); err != nil {
		return failedPhase("OBSERVATION_RECEIPT_FAILED")
	}
	return nil
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "--config" {
		fmt.Fprintln(os.Stderr, "observer: exactly --config <path> is required")
		os.Exit(2)
	}
	cfg, err := loadConfig(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "observer: invalid bounded config")
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := observe(context.Background(), cfg, func(r receipt) error { return encoder.Encode(r) }); err != nil {
		var phase *phaseError
		if errors.As(err, &phase) {
			fmt.Fprintln(os.Stderr, "observer:", phase.code)
		} else {
			fmt.Fprintln(os.Stderr, "observer: PROTOCOL_INCOMPLETE")
		}
		os.Exit(1)
	}
}
