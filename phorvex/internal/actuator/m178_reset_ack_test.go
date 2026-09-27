package actuator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestM178ResetPrefixCacheRequiresExplicitTrueAcknowledgement(t *testing.T) {
	const privateMarker = "private-reset-backend-marker"
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{name: "explicit-true", status: http.StatusOK, body: `{"success":true}`},
		{name: "explicit-true-with-extension", status: http.StatusOK, body: `{"success":true,"request_id":"fixture"}`},
		{name: "explicit-false", status: http.StatusOK, body: `{"success":false}`, wantErr: true},
		{name: "empty-200", status: http.StatusOK, wantErr: true},
		{name: "no-content", status: http.StatusNoContent, wantErr: true},
		{name: "accepted", status: http.StatusAccepted, body: `{"success":true}`, wantErr: true},
		{name: "missing", status: http.StatusOK, body: `{}`, wantErr: true},
		{name: "null", status: http.StatusOK, body: `{"success":null}`, wantErr: true},
		{name: "string", status: http.StatusOK, body: `{"success":"true"}`, wantErr: true},
		{name: "number", status: http.StatusOK, body: `{"success":1}`, wantErr: true},
		{name: "case-alias", status: http.StatusOK, body: `{"Success":true}`, wantErr: true},
		{name: "alias-collision", status: http.StatusOK, body: `{"success":true,"SUCCESS":false}`, wantErr: true},
		{name: "duplicate", status: http.StatusOK, body: `{"success":true,"success":false}`, wantErr: true},
		{name: "duplicate-reverse", status: http.StatusOK, body: `{"success":false,"success":true}`, wantErr: true},
		{name: "escaped-decoded-duplicate", status: http.StatusOK, body: `{"success":true,"succe\u0073s":true}`, wantErr: true},
		{name: "array", status: http.StatusOK, body: `[{"success":true}]`, wantErr: true},
		{name: "top-level-null", status: http.StatusOK, body: `null`, wantErr: true},
		{name: "malformed", status: http.StatusOK, body: `{"success":`, wantErr: true},
		{name: "trailing", status: http.StatusOK, body: `{"success":true} trailing`, wantErr: true},
		{name: "multiple", status: http.StatusOK, body: `{"success":true}{"success":true}`, wantErr: true},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", servingResponseMaxBytes+1), wantErr: true},
		{name: "secret-body", status: http.StatusInternalServerError, body: privateMarker, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodPost || r.URL.Path != defaultResetPath {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			err = newHTTPVLLM().ResetPrefixCache(context.Background(), servingEndpoint{podIP: host, port: port, resetPath: defaultResetPath})
			if requests != 1 {
				t.Fatalf("requests=%d, want 1", requests)
			}
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("confirmed acknowledgement rejected: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, errServingOutcomeUnknown) || errors.Is(err, errStackUnreachable) {
				t.Fatalf("nonconfirming response was not retained as unknown: %v", err)
			}
			if strings.Contains(err.Error(), privateMarker) {
				t.Fatalf("backend response body leaked through public error: %v", err)
			}
		})
	}
}

func TestM178ResetAcknowledgementParserRejectsAmbiguousReservedKeys(t *testing.T) {
	for _, body := range []string{
		`{"success":true,"Success":true}`,
		`{"SUCCESS":true,"success":true}`,
		`{"success":true,"nested":{"x":1,"x":2}}`,
	} {
		if err := parseResetPrefixCacheAcknowledgement(body); err == nil {
			t.Fatalf("ambiguous acknowledgement accepted: %s", body)
		}
	}
	if err := parseResetPrefixCacheAcknowledgement(`{"success":true,"nested":{"x":1}}`); err != nil {
		t.Fatalf("harmless extension rejected: %v", err)
	}
}

func TestM178ResetDeadlineCoversDelayedAckButPreservesUnknownTimeout(t *testing.T) {
	defaultClient := newHTTPVLLM()
	if defaultClient.hc.Timeout != 3*time.Second || defaultClient.resetTimeout <= 10*time.Second || defaultClient.resetTimeout >= 40*time.Second {
		t.Fatalf("reset bound must cover the 10s engine RPC within the default outer tick: ordinary=%s reset=%s", defaultClient.hc.Timeout, defaultClient.resetTimeout)
	}
	for _, tc := range []struct {
		name           string
		selectedClient bool
		resetTimeout   time.Duration
		outerTimeout   time.Duration
		wantUnknown    bool
	}{
		{name: "legacy delayed acknowledgement", resetTimeout: 200 * time.Millisecond},
		{name: "trusted endpoint delayed acknowledgement", selectedClient: true, resetTimeout: 200 * time.Millisecond},
		{name: "reset client expires after accepted request", resetTimeout: 25 * time.Millisecond, wantUnknown: true},
		{name: "outer caller deadline wins", resetTimeout: 200 * time.Millisecond, outerTimeout: 25 * time.Millisecond, wantUnknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != defaultResetPath {
					t.Errorf("unexpected reset request %s %s", r.Method, r.URL.Path)
				}
				time.Sleep(90 * time.Millisecond)
				_, _ = w.Write([]byte(`{"success":true}`))
			}))
			defer server.Close()
			host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			baseClient := &http.Client{Timeout: 25 * time.Millisecond}
			v := &httpVLLM{hc: baseClient, resetTimeout: tc.resetTimeout}
			ep := servingEndpoint{podIP: host, port: port, resetPath: defaultResetPath}
			if tc.selectedClient {
				ep.client = &http.Client{Timeout: 25 * time.Millisecond}
			}
			ctx := context.Background()
			if tc.outerTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.outerTimeout)
				defer cancel()
			}
			err = v.ResetPrefixCache(ctx, ep)
			if requests.Load() != 1 || baseClient.Timeout != 25*time.Millisecond ||
				(tc.selectedClient && ep.client.Timeout != 25*time.Millisecond) {
				t.Fatalf("reset copied the wrong client or sent multiple times: requests=%d base=%s endpoint=%v err=%v", requests.Load(), baseClient.Timeout, ep.client, err)
			}
			if tc.wantUnknown {
				if err == nil || !errors.Is(err, errServingOutcomeUnknown) || errors.Is(err, errStackUnreachable) {
					t.Fatalf("accepted timed-out reset must remain unknown: %v", err)
				}
			} else if err != nil {
				t.Fatalf("delayed valid acknowledgement rejected: %v", err)
			}
		})
	}
}
