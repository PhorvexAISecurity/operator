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

func TestM178KVInvalidateRequiresExplicitTrueAcknowledgement(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{name: "explicit-true", status: http.StatusOK, body: `{"success":true}`},
		{name: "explicit-false", status: http.StatusOK, body: `{"success":false}`, wantErr: errServingOutcomeUnknown},
		{name: "empty-200", status: http.StatusOK, wantErr: errServingOutcomeUnknown},
		{name: "no-content", status: http.StatusNoContent, wantErr: errServingOutcomeUnknown},
		{name: "backend-error", status: http.StatusInternalServerError, wantErr: errServingOutcomeUnknown},
		{name: "accepted", status: http.StatusAccepted, body: `{"success":true}`, wantErr: errServingQueued},
		{name: "duplicate", status: http.StatusOK, body: `{"success":true,"success":false}`, wantErr: errServingOutcomeUnknown},
		{name: "trailing", status: http.StatusOK, body: `{"success":true} trailing`, wantErr: errServingOutcomeUnknown},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", servingResponseMaxBytes+1), wantErr: errServingOutcomeUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != defaultKVInvPath {
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
			err = (httpKVTransfer{v: &httpVLLM{hc: server.Client()}}).InvalidateLocal(
				context.Background(),
				servingEndpoint{podIP: host, port: port, kvInvPath: defaultKVInvPath},
			)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("confirmed acknowledgement rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want errors.Is(_, %v)", err, tc.wantErr)
			}
		})
	}
}

func TestM178LocalInvalidateUsesResetDeadlineAndKeepsTimeoutUnknown(t *testing.T) {
	for _, tc := range []struct {
		name         string
		resetTimeout time.Duration
		wantUnknown  bool
	}{
		{name: "delayed acknowledgement", resetTimeout: 200 * time.Millisecond},
		{name: "accepted request timeout", resetTimeout: 25 * time.Millisecond, wantUnknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != defaultKVInvPath {
					t.Errorf("unexpected local invalidation request %s %s", r.Method, r.URL.Path)
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
			err = (httpKVTransfer{v: v}).InvalidateLocal(context.Background(), servingEndpoint{podIP: host, port: port, kvInvPath: defaultKVInvPath})
			if requests.Load() != 1 || baseClient.Timeout != 25*time.Millisecond {
				t.Fatalf("local invalidation did not preserve one isolated request: requests=%d baseTimeout=%s err=%v", requests.Load(), baseClient.Timeout, err)
			}
			if tc.wantUnknown {
				if err == nil || !errors.Is(err, errServingOutcomeUnknown) || errors.Is(err, errStackUnreachable) {
					t.Fatalf("timed-out local reset was not unknown: %v", err)
				}
			} else if err != nil {
				t.Fatalf("delayed local reset acknowledgement rejected: %v", err)
			}
		})
	}
}
