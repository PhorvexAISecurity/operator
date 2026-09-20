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
	"testing"
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
