package actuator

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestM040DrainRequestsStrictSynchronousResponse(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    int
		wantErr bool
	}{
		{name: "positive", status: http.StatusOK, body: `{"aborted":3}`, want: 3},
		{name: "zero-valid-for-shared-quiescence", status: http.StatusOK, body: `{"aborted":0}`, want: 0},
		{name: "async", status: http.StatusAccepted, body: ``, wantErr: true},
		{name: "no-content", status: http.StatusNoContent, body: ``, wantErr: true},
		{name: "empty-object", status: http.StatusOK, body: `{}`, wantErr: true},
		{name: "malformed", status: http.StatusOK, body: `{`, wantErr: true},
		{name: "negative", status: http.StatusOK, body: `{"aborted":-1}`, wantErr: true},
		{name: "null", status: http.StatusOK, body: `{"aborted":null}`, wantErr: true},
		{name: "fractional", status: http.StatusOK, body: `{"aborted":1.5}`, wantErr: true},
		{name: "string", status: http.StatusOK, body: `{"aborted":"1"}`, wantErr: true},
		{name: "duplicate", status: http.StatusOK, body: `{"aborted":1,"aborted":2}`, wantErr: true},
		{name: "overflow", status: http.StatusOK, body: `{"aborted":999999999999999999999999999999}`, wantErr: true},
		{name: "multiple-json", status: http.StatusOK, body: `{"aborted":1}{"aborted":2}`, wantErr: true},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", servingResponseMaxBytes+1), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != defaultDrainPath {
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
			got, err := (&httpVLLM{hc: server.Client()}).DrainRequests(context.Background(), servingEndpoint{podIP: host, port: port, drainPath: defaultDrainPath})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted unconfirmed response: aborted=%d", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got aborted=%d err=%v, want %d", got, err, tc.want)
			}
		})
	}
}
