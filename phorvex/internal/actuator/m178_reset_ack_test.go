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
