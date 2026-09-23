package cataloguev1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type authMemoryRecorder struct {
	intents []Intent
	events  []Event
}

func (r *authMemoryRecorder) Intent(value Intent) error {
	r.intents = append(r.intents, value)
	return nil
}
func (r *authMemoryRecorder) Event(value Event) error       { r.events = append(r.events, value); return nil }
func (*authMemoryRecorder) Metric(Metric) error             { return nil }
func (*authMemoryRecorder) MetricRaw(json.RawMessage) error { return nil }
func (*authMemoryRecorder) Result(Result) error             { return nil }

func authHandlerRuntime(t *testing.T, fixture *authTestServer) Runtime {
	t.Helper()
	cfg := authTestConfig(t, fixture)
	origin, err := url.Parse(cfg.FixedLoopback)
	if err != nil {
		t.Fatal(err)
	}
	grant := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(grant, []byte(`{"version":1,"subjects":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return Runtime{
		HTTPClient: fixture.server.Client(), FixedLoopback: origin,
		ScopedTokenFile: cfg.ScopedTokenFile, ExpectedSubject: cfg.ExpectedSubject,
		AllowedTenant: cfg.AllowedTenant, DeniedTenant: cfg.DeniedTenant, DeniedTarget: cfg.DeniedTarget,
		GrantFile: grant,
	}
}

func TestAuthHandlersUseCanonicalDefinitions(t *testing.T) {
	for _, handler := range []Handler{NewAuthUnauthHandler(), NewAuthScopeHandler()} {
		want, err := DefinitionFor(handler.Definition().ID)
		if err != nil {
			t.Fatal(err)
		}
		if got := handler.Definition(); got != want {
			t.Fatalf("definition = %+v, want %+v", got, want)
		}
	}
}

func TestAuthHandlersReturnFunctionalPassAndSanitizedJournal(t *testing.T) {
	for _, handler := range []Handler{NewAuthUnauthHandler(), NewAuthScopeHandler()} {
		t.Run(string(handler.Definition().ID), func(t *testing.T) {
			fixture := newAuthTestServer(t)
			runtime := authHandlerRuntime(t, fixture)
			if err := handler.Validate(runtime); err != nil {
				t.Fatal(err)
			}
			recorder := &authMemoryRecorder{}
			result := handler.Run(context.Background(), JobContext{
				Job: Job{RunID: "v1run-1", Profile: handler.Definition().ID}, Runtime: runtime, Recorder: recorder,
			})
			if result.Outcome != OutcomeFunctionalPass || !result.Cleanup.Attempted || !result.Cleanup.Verified || result.Cleanup.Status != "PASS" {
				t.Fatalf("result = %+v", result)
			}
			wantRequests := 4
			if handler.Definition().ID == AuthScope {
				wantRequests = 5
			}
			if len(recorder.intents) != wantRequests || len(recorder.events) != wantRequests {
				t.Fatalf("journal counts = %d intents, %d events", len(recorder.intents), len(recorder.events))
			}
			for _, intent := range recorder.intents {
				if intent.Mutation {
					t.Fatalf("mutation intent = %+v", intent)
				}
			}
			for _, value := range []string{result.Summary, result.Cleanup.Details["stateFingerprint"]} {
				if strings.Contains(value, authTestToken) {
					t.Fatal("result exposed token")
				}
			}
		})
	}
}

func TestAuthHandlerExpiredCredentialIsInconclusive(t *testing.T) {
	fixture := newAuthTestServer(t)
	runtime := authHandlerRuntime(t, fixture)
	if err := os.WriteFile(runtime.ScopedTokenFile, []byte(strings.Repeat("x", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &authMemoryRecorder{}
	result := NewAuthUnauthHandler().Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || !strings.Contains(result.Summary, "unavailable") {
		t.Fatalf("result = %+v", result)
	}
	if len(recorder.intents) != 4 || len(recorder.events) != 4 {
		t.Fatalf("journal counts = %d/%d", len(recorder.intents), len(recorder.events))
	}
}

func TestAuthHandlerReconcileNeverReplaysRequests(t *testing.T) {
	fixture := newAuthTestServer(t)
	handler := NewAuthScopeHandler()
	cleanup := handler.Reconcile(context.Background(), JobContext{Runtime: authHandlerRuntime(t, fixture)}, Journal{Records: []JournalRecord{
		{Kind: "intent", Intent: &Intent{Step: "allowed-tenant-before", Mutation: false, At: time.Now()}},
	}})
	if !cleanup.Verified || cleanup.UnsafeToRetry || cleanup.Details["requestsReplayed"] != "0" || len(fixture.requests) != 0 {
		t.Fatalf("cleanup = %+v, requests = %v", cleanup, fixture.requests)
	}
	foreign := handler.Reconcile(context.Background(), JobContext{}, Journal{Records: []JournalRecord{
		{Kind: "intent", Intent: &Intent{Step: "foreign", Mutation: true, At: time.Now()}},
	}})
	if foreign.Verified || !foreign.UnsafeToRetry {
		t.Fatalf("foreign cleanup = %+v", foreign)
	}
}

func TestAuthHandlerValidateRefusesMissingFixture(t *testing.T) {
	fixture := newAuthTestServer(t)
	runtime := authHandlerRuntime(t, fixture)
	runtime.FixedLoopback = &url.URL{Scheme: "http", Host: "example.com:8090"}
	if err := NewAuthScopeHandler().Validate(runtime); err == nil || !strings.Contains(err.Error(), "literal loopback") {
		t.Fatalf("error = %v", err)
	}
	runtime = authHandlerRuntime(t, fixture)
	runtime.GrantFile = filepath.Join(t.TempDir(), "missing-grants")
	if err := NewAuthScopeHandler().Validate(runtime); err == nil || !strings.Contains(err.Error(), "grant authority") {
		t.Fatalf("error = %v", err)
	}
	if len(fixture.requests) != 0 {
		t.Fatalf("validation sent HTTP requests: %v", fixture.requests)
	}
}

func TestAuthStatusFailureIsFunctionalFail(t *testing.T) {
	err := authStatusError{Step: "missing-credential", Got: http.StatusOK, Want: http.StatusUnauthorized}
	observed := authHTTPResult{Observations: []authHTTPObservation{
		{Step: "missing-credential", Status: http.StatusOK, SchemaKeys: []string{"authModes", "source", "subject"}},
		{Step: "legitimate-session-before", Status: http.StatusOK, SchemaKeys: []string{"authModes", "source", "subject"}},
	}}
	outcome, _ := classifyAuthProbeFailure(err, observed)
	if outcome != OutcomeFunctionalFail {
		t.Fatalf("outcome = %s", outcome)
	}
}

func TestAuthStatusFailuresDoNotManufactureBoundaryFailure(t *testing.T) {
	positive := authHTTPObservation{Step: "legitimate-session", Status: http.StatusOK, SchemaKeys: []string{"authModes", "source", "subject"}}
	cases := []struct {
		name string
		err  authStatusError
		obs  []authHTTPObservation
		want Outcome
	}{
		{"server error", authStatusError{Step: "denied-tenant", Got: http.StatusServiceUnavailable, Want: http.StatusForbidden}, []authHTTPObservation{positive}, OutcomeInconclusive},
		{"stale endpoint", authStatusError{Step: "denied-target", Got: http.StatusNotFound, Want: http.StatusForbidden}, []authHTTPObservation{positive}, OutcomeTestFailed},
		{"positive denied", authStatusError{Step: "allowed-tenant-before", Got: http.StatusForbidden, Want: http.StatusOK}, []authHTTPObservation{positive}, OutcomeInconclusive},
		{"unshaped 200", authStatusError{Step: "denied-tenant", Got: http.StatusOK, Want: http.StatusForbidden}, []authHTTPObservation{positive, {Step: "denied-tenant", Status: http.StatusOK, SchemaKeys: []string{"message"}}}, OutcomeTestFailed},
		{"no positive proof", authStatusError{Step: "denied-tenant", Got: http.StatusOK, Want: http.StatusForbidden}, []authHTTPObservation{{Step: "denied-tenant", Status: http.StatusOK, SchemaKeys: []string{"events", "rollup"}}}, OutcomeTestFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := classifyAuthProbeFailure(tc.err, authHTTPResult{Observations: tc.obs})
			if got != tc.want {
				t.Fatalf("outcome = %s, want %s", got, tc.want)
			}
		})
	}
}
