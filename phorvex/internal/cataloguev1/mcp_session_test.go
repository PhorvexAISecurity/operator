package cataloguev1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type mcpTestTransport struct {
	responses      []mcpWireResponse
	calls          []string
	sessions       []string
	snapshots      int
	driftAt        int
	sourcePinError bool
	failCall       int
}

func (*mcpTestTransport) authority() mcpAuthority {
	return mcpAuthority{PodName: "mcp-server-a", PodUID: "pod-uid", ContainerID: "containerd://a", ImageID: "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff", DeployUID: "deploy-uid", DeployGeneration: 10, ServiceUID: "service-uid", SliceUID: "slice-uid", SourceUID: "source-uid", SourceRV: "7", SourceSHA: mcpInstalledSourceSHA}
}
func (f *mcpTestTransport) snapshot(context.Context, MCPSessionRuntime) (mcpAuthority, error) {
	f.snapshots++
	a := f.authority()
	if f.driftAt > 0 && f.snapshots >= f.driftAt {
		a.PodUID = "foreign-pod"
	}
	return a, nil
}
func (f *mcpTestTransport) installedSourcePin(context.Context, MCPSessionRuntime, mcpAuthority) error {
	if f.sourcePinError {
		return errors.New("pin differs")
	}
	return nil
}
func (f *mcpTestTransport) call(_ context.Context, _ MCPSessionRuntime, _ mcpAuthority, method string, body []byte, session string) (mcpWireResponse, error) {
	f.calls = append(f.calls, method)
	f.sessions = append(f.sessions, session)
	if len(f.calls) > 6 {
		return mcpWireResponse{}, errors.New("unexpected seventh request")
	}
	if method == http.MethodPost && !json.Valid(body) {
		return mcpWireResponse{}, errors.New("invalid fixed JSON")
	}
	if f.failCall == len(f.calls) {
		return mcpWireResponse{}, errors.New("ambiguous wire outcome")
	}
	if method == http.MethodDelete {
		return f.responses[4], nil
	}
	if strings.Contains(string(body), `"id":4`) {
		return f.responses[5], nil
	}
	if len(f.responses) < len(f.calls) {
		return mcpWireResponse{}, errors.New("fixture exhausted")
	}
	return f.responses[len(f.calls)-1], nil
}

type mcpTestRecorder struct {
	intents  []Intent
	events   []Event
	failStep string
}

func (r *mcpTestRecorder) Intent(v Intent) error {
	if r.failStep == v.Step {
		return errors.New("journal unavailable")
	}
	r.intents = append(r.intents, v)
	return nil
}
func (r *mcpTestRecorder) Event(v Event) error {
	if r.failStep == v.Step {
		return errors.New("journal unavailable")
	}
	r.events = append(r.events, v)
	return nil
}
func (*mcpTestRecorder) Metric(Metric) error             { return nil }
func (*mcpTestRecorder) MetricRaw(json.RawMessage) error { return nil }
func (*mcpTestRecorder) Result(Result) error             { return nil }

func mcpTestConfig() MCPSessionRuntime {
	return MCPSessionRuntime{Enabled: true, Namespace: "mcp", Deployment: "mcp-server", Service: "mcp-server", Container: "mcp-server", Port: 8000, SourceConfigMap: "mcp-code", SourceKey: "server.py", ExpectedSourceSHA256: mcpInstalledSourceSHA, ExpectedImageID: "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"}
}

func mcpWire(status int, id any, result any, session string) mcpWireResponse {
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	return mcpWireResponse{Status: status, ContentType: "application/json", SessionID: session, Body: data}
}
func mcpSuccessFixture() *mcpTestTransport {
	session := "0123456789abcdef0123456789abcdef"
	initialize := mcpWire(200, 1, map[string]any{"protocolVersion": mcpProtocolVersion, "serverInfo": map[string]any{"name": "mcp-server"}}, session)
	list := mcpWire(200, 2, map[string]any{"tools": []any{
		map[string]any{"name": "store_directory", "description": "static directory", "inputSchema": map[string]any{"type": "object", "required": []string{"topic"}}},
		map[string]any{"name": "check_promotions", "description": "static promotions", "inputSchema": map[string]any{"type": "object"}},
	}}, "")
	// The installed SDK returned text/event-stream for the RPC result.
	list.ContentType = "text/event-stream"
	list.Body = append(append([]byte("event: message\ndata: "), list.Body...), []byte("\n\n")...)
	call := mcpWire(200, 3, map[string]any{"content": []any{map[string]any{"type": "text", "text": "All stores open 9am-9pm daily; the support line is 9am-6pm Pacific, Mon-Fri."}}, "isError": false}, "")
	call.ContentType = "text/event-stream"
	call.Body = append(append([]byte("event: message\ndata: "), call.Body...), []byte("\n\n")...)
	deleted, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "server-error", "error": map[string]any{"code": -32600, "message": "Session not found"}})
	return &mcpTestTransport{responses: []mcpWireResponse{initialize, {Status: 202, ContentType: "application/json"}, list, call, {Status: 200, ContentType: "application/json"}, {Status: 404, ContentType: "application/json", Body: deleted}}}
}

func runMCPFixture(t *testing.T, f *mcpTestTransport, r *mcpTestRecorder) Result {
	t.Helper()
	jc := JobContext{Runtime: Runtime{MCP: mcpTestConfig()}, Recorder: r}
	return runMCPSession(context.Background(), jc, f, Result{Outcome: OutcomeInconclusive, Summary: "incomplete", StartedAt: time.Now(), Evidence: map[string]string{}, Cleanup: Cleanup{Status: "not-started"}})
}

func TestMCPSessionActualTypedLifecycle(t *testing.T) {
	f := mcpSuccessFixture()
	r := &mcpTestRecorder{}
	result := runMCPFixture(t, f, r)
	if result.Outcome != OutcomeFunctionalPass || !result.Cleanup.Verified || result.Evidence["toolTextSHA256"] != mcpHoursSHA || result.Evidence["requestCount"] != "6" {
		t.Fatalf("fixed protocol failed: %+v", result)
	}
	if strings.Join(f.calls, ",") != "POST,POST,POST,POST,DELETE,POST" || f.sessions[0] != "" || f.sessions[1] == "" || f.sessions[5] != f.sessions[1] {
		t.Fatalf("unexpected exact session sequence: %v %v", f.calls, f.sessions)
	}
	if len(r.intents) != 6 || len(r.events) != 6 || !r.intents[0].Mutation || !r.intents[4].Mutation || r.intents[5].Mutation {
		t.Fatalf("journal sequence: %+v %+v", r.intents, r.events)
	}
	encoded, _ := json.Marshal(struct {
		Result  Result
		Intents []Intent
		Events  []Event
	}{result, r.intents, r.events})
	if strings.Contains(string(encoded), f.sessions[1]) || strings.Contains(string(encoded), "All stores open") {
		t.Fatal("session or tool text leaked into receipt")
	}
}

func TestMCPSessionRefusesWrongReplyAndCleansExactSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*mcpTestTransport)
	}{
		{"wrong JSON-RPC id", func(f *mcpTestTransport) { f.responses[2] = mcpWire(200, 7, map[string]any{"tools": []any{}}, "") }},
		{"wrong session", func(f *mcpTestTransport) { f.responses[2].SessionID = "ffffffffffffffffffffffffffffffff" }},
		{"wrong tool text", func(f *mcpTestTransport) {
			f.responses[3] = mcpWire(200, 3, map[string]any{"content": []any{map[string]any{"type": "text", "text": "wrong"}}}, "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := mcpSuccessFixture()
			tc.change(f)
			r := &mcpTestRecorder{}
			result := runMCPFixture(t, f, r)
			if result.Outcome == OutcomeFunctionalPass || !result.Cleanup.Verified {
				t.Fatalf("wrong reply accepted or session not cleaned: %+v", result)
			}
			if f.calls[len(f.calls)-2] != http.MethodDelete || f.calls[len(f.calls)-1] != http.MethodPost {
				t.Fatalf("cleanup omitted: %v", f.calls)
			}
		})
	}
}

func TestMCPSessionAmbiguousInitAndCleanupFailureRemainUnsafe(t *testing.T) {
	f := mcpSuccessFixture()
	f.failCall = 1
	r := &mcpTestRecorder{}
	result := runMCPFixture(t, f, r)
	if result.Outcome != OutcomeInconclusive || !result.UnsafeToRetry || result.Cleanup.Verified || len(f.calls) != 1 {
		t.Fatalf("ambiguous init replayed or accepted: %+v %v", result, f.calls)
	}
	f = mcpSuccessFixture()
	f.responses[4].Status = 503
	r = &mcpTestRecorder{}
	result = runMCPFixture(t, f, r)
	if result.Outcome == OutcomeFunctionalPass || !result.UnsafeToRetry || result.Cleanup.Verified || len(f.calls) != 5 {
		t.Fatalf("failed DELETE accepted: %+v %v", result, f.calls)
	}
}

func TestMCPSessionDriftAndPinRefuseBeforeTraffic(t *testing.T) {
	f := mcpSuccessFixture()
	f.driftAt = 2
	r := &mcpTestRecorder{}
	result := runMCPFixture(t, f, r)
	if len(f.calls) != 0 || result.Outcome != OutcomeInconclusive {
		t.Fatalf("identity drift dispatched: %+v %v", result, f.calls)
	}
	f = mcpSuccessFixture()
	f.sourcePinError = true
	result = runMCPFixture(t, f, &mcpTestRecorder{})
	if len(f.calls) != 0 || result.Outcome != OutcomeInconclusive {
		t.Fatalf("source drift dispatched: %+v %v", result, f.calls)
	}
}

func TestMCPSessionReconcileDoesNotInventSessionCleanup(t *testing.T) {
	h := mcpSessionHandler{}
	unknown := h.Reconcile(context.Background(), JobContext{}, Journal{Records: []JournalRecord{{Intent: &Intent{Step: "mcp.initialize", Mutation: true}}}})
	if unknown.Verified || !unknown.UnsafeToRetry {
		t.Fatalf("unobservable session falsely cleaned: %+v", unknown)
	}
	known := h.Reconcile(context.Background(), JobContext{}, Journal{Records: []JournalRecord{{Event: &Event{Step: "mcp.verify-deleted", Status: "verified"}}}})
	if !known.Verified {
		t.Fatalf("verified session lost: %+v", known)
	}
}

func TestMCPSessionRuntimeIsClosedAndDisabledByDefault(t *testing.T) {
	c := mcpTestConfig()
	if err := ValidateMCPSessionRuntime(c); err != nil {
		t.Fatal(err)
	}
	c.Enabled = false
	if ValidateMCPSessionRuntime(c) == nil {
		t.Fatal("disabled profile admitted")
	}
	c = mcpTestConfig()
	c.ExpectedSourceSHA256 = strings.Repeat("0", 64)
	if ValidateMCPSessionRuntime(c) == nil {
		t.Fatal("unreviewed source admitted")
	}
	c = mcpTestConfig()
	c.Namespace = "customer"
	if ValidateMCPSessionRuntime(c) == nil {
		t.Fatal("arbitrary namespace admitted")
	}
}
