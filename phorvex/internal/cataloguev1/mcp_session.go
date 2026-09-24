package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	mcpInstalledSourceSHA = "483009cd01640e9f604a21f16aa890539566f53a25fd7dc478bc43c1831212c5"
	mcpHoursSHA           = "d470bb916e2aca9ac8fe34d7bcb94fa30d74503ca188233c2d461119381ba117"
	mcpProtocolVersion    = "2025-03-26"
	mcpMaxResponse        = 64 << 10
)

var mcpSessionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type mcpSessionHandler struct {
	newTransport func(Runtime) (mcpTransport, error)
}

func NewMCPSessionHandler() Handler { return mcpSessionHandler{newTransport: newMCPKubeTransport} }

func (h mcpSessionHandler) Definition() Definition {
	d, _ := DefinitionFor(MCPSessionBaseline)
	return d
}

func ValidateMCPSessionRuntime(c MCPSessionRuntime) error {
	if !c.Enabled || c.Namespace != "mcp" || c.Deployment != "mcp-server" || c.Service != "mcp-server" ||
		c.Container != "mcp-server" || c.Port != 8000 || c.SourceConfigMap != "mcp-code" || c.SourceKey != "server.py" ||
		c.ExpectedSourceSHA256 != mcpInstalledSourceSHA || c.ExpectedImageID != "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff" {
		return errors.New("MCP session runtime is disabled or differs from the reviewed installed contract")
	}
	return nil
}

func (h mcpSessionHandler) Validate(r Runtime) error {
	if err := ValidateMCPSessionRuntime(r.MCP); err != nil {
		return err
	}
	if r.Kube == nil || r.RESTConfig == nil {
		return errors.New("MCP Kubernetes transport is unavailable")
	}
	return nil
}

type mcpAuthority struct {
	PodName          string `json:"podName"`
	PodUID           string `json:"podUID"`
	ContainerID      string `json:"containerID"`
	ImageID          string `json:"imageID"`
	RestartCount     int32  `json:"restartCount"`
	DeployUID        string `json:"deployUID"`
	DeployGeneration int64  `json:"deployGeneration"`
	ServiceUID       string `json:"serviceUID"`
	SliceUID         string `json:"sliceUID"`
	SourceUID        string `json:"sourceUID"`
	SourceRV         string `json:"sourceRV"`
	SourceSHA        string `json:"sourceSHA"`
}

func (a mcpAuthority) fingerprint() string {
	b, _ := json.Marshal(a)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type mcpWireResponse struct {
	Status      int
	ContentType string
	SessionID   string
	Body        []byte
}

type mcpTransport interface {
	snapshot(context.Context, MCPSessionRuntime) (mcpAuthority, error)
	installedSourcePin(context.Context, MCPSessionRuntime, mcpAuthority) error
	call(context.Context, MCPSessionRuntime, mcpAuthority, string, []byte, string) (mcpWireResponse, error)
}

func (h mcpSessionHandler) Run(ctx context.Context, jc JobContext) (result Result) {
	started := time.Now().UTC()
	result = Result{Outcome: OutcomeInconclusive, Summary: "MCP session control incomplete", StartedAt: started,
		Evidence: map[string]string{"securityOutcome": "NOT_EVALUATED", "installedDefense": "NOT_EVALUATED", "requestCount": "0"},
		Limits:   []string{h.Definition().ClaimLimits}, Cleanup: Cleanup{Status: "not-started"}}
	defer func() { result.FinishedAt = time.Now().UTC() }()
	if err := h.Validate(jc.Runtime); err != nil {
		result.Summary = "MCP runtime authority unavailable"
		return result
	}
	if jc.Recorder == nil {
		result.Summary = "MCP journal unavailable"
		return result
	}
	transport, err := h.newTransport(jc.Runtime)
	if err != nil {
		result.Summary = "MCP transport unavailable"
		return result
	}
	result = runMCPSession(ctx, jc, transport, result)
	return result
}

func runMCPSession(ctx context.Context, jc JobContext, t mcpTransport, result Result) (out Result) {
	out = result
	defer func() { out.FinishedAt = time.Now().UTC() }()
	cfg := jc.Runtime.MCP
	before, err := t.snapshot(ctx, cfg)
	if err != nil {
		out.Summary = "MCP target preflight unavailable"
		return
	}
	if err = t.installedSourcePin(ctx, cfg, before); err != nil {
		out.Summary = "MCP installed source pin unavailable"
		return
	}
	out.Evidence["targetPodUID"] = before.PodUID
	out.Evidence["sourceSHA256"] = before.SourceSHA
	out.Evidence["sourceEvidence"] = "mounted-file-and-installed-package-hashes"
	out.Evidence["loadedPythonBytes"] = "NOT_ATTESTED"
	out.Evidence["authorityBeforeSHA256"] = before.fingerprint()
	var session string
	var initAttempted, protocolComplete bool
	var requests int
	defer func() {
		defer func() {
			out.Evidence["requestCount"] = fmt.Sprint(requests)
			if !out.Cleanup.Verified && out.Outcome == OutcomeFunctionalFail {
				out.Outcome = OutcomeInconclusive
			}
		}()
		if !initAttempted {
			out.Cleanup = Cleanup{Verified: true, Status: "not-needed"}
			return
		}
		out.Cleanup = Cleanup{Attempted: true, Status: "session-unverified", UnsafeToRetry: true}
		out.UnsafeToRetry = true
		if session == "" {
			out.Summary += "; session creation outcome unknown"
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		current, checkErr := t.snapshot(cleanupCtx, cfg)
		if checkErr != nil || current.fingerprint() != before.fingerprint() || t.installedSourcePin(cleanupCtx, cfg, current) != nil {
			out.Summary += "; exact target changed before session cleanup"
			return
		}
		if jc.Recorder.Intent(Intent{Step: "mcp.delete", Mutation: true, At: time.Now().UTC(), Identity: map[string]string{"targetPodUID": before.PodUID}}) != nil {
			out.Summary += "; session cleanup intent could not be recorded"
			return
		}
		deleted, callErr := t.call(cleanupCtx, cfg, before, http.MethodDelete, nil, session)
		requests++
		if callErr != nil || deleted.Status != http.StatusOK || !validMCPSessionHeader(deleted.SessionID, session) || len(deleted.Body) > mcpMaxResponse {
			out.Summary += "; session DELETE unconfirmed"
			return
		}
		if jc.Recorder.Event(Event{Step: "mcp.delete", Status: "accepted", At: time.Now().UTC()}) != nil {
			out.Summary += "; DELETE receipt unavailable"
			return
		}
		if jc.Recorder.Intent(Intent{Step: "mcp.verify-deleted", At: time.Now().UTC(), Identity: map[string]string{"targetPodUID": before.PodUID}}) != nil {
			out.Summary += "; cleanup verification intent unavailable"
			return
		}
		verified, verifyErr := t.call(cleanupCtx, cfg, before, http.MethodPost, mcpRPC(4, "tools/list", map[string]any{}), session)
		requests++
		if verifyErr != nil || !mcpDeletedResponse(verified, session) {
			out.Summary += "; same-session invalidation unverified"
			return
		}
		if jc.Recorder.Event(Event{Step: "mcp.verify-deleted", Status: "verified", At: time.Now().UTC()}) != nil {
			out.Summary += "; cleanup proof could not be recorded"
			return
		}
		after, afterErr := t.snapshot(cleanupCtx, cfg)
		if afterErr != nil || after.fingerprint() != before.fingerprint() || t.installedSourcePin(cleanupCtx, cfg, after) != nil {
			out.Summary += "; final MCP target/source pin changed"
			return
		}
		out.Evidence["authorityAfterSHA256"] = after.fingerprint()
		out.Cleanup = Cleanup{Attempted: true, Verified: true, Status: "session-delete-and-404-verified"}
		out.UnsafeToRetry = false
		if protocolComplete {
			out.Outcome = OutcomeFunctionalPass
			out.Summary = "fixed MCP read and same-session invalidation verified"
		}
	}()

	step := func(name, method string, payload []byte, mutation bool) (mcpWireResponse, error) {
		if requests >= 4 {
			return mcpWireResponse{}, errors.New("request bound")
		}
		current, e := t.snapshot(ctx, cfg)
		if e != nil || current.fingerprint() != before.fingerprint() {
			return mcpWireResponse{}, errors.New("target identity changed")
		}
		if e = t.installedSourcePin(ctx, cfg, current); e != nil {
			return mcpWireResponse{}, errors.New("installed source changed")
		}
		if e = jc.Recorder.Intent(Intent{Step: name, Mutation: mutation, At: time.Now().UTC(), Identity: map[string]string{"targetPodUID": before.PodUID}}); e != nil {
			return mcpWireResponse{}, errors.New("intent persistence failed")
		}
		if name == "mcp.initialize" {
			initAttempted = true
		}
		response, e := t.call(ctx, cfg, before, method, payload, session)
		requests++
		if e != nil {
			return mcpWireResponse{}, errors.New("fixed MCP request outcome ambiguous")
		}
		if len(response.Body) > mcpMaxResponse {
			return mcpWireResponse{}, errors.New("MCP response bound exceeded")
		}
		if e = jc.Recorder.Event(Event{Step: name, Status: "observed", At: time.Now().UTC(), Identity: map[string]string{"httpStatus": fmt.Sprint(response.Status)}}); e != nil {
			return mcpWireResponse{}, errors.New("observation persistence failed")
		}
		return response, nil
	}
	initBody := mcpRPC(1, "initialize", map[string]any{"protocolVersion": mcpProtocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "phorvex-owned-functional-control", "version": "1.0"}})
	init, e := step("mcp.initialize", http.MethodPost, initBody, true)
	if e != nil {
		out.Summary = e.Error()
		return
	}
	if init.Status != http.StatusOK || !mcpSessionPattern.MatchString(init.SessionID) {
		out.Summary = "MCP initialize status or session header differed"
		return
	}
	session = init.SessionID
	initResult, e := mcpRPCResult(init, 1)
	if e != nil || initResult["protocolVersion"] != mcpProtocolVersion {
		out.Summary = "MCP initialize protocol differed"
		return
	}
	server, ok := initResult["serverInfo"].(map[string]any)
	if !ok || server["name"] == "" {
		out.Summary = "MCP server info missing"
		return
	}
	notify, e := step("mcp.initialized", http.MethodPost, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), false)
	if e != nil || notify.Status != http.StatusAccepted || !validMCPSessionHeader(notify.SessionID, session) || len(notify.Body) != 0 {
		out.Summary = "MCP initialized notification differed"
		return
	}
	list, e := step("mcp.list", http.MethodPost, mcpRPC(2, "tools/list", map[string]any{}), false)
	if e != nil {
		out.Summary = e.Error()
		return
	}
	if list.Status != http.StatusOK || !validMCPSessionHeader(list.SessionID, session) {
		out.Summary = "MCP tools/list status or session differed"
		return
	}
	listed, e := mcpRPCResult(list, 2)
	if e != nil || !mcpExactTools(listed) {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "MCP fixed tool list/schema differed"
		return
	}
	call, e := step("mcp.call-hours", http.MethodPost, mcpRPC(3, "tools/call", map[string]any{"name": "store_directory", "arguments": map[string]string{"topic": "hours"}}), false)
	if e != nil {
		out.Summary = e.Error()
		return
	}
	if call.Status != http.StatusOK || !validMCPSessionHeader(call.SessionID, session) {
		out.Summary = "MCP tool call status or session differed"
		return
	}
	called, e := mcpRPCResult(call, 3)
	if e != nil {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "MCP tool result envelope differed"
		return
	}
	content, ok := called["content"].([]any)
	if !ok || len(content) != 1 || (called["isError"] != nil && called["isError"] != false) {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "MCP tool result shape differed"
		return
	}
	item, ok := content[0].(map[string]any)
	if !ok || item["type"] != "text" {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "MCP tool content type differed"
		return
	}
	text, ok := item["text"].(string)
	if !ok {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "MCP tool text missing"
		return
	}
	digest := sha256.Sum256([]byte(text))
	if len([]byte(text)) != 76 || hex.EncodeToString(digest[:]) != mcpHoursSHA {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "MCP fixed hours result differed"
		return
	}
	out.Evidence["toolTextSHA256"] = mcpHoursSHA
	out.Evidence["toolTextBytes"] = "76"
	protocolComplete = true
	return
}

func (h mcpSessionHandler) Reconcile(_ context.Context, _ JobContext, journal Journal) Cleanup {
	for _, record := range journal.Records {
		if record.Event != nil && record.Event.Step == "mcp.verify-deleted" && record.Event.Status == "verified" {
			return Cleanup{Attempted: true, Verified: true, Status: "previously-verified-no-replay"}
		}
	}
	return Cleanup{Attempted: true, Verified: false, Status: "session-id-was-memory-only; exact invalidation unproven", UnsafeToRetry: true}
}

func mcpRPC(id int, method string, params any) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return b
}

func validMCPSessionHeader(got, want string) bool { return got == "" || got == want }

func mcpRPCResult(r mcpWireResponse, id int) (map[string]any, error) {
	if r.ContentType != "application/json" && r.ContentType != "text/event-stream" {
		return nil, errors.New("MCP response content type differed")
	}
	data := r.Body
	if r.ContentType == "text/event-stream" {
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		var found []byte
		for _, block := range bytes.Split(data, []byte("\n\n")) {
			var lines [][]byte
			for _, line := range bytes.Split(block, []byte("\n")) {
				line = bytes.TrimSuffix(line, []byte("\r"))
				if bytes.HasPrefix(line, []byte("data:")) {
					lines = append(lines, bytes.TrimSpace(line[5:]))
				}
			}
			if len(lines) == 0 {
				continue
			}
			candidate := bytes.Join(lines, []byte("\n"))
			var obj map[string]any
			if json.Unmarshal(candidate, &obj) == nil && obj["id"] == float64(id) {
				found = candidate
				break
			}
		}
		if len(found) == 0 {
			return nil, errors.New("MCP SSE matching event absent")
		}
		data = found
	}
	var envelope map[string]any
	if json.Unmarshal(data, &envelope) != nil || envelope["jsonrpc"] != "2.0" || envelope["id"] != float64(id) || envelope["error"] != nil {
		return nil, errors.New("MCP JSON-RPC envelope differed")
	}
	result, ok := envelope["result"].(map[string]any)
	if !ok {
		return nil, errors.New("MCP JSON-RPC result missing")
	}
	return result, nil
}

func mcpExactTools(result map[string]any) bool {
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) != 2 {
		return false
	}
	names := make([]string, 0, 2)
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		name, ok := tool["name"].(string)
		if !ok {
			return false
		}
		_, hasDescription := tool["description"].(string)
		schema, hasSchema := tool["inputSchema"].(map[string]any)
		if !hasDescription || !hasSchema {
			return false
		}
		if name == "store_directory" {
			if schema["type"] != "object" {
				return false
			}
			required, ok := schema["required"].([]any)
			if !ok {
				return false
			}
			found := false
			for _, x := range required {
				if x == "topic" {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",") == "check_promotions,store_directory"
}

func mcpDeletedResponse(r mcpWireResponse, session string) bool {
	if r.Status != http.StatusNotFound || r.ContentType != "application/json" || !validMCPSessionHeader(r.SessionID, session) || len(r.Body) > mcpMaxResponse {
		return false
	}
	var envelope map[string]any
	if json.Unmarshal(r.Body, &envelope) != nil || envelope["jsonrpc"] != "2.0" || envelope["id"] != "server-error" || envelope["result"] != nil {
		return false
	}
	problem, ok := envelope["error"].(map[string]any)
	return ok && problem["code"] == float64(-32600)
}
