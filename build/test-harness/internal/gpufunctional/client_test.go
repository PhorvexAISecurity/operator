package gpufunctional

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef"

var testDrainOwner = DrainOwner{Tenant: "catalogue", NamespaceUID: "namespace", PolicyUID: "run", PodUID: "11111111-2222-4333-8444-555555555555", ServiceUID: "service"}

func capabilityBody() map[string]any {
	return map[string]any{
		"schema": "phorvex.drain.v1", "capability": "operation-bound-quiescence-v1",
		"pod_uid": "11111111-2222-4333-8444-555555555555", "ledger_id": strings.Repeat("a", 32),
		"proxy_boot_id": strings.Repeat("b", 32), "engine_boot_id": strings.Repeat("c", 32),
		"incarnation_digest": strings.Repeat("d", 64), "proxy_source": strings.Repeat("e", 40),
		"engine_source": strings.Repeat("f", 64), "engine_mode": "v0-frontend-multiprocessing",
		"virtual_engine_ids": []int{0}, "generation_high_water": "0", "next_operation_generation": "1", "admission": "OPEN",
	}
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type prefixServer struct {
	mu                 sync.Mutex
	prompt, completed  int
	hit                float64
	active             int
	resetCalls         int
	streamDones        []chan struct{}
	lastPrompt         string
	successMetricMode  string
	requestPaths       []string
	completionPrompts  []string
	completedAtReset   []int
	rejectPrimer       bool
	blockPrimer        bool
	finishStreamsFast  bool
	forceBusySuccess   bool
	missingTerminal    bool
	terminalReason     string
	skipStreamSuccess  bool
	extraStreamSuccess int
	postCohortBusy     bool
	rejectStream       int
	streamRequests     int
	releaseStreams     bool
}

func (s *prefixServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requestPaths = append(s.requestPaths, r.URL.Path)
	s.mu.Unlock()
	if r.URL.Path != "/metrics" && r.Header.Get("Authorization") != "Bearer "+testToken {
		jsonResponse(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	switch r.URL.Path {
	case "/v1/drain/capability":
		jsonResponse(w, http.StatusOK, capabilityBody())
	case "/metrics":
		s.mu.Lock()
		prompt, completed, hit, active, successMetricMode := s.prompt, s.completed, s.hit, s.active, s.successMetricMode
		s.mu.Unlock()
		running, waiting := 0, 0
		if active > 0 {
			running, waiting = 1, active-1
		} else if s.postCohortBusy && completed >= 3+streamCohortSize {
			running = 1
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "vllm:gpu_prefix_cache_hit_rate{model_name=\"%s\"} %g\n", modelName, hit)
		fmt.Fprintf(w, "vllm:num_requests_running{model_name=\"%s\"} %d\n", modelName, running)
		fmt.Fprintf(w, "vllm:num_requests_waiting{model_name=\"%s\"} %d\n", modelName, waiting)
		fmt.Fprintf(w, "vllm:gpu_cache_usage_perc{model_name=\"%s\"} 0.2\n", modelName)
		fmt.Fprintf(w, "vllm:prompt_tokens_total{model_name=\"%s\"} %d\n", modelName, prompt)
		switch {
		case successMetricMode == "always-absent" || completed == 0:
		case successMetricMode == "malformed":
			fmt.Fprintln(w, "vllm:request_success_total 1")
		case successMetricMode == "foreign":
			fmt.Fprintln(w, "vllm:request_success_total{finished_reason=\"length\",model_name=\"foreign/model\"} 1")
		default:
			fmt.Fprintf(w, "vllm:request_success_total{finished_reason=\"length\",model_name=\"%s\"} %d\n", modelName, completed)
		}
	case "/reset_prefix_cache":
		s.mu.Lock()
		s.resetCalls++
		s.completedAtReset = append(s.completedAtReset, s.completed)
		success := s.active == 0
		if s.active > 0 && s.forceBusySuccess {
			success = true
		}
		if success {
			s.hit = 0
			s.lastPrompt = ""
		}
		if s.active > 0 {
			s.releaseStreams = true
			for _, done := range s.streamDones {
				close(done)
			}
			s.streamDones = nil
		}
		s.mu.Unlock()
		jsonResponse(w, http.StatusOK, map[string]any{"success": success})
	case "/v1/completions":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if streaming, _ := body["stream"].(bool); streaming {
			s.mu.Lock()
			ordinal := s.streamRequests
			s.streamRequests++
			if s.rejectStream > 0 && ordinal == s.rejectStream-1 {
				s.mu.Unlock()
				jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "stream-refused"})
				return
			}
			if !s.finishStreamsFast {
				s.active++
			}
			done := make(chan struct{})
			s.streamDones = append(s.streamDones, done)
			released := s.releaseStreams
			s.mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "data: {\"id\":\"cmpl-prefix-stream-%d\",\"object\":\"text_completion\",\"created\":1,\"model\":\"%s\",\"choices\":[{\"index\":0,\"text\":\"x\",\"logprobs\":null,\"finish_reason\":null,\"stop_reason\":null}]}\n\n", ordinal, modelName)
			w.(http.Flusher).Flush()
			if !s.finishStreamsFast && !released {
				select {
				case <-done:
				case <-r.Context().Done():
				}
			}
			s.mu.Lock()
			if !s.finishStreamsFast {
				s.active--
			}
			if !s.skipStreamSuccess {
				s.completed++
				if ordinal == streamCohortSize-1 {
					s.completed += s.extraStreamSuccess
				}
			}
			reason := s.terminalReason
			if reason == "" {
				reason = "length"
			}
			s.mu.Unlock()
			if !s.missingTerminal {
				fmt.Fprintf(w, "data: {\"id\":\"cmpl-prefix-stream-%d\",\"object\":\"text_completion\",\"created\":1,\"model\":%q,\"choices\":[{\"index\":0,\"text\":\"\",\"logprobs\":null,\"finish_reason\":%q,\"stop_reason\":null}]}\n\n", ordinal, modelName, reason)
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		prompt, _ := body["prompt"].(string)
		s.mu.Lock()
		s.completionPrompts = append(s.completionPrompts, prompt)
		isPrimer := len(s.completionPrompts) == 1
		rejectPrimer, blockPrimer := s.rejectPrimer && isPrimer, s.blockPrimer && isPrimer
		s.mu.Unlock()
		if blockPrimer {
			<-r.Context().Done()
			return
		}
		if rejectPrimer {
			jsonResponse(w, http.StatusServiceUnavailable, map[string]any{"error": "primer-refused"})
			return
		}
		s.mu.Lock()
		s.prompt += 10
		s.completed++
		if prompt == s.lastPrompt {
			s.hit = .5
		} else {
			s.hit = 0
		}
		s.lastPrompt = prompt
		s.mu.Unlock()
		jsonResponse(w, http.StatusOK, map[string]any{"id": "cmpl-test", "object": "text_completion", "created": 1, "model": modelName, "choices": []map[string]any{{"index": 0, "text": "x", "logprobs": nil, "finish_reason": "length", "stop_reason": nil, "prompt_logprobs": nil}}, "usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11, "prompt_tokens_details": nil}})
	default:
		http.NotFound(w, r)
	}
}

func TestRunPrefixCohortRefusesUnestablishedAndContradictoryBusyControls(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state *prefixServer
	}{
		{name: "fast cohort drains before active sample", state: &prefixServer{finishStreamsFast: true}},
		{name: "partial admission", state: &prefixServer{rejectStream: 1}},
		{name: "active reset acknowledged", state: &prefixServer{forceBusySuccess: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tc.state.serve))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			client.sleep = func(context.Context, time.Duration) error { return nil }
			receipt, err := client.RunPrefix(t.Context(), true)
			if err == nil || receipt.Busy == nil || receipt.Busy.Cohort.Schema != "phorvex.gpu.stream-cohort.v3" || len(receipt.Busy.Cohort.Streams) != streamCohortSize {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
			tc.state.mu.Lock()
			resetCalls, active := tc.state.resetCalls, tc.state.active
			tc.state.mu.Unlock()
			wantCalls := 1
			if tc.state.forceBusySuccess {
				wantCalls = 2
			}
			for attempt := 0; active != 0 && attempt < 100; attempt++ {
				time.Sleep(time.Millisecond)
				tc.state.mu.Lock()
				active = tc.state.active
				tc.state.mu.Unlock()
			}
			if resetCalls != wantCalls || active != 0 {
				t.Fatalf("resetCalls=%d want=%d active=%d", resetCalls, wantCalls, active)
			}
			for _, stream := range receipt.Busy.Cohort.Streams {
				if stream.SubmittedAt == "" || !stream.Finished || stream.Termination == "running" || stream.Termination == "not-started" {
					t.Fatalf("stream finalizer omitted actual terminal state: %+v", stream)
				}
			}
		})
	}
}

func TestRunPrefixActualHTTPProducerNoActionAndDirect(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-action", true: "direct"}[direct], func(t *testing.T) {
			state := &prefixServer{}
			server := httptest.NewServer(http.HandlerFunc(state.serve))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			client.sleep = func(context.Context, time.Duration) error { return nil }
			receipt, err := client.RunPrefix(t.Context(), direct)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.EngineBootID != strings.Repeat("c", 32) || receipt.Primer.ID == "" || receipt.Cold.RequestSuccessMetricPresent ||
				!receipt.Baseline.RequestSuccessMetricPresent || receipt.Baseline.Values["vllm:request_success_total"] != 1 ||
				receipt.Populated.Values["vllm:request_success_total"] != 3 || receipt.Populated.Values["vllm:gpu_prefix_cache_hit_rate"] <= 0 {
				t.Fatalf("receipt=%+v", receipt)
			}
			state.mu.Lock()
			prompts := append([]string(nil), state.completionPrompts...)
			paths := append([]string(nil), state.requestPaths...)
			completedAtReset := append([]int(nil), state.completedAtReset...)
			state.mu.Unlock()
			measuredPrompt := strings.TrimSpace(strings.Repeat("one two three four five six seven eight ", 20))
			if len(prompts) < 3 || prompts[0] != primerPrompt || prompts[1] != measuredPrompt || prompts[2] != measuredPrompt || prompts[0] == prompts[1] {
				t.Fatalf("primer/measured prompt sequence=%q", prompts)
			}
			wantPrefix := []string{"/v1/drain/capability", "/metrics", "/v1/completions", "/metrics", "/v1/completions", "/v1/completions", "/metrics"}
			if len(paths) < len(wantPrefix) || !slices.Equal(paths[:len(wantPrefix)], wantPrefix) {
				t.Fatalf("HTTP prefix=%q want=%q", paths, wantPrefix)
			}
			if direct {
				if receipt.Reset == nil || !receipt.Reset.Success || receipt.FirstMiss == nil || receipt.FirstMiss.Values["vllm:gpu_prefix_cache_hit_rate"] != 0 || receipt.Repopulated == nil || receipt.Busy == nil || receipt.Busy.Reset.Success || receipt.Busy.Cohort.Expected != streamCohortSize || len(receipt.Busy.Cohort.Streams) != streamCohortSize {
					t.Fatalf("direct receipt incomplete: %+v", receipt)
				}
				if state.resetCalls != 2 {
					t.Fatalf("reset calls=%d want 2", state.resetCalls)
				}
				if len(completedAtReset) != 2 || completedAtReset[0] != 3 {
					t.Fatalf("first reset followed completed=%v; primer plus the same two measured requests must precede divergence", completedAtReset)
				}
				if len(receipt.CapabilityObservation.Body) == 0 || len(receipt.Reset.Observation.Body) == 0 || receipt.Populated.RawBody == "" || receipt.Busy.Cohort.Streams[0].RequestID == "" {
					t.Fatalf("direct receipt omitted retained producer proof: %+v", receipt)
				}
				if !busyEstablished(receipt.Busy.ActiveMetrics.Values) || !idle(receipt.Busy.PreIdle.Values) {
					t.Fatalf("direct receipt omitted idle/active cohort bracket: %+v", receipt.Busy)
				}
				if !idle(receipt.Busy.PostCohort.Values) || receipt.Busy.PostCohort.Values["vllm:request_success_total"]-receipt.Busy.PreIdle.Values["vllm:request_success_total"] != streamCohortSize || receipt.Busy.PostCohort.RawBody == "" {
					t.Fatalf("direct receipt omitted exact post-cohort reconciliation: %+v", receipt.Busy)
				}
				seenIDs := map[string]bool{}
				for _, stream := range receipt.Busy.Cohort.Streams {
					if stream.SubmittedAt == "" || stream.AcceptedAt == "" || stream.RequestID == "" || stream.EventCount < 2 || !stream.Finished || !stream.SawDone || stream.FinishReason != "length" || stream.Termination != "complete" || seenIDs[stream.RequestID] {
						t.Fatalf("direct cohort lifecycle differs: %+v", stream)
					}
					seenIDs[stream.RequestID] = true
				}
			} else if receipt.Reset != nil || state.resetCalls != 0 || len(prompts) != 3 {
				t.Fatalf("no-action executed reset or extra inference: reset=%+v calls=%d prompts=%q", receipt.Reset, state.resetCalls, prompts)
			}
		})
	}
}

func TestRunPrefixRequiresTerminalLengthAndExactPostCohortCounter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state *prefixServer
	}{
		{name: "missing terminal event", state: &prefixServer{missingTerminal: true}},
		{name: "contradictory terminal reason", state: &prefixServer{terminalReason: "stop"}},
		{name: "missing success counter advancement", state: &prefixServer{skipStreamSuccess: true}},
		{name: "incorrect success counter advancement", state: &prefixServer{extraStreamSuccess: 1}},
		{name: "post cohort remains busy", state: &prefixServer{postCohortBusy: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tc.state.serve))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			client.sleep = func(context.Context, time.Duration) error { return nil }
			receipt, err := client.RunPrefix(t.Context(), true)
			if err == nil || receipt.Busy == nil || receipt.Busy.Cohort.Expected != streamCohortSize {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

func TestRunPrefixRequiresStrictSuccessMetricAfterPrimer(t *testing.T) {
	for _, mode := range []string{"always-absent", "malformed", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			state := &prefixServer{successMetricMode: mode}
			server := httptest.NewServer(http.HandlerFunc(state.serve))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			client.sleep = func(context.Context, time.Duration) error { return nil }
			receipt, err := client.RunPrefix(t.Context(), false)
			if err == nil || receipt.Primer.ID == "" || receipt.Baseline.RawBody == "" || receipt.First.ID != "" {
				t.Fatalf("mode=%s receipt=%+v err=%v", mode, receipt, err)
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.resetCalls != 0 || len(state.completionPrompts) != 1 || state.completionPrompts[0] != primerPrompt {
				t.Fatalf("mode=%s resets=%d prompts=%q", mode, state.resetCalls, state.completionPrompts)
			}
		})
	}
}

func TestRunPrefixRetainsColdStateAndRefusesFailedOrCancelledPrimer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		state  *prefixServer
		ctx    func(*testing.T) (context.Context, context.CancelFunc)
		status int
	}{
		{name: "bad-response", state: &prefixServer{rejectPrimer: true}, ctx: func(*testing.T) (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}, status: http.StatusServiceUnavailable},
		{name: "cancelled", state: &prefixServer{blockPrimer: true}, ctx: func(*testing.T) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tc.state.serve))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := tc.ctx(t)
			defer cancel()
			receipt, err := client.RunPrefix(ctx, false)
			if err == nil || receipt.Cold.RawBody == "" || receipt.Cold.RequestSuccessMetricPresent || receipt.Primer.Observation.Path != "/v1/completions" || receipt.Primer.Observation.Status != tc.status || receipt.Baseline.RawBody != "" || receipt.First.ID != "" {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
			tc.state.mu.Lock()
			defer tc.state.mu.Unlock()
			if tc.state.resetCalls != 0 || len(tc.state.completionPrompts) != 1 || tc.state.completionPrompts[0] != primerPrompt {
				t.Fatalf("resets=%d prompts=%q", tc.state.resetCalls, tc.state.completionPrompts)
			}
		})
	}
}

func operationBody(opID, generation, state, admission, revision, nonce1, nonce2 string, requestIDs []string) map[string]any {
	observations := []any{}
	if nonce1 != "" {
		observations = append(observations, map[string]any{"nonce": nonce1, "sequence": "1", "queues": map[string]any{"0": map[string]any{"waiting": []string{}, "running": []string{}, "swapped": []string{}, "cached": []string{}}}, "hash": strings.Repeat("1", 64)})
	}
	if nonce2 != "" {
		observations = append(observations, map[string]any{"nonce": nonce2, "sequence": "2", "queues": map[string]any{"0": map[string]any{"waiting": []string{}, "running": []string{}, "swapped": []string{}, "cached": []string{}}}, "hash": strings.Repeat("2", 64)})
	}
	var queryNonce any
	if nonce2 != "" {
		queryNonce = nonce2
	} else if nonce1 != "" {
		queryNonce = nonce1
	}
	dispositions := map[string]string{}
	for _, requestID := range requestIDs {
		dispositions[requestID] = "aborted"
	}
	body := map[string]any{"schema": "phorvex.drain.v1", "operation_id": opID, "operation_generation": generation, "attempt": 1, "owner_digest": drainOwnerDigest(testDrainOwner), "backend_incarnation_digest": strings.Repeat("d", 64), "revision": revision, "state": state, "admission": admission, "admission_generation": "1", "engine_boot_id": strings.Repeat("c", 32), "virtual_engine_ids": []int{0}, "engine_snapshot": map[string]any{"0": map[string]any{"waiting": requestIDs[1:], "running": requestIDs[:1], "swapped": []string{}, "cached": []string{}}}, "terminal_dispositions": dispositions, "proxy_snapshot": map[string]any{"before_engine_begin": map[string]int{"active": len(requestIDs)}, "after_engine_begin": map[string]int{"cancelled": len(requestIDs), "remaining": 0}}, "observations": observations, "deadline": "2026-09-22T00:00:00Z", "cancellation_grace_deadline": "2026-09-22T00:00:30.000000Z", "transition_reason": "none", "cancel_boundary_revision": "0", "last_transition": "2026-09-22T00:00:00Z", "query_nonce": queryNonce}
	digest, err := drainDigest("phorvex-drain-status-v1", body)
	if err != nil {
		panic(err)
	}
	body["receipt_sha256"] = digest
	return body
}

type drainServer struct {
	mu                    sync.Mutex
	active                int
	streamRequests        int
	closed                bool
	streamDones           []chan struct{}
	streamIDs             []string
	streamMaxTokens       []int
	metricsCalls          int
	snapshotIDs           []string
	opID, generation      string
	nonces                []string
	reopenCalls           int
	capabilities          int
	wrongRecoveredEpoch   bool
	omitDisposition       bool
	loseCreateResponse    bool
	loseReopenResponse    bool
	wrongStreamIdentity   bool
	noAuthenticatedEvents bool
}

func (s *drainServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" && r.Header.Get("Authorization") != "Bearer "+testToken {
		jsonResponse(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	switch {
	case r.URL.Path == "/v1/drain/capability":
		s.mu.Lock()
		s.capabilities++
		body := capabilityBody()
		if s.opID != "" {
			body["generation_high_water"] = "1"
			delete(body, "next_operation_generation")
		}
		if s.wrongRecoveredEpoch && s.capabilities > 1 {
			body["engine_boot_id"] = strings.Repeat("9", 32)
		}
		if s.closed {
			body["admission"] = "CLOSED"
		}
		s.mu.Unlock()
		jsonResponse(w, 200, body)
	case r.URL.Path == "/metrics":
		s.mu.Lock()
		s.metricsCalls++
		active := s.active
		s.mu.Unlock()
		running, waiting := 0, 0
		if active > 0 {
			running, waiting = 1, active-1
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "vllm:gpu_prefix_cache_hit_rate{model_name=\"%s\"} 0\nvllm:num_requests_running{model_name=\"%s\"} %d\nvllm:num_requests_waiting{model_name=\"%s\"} %d\nvllm:gpu_cache_usage_perc{model_name=\"%s\"} 0.2\nvllm:prompt_tokens_total{model_name=\"%s\"} 1\nvllm:request_success_total{model_name=\"%s\",finished_reason=\"length\"} 1\n", modelName, modelName, running, modelName, waiting, modelName, modelName, modelName)
	case r.URL.Path == "/v1/completions":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			jsonResponse(w, 503, map[string]string{"error": "admission_closed"})
			return
		}
		if streaming, _ := body["stream"].(bool); streaming {
			s.mu.Lock()
			ordinal := s.streamRequests
			s.streamRequests++
			maxTokens, _ := body["max_tokens"].(float64)
			s.streamMaxTokens = append(s.streamMaxTokens, int(maxTokens))
			s.active++
			s.streamIDs = append(s.streamIDs, fmt.Sprintf("cmpl-drain-stream-%d-0", ordinal))
			done := make(chan struct{})
			s.streamDones = append(s.streamDones, done)
			s.mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			requestID := fmt.Sprintf("cmpl-drain-stream-%d", ordinal)
			if ordinal == 0 && !s.noAuthenticatedEvents {
				fmt.Fprintf(w, "data: {\"id\":%q,\"object\":\"text_completion\",\"created\":1,\"model\":\"%s\",\"choices\":[{\"index\":0,\"text\":\"x\",\"logprobs\":null,\"finish_reason\":null,\"stop_reason\":null}]}\n\n", requestID, modelName)
			}
			w.(http.Flusher).Flush()
			if s.noAuthenticatedEvents {
				s.mu.Lock()
				s.active--
				s.mu.Unlock()
				return
			}
			select {
			case <-done:
			case <-r.Context().Done():
			}
			s.mu.Lock()
			s.active--
			s.mu.Unlock()
			return
		}
		jsonResponse(w, 200, map[string]any{"id": "cmpl", "object": "text_completion", "created": 1, "model": modelName, "choices": []map[string]any{{"index": 0, "text": "x", "logprobs": nil, "finish_reason": "length", "stop_reason": nil, "prompt_logprobs": nil}}, "usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2, "prompt_tokens_details": nil}})
	case r.URL.Path == "/v1/drain/operations" && r.Method == http.MethodPost:
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.mu.Lock()
		s.closed = true
		s.opID = payload["operation_id"].(string)
		s.generation = payload["operation_generation"].(string)
		s.snapshotIDs = append([]string(nil), s.streamIDs...)
		if s.wrongStreamIdentity && len(s.snapshotIDs) > 0 {
			s.snapshotIDs[0] = "cmpl-foreign-stream-0"
		}
		for _, done := range s.streamDones {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		s.streamDones = nil
		body := operationBody(s.opID, s.generation, "DRAINING", "CLOSED", "2", "", "", s.snapshotIDs)
		if s.omitDisposition {
			body["terminal_dispositions"] = map[string]string{}
		}
		s.mu.Unlock()
		if s.loseCreateResponse {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"truncated":`)
			return
		}
		jsonResponse(w, 201, body)
	case strings.HasSuffix(r.URL.Path, "/reopen"):
		s.mu.Lock()
		s.closed = false
		s.reopenCalls++
		body := operationBody(s.opID, s.generation, "OPENED", "OPEN", "6", "", "", s.snapshotIDs)
		s.mu.Unlock()
		if s.loseReopenResponse {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"truncated":`)
			return
		}
		jsonResponse(w, 200, body)
	case strings.HasPrefix(r.URL.Path, "/v1/drain/operations/"):
		nonce := r.URL.Query().Get("observation_nonce")
		s.mu.Lock()
		s.nonces = append(s.nonces, nonce)
		one, two := "", ""
		if len(s.nonces) > 0 {
			one = s.nonces[0]
		}
		if len(s.nonces) > 1 {
			two = s.nonces[1]
		}
		state, admission := "DRAINING", "CLOSED"
		if !s.closed {
			state, admission = "OPENED", "OPEN"
		} else if len(s.nonces) >= 2 {
			state = "QUIESCENT"
		}
		body := operationBody(s.opID, s.generation, state, admission, strconv.Itoa(2+len(s.nonces)), one, two, s.snapshotIDs)
		if s.omitDisposition {
			body["terminal_dispositions"] = map[string]string{}
		}
		s.mu.Unlock()
		jsonResponse(w, 200, body)
	default:
		http.NotFound(w, r)
	}
}

func TestRunDrainActualHTTPProducerModesAndFailures(t *testing.T) {
	owner := testDrainOwner
	for _, tc := range []struct {
		name                                                                                                                    string
		direct, wrongEpoch, omitDisposition, loseCreateResponse, loseReopenResponse, wrongStreamIdentity, noAuthenticatedEvents bool
		wantErr                                                                                                                 bool
		wantReopens                                                                                                             int
	}{
		{name: "no-action"}, {name: "direct", direct: true, wantReopens: 1}, {name: "wrong recovered epoch", direct: true, wrongEpoch: true, wantErr: true, wantReopens: 1}, {name: "tampered disposition receipt", direct: true, omitDisposition: true, wantErr: true}, {name: "accepted create lost response", direct: true, loseCreateResponse: true, wantErr: true, wantReopens: 1}, {name: "accepted reopen lost response", direct: true, loseReopenResponse: true, wantErr: true, wantReopens: 1}, {name: "snapshot missing selected anchor", direct: true, wrongStreamIdentity: true, wantErr: true, wantReopens: 1}, {name: "queued requests expose no authenticated ID", direct: true, noAuthenticatedEvents: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &drainServer{wrongRecoveredEpoch: tc.wrongEpoch, omitDisposition: tc.omitDisposition, loseCreateResponse: tc.loseCreateResponse, loseReopenResponse: tc.loseReopenResponse, wrongStreamIdentity: tc.wrongStreamIdentity, noAuthenticatedEvents: tc.noAuthenticatedEvents}
			server := httptest.NewServer(http.HandlerFunc(state.serve))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			client.sleep = func(context.Context, time.Duration) error { return nil }
			receipt, err := client.RunDrain(t.Context(), tc.direct, owner)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v receipt=%+v", err, receipt)
			}
			if !tc.direct {
				if receipt.Create != nil || state.reopenCalls != 0 || state.metricsCalls != 2 {
					t.Fatalf("no-action mutated: %+v", receipt)
				}
				return
			}
			if state.metricsCalls != 1 {
				t.Fatalf("direct drain used a post-submission metrics gate: calls=%d", state.metricsCalls)
			}
			if state.reopenCalls != tc.wantReopens {
				t.Fatalf("reopen calls=%d want %d", state.reopenCalls, tc.wantReopens)
			}
			if tc.noAuthenticatedEvents && (receipt.Create != nil || state.opID != "" || receipt.Anchor != nil) {
				t.Fatalf("operation was sent without an authenticated unfinished anchor: %+v", receipt)
			}
			if tc.loseCreateResponse && (receipt.CreateObservation == nil || receipt.CreateObservation.Body == "" || len(receipt.CleanupObservations) < 2) {
				t.Fatalf("lost create response did not retain partial body and cleanup reads: %+v", receipt)
			}
			if tc.loseReopenResponse && (receipt.ReopenObservation == nil || receipt.ReopenObservation.Body == "" || len(receipt.CleanupObservations) != 1 || receipt.Reopen == nil || receipt.Reopen.State != "OPENED") {
				t.Fatalf("lost reopen response did not retain raw response and observed OPEN state: %+v", receipt)
			}
			var active int
			for deadline := time.Now().Add(time.Second); ; time.Sleep(time.Millisecond) {
				state.mu.Lock()
				active = state.active
				state.mu.Unlock()
				if active == 0 || time.Now().After(deadline) {
					break
				}
			}
			if active != 0 {
				t.Fatalf("owned stream remained active after return: %d", active)
			}
			if !tc.wantErr && (receipt.SecondObservation == nil || len(receipt.SecondObservation.Observations) != 2 || receipt.PostInference == nil || receipt.Mode != "direct" || len(receipt.SnapshotBindings) != 1 || len(receipt.UnattributedSnapshotIDs) != streamCohortSize-1 || receipt.FullCohortAttributed || receipt.Anchor == nil || receipt.Anchor.StreamOrdinal < 0 || receipt.Anchor.ProducerRequestID != "cmpl-drain-stream-0" || receipt.Anchor.EngineRequestID != "cmpl-drain-stream-0-0" || receipt.Anchor.CreateStartedAtUTC == "" || receipt.Cohort.Expected != streamCohortSize || len(receipt.FirstObservationSource.Body) == 0 || len(receipt.SecondObservationSource.Body) == 0 || len(receipt.ReopenObservation.Body) == 0 || len(receipt.RecoveredCapabilityObservation.Body) == 0) {
				t.Fatalf("direct receipt incomplete: %+v", receipt)
			}
			if !tc.wantErr {
				if len(state.streamMaxTokens) != streamCohortSize {
					t.Fatalf("drain stream demand count differs: %v", state.streamMaxTokens)
				}
				for _, maxTokens := range state.streamMaxTokens {
					if maxTokens != drainStreamMaxTokens {
						t.Fatalf("drain stream token demand=%d want %d", maxTokens, drainStreamMaxTokens)
					}
				}
				for _, stream := range receipt.Cohort.Streams {
					if stream.Ordinal == receipt.Anchor.StreamOrdinal {
						continue
					}
					if stream.RequestID != "" || stream.FinishedAt == "" || !stream.Finished {
						t.Fatalf("queued background request was falsely attributed or not finalized: %+v", stream)
					}
				}
			}
		})
	}
}

func TestDrainAnchorAuthorityRejectsCompletedAndUnauthenticatedStreams(t *testing.T) {
	lifecycle := make(chan struct{}, 4)
	finished := make(chan struct{})
	stream := &streamExecution{finished: finished, lifecycle: lifecycle, receipt: StreamLifecycleReceipt{
		Ordinal: 0, RequestID: "cmpl-anchor", AcceptedAt: "2026-09-23T00:00:00Z", EventCount: 1, Termination: "running",
	}}
	cohort := &streamCohort{streams: []*streamExecution{stream}, lifecycle: lifecycle}
	anchor, err := cohort.selectUnfinishedAnchor(time.Date(2026, 9, 23, 0, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	stream.mu.Lock()
	stream.receipt.Finished = true
	stream.receipt.FinishedAt = "2026-09-23T00:00:02Z"
	stream.receipt.Termination = "complete"
	stream.mu.Unlock()
	close(finished)
	if cohort.anchorStillUnfinished(anchor) {
		t.Fatal("completed selected anchor remained authorized for create")
	}
	if _, err := cohort.selectUnfinishedAnchor(time.Date(2026, 9, 23, 0, 0, 3, 0, time.UTC)); !errors.Is(err, errNoAuthenticatedUnfinishedAnchor) {
		t.Fatalf("completed cohort was accepted: %v", err)
	}

	queued := &streamExecution{finished: make(chan struct{}), lifecycle: lifecycle, receipt: StreamLifecycleReceipt{Ordinal: 1, Termination: "running"}}
	cohort = &streamCohort{streams: []*streamExecution{queued}, lifecycle: lifecycle}
	if _, err := cohort.selectUnfinishedAnchor(time.Date(2026, 9, 23, 0, 0, 4, 0, time.UTC)); !errors.Is(err, errNoAuthenticatedUnfinishedAnchor) {
		t.Fatalf("queued request without producer identity became an anchor: %v", err)
	}
}

func TestWaitResponseHeadersPrefersAcceptedAuthorityAndKeepsSeparateUnfinishedAnchor(t *testing.T) {
	acceptedCompleted := func(ordinal int) *streamExecution {
		response := make(chan struct{})
		finished := make(chan struct{})
		close(response)
		close(finished)
		return &streamExecution{response: response, finished: finished, receipt: StreamLifecycleReceipt{
			Ordinal: ordinal, HTTPStatus: http.StatusOK, MediaType: "text/event-stream", Finished: true,
			RequestID: "cmpl-completed", AcceptedAt: "2026-09-23T00:00:00Z", Termination: "complete",
		}}
	}
	response := make(chan struct{})
	close(response)
	unfinished := &streamExecution{response: response, finished: make(chan struct{}), receipt: StreamLifecycleReceipt{
		Ordinal: 1, HTTPStatus: http.StatusOK, MediaType: "text/event-stream",
		RequestID: "cmpl-anchor", AcceptedAt: "2026-09-23T00:00:01Z", Termination: "running",
	}}
	for i := 0; i < 100; i++ {
		cohort := &streamCohort{streams: []*streamExecution{acceptedCompleted(0), unfinished}}
		if err := cohort.waitResponseHeaders(context.Background(), time.Millisecond); err != nil {
			t.Fatalf("iteration %d rejected an already accepted completed SSE peer: %v", i, err)
		}
		anchor, err := cohort.selectUnfinishedAnchor(time.Date(2026, 9, 23, 0, 0, 2, 0, time.UTC))
		if err != nil || anchor.StreamOrdinal != 1 || anchor.ProducerRequestID != "cmpl-anchor" {
			t.Fatalf("separate unfinished anchor was not selected: anchor=%+v err=%v", anchor, err)
		}
	}
}

func TestWaitResponseHeadersRejectsMissingAndInvalidAuthority(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response bool
		status   int
		media    string
	}{
		{name: "finished without response"},
		{name: "invalid accepted response", response: true, status: http.StatusBadGateway, media: "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := make(chan struct{})
			finished := make(chan struct{})
			if tc.response {
				close(response)
			}
			close(finished)
			stream := &streamExecution{response: response, finished: finished, receipt: StreamLifecycleReceipt{
				Ordinal: 0, HTTPStatus: tc.status, MediaType: tc.media, Finished: true, Termination: "error",
			}}
			cohort := &streamCohort{streams: []*streamExecution{stream}}
			if err := cohort.waitResponseHeaders(context.Background(), time.Millisecond); err == nil {
				t.Fatal("missing or invalid response authority was accepted")
			}
		})
	}
}

func TestRetainedRealWireCorpusParsesAndBindsProducerDigests(t *testing.T) {
	for _, control := range []struct {
		name, file, sha string
		wantBusy        bool
		wantRunning     float64
		wantWaiting     float64
		wantCompleted   float64
	}{
		{name: "R71 fast request completed before scrape", file: "r71-fast-complete-metrics.txt", sha: "83f8eeee750b587fc8f8ac4b9a936ec9061b0633ee8feff349dc3c9400b49494", wantCompleted: 6},
		{name: "v9 eight-request cohort retained active state", file: "v9-cohort-active-metrics.txt", sha: "c30583ff0b49cf9772d65289b8d3a0bf4a53c484de62c215277ff762f1a1dbaa", wantBusy: true, wantRunning: 1, wantWaiting: 6, wantCompleted: 5},
	} {
		t.Run(control.name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/retained-wire/" + control.file)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != control.sha {
				t.Fatalf("retained control hash differs: %s", got)
			}
			values, err := parseMetrics(raw)
			if err != nil {
				t.Fatalf("retained actual vLLM metrics rejected: %v", err)
			}
			if busyEstablished(values) != control.wantBusy || values["vllm:num_requests_running"] != control.wantRunning || values["vllm:num_requests_waiting"] != control.wantWaiting || values["vllm:request_success_total"] != control.wantCompleted {
				t.Fatalf("retained control semantics differ: %+v", values)
			}
		})
	}

	coldRaw, err := os.ReadFile("testdata/retained-wire/cold-metrics.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(coldRaw)); got != "f3b9b115fe8cdf45c91bf8d21b3720b67434cbc7e4194e2da1fc38ec02921765" {
		t.Fatalf("retained cold metrics corpus hash differs: %s", got)
	}
	coldValues, successPresent, err := parseMetricsMode(coldRaw, false)
	if err != nil || successPresent || !idle(coldValues) || coldValues["vllm:prompt_tokens_total"] != 0 {
		t.Fatalf("actual cold vLLM 0.7.3 metrics rejected: present=%v values=%+v err=%v", successPresent, coldValues, err)
	}
	if _, err := parseMetrics(coldRaw); err == nil || !strings.Contains(err.Error(), "request success metric is absent") {
		t.Fatalf("strict post-primer parser accepted actual cold metrics: %v", err)
	}

	metricsRaw, err := os.ReadFile("testdata/retained-wire/populated-metrics.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(metricsRaw)); got != "0680c52b1366ec5b19133b44467afc9e4d44d9e88efcd8a8f3f9ea7de8d73225" {
		t.Fatalf("retained metrics corpus hash differs: %s", got)
	}
	values, err := parseMetrics(metricsRaw)
	if err != nil {
		t.Fatalf("actual vLLM 0.7.3 metrics rejected: %v", err)
	}
	if values["vllm:gpu_prefix_cache_hit_rate"] != .5 || values["vllm:request_success_total"] != 2 {
		t.Fatalf("actual metrics values differ: %+v", values)
	}
	for _, corrupt := range []string{
		"vllm:request_success_total{finished_reason=\"stop\",model_name=\"foreign/model\"} NaN\n",
		"vllm:request_success_total{finished_reason=\"length\",model_name=\"facebook/opt-125m\"} 9\n",
		"vllm:prompt_tokens_total{model_name=\"facebook/opt-125m\"} NaN\n",
	} {
		mixed := append(append([]byte(nil), metricsRaw...), []byte(corrupt)...)
		if _, err := parseMetrics(mixed); err == nil {
			t.Fatalf("strict parser accepted mixed valid/invalid target series %q", corrupt)
		}
		if _, _, err := parseMetricsMode(mixed, false); err == nil {
			t.Fatalf("cold parser accepted mixed valid/invalid target series %q", corrupt)
		}
	}
	modelFirst := strings.Replace(string(metricsRaw), `{finished_reason="length",model_name="facebook/opt-125m"}`, `{model_name="facebook/opt-125m",finished_reason="length"}`, 1)
	if _, err := parseMetrics([]byte(modelFirst)); err != nil {
		t.Fatalf("semantically equivalent label order rejected: %v", err)
	}
	withUnexpected := strings.Replace(modelFirst, `{model_name="facebook/opt-125m",finished_reason="length"}`, `{model_name="facebook/opt-125m",finished_reason="length",tenant="foreign"}`, 1)
	if _, err := parseMetrics([]byte(withUnexpected)); err == nil {
		t.Fatal("unexpected request-success label accepted")
	}

	wireHashes := map[string]string{
		"drain-created.json":     "7adb4360cc1a0568536465cedd4478c0bc445e131045f897ed56267cced5f340",
		"drain-observe-one.json": "1df57122985a4b27faa6285bea1984a4a21b7a7a878d1f7a79334f871ffe1b52",
		"drain-observe-two.json": "4f09e97ec9d08e5aa492cdf44c8c51198ff17f765c5b093e295ffad64ed9b357",
		"drain-reopened.json":    "def01be736739bbd9c6608c87e13aa6423710a4db263c8e6f47663b90e6611ba",
	}
	readOperation := func(name string) DrainOperation {
		t.Helper()
		raw, err := os.ReadFile("testdata/retained-wire/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != wireHashes[name] {
			t.Fatalf("retained %s wire hash differs: %s", name, got)
		}
		var operation DrainOperation
		if err := strictJSON(raw, &operation); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if err := validateDrainReceiptDigest(operation); err != nil {
			t.Fatalf("actual producer digest %s: %v", name, err)
		}
		return operation
	}
	created := readOperation("drain-created.json")
	first := readOperation("drain-observe-one.json")
	second := readOperation("drain-observe-two.json")
	_ = readOperation("drain-reopened.json")
	if first.QueryNonce == nil || second.QueryNonce == nil {
		t.Fatal("actual producer corpus omitted query nonce")
	}
	if err := validateTerminalSequence(created, first, second, *first.QueryNonce, *second.QueryNonce); err != nil {
		t.Fatalf("actual DRAINING then QUIESCENT sequence rejected: %v", err)
	}
	tampered := second
	tampered.State = "DRAINING"
	if err := validateDrainReceiptDigest(tampered); err == nil {
		t.Fatal("tampered actual producer receipt digest accepted")
	}
}

func TestCapabilityRejectsMalformedAndOversizedActualResponses(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{name: "duplicate", body: `{"schema":"phorvex.drain.v1","schema":"phorvex.drain.v1"}`},
		{name: "oversized", body: strings.Repeat("x", MaxResponseBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := client.Capability(t.Context()); err == nil {
				t.Fatal("malformed capability accepted")
			}
		})
	}
}

func TestOwnedStreamCleanupReportsJoinTimeout(t *testing.T) {
	run := &streamExecution{cancel: func() {}, finished: make(chan struct{}), joinTimeout: time.Millisecond}
	if err := run.stop(); err == nil {
		t.Fatal("owned stream join timeout was hidden")
	}
}

func TestCapabilityAcceptsRetainedActualWireShape(t *testing.T) {
	raw, err := os.ReadFile("testdata/retained-wire/drain-capability.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	client, err := New(server.URL, testToken, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	capability, observation, err := client.Capability(t.Context())
	if err != nil {
		t.Fatalf("actual capability rejected: %v", err)
	}
	if capability.Schema != "phorvex.drain.v1" || len(observation.Body) != len(raw) || observation.SHA256 != "0ab172493cb9ed3064b3b9058210c819d1609b9a5cfd0d3ab76335b2421c9e00" {
		t.Fatalf("actual capability receipt differs: %+v %+v", capability, observation)
	}
}

func TestCapabilityGenerationTransitionsAllowIntentionalMissingNextGeneration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "baseline creatable"},
		{name: "active closed", mutate: func(body map[string]any) {
			body["generation_high_water"] = "1"
			body["admission"] = "CLOSED"
			delete(body, "next_operation_generation")
		}},
		{name: "reopened retained operation", mutate: func(body map[string]any) {
			body["generation_high_water"] = "1"
			delete(body, "next_operation_generation")
		}},
		{name: "noncanonical high water", mutate: func(body map[string]any) {
			body["generation_high_water"] = "01"
			delete(body, "next_operation_generation")
		}, wantErr: true},
		{name: "next generation gap", mutate: func(body map[string]any) {
			body["generation_high_water"] = "1"
			body["next_operation_generation"] = "3"
		}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := capabilityBody()
			if tc.mutate != nil {
				tc.mutate(body)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				jsonResponse(w, http.StatusOK, body)
			}))
			defer server.Close()
			client, err := New(server.URL, testToken, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = client.Capability(t.Context())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestDrainTimingAcceptsExactPythonMicrosecondGraceForNanosecondDeadline(t *testing.T) {
	opID := strings.Repeat("1", 32)
	body := operationBody(opID, "1", "DRAINING", "CLOSED", "2", "", "", []string{"cmpl-anchor-0"})
	body["deadline"] = "2026-09-23T10:57:43.351817702Z"
	body["cancellation_grace_deadline"] = "2026-09-23T10:58:13.351817Z"
	delete(body, "receipt_sha256")
	digest, err := drainDigest("phorvex-drain-status-v1", body)
	if err != nil {
		t.Fatal(err)
	}
	body["receipt_sha256"] = digest
	decode := func(value map[string]any) DrainOperation {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var operation DrainOperation
		if err := strictJSON(raw, &operation); err != nil {
			t.Fatal(err)
		}
		return operation
	}
	payload := createOperation{Schema: "phorvex.drain.v1", OperationID: opID, OperationGeneration: "1", Attempt: 1, Owner: testDrainOwner, ExpectedIncarnationDigest: strings.Repeat("d", 64), Deadline: body["deadline"].(string), Mode: "abort-and-quiesce"}
	capability := Capability{IncarnationDigest: strings.Repeat("d", 64), EngineBootID: strings.Repeat("c", 32)}
	if err := validateDrainBinding(decode(body), payload, capability); err != nil {
		t.Fatalf("actual Go-deadline/Python-grace precision contract rejected: %v", err)
	}
	for _, grace := range []string{
		"2026-09-23T10:58:13.351817000Z",
		"2026-09-23T10:58:13.351818Z",
	} {
		bad := maps.Clone(body)
		bad["cancellation_grace_deadline"] = grace
		if err := validateDrainBinding(decode(bad), payload, capability); err == nil || !strings.Contains(err.Error(), "timing or cancellation boundary") {
			t.Fatalf("non-producer grace %q accepted: %v", grace, err)
		}
	}
}

func TestInferenceAcceptsRetainedVLLM073CompletionShape(t *testing.T) {
	retained, err := os.ReadFile("testdata/retained-wire/prefix-completion.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(retained)
	}))
	defer server.Close()
	client, err := New(server.URL, testToken, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.Inference(t.Context(), "synthetic", 1)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ID != "cmpl-3b36c8fd2baf4b76bcba2e86b56f65f0" || receipt.Observation.SHA256 != "8b2675f31024cb90168ea13ca31497c072d7f2376a7b3e1b5aba4cb201a0cbb3" || receipt.TextSHA256 == "" {
		t.Fatalf("retained completion identity differs: %+v", receipt)
	}
}
