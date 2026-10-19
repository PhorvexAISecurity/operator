package console

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOwnedLoRACleanupObservesBeforeSingleUnloadAndRetainsUnknown(t *testing.T) {
	const name = "phorvex-probe-aabbccddeeff0011"
	for _, tc := range []struct {
		name, mode  string
		startLoaded bool
		wantOK      bool
		wantUnloads int
	}{
		{"confirmed present", "", true, true, 1},
		{"lost unload ack but absent", "lost-ack", true, true, 1},
		{"already absent", "", false, true, 0},
		{"route contradicts inventory", "route-mismatch", true, false, 0},
		{"unload remains unresolved", "stuck", true, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			loaded, unloads := tc.startLoaded, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case "/v1/models":
					data := []map[string]string{{"id": liveLoRABaseModel}}
					if loaded {
						data = append(data, map[string]string{"id": name})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
				case "/v1/completions":
					var request struct {
						Model string `json:"model"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					if request.Model == name && (!loaded || tc.mode == "route-mismatch") {
						w.WriteHeader(http.StatusNotFound)
						_ = json.NewEncoder(w).Encode(map[string]any{"object": "error", "message": "The model `" + name + "` does not exist.", "type": "NotFoundError", "code": 404})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "object": "text_completion", "model": request.Model, "choices": []map[string]any{{"index": 0, "text": "blue", "finish_reason": "length"}}, "usage": map[string]int{"completion_tokens": 1}})
				case "/v1/unload_lora_adapter":
					unloads++
					if tc.mode != "stuck" {
						loaded = false
					}
					_ = json.NewEncoder(w).Encode(map[string]bool{"unloaded": true})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}}
			cfg := Config{StateDir: t.TempDir(), Sleep: func(time.Duration) {}, Exec: func(d time.Duration, bin string, args ...string) (string, error) {
				out, err := fixture.exec(d, bin, args...)
				if tc.mode == "lost-ack" && strings.Contains(strings.Join(args, " "), "/v1/unload_lora_adapter") {
					return "", errors.New("unload acknowledgement lost")
				}
				return out, err
			}}
			s := &Server{cfg: cfg}
			err := s.reconcileOwnedLoRA("vllm-0", "pod-uid", name)
			if (err == nil) != tc.wantOK {
				t.Fatalf("cleanup err=%v wantOK=%t", err, tc.wantOK)
			}
			mu.Lock()
			gotUnloads := unloads
			mu.Unlock()
			if gotUnloads != tc.wantUnloads {
				t.Fatalf("unload calls=%d want=%d", gotUnloads, tc.wantUnloads)
			}
			fixture.mu.Lock()
			commands := append([]string(nil), fixture.commands...)
			fixture.mu.Unlock()
			removed := false
			for _, command := range commands {
				removed = removed || (strings.Contains(command, "-- python3 -c") && !strings.HasSuffix(strings.TrimSpace(command), " verify"))
			}
			if removed != tc.wantOK {
				t.Fatalf("artifact cleanup=%t err=%v", removed, err)
			}
		})
	}
}

func TestOwnedLoRATerminalPersistenceFailureClearsPublishedDefense(t *testing.T) {
	resetM168AttackMemory()
	now := time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)
	s := &Server{cfg: Config{StateDir: t.TempDir(), Now: func() time.Time { return now },
		StateAppend: func(string, []byte) error { return errors.New("sink unavailable") },
		Exec:        func(time.Duration, string, ...string) (string, error) { return "", nil }}}
	r := &attackRecord{ID: "owned-lora-failed-persist", FiredAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		ObservationStart: now.Add(-time.Second).Format(time.RFC3339Nano), ObservationEnd: now.Format(time.RFC3339Nano),
		Namespace: "vllm", Pod: "vllm-0", TargetUID: "pod-uid", AttackID: "poison", EvidenceKind: "vllm-in-place-effect",
		Outcome: "DEFENDED", OutcomeClass: "unapproved-adapter-capability-removed", Action: "adapter-rotate", Actuated: true,
		EffectEvidence: &attackEffectEvidence{Kind: "adapter-epoch", Observed: true, TargetUID: "pod-uid"},
		vllmEffect:     &vllmEffectBaseline{kind: "adapter-epoch", adapterName: "phorvex-probe-aabbccddeeff0011"}}
	s.watchAttackUntil("", r, now, time.Millisecond)
	got := attackSnapshotByID(r.ID)
	if got == nil || got.Outcome != "" || got.Actuated || got.Status != "partial" || got.PersistenceError == "" || got.EffectEvidence == nil || !got.EffectEvidence.Observed {
		t.Fatalf("undurable defense was published or observations lost: %+v", got)
	}
}

func TestOwnedLoRAObserverNeverPublishesUndurableDefense(t *testing.T) {
	resetM168AttackMemory()
	const name = "phorvex-probe-aabbccddeeff0011"
	const podUID = "11111111-1111-4111-8111-111111111111"
	const policyUID = "22222222-2222-4222-8222-222222222222"
	const cmUID = "33333333-3333-4333-8333-333333333333"
	now := time.Date(2026, 9, 27, 8, 0, 1, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": liveLoRABaseModel}}})
			return
		}
		if r.URL.Path == "/v1/completions" {
			var request struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.Model == name {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"object": "error", "message": "The model `" + name + "` does not exist.", "type": "NotFoundError", "code": 404})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "object": "text_completion", "model": request.Model, "choices": []map[string]any{{"index": 0, "text": "blue", "finish_reason": "length"}}, "usage": map[string]int{"completion_tokens": 1}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, podUID: podUID, adapterEpoch: "event-uid", events: map[string]string{}}
	event := map[string]any{"metadata": map[string]any{"name": "event-name", "uid": "event-uid", "creationTimestamp": "2026-09-27T08:00:00Z", "labels": map[string]string{"phorvex.ai/attack-correlation": "corr", "phorvex.ai/console-vllm": "true"}, "annotations": map[string]string{"phorvex.ai/adapter-name": name, "phorvex.ai/target-pod-uid": podUID}}, "spec": map[string]any{"targets": []string{"vllm/vllm-0"}, "rule": map[string]string{"type": "phorvex.attack.adapter", "source": "redteam"}}}
	eventBytes, _ := json.Marshal(event)
	fixture.events["event-name"] = string(eventBytes)
	sum := sha256.Sum256([]byte("adapter-rotate/" + policyUID + "/" + podUID))
	journalName := fmt.Sprintf("phorvex-operation-%x", sum[:20])
	d := decisionEvidence{Correlation: "exact-event-uid", Source: "decision-trace-steered-event", EventUID: "event-uid", EventName: "event-name", EventRule: "phorvex.attack.adapter", TargetUID: podUID, TrustVerdict: "trusted", PolicyNamespace: "vllm", PolicyName: "policy", PolicyUID: policyUID, TickID: "tick-1", DecisionID: "decision-1", Action: "adapter-rotate", Selected: true, Feasible: true, Actuated: true, DispatchOutcome: "emitted", Handler: "adapter-rotate", MutationKind: "forward-only", RollbackRef: "phorvex-system/" + journalName + "@" + cmUID, ObjectsTouched: []string{"ConfigMap/phorvex-system/" + journalName, "Pod/vllm/vllm-0"}}
	appendCalls := 0
	cfg := Config{StateDir: t.TempDir(), Now: func() time.Time { return now }, Exec: fixture.exec,
		StateAppend: func(path string, b []byte) error {
			if strings.HasSuffix(path, "phorvex-attacks.jsonl") {
				appendCalls++
				return errors.New("terminal sink unavailable")
			}
			return appendState(path, b)
		}}
	s := &Server{cfg: cfg}
	r := &attackRecord{ID: "owned-lora-observer-persist", Namespace: "vllm", Pod: "vllm-0", TargetUID: podUID, AttackID: "poison", EvidenceKind: "vllm-in-place-effect", started: now.Add(-time.Second),
		StimulusEvidence: &attackStimulusEvidence{Observed: true, EventName: "event-name", EventUID: "event-uid", EventCreatedAt: "2026-09-27T08:00:00Z", EventRule: "phorvex.attack.adapter", Correlation: "corr", TargetUID: podUID},
		EffectEvidence:   &attackEffectEvidence{Kind: "adapter-epoch", Observed: true, TargetUID: podUID}, vllmEffect: &vllmEffectBaseline{kind: "adapter-epoch", adapterName: name}, DecisionTraceEvidence: []decisionEvidence{d}}
	s.observeOwnedLoRAOutcome("", r, now.Add(10*time.Second))
	publishAttack(r)
	got := attackSnapshotByID(r.ID)
	if appendCalls != 1 || got == nil || got.Outcome != "" || got.Actuated || got.Status != "partial" || got.EffectEvidence == nil || !got.EffectEvidence.Observed || got.LoRACleanupStatus != "completed" || !got.loRATerminalPersistFailed {
		t.Fatalf("undurable observer defense published or cleanup retried: appendCalls=%d record=%+v", appendCalls, got)
	}
	s.observeOwnedLoRAOutcome("", r, now.Add(10*time.Second))
	if appendCalls != 1 {
		t.Fatalf("failed terminal observer retried mutation or persistence: calls=%d", appendCalls)
	}
}

func TestPoisonSetupFailureReconcilesExactOwnedAdapterWithoutLoadRetry(t *testing.T) {
	for _, mode := range []string{"load-ack-lost", "route-probe-failed", "route-probe-stays-bad", "event-create-absent", "event-create-ack-lost"} {
		t.Run(mode, func(t *testing.T) {
			resetM168AttackMemory()
			var mu sync.Mutex
			loaded, loads, unloads, routeFailure := "", 0, 0, mode == "route-probe-failed" || mode == "route-probe-stays-bad"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case "/v1/models":
					data := []map[string]string{{"id": liveLoRABaseModel}}
					if loaded != "" {
						data = append(data, map[string]string{"id": loaded})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
				case "/v1/load_lora_adapter":
					loads++
					var request struct {
						Name string `json:"lora_name"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					loaded = request.Name
					_ = json.NewEncoder(w).Encode(map[string]bool{"loaded": true})
				case "/v1/unload_lora_adapter":
					unloads++
					loaded = ""
					_ = json.NewEncoder(w).Encode(map[string]bool{"unloaded": true})
				case "/v1/completions":
					var request struct {
						Model string `json:"model"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					if request.Model == loaded && loaded != "" && routeFailure {
						if mode != "route-probe-stays-bad" {
							routeFailure = false
						}
						http.Error(w, "transient probe failure", http.StatusServiceUnavailable)
						return
					}
					if strings.HasPrefix(request.Model, "phorvex-probe-") && request.Model != loaded {
						w.WriteHeader(http.StatusNotFound)
						_ = json.NewEncoder(w).Encode(map[string]any{"object": "error", "message": "The model `" + request.Model + "` does not exist.", "type": "NotFoundError", "code": 404})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "object": "text_completion", "model": request.Model, "choices": []map[string]any{{"index": 0, "text": "blue", "finish_reason": "length"}}, "usage": map[string]int{"completion_tokens": 1}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}, loseCreateAck: mode == "event-create-ack-lost"}
			cfg := Config{StateDir: t.TempDir(), AttackWatchDuration: 5 * time.Millisecond, AttackWatchInterval: time.Millisecond,
				Exec: func(d time.Duration, bin string, args ...string) (string, error) {
					if mode == "event-create-absent" && bin == "kubectl" && len(args) > 0 && args[0] == "create" {
						return "", errors.New("create not accepted")
					}
					out, err := fixture.exec(d, bin, args...)
					if mode == "load-ack-lost" && strings.Contains(strings.Join(args, " "), "/v1/load_lora_adapter") {
						return "", errors.New("load acknowledgement lost")
					}
					return out, err
				}}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
			t.Cleanup(s.attackWatchers.Wait)
			response := httptest.NewRecorder()
			s.vllmAttack(response, httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"poison"}`)))
			var reconciledRecord *attackRecord
			if mode == "event-create-ack-lost" {
				var reply struct {
					AttackID string `json:"attackId"`
				}
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reply) != nil || reply.AttackID == "" {
					t.Fatalf("exact event create acknowledgement was not reconciled: %d %s", response.Code, response.Body.String())
				}
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					reconciledRecord = attackSnapshotByID(reply.AttackID)
					if reconciledRecord != nil && reconciledRecord.Status != "running" {
						break
					}
					time.Sleep(time.Millisecond)
				}
			}
			mu.Lock()
			gotLoads, gotUnloads, stillLoaded := loads, unloads, loaded
			mu.Unlock()
			fixture.mu.Lock()
			commands := append([]string(nil), fixture.commands...)
			fixture.mu.Unlock()
			for _, command := range commands {
				if strings.Contains(command, " exec ") && !strings.Contains(command, " -c vllm --") {
					t.Fatalf("LoRA command escaped exact vllm container: %q", command)
				}
			}
			if gotLoads != 1 {
				t.Fatalf("load retried or skipped: %d", gotLoads)
			}
			if mode == "event-create-ack-lost" {
				if reconciledRecord == nil || reconciledRecord.Outcome != "LANDED" || reconciledRecord.LoRACleanupStatus != "completed" || gotUnloads != 1 {
					t.Fatalf("exact accepted event was not handed to watcher: record=%+v unloads=%d body=%s", reconciledRecord, gotUnloads, response.Body.String())
				}
				return
			}
			if mode == "route-probe-stays-bad" {
				if response.Code != http.StatusBadGateway || gotUnloads != 0 || stillLoaded == "" || !strings.Contains(response.Body.String(), "unsafe-to-retry") {
					t.Fatalf("ambiguous owned adapter was silently discarded: code=%d unloads=%d loaded=%q body=%s", response.Code, gotUnloads, stillLoaded, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusBadGateway || gotUnloads != 1 || stillLoaded != "" || !strings.Contains(response.Body.String(), "absent and artifact removed") {
				t.Fatalf("owned failure cleanup missing: code=%d loads=%d unloads=%d loaded=%q body=%s", response.Code, gotLoads, gotUnloads, stillLoaded, response.Body.String())
			}
			data, err := os.ReadFile(cfg.statePath("effect-intents.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"adapterName":"phorvex-probe-`) || !strings.Contains(string(data), `"restoration":"completed:`) {
				t.Fatalf("exact setup failure owner missing: %s", data)
			}
		})
	}
}

func TestOwnedLoRATerminalDecisionRejectsPartialAndCompetingAudit(t *testing.T) {
	const podUID = "11111111-1111-4111-8111-111111111111"
	const policyUID = "22222222-2222-4222-8222-222222222222"
	const cmUID = "33333333-3333-4333-8333-333333333333"
	sum := sha256.Sum256([]byte("adapter-rotate/" + policyUID + "/" + podUID))
	name := fmt.Sprintf("phorvex-operation-%x", sum[:20])
	base := decisionEvidence{
		Correlation: "exact-event-uid", Source: "decision-trace-steered-event", EventUID: "event-uid", EventName: "event-name", EventRule: "phorvex.attack.adapter",
		TargetUID: podUID, TrustVerdict: "trusted", PolicyNamespace: "vllm", PolicyName: "policy", PolicyUID: policyUID,
		TickID: "tick-1", DecisionID: "decision-1", Action: "adapter-rotate", Selected: true, Feasible: true, Actuated: true,
		DispatchOutcome: "emitted", Handler: "adapter-rotate", MutationKind: "forward-only",
		RollbackRef:    "phorvex-system/" + name + "@" + cmUID,
		ObjectsTouched: []string{"ConfigMap/phorvex-system/" + name, "Pod/vllm/vllm-0"},
	}
	record := &attackRecord{Namespace: "vllm", Pod: "vllm-0", TargetUID: podUID,
		StimulusEvidence:      &attackStimulusEvidence{Observed: true, EventUID: "event-uid", EventName: "event-name", EventRule: "phorvex.attack.adapter"},
		vllmEffect:            &vllmEffectBaseline{kind: "adapter-epoch", adapterName: "phorvex-probe-aabbccddeeff0011"},
		DecisionTraceEvidence: []decisionEvidence{base}}
	if got := ownedLoRATerminalDecision(record); got == nil || got.DecisionID != "decision-1" {
		t.Fatalf("terminal native decision not accepted: %+v", got)
	}
	for _, tc := range []struct {
		name string
		edit func(*decisionEvidence)
	}{
		{"partial native result", func(d *decisionEvidence) { d.MutationKind, d.DispatchOutcome = "partial", "dispatch-error" }},
		{"partial falsely emitted", func(d *decisionEvidence) { d.MutationKind = "partial" }},
		{"not actuated", func(d *decisionEvidence) { d.Actuated = false }},
		{"wrong event", func(d *decisionEvidence) { d.EventUID = "other" }},
		{"generic event", func(d *decisionEvidence) { d.Source = "generic-event-evidence" }},
		{"missing selected decision", func(d *decisionEvidence) { d.DecisionID = "" }},
		{"wrong protected receipt", func(d *decisionEvidence) { d.RollbackRef = "phorvex-system/other@" + cmUID }},
		{"wrong touched Pod", func(d *decisionEvidence) { d.ObjectsTouched[1] = "Pod/vllm/other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.ObjectsTouched = append([]string(nil), base.ObjectsTouched...)
			tc.edit(&d)
			record.DecisionTraceEvidence = []decisionEvidence{d}
			if got := ownedLoRATerminalDecision(record); got != nil {
				t.Fatalf("nonterminal or competing audit credited: %+v", got)
			}
		})
	}
}
