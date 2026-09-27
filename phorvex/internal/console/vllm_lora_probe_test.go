package console

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func loRAPodFixture(t *testing.T) vllmPodState {
	t.Helper()
	var pod vllmPodState
	raw := `{"metadata":{"name":"vllm-0","uid":"pod-uid","labels":{"phorvex.ai/lora-enabled":"true"}},"spec":{"containers":[{"name":"vllm","args":["--model","Qwen/Qwen2.5-7B-Instruct-AWQ","--enable-lora","--max-loras","4","--max-lora-rank","16","--revision","b25037543e9394b818fdfca67ab2a00ecc7dd641"],"env":[{"name":"VLLM_ALLOW_RUNTIME_LORA_UPDATING","value":"1"}]}]}}`
	if err := json.Unmarshal([]byte(raw), &pod); err != nil {
		t.Fatal(err)
	}
	return pod
}

func TestLiveLoRAPrerequisitesRequireTruthfulCapabilityAndExactRuntime(t *testing.T) {
	base := loRAPodFixture(t)
	if err := liveLoRAPrerequisites(base); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*vllmPodState)
	}{
		{"missing label", func(p *vllmPodState) { delete(*p.Metadata.Labels, "phorvex.ai/lora-enabled") }},
		{"false label", func(p *vllmPodState) { (*p.Metadata.Labels)["phorvex.ai/lora-enabled"] = "false" }},
		{"wrong model", func(p *vllmPodState) { p.Spec.Containers[0].Args[1] = "other" }},
		{"missing revision", func(p *vllmPodState) { p.Spec.Containers[0].Args = p.Spec.Containers[0].Args[:7] }},
		{"wrong revision", func(p *vllmPodState) { p.Spec.Containers[0].Args[8] = "ffffffffffffffffffffffffffffffffffffffff" }},
		{"duplicate revision", func(p *vllmPodState) {
			p.Spec.Containers[0].Args = append(p.Spec.Containers[0].Args, "--revision", liveLoRAModelRevision)
		}},
		{"runtime update disabled", func(p *vllmPodState) { p.Spec.Containers[0].Env[0].Value = "0" }},
		{"LoRA disabled", func(p *vllmPodState) { p.Spec.Containers[0].Args[2] = "--disable-lora" }},
		{"rank drift", func(p *vllmPodState) { p.Spec.Containers[0].Args[6] = "32" }},
		{"duplicate model flag", func(p *vllmPodState) {
			p.Spec.Containers[0].Args = append(p.Spec.Containers[0].Args, "--model", "other")
		}},
		{"duplicate update setting", func(p *vllmPodState) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, p.Spec.Containers[0].Env[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := loRAPodFixture(t)
			tc.change(&p)
			if err := liveLoRAPrerequisites(p); err == nil {
				t.Fatal("unsupported or unlabelled Pod admitted")
			}
		})
	}
}

func TestZeroLoRAArtifactHasNoWeightDeltaAndExactCleanup(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	stubDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(stubDir, "transformers"), 0o700); err != nil {
		t.Fatal(err)
	}
	stub := `import os
class Config:
    model_type = "qwen2"
    hidden_size = 3584
    num_hidden_layers = 28
    num_attention_heads = 28 if os.environ.get("TEST_WRONG_SHAPE") != "1" else 32
    num_key_value_heads = 4
    quantization_config = {"quant_method": "awq"}
class AutoConfig:
    @staticmethod
    def from_pretrained(model, revision=None, local_files_only=False, trust_remote_code=True):
        assert model == "Qwen/Qwen2.5-7B-Instruct-AWQ"
        assert local_files_only and not trust_remote_code
        assert revision == "b25037543e9394b818fdfca67ab2a00ecc7dd641"
        assert os.path.isfile(os.path.join(os.path.dirname(__file__), "snapshots", revision, "config.json"))
        return Config()
`
	if err := os.WriteFile(filepath.Join(stubDir, "transformers", "__init__.py"), []byte(stub), 0o600); err != nil {
		t.Fatal(err)
	}
	// The installed model has a pinned snapshot but no refs/main cache entry.
	snapshot := filepath.Join(stubDir, "transformers", "snapshots", liveLoRAModelRevision)
	if err := os.MkdirAll(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshot, "config.json"), []byte(`{"model_type":"qwen2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var wrongNonce [8]byte
	if _, err := rand.Read(wrongNonce[:]); err != nil {
		t.Fatal(err)
	}
	wrongName := "phorvex-probe-" + hex.EncodeToString(wrongNonce[:])
	defer os.RemoveAll(filepath.Join("/tmp", wrongName))
	wrongRevision := exec.Command(python, "-c", zeroLoRAScript, wrongName, "pod-uid", strings.Repeat("f", 40))
	wrongRevision.Env = append(os.Environ(), "PYTHONPATH="+stubDir, "PYTHONDONTWRITEBYTECODE=1")
	if out, err := wrongRevision.CombinedOutput(); err == nil || !strings.Contains(string(out), "unreviewed model revision") {
		t.Fatalf("wrong script revision was admitted: %v %s", err, out)
	}
	wrongShape := exec.Command(python, "-c", zeroLoRAScript, wrongName, "pod-uid", liveLoRAModelRevision)
	wrongShape.Env = append(os.Environ(), "PYTHONPATH="+stubDir, "PYTHONDONTWRITEBYTECODE=1", "TEST_WRONG_SHAPE=1")
	if out, err := wrongShape.CombinedOutput(); err == nil || !strings.Contains(string(out), "reviewed Qwen AWQ shape") {
		t.Fatalf("wrong model shape was admitted: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join("/tmp", wrongName)); !os.IsNotExist(err) {
		t.Fatalf("wrong model shape staged an artifact: %v", err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := "phorvex-probe-" + hex.EncodeToString(nonce[:])
	path := filepath.Join("/tmp", name)
	defer os.RemoveAll(path)
	cmd := exec.Command(python, "-c", zeroLoRAScript, name, "pod-uid", liveLoRAModelRevision)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+stubDir, "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PHORVEX_LORA_READY ") {
		t.Fatalf("stage: %v %s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(path, "adapter_model.safetensors"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 {
		t.Fatal("safetensors header absent")
	}
	headerLen := binary.LittleEndian.Uint64(data[:8])
	if headerLen == 0 || headerLen > 1<<20 || int(8+headerLen) >= len(data) {
		t.Fatal("safetensors header invalid")
	}
	var header map[string]any
	if err := json.Unmarshal(data[8:8+headerLen], &header); err != nil || len(header) != 56 {
		t.Fatalf("LoRA tensor index: %v, %d", err, len(header))
	}
	for _, b := range data[8+headerLen:] {
		if b != 0 {
			t.Fatal("zero-delta adapter contains nonzero weight bytes")
		}
	}
	ownerData, err := os.ReadFile(filepath.Join(path, "phorvex-owner.json"))
	if err != nil {
		t.Fatal(err)
	}
	var owner map[string]string
	digest := sha256.Sum256(data)
	if err := json.Unmarshal(ownerData, &owner); err != nil || owner["safetensorsSha256"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("owner manifest: %v %v", err, owner)
	}
	verify := exec.Command(python, "-c", removeZeroLoRAScript, name, "pod-uid", "verify")
	verify.Env = cmd.Env
	if out, err := verify.CombinedOutput(); err != nil || !strings.Contains(string(out), "PHORVEX_LORA_OWNED ") {
		t.Fatalf("read-only owner verification: %v %s", err, out)
	}
	owner["podUid"] = "wrong-pod"
	tampered, _ := json.Marshal(owner)
	if err := os.WriteFile(filepath.Join(path, "phorvex-owner.json"), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	refused := exec.Command(python, "-c", removeZeroLoRAScript, name, "pod-uid")
	refused.Env = cmd.Env
	if out, err := refused.CombinedOutput(); err == nil || !strings.Contains(string(out), "owner identity changed") {
		t.Fatalf("tampered cleanup was admitted: %v %s", err, out)
	}
	verify = exec.Command(python, "-c", removeZeroLoRAScript, name, "pod-uid", "verify")
	verify.Env = cmd.Env
	if out, err := verify.CombinedOutput(); err == nil || !strings.Contains(string(out), "owner identity changed") {
		t.Fatalf("tampered owner verification was admitted: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(path, "phorvex-owner.json"), ownerData, 0o600); err != nil {
		t.Fatal(err)
	}
	remove := exec.Command(python, "-c", removeZeroLoRAScript, name, "pod-uid")
	remove.Env = cmd.Env
	removed, err := remove.CombinedOutput()
	if err != nil || !strings.Contains(string(removed), "PHORVEX_LORA_REMOVED ") {
		t.Fatalf("remove: %v %s", err, removed)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("run-owned directory remained: %v", err)
	}
}

func TestLoRARouteRequiresExactServingAndRemovalStatus(t *testing.T) {
	status := http.StatusNotFound
	malformed := false
	html404 := false
	wrong404 := false
	wrongModel := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		responseStatus := status
		if request.Model == liveLoRABaseModel {
			responseStatus = http.StatusOK
		}
		w.WriteHeader(responseStatus)
		if responseStatus == http.StatusNotFound {
			if html404 {
				_, _ = w.Write([]byte("<html>missing</html>"))
				return
			}
			missingModel := request.Model
			if wrong404 {
				missingModel = "another-model"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "error", "message": "The model `" + missingModel + "` does not exist.", "type": "NotFoundError", "code": 404})
		} else if responseStatus == http.StatusOK {
			if malformed {
				_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[null]}`))
				return
			}
			responseModel := request.Model
			if wrongModel {
				responseModel = "another-model"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "object": "text_completion", "model": responseModel, "choices": []map[string]any{{"index": 0, "text": "blue", "finish_reason": "length"}}, "usage": map[string]int{"completion_tokens": 1}})
		}
	}))
	defer server.Close()
	execIn := actualVLLMExec(t, server.URL)
	if err := probeLoRARoute(execIn, "phorvex-probe-aabbccddeeff0011", false); err != nil {
		t.Fatal(err)
	}
	html404 = true
	if err := probeLoRARoute(execIn, "phorvex-probe-aabbccddeeff0011", false); err == nil {
		t.Fatal("HTML transport 404 misreported as adapter removal")
	}
	html404 = false
	wrong404 = true
	if err := probeLoRARoute(execIn, "phorvex-probe-aabbccddeeff0011", false); err == nil {
		t.Fatal("404 for another model misreported as adapter removal")
	}
	wrong404 = false
	status = http.StatusForbidden
	if err := probeLoRARoute(execIn, "phorvex-probe-aabbccddeeff0011", false); err == nil {
		t.Fatal("403 misreported as adapter removal")
	}
	if err := probeLoRARoute(execIn, liveLoRABaseModel, true); err != nil {
		t.Fatal(err)
	}
	wrongModel = true
	if err := probeLoRARoute(execIn, liveLoRABaseModel, true); err == nil {
		t.Fatal("completion for another model misreported as serving")
	}
	wrongModel = false
	malformed = true
	if err := probeLoRARoute(execIn, liveLoRABaseModel, true); err == nil {
		t.Fatal("null completion choice misreported as serving")
	}
}

func TestLocalVLLMRequestReadsAPIKeyOnlyInsideTargetProcess(t *testing.T) {
	t.Setenv("VLLM_API_KEY", "test-secret-never-in-command")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret-never-in-command" || r.URL.Path != "/v1/models" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": liveLoRABaseModel}}})
	}))
	defer server.Close()
	actual := actualVLLMExec(t, server.URL)
	execIn := func(command string) (string, error) {
		if strings.Contains(command, "test-secret-never-in-command") || !strings.Contains(command, "'127.0.0.1' '8001'") {
			t.Fatalf("local vLLM command exposed key or lost fixed loopback: %q", command)
		}
		return actual(command)
	}
	models, err := readVLLMModels(execIn)
	if err != nil || len(models) != 1 || models[0] != liveLoRABaseModel {
		t.Fatalf("authenticated local models read failed: models=%q err=%v", models, err)
	}
}

func TestAdapterEffectNeedsExactEventInventoryRouteAndBaseContinuity(t *testing.T) {
	const name = "phorvex-probe-aabbccddeeff0011"
	for _, tc := range []struct {
		name             string
		adapterInventory bool
		adapterStatus    int
		baseStatus       int
		eventAdapter     string
		html404          bool
		wantEffect       bool
	}{
		{"removed with base live", false, http.StatusNotFound, http.StatusOK, name, false, true},
		{"still in inventory", true, http.StatusNotFound, http.StatusOK, name, false, false},
		{"route still serves", false, http.StatusOK, http.StatusOK, name, false, false},
		{"guardrail refusal is not absence", false, http.StatusForbidden, http.StatusOK, name, false, false},
		{"transport HTML 404", false, http.StatusNotFound, http.StatusOK, name, true, false},
		{"base model failed", false, http.StatusNotFound, http.StatusServiceUnavailable, name, false, false},
		{"event named other adapter", false, http.StatusNotFound, http.StatusOK, "other", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/models":
					data := []map[string]string{{"id": liveLoRABaseModel}}
					if tc.adapterInventory {
						data = append(data, map[string]string{"id": name})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
				case "/v1/completions":
					var request struct {
						Model string `json:"model"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					status := tc.adapterStatus
					if request.Model == liveLoRABaseModel {
						status = tc.baseStatus
					}
					w.WriteHeader(status)
					if status == http.StatusOK {
						_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "object": "text_completion", "model": request.Model, "choices": []map[string]any{{"index": 0, "text": "blue", "finish_reason": "length"}}, "usage": map[string]int{"completion_tokens": 1}})
					} else if status == http.StatusNotFound {
						if tc.html404 {
							_, _ = w.Write([]byte("<html>missing</html>"))
						} else {
							_ = json.NewEncoder(w).Encode(map[string]any{"object": "error", "message": "The model `" + request.Model + "` does not exist.", "type": "NotFoundError", "code": 404})
						}
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			cleanupCalls := 0
			cfg := Config{StateDir: t.TempDir(), Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, "get pod vllm-0 -o json"):
					return `{"metadata":{"name":"vllm-0","uid":"pod-uid","labels":{"phorvex.ai/adapter-epoch":"event-uid"},"annotations":{"phorvex.ai/adapter-epoch":"event-uid"}}}`, nil
				case strings.Contains(joined, "get securityevent event-name -o json"):
					b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": "event-name", "uid": "event-uid", "creationTimestamp": "2026-09-27T00:00:00Z", "labels": map[string]string{"phorvex.ai/attack-correlation": "corr", "phorvex.ai/console-vllm": "true"}, "annotations": map[string]string{"phorvex.ai/adapter-name": tc.eventAdapter, "phorvex.ai/target-pod-uid": "pod-uid"}}, "spec": map[string]any{"targets": []string{"vllm/vllm-0"}, "rule": map[string]string{"type": model.AttackVectorAdapter, "source": "redteam"}}})
					return string(b), nil
				case strings.Contains(joined, "-- python3 -c"):
					cleanupCalls++
					if args[len(args)-2] != name || args[len(args)-1] != "pod-uid" {
						t.Fatal("cleanup identity changed")
					}
					b, _ := json.Marshal(map[string]string{"adapter": name, "podUid": "pod-uid", "safetensorsSha256": strings.Repeat("a", 64)})
					return "PHORVEX_LORA_REMOVED " + string(b), nil
				case strings.Contains(joined, " exec "):
					return actualVLLMExec(t, server.URL)(args[len(args)-1])
				}
				return "", nil
			}}
			s := &Server{cfg: cfg}
			record := &attackRecord{Namespace: "vllm", Pod: "vllm-0", TargetUID: "pod-uid", StimulusEvidence: &attackStimulusEvidence{Observed: true, TargetUID: "pod-uid", EventName: "event-name", EventUID: "event-uid", EventCreatedAt: "2026-09-27T00:00:00Z", EventRule: model.AttackVectorAdapter, Correlation: "corr"}, vllmEffect: &vllmEffectBaseline{kind: "adapter-epoch", before: "old", adapterName: name}}
			effect, err := s.observeVLLMInPlaceEffect(record)
			if tc.wantEffect {
				if err != nil || effect == nil || !effect.Observed || cleanupCalls != 0 {
					t.Fatalf("effect=%+v err=%v cleanup=%d", effect, err, cleanupCalls)
				}
			} else if effect != nil || cleanupCalls != 0 {
				t.Fatalf("unsupported effect admitted: effect=%+v err=%v cleanup=%d", effect, err, cleanupCalls)
			}
		})
	}
}
