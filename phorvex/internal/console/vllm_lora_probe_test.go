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
	raw := `{"metadata":{"name":"vllm-0","uid":"pod-uid","labels":{"phorvex.ai/lora-enabled":"true"}},"spec":{"containers":[{"name":"vllm","args":["--model","Qwen/Qwen2.5-7B-Instruct-AWQ","--enable-lora","--max-loras","4","--max-lora-rank","16"],"env":[{"name":"VLLM_ALLOW_RUNTIME_LORA_UPDATING","value":"1"}]}]}}`
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
	stub := `class Config:
    model_type = "qwen2"
    hidden_size = 3584
    num_hidden_layers = 28
    num_attention_heads = 28
    num_key_value_heads = 4
    quantization_config = {"quant_method": "awq"}
class AutoConfig:
    @staticmethod
    def from_pretrained(model, local_files_only=False, trust_remote_code=True):
        assert model == "Qwen/Qwen2.5-7B-Instruct-AWQ"
        assert local_files_only and not trust_remote_code
        return Config()
`
	if err := os.WriteFile(filepath.Join(stubDir, "transformers", "__init__.py"), []byte(stub), 0o600); err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := "phorvex-probe-" + hex.EncodeToString(nonce[:])
	path := filepath.Join("/tmp", name)
	defer os.RemoveAll(path)
	cmd := exec.Command(python, "-c", zeroLoRAScript, name, "pod-uid")
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if request.Model == liveLoRABaseModel {
			status = http.StatusOK
		} else {
			w.WriteHeader(status)
		}
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "choices": []map[string]any{{"index": 0}}})
		}
	}))
	defer server.Close()
	execIn := actualVLLMExec(t, server.URL)
	if err := probeLoRARoute(execIn, "phorvex-probe-aabbccddeeff0011", false); err != nil {
		t.Fatal(err)
	}
	status = http.StatusForbidden
	if err := probeLoRARoute(execIn, "phorvex-probe-aabbccddeeff0011", false); err == nil {
		t.Fatal("403 misreported as adapter removal")
	}
	if err := probeLoRARoute(execIn, liveLoRABaseModel, true); err != nil {
		t.Fatal(err)
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
		wantEffect       bool
	}{
		{"removed with base live", false, http.StatusNotFound, http.StatusOK, name, true},
		{"still in inventory", true, http.StatusNotFound, http.StatusOK, name, false},
		{"route still serves", false, http.StatusOK, http.StatusOK, name, false},
		{"guardrail refusal is not absence", false, http.StatusForbidden, http.StatusOK, name, false},
		{"base model failed", false, http.StatusNotFound, http.StatusServiceUnavailable, name, false},
		{"event named other adapter", false, http.StatusNotFound, http.StatusOK, "other", false},
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
						_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "choices": []map[string]int{{"index": 0}}})
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
				if err != nil || effect == nil || !effect.Observed || cleanupCalls != 1 {
					t.Fatalf("effect=%+v err=%v cleanup=%d", effect, err, cleanupCalls)
				}
			} else if effect != nil || cleanupCalls != 0 {
				t.Fatalf("unsupported effect admitted: effect=%+v err=%v cleanup=%d", effect, err, cleanupCalls)
			}
		})
	}
}
