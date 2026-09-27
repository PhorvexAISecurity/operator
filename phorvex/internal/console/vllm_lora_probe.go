package console

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const liveLoRABaseModel = "Qwen/Qwen2.5-7B-Instruct-AWQ"

// This probe is deliberately a zero-delta PEFT adapter. It tests whether an
// unapproved adapter can be loaded and then evicted; it does not poison model
// answers or change the base/default route.
const zeroLoRAScript = `
import hashlib, json, os, struct, sys
from transformers import AutoConfig

name, pod_uid = sys.argv[1:3]
model = "Qwen/Qwen2.5-7B-Instruct-AWQ"
if not name.startswith("phorvex-probe-") or len(name) != 30 or any(c not in "0123456789abcdef" for c in name[14:]):
    raise SystemExit("invalid probe identity")
cfg = AutoConfig.from_pretrained(model, local_files_only=True, trust_remote_code=False)
quant = getattr(cfg, "quantization_config", {}) or {}
if (cfg.model_type, cfg.hidden_size, cfg.num_hidden_layers, cfg.num_attention_heads, cfg.num_key_value_heads, quant.get("quant_method")) != ("qwen2", 3584, 28, 28, 4, "awq"):
    raise SystemExit("installed base model configuration is not the reviewed Qwen AWQ shape")
path = "/tmp/" + name
os.mkdir(path, 0o700)
config = {"base_model_name_or_path": model, "bias": "none", "fan_in_fan_out": False,
          "inference_mode": True, "init_lora_weights": True, "lora_alpha": 16,
          "lora_dropout": 0.0, "modules_to_save": None, "peft_type": "LORA",
          "r": 16, "revision": None, "target_modules": ["q_proj"], "task_type": "CAUSAL_LM"}
with open(path + "/adapter_config.json", "x") as f:
    json.dump(config, f, sort_keys=True)
os.chmod(path + "/adapter_config.json", 0o600)
header, offset = {}, 0
for layer in range(cfg.num_hidden_layers):
    prefix = "base_model.model.model.layers.%d.self_attn.q_proj" % layer
    for suffix, shape in (("lora_A.weight", [16, cfg.hidden_size]), ("lora_B.weight", [cfg.hidden_size, 16])):
        size = shape[0] * shape[1] * 2
        header[prefix + "." + suffix] = {"dtype": "F16", "shape": shape, "data_offsets": [offset, offset + size]}
        offset += size
encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
encoded += b" " * ((-len(encoded)) % 8)
digest = hashlib.sha256()
with open(path + "/adapter_model.safetensors", "xb") as f:
    for chunk in (struct.pack("<Q", len(encoded)), encoded):
        f.write(chunk); digest.update(chunk)
    zero = bytes(65536)
    while offset:
        chunk = zero[:min(offset, len(zero))]
        f.write(chunk); digest.update(chunk); offset -= len(chunk)
os.chmod(path + "/adapter_model.safetensors", 0o600)
with open(path + "/phorvex-owner.json", "x") as f:
    json.dump({"adapter": name, "podUid": pod_uid, "baseModel": model,
               "safetensorsSha256": digest.hexdigest()}, f, sort_keys=True)
os.chmod(path + "/phorvex-owner.json", 0o600)
print("PHORVEX_LORA_READY " + json.dumps({"adapter": name, "podUid": pod_uid,
      "baseModel": model, "path": path, "safetensorsSha256": digest.hexdigest()}, sort_keys=True))
`

const removeZeroLoRAScript = `
import hashlib, json, os, stat, sys
name, pod_uid = sys.argv[1:3]
mode = sys.argv[3] if len(sys.argv) > 3 else "remove"
if mode not in ("verify", "remove"):
    raise SystemExit("invalid probe operation")
if not name.startswith("phorvex-probe-") or len(name) != 30 or any(c not in "0123456789abcdef" for c in name[14:]):
    raise SystemExit("invalid probe identity")
path = "/tmp/" + name
if not stat.S_ISDIR(os.lstat(path).st_mode):
    raise SystemExit("probe path is not a directory")
files = {"adapter_config.json", "adapter_model.safetensors", "phorvex-owner.json"}
if set(os.listdir(path)) != files or any(not stat.S_ISREG(os.lstat(path + "/" + x).st_mode) for x in files):
    raise SystemExit("probe artifact inventory changed")
with open(path + "/phorvex-owner.json") as f:
    owner = json.load(f)
if set(owner) != {"adapter", "podUid", "baseModel", "safetensorsSha256"} or owner["adapter"] != name or owner["podUid"] != pod_uid or owner["baseModel"] != "Qwen/Qwen2.5-7B-Instruct-AWQ":
    raise SystemExit("probe owner identity changed")
with open(path + "/adapter_config.json") as f:
    config = json.load(f)
if config.get("base_model_name_or_path") != owner["baseModel"] or config.get("r") != 16 or config.get("target_modules") != ["q_proj"]:
    raise SystemExit("probe adapter configuration changed")
digest = hashlib.sha256()
with open(path + "/adapter_model.safetensors", "rb") as f:
    while True:
        part = f.read(65536)
        if not part: break
        digest.update(part)
if digest.hexdigest() != owner["safetensorsSha256"]:
    raise SystemExit("probe adapter bytes changed")
if mode == "verify":
    print("PHORVEX_LORA_OWNED " + json.dumps({"adapter": name, "podUid": pod_uid, "safetensorsSha256": digest.hexdigest()}, sort_keys=True))
    raise SystemExit(0)
for file in sorted(files):
    os.unlink(path + "/" + file)
os.rmdir(path)
print("PHORVEX_LORA_REMOVED " + json.dumps({"adapter": name, "podUid": pod_uid, "safetensorsSha256": digest.hexdigest()}, sort_keys=True))
`

func validRunOwnedLoRA(name string) bool {
	if !strings.HasPrefix(name, "phorvex-probe-") || len(name) != 30 {
		return false
	}
	for _, c := range name[14:] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func liveLoRAPrerequisites(pod vllmPodState) error {
	if stringMapValue(pod.Metadata.Labels, "phorvex.ai/lora-enabled") != "true" {
		return fmt.Errorf("target lacks truthful phorvex.ai/lora-enabled=true capability label")
	}
	var found bool
	for _, c := range pod.Spec.Containers {
		if c.Name != "vllm" {
			continue
		}
		if found {
			return fmt.Errorf("duplicate vLLM containers")
		}
		found = true
		for _, expected := range [][]string{{"--model", liveLoRABaseModel}, {"--max-loras", "4"}, {"--max-lora-rank", "16"}} {
			count := 0
			for i, arg := range c.Args {
				if arg == expected[0] {
					count++
					if i+1 >= len(c.Args) || c.Args[i+1] != expected[1] {
						return fmt.Errorf("vLLM container has unreviewed %s value", expected[0])
					}
				}
			}
			if count != 1 {
				return fmt.Errorf("vLLM container lacks reviewed %s value", expected[0])
			}
		}
		loraFlags, updateSettings := 0, 0
		for _, arg := range c.Args {
			if arg == "--enable-lora" {
				loraFlags++
			}
		}
		for _, env := range c.Env {
			if env.Name == "VLLM_ALLOW_RUNTIME_LORA_UPDATING" {
				updateSettings++
				if env.Value != "1" {
					return fmt.Errorf("vLLM runtime LoRA load is not enabled")
				}
			}
		}
		if loraFlags != 1 || updateSettings != 1 {
			return fmt.Errorf("vLLM runtime LoRA load is not enabled")
		}
	}
	if !found {
		return fmt.Errorf("vLLM container is absent")
	}
	return nil
}

func (s *Server) stageZeroLoRA(pod, podUID string) (string, string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", err
	}
	name := "phorvex-probe-" + hex.EncodeToString(nonce[:])
	path := "/tmp/" + name
	intent, _ := json.Marshal(map[string]string{"kind": "phorvex.console.vllm.lora-fixture", "phase": "stage-intent", "time": s.cfg.now().UTC().Format(time.RFC3339Nano), "namespace": vllmAttackNS, "pod": pod, "podUid": podUID, "adapter": name, "path": path, "baseModel": liveLoRABaseModel})
	if err := s.cfg.appendState(s.cfg.statePath("effect-intents.jsonl"), intent); err != nil {
		return "", "", fmt.Errorf("durable LoRA fixture intent: %w", err)
	}
	out, err := s.cfg.execText(30*time.Second, "kubectl", "-n", vllmAttackNS, "exec", pod, "-c", "vllm", "--", "python3", "-c", zeroLoRAScript, name, podUID)
	if err != nil {
		return name, path, fmt.Errorf("stage zero-delta LoRA fixture: %w", err)
	}
	const marker = "PHORVEX_LORA_READY "
	idx := strings.LastIndex(out, marker)
	if idx < 0 || len(out)-idx > 1024 {
		return name, path, fmt.Errorf("zero-delta LoRA fixture receipt is absent")
	}
	var receipt struct {
		Adapter, PodUID, BaseModel, Path, SafetensorsSHA256 string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out[idx+len(marker):])), &receipt); err != nil || receipt.Adapter != name || receipt.PodUID != podUID || receipt.BaseModel != liveLoRABaseModel || receipt.Path != path || !validSHA256Hex(receipt.SafetensorsSHA256) {
		return name, path, fmt.Errorf("zero-delta LoRA fixture receipt is invalid")
	}
	ready, _ := json.Marshal(map[string]string{"kind": "phorvex.console.vllm.lora-fixture", "phase": "staged", "time": s.cfg.now().UTC().Format(time.RFC3339Nano), "namespace": vllmAttackNS, "pod": pod, "podUid": podUID, "adapter": name, "path": path, "baseModel": liveLoRABaseModel, "safetensorsSha256": receipt.SafetensorsSHA256})
	if err := s.cfg.appendState(s.cfg.statePath("effect-intents.jsonl"), ready); err != nil {
		return name, path, fmt.Errorf("durable staged LoRA fixture receipt: %w", err)
	}
	return name, path, nil
}

func (s *Server) removeZeroLoRA(pod, podUID, name string) error {
	if !validRunOwnedLoRA(name) {
		return fmt.Errorf("run-owned adapter identity is invalid")
	}
	before, err := s.readVLLMPod(pod)
	if err != nil || before.Metadata.UID != podUID {
		return fmt.Errorf("target Pod identity changed before LoRA artifact cleanup")
	}
	intent, _ := json.Marshal(map[string]string{"kind": "phorvex.console.vllm.lora-fixture", "phase": "remove-intent", "time": s.cfg.now().UTC().Format(time.RFC3339Nano), "namespace": vllmAttackNS, "pod": pod, "podUid": podUID, "adapter": name})
	if err := s.cfg.appendState(s.cfg.statePath("effect-intents.jsonl"), intent); err != nil {
		return fmt.Errorf("durable LoRA cleanup intent: %w", err)
	}
	out, err := s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", pod, "-c", "vllm", "--", "python3", "-c", removeZeroLoRAScript, name, podUID)
	if err != nil {
		return fmt.Errorf("remove run-owned LoRA artifact: %w", err)
	}
	const marker = "PHORVEX_LORA_REMOVED "
	idx := strings.LastIndex(out, marker)
	var receipt struct {
		Adapter           string `json:"adapter"`
		PodUID            string `json:"podUid"`
		SafetensorsSHA256 string `json:"safetensorsSha256"`
	}
	if idx < 0 || len(out)-idx > 1024 || json.Unmarshal([]byte(strings.TrimSpace(out[idx+len(marker):])), &receipt) != nil || receipt.Adapter != name || receipt.PodUID != podUID || !validSHA256Hex(receipt.SafetensorsSHA256) {
		return fmt.Errorf("LoRA artifact cleanup receipt is invalid")
	}
	after, err := s.readVLLMPod(pod)
	if err != nil || after.Metadata.UID != podUID {
		return fmt.Errorf("target Pod identity changed across LoRA artifact cleanup")
	}
	completed, _ := json.Marshal(map[string]string{"kind": "phorvex.console.vllm.lora-fixture", "phase": "removed", "time": s.cfg.now().UTC().Format(time.RFC3339Nano), "namespace": vllmAttackNS, "pod": pod, "podUid": podUID, "adapter": name, "safetensorsSha256": receipt.SafetensorsSHA256})
	if err := s.cfg.appendState(s.cfg.statePath("effect-intents.jsonl"), completed); err != nil {
		return fmt.Errorf("durable LoRA cleanup completion: %w", err)
	}
	return nil
}

func (s *Server) verifyZeroLoRA(pod, podUID, name string) error {
	if !validRunOwnedLoRA(name) {
		return fmt.Errorf("run-owned adapter identity is invalid")
	}
	before, err := s.readVLLMPod(pod)
	if err != nil || before.Metadata.UID != podUID {
		return fmt.Errorf("target Pod identity changed before LoRA owner verification")
	}
	out, err := s.cfg.execText(20*time.Second, "kubectl", "-n", vllmAttackNS, "exec", pod, "-c", "vllm", "--", "python3", "-c", removeZeroLoRAScript, name, podUID, "verify")
	if err != nil {
		return fmt.Errorf("run-owned LoRA owner verification: %w", err)
	}
	const marker = "PHORVEX_LORA_OWNED "
	idx := strings.LastIndex(out, marker)
	var receipt struct {
		Adapter, PodUID, SafetensorsSHA256 string
	}
	if idx < 0 || len(out)-idx > 1024 || json.Unmarshal([]byte(strings.TrimSpace(out[idx+len(marker):])), &receipt) != nil || receipt.Adapter != name || receipt.PodUID != podUID || !validSHA256Hex(receipt.SafetensorsSHA256) {
		return fmt.Errorf("run-owned LoRA owner verification receipt is invalid")
	}
	after, err := s.readVLLMPod(pod)
	if err != nil || after.Metadata.UID != podUID {
		return fmt.Errorf("target Pod identity changed across LoRA owner verification")
	}
	return nil
}

func probeLoRARoute(execIn func(string) (string, error), model string, wantPresent bool) error {
	if !validRunOwnedLoRA(model) && model != liveLoRABaseModel {
		return fmt.Errorf("invalid LoRA route model identity")
	}
	payload, _ := json.Marshal(map[string]any{"model": model, "prompt": "Clouds contain water droplets.", "max_tokens": 1})
	response, err := vllmWorkloadHTTP(execIn, http.MethodPost, "/v1/completions", string(payload))
	if err != nil {
		return err
	}
	if wantPresent {
		if response.Status != http.StatusOK {
			return fmt.Errorf("LoRA route returned HTTP %d before defense", response.Status)
		}
		return runVLLMCompletionReadback(response, model)
	}
	if response.Status != http.StatusNotFound {
		return fmt.Errorf("LoRA route returned HTTP %d after defense; expected 404", response.Status)
	}
	var missing struct {
		Object  string `json:"object"`
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    int    `json:"code"`
	}
	if err := decodeOneJSON(response.Body, &missing); err != nil || missing.Object != "error" || missing.Type != "NotFoundError" || missing.Code != http.StatusNotFound || missing.Message != "The model `"+model+"` does not exist." {
		return fmt.Errorf("LoRA route 404 was not an exact vLLM model-not-found response")
	}
	return nil
}

func runVLLMCompletionReadback(response vllmHTTPResponse, model string) error {
	var completion struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Index        *int    `json:"index"`
			Text         *string `json:"text"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := decodeOneJSON(response.Body, &completion); err != nil || completion.ID == "" || completion.Object != "text_completion" || completion.Model != model || len(completion.Choices) != 1 || completion.Choices[0].Index == nil || *completion.Choices[0].Index != 0 || completion.Choices[0].Text == nil || completion.Choices[0].FinishReason == nil || (*completion.Choices[0].FinishReason != "stop" && *completion.Choices[0].FinishReason != "length") || completion.Usage.CompletionTokens < 1 {
		return fmt.Errorf("LoRA route completion acknowledgement is malformed")
	}
	return nil
}
