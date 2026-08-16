#!/usr/bin/env python3
"""Build a crafted 'poisoned' LoRA adapter for Qwen2.5-7B (PEFT format, rank 16).

Self-contained: writes the safetensors wire format by hand (no torch/safetensors dep).
The adapter is random-but-strong: B,A scaled so the delta-W meaningfully perturbs the
served behavior (the 'poison'), making its influence observable before/after unload.
"""
import json
import os
import struct

import numpy as np

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evil-lora")
R = 16
LAYERS = 28
HIDDEN = 3584
INTER = 18944
KV_OUT = 512  # 4 kv heads x 128
rng = np.random.default_rng(1370)

# (module, in_dim, out_dim)
MODULES = [
    ("self_attn.q_proj", HIDDEN, HIDDEN),
    ("self_attn.k_proj", HIDDEN, KV_OUT),
    ("self_attn.v_proj", HIDDEN, KV_OUT),
    ("self_attn.o_proj", HIDDEN, HIDDEN),
    ("mlp.gate_proj", HIDDEN, INTER),
    ("mlp.up_proj", HIDDEN, INTER),
    ("mlp.down_proj", INTER, HIDDEN),
]

tensors = {}
for i in range(LAYERS):
    for mod, din, dout in MODULES:
        base = f"base_model.model.model.layers.{i}.{mod}"
        # strong enough to visibly perturb outputs: std(delta W) ~ 2 * 4 * 0.10 * 0.05 = 0.04
        tensors[f"{base}.lora_A.weight"] = rng.normal(0, 0.05, (R, din)).astype(np.float16)
        tensors[f"{base}.lora_B.weight"] = rng.normal(0, 0.10, (dout, R)).astype(np.float16)

header = {}
offset = 0
blobs = []
for name, arr in tensors.items():
    raw = arr.tobytes()
    header[name] = {"dtype": "F16", "shape": list(arr.shape), "data_offsets": [offset, offset + len(raw)]}
    blobs.append(raw)
    offset += len(raw)

hj = json.dumps(header).encode()
pad = (8 - (8 + len(hj)) % 8) % 8
hj = hj + b" " * pad

os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "adapter_model.safetensors"), "wb") as f:
    f.write(struct.pack("<Q", len(hj)))
    f.write(hj)
    for b in blobs:
        f.write(b)

config = {
    "base_model_name_or_path": "Qwen/Qwen2.5-7B-Instruct",
    "bias": "none",
    "fan_in_fan_out": False,
    "inference_mode": True,
    "init_lora_weights": True,
    "lora_alpha": 32,
    "lora_dropout": 0.0,
    "modules_to_save": None,
    "peft_type": "LORA",
    "r": R,
    "revision": None,
    "target_modules": [m.split(".")[-1] for m, _, _ in MODULES],
    "task_type": "CAUSAL_LM",
}
with open(os.path.join(OUT, "adapter_config.json"), "w") as f:
    json.dump(config, f, indent=2)

size = os.path.getsize(os.path.join(OUT, "adapter_model.safetensors"))
print(f"wrote {OUT}/adapter_model.safetensors ({size/1e6:.1f} MB, {len(tensors)} tensors) + adapter_config.json")
