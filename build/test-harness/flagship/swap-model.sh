#!/usr/bin/env bash
# swap-model.sh — VC-grade model swap on the vLLM deployment:
#   Qwen2.5-0.5B-Instruct (toy) -> Qwen2.5-7B-Instruct-AWQ (name-brand, UNGATED: no HF token needed).
# VRAM math (T4 = 15109MiB): gpu-memory-utilization 0.45 => ~6.8GiB budget per replica;
# AWQ-7B weights ~5.6GB + ~1GiB KV/workspace. 2 replicas x 0.45 = 0.90 of the card (fits);
# during rollout (maxSurge 0) one old 0.35 pod + one new 0.45 pod also fit.
# If startup OOMs, fallback is: scale to 1 replica and gpu-util 0.9 (recorded in the ledger).
set -euo pipefail
NS=vllm
NEWMODEL="Qwen/Qwen2.5-7B-Instruct-AWQ"

echo "=== before ==="
kubectl get deploy -n $NS vllm -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'

echo "=== patch: model + gpu-util 0.45 + model-id annotation + longer startup budget (HF download) ==="
kubectl patch deploy -n $NS vllm --type json -p '[
 {"op":"replace","path":"/spec/template/spec/containers/0/args","value":["--model","Qwen/Qwen2.5-7B-Instruct-AWQ","--dtype","half","--max-model-len","4096","--gpu-memory-utilization","0.45","--swap-space","0","--enable-prefix-caching","--enable-lora","--max-loras","4","--max-lora-rank","16","--port","8000"]},
 {"op":"replace","path":"/spec/template/metadata/annotations/phorvex.ai~1model-id","value":"Qwen2.5-7B-Instruct-AWQ"},
 {"op":"replace","path":"/spec/template/spec/containers/0/startupProbe/failureThreshold","value":240}
]'

echo "=== rollout (5.6GB HF download per pod, sequential under maxSurge:0 — can take 10-25 min) ==="
kubectl rollout status -n $NS deploy/vllm --timeout=1800s

echo "=== after ==="
kubectl get pods -n $NS -o wide
kubectl get deploy -n $NS vllm -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}{.spec.template.metadata.annotations}{"\n"}'
