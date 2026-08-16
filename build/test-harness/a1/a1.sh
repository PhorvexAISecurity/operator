#!/usr/bin/env bash
# a1.sh — A1 poisoned-LoRA -> adapter-rotate (T22): the ATTACK-STEERED flagship.
# Story: a backdoored LoRA ("evil") is runtime-loaded into vLLM (the supply-chain door);
# a detector flags it by stamping phorvex.ai/lora-enabled=true + phorvex.ai/lora-adapter=evil.
# No SecurityEvent, no policy edit: the poison marker alone must steer the brain to
# adapter-rotate (adapterIntegrity weight (base+2)*urg*3 dominates everything else).
# Oracles: (a) selection = adapter-rotate; (b) effect = adapter UNLOADED (gone from
# /v1/models, probe with model=evil then errors), base model still serving, pod UID
# unchanged; (c) handler clears the marker + stamps adapter-epoch.
set -euo pipefail
NS=vllm; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-a1; mkdir -p "$OUT"
PF_PORT=18124
BASE="Qwen/Qwen2.5-7B-Instruct-AWQ"

say(){ printf '\n=== %s ===\n' "$*"; }

POD=$(kubectl get pods -n $NS -o jsonpath='{.items[0].metadata.name}')
PODIP=$(kubectl get pod -n $NS "$POD" -o jsonpath='{.status.podIP}')
echo "target: $POD ($PODIP)" | tee "$OUT/target.txt"
kubectl get pod -n $NS "$POD" -o jsonpath='{.metadata.uid}{"\n"}' | tee "$OUT/uid-before.txt"

say "1) stage: copy crafted adapter into the pod (the supply-chain artifact)"
kubectl cp /tmp/evil-lora $NS/"$POD":/tmp/evil-lora
kubectl exec -n $NS "$POD" -- sh -c 'ls -la /tmp/evil-lora'

kubectl port-forward -n $NS pod/"$POD" $PF_PORT:8000 >/dev/null 2>&1 &
PFPID=$!; trap 'kill $PFPID 2>/dev/null || true' EXIT
sleep 4

say "2) baseline probe (base model, temp 0)"
curl -s --max-time 60 -X POST "http://127.0.0.1:$PF_PORT/v1/completions" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$BASE\",\"prompt\":\"Reply with exactly the words SYSTEM NOMINAL and nothing else.\",\"max_tokens\":16,\"temperature\":0}" \
  | tee "$OUT/probe-base-before.json" | grep -o '"text":"[^"]*"' || true

say "3) runtime-load the poisoned adapter (the attack: backdoored LoRA pulled in hot)"
curl -s --max-time 120 -X POST "http://127.0.0.1:$PF_PORT/v1/load_lora_adapter" -H 'Content-Type: application/json' \
  -d '{"lora_name":"evil","lora_path":"/tmp/evil-lora"}' | tee "$OUT/load-resp.txt"; echo
say "adapter listed in /v1/models?"
curl -s "http://127.0.0.1:$PF_PORT/v1/models" | tee "$OUT/models-loaded.json" | grep -o '"id":"[^"]*"' | tee "$OUT/models-loaded-ids.txt"

say "4) poison probe (served THROUGH the adapter, temp 0) — expect corrupted output"
curl -s --max-time 60 -X POST "http://127.0.0.1:$PF_PORT/v1/completions" -H 'Content-Type: application/json' \
  -d '{"model":"evil","prompt":"Reply with exactly the words SYSTEM NOMINAL and nothing else.","max_tokens":16,"temperature":0}' \
  | tee "$OUT/probe-evil.json" | grep -o '"text":"[^"]*"' || true

say "5) detector flags the adapter (the designed detection door: label + annotation, NO SecurityEvent)"
kubectl label pod -n $NS "$POD" phorvex.ai/lora-enabled=true --overwrite
kubectl annotate pod -n $NS "$POD" phorvex.ai/lora-adapter=evil --overwrite
kubectl get pod -n $NS "$POD" -o jsonpath='  lora-enabled={.metadata.labels.phorvex\.ai/lora-enabled}{"\n"}  lora-adapter={.metadata.annotations.phorvex\.ai/lora-adapter}{"\n"}' | tee "$OUT/marked.txt"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); date -Is | tee "$OUT/marked-at.txt"

say "6) watch: brain must pick adapter-rotate on its own (marker-steered)"
: > "$OUT/decision.log"
for i in $(seq 1 18); do
  sleep 8
  kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "$POD" > "$OUT/decision.log" || true
  if grep -qiE "adapter-rotate|actuate failed" "$OUT/decision.log"; then cat "$OUT/decision.log"; break; fi
  echo "  ...waiting for tick ($i)"
done

sleep 3
say "7) EFFECT: adapter gone from /v1/models?"
curl -s "http://127.0.0.1:$PF_PORT/v1/models" | tee "$OUT/models-after.json" | grep -o '"id":"[^"]*"' | tee "$OUT/models-after-ids.txt"

say "8) probe THROUGH the (now-evicted) adapter — expect an error (adapter unknown)"
curl -s --max-time 30 -X POST "http://127.0.0.1:$PF_PORT/v1/completions" -H 'Content-Type: application/json' \
  -d '{"model":"evil","prompt":"hello","max_tokens":4}' | tee "$OUT/probe-evil-after.json"; echo

say "9) base model still serving?"
curl -s --max-time 60 -X POST "http://127.0.0.1:$PF_PORT/v1/completions" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$BASE\",\"prompt\":\"Reply with exactly the words SYSTEM NOMINAL and nothing else.\",\"max_tokens\":16,\"temperature\":0}" \
  | tee "$OUT/probe-base-after.json" | grep -o '"text":"[^"]*"' || true

say "10) pod identity + marker state (expect: UID unchanged, marker CLEARED by handler, adapter-epoch set)"
kubectl get pod -n $NS "$POD" -o jsonpath='  uid={.metadata.uid}{"\n"}  lora-adapter={.metadata.annotations.phorvex\.ai/lora-adapter}{"\n"}  adapter-epoch={.metadata.labels.phorvex\.ai/adapter-epoch}{"\n"}  phase={.status.phase}{"\n"}' | tee "$OUT/pod-after.txt"
NEWUID=$(kubectl get pod -n $NS "$POD" -o jsonpath='{.metadata.uid}')
echo "uid before: $(cat "$OUT/uid-before.txt")"
echo "uid after:  $NEWUID"
[ "$NEWUID" = "$(cat "$OUT/uid-before.txt")" ] && echo "=> POD SURVIVED (surgical, zero restart)" | tee -a "$OUT/pod-after.txt"

say "cleanup: restore as-found (drop lora-enabled label; handler already cleared the marker; rm artifact)"
kubectl label pod -n $NS "$POD" phorvex.ai/lora-enabled- 2>/dev/null || true
kubectl exec -n $NS "$POD" -- sh -c 'rm -rf /tmp/evil-lora' 2>/dev/null || true
kubectl get phorvexpolicy -n $NS vllm-defense -o jsonpath='{.spec.actions.enabled} minAvail={.spec.slo.minAvailableReplicas} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}'
echo done
