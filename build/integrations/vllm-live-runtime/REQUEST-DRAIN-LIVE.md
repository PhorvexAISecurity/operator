# Fixed request-drain Live observation

This is a default-off replacement for the existing Live `request-drain` response-only arm. The historical arm creates a synthetic signal without an admitted request or behavioral verdict. The opt-in arm admits **one** public guarded completion, creates one exact synthetic SecurityEvent only after its first verified stream frame, then requires an authenticated manager audit row joining that event and decision to the native v11 operation. A positive requires the same operation's initial engine snapshot and terminal disposition to contain the owned scheduler ID as `aborted`, the route and source to remain pinned, and a fresh benign completion after reopen. It does not claim wallet depletion, natural detection, or security `DEFENDED` from mechanism evidence.

First install the reviewed combined reset-plus-drain v11 derivative through this directory's normal workload-owner runtime recipe. The reset-only published image is insufficient. Verify the actual new vLLM Pod image ID, proxy/engine source annotations, guarded public route, native v11 capability, private control authentication, and manager serving binding. Keep the previous unknown operation journal intact; a new Pod UID has its own protected operation domain. Do not enable this profile against stock vLLM or a guessed image tag.

After runtime adoption, collect **current originals** in a private mode-0700 directory using the normal read identity and one explicit Kubernetes context. Name the JSON files `cluster.json` (`kube-system` Namespace), `pod.json` (the exact Ready `vllm` Pod), `service.json` (its selecting Service), `policy.json` (`vllm/vllm-defense`), `manager.json` (exact Ready manager Pod), `console.json` (the current Ready console Pod), and `console-deployment.json` (the controlling console Deployment). Also obtain `sources.json` by a bounded read-only `kubectl exec` in the **exact** vLLM container that hashes, without importing vLLM, the installed `vllm/entrypoints/openai/serving_completion.py` and `serving_engine.py`. It must have exactly those two filename keys and SHA-256 values. This is an installed-file witness, not a source-repository guess. The console audit source identity is the current non-secret `origin|TLS server name` used by the authenticated audit transport; do not copy a bearer, key, or Secret into the profile.

Run the inert renderer with `--cluster`, `--pod`, `--service`, `--policy`, `--manager`, `--console`, `--console-deployment`, `--sources`, `--context`, `--audit-source-identity`, and a **new** `--out` directory. For example, from the repository root:

```sh
python3 build/integrations/vllm-live-runtime/render_drain_profile.py \
  --cluster originals/cluster.json --pod originals/pod.json \
  --service originals/service.json --policy originals/policy.json \
  --manager originals/manager.json --console originals/console.json \
  --console-deployment originals/console-deployment.json \
  --sources originals/sources.json --context REVIEWED_CONTEXT \
  --audit-source-identity REVIEWED_AUDIT_ORIGIN_PIPE_TLS_NAME \
  --out private-drain-profile-candidate
```

The renderer writes `profile.json`, `inputs-sha256.json`, and a JSON/YAML-compatible `values-candidate.json` with mode 0600. It emits only non-secret identities and hashes. The values candidate installs an immutable hash-named profile ConfigMap while leaving `phorvex.phorvex.console.drainLive.enabled=false`. Review its source/build/Pod/Service/policy/audit joins and the exact named journal grant before switching this one opt-in to true through the normal chart deployment. Enabling the mount rolls the console; the profile deliberately pins the **Deployment UID and immutable image**, not an unknowable future self Pod/container ID. At launch, the worker binds its actual Downward API Pod to the sole ReplicaSet→Deployment controller chain and checks that Pod/container identity again after the operation. Any target, source, selector, policy, audit transport, manager, or console image drift refuses the run. A new vLLM Pod, Service, or manager image needs a newly reviewed profile.

The new console arm still uses `/api/vllm/attack` with `{"action":"request-drain"}` and the existing exact-result GET. It pins the public `vllm.vllm.svc.cluster.local:8000` Service route, including the exact Service UID, selector, and sole TCP 8000-to-8000 port, before and after its stream and benign completion. It is one fixed model request with at most 1024 generated tokens, one SecurityEvent, no retry or flood, and one absolute 240-second worker window; the frontend follows its exact ID for at most 270 seconds. A stream ending before the event is non-discriminating. Transport errors, incomplete authenticated audit bytes, mismatched original identities, or missing terminal proof stay `UNKNOWN`. The original event manifest is sealed before create; a lost create reply is never retried automatically. A typed native mechanism without this owned request's disposition remains mechanism-only.

Focused source checks:

```sh
(cd phorvex && go test ./internal/console ./internal/actuator ./internal/audit ./internal/runner)
python3 -m unittest tools.test_drain_live_chart
python3 -m unittest discover -s build/integrations/vllm-live-runtime -p test_render_drain_profile.py
node --test dashboard-web/tests/live-attack-dispatch.test.cjs
```

These are source controls. They do not establish that the derivative is installed or that a Live request was aborted.
