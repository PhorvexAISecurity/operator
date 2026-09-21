# phorvex-loadgen

Synthetic "real user" traffic for the demo apps on `phorvex-dev-eks`.

The PhorvexPolicies in `litellm`, `vllm`, `voice` and `nats` only produce meaningful uptime
and defense numbers when there is a believable baseline of user traffic to protect. Between
attack runs this cluster is idle, which makes the *attack landed / Phorvex / R6Blind* charts
read against a flat line. This generates that baseline.

It is **not** an attack tool and **not** a benchmark. Each app is driven the way its real
client drives it — same endpoints, same protocols, same order of operations — at a human
rate (sessions per minute, not requests per second), with think-time between steps and a
diurnal shape across the day.

## What it drives

| App | Target | What a "session" is |
|---|---|---|
| `crm` | `crm.crm:8080` | Support interaction: account lookup → orders → sometimes a privileged write (refund / password reset / appointment). ~15% of callers use a number with no account, so the 404 path is exercised too. |
| `voice` | `voice-bot.voice:8080` | A whole phone call: the Twilio webhook `POST /` for TwiML, then `/ws` in the Twilio Media-Streams protocol — μ-law 8 kHz, 20 ms frames, paced in wall-clock time, alternating caller utterances with the silence while the bot answers. |
| `vllm` | `vllm.vllm:8000` | OpenAI-compatible chat against the real `Qwen/Qwen2.5-7B-Instruct-AWQ`, 1–3 turns, ~45% streamed. Real GPU inference. |
| `litellm` | `litellm.litellm:4000` | OpenAI-compatible chat through the proxy (`gpt-4o-mini` / `gpt-3.5-turbo`) plus occasional `/v1/models`. See **Known limitation** below. |
| `mcp` | `mcp-server.mcp:8000/mcp` | A full Streamable-HTTP MCP session: `initialize` → `notifications/initialized` → `tools/list` → 1–2 `tools/call` → session `DELETE`. |
| `chroma` | `chroma.document-store:8000` | RAG retrieval against the `knowledge_base` collection — the read the voice agent does before answering. |

Arrivals are **Poisson**, not fixed-interval. Real users don't arrive on a metronome, and a
metronome is trivially distinguishable from organic load in the very charts this feeds.

Actuator endpoints are never called — `vllm /v1/drain`, `vllm /v1/kv/invalidate` and
`chroma /api/v1/reset` belong to the operator, not to users. Calling them here would forge
the exact signal Phorvex is supposed to be producing.

## Deploy

```bash
./apply.sh                 # namespace, code ConfigMap, deployment, ServiceMonitor
./apply.sh --no-monitor    # skip the ServiceMonitor
```

`loadgen.py` is the single source of truth: `apply.sh` builds the `loadgen-code` ConfigMap
from it and stamps a hash of the file onto the pod template, so edits actually roll the pod
instead of sitting in a stale mount. No image build — `python:3.11-slim` + `pip install`,
the same pattern the `crm` and `mcp-server` demo apps already use.

```bash
kubectl logs -n phorvex-loadgen deploy/loadgen -f
kubectl scale deployment/loadgen -n phorvex-loadgen --replicas=0   # pause
```

## Tuning

Everything is an env var on the Deployment. The one dial you usually want is
`LOADGEN_RATE_SCALE` — it multiplies every app's rate at once.

| Var | Default | Meaning |
|---|---|---|
| `LOADGEN_APPS` | all six | Comma-separated subset to drive. |
| `LOADGEN_RATE_SCALE` | `1.0` | Global volume multiplier. |
| `CRM_SPM` / `VOICE_CPM` / `VLLM_SPM` / `LITELLM_SPM` / `MCP_SPM` / `CHROMA_SPM` | `6 / 1.2 / 4 / 3 / 2.5 / 5` | Peak sessions (calls) per minute, *before* the diurnal curve scales them down. |
| `*_CONCURRENCY` | `6 / 3 / 4 / 4 / 4 / 6` | Max simultaneous sessions per app. An arrival that finds every worker busy is counted as `outcome="shed"` — what a real user hitting a full queue does. |
| `DIURNAL` | `1` | Business-day shape: broad peak at 13:00 local, quiet night floor (~0.12), weekends at 45%. |
| `TZ_OFFSET_HOURS` | `-8` | Which local time that curve is centred on. **Set this to your demo audience's timezone** — at `-8` the peak lands at 21:00 UTC, so a demo run at 11:00 UTC sees the night floor. |
| `ENABLE_WRITES` | `1` | Whether sessions perform mutations at all. |
| `WRITES_PER_MIN` | `2` | Hard token-bucket ceiling on CRM mutations, independent of read volume. |
| `VOICE_USE_ECHO` | `1` | See **Voice audio** below. |
| `VOICE_TWIML_STREAM_HOST` | host from `VOICE_WS_URL` | Expected host in the TwiML `<Stream>` URL. The deployment sets the public voice route explicitly while connecting through the in-cluster WebSocket URL. |

## Voice audio

A synthetic caller has no voice. Three mechanisms cover that, tried in order:

1. **espeak-ng** (`VOICE_USE_TTS=1`, the default) — real words, synthesised offline in the
   pod, resampled to 8 kHz μ-law. Deepgram transcribes these, which is what carries a call
   past the VAD and into the LLM. Speed and pitch are jittered per utterance so repeat
   callers aren't byte-identical. Callers open with a reason for calling
   (`VOICE_OPENERS`) and then follow up in short fragments (`VOICE_FOLLOWUPS`), the way
   people actually talk to a phone agent.
2. **Echo corpus** (`VOICE_USE_ECHO=1`) — the bot answers in ElevenLabs TTS, which *is*
   genuine human-sounding μ-law. The generator keeps a few of those clips and replays them
   as caller audio later. In-memory only, capped at 8 clips of 6 s.
3. **Speech-shaped tones** — a jittered glottal pulse train through three formants, gated by
   a ~4 Hz syllable envelope. Not words, and no STT will transcribe it, but it carries the
   signature a VAD gates on. This is the fallback if espeak-ng failed to install.

espeak-ng is installed at pod start. `apt` normally drops privileges to the `_apt` user,
which the container can't do with `drop: [ALL]` capabilities — the manifest works around
that by pointing apt's state at `/tmp` and setting `APT::Sandbox::User=root`, so the
container stays hardened. If the install fails the pod still starts and logs
`espeak-ng not installed — voice falls back to speech-shaped tones`; check
`loadgen_voice_utterances_total{source=...}` to see which mechanism is actually in use.

The echo corpus cannot bootstrap until a call returns valid media. A missing corpus is an
observation about this generator process, not a diagnosis of the voice service or any one
of its dependencies.

### Voice outcome semantics

A voice attempt is successful only after a 2xx TwiML response advertises the configured
stream host and path, the bounded WebSocket exchange completes, and this stream returns at
least one nonempty valid base64 media frame. `voice-bidirectional` therefore means that
synthetic audio moved in both directions. It does not prove intelligible speech, a correct
answer, transcript persistence, caller isolation, or effective defense. The tone fallback
can exercise transport and VAD pacing but is not speech.

The earlier `loadgen_voice_calls_total` and voice `loadgen_sessions_total{outcome="ok"}`
series used send-side completion as success. They are intentionally frozen rather than
silently reinterpreted. New calls use `loadgen_voice_call_attempts_total` and the
`voice-bidirectional` / `voice-failed` session outcomes. Compare historical and new series
only with an explicit cutover marker.

## Synthetic vs. attack data

CRM mutations are the only writes. Chroma is deliberately **read-only**: `knowledge_base` is
the corpus the indirect prompt-injection demos poison, and writing synthetic documents into
it would contaminate the thing those tests measure.

Refunds carry `SYNTH_TAG` (default `[synthetic-loadgen]`) in their free-text `reason`, so
they're greppable in `GET /audit`. Password resets and appointments have no free-text field —
those are identifiable only by the generator's own counters (`loadgen_writes_total`) and by
timestamp. If you need `/audit` to be pristine for an attack run, scale the deployment to
zero first, or set `ENABLE_WRITES=0`.

## Metrics

Prometheus exposition on `:9090/metrics`, scraped by the kube-prometheus-stack in
`monitoring` (its `serviceMonitorSelector` is empty, so it picks this up with no release
label needed).

| Metric | Labels |
|---|---|
| `loadgen_requests_total` | `app`, `op`, `status` |
| `loadgen_request_duration_seconds` | `app`, `op` (histogram) |
| `loadgen_sessions_total` | `app`, `outcome` |
| `loadgen_errors_total` | `app`, `op`, `kind` |
| `loadgen_ttft_seconds` | `app` (streamed time-to-first-token) |
| `loadgen_writes_total` | `app`, `op` |
| `loadgen_voice_call_attempts_total` | `outcome` (`success`/`failure`), finite `reason` |
| `loadgen_voice_call_duration_seconds` | `outcome` |
| `loadgen_voice_media_frames_total` | `dir` (`tx`/`rx`) |
| `loadgen_voice_valid_media_frames_total`, `loadgen_voice_valid_media_bytes_total` | none |
| `loadgen_voice_first_valid_audio_seconds` | none |
| `loadgen_voice_utterances_total` | `source` (`synth`/`echo`) |
| `loadgen_mcp_tool_results_total` | `tool`, `outcome` |
| `loadgen_target_sessions_per_min`, `loadgen_diurnal_factor`, `loadgen_inflight_sessions` | gauges |

`loadgen_requests_total` is the honest baseline denominator for uptime charts: it counts
what a user *attempted*, so requests lost during a defensive action still appear.

## Historical dependency observation

The following was observed when this generator was originally introduced. It is retained
as historical troubleshooting context and is not a claim about the current deployment.
Re-check current configuration and bounded call outcomes before drawing a diagnosis.

**1. Any caller using the master key → `401`.** `litellm`'s `OPENAI_API_KEY` is the
placeholder `sk-placeholder-replace-me`, so OpenAI rejects the upstream call:

```
401  litellm.AuthenticationError: OpenAIException -
     Incorrect API key provided: sk-place*************e-me
```

**2. The voice bot → `400`.** `voice-bot` calls LiteLLM with `LITELLM_API_KEY=sk-noauth`,
which is not the master key. LiteLLM tries to validate it against a key database that was
never configured:

```
400  {"message":"No connected db.","type":"no_db_connection"}
```

At that time the observed configuration prevented the voice agent from producing an answer,
and the receive-side media counter remained zero. Aggregate counters alone do not establish
that any particular call followed this path.

Fixing both at once, without any external dependency, by pointing the model groups at the
in-cluster vLLM (which already serves real completions) — in `litellm-config`:

```yaml
model_list:
  - model_name: gpt-4o-mini
    litellm_params:
      model: openai/Qwen/Qwen2.5-7B-Instruct-AWQ
      api_base: http://vllm.vllm.svc.cluster.local:8000/v1
      api_key: sk-noauth
  - model_name: gpt-3.5-turbo
    litellm_params:
      model: openai/Qwen/Qwen2.5-7B-Instruct-AWQ
      api_base: http://vllm.vllm.svc.cluster.local:8000/v1
      api_key: sk-noauth
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
```

That resolves the 401. The voice bot's 400 additionally needs either
`LITELLM_API_KEY=sk-phorvex-demo-1234` on the `voice-bot` deployment, or
`general_settings.allow_requests_on_db_unavailable: true` on LiteLLM.

After correcting the dependency, a bounded synthetic call should independently demonstrate
valid returned media before enabling conclusions about the echo corpus.
