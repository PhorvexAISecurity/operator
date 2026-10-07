# Phorvex Benchmark Lab

An isolated operator-monorepo app: English/LTR Next.js dashboard, NestJS API,
durable SQLite scheduler, and an evidence-preserving Python worker. The browser
never receives Kubernetes credentials or the LLM key. It does not execute LLM
commands. The supplied request/context informs an advisory plan; the complete
current Live catalogue remains the execution scope.

## Behavior and evidence

- All current Live entries are considered for **vllm, voice, litellm and crm**.
  Incompatible/unarmed entries remain explicit blocked rows, not fabricated passes.
  Known producer/readback defects may also be quarantined from launch using
  `BENCHMARK_BLOCKED_CASES=namespace:catalogue-id,...` and an explicit
  `BENCHMARK_BLOCK_REASON`. Original catalogue flags remain intact; these cases
  carry a separate benchmark block annotation and never earn a defense verdict.
  `BENCHMARK_MUTATIONS_PAUSED_REASON` blocks new runs/queue claims while an
  operator reconciles ambiguous producer effects. History, plans, exports and
  metrics stay available; clearing it requires deliberate server configuration.
- Serial: one case at a time. Parallel: concurrent app groups, one case per app;
  shared model-gateway/CRM locks prevent interacting trials from overlapping.
- Uses the existing authenticated Console routes and normal Brain selection.
  No force actuator, policy/grant expansion, arbitrary shell command, or blind
  POST retry. Stateful defenses can retire later catalogue entries; this is reported.
- Captures original per-namespace/tenant SSE **before** launch, follows exact
  returned attack IDs, retains full decision traces and before/after policy,
  namespace, Deployment and owned-Pod image/UID pins. Changed controller identity,
  stream truncation, unknown POST acceptance or incomplete observations remain gaps.
- Cancel stops new launches but observes already accepted producers to their
  deadlines. API shutdown waits for observation/export before closing SQLite.
  Restarted campaigns are interrupted, never automatically replayed; a surviving
  worker blocks the queue until reconciliation.
- Both uploaded RAW template sheet names and original headers are preserved.
  Identity, original outcomes, evidence coverage, expected-cost checks and version
  sheets are added. Original templates, source and SHA256SUMS ship in evidence.zip.
- `CNorm_measured`/`CFlow_measured` remain blank/UNAVAILABLE when the producer has
  no compatible measurement definition/window. Latency, selection or legacy zero
  fields are not substituted. Numeric recorded zero is retained as zero.
- Completed means campaign scheduling/export finished, **not** that every defense
  passed. Selection, emission, actuation, behavioral effect and mitigation are
  distinct. Inspect original outcome and evidence scope, not just action names.

## Local verification

Requires Node 22.12+ and Python 3.10+ (deployment/CI use 22.23.3 / Python 3.12).

```sh
python3 -m venv .venv
.venv/bin/pip install -r worker/requirements.txt
npm run install:apps
npm run test:api
npm run typecheck
npm run build
.venv/bin/python -m unittest discover -s worker -p 'test_*.py'
```

Run from `benchmark/`. Set server configuration from `deploy/server.env.example`
outside Git. API and web ports are 4101/4100 on loopback. The web's same-origin
API proxy preserves browser Origin/Cookie; mutations require a signed session and
the exact configured public origin. Metrics have a separate bearer credential.

## Jump-host deployment

Keep the existing ingress, proxies and product services untouched. Install the
Ubuntu `python3.12-venv` prerequisite, then as the authorized jump-host user:

```sh
# Administrator, once: sudo loginctl enable-linger hami
bash benchmark/deploy/bootstrap.sh
# Provision /home/hami/phorvex-benchmark/config/server.env with mode 600.
bash benchmark/deploy/install.sh /home/hami/phorvex-benchmark/releases/RELEASE
```

Release directory contains `benchmark/`. Node and Caddy archives are verified
against pinned Node SHA256 and official Caddy SHA512 checksums. Builds are bounded
to one Next worker; Python exports use disk-backed rows/write-only workbooks.
User services survive logout/reboot when lingering is enabled. Upgrade only while
the queue is idle; do not interrupt a benchmark to publish a newer dashboard.

Default endpoint: **https://87.106.63.105:8444**. Caddy uses an internal CA for
the IP endpoint. Verify/trust its provided root certificate before entering the
dashboard password; this is not a public-CA certificate. For a verified owned DNS
name, change the Caddy site and PUBLIC_ORIGIN together and configure an appropriate
public certificate. Do not disable TLS verification in production clients.

Runtime data/evidence: `/home/hami/phorvex-benchmark/data`. Config and data are
private. No automatic evidence deletion; watch available disk space and archive
old campaigns deliberately. LLM requests may contain user context and catalogue
metadata; only the user-chosen provider receives them. Rotate keys out of band.

### Additive Grafana integration

After HTTPS starts, the internal root certificate is at
`runtime/caddy-data/caddy/pki/authorities/local/root.crt`.

```sh
python3 benchmark/deploy/render-monitoring.py \
  --env /home/hami/phorvex-benchmark/config/server.env \
  --ca /home/hami/phorvex-benchmark/runtime/caddy-data/caddy/pki/authorities/local/root.crt \
  --out /home/hami/phorvex-benchmark/config/monitoring.json
kubectl apply -f /home/hami/phorvex-benchmark/config/monitoring.json
```

This adds only a dedicated metrics Secret, ScrapeConfig and dashboard ConfigMap
in monitoring; it does not overwrite existing app dashboards. Scraping verifies
the internal CA and authenticates separately. Grafana uid `phorvex-benchmark`
shows the same retained run/case outcomes, recorded actions, original actuation
flag and evidence counts. Deep links pad display time for the final scrape; raw
observation windows do not change.

If direct TCP 8444 from EKS is filtered, an existing authorized HTTPS CONNECT
proxy can be supplied with `--proxy-url`, `--proxy-authorization` (private file
containing a full Basic header) and `--proxy-ca` (public certificate verified
through SSH). The Secret then contains a CA bundle for both TLS hops and a separate
proxy-auth header. Neither TLS verification nor metrics bearer authentication is
disabled; the existing proxy configuration is unchanged.

## Reproduce an export without attacks

```sh
.venv/bin/python worker/runner.py --request RUN/request.json --out RUN --export-only
```

This reads retained evidence only. Live launch is refused if the directory already
contains launch evidence. The standalone benchmark CI workflow performs builds
and offline tests, never attacks a live cluster.
