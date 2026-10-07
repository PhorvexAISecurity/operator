# Benchmark dashboard implementation decision

Lead: root. Source: operator main a63c7ea3b65d86e86ca045ccbc3d2d9f83583b8e.
Owner scope: 2026-10-07 request to implement and deploy on 87.106.63.105,
run the existing Live catalogue against vllm, voice, litellm and crm, export
the two supplied RAW Excel templates and expose measured results in Grafana.

The benchmark is a separate monorepo application: Next.js web, NestJS API,
and a Python worker using the existing authenticated Console producers.
Keep the running product and its admission/grant rules authoritative.

API contract (all except health and login require a dashboard session):
- POST /api/auth/login {password}; signed httpOnly same-site cookie.
- POST /api/auth/logout; GET /api/auth/session.
- GET /api/meta -> {models, applications, version, grafanaUrl}.
- GET /api/catalogue -> {applications:[{namespace,live:[...]}],version}.
- POST /api/plans {mode,model,request,context,applications} ->
  {id,summary,mode,model,request,context,applications,cases,limitations}.
  Cases retain namespace,id,name,endpoint,armed,compatible,reason,expectedActuator.
  Model may describe/choose allowlisted cases; never execute generated code.
- POST /api/runs {planId} -> run; GET /api/runs -> {runs}.
- GET /api/runs/:id -> {id,status,mode,model,request,context,startedAt,
  finishedAt,progress:{total,completed},cases,version,artifacts,errors,grafanaUrl}.
- POST /api/runs/:id/cancel -> stop scheduling and observe already fired records.
- GET /api/runs/:id/artifacts/:name -> protected, path-safe file download.
- GET /api/runs/:id/events -> {events:[{time,level,message}]}.
- GET /metrics -> authenticated scrape; configure an independent scrape token.

One active campaign per cluster, durable queue and run metadata, explicit restart
reconciliation. Serial executes one case at a time; parallel runs app groups
concurrently and retains serial order within each app, respecting shared producer
locks. HTTP launch is never blindly retried after an ambiguous POST.

Worker protocol: `python3 benchmark/worker/runner.py --request REQUEST.json
--out RUN_DIRECTORY`; writes progress.json, events.jsonl, cases.jsonl,
manifest.json and both .xlsx exports. Environment supplies the console URL,
token or Kubernetes token issuer, current source pin, capture limits and metrics.
Catalogue inspection: same script --catalogue (JSON stdout).
Capture original per-tenant SSE before mutations, preserve exact result IDs,
UIDs, decision/action gates, expected cost and measured cost prerequisites.
Capture truncation/reconnection/version drift is an explicit gap.

Workbook headers/sheet names match the supplied templates. Optional identity and
evidence sheets/columns are additions. Measured cost needs a declared compatible
measurement and window; latency or zero-valued legacy fields cannot substitute.
UNKNOWN/UNAVAILABLE/BLOCKED remain explicit. No complete or defended verdict is
earned from an emitted request or selected actuator alone.

Grafana displays campaign state, attacks, observed action/outcome and evidence
coverage from the same retained result records. Deep links use run ID and time
window; monitoring metrics do not substitute for the raw records.

Implementation is delegated; lead reviews authors' changes and live evidence.
Secrets remain server-side outside Git. Dashboard login, same-origin API,
bounded requests, fixed endpoint allowlist, safe downloads and cancellation are
part of the implementation. No LLM-provided command, URL or target is executed.
