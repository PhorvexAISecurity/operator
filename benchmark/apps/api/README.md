# Benchmark API

NestJS API, durable SQLite queue and one Python campaign worker at a time. Requires
Node.js 22.12 or later and the Python dependencies in `benchmark/worker`.

```
npm ci
npm run build
npm test
npm start
```

Set `BENCHMARK_ROOT` to the absolute `benchmark` directory and `DATA_DIR` to a
persistent private directory. Runtime needs the jump-host Kubernetes/AWS identity
already granted to the authenticated Console test issuer. The web process does
not need those credentials.

Required server environment:

- `DASHBOARD_PASSWORD` (at least 12 characters), `SESSION_SECRET` (at least 32).
- `DASHBOARD_ORIGIN` (or `PUBLIC_ORIGIN`) is the exact browser origin, including port.
- `LLM_API_KEY` is used only by the API with the configured allowlisted models.
- `METRICS_TOKEN` (at least 24 characters) authorizes independent Prometheus scrapes.
- Worker environment as documented in `benchmark/worker`.

`HOST` defaults to `127.0.0.1`; `PORT` defaults to `4101`. TLS terminates at the
reverse proxy. Keep `COOKIE_SECURE=true` (the default) for deployment. Forward the
browser `Origin` and `Cookie` headers through the same-origin `/api` proxy.
`LLM_MODELS` defaults to `gpt-6.1-sol,gpt-6-astra,gpt-6-sol`; `PYTHON` chooses the
worker virtualenv executable. `GRAFANA_URL` deep-links the dashboard by run ID/time.

Plans include the complete currently observed catalogue for all four applications.
LLM output is a planning annotation; it cannot change endpoint, target, commands,
cases or evidence. An unavailable LLM produces an explicit planning limitation.

SQLite atomically owns the scheduler and claims queued campaigns. On restart, active
campaigns become `interrupted` and are never replayed. Scheduling remains blocked
while a recovered child is alive or its PID is unknown. Operators must reconcile
that ambiguity before releasing it. A cancelled campaign stops scheduling and lets
the worker observe already accepted attacks; HTTP mutations are not blindly retried.
Use systemd `KillMode=mixed` with `TimeoutStopSec=1000` or greater. The API waits up
to 980 seconds for accepted attack observations and exports after setting the
cancellation flag, keeping SQLite and the worker's port-forward processes alive.
At that explicit stop deadline it records interruption/UNKNOWN before sending TERM,
then KILL only if the child still does not close. The shutdown promise releases
scheduler ownership and closes SQLite after that wait. Unknown surviving children
continue to block scheduling on restart.

All data/download routes require a signed, server-revocable dashboard session.
Mutating browser requests require the configured Origin. Metrics require their own
Bearer token. Downloads are restricted to the two Excel names and `evidence.zip`.
Metrics preserve original outcomes and evidence gaps; a selected or emitted actuator
does not imply mitigation. `completed` describes a finished campaign/export, while
`incomplete` preserves capture/observation debt.
Grafana links add 15 seconds before and 60 seconds after the recorded run window so
Prometheus can display the final scrape. This display padding does not change the
original evidence or measurement windows in the run and exports.
