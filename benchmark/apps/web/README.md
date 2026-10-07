# Benchmark web

Standalone Next.js interface for the benchmark API. The UI uses Persian labels
and displays engineering identifiers left-to-right. All model choices,
applications, plans, results and files come from the authenticated API.

```sh
npm ci
npm run typecheck
npm run build
PORT=4100 HOSTNAME=127.0.0.1 node .next/standalone/server.js
```

For standalone distribution, copy `public` and `.next/static` alongside the
generated server (`.next/standalone/public` and
`.next/standalone/.next/static`). Production Caddy sends `/api/*` to the Nest
service on port 4101. Local Next development uses the same-origin rewrite
specified by `BENCHMARK_API_ORIGIN` (default `http://127.0.0.1:4101`). The rewrite
origin is fixed when building; it contains no authentication credential.

The API issues the login cookie. No API token or LLM key is stored in the browser.
POSTs are never automatically retried. Status polling backs off after errors,
pauses while the page is hidden and refreshes every 4 seconds while a run is active
or 12 seconds otherwise. Explicit unavailable/blocked states and missing evidence
remain visible. File downloads use protected run artifact routes.
