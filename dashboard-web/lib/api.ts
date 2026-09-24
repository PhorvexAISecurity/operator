// Phorvex Console — typed client for the Go data backend (proxied at /api).
import { captureQueryEventProvider, emitQueryChange, isCurrentQueryEventProvider } from "@/lib/query-events";
//
// [M-136] Authentication is the ALB Cognito session (the browser already carries it) or a bearer
// token for CLI callers. The console sends NO credential of its own: there is no ?user=, no
// ?tenant= identity and no token in a URL. The lens below is a PRESENTATION hint only — the
// server narrows it to the caller's grant and can never be widened by it. Read /api/session to
// learn what the signed-in identity may actually do; the server enforces it regardless.

export type Lens = "investor" | "operator" | "owner";

// Session is the effective grant for the signed-in identity (GET /api/session).
export interface Session {
  subject: string;
  issuer: string;
  source: "alb" | "bearer";
  roles: Lens[];
  tenants: string[];
  targets: string[];
  lens: Lens;
  canRead: boolean;
  canEdit: boolean;
  authModes: string[];
  grantsConfigured: boolean;
  auditClearAvailable: boolean;
  trustedOrigins: string[];
  note: string;
}

// ApiError carries the HTTP status so the UI can tell "not signed in" from "not allowed".
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** unauthenticated: identity could not be verified (missing, expired, or rejected credentials). */
export const isUnauthenticated = (e: unknown) => e instanceof ApiError && e.status === 401;
/** unauthorized: signed in, but the server-side grant does not cover this. */
export const isUnauthorized = (e: unknown) => e instanceof ApiError && e.status === 403;

export interface CI { mean: number; lo: number; hi: number; n: number }
export interface Stat {
  key: string; label: string; value: string; unit?: string;
  ci?: CI; source: string; status: "real" | "modeled" | "pending"; product: "k8s" | "ai" | "both"; note?: string;
}
export interface FrontierRow {
  arm: string; interval: string;
  prevention: CI; harm: CI; infeasible: CI; win: string;
}
export interface ClaimScope {
  scope: string; detectorSet: string[]; detectorSetKnown: boolean;
  recallCap: string; note: string; brainImage: string; gitSHA: string;
}
export interface OwnerEvent {
  claim?: ClaimScope; outcomeEvidence?: string;
  tenant: string; namespace: string; pod: string; action: string; actuated: boolean; dryRun: boolean;
  handler?: string; objectsTouched?: string[]; reversible: boolean; attackPrevented: boolean;
  workPreserved: boolean; harmCaused: boolean; sloKept: boolean; attackStage: string; why: string; blindOutcome: string;
}
export interface ArmResult { defender: string; trials: number; disruption: number; dwellMean: number }
export interface RunStatus {
  id: string; config: string; state: "queued" | "running" | "done" | "partial" | "error" | "stopped"; started: string;
  date?: string; finished?: string; namespace?: string; target?: string; provider?: string; targetLabel?: string;
  trials: number; expectedTrials?: number; arms?: ArmResult[]; error?: string; nativeActuator: boolean; compare3?: boolean;
  executionKind?: string; claimClass?: string; outcome?: TrialOutcome; cleanupStatus?: string; unsafeToRetry?: boolean;
}
export interface PageMeta {
  limit: number;
  total: number;
  nextCursor?: string;
  currentCursor?: string;
}
function pageQuery(limit: number, filters: Record<string, string | undefined> = {}, cursor?: string): string {
  const q = new URLSearchParams({ limit: String(limit) });
  Object.entries(filters).forEach(([key, value]) => { if (value?.trim()) q.set(key, key === "q" ? value.trim().toLowerCase() : value.trim()); });
  if (cursor) q.set("cursor", cursor);
  return q.toString();
}
export interface Suite { Name: string; Desc: string }

// API base: empty = same-origin (the single Go binary serves the SPA + /api on one port).
// For `next dev`, set NEXT_PUBLIC_API_BASE=http://localhost:8090 (CORS is allowed).
export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "";

// credentials: "include" carries the ALB session cookie. It is not a credential this client
// creates — the browser already holds it, and the server treats Origin as a CSRF boundary rather
// than as an authentication factor.
function staleProviderAbort(): DOMException {
  return new DOMException("Request belongs to a retired authenticated provider", "AbortError");
}

async function get<T>(path: string, lens: Lens, signal?: AbortSignal, bindProvider = true): Promise<T> {
  const provider = bindProvider ? captureQueryEventProvider() : null;
  let r: Response;
  try {
    r = await fetch(API_BASE + path, { headers: { "X-Phorvex-Lens": lens }, cache: "no-store", credentials: "include", signal });
  } catch (error) {
    if (signal?.aborted || (error instanceof DOMException && error.name === "AbortError")) throw error;
    throw new Error("BACKEND_UNREACHABLE");
  }
  if (signal?.aborted || (provider && !isCurrentQueryEventProvider(provider))) throw staleProviderAbort();
  if (!r.ok) {
    const error = new ApiError((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`, r.status);
    if (r.status === 401 && provider && isCurrentQueryEventProvider(provider) && typeof window !== "undefined") window.dispatchEvent(new CustomEvent("phorvex-auth-lost", { detail: { providerToken: provider.token } }));
    throw error;
  }
  if (provider && !isCurrentQueryEventProvider(provider)) throw staleProviderAbort();
  return r.json();
}
async function post<T>(path: string, body: unknown, lens: Lens, context?: string): Promise<T> {
  const provider = captureQueryEventProvider();
  let r: Response;
  try {
    r = await fetch(API_BASE + path, {
      method: "POST", headers: { "X-Phorvex-Lens": lens, "Content-Type": "application/json" },
      body: JSON.stringify(body), credentials: "include",
    });
  } catch {
    throw new Error("BACKEND_UNREACHABLE");
  }
  if (provider && !isCurrentQueryEventProvider(provider)) throw staleProviderAbort();
  if (!r.ok) {
    const error = new ApiError((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`, r.status);
    if (r.status === 401 && provider && isCurrentQueryEventProvider(provider) && typeof window !== "undefined") window.dispatchEvent(new CustomEvent("phorvex-auth-lost", { detail: { providerToken: provider.token } }));
    throw error;
  }
  const result = await r.json() as T;
  if (provider && !isCurrentQueryEventProvider(provider)) throw staleProviderAbort();
  if (result && typeof result === "object" && "ok" in result && (result as { ok?: boolean }).ok === false) {
    throw new Error(String((result as { message?: string; error?: string }).error || (result as { message?: string }).message || "Mutation was not accepted"));
  } else {
    const resources = path.startsWith("/api/runs/") ? ["runs", "runs-summary", "run-status", "run-evidence", "reports", "effectiveness", "posture", "benchmarks", "cost", "cost-timeseries", "uptime", "matrix"]
      : path.startsWith("/api/availability-arms/") ? ["availability-arms", "cost", "uptime"]
      : path === "/api/policy/edit" ? ["targets", "catalog", "reports", "workloads", "cluster", "workload-attacks"]
      : path.includes("attack") || path.includes("fire-scenario") ? ["attack-results", "attack-monitoring", "workload-attacks", "cost", "cost-timeseries", "uptime", "owner-events"] : [];
    const runId = path.startsWith("/api/runs/")
      ? String((result as { id?: string }).id || (body as { id?: string } | null)?.id || "") || undefined
      : undefined;
    if (resources.length && provider) emitQueryChange({ identity: provider.identity, providerToken: provider.token, lens, context, runId, resources, kind: "mutation" });
  }
  return result;
}

export interface CatalogItem {
  entryID?: string; name: string; product: "k8s" | "ai" | "structural" | "application" | "platform"; category: string; r6Tag: string;
  techniques: string[]; exercisedTechniques: string[]; caps: string[]; hasRun: boolean;
  realism?: string; benignControl?: boolean;
  expectedActuators?: string[]; responseGuidanceBasis?: "name-heuristic" | "explicit-effect" | "none";
  responseGuidance?: string; meaningfulWhen?: string; runnableNote?: string; prereqs?: string[];
  launchKind?: "harness-scenario" | "fixed-suite" | "named-suite" | "live-vllm-effect";
  claimClass?: "security" | "functional" | "effect" | "calibration";
  profile?: string; available?: boolean; unavailableReason?: string;
  runtimeContext?: string;
}
export type FunctionalAdmissionReason = "READY" | "CONFIG_UNAVAILABLE" | "RUNTIME_UNAVAILABLE" | "RETAINED_STATE_UNAVAILABLE" | "PRIOR_UNSAFE_FIXED_SUITE" | "CONCURRENCY_LIMIT" | "RATE_LIMIT";
export interface FunctionalAdmission {
  profile: string;
  observedAt: string;
  launchable: boolean;
  reasonCode: FunctionalAdmissionReason;
  message: string;
}
export interface BenchArm { defender: string; disruption: CI; dwell: CI; harmRate: CI; trials: number }
export interface BenchGroup { scenario: string; source: string; arms: BenchArm[] }
export interface CoverageTechnique { technique: string; scenarios: string[]; product: string; covered: boolean }
export interface PostureSub { label: string; score: number; basis: string }
export interface Posture { grade: string; score: number; subs: PostureSub[]; note: string }
export interface OwnerRollup { dispatched?: number; isolationAttempts?: number; actions: number; attacksPrevented: number; workPreserved: number; sloKept: number }

// --- P-VCLUSTER Pass 2: the safe apply-fix write-path client ---
export interface ApplyFixDelta {
  normSparsity?: number;
  flowDisruption?: number;
  maxMovesPerTick?: number;
  proactiveFloorSec?: number;
}
// AFScope is the TENANT SELECTION for the apply-fix flows — not an identity. The acting subject
// is the verified session; a caller granted several tenants names which one it is acting on, and
// the server refuses any tenant outside that grant.
export interface AFScope { tenant?: string }
export interface GatePreview { pass: boolean; reason: string }
// AFPending is one OPEN request as the server lists it. `generation` is the server-issued identity an
// approval must echo back (it changes on every submit and on every console restart); `state` is
// "pending" or "applying" (claimed by `approver`, callback in flight).
export interface AFPending {
  id: string; tenant: string; namespace: string; requester: string; reason: string; deltaHash: string;
  generation: string; state: "pending" | "applying"; approver?: string;
}
export interface AFPendingList { pending: AFPending[]; applierMode: string; applierWired: boolean }
export interface AFSubmitResult { status: string; id: string; tenant: string; generation: string; existing: boolean; note: string }
// AFApproveOutcome is what ONE approval call did. Only status === "applied" means the applier accepted
// the candidate; every other status is an explicit non-applied outcome (see docs/CONSOLE-APPLY-FIX.md).
export type AFApproveStatus =
  | "applied" | "in-progress" | "conflict" | "stale-generation" | "stale" | "refused" | "rejected"
  | "applier-unavailable" | "failed" | "not-found" | "invalid";
export interface AFApproveOutcome {
  status: AFApproveStatus | string; id: string; tenant: string; generation: string; state: string;
  approver: string; retry: boolean; error?: string; httpStatus: number;
}
export interface AFAuditEntry { event: string; fields: Record<string, any> }

function withTenant(path: string, scope: AFScope): string {
  if (!scope.tenant) return path;
  const q = new URLSearchParams({ tenant: scope.tenant }).toString();
  return path + (path.includes("?") ? "&" : "?") + q;
}
async function afFetch<T>(method: string, path: string, scope: AFScope, lens: Lens, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-Phorvex-Lens": lens };
  if (body) headers["Content-Type"] = "application/json";
  let r: Response;
  try {
    r = await fetch(API_BASE + withTenant(path, scope), {
      method, headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store", credentials: "include",
    });
  } catch { throw new Error("BACKEND_UNREACHABLE"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(data.error || `HTTP ${r.status}`, r.status);
  return data as T;
}
// afApprove posts ONE approval for the exact pending generation and returns the server's outcome for
// every response that carries a `status` — a 409/422/500/501 outcome is an answer about this approval,
// not a transport failure. Responses without a status (401/403/400 from the boundary) still throw.
async function afApprove(req: { id: string; generation: string }, scope: AFScope, lens: Lens): Promise<AFApproveOutcome> {
  let r: Response;
  try {
    r = await fetch(API_BASE + withTenant("/api/apply-fix/approve", scope), {
      method: "POST", headers: { "X-Phorvex-Lens": lens, "Content-Type": "application/json" },
      body: JSON.stringify({ id: req.id, generation: req.generation }), cache: "no-store", credentials: "include",
    });
  } catch { throw new Error("BACKEND_UNREACHABLE"); }
  const data = await r.json().catch(() => ({}));
  if (typeof data.status !== "string") throw new ApiError(data.error || `HTTP ${r.status}`, r.status);
  return { ...(data as Omit<AFApproveOutcome, "httpStatus">), httpStatus: r.status };
}
export const applyFixApi = {
  gatePreview: (delta: ApplyFixDelta, scope: AFScope, lens: Lens) =>
    afFetch<GatePreview>("POST", "/api/apply-fix/gate-preview", scope, lens, { delta }),
  submit: (reqId: string, delta: ApplyFixDelta, reason: string, scope: AFScope, lens: Lens) =>
    afFetch<AFSubmitResult>("POST", "/api/apply-fix/submit", scope, lens, { id: reqId, delta, reason }),
  approve: afApprove,
  pending: (scope: AFScope, lens: Lens) =>
    afFetch<AFPendingList>("GET", "/api/apply-fix/pending", scope, lens),
  audit: (scope: AFScope, lens: Lens) =>
    afFetch<{ audit: AFAuditEntry[] }>("GET", "/api/apply-fix/audit", scope, lens),
};

export const api = {
  // session reports what the signed-in identity may actually do, so the UI can offer only the
  // lenses and controls the grant supports. The server re-checks every request regardless.
  session: (lens: Lens = "operator", signal?: AbortSignal) => get<Session>("/api/session", lens, signal, false),
  liveHistory: (lens: Lens, filters: Record<string, string>, signal?: AbortSignal) =>
    get<LiveHistoryPage>(`/api/live/history?${new URLSearchParams(filters)}`, lens, signal),
  health: (lens: Lens = "operator") => get<any>("/api/health", lens),
  // diagnostics is the authenticated form of what /api/health used to disclose.
  diagnostics: (lens: Lens = "operator", signal?: AbortSignal) => get<any>("/api/diagnostics", lens, signal),
  effectiveness: (lens: Lens, signal?: AbortSignal) => get<{ stats: Stat[] }>("/api/effectiveness", lens, signal),
  frontier: (lens: Lens, signal?: AbortSignal) => get<{ rows: FrontierRow[] }>("/api/frontier", lens, signal),
  suites: (lens: Lens, signal?: AbortSignal) => get<{ suites: Suite[] }>("/api/suites", lens, signal),
  // owner endpoints are tenant-scoped: the owner lens MUST pass its tenant (the backend fail-closes
  // on an empty tenant to prevent cross-tenant leak). ownerTenants lists the selectable tenants.
  ownerEvents: (lens: Lens, tenant?: string, signal?: AbortSignal) => get<{ events: OwnerEvent[]; empty: boolean; rollup: OwnerRollup; note: string; partial: boolean; coveredFrom?: string; coveredTo?: string }>(`/api/owner/events${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ""}`, lens, signal),
  ownerTenants: (lens: Lens, signal?: AbortSignal) => get<{ tenants: string[]; partial: boolean; coveredFrom?: string; coveredTo?: string }>("/api/owner/tenants", lens, signal),
  reports: (lens: Lens, signal?: AbortSignal) => get<{ reports: ReportMeta[] }>("/api/reports", lens, signal),
  cost: (lens: Lens, context = "", signal?: AbortSignal) => get<CostResult>(`/api/cost${context ? `?context=${encodeURIComponent(context)}` : ""}`, lens, signal),
  costTimeseries: (lens: Lens, signal?: AbortSignal) => get<CostTimeseries>("/api/cost-timeseries", lens, signal),
  uptime: (lens: Lens, window = "1h", context = "", signal?: AbortSignal) => get<UptimeResult>(`/api/uptime?window=${encodeURIComponent(window)}${context ? `&context=${encodeURIComponent(context)}` : ""}`, lens, signal),
  report: (id: string, lens: Lens, signal?: AbortSignal) => get<{ id: string; title: string; content: string }>(`/api/reports?id=${encodeURIComponent(id)}`, lens, signal),
  startRun: (config: string, nativeActuator: boolean, lens: Lens) =>
    post<{ id: string }>("/api/runs/start", { config, nativeActuator, startedAt: new Date().toLocaleTimeString() }, lens),
  startFunctional: (profile: string, lens: Lens) =>
    post<{ id: string; context: string }>("/api/runs/functional", { profile, startedAt: new Date().toLocaleTimeString() }, lens),
  functionalAdmission: (profile: string, lens: Lens, signal?: AbortSignal) =>
    get<FunctionalAdmission>(`/api/runs/functional/admission?profile=${encodeURIComponent(profile)}`, lens, signal),
  version: (lens: Lens, signal?: AbortSignal) => get<{ console: string; operator?: string; operatorImage?: string }>("/api/version", lens, signal),
  vllmAttack: (action: VllmAttackAction, lens: Lens) => post<{ ok: boolean; action: string; message: string; attackId?: string }>("/api/vllm/attack", { action }, lens),
  workloadAttack: (namespace: string, action: "foothold" | "clear", lens: Lens) => post<{ ok: boolean; action: string; message: string; pod?: string; expect?: string; attackId?: string }>("/api/workload/attack", { namespace, action }, lens),
  attackResults: (lens: Lens, includeObservations = false) => get<{ attacks: AttackResult[] }>(`/api/attack-results${includeObservations ? "?includeObservations=true" : ""}`, lens),
  attackResultsPage: (lens: Lens, limit: number, filters: { q?: string; id?: string; includeObservations?: string } = {}, cursor?: string, signal?: AbortSignal) =>
    get<{ attacks: AttackResult[]; page?: PageMeta }>(`/api/attack-results?${pageQuery(limit, filters, cursor)}`, lens, signal),
  // Per-app attack compatibility: which attacks THIS app's stack supports, which are armed to
  // fire now, and — when the harness binary is in the image — the catalogue filtered per app.
  workloadAttacks: (namespace: string, lens: Lens, signal?: AbortSignal) =>
    get<WorkloadAttacks>(`/api/workload/attacks?namespace=${encodeURIComponent(namespace)}`, lens, signal),
  // Fire a catalogue scenario as a REAL SecurityEvent at a live app's pod (not the sandbox).
  fireScenarioLive: (body: { namespace: string; scenario: string; mitre?: string; expected?: string; action?: "fire" | "clear" }, lens: Lens) =>
    post<{ ok: boolean; scenario: string; namespace: string; pod?: string; expect?: string; message: string; attackId?: string }>("/api/workload/fire-scenario", body, lens),
  // LIVE-ATTACK MONITORING — availability before/during/after each real attack + downtime $.
  attackMonitoring: (lens: Lens) =>
    get<AttackMonitoringResult>("/api/attack-monitoring", lens),
  attackMonitoringPage: (lens: Lens, limit: number, filters: { q?: string; id?: string; includeObservations?: string } = {}, cursor?: string, signal?: AbortSignal) =>
    get<AttackMonitoringResult & { page?: PageMeta }>(`/api/attack-monitoring?${pageQuery(limit, filters, cursor)}`, lens, signal),
  // three-arm availability: no-defense vs blind timer vs Phorvex, measured on the same app.
  // start a three-arm comparison for one app (disruptive, ~7 min) — the 3-way tab shows it live.
  runAvailabilityArms: (namespace: string, attack: string, lens: Lens) =>
    post<{ ok: boolean; namespace: string; note: string }>("/api/availability-arms/run", { namespace, attack }, lens),
  availabilityArms: (ns: string, lens: Lens) =>
    get<AvailabilityArms>(`/api/availability-arms${ns ? `?ns=${encodeURIComponent(ns)}` : ""}`, lens),
  availabilityArmsPage: (lens: Lens, limit: number, filters: { ns?: string; q?: string } = {}, cursor?: string, signal?: AbortSignal) =>
    get<AvailabilityArms & { page?: PageMeta }>(`/api/availability-arms?${pageQuery(limit, filters, cursor)}`, lens, signal),
  // Optimizer Bench — run the REAL p1-coverage engine over a config sweep, in-process (no live attack).
  // horizonSec>0 adds the temporal (over-time) simulation where tickInterval + anti-rotation manifest.
  benchmarkSim: (scenario: string, configs: BenchConfigInput[], horizonSec: number, r6IntervalSec: number, lens: Lens) =>
    post<BenchResult>("/api/benchmark-sim", { scenario, configs, horizonSec, r6IntervalSec }, lens),
  runStatus: (id: string, lens: Lens, signal?: AbortSignal) => get<RunStatus>(`/api/runs/status?id=${encodeURIComponent(id)}`, lens, signal),
  runsList: (lens: Lens) => get<{ runs: RunStatus[] }>("/api/runs/list", lens),
  runsPage: (lens: Lens, limit: number, filters: { context?: string; provider?: string; q?: string } = {}, cursor?: string, signal?: AbortSignal) =>
    get<{ runs: RunStatus[]; page?: PageMeta }>(`/api/runs/list?${pageQuery(limit, filters, cursor)}`, lens, signal),
  stopRun: (id: string, lens: Lens) => post<{ status: string; id: string }>("/api/runs/stop", { id }, lens),
  reconcileNATSRun: (id: string, lens: Lens) => post<{ status: string; id: string }>(`/api/runs/nats-reconcile?id=${encodeURIComponent(id)}`, { id }, lens),
  runEvidence: (id: string, lens: Lens, signal?: AbortSignal) => get<RunEvidence>(`/api/runs/evidence?id=${encodeURIComponent(id)}`, lens, signal),
  catalog: (lens: Lens, signal?: AbortSignal) => get<{ items: CatalogItem[] }>("/api/catalog", lens, signal),
  benchmarks: (lens: Lens, signal?: AbortSignal) => get<{ groups: BenchGroup[] }>("/api/benchmarks", lens, signal),
  threatMatrix: (lens: Lens, signal?: AbortSignal) => get<{ techniques: CoverageTechnique[] }>("/api/threat-matrix", lens, signal),
  posture: (lens: Lens, signal?: AbortSignal) => get<Posture>("/api/posture", lens, signal),
  rawlog: (path: string, lens: Lens) => get<{ log: string }>(`/api/rawlog?path=${encodeURIComponent(path)}`, lens),
  targets: (lens: Lens, signal?: AbortSignal) => get<{ targets: ClusterTarget[] }>("/api/targets", lens, signal),
  // workloads enumerates the REAL workloads on the selected cluster (live get/list — read-only).
  workloads: (target: string, lens: Lens, signal?: AbortSignal) =>
    get<{ context: string; namespaces: WorkloadNS[] }>(`/api/workloads${target ? `?target=${encodeURIComponent(target)}` : ""}`, lens, signal),
  // capabilities reports live cluster GPU/MIG/multi-node so the UI gates only genuinely-unmet scenarios.
  capabilities: (target: string, lens: Lens, signal?: AbortSignal) =>
    get<{ gpu: boolean; mig: boolean; multiNode: boolean; nodes: number; gpuCount: number }>(`/api/capabilities${target ? `?target=${encodeURIComponent(target)}` : ""}`, lens, signal),
  startScenario: (scenarios: string | string[], withPX: boolean, target: string, namespace: string, lens: Lens, compare3 = false, context?: string) =>
    post<{ id: string }>("/api/runs/scenario", { scenarios: Array.isArray(scenarios) ? scenarios : [scenarios], withPX, compare3, target, namespace, startedAt: new Date().toLocaleTimeString() }, lens, context),
  // scan execs `phorvex --scan` LIVE (fresh exec each call — not a cached corpus). ns="" scans all
  // namespaces; context targets a specific kubeconfig context (the selected environment).
  scan: (ns: string, lens: Lens, context?: string, signal?: AbortSignal) => {
    const q = new URLSearchParams();
    if (ns) q.set("ns", ns);
    if (context) q.set("context", context);
    const s = q.toString();
    return get<ScanResult>(`/api/scan${s ? `?${s}` : ""}`, lens, signal);
  },
  ablation: (ns: string, lens: Lens) => get<AblationResult>(`/api/ablation${ns ? `?ns=${encodeURIComponent(ns)}` : ""}`, lens),
  cluster: (lens: Lens, signal?: AbortSignal) => get<{ policies: PolicyView[]; available: boolean; note: string }>("/api/cluster", lens, signal),
  // LIVE cluster control: patch a PhorvexPolicy. Only the fields present are changed. A real
  // cluster write, gated to the operator lens behind the console's Cognito auth.
  policyEdit: (body: PolicyEdit, lens: Lens, context?: string) =>
    post<{ ok: boolean; namespace: string; name: string; patched: Record<string, unknown>; result: string }>("/api/policy/edit", body, lens, context),
  handlers: (lens: Lens, signal?: AbortSignal) => get<RegistryView>("/api/handlers", lens, signal),
  matrix: (lens: Lens, signal?: AbortSignal) => get<MatrixResult>("/api/matrix", lens, signal),
  aiSurface: (lens: Lens, signal?: AbortSignal) => get<AISurface>("/api/ai-surface", lens, signal),
  metrics: (lens: Lens, signal?: AbortSignal) => get<MetricsResult>("/api/metrics", lens, signal),
  // Red-team READ endpoints (previously backend-only; now wired). run/continuous/live trigger compute /
  // need a real cluster — surfaced as [PENDING] actions, not auto-run.
  redteamFindings: (lens: Lens, signal?: AbortSignal) => get<{ findings: RTFinding[] }>("/api/redteam/findings", lens, signal),
  redteamGates: (lens: Lens) => get<{ gates: RTGate[]; allPass: boolean; ranAt: string }>("/api/redteam/gates", lens),
  redteamCampaigns: (lens: Lens, signal?: AbortSignal) => get<{ campaigns: RTCampaign[] }>("/api/redteam/campaigns", lens, signal),
  // clearLive empties the live decision-audit the SSE replays (operator-only write).
  clearLive: (lens: Lens, context = "") => post<{ cleared: boolean; note?: string }>(`/api/live/clear?${new URLSearchParams({ context })}`, {}, lens),
};
export interface RTFinding { id: string; title: string; product: string; category: string; source: string; reasoning: string; cycle: string; fix: string; fixFile: string; status?: string; applyNote?: string }
export interface RTGate { label: string; pass: boolean; out: string }
export interface RTCampaignArm { arm: string; disruption: number; defensiveActions: number; n: number }
export interface RTCampaign { scenario: string; product: string; arms: RTCampaignArm[] }
export interface MatrixCell { scenario: string; arm: string; disruption: number; n: number }
export interface LearnArm { arm: string; mean: number; firstHalf: number; secondHalf: number; n: number }
export interface MatrixResult { source: string; arms: string[]; scenarios: string[]; cells: MatrixCell[]; fpRows: number; fpViolations: number; fpRate: number; learnability: LearnArm[]; learnScenario: string; note: string }
export interface AISurface { totalRows: number; scenarios: number; slotRows: number; slotDisruptMax: number; atlasIds: string[]; owaspIds: string[]; mtdEffect: Record<string, number>; splitOracle: Record<string, number>; schwartauRows: number; reuseRows: number; replayReduced: string; note: string }
export interface PodRisk { namespace: string; pod: string; risk: number; blast: number; perDollar: number }
export interface MetricsResult { available: boolean; source: string; pods: PodRisk[]; note: string }
export interface RegistryView { names: string[]; generatable: string[]; missing: string[]; orphans: string[]; count: number; generatables: number; complete: boolean }
export interface AblationResult { ratio: number; p1PerDollar: number; randomPerDollar: number; ran: boolean; note: string; raw: string }
export interface PhysWitness { pod: string; imageRarity: number; coResidency: number; slack: number; pdbMinAvail: number; migValid: boolean; epss: number; stateful: boolean; gpuPresent: boolean; vramFraction: number; smOccupancy: number; linkBandwidth: number }
export interface KillchainRow { pod: string; stage: string; ai: boolean; pHold: number; preemptMargin: number; projNextStageSec: number; infectionFrontier: number }
export interface GraphNode { key: string; blast: number; ai: boolean }
export interface GraphEdge { src: string; dst: string }
export interface NodeInfo { name: string; allocCPUm: number; allocMemMi: number; allocGPU: number; migKinds: number }
export interface ScanResult { platform: string; nodes: number; pods: number; nodeList: NodeInfo[]; witness: PhysWitness[]; killchain: KillchainRow[]; graphNodes: GraphNode[]; graphEdges: GraphEdge[]; emr: { baseline: number; scarcity: number; lift: number; note: string }; raw: string }
export interface PolicyView { name: string; namespace: string; tenant: string; mode: string; spec: any; status: any }
// A partial live edit to one PhorvexPolicy — only the present fields are patched.
export interface PolicyEdit { namespace: string; name: string; maxMovesPerTick?: number; mode?: "active" | "dryRun"; enabledActions?: string[] }
export interface ClusterTarget { id: string; context: string; label: string; provider: string; runnable: boolean; note: string; defaultMutationTarget?: boolean }
// Live workloads (P-DASHBOARD-LIVE): the real controllers running on the selected cluster.
export interface Workload { kind: string; name: string; replicas: number; ready: number; images: string[]; selector: Record<string, string> }
export interface WorkloadNS { namespace: string; system: boolean; podCount: number; workloads: Workload[] }

// The live-attack action set the /api/vllm/attack endpoint accepts (vllm_attack.go). `reset` is
// the cleanup action, not an attack — it clears the last one.
export type VllmAttackAction =
  | "poison" | "kvcache" | "endpoint-rotate" | "guardrail-rotate" | "request-drain"
  | "kv-migrate-invalidate" | "warm-swap" | "model-shard-replace" | "reset";

// --- per-app attack compatibility (GET /api/workload/attacks) ---
export interface LiveAttack {
  id: string; name: string; endpoint: string; mitre: string;
  expectedActuator: string; stack: string; description: string;
}
export interface CompatEntry extends LiveAttack { compatible: boolean; armed: boolean; reason: string }
export interface AppStack {
  namespace: string; servedModel: boolean; vllm: boolean; gpu: boolean;
  stateful: boolean; workload: boolean; armed: boolean;
}
export interface CatalogCompat {
  name: string; product: string; category: string; techniques: string[]; benignControl?: boolean;
  expectedActuators: string[]; responseGuidanceBasis?: "name-heuristic" | "explicit-effect" | "none";
  responseGuidance?: string; prereqs: string[]; compatible: boolean; reason: string;
}
export interface WorkloadAttacks {
  namespace: string; stack: AppStack; live: CompatEntry[];
  catalog: CatalogCompat[]; catalogNote?: string;
  // the actuators a policy on THIS app may enable — runnable on its stack, so the brain never
  // gets handed one it will select but cannot actuate.
  policyActuators?: string[];
}
// Attack-timeline SSE event (one per harness stage header / completed trial / run end).
export interface TimelineEvent {
  type: "meta" | "stage" | "trial" | "evidence-error" | "end";
  id?: string; state?: string; queuePos?: number; expectedTrials?: number; provider?: string; targetLabel?: string;
  scenario?: string; defender?: string; trial?: number;
  oracleAchieved?: boolean; disruption?: number; dwellSeconds?: number;
  mtdEffect?: string; observed?: string; commands?: string[]; defensiveActions?: number;
  scenarioRealism?: string; scenarioBenignControl?: boolean; scenarioClaimLimits?: string;
  functionalOracleStatus?: string;
  outcome?: TrialOutcome; outcomeReason?: string; claimClass?: "functional" | "security" | "control" | "calibration";
  measurementStatus?: string; measurementPhase?: string; validityReasons?: string[];
  reason?: string;
}
export type TrialOutcome = "test-failed" | "inconclusive" | "unverified" | "functional-pass" | "functional-fail" | "skipped" | "negative-control" | "security-landed" | "security-disrupted";
export interface DecisionActionStatus {
  action: string;
  status: string;
  exclusionKind?: string;
  reason?: string;
  scored?: boolean;
  rbacUnknown?: boolean;
}
export interface AttackDecisionEvidence {
  // Legacy fields remain optional so retained rows continue to decode.
  correlation?: "exact-event-uid" | "temporal-workload" | "temporal-workload-candidate" | string;
  time?: string;
  action?: string;
  reason?: string;
  selected?: boolean;
  actuated?: boolean;
  source?: "decision-trace-steered-event" | "generic-event-evidence" | "temporal-candidate" | string;
  eventName?: string;
  eventUid?: string;
  eventRule?: string;
  declaredSource?: string;
  trustVerdict?: string;
  creatorIdentity?: string;
  targetUid?: string;
  decisionId?: string;
  tickId?: string;
  brainImage?: string;
  gitSha?: string;
  policyNamespace?: string;
  policyName?: string;
  policyUid?: string;
  feasible?: boolean;
  infeasibleWhy?: string;
  dryRun?: boolean;
  dryRunCause?: string;
  actuationBrakeCause?: string;
  killSwitch?: boolean;
  killSwitchCause?: string;
  dispatchOutcome?: string;
  dispatchReason?: string;
  handler?: string;
  objectsTouched?: string[];
  rollbackRef?: string;
  mutationKind?: string;
  actionStatus?: DecisionActionStatus[];
}
export interface ReportMeta { id: string; title: string; group: string; exists: boolean; lines: number }
export interface AttackCost {
  valueAtRisk: number; without: number; r6: number; with: number; savings: number; note: string;
  // inputs behind the three totals, so the card can show the arithmetic
  nodeInstance?: string; nodeRatePerHr?: number;
  preventNone?: number; preventR6?: number; preventPhorvex?: number;
  ratesSource?: string; operatorCost?: number; r6Churn?: number;
}
export interface AttackResult {
  claim?: ClaimScope;
  id: string; firedAt: string; service: string; namespace: string; pod: string; defendedPod: string; deploy: string;
  attack: string; attackId: string; mitre: string; expectedActuator: string; stateful: boolean;
  status: "running" | "partial" | "done"; outcome: "DEFENDED" | "LANDED" | ""; phorvexAction: string; actuated: boolean; timeToDefendSec: number;
  outcomeClass?: "behavioral-oracle-unsupported" | "effect-only" | "effect-unverified" | string;
  evidenceKind?: "catalogue-signal" | "synthetic-detector-signal" | string;
  producerRoute?: string;
  resultSchemaVersion?: string;
  stimulusEvidence?: { kind: string; observed: boolean; targetUid: string; eventName: string; eventUid: string; eventCreatedAt: string; eventRule: string; correlation: string; behavioralExecuted: boolean; limitation: string };
  effectEvidence?: { kind: string; observed: boolean; observedAt?: string; targetUid: string; before?: string; after?: string; serviceUid?: string; correlation: string; limitation: string; seconds: number };
  decisionEvidence?: AttackDecisionEvidence;
  decisionTraceEvidence?: AttackDecisionEvidence[];
  temporalDecisionEvidence?: AttackDecisionEvidence;
  observationStartedAt?: string;
  observationDeadline?: string;
  responseObserved?: boolean;
  responseAction?: string;
  responsePod?: string;
  responseSeconds?: number;
  observationError?: string;
  dwellSec: number; dwellOngoing: boolean; containment: "evicted" | "contained" | "flushed" | "foothold-active" | "landed" | "";
  why: string; perDollar: number; stage: string; coveredFacts: number; pHold: number; lambda: number; r6Would: string; r6Note: string;
  uptimeBefore: number; uptimeDip: number; uptimeAfter: number; cost: AttackCost;
}
// --- Optimizer Bench: config sweep over the real p1-coverage engine (in-process, no live attack) ---
export interface BenchConfigInput {
  label: string;
  maxMovesPerTick: number;
  normSparsity: number;
  flowDisruption: number;
  weightSecrets: number;
  minAvailableReplicas: number;
  proactiveFloorSec: number;
  reactiveOnly: boolean;
  lambda: number;
  tickIntervalSec: number;
  antiOverRotationSec: number;
  enabledActions?: string[];
}
export interface BenchMove {
  pod: string; stateful: boolean; attacked: boolean; action: string; selected: boolean; feasible: boolean;
  infeasibleWhy: string; cost: number; coverage: number; coveredFacts: number; perDollar: number; stage: string;
  pHold: number; assetValue: number; blindCost: number; r6Would: string;
}
export interface BenchTemporalPoint { sec: number; phorvexCum: number; r6Cum: number; moves: number }
export interface BenchTemporal {
  horizonSec: number; tickSec: number; ticks: number; phorvexMoves: number; phorvexCost: number;
  phorvexByAction: Record<string, number>; r6IntervalSec: number; r6Moves: number; r6Cost: number;
  r6StatefulKills: number; savingsVsR6: number; series: BenchTemporalPoint[];
}
export interface BenchConfigResult {
  label: string; config: BenchConfigInput; moves: BenchMove[]; movesSelected: number; totalCoverage: number;
  totalCost: number; perDollar: number; ablationRatio: number; statefulRotated: boolean; phorvexMovesPerHour: number;
  optimalityRatio: number; optimalityGap: number; coversDisjoint: boolean; exactSkipped: boolean; swapRatio: number;
  temporal?: BenchTemporal;
}
export interface OptimizerProbeArm {
  name: string; greedyObjective: number; swapObjective: number; exactObjective: number;
  greedyRatio: number; swapRatio: number; greedyPicks: string[]; swapPicks: string[]; coversDisjoint: boolean;
  /** true => the fixture exceeded the brute-force cap, so NEITHER ratio was measured (PHVX-23). */
  exactSkipped: boolean;
}
export interface OptimizerProbe { b: number; lambda: number; shared: OptimizerProbeArm; disjoint: OptimizerProbeArm }
export interface BenchResult {
  claim?: ClaimScope;
  scenario: string; scenarioLabel: string; engine: string; pods: number; stateful: number; attacked: number;
  attackLandedRisk: number; r6BlindCost: number; r6DestroysStateful: number; r6BlindMovesPerHour: number;
  horizonSec: number; r6IntervalSec: number; computeMs: number; optimizerProbe: OptimizerProbe;
  configs: BenchConfigResult[]; note: string;
}
export interface CostScenario { scenario: string; avoidedBreach: number; disruptWithout: number; disruptBlind: number; disruptWith: number; defensiveActions: number; blindActions: number; responseCost: number; defenseCost: number; costWithout: number; costBlind: number; costWith: number; successNone: number; successBlind: number; successWith: number; savings: number; helps: boolean }
export interface NodePrice { instanceType: string; count: number; gpu: boolean; pricePerHr: number; estimated: boolean }
export interface ClusterPricing { provider: string; region: string; nodes: NodePrice[]; totalPerHr: number; totalPerYear: number; gpuPricePerHr: number; gpuCount: number; source: string; available: boolean }
export interface CostResult { available: boolean; scenarios: CostScenario[]; source?: string; runId?: string; totalWithout: number; totalBlind: number; totalWith: number; totalSavings: number; pricing?: ClusterPricing; valueAtRisk?: number; defenseOverhead?: number; operatorCost?: number; actuationCost?: number; actuationRatePerHr?: number; actuationPartial?: boolean; perActionCost?: number; overheadBasis?: string; note: string }
export interface CostTimePoint { time: string; unixMillis: number; phorvexCost: number; blindCost: number; savings: number; decisions: number }
export interface CostTimeseries { available: boolean; points: CostTimePoint[]; totalPhorvex: number; totalBlind: number; totalSavings: number; decisions: number; note: string; partial: boolean; coveredFrom?: string; coveredTo?: string }
// UPTIME (P-UPTIME) — MEASURED service availability vs the moments Phorvex acted.
export interface UptimePoint { t: string; pct: number }
export interface UptimeMarker { t: string; action: string }
export interface UptimeWorkload { ns: string; workload: string; kind: string; series: UptimePoint[]; markers: UptimeMarker[]; uptimePct: number; minPct: number; actuations: number; killingActs: number }
export interface UptimeStrategy { key: string; label: string; attackSuccess: number; disrupted: number; defensiveActions: number; trials: number }
export interface UptimeScenarioArm { key: string; label: string; attackSuccess: number; disrupted: number; dwell: number; defensiveActions: number; trials: number }
export interface UptimeScenario { scenario: string; category: string; arms: UptimeScenarioArm[] }
export interface UptimeResult { windowSeconds: number; workloads: UptimeWorkload[]; markerPartial?: boolean; strategies?: UptimeStrategy[]; scenarios?: UptimeScenario[]; strategiesSource?: string; strategiesRun?: string; note: string }
export interface RunEvidenceArm { defender: string; label: string; trials: number; disruption: CI; dwell: CI; oracleHitPct: number; defensiveActions: number; securityPerCost: number; evidenceRetention: number; mtdEffect: string; schwartauP: number; schwartauD: number; schwartauR: number; replaySuccess: number; replayAttempts: number }
export interface RunEvidenceTrial {
  scenario: string; defender: string; trial: number; skipped: boolean; oracleAchieved: boolean; disruption: number; dwell: number;
  defensiveActions: number; mtdEffect: string; observed: string; commands: string[];
  scenarioRealism?: string; scenarioBenignControl: boolean; scenarioClaimLimits?: string;
  functionalOracleStatus?: string;
  outcome: TrialOutcome; outcomeReason: string; claimClass: "functional" | "security" | "control" | "calibration";
  measurementStatus: string; measurementPhase: string; validityReasons: string[];
}
export interface RunEvidenceIssue { line: number; outcome: "unverified"; reason: string }
export interface FunctionalResult { outcome: TrialOutcome; summary: string; evidence: Record<string, string>; limits: string[]; cleanup: { attempted: boolean; verified: boolean; status: string; details?: Record<string, string>; unsafeToRetry?: boolean }; unsafeToRetry?: boolean; startedAt: string; finishedAt: string }
export interface NATSConfigurationResult { finding: "EXPOSED" | "NOT_EXPOSED_IN_THIS_CONTROL" | "UNKNOWN"; observedFinding: "EXPOSED" | "NOT_EXPOSED_IN_THIS_CONTROL" | "UNKNOWN"; accepted: boolean; remoteStatus: string; remotePodUID?: string; brokerPodUID?: string; legitimateAcked: boolean; storedPayloadSHA256?: string; streamCleanup: string; observerCleanup: string; fixtureResourcesCleanup: string; brainMode: "NO_SIGNAL"; securityEfficacy: "NOT_EVALUATED"; sourceAttestation: string; issues?: string[] }
export interface NATSResponseDecisionTrace {
  schema: string;
  runId: string;
  namespaceUID: string;
  clientPodUID: string;
  policyUID: string;
  policyGeneration: number;
  managerPodUID: string;
  managerContainerID: string;
  m0ReceiptSHA256: string;
  peerM0ReceiptSHA256: string;
  decisionId: string;
  tickId: string;
  eventName: string;
  eventUID: string;
  decisionTraceSHA256: string;
  brainImage: string;
  brainImageSHA256: string;
  gitSHA: string;
  inputPhase: string;
  inputStage: string;
  pHold: { present: boolean; value: number };
  threatPosture: { present: boolean; value: number };
  sloHeadroom: { present: boolean; value: number };
  facts: { type: string; weight: number; source: string; coveredBefore: boolean }[];
  candidates: { action: string; marginalCoverage: { present: boolean; value: number }; expectedCost: { present: boolean; value: number }; netGain: { present: boolean; value: number }; feasible: { present: boolean; value: boolean }; selected: boolean; exclusion: string }[];
  actionStatus: { action: string; status: string; exclusionKind: string; reason: string; scored: boolean; rbacUnknown: boolean }[];
  selectedAction: string;
  noopReason: string;
  dispatchOutcome: string;
  dispatchReason: string;
  objectEffect?: { generatedEventName: string; generatedEventUID: string; operationID: string; amtdName: string; amtdUID: string; phoenixNetworkPolicyName: string; phoenixNetworkPolicyUID: string; sourcePodUID: string; peerPodUID: string };
  claim: string;
}
export interface NATSResponseResult {
  accepted: boolean;
  cleanupVerified: boolean;
  m0Status: string;
  signalStatus: string;
  decisionStatus: string;
  selectedAction: string;
  dispatchOutcome: string;
  effectStatus: string;
  m1Status: string;
  peerStatus: string;
  cleanupStatus: string;
  capacityReservationStatus: "UNKNOWN" | "NOT_APPLICABLE" | "UNRECONCILED_POSSIBLE";
  repeatability: "UNKNOWN" | "NOT_EVALUATED";
  securityEfficacy: "NOT_EVALUATED" | "CONTAINMENT_NOT_ACHIEVED";
  decisionTrace?: NATSResponseDecisionTrace;
  issues: string[];
}
export interface RunEvidence { id: string; scenario: string; date: string; finished: string; namespace: string; state: string; arms: RunEvidenceArm[]; trials: RunEvidenceTrial[]; issues: RunEvidenceIssue[]; functionalResult?: FunctionalResult; configurationResult?: NATSConfigurationResult; natsResponseResult?: NATSResponseResult; note: string }

export interface LiveHistoryPage {
  events: { id: string; event: any }[];
  nextCursor?: string;
  partial: boolean;
  notice: string;
  projection: string;
  scannedBytes: number;
}

// liveStream opens the SSE decision stream (per-lens projected server-side). Returns a
// cleanup fn. Each message is the per-lens payload (full Record for investor/operator;
// OwnerEvent for owner).
export function liveStream(lens: Lens, onEvent: (data: any) => void, tenant?: string, tail = 80, context = "", onError?: (error: Error) => void): () => void {
  // tail=N: replay only the last N decisions on connect (avoids the "fast train" flood after the
  // operator has run for hours), then tail live. tail=0 replays the whole audit (opt-in).
  // context=<kubeconfig context>: SCOPE the stream to that provider's operator audit (EKS vs vCluster).
  //
  // [M-136] EventSource cannot set headers, so the browser authenticates this stream the same way
  // it authenticates every other request: with the ALB session it already carries
  // (withCredentials). No token is ever put in this URL. ?lens= and ?tenant= are a projection
  // hint and a tenant SELECTION — the server narrows both to the caller's grant, so an unscoped
  // or mismatched value streams nothing rather than everything.
  const es = new EventSource(
    `${API_BASE}/api/live?lens=${lens}&tail=${tail}${tenant ? `&tenant=${encodeURIComponent(tenant)}` : ""}${context ? `&context=${encodeURIComponent(context)}` : ""}`,
    { withCredentials: true },
  );
  es.onmessage = (e) => { try { onEvent(JSON.parse(e.data)); } catch {} };
  if (onError) es.onerror = () => onError(new Error("Decision stream connection failed"));
  return () => es.close();
}

// runStream opens the per-run attack-timeline SSE: stage headers, completed trials (with the
// attacker's command steps + outcome), and a final "end" event. Returns a cleanup fn.
export function runStream(id: string, lens: Lens, onEvent: (e: TimelineEvent) => void): () => void {
  const es = new EventSource(`${API_BASE}/api/runs/stream?id=${encodeURIComponent(id)}&lens=${lens}`, { withCredentials: true });
  es.onmessage = (e) => { try { onEvent(JSON.parse(e.data)); } catch {} };
  return () => es.close();
}

// ---- live-attack monitoring (before / during / after) ----
export interface MonPoint { t: string; offsetSec: number; ready: number; desired: number; pct: number; phase: "before" | "during" | "after" }
export interface MonPhase { samples: number; meanPct: number; minPct: number; complete: boolean }
export interface DowntimeCost { replicaSeconds: number; nodeRatePerHr: number; dollars: number; basis: string }
export interface AttackMonitoring {
  id: string; firedAt: string; service: string; namespace: string; workload: string;
  attack: string; attackId: string; outcome: string; phorvexAction: string;
  before: MonPhase; during: MonPhase; after: MonPhase;
  recoveredSec: number; impacted: boolean; series: MonPoint[]; downtime: DowntimeCost; note: string;
}
export interface AttackMonitoringResult {
  attacks: AttackMonitoring[]; sampleInterval: number; preWindowSec: number; postWindowSec: number; note: string;
}

// ---- three-arm availability comparison ----
export interface ArmResult {
  arm: string; label: string; samples: number; meanPct: number; minPct: number;
  dipCount: number; secondsDegraded: number; replicaSeconds: number; downtimeUsd: number;
  attackerStopped: "yes" | "no" | "unknown"; verdict: string; complete: boolean;
  responseObserved: boolean;
}
export interface ArmRun {
  operation?: string; runAt: string; namespace: string; deploy: string; attack: string;
  nodeRatePerHr: number; arms: ArmResult[];
}
export interface ArmsJob {
  namespace: string; deploy: string; attack: string; startedAt: string;
  phase: "arm-a" | "arm-b" | "arm-c" | "done" | "failed"; detail: string; progress: number; error?: string;
}
export interface AvailabilityArms {
  running: ArmsJob[]; runs: ArmRun[]; available: boolean; note: string; howItRan: string; whyNoDrop: string;
}
