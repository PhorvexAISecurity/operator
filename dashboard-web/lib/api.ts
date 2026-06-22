// Phorvex Console — typed client for the Go data backend (proxied at /api).
// The lens header is sent server-side; the owner lens is gated by the backend.

export type Lens = "investor" | "operator" | "owner";

export interface CI { mean: number; lo: number; hi: number; n: number }
export interface Stat {
  key: string; label: string; value: string; unit?: string;
  ci?: CI; source: string; status: "real" | "modeled" | "pending"; product: "k8s" | "ai" | "both"; note?: string;
}
export interface FrontierRow {
  arm: string; interval: string;
  prevention: CI; harm: CI; infeasible: CI; win: string;
}
export interface OwnerEvent {
  tenant: string; namespace: string; pod: string; action: string; actuated: boolean; dryRun: boolean;
  handler?: string; objectsTouched?: string[]; reversible: boolean; attackPrevented: boolean;
  workPreserved: boolean; harmCaused: boolean; sloKept: boolean; attackStage: string; why: string; blindOutcome: string;
}
export interface ArmResult { defender: string; trials: number; disruption: number; dwellMean: number }
export interface RunStatus {
  id: string; config: string; state: "running" | "done" | "error" | "stopped"; started: string;
  date?: string; finished?: string; namespace?: string; target?: string; provider?: string; targetLabel?: string;
  trials: number; expectedTrials?: number; arms?: ArmResult[]; error?: string; nativeActuator: boolean;
}
export interface Suite { Name: string; Desc: string }

// API base: empty = same-origin (the single Go binary serves the SPA + /api on one port).
// For `next dev`, set NEXT_PUBLIC_API_BASE=http://localhost:8090 (CORS is allowed).
export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "";

async function get<T>(path: string, lens: Lens): Promise<T> {
  let r: Response;
  try {
    r = await fetch(API_BASE + path, { headers: { "X-Phorvex-Lens": lens }, cache: "no-store" });
  } catch {
    throw new Error("BACKEND_UNREACHABLE");
  }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  return r.json();
}
async function post<T>(path: string, body: unknown, lens: Lens): Promise<T> {
  let r: Response;
  try {
    r = await fetch(API_BASE + path, {
      method: "POST", headers: { "X-Phorvex-Lens": lens, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error("BACKEND_UNREACHABLE");
  }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  return r.json();
}

export interface CatalogItem { name: string; product: "k8s" | "ai" | "structural"; category: string; r6Tag: string; techniques: string[]; caps: string[]; hasRun: boolean }
export interface BenchArm { defender: string; disruption: CI; dwell: CI; harmRate: CI; trials: number }
export interface BenchGroup { scenario: string; source: string; arms: BenchArm[] }
export interface CoverageTechnique { technique: string; scenarios: string[]; product: string; covered: boolean }
export interface PostureSub { label: string; score: number; basis: string }
export interface Posture { grade: string; score: number; subs: PostureSub[]; note: string }
export interface OwnerRollup { actions: number; attacksPrevented: number; workPreserved: number; sloKept: number }

// --- P-VCLUSTER Pass 2: the safe apply-fix write-path client ---
export interface ApplyFixDelta {
  normSparsity?: number;
  flowDisruption?: number;
  maxMovesPerTick?: number;
  proactiveFloorSec?: number;
}
// AFIdentity: OIDC token (Bearer) when configured; else demo-trust ?user=&tenant= for local click-through.
export interface AFIdentity { user: string; tenant: string; token?: string }
export interface GatePreview { pass: boolean; reason: string }
export interface AFPending { id: string; tenant: string; namespace: string; requester: string; reason: string; deltaHash: string }
export interface AFAuditEntry { event: string; fields: Record<string, any> }

function withIdentity(path: string, id: AFIdentity): string {
  if (id.token) return path; // OIDC: identity is in the Authorization header, never the URL
  const q = new URLSearchParams();
  if (id.user) q.set("user", id.user);
  if (id.tenant) q.set("tenant", id.tenant);
  const s = q.toString();
  return path + (s ? (path.includes("?") ? "&" : "?") + s : "");
}
async function afFetch<T>(method: string, path: string, id: AFIdentity, lens: Lens, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-Phorvex-Lens": lens };
  if (body) headers["Content-Type"] = "application/json";
  if (id.token) headers["Authorization"] = "Bearer " + id.token; // OIDC verified identity
  let r: Response;
  try {
    r = await fetch(API_BASE + withIdentity(path, id), { method, headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store" });
  } catch { throw new Error("BACKEND_UNREACHABLE"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e: any = new Error(data.error || `HTTP ${r.status}`); e.status = r.status; throw e; }
  return data as T;
}
export const applyFixApi = {
  gatePreview: (delta: ApplyFixDelta, id: AFIdentity, lens: Lens) =>
    afFetch<GatePreview>("POST", "/api/apply-fix/gate-preview", id, lens, { delta }),
  submit: (reqId: string, delta: ApplyFixDelta, reason: string, id: AFIdentity, lens: Lens) =>
    afFetch<{ status: string; id: string; note: string }>("POST", "/api/apply-fix/submit", id, lens, { id: reqId, delta, reason }),
  approve: (reqId: string, id: AFIdentity, lens: Lens) =>
    afFetch<{ status: string; id: string }>("POST", "/api/apply-fix/approve", id, lens, { id: reqId }),
  pending: (id: AFIdentity, lens: Lens) =>
    afFetch<{ pending: AFPending[]; applierMode: string }>("GET", "/api/apply-fix/pending", id, lens),
  audit: (id: AFIdentity, lens: Lens) =>
    afFetch<{ audit: AFAuditEntry[] }>("GET", "/api/apply-fix/audit", id, lens),
};

export const api = {
  health: (lens: Lens = "operator") => get<any>("/api/health", lens),
  effectiveness: (lens: Lens) => get<{ stats: Stat[] }>("/api/effectiveness", lens),
  frontier: (lens: Lens) => get<{ rows: FrontierRow[] }>("/api/frontier", lens),
  suites: (lens: Lens) => get<{ suites: Suite[] }>("/api/suites", lens),
  // owner endpoints are tenant-scoped: the owner lens MUST pass its tenant (the backend fail-closes
  // on an empty tenant to prevent cross-tenant leak). ownerTenants lists the selectable tenants.
  ownerEvents: (lens: Lens, tenant?: string) => get<{ events: OwnerEvent[]; empty: boolean; rollup: OwnerRollup; note: string }>(`/api/owner/events${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ""}`, lens),
  ownerTenants: (lens: Lens) => get<{ tenants: string[] }>("/api/owner/tenants", lens),
  reports: (lens: Lens) => get<{ reports: ReportMeta[] }>("/api/reports", lens),
  cost: (lens: Lens) => get<CostResult>("/api/cost", lens),
  costTimeseries: (lens: Lens) => get<CostTimeseries>("/api/cost-timeseries", lens),
  report: (id: string, lens: Lens) => get<{ id: string; title: string; content: string }>(`/api/reports?id=${encodeURIComponent(id)}`, lens),
  startRun: (config: string, nativeActuator: boolean, lens: Lens) =>
    post<{ id: string }>("/api/runs/start", { config, nativeActuator, startedAt: new Date().toLocaleTimeString() }, lens),
  runStatus: (id: string, lens: Lens) => get<RunStatus>(`/api/runs/status?id=${id}`, lens),
  runsList: (lens: Lens) => get<{ runs: RunStatus[] }>("/api/runs/list", lens),
  stopRun: (id: string, lens: Lens) => post<{ status: string; id: string }>("/api/runs/stop", { id }, lens),
  runEvidence: (id: string, lens: Lens) => get<RunEvidence>(`/api/runs/evidence?id=${encodeURIComponent(id)}`, lens),
  catalog: (lens: Lens) => get<{ items: CatalogItem[] }>("/api/catalog", lens),
  benchmarks: (lens: Lens) => get<{ groups: BenchGroup[] }>("/api/benchmarks", lens),
  threatMatrix: (lens: Lens) => get<{ techniques: CoverageTechnique[] }>("/api/threat-matrix", lens),
  posture: (lens: Lens) => get<Posture>("/api/posture", lens),
  rawlog: (path: string, lens: Lens) => get<{ log: string }>(`/api/rawlog?path=${encodeURIComponent(path)}`, lens),
  targets: (lens: Lens) => get<{ targets: ClusterTarget[] }>("/api/targets", lens),
  // workloads enumerates the REAL workloads on the selected cluster (live get/list — read-only).
  workloads: (target: string, lens: Lens) =>
    get<{ context: string; namespaces: WorkloadNS[] }>(`/api/workloads${target ? `?target=${encodeURIComponent(target)}` : ""}`, lens),
  // capabilities reports live cluster GPU/MIG/multi-node so the UI gates only genuinely-unmet scenarios.
  capabilities: (target: string, lens: Lens) =>
    get<{ gpu: boolean; mig: boolean; multiNode: boolean; nodes: number; gpuCount: number }>(`/api/capabilities${target ? `?target=${encodeURIComponent(target)}` : ""}`, lens),
  startScenario: (scenario: string, withPX: boolean, target: string, namespace: string, lens: Lens) =>
    post<{ id: string }>("/api/runs/scenario", { scenario, withPX, target, namespace, startedAt: new Date().toLocaleTimeString() }, lens),
  // scan execs `phorvex --scan` LIVE (fresh exec each call — not a cached corpus). ns="" scans all
  // namespaces; context targets a specific kubeconfig context (the selected environment).
  scan: (ns: string, lens: Lens, context?: string) => {
    const q = new URLSearchParams();
    if (ns) q.set("ns", ns);
    if (context) q.set("context", context);
    const s = q.toString();
    return get<ScanResult>(`/api/scan${s ? `?${s}` : ""}`, lens);
  },
  ablation: (ns: string, lens: Lens) => get<AblationResult>(`/api/ablation${ns ? `?ns=${encodeURIComponent(ns)}` : ""}`, lens),
  cluster: (lens: Lens) => get<{ policies: PolicyView[]; available: boolean; note: string }>("/api/cluster", lens),
  handlers: (lens: Lens) => get<RegistryView>("/api/handlers", lens),
  matrix: (lens: Lens) => get<MatrixResult>("/api/matrix", lens),
  aiSurface: (lens: Lens) => get<AISurface>("/api/ai-surface", lens),
  metrics: (lens: Lens) => get<MetricsResult>("/api/metrics", lens),
  // Red-team READ endpoints (previously backend-only; now wired). run/continuous/live trigger compute /
  // need a real cluster — surfaced as [PENDING] actions, not auto-run.
  redteamFindings: (lens: Lens) => get<{ findings: RTFinding[] }>("/api/redteam/findings", lens),
  redteamGates: (lens: Lens) => get<{ gates: RTGate[]; allPass: boolean; ranAt: string }>("/api/redteam/gates", lens),
  redteamCampaigns: (lens: Lens) => get<{ campaigns: RTCampaign[] }>("/api/redteam/campaigns", lens),
  // clearLive empties the live decision-audit the SSE replays (operator-only write).
  clearLive: (lens: Lens) => post<{ cleared: boolean; note?: string }>("/api/live/clear", {}, lens),
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
export interface ScanResult { platform: string; nodes: number; pods: number; witness: PhysWitness[]; killchain: KillchainRow[]; graphNodes: GraphNode[]; graphEdges: GraphEdge[]; emr: { baseline: number; scarcity: number; lift: number; note: string }; raw: string }
export interface PolicyView { name: string; namespace: string; tenant: string; mode: string; spec: any; status: any }
export interface ClusterTarget { id: string; context: string; label: string; provider: string; runnable: boolean; note: string }
// Live workloads (P-DASHBOARD-LIVE): the real controllers running on the selected cluster.
export interface Workload { kind: string; name: string; replicas: number; ready: number; images: string[]; selector: Record<string, string> }
export interface WorkloadNS { namespace: string; system: boolean; podCount: number; workloads: Workload[] }
// Attack-timeline SSE event (one per harness stage header / completed trial / run end).
export interface TimelineEvent {
  type: "meta" | "stage" | "trial" | "end";
  id?: string; state?: string; expectedTrials?: number; provider?: string; targetLabel?: string;
  scenario?: string; defender?: string; trial?: number;
  oracleAchieved?: boolean; disruption?: number; dwellSeconds?: number;
  mtdEffect?: string; observed?: string; commands?: string[]; defensiveActions?: number;
}
export interface ReportMeta { id: string; title: string; group: string; exists: boolean; lines: number }
export interface CostScenario { scenario: string; avoidedBreach: number; disruptWithout: number; disruptWith: number; defenseCost: number; costWithout: number; costWith: number; savings: number; helps: boolean }
export interface NodePrice { instanceType: string; count: number; gpu: boolean; pricePerHr: number; estimated: boolean }
export interface ClusterPricing { provider: string; region: string; nodes: NodePrice[]; totalPerHr: number; totalPerYear: number; gpuPricePerHr: number; gpuCount: number; source: string; available: boolean }
export interface CostResult { available: boolean; scenarios: CostScenario[]; totalWithout: number; totalWith: number; totalSavings: number; pricing?: ClusterPricing; valueAtRisk?: number; defenseOverhead?: number; overheadBasis?: string; note: string }
export interface CostTimePoint { time: string; unixMillis: number; phorvexCost: number; blindCost: number; savings: number; decisions: number }
export interface CostTimeseries { available: boolean; points: CostTimePoint[]; totalPhorvex: number; totalBlind: number; totalSavings: number; decisions: number; note: string }
export interface RunEvidenceArm { defender: string; label: string; trials: number; disruption: CI; dwell: CI; oracleHitPct: number; defensiveActions: number; securityPerCost: number; evidenceRetention: number; mtdEffect: string; schwartauP: number; schwartauD: number; schwartauR: number; replaySuccess: number; replayAttempts: number }
export interface RunEvidenceTrial { defender: string; trial: number; skipped: boolean; oracleAchieved: boolean; disruption: number; dwell: number; defensiveActions: number; mtdEffect: string; observed: string; commands: string[] }
export interface RunEvidence { id: string; scenario: string; date: string; finished: string; namespace: string; state: string; arms: RunEvidenceArm[]; trials: RunEvidenceTrial[]; note: string }

// liveStream opens the SSE decision stream (per-lens projected server-side). Returns a
// cleanup fn. Each message is the per-lens payload (full Record for investor/operator;
// OwnerEvent for owner).
export function liveStream(lens: Lens, onEvent: (data: any) => void, tenant?: string, tail = 80): () => void {
  // tail=N: replay only the last N decisions on connect (avoids the "fast train" flood after the
  // operator has run for hours), then tail live. tail=0 replays the whole audit (opt-in).
  const es = new EventSource(`${API_BASE}/api/live?lens=${lens}&tail=${tail}${tenant ? `&tenant=${encodeURIComponent(tenant)}` : ""}`);
  // NOTE: EventSource cannot send headers; the lens is passed as a query param the backend
  // also honors. (Demo-trust; real authn is [PENDING-P-VCLUSTER].)
  es.onmessage = (e) => { try { onEvent(JSON.parse(e.data)); } catch {} };
  return () => es.close();
}

// runStream opens the per-run attack-timeline SSE: stage headers, completed trials (with the
// attacker's command steps + outcome), and a final "end" event. Returns a cleanup fn.
export function runStream(id: string, lens: Lens, onEvent: (e: TimelineEvent) => void): () => void {
  const es = new EventSource(`${API_BASE}/api/runs/stream?id=${encodeURIComponent(id)}&lens=${lens}`);
  es.onmessage = (e) => { try { onEvent(JSON.parse(e.data)); } catch {} };
  return () => es.close();
}
