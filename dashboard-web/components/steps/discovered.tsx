"use client";
import * as React from "react";
import { Lens, GraphEdge, NodeInfo } from "@/lib/api";
import { StepId } from "@/lib/journey";
import { useSelectedTarget } from "@/lib/provider-store";
import { useOwnerTenant } from "@/lib/owner";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Segmented, Empty, ErrorBox, ReadStatus } from "@/components/ui/more";
import { StepHead } from "./shared";
import { PhysicsPanel } from "@/components/subsystems/panels";
import { Gem, Network, GitBranch, ArrowRight, Loader2 } from "lucide-react";
import { useLocalPage } from "@/lib/use-local-page";
import { PaginationBar } from "@/components/ui/pagination";
import { DEFAULT_SNAPSHOT_LIMIT } from "@/lib/audit-snapshot";
import { useAuditSnapshot, useScanSnapshot } from "@/lib/query";
import { useScopedUIState } from "@/lib/use-scoped-ui-state";
import { DiscoveredPod, StageGroup, projectDiscoveredPods, stageGroup } from "@/lib/discovered-projection";

type PodNode = DiscoveredPod;

export function DiscoveredStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const sel = useSelectedTarget();
  const { tenant } = useOwnerTenant(lens);
  const scopeKey = `${lens}\u0000${sel.context}\u0000${tenant}`;
  const [tab, setTab] = useScopedUIState<"graph" | "jewels" | "killchain" | "physics">(`discovered-tab\u0000${scopeKey}`, "graph");
  const [listQuery, setListQuery] = useScopedUIState(`discovered-filter\u0000${scopeKey}`, "");
  const scanQuery = useScanSnapshot(lens, sel.context, "", lens !== "owner");
  const scan = scanQuery.data;
  const expectedPods = React.useMemo(() => (scan?.graphNodes ?? []).filter((node) => !!node.uid).map((node) => ({ key: node.key, uid: node.uid! })), [scan?.graphNodes]);
  // Discovered is the one fleet-wide view: it needs a decision for EVERY scanned Pod, not for the
  // handful of workloads that dominate the audit. Policies tick independently, so a busy tenant can
  // emit thousands of decisions while a quiet one emits a few — a fixed 80-record replay reaches
  // only the busy ones and leaves the rest with no stage and no asset value. Scale the replay with
  // the fleet and retain one row per scanned Pod, with a ceiling so a large cluster still loads.
  const auditSample = React.useMemo(() => ({
    tail: Math.min(4000, Math.max(DEFAULT_SNAPSHOT_LIMIT, expectedPods.length * 12)),
    limit: Math.max(DEFAULT_SNAPSHOT_LIMIT, expectedPods.length),
  }), [expectedPods.length]);
  const auditQuery = useAuditSnapshot(lens, sel.context, lens === "owner" ? tenant : "", 2500, lens !== "owner" || !!tenant, lens !== "owner", expectedPods, auditSample);
  const edges = scan?.graphEdges ?? [];
  const nodes = scan?.nodeList ?? [];
  const reportedNodeCount = typeof scan?.nodes === "number" ? scan.nodes : null;

  const pods = React.useMemo(() => projectDiscoveredPods(scan?.graphNodes ?? [], auditQuery.data ?? []), [scan?.graphNodes, auditQuery.data]);
  const scannedPods = pods.filter((p) => p.source === "scan");

  const scoped = true;
  const visibleNodes = scoped ? nodes : [];
  const visibleEdges = scoped ? edges : [];
  const visibleNodeCount = scoped ? reportedNodeCount : null;
  const visibleError = scoped && scanQuery.error ? String((scanQuery.error as Error).message || scanQuery.error) : "";
  const streamSettled = lens === "owner" && !tenant ? true : !!auditQuery.data || !!auditQuery.error;
  const loading = (lens !== "owner" && !scan && scanQuery.isPending) || !streamSettled;
  const scanPhase = lens === "owner" ? "Owner view" : scanQuery.isFetching && !scan ? "Scanning nodes" : visibleError ? "Scan error" : `${visibleNodes.length} nodes listed${scanQuery.dataUpdatedAt ? ` · snapshot ${new Date(scanQuery.dataUpdatedAt).toISOString().slice(11, 16)} UTC` : ""}`;
  const evidencePhase = !scoped || !streamSettled ? "Loading decision evidence" : auditQuery.data?.length ? `${auditQuery.data.length} decision records sampled` : "No decision evidence in bounded sample";
  const query = listQuery.trim().toLowerCase();
  const matchingPods = pods.filter((p) => !query || p.key.toLowerCase().includes(query));
  const matchingNodes = visibleNodes.filter((n) => !query || n.name.toLowerCase().includes(query));
  const podPage = useLocalPage(matchingPods, 12, `${scopeKey}\u0000${tab}\u0000${listQuery}`);
  const nodePage = useLocalPage(matchingNodes, 12, `${scopeKey}\u0000${listQuery}`);

  if (loading && pods.length === 0 && visibleNodes.length === 0) return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={3} title="Discovered" sub="Mapping your platform…" lens={lens} />
      <div role="status" className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
        <div className="rounded-md border border-border/60 px-3 py-3">{lens !== "owner" && (!scoped || (scanQuery.isFetching && !scan)) && <Loader2 className="mr-2 inline h-3.5 w-3.5 animate-spin" />}<span className="font-medium text-foreground">Scan:</span> {scanPhase}</div>
        <div className="rounded-md border border-border/60 px-3 py-3">{(!scoped || !streamSettled) && <Loader2 className="mr-2 inline h-3.5 w-3.5 animate-spin" />}<span className="font-medium text-foreground">Evidence:</span> {evidencePhase}</div>
      </div>
      <div className="text-center text-xs text-muted-foreground">Selected target: {sel.label || sel.context || "current context"}</div>
    </div>
  );

  const owner = lens === "owner";
  const jewels = [...pods].sort((a, b) => a.asset == null ? (b.asset == null ? 0 : 1) : b.asset == null ? -1 : b.asset - a.asset);

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={3} title="Discovered" sub={owner ? "The tenant-scoped workloads present in bounded decision evidence." : "What the selected target's fresh scan and bounded decision evidence returned — physical nodes remain distinct from the workload graph."} lens={lens} />

      <div role="status" className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
        <div className="rounded-md border border-border/60 px-3 py-2"><span className="font-medium text-foreground">Scan:</span> {scanPhase}</div>
        <div className="rounded-md border border-border/60 px-3 py-2"><span className="font-medium text-foreground">Evidence:</span> {evidencePhase}</div>
      </div>

      {!owner && <Button disabled={scanQuery.isFetching || auditQuery.isFetching} onClick={() => { void scanQuery.refetch(); void auditQuery.refetch(); }}>Refresh scan and decisions</Button>}

      {visibleError && <div className="space-y-2"><ErrorBox msg={`The scan request failed: ${visibleError}. Decision-stream workloads are still shown when available.`} /><Button onClick={() => void scanQuery.refetch()}>Retry scan</Button></div>}
      {(lens !== "owner" || tenant) && <ReadStatus error={auditQuery.error} hasData={false} refreshing={auditQuery.isFetching} onRetry={() => void auditQuery.refetch()} />}
      {loading && pods.length > 0 && <div role="status" className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Partial discovery shown while remaining evidence loads…</div>}

      {(pods.length > 0 || visibleNodes.length > 0) && <input value={listQuery} onChange={(e) => setListQuery(e.target.value)} placeholder="Search workload or node…" aria-label="Search discovered workloads and nodes" className="w-full max-w-sm rounded-md border border-border bg-panel px-3 py-2 text-sm focus:outline-none" />}

      {pods.length === 0 && (owner || visibleNodes.length === 0) ? (
        <div className="space-y-3">
          <Empty msg={owner && !tenant ? "No concrete owner tenant is selected yet; tenant-scoped discovery cannot be read until one is available." : visibleError ? "No decision-stream workloads were available, and the live scan failed. Retry discovery after checking access to the selected target." : "No discovered workload evidence was returned for the selected target."} />
          {(lens !== "owner" || tenant) && <div className="flex justify-center"><Button onClick={() => void (lens === "owner" ? auditQuery.refetch() : scanQuery.refetch())}>Retry discovery</Button></div>}
        </div>
      ) : owner ? (
        <Card><CardContent className="p-5">
          <div className="mb-3 text-[11px] uppercase tracking-wider text-muted-foreground">Your protected workloads ({pods.length})</div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {podPage.pageItems.map((p) => <div key={p.key} className="flex items-center gap-2 rounded-md border border-border/50 px-3 py-2 font-mono text-[13px]"><Network className="h-3.5 w-3.5 text-primary" />{p.key}</div>)}
          </div>
          {matchingPods.length === 0 ? <div className="text-xs text-muted-foreground">No workloads match this search.</div> : <div className="mt-3"><PaginationBar page={podPage.page} pageSize={12} total={matchingPods.length} hasNext={podPage.hasNext} onPrevious={() => podPage.setPage((p) => Math.max(0, p - 1))} onNext={() => podPage.setPage((p) => p + 1)} /></div>}
        </CardContent></Card>
      ) : (
        <>
          <Card><CardContent className="p-4">
            <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Physical cluster nodes ({visibleNodes.length}{visibleNodeCount !== null ? ` of ${visibleNodeCount}` : ""})</div>
            {visibleNodes.length === 0 ? <div className="text-xs text-muted-foreground">No physical nodes were listed.</div> : matchingNodes.length === 0 ? <div className="text-xs text-muted-foreground">No physical nodes match this search.</div> : (
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">{nodePage.pageItems.map((n) => (
                <div key={n.name} className="rounded-md border border-border/60 px-3 py-2">
                  <div className="truncate font-mono text-xs" title={n.name}>{n.name}</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">{typeof n.allocCPUm === "number" ? `${(n.allocCPUm / 1000).toFixed(1)} CPU` : "CPU —"} · {typeof n.allocMemMi === "number" ? `${(n.allocMemMi / 1024).toFixed(1)} GiB` : "memory —"} · {typeof n.allocGPU === "number" ? n.allocGPU : "—"} GPU{typeof n.migKinds === "number" ? ` · ${n.migKinds} MIG kind` : ""}</div>
                </div>
              ))}</div>
            )}
            {matchingNodes.length > 0 && <div className="mt-3"><PaginationBar page={nodePage.page} pageSize={12} total={matchingNodes.length} hasNext={nodePage.hasNext} onPrevious={() => nodePage.setPage((p) => Math.max(0, p - 1))} onNext={() => nodePage.setPage((p) => p + 1)} /></div>}
            <div className="mt-2 text-[11px] text-muted-foreground">Workloads listed: {pods.length}</div>
          </CardContent></Card>
          <Segmented value={tab} onChange={setTab} tabs={[{ id: "graph", label: "Blast-radius graph" }, { id: "jewels", label: "Crown jewels", count: jewels.filter(j => j.source === "scan" && j.asset != null && j.asset > 0).length }, { id: "killchain", label: "Kill-chain" }, { id: "physics", label: "Physics (scan)" }]} />
          {tab === "graph" && <BlastGraph pods={scannedPods} edges={visibleEdges} />}
          {tab === "jewels" && <CrownJewels jewels={query ? jewels.filter((j) => j.key.toLowerCase().includes(query)) : jewels} scopeKey={`${scopeKey}\u0000${listQuery}`} />}
          {tab === "killchain" && <KillChain pods={scannedPods} />}
          {/* Physics is the platform scan — always all namespaces (ns="") so it shows the
              per-pod scan response, independent of the bounded decision stream. */}
          {tab === "physics" && <PhysicsPanel lens={lens} ns="" />}
        </>
      )}
      {(pods.length > 0 || visibleNodes.length > 0) && <div className="pt-1"><button onClick={() => go("protect")} className="inline-flex items-center gap-1.5 text-[13px] text-primary hover:underline">Now protect these workloads <ArrowRight className="h-3.5 w-3.5" /></button></div>}
    </div>
  );
}

function BlastGraph({ pods, edges }: { pods: PodNode[]; edges: GraphEdge[] }) {
  const cols: StageGroup[] = ["recon", "exploit", "lateral", "impact", "ai", "other", "unknown"];
  const W = 1120, H = 380, colW = W / cols.length;
  // Grid-pack nodes within each observed stage group. Missing and AI stages have
  // their own columns, so neither is represented as reconnaissance.
  const placed = pods.map((p) => {
    const c = cols.indexOf(stageGroup(p.stage));
    const inCol = pods.filter((q) => stageGroup(q.stage) === cols[c]);
    const idx = inCol.indexOf(p);
    const n = inCol.length;
    const rows = Math.max(1, Math.ceil(Math.sqrt(n * (H - 70) / colW)));
    const subCols = Math.ceil(n / rows);
    const r0 = idx % rows, c0 = Math.floor(idx / rows);
    const x = colW * c + (colW / (subCols + 1)) * (c0 + 1);
    const y = 48 + ((H - 64) / (rows + 1)) * (r0 + 1);
    const r = p.asset == null ? 6 : n > 8 ? 5 + Math.min(9, p.asset * 7) : 10 + Math.min(22, p.asset * 9);
    return { ...p, x, y, r };
  });
  const pos = new Map(placed.map((p) => [p.key, p]));
  // only draw edges whose BOTH endpoints are placed nodes (the visible reachability set).
  const drawn = edges.filter((e) => pos.has(e.src) && pos.has(e.dst) && e.src !== e.dst);
  return (
    <Card><CardContent className="p-2">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full">
        <defs>
          <marker id="px-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="hsl(184 78% 46% / 0.55)" />
          </marker>
        </defs>
        {cols.map((c, i) => (
          <g key={c}>
            <text x={colW * i + colW / 2} y={24} textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>{c === "unknown" ? "stage not sampled" : c}</text>
            <line x1={colW * (i + 1)} y1={40} x2={colW * (i + 1)} y2={H - 20} stroke="hsl(222 18% 16%)" strokeDasharray="3 5" />
          </g>
        ))}
        {/* reachability edges (network + RBAC + co-location), drawn under the nodes */}
        {drawn.map((e, i) => {
          const a = pos.get(e.src)!, b = pos.get(e.dst)!;
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="hsl(184 78% 46% / 0.28)" strokeWidth={1} markerEnd="url(#px-arrow)" />;
        })}
        {placed.map((p) => (
          <g key={p.key}>
            <title>{p.key} · asset {p.asset == null ? "unknown" : p.asset.toFixed(2)} · stage {p.stage ?? "not sampled"} · blast {p.blast == null ? "unknown" : p.blast.toFixed(2)}{p.ai ? " · AI" : ""}</title>
            <circle cx={p.x} cy={p.y} r={p.r + (placed.length > 8 ? 4 : 8) + (p.blast ?? 0) * (placed.length > 8 ? 6 : 10)} fill="hsl(184 78% 46% / 0.06)" />
            <circle cx={p.x} cy={p.y} r={p.r} fill={p.ai ? "hsl(212 80% 60% / 0.25)" : "hsl(184 78% 46% / 0.22)"} stroke={p.ai ? "hsl(212 80% 60%)" : "hsl(184 78% 46%)"} strokeWidth={1.5} />
            {placed.length <= 8 && <text x={p.x} y={p.y + p.r + 13} textAnchor="middle" className="fill-foreground/70" style={{ fontSize: 10, fontFamily: "monospace" }}>{p.pod}</text>}
          </g>
        ))}
      </svg>
      <div className="flex flex-wrap items-center gap-4 px-3 pb-2 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-primary/40 ring-1 ring-primary" /> node size = observed asset value; small = unknown · halo = blast radius</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-info/40 ring-1 ring-info" /> AI/inference workload</span>
        <span>→ = lateral reach (network + RBAC + co-location)</span>
        <span>column = observed stage group; stage not sampled means no matching stage in this sample</span>
      </div>
    </CardContent></Card>
  );
}

function CrownJewels({ jewels, scopeKey }: { jewels: PodNode[]; scopeKey: string }) {
  const max = Math.max(1, ...jewels.map((j) => j.asset ?? 0));
  const page = useLocalPage(jewels, 12, scopeKey);
  return (
    <Card><CardContent className="p-5">
      <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold"><Gem className="h-4 w-4 text-warning" /> Observed asset values</div>
      <div className="space-y-2">
        {page.pageItems.map((j) => (
          <div key={j.key} className="flex items-center gap-3">
            <span className="w-44 shrink-0 truncate font-mono text-[12px]">{j.key}</span>
            <div className="h-2 flex-1 rounded-full bg-muted/40">{j.asset != null && <div className="h-2 rounded-full bg-warning/70" style={{ width: `${Math.max(4, (j.asset / max) * 100)}%` }} />}</div>
            <span className="w-24 text-right text-[11px] tabular text-muted-foreground">{j.asset == null ? "value unknown" : `value ${j.asset.toFixed(2)}`}</span>
            {j.ai && <Badge variant="modeled">AI</Badge>}
            <span className="text-[10px] text-muted-foreground" title={j.evidenceTime ?? undefined}>{j.source === "decision" ? `decision ${j.evidenceTime ? `${j.evidenceTime.slice(11, 16)} UTC` : "time unknown"}; current Pod unverified` : j.evidenceTime ? `UID-matched decision ${j.evidenceTime.slice(11, 16)} UTC` : "no matched decision"}</span>
          </div>
        ))}
      </div>
      {jewels.length === 0 ? <div className="text-xs text-muted-foreground">No crown jewels match this search.</div> : <div className="mt-3"><PaginationBar page={page.page} pageSize={12} total={jewels.length} hasNext={page.hasNext} onPrevious={() => page.setPage((p) => Math.max(0, p - 1))} onNext={() => page.setPage((p) => p + 1)} /></div>}
    </CardContent></Card>
  );
}

function KillChain({ pods }: { pods: PodNode[] }) {
  const stages: StageGroup[] = ["recon", "exploit", "lateral", "impact", "ai", "other", "unknown"];
  const counts = stages.map((s) => pods.filter((p) => stageGroup(p.stage) === s).length);
  return (
    <Card><CardContent className="p-5">
      <div className="mb-4 flex items-center gap-2 text-[13px] font-semibold"><GitBranch className="h-4 w-4 text-primary" /> Kill-chain distribution</div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        {stages.map((s, i) => (
          <div key={s} className="rounded-lg border border-border bg-elevated/30 p-3 text-center">
            <div className="text-2xl font-semibold tabular">{counts[i]}</div>
            <div className="mt-1 text-[11px] uppercase tracking-wide text-muted-foreground">{s === "unknown" ? "stage not sampled" : s}</div>
          </div>
        ))}
      </div>
      <div className="mt-3 text-[11px] text-muted-foreground">Counts cover Pods in the scan snapshot, using current-Pod decision stages. AI includes gpu-side-channel, model-theft, llm-jacking and prompt-inject-persist. Stage not sampled means no matching stage was observed in the bounded decision sample.</div>
    </CardContent></Card>
  );
}
