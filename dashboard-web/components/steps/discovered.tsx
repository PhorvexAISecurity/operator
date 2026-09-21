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
import { useAuditSnapshot, useScanSnapshot } from "@/lib/query";
import { useScopedUIState } from "@/lib/use-scoped-ui-state";

interface PodNode { key: string; ns: string; pod: string; stage: string; asset: number; blast: number; ai: boolean }
interface StreamPod { key: string; ns: string; pod: string; stage: string; asset?: number; blast?: number; ai: boolean }

const STAGE_COL: Record<string, number> = { recon: 0, "early reconnaissance": 0, exploit: 1, exploitation: 1, lateral: 2, impact: 3, exfil: 3 };
const stageName = (s: string) => s || "recon";

export function DiscoveredStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const sel = useSelectedTarget();
  const { tenant } = useOwnerTenant(lens);
  const scopeKey = `${lens}\u0000${sel.context}\u0000${tenant}`;
  const [tab, setTab] = useScopedUIState<"graph" | "jewels" | "killchain" | "physics">(`discovered-tab\u0000${scopeKey}`, "graph");
  const [listQuery, setListQuery] = useScopedUIState(`discovered-filter\u0000${scopeKey}`, "");
  const scanQuery = useScanSnapshot(lens, sel.context, "", lens !== "owner");
  const auditQuery = useAuditSnapshot(lens, sel.context, lens === "owner" ? tenant : "", 2500, lens !== "owner" || !!tenant);
  const streamPods: StreamPod[] = (auditQuery.data || []).flatMap((e) => e.namespace && e.pod ? [{ key: `${e.namespace}/${e.pod}`, ns: e.namespace, pod: e.pod, stage: stageName(e.stage), asset: e.assetValue, blast: e.blastRadius, ai: !!e.aiClassified }] : []);
  const scan = scanQuery.data;
  const scanPods: PodNode[] = (scan?.graphNodes ?? []).map((n) => { const [ns, ...rest] = n.key.split("/"); return { key: n.key, ns, pod: rest.join("/"), stage: "recon", asset: n.blast, blast: n.blast, ai: n.ai }; });
  const edges = scan?.graphEdges ?? [];
  const nodes = scan?.nodeList ?? [];
  const reportedNodeCount = typeof scan?.nodes === "number" ? scan.nodes : null;

  const pods = React.useMemo(() => {
    const merged = new Map<string, StreamPod>(scanPods.map((p) => [p.key, { ...p }]));
    streamPods.forEach((p) => {
      const scanned = merged.get(p.key);
      merged.set(p.key, scanned ? { ...scanned, ...p, asset: p.asset ?? scanned.asset, blast: p.blast ?? scanned.blast, ai: p.ai || scanned.ai } : { ...p });
    });
    return Array.from(merged.values()).map((p) => ({ ...p, asset: p.asset ?? 0, blast: p.blast ?? 0 }));
  }, [scanPods, streamPods]);

  const scoped = true;
  const visibleNodes = scoped ? nodes : [];
  const visibleEdges = scoped ? edges : [];
  const visibleNodeCount = scoped ? reportedNodeCount : null;
  const visibleError = scoped && scanQuery.error ? String((scanQuery.error as Error).message || scanQuery.error) : "";
  const streamSettled = lens === "owner" && !tenant ? true : !!auditQuery.data || !!auditQuery.error;
  const loading = (lens !== "owner" && !scan && scanQuery.isPending) || !streamSettled;
  const scanPhase = lens === "owner" ? "Owner view" : scanQuery.isFetching && !scan ? "Scanning nodes" : visibleError ? "Scan error" : `${visibleNodes.length} nodes listed`;
  const evidencePhase = !scoped || !streamSettled ? "Loading initial evidence" : `${pods.length} workloads loaded`;
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
  const jewels = [...pods].sort((a, b) => b.asset - a.asset);

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={3} title="Discovered" sub={owner ? "The tenant-scoped workloads present in bounded decision evidence." : "What the selected target's fresh scan and bounded decision evidence returned — physical nodes remain distinct from the workload graph."} lens={lens} />

      <div role="status" className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
        <div className="rounded-md border border-border/60 px-3 py-2"><span className="font-medium text-foreground">Scan:</span> {scanPhase}</div>
        <div className="rounded-md border border-border/60 px-3 py-2"><span className="font-medium text-foreground">Evidence:</span> {evidencePhase}</div>
      </div>

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
          <Segmented value={tab} onChange={setTab} tabs={[{ id: "graph", label: "Blast-radius graph" }, { id: "jewels", label: "Crown jewels", count: jewels.filter(j => j.asset > 0).length }, { id: "killchain", label: "Kill-chain" }, { id: "physics", label: "Physics (scan)" }]} />
          {tab === "graph" && <BlastGraph pods={pods} edges={visibleEdges} />}
          {tab === "jewels" && <CrownJewels jewels={query ? jewels.filter((j) => j.key.toLowerCase().includes(query)) : jewels} scopeKey={`${scopeKey}\u0000${listQuery}`} />}
          {tab === "killchain" && <KillChain pods={pods} />}
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
  const cols = ["recon", "exploit", "lateral", "impact"];
  const W = 880, H = 380, colW = W / cols.length;
  // Grid-pack nodes WITHIN each kill-chain column (idle workloads cluster at "recon"; a column
  // can hold the whole platform without overlap). Sub-columns × rows scale with the count.
  const placed = pods.map((p) => {
    const c = STAGE_COL[p.stage] ?? 0;
    const inCol = pods.filter((q) => (STAGE_COL[q.stage] ?? 0) === c);
    const idx = inCol.indexOf(p);
    const n = inCol.length;
    const rows = Math.max(1, Math.ceil(Math.sqrt(n * (H - 70) / colW)));
    const subCols = Math.ceil(n / rows);
    const r0 = idx % rows, c0 = Math.floor(idx / rows);
    const x = colW * c + (colW / (subCols + 1)) * (c0 + 1);
    const y = 48 + ((H - 64) / (rows + 1)) * (r0 + 1);
    const r = n > 8 ? 5 + Math.min(9, p.asset * 7) : 10 + Math.min(22, p.asset * 9);
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
            <text x={colW * i + colW / 2} y={24} textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>{c}</text>
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
            <title>{p.key} · blast {p.blast.toFixed(2)}{p.ai ? " · AI" : ""}</title>
            <circle cx={p.x} cy={p.y} r={p.r + (placed.length > 8 ? 4 : 8) + p.blast * (placed.length > 8 ? 6 : 10)} fill="hsl(184 78% 46% / 0.06)" />
            <circle cx={p.x} cy={p.y} r={p.r} fill={p.ai ? "hsl(212 80% 60% / 0.25)" : "hsl(184 78% 46% / 0.22)"} stroke={p.ai ? "hsl(212 80% 60%)" : "hsl(184 78% 46%)"} strokeWidth={1.5} />
            {placed.length <= 8 && <text x={p.x} y={p.y + p.r + 13} textAnchor="middle" className="fill-foreground/70" style={{ fontSize: 10, fontFamily: "monospace" }}>{p.pod}</text>}
          </g>
        ))}
      </svg>
      <div className="flex flex-wrap items-center gap-4 px-3 pb-2 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-primary/40 ring-1 ring-primary" /> node size = asset value · halo = blast radius</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-info/40 ring-1 ring-info" /> AI/inference workload</span>
        <span>→ = lateral reach (network + RBAC + co-location)</span>
        <span>column = current kill-chain stage</span>
      </div>
    </CardContent></Card>
  );
}

function CrownJewels({ jewels, scopeKey }: { jewels: PodNode[]; scopeKey: string }) {
  const max = Math.max(1, ...jewels.map((j) => j.asset));
  const page = useLocalPage(jewels, 12, scopeKey);
  return (
    <Card><CardContent className="p-5">
      <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold"><Gem className="h-4 w-4 text-warning" /> Highest-value assets</div>
      <div className="space-y-2">
        {page.pageItems.map((j) => (
          <div key={j.key} className="flex items-center gap-3">
            <span className="w-44 shrink-0 truncate font-mono text-[12px]">{j.key}</span>
            <div className="h-2 flex-1 rounded-full bg-muted/40"><div className="h-2 rounded-full bg-warning/70" style={{ width: `${Math.max(4, (j.asset / max) * 100)}%` }} /></div>
            <span className="w-16 text-right text-[11px] tabular text-muted-foreground">value {j.asset.toFixed(2)}</span>
            {j.ai && <Badge variant="modeled">AI</Badge>}
          </div>
        ))}
      </div>
      {jewels.length === 0 ? <div className="text-xs text-muted-foreground">No crown jewels match this search.</div> : <div className="mt-3"><PaginationBar page={page.page} pageSize={12} total={jewels.length} hasNext={page.hasNext} onPrevious={() => page.setPage((p) => Math.max(0, p - 1))} onNext={() => page.setPage((p) => p + 1)} /></div>}
    </CardContent></Card>
  );
}

function KillChain({ pods }: { pods: PodNode[] }) {
  const stages = ["recon", "exploit", "lateral", "impact"];
  const counts = stages.map((s) => pods.filter((p) => (STAGE_COL[p.stage] ?? 0) === stages.indexOf(s)).length);
  return (
    <Card><CardContent className="p-5">
      <div className="mb-4 flex items-center gap-2 text-[13px] font-semibold"><GitBranch className="h-4 w-4 text-primary" /> Kill-chain distribution</div>
      <div className="flex items-stretch gap-2">
        {stages.map((s, i) => (
          <React.Fragment key={s}>
            <div className="flex-1 rounded-lg border border-border bg-elevated/30 p-3 text-center">
              <div className="text-2xl font-semibold tabular">{counts[i]}</div>
              <div className="mt-1 text-[11px] uppercase tracking-wide text-muted-foreground">{s}</div>
            </div>
            {i < stages.length - 1 && <div className="flex items-center text-muted-foreground/40"><ArrowRight className="h-4 w-4" /></div>}
          </React.Fragment>
        ))}
      </div>
      <div className="mt-3 text-[11px] text-muted-foreground">Phorvex acts on the <span className="text-primary">moved-before-next-stage</span> horizon — evicting before a workload advances. The 4 AI stages (gpu-side-channel · model-theft · llm-jacking · prompt-inject-persist) classify here too; magnitudes [SP-0-PENDING-P4].</div>
    </CardContent></Card>
  );
}
