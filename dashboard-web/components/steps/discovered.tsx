"use client";
import * as React from "react";
import { Lens, liveStream } from "@/lib/api";
import { StepId } from "@/lib/journey";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Segmented, Pending, Empty } from "@/components/ui/more";
import { StepHead } from "./shared";
import { PhysicsPanel } from "@/components/subsystems/panels";
import { cn } from "@/lib/utils";
import { Gem, Network, GitBranch, ArrowRight, Loader2 } from "lucide-react";

interface PodNode { key: string; ns: string; pod: string; stage: string; asset: number; blast: number; ai: boolean }

const STAGE_COL: Record<string, number> = { recon: 0, "early reconnaissance": 0, exploit: 1, exploitation: 1, lateral: 2, impact: 3, exfil: 3 };
const stageName = (s: string) => s || "recon";

function collect(lens: Lens, ms: number, cb: (pods: PodNode[]) => void) {
  const map = new Map<string, PodNode>();
  const stop = liveStream(lens, (e) => {
    const ns = e.namespace, pod = e.pod;
    if (!ns || !pod) return;
    map.set(`${ns}/${pod}`, { key: `${ns}/${pod}`, ns, pod, stage: stageName(e.stage), asset: e.assetValue || 0, blast: e.blastRadius || 0, ai: !!e.aiClassified });
  });
  setTimeout(() => { stop(); cb(Array.from(map.values())); }, ms);
  return stop;
}

export function DiscoveredStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const [pods, setPods] = React.useState<PodNode[] | null>(null);
  const [tab, setTab] = React.useState<"graph" | "jewels" | "killchain" | "physics">("graph");
  React.useEffect(() => { const s = collect(lens, 2500, setPods); return s; }, [lens]);

  if (!pods) return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={3} title="Discovered" sub="Mapping your platform…" lens={lens} />
      <Card><CardContent className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> reading the discovered context from the decision stream…</CardContent></Card>
    </div>
  );

  const owner = lens === "owner";
  const jewels = [...pods].sort((a, b) => b.asset - a.asset);

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={3} title="Discovered" sub={owner ? "The workloads in your platform that Phorvex is protecting." : "What the scan found — the physics/context graph, your crown jewels, and the kill-chain. Full network/RBAC/co-location edges from the live scan are [PENDING-wire · Phase 3]; the per-pod context here is real from the decision stream."} lens={lens} />

      {pods.length === 0 ? (
        <Empty msg="No discovered workloads yet — start Phorvex in the Protect step (or run a scenario) to populate the platform map." />
      ) : owner ? (
        <Card><CardContent className="p-5">
          <div className="mb-3 text-[11px] uppercase tracking-wider text-muted-foreground">Your protected workloads ({pods.length})</div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {pods.map((p) => <div key={p.key} className="flex items-center gap-2 rounded-md border border-border/50 px-3 py-2 font-mono text-[13px]"><Network className="h-3.5 w-3.5 text-primary" />{p.key}</div>)}
          </div>
        </CardContent></Card>
      ) : (
        <>
          <Segmented value={tab} onChange={setTab} tabs={[{ id: "graph", label: "Blast-radius graph" }, { id: "jewels", label: "Crown jewels", count: jewels.filter(j => j.asset > 0).length }, { id: "killchain", label: "Kill-chain" }, { id: "physics", label: "Physics (scan)" }]} />
          {tab === "graph" && <BlastGraph pods={pods} />}
          {tab === "jewels" && <CrownJewels jewels={jewels} />}
          {tab === "killchain" && <KillChain pods={pods} />}
          {tab === "physics" && <PhysicsPanel lens={lens} ns={pods[0]?.ns || "scandemo"} />}
          <Pending stage="PENDING-wire · Phase 3" msg="The full reachability edge set (network + RBAC + co-location) comes from the live `phorvex --scan` graph endpoint, wired in Phase 3. Node value/blast/stage shown here are real." />
        </>
      )}
      {pods.length > 0 && <div className="pt-1"><button onClick={() => go("protect")} className="inline-flex items-center gap-1.5 text-[13px] text-primary hover:underline">Now protect these workloads <ArrowRight className="h-3.5 w-3.5" /></button></div>}
    </div>
  );
}

function BlastGraph({ pods }: { pods: PodNode[] }) {
  const cols = ["recon", "exploit", "lateral", "impact"];
  const W = 880, H = 380, colW = W / cols.length;
  const placed = pods.map((p, i) => {
    const c = STAGE_COL[p.stage] ?? 0;
    const inCol = pods.filter((q) => (STAGE_COL[q.stage] ?? 0) === c);
    const idx = inCol.indexOf(p);
    const x = colW * c + colW / 2;
    const y = 60 + (idx + 1) * (H - 80) / (inCol.length + 1);
    return { ...p, x, y, r: 10 + Math.min(22, p.asset * 9) };
  });
  return (
    <Card><CardContent className="p-2">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full">
        {cols.map((c, i) => (
          <g key={c}>
            <text x={colW * i + colW / 2} y={24} textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>{c}</text>
            <line x1={colW * (i + 1)} y1={40} x2={colW * (i + 1)} y2={H - 20} stroke="hsl(222 18% 16%)" strokeDasharray="3 5" />
          </g>
        ))}
        {placed.map((p) => (
          <g key={p.key}>
            <circle cx={p.x} cy={p.y} r={p.r + 8 + p.blast * 10} fill="hsl(184 78% 46% / 0.06)" />
            <circle cx={p.x} cy={p.y} r={p.r} fill={p.ai ? "hsl(212 80% 60% / 0.25)" : "hsl(184 78% 46% / 0.22)"} stroke={p.ai ? "hsl(212 80% 60%)" : "hsl(184 78% 46%)"} strokeWidth={1.5} />
            <text x={p.x} y={p.y + p.r + 13} textAnchor="middle" className="fill-foreground/70" style={{ fontSize: 10, fontFamily: "monospace" }}>{p.pod}</text>
          </g>
        ))}
      </svg>
      <div className="flex items-center gap-4 px-3 pb-2 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-primary/40 ring-1 ring-primary" /> node size = asset value · halo = blast radius</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-info/40 ring-1 ring-info" /> AI/inference workload</span>
        <span>column = current kill-chain stage</span>
      </div>
    </CardContent></Card>
  );
}

function CrownJewels({ jewels }: { jewels: PodNode[] }) {
  const max = Math.max(1, ...jewels.map((j) => j.asset));
  return (
    <Card><CardContent className="p-5">
      <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold"><Gem className="h-4 w-4 text-warning" /> Highest-value assets</div>
      <div className="space-y-2">
        {jewels.map((j) => (
          <div key={j.key} className="flex items-center gap-3">
            <span className="w-44 shrink-0 truncate font-mono text-[12px]">{j.key}</span>
            <div className="h-2 flex-1 rounded-full bg-muted/40"><div className="h-2 rounded-full bg-warning/70" style={{ width: `${Math.max(4, (j.asset / max) * 100)}%` }} /></div>
            <span className="w-16 text-right text-[11px] tabular text-muted-foreground">value {j.asset.toFixed(2)}</span>
            {j.ai && <Badge variant="modeled">AI</Badge>}
          </div>
        ))}
      </div>
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
