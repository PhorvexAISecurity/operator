"use client";
import * as React from "react";
import { Lens, liveStream } from "@/lib/api";
import { useOwnerTenant } from "@/lib/owner";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, SectionLabel } from "./effectiveness";
import { Pending } from "@/components/ui/more";
import { cn } from "@/lib/utils";
import { Radio, Activity, Lock } from "lucide-react";

export function LiveOpsPanel({ lens }: { lens: Lens }) {
  const [events, setEvents] = React.useState<any[]>([]);
  const [connected, setConnected] = React.useState(false);
  const owner = lens === "owner";
  const { tenant, tenants, setTenant } = useOwnerTenant(lens);

  React.useEffect(() => {
    // owner stream is tenant-scoped: wait for a tenant before opening the SSE.
    if (owner && !tenant) { setEvents([]); setConnected(false); return; }
    setEvents([]); setConnected(true);
    const stop = liveStream(lens, (data) => setEvents((prev) => [data, ...prev].slice(0, 60)), owner ? tenant : undefined);
    return () => { stop(); setConnected(false); };
  }, [lens, owner, tenant]);

  const actuated = events.filter((e) => e.actuated || e.Actuated).length;

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title="Live Operations" sub="Phorvex deciding in real time — streamed from the decision audit. Investor/Operator see the full per-decision internals; the Customer-Owner stream is projected through the IP-wall (outcome only)." />
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 rounded-md border border-border bg-panel/60 px-3 py-1.5 text-[12px]">
          <Radio className={cn("h-3.5 w-3.5", connected ? "animate-pulse-soft text-success" : "text-muted-foreground")} />
          <span className={connected ? "text-foreground" : "text-muted-foreground"}>{connected ? "Streaming /api/live (SSE)" : "Disconnected"}</span>
        </div>
        <div className="text-[12px] text-muted-foreground">{events.length} decisions · {actuated} actuated</div>
        {owner && tenants.length > 0 && (
          <label className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            platform:
            <select value={tenant} onChange={(e) => setTenant(e.target.value)} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[11px] text-foreground">
              {tenants.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
        )}
        {owner && <div className="flex items-center gap-1.5 text-[11px] text-primary"><Lock className="h-3 w-3" /> IP-walled stream (outcome only)</div>}
      </div>

      {events.length === 0 ? (
        <Card><CardContent className="flex flex-col items-center gap-3 py-12 text-center text-sm text-muted-foreground">
          <Activity className="h-5 w-5 animate-pulse-soft" />
          No live decisions yet. Start the Phorvex operator with <span className="font-mono text-foreground/80">--audit-json</span>, or launch a scenario from the Attack Catalog — decisions appear here as they happen.
          <Pending stage="REAL-NOW" msg="The stream is connected; it replays the latest audit trail + tails new decisions." />
        </CardContent></Card>
      ) : (
        <section>
          <SectionLabel>Decision stream {owner ? "(owner projection)" : "(full internals)"}</SectionLabel>
          <div className="space-y-2">
            {events.map((e, i) => owner ? <OwnerCard key={i} e={e} /> : <DecisionCard key={i} e={e} />)}
          </div>
        </section>
      )}
    </div>
  );
}

function DecisionCard({ e }: { e: any }) {
  const acted = e.actuated, sel = e.selected;
  return (
    <Card className={cn("transition-colors", acted && "border-primary/20 bg-primary/[0.03]")}>
      <CardContent className="flex flex-wrap items-center gap-x-4 gap-y-1.5 p-3 text-[12px]">
        <span className="font-mono text-[13px] text-foreground">{e.namespace}/{e.pod}</span>
        <Badge variant={e.action === "noop" ? "neutral" : "accent"}>{e.action}</Badge>
        {sel && <Badge variant="real">selected</Badge>}
        {acted && <Badge variant="accent">actuated{e.handler ? ` · ${e.handler}` : ""}</Badge>}
        {e.stage && <span className="text-muted-foreground">stage <span className="text-foreground/80">{e.stage}</span></span>}
        {e.aiClassified && <Badge variant="modeled">AI</Badge>}
        <span className="ml-auto flex items-center gap-3 tabular text-muted-foreground">
          {typeof e.risk === "number" && <span>risk {e.risk.toFixed(2)}</span>}
          {typeof e.lambda === "number" && e.lambda > 0 && <span>λ {e.lambda.toFixed(2)}</span>}
          {typeof e.perDollar === "number" && e.perDollar > 0 && <span>per-$ {e.perDollar.toFixed(2)}</span>}
          {typeof e.preemptMargin === "number" && e.preemptMargin > 0 && <span className="text-primary">preempt {(e.preemptMargin * 100).toFixed(0)}%</span>}
        </span>
      </CardContent>
    </Card>
  );
}

function OwnerCard({ e }: { e: any }) {
  return (
    <Card><CardContent className="flex flex-wrap items-center gap-x-4 gap-y-1.5 p-3 text-[12px]">
      <span className="font-mono text-[13px] text-foreground">{e.namespace}/{e.pod}</span>
      <Badge variant="accent">{e.action}</Badge>
      {e.reversible && <Badge variant="real">reversible</Badge>}
      <span className="text-muted-foreground">{e.attackStage}</span>
      <span className="ml-auto max-w-md truncate text-foreground/80">{e.why}</span>
    </CardContent></Card>
  );
}
