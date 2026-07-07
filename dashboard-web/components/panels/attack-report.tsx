"use client";
import * as React from "react";
import { api, Lens, AttackResult } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { csvDownload, Empty } from "@/components/ui/more";
import { ShieldCheck, ShieldAlert, Loader2, Download, Swords, Activity } from "lucide-react";
import { cn } from "@/lib/utils";

// AttackResultsPanel — the REAL outcome of every attack fired from Live Operations: landed vs defended,
// the actuator Phorvex chose + why, uptime before/dip/after, and the three-way cost (without / R6 / with).
// Everything is measured on the live cluster — polled from /api/attack-results (persisted per attack).
export function AttackResultsPanel({ lens, compact }: { lens: Lens; compact?: boolean }) {
  const [rows, setRows] = React.useState<AttackResult[] | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => {
    let alive = true;
    const load = () => api.attackResults(lens).then((d) => { if (alive) setRows(d.attacks || []); }).catch((e) => { if (alive) setErr(String(e.message || e)); });
    load();
    const t = setInterval(load, 4000); // live: running → done
    return () => { alive = false; clearInterval(t); };
  }, [lens]);

  if (err) return <div className="text-[12px] text-danger">error: {err}</div>;
  if (!rows) return <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading attack results…</div>;
  if (rows.length === 0) return <Empty msg="No attacks fired yet. Go to Protect → Live theatre, pick a workload, and fire a real attack — its measured outcome, uptime impact and 3-way cost will appear here." />;

  const shown = compact ? rows.slice(0, 3) : rows;
  function exportCSV() {
    const rs = rows || [];
    const head = ["fired", "service", "attack", "mitre", "outcome", "actuator", "time_to_defend_s", "uptime_before", "uptime_dip", "uptime_after", "cost_without", "cost_r6", "cost_with", "savings", "why"];
    const body = rs.map((r) => [r.firedAt, r.service, r.attack, r.mitre, r.outcome || r.status, r.phorvexAction, r.timeToDefendSec, r.uptimeBefore, r.uptimeDip, r.uptimeAfter, r.cost?.without, r.cost?.r6, r.cost?.with, r.cost?.savings, r.why]);
    csvDownload("phorvex-attack-results.csv", [head, ...body]);
  }

  const defended = rows.filter((r) => r.outcome === "DEFENDED").length;
  const landed = rows.filter((r) => r.outcome === "LANDED").length;

  return (
    <div className="space-y-3">
      {!compact && (
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 text-[12px] font-medium"><Swords className="h-3.5 w-3.5 text-primary" /> Live attack results</div>
          <div className="text-[11px] text-muted-foreground">{rows.length} attacks · <span className="text-success">{defended} defended</span> · <span className="text-danger">{landed} landed</span></div>
          <Button size="sm" variant="outline" onClick={exportCSV} className="ml-auto gap-1.5"><Download className="h-3.5 w-3.5" /> CSV</Button>
        </div>
      )}
      {shown.map((r) => <AttackCard key={r.id} r={r} />)}
    </div>
  );
}

function AttackCard({ r }: { r: AttackResult }) {
  const running = r.status === "running";
  const defended = r.outcome === "DEFENDED";
  const landed = r.outcome === "LANDED";
  return (
    <Card className={cn("border-l-2", defended ? "border-l-success" : landed ? "border-l-danger" : "border-l-warning")}>
      <CardContent className="space-y-3 p-4">
        {/* header */}
        <div className="flex flex-wrap items-center gap-2">
          {running ? <Badge variant="modeled" className="gap-1"><Loader2 className="h-3 w-3 animate-spin" /> measuring…</Badge>
            : defended ? <Badge variant="real" className="gap-1"><ShieldCheck className="h-3 w-3" /> DEFENDED</Badge>
              : <Badge variant="pending" className="gap-1"><ShieldAlert className="h-3 w-3" /> LANDED</Badge>}
          <span className="font-mono text-[12px] font-medium text-foreground">{r.service}</span>
          <span className="text-[12px] text-muted-foreground">· {r.attack}</span>
          <span className="rounded border border-border bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{r.mitre}</span>
          <span className="ml-auto font-mono text-[10px] text-muted-foreground/60">{new Date(r.firedAt).toLocaleTimeString()}</span>
        </div>

        {/* actuator line */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px]">
          <span className="text-muted-foreground">Phorvex →
            <span className={cn("ml-1 font-mono font-semibold", defended ? "text-success" : "text-foreground")}>{r.phorvexAction || r.expectedActuator}</span>
          </span>
          {defended && r.timeToDefendSec > 0 && <span className="text-muted-foreground">in <span className="tabular text-foreground">{r.timeToDefendSec}s</span></span>}
          <span className="text-muted-foreground">target pod <span className="font-mono text-[11px] text-foreground/80">{r.pod?.split("-").slice(-1)[0]}</span></span>
          {landed && <span className="text-danger">foothold persists — attacker retains access</span>}
          {defended && <span className="text-success">foothold removed — attacker access lost</span>}
        </div>

        {/* uptime before / dip / after */}
        <div>
          <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"><Activity className="h-3 w-3" /> availability</div>
          <div className="flex items-center gap-2 text-[12px]">
            <UpCell label="before" v={r.uptimeBefore} />
            <span className="text-muted-foreground/40">→</span>
            <UpCell label="dip" v={r.uptimeDip} warn />
            <span className="text-muted-foreground/40">→</span>
            <UpCell label="after" v={r.uptimeAfter} good={r.uptimeAfter >= 100} />
            <span className="ml-2 text-[11px] text-muted-foreground">{r.uptimeAfter >= 100 && r.uptimeDip < 100 ? "recovered — sibling replica kept serving" : r.uptimeDip >= 100 ? "no availability impact" : ""}</span>
          </div>
        </div>

        {/* three-way cost */}
        <div>
          <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground/70">annual cost exposure (real AWS $/yr)</div>
          <div className="grid grid-cols-3 gap-2">
            <CostCell label="Without any defense" v={r.cost?.without} tone="bad" max={r.cost?.without} />
            <CostCell label="R6 blind timer" v={r.cost?.r6} tone="warn" max={r.cost?.without} sub={r.stateful ? "destroys DB data" : "churns · ~20% catch"} />
            <CostCell label="With Phorvex" v={r.cost?.with} tone="good" max={r.cost?.without} sub={`saves $${fmt(r.cost?.savings)}/yr`} />
          </div>
        </div>

        {/* reasoning */}
        {(r.why || r.r6Note) && (
          <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5 text-[11px] leading-relaxed">
            {r.why && <div><span className="text-muted-foreground">why: </span><span className="font-mono text-foreground/85">{r.why}</span></div>}
            <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[10px] text-muted-foreground">
              {r.perDollar > 0 && <span>per-$={r.perDollar.toFixed(2)}</span>}
              {r.stage && <span>stage={r.stage}</span>}
              {r.coveredFacts > 0 && <span>facts={r.coveredFacts}</span>}
              {r.pHold > 0 && <span>pHold={r.pHold.toFixed(2)}</span>}
              <span>λ={r.lambda?.toFixed(2)}</span>
            </div>
            {r.r6Note && <div className="mt-1 text-warning/90"><span className="text-muted-foreground">R6 counterfactual: </span>{r.r6Note}</div>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function UpCell({ label, v, warn, good }: { label: string; v: number; warn?: boolean; good?: boolean }) {
  const bad = v >= 0 && v < 100;
  return (
    <div className="text-center">
      <div className={cn("tabular text-[13px] font-semibold", v < 0 ? "text-muted-foreground" : good ? "text-success" : warn && bad ? "text-warning" : bad ? "text-danger" : "text-foreground")}>{v < 0 ? "—" : `${v}%`}</div>
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground/60">{label}</div>
    </div>
  );
}

function CostCell({ label, v, max, tone, sub }: { label: string; v: number; max: number; tone: "bad" | "warn" | "good"; sub?: string }) {
  const pct = max > 0 ? Math.max(3, Math.min(100, (v / max) * 100)) : 3;
  const bar = tone === "bad" ? "bg-danger" : tone === "warn" ? "bg-warning" : "bg-success";
  const txt = tone === "bad" ? "text-danger" : tone === "warn" ? "text-warning" : "text-success";
  return (
    <div className="rounded-md border border-border/60 bg-panel/40 p-2">
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground/70">{label}</div>
      <div className={cn("tabular text-[15px] font-semibold", txt)}>${fmt(v)}<span className="text-[10px] font-normal text-muted-foreground">/yr</span></div>
      <div className="mt-1 h-1 overflow-hidden rounded bg-border/50"><div className={cn("h-full rounded", bar)} style={{ width: `${pct}%` }} /></div>
      {sub && <div className="mt-1 text-[9px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

function fmt(n?: number) {
  if (n == null) return "—";
  return Math.round(n).toLocaleString();
}
