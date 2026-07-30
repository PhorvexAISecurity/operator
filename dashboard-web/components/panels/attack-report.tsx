"use client";
import * as React from "react";
import { api, Lens, AttackResult, AttackCost } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { csvDownload, Empty } from "@/components/ui/more";
import { ShieldCheck, ShieldAlert, Loader2, Download, Swords, Activity, Clock, Calculator } from "lucide-react";
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
    const head = ["fired", "service", "attack", "mitre", "outcome", "actuator", "containment", "time_to_action_s", "dwell_s", "dwell_ongoing", "uptime_before", "uptime_dip", "uptime_after", "cost_without", "cost_r6", "cost_with", "savings", "why"];
    const body = rs.map((r) => [r.firedAt, r.service, r.attack, r.mitre, r.outcome || r.status, r.phorvexAction, r.containment, r.timeToDefendSec, r.dwellSec, r.dwellOngoing ? "ongoing" : "bounded", r.uptimeBefore, r.uptimeDip, r.uptimeAfter, r.cost?.without, r.cost?.r6, r.cost?.with, r.cost?.savings, r.why]);
    csvDownload("phorvex-attack-results.csv", [head, ...body]);
  }

  const defended = rows.filter((r) => r.outcome === "DEFENDED").length;
  const landed = rows.filter((r) => r.outcome === "LANDED").length;
  const boundedRows = rows.filter((r) => (r.containment === "evicted" || r.containment === "contained" || r.containment === "flushed") && r.dwellSec > 0);
  const meanDwell = boundedRows.length ? (boundedRows.reduce((a, r) => a + r.dwellSec, 0) / boundedRows.length).toFixed(1) : null;

  return (
    <div className="space-y-3">
      {!compact && (
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 text-[12px] font-medium"><Swords className="h-3.5 w-3.5 text-primary" /> Live attack results</div>
          <div className="text-[11px] text-muted-foreground">{rows.length} attacks · <span className="text-success">{defended} defended</span> · <span className="text-danger">{landed} landed</span>{meanDwell && <> · mean containment dwell <span className="tabular text-foreground">{meanDwell}s</span></>}</div>
          <Button size="sm" variant="outline" onClick={exportCSV} className="ml-auto gap-1.5"><Download className="h-3.5 w-3.5" /> CSV</Button>
        </div>
      )}
      {shown.map((r) => <AttackCard key={r.id} r={r} />)}
    </div>
  );
}

// containmentInfo frames what the action actually did to the FOOTHOLD (not just "an action fired").
function containmentInfo(r: AttackResult): { tone: "good" | "warn" | "bad"; cls: string; line: string; dwellNote: string; bounded: boolean } {
  switch (r.containment) {
    case "evicted":
      return { tone: "good", cls: "text-success", line: `${r.pod} rotated away — attacker evicted`, dwellNote: "attacker evicted — window closed", bounded: true };
    case "contained":
      return { tone: "good", cls: "text-success", line: `${r.pod} quarantined — attacker isolated on its own node`, dwellNote: "foothold network-isolated on its node", bounded: true };
    case "flushed":
      return { tone: "good", cls: "text-success", line: `${r.pod} kept serving — injected cache state flushed in place`, dwellNote: "planted state cleared — no restart, no downtime", bounded: true };
    case "foothold-active":
      return { tone: "warn", cls: "text-warning", line: `neighbor ${r.defendedPod} isolated — attacker STILL holds ${r.pod}`, dwellNote: `foothold on ${r.pod} not evicted — lateral spread cut only`, bounded: false };
    case "landed":
      return { tone: "bad", cls: "text-danger", line: "foothold persists — attacker retains access", dwellNote: "attacker never evicted", bounded: false };
    default:
      return { tone: "bad", cls: "text-muted-foreground", line: "", dwellNote: "", bounded: false };
  }
}

function AttackCard({ r }: { r: AttackResult }) {
  const running = r.status === "running";
  const defended = r.outcome === "DEFENDED";
  const landed = r.outcome === "LANDED";
  const cinfo = containmentInfo(r);
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
          {!running && cinfo.line && <span className={cinfo.cls}>{cinfo.line}</span>}
        </div>

        {/* attacker dwell time — how long the intruder held effective access */}
        <div>
          <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"><Clock className="h-3 w-3" /> attacker dwell time</div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px]">
            {running
              ? <span className="text-muted-foreground">measuring…</span>
              : cinfo.bounded
                ? <><span className="tabular text-[15px] font-semibold text-success">{r.dwellSec}s</span><span className="text-muted-foreground">{cinfo.dwellNote}</span></>
                : <><span className="tabular text-[15px] font-semibold text-danger">≥ {r.dwellSec}s</span><span className="text-warning">ongoing — {cinfo.dwellNote}</span></>}
            <span className="ml-auto text-[10px] text-muted-foreground/60">bounded only when the foothold pod itself is evicted/contained · no defense: unbounded</span>
          </div>
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
          <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground/70">annual cost exposure (real AWS $/yr) · <span className="text-muted-foreground/50">modelled from measured prevention rates — not this attack&apos;s outcome</span></div>
          <div className="grid grid-cols-3 gap-2">
            <CostCell label="Without any defense" v={r.cost?.without} tone="bad" max={r.cost?.without} />
            <CostCell label="R6 blind timer" v={r.cost?.r6} tone="warn" max={r.cost?.without} sub={r.stateful ? "destroys DB data" : "churns · blind rotation"} />
            <CostCell label="With Phorvex" v={r.cost?.with} tone="good" max={r.cost?.without} sub={(r.cost?.savings ?? 0) > 0 ? `saves $${fmt(r.cost?.savings)}/yr` : `costs $${fmt(Math.abs(r.cost?.savings ?? 0))}/yr more`} />
          </div>
          <CostBreakdown c={r.cost} />
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

// CostBreakdown prints the ARITHMETIC behind the three totals. A reader should never have to take
// a dollar figure on trust: every input is named, sourced, and the formula is shown with this
// attack's own numbers substituted in.
function CostBreakdown({ c }: { c?: AttackCost }) {
  const [open, setOpen] = React.useState(false);
  if (!c || !c.nodeRatePerHr) return null;
  const pct = (x?: number) => `${((x ?? 0) * 100).toFixed(1)}%`;
  const d = (x?: number) => `$${fmt(x)}`;
  const Row = ({ k, v }: { k: string; v: React.ReactNode }) => (
    <div className="flex flex-wrap items-baseline gap-x-2 py-0.5">
      <span className="min-w-[150px] text-muted-foreground">{k}</span>
      <span className="font-mono text-[11px] text-foreground/90">{v}</span>
    </div>
  );
  return (
    <div className="mt-2">
      <button onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[11px] text-primary transition-colors hover:text-primary/80">
        <Calculator className="h-3 w-3" />
        {open ? "Hide" : "How was this calculated?"}
      </button>
      {open && (
        <div className="mt-2 space-y-2 rounded-md border border-border/60 bg-elevated/30 p-3 text-[11px] leading-relaxed">
          <div>
            <div className="mb-1 font-medium text-foreground">1 · What is at risk (real AWS price)</div>
            <Row k="attacked pod runs on" v={`${c.nodeInstance || "node"} @ ${d(c.nodeRatePerHr)}/hr`} />
            <Row k="value at risk / yr" v={`${d(c.nodeRatePerHr)}/hr x 8,760 hr = ${d(c.valueAtRisk)}`} />
            <div className="mt-1 text-muted-foreground/80">
              This is your live AWS on-demand price for the hardware the attack compromises — not a
              breach/reputation estimate.
            </div>
          </div>
          <div>
            <div className="mb-1 font-medium text-foreground">2 · How often each defender actually stops an attack</div>
            <Row k="no defense" v={pct(c.preventNone)} />
            <Row k="R6 blind timer" v={pct(c.preventR6)} />
            <Row k="Phorvex" v={pct(c.preventPhorvex)} />
            <div className="mt-1 text-muted-foreground/80">Measured, not assumed: {c.ratesSource}</div>
          </div>
          <div>
            <div className="mb-1 font-medium text-foreground">3 · The arithmetic</div>
            <Row k="without any defense" v={`${d(c.valueAtRisk)} x (1 - ${pct(c.preventNone)}) = ${d(c.without)}`} />
            <Row k="R6 blind timer" v={`${d(c.valueAtRisk)} x (1 - ${pct(c.preventR6)}) + ${d(c.r6Churn)} churn = ${d(c.r6)}`} />
            <Row k="with Phorvex" v={`${d(c.valueAtRisk)} x (1 - ${pct(c.preventPhorvex)}) + ${d(c.operatorCost)} operator = ${d(c.with)}`} />
            <Row k="difference" v={`${d(c.without)} - ${d(c.with)} = ${d(c.savings)}/yr`} />
          </div>
          <div className="border-t border-border/50 pt-2 text-muted-foreground/80">
            These three are an ANNUAL projection using each defender&apos;s measured stop-rate — they answer
            &quot;what does a year of this cost?&quot;, not &quot;what did this one attack cost?&quot;. This attack&apos;s own
            result is the DEFENDED/LANDED badge and the dwell time above.
          </div>
        </div>
      )}
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
