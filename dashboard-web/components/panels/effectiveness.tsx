"use client";
import * as React from "react";
import { api, Lens, Stat } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, Badge } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { Info, FileText } from "lucide-react";

const HERO = ["disruption", "work-preserved", "prevention", "explainability"];

function statusBadge(s: Stat["status"]) {
  if (s === "real") return <Badge variant="real">REAL · EKS</Badge>;
  if (s === "modeled") return <Badge variant="modeled">MODELED</Badge>;
  return <Badge variant="pending">SP-0-PENDING-P4</Badge>;
}

function CIBar({ lo, hi, mean, max }: { lo: number; hi: number; mean: number; max: number }) {
  const pc = (v: number) => `${Math.min(100, Math.max(0, (v / max) * 100))}%`;
  return (
    <div className="relative mt-3 h-1.5 w-full rounded-full bg-muted/50">
      <div className="absolute h-1.5 rounded-full bg-primary/25" style={{ left: pc(lo), width: `calc(${pc(hi)} - ${pc(lo)})` }} />
      <div className="absolute h-1.5 w-1.5 -translate-x-1/2 rounded-full bg-primary shadow-[0_0_8px_hsl(var(--primary))]" style={{ left: pc(mean) }} />
    </div>
  );
}

function StatTile({ s, hero }: { s: Stat; hero?: boolean }) {
  const isPct = s.unit === "%";
  const max = isPct ? 1 : s.ci ? s.ci.hi * 1.15 : 1;
  return (
    <Card className={cn("group transition-colors hover:border-border/80", hero && "bg-gradient-to-b from-panel to-panel/60")}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="text-[12px] font-medium uppercase tracking-wide text-muted-foreground">{s.label}</div>
          {statusBadge(s.status)}
        </div>
        <div className="mt-2 flex items-baseline gap-1.5">
          <span className={cn("tabular font-semibold tracking-tight", hero ? "text-4xl" : "text-3xl", s.status === "pending" ? "text-warning/80" : "text-foreground")}>
            {s.value}
          </span>
          {s.unit && s.unit !== "PASS" && <span className="text-lg text-muted-foreground">{s.unit}</span>}
          {s.unit === "PASS" && <span className="text-sm font-medium text-success">PASS</span>}
        </div>
        {s.ci && s.ci.n > 0 ? (
          <>
            <CIBar lo={s.ci.lo} hi={s.ci.hi} mean={s.ci.mean} max={max} />
            <div className="mt-1.5 text-[11px] tabular text-muted-foreground">
              95% CI [{isPct ? `${(s.ci.lo * 100).toFixed(0)}, ${(s.ci.hi * 100).toFixed(0)}` : `${s.ci.lo.toFixed(1)}, ${s.ci.hi.toFixed(1)}`}] · n={s.ci.n}
            </div>
          </>
        ) : (
          <div className="mt-2 text-[11px] text-muted-foreground">{s.status === "pending" ? "no measured value — validated on real GPU at P4" : "ratio / definitional · no CI"}</div>
        )}
        {s.note && <div className="mt-2 text-[11px] leading-snug text-muted-foreground/80">{s.note}</div>}
        <div className="mt-3 flex items-center gap-1.5 border-t border-border/60 pt-2.5 text-[10px] text-muted-foreground/70">
          <FileText className="h-3 w-3" />
          <span className="truncate font-mono">{s.source}</span>
        </div>
      </CardContent>
    </Card>
  );
}

export function EffectivenessPanel({ lens }: { lens: Lens }) {
  const [stats, setStats] = React.useState<Stat[] | null>(null);
  const [err, setErr] = React.useState<string>("");
  React.useEffect(() => {
    api.effectiveness(lens).then((d) => setStats(d.stats ?? [])).catch((e) => setErr(String(e.message || e)));
  }, [lens]);

  if (err) return <ErrorState msg={err} />;
  if (!stats) return <Skeleton rows={8} />;

  const hero = stats.filter((s) => HERO.includes(s.key));
  const dwell = stats.filter((s) => s.key.startsWith("dwell-"));
  const rest = stats.filter((s) => !HERO.includes(s.key) && !s.key.startsWith("dwell-"));

  return (
    <div className="animate-fade-up space-y-7">
      <PageHead
        title="Effectiveness"
        sub="The proven outcomes — every number traced to a real metrics file, with 95% confidence intervals. K8s is proven on AWS EKS; the AI product's defense is honestly GPU-pending."
      />
      <section>
        <SectionLabel>Headline · prevention / disruption board</SectionLabel>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {hero.map((s) => <StatTile key={s.key} s={s} hero />)}
        </div>
      </section>
      <section>
        <SectionLabel>Dwell-to-eviction · attacker time-on-target (lower is better)</SectionLabel>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">{dwell.map((s) => <StatTile key={s.key} s={s} />)}</div>
      </section>
      <section>
        <SectionLabel>Mechanism &amp; gates</SectionLabel>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">{rest.map((s) => <StatTile key={s.key} s={s} />)}</div>
      </section>
    </div>
  );
}

export function PageHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-muted-foreground">{sub}</p>
    </div>
  );
}
export function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="mb-3 flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground/80">{children}</div>;
}
export function Skeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-36 animate-pulse-soft rounded-lg border border-border bg-panel/50" />
      ))}
    </div>
  );
}
export function ErrorState({ msg }: { msg: string }) {
  const down = msg.includes("BACKEND_UNREACHABLE");
  return (
    <Card className="border-warning/30">
      <CardContent className="flex items-start gap-3 p-5 text-sm">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
        {down ? (
          <div>
            <div className="font-medium text-foreground">Data backend isn’t running.</div>
            <div className="mt-1 text-muted-foreground">Start the Phorvex console (it serves this app + the data on one port):</div>
            <code className="mt-2 block rounded-md bg-elevated/60 px-3 py-2 font-mono text-[12px] text-foreground/90">phorvex-console --root &lt;your Phorvex root&gt;</code>
            <div className="mt-1.5 text-[11px] text-muted-foreground/70">then refresh.</div>
          </div>
        ) : (
          <div><span className="font-medium text-foreground">Couldn’t load.</span> <span className="text-muted-foreground">{msg}</span></div>
        )}
      </CardContent>
    </Card>
  );
}
