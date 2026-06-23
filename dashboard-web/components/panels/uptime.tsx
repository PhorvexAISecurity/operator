"use client";
import * as React from "react";
import { api, Lens, UptimeResult, UptimeWorkload, UptimeMarker } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Segmented } from "@/components/ui/more";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Activity, ShieldCheck, Loader2, Zap, Scissors, RefreshCw } from "lucide-react";

// action -> color + label. kv-reset never kills the pod, so it sits on a flat 100% line;
// quarantine/rotate detach/delete a pod -> a brief dip that recovers. Color encodes that.
function actionMeta(a: string): { color: string; label: string } {
  switch (a) {
    case "kv-reset": return { color: "hsl(var(--primary))", label: "kv-reset (no kill)" };
    case "quarantine": return { color: "hsl(var(--warning))", label: "quarantine" };
    case "rotate": return { color: "hsl(var(--danger))", label: "rotate" };
    case "warm-swap": return { color: "hsl(var(--primary))", label: "warm-swap" };
    default: return { color: "hsl(var(--muted-foreground))", label: a };
  }
}

// UptimeChart — self-contained inline SVG (no chart lib; matches the CostOverTimeChart pattern).
// Availability % over the window (area + line) with a vertical marker at every moment Phorvex acted.
function UptimeChart({ wl }: { wl: UptimeWorkload }) {
  const pts = wl.series;
  if (!pts || pts.length < 2) return <div className="py-6 text-center text-[12px] text-muted-foreground">collecting samples… (the sampler records availability every 5s)</div>;
  const W = 720, H = 200, padL = 40, padR = 14, padT = 12, padB = 26;
  const innerW = W - padL - padR, innerH = H - padT - padB;
  const ms = (s: string) => new Date(s).getTime();
  const t0 = ms(pts[0].t);
  const tN = ms(pts[pts.length - 1].t);
  const span = Math.max(1, tN - t0);
  const x = (t: number) => padL + ((t - t0) / span) * innerW;
  const y = (pct: number) => padT + innerH - (pct / 100) * innerH;
  const line = pts.map((p) => `${x(ms(p.t)).toFixed(1)},${y(p.pct).toFixed(1)}`).join(" ");
  const area = `${padL},${y(0).toFixed(1)} ${line} ${x(tN).toFixed(1)},${y(0).toFixed(1)}`;
  const yticks = [0, 50, 100];
  // only render markers that fall within the plotted time span.
  const inMarkers = (wl.markers || []).filter((m) => { const t = ms(m.t); return t >= t0 - span * 0.02 && t <= tN + span * 0.02; });
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`Availability of ${wl.workload} over time with actuation markers`}>
      {yticks.map((v, i) => (
        <g key={i}>
          <line x1={padL} y1={y(v)} x2={W - padR} y2={y(v)} stroke="hsl(var(--border))" strokeWidth={1} strokeDasharray={v === 100 ? "0" : "2 3"} />
          <text x={padL - 6} y={y(v) + 3} textAnchor="end" fontSize={10} fill="hsl(var(--muted-foreground))">{v}%</text>
        </g>
      ))}
      {/* actuation markers (vertical lines, colored by action) */}
      {inMarkers.map((m, i) => {
        const mx = x(ms(m.t));
        return <line key={i} x1={mx} y1={padT} x2={mx} y2={padT + innerH} stroke={actionMeta(m.action).color} strokeWidth={1.5} strokeOpacity={0.55} strokeDasharray="3 2" />;
      })}
      <polygon points={area} fill="hsl(var(--primary))" fillOpacity={0.1} />
      <polyline points={line} fill="none" stroke="hsl(var(--primary))" strokeWidth={2} />
      <text x={padL} y={H - 7} textAnchor="start" fontSize={10} fill="hsl(var(--muted-foreground))">{new Date(t0).toLocaleTimeString()}</text>
      <text x={W - padR} y={H - 7} textAnchor="end" fontSize={10} fill="hsl(var(--muted-foreground))">{new Date(tN).toLocaleTimeString()}</text>
    </svg>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "good" | "warn" | "muted" }) {
  return (
    <div className="rounded-md border border-border/60 bg-elevated/30 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={cn("tabular text-[15px] font-semibold", tone === "good" && "text-success", tone === "warn" && "text-warning", tone === "muted" && "text-muted-foreground")}>{value}</div>
    </div>
  );
}

function actionLegend(markers: UptimeMarker[]) {
  const counts: Record<string, number> = {};
  for (const m of markers) counts[m.action] = (counts[m.action] || 0) + 1;
  return Object.entries(counts).sort((a, b) => b[1] - a[1]);
}

function WorkloadCard({ wl }: { wl: UptimeWorkload }) {
  const legend = actionLegend(wl.markers || []);
  const upTone = wl.uptimePct >= 99.5 ? "good" : wl.uptimePct >= 90 ? "warn" : "muted";
  return (
    <Card>
      <CardContent className="p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            <span className="font-medium text-[14px] text-foreground">{wl.ns}/{wl.workload}</span>
            <Badge variant="real">{wl.kind}</Badge>
          </div>
          <div className="flex items-center gap-1.5">
            {legend.map(([a, n]) => (
              <span key={a} className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px]" style={{ color: actionMeta(a).color, background: "color-mix(in srgb, currentColor 12%, transparent)" }}>
                {a === "kv-reset" ? <Zap className="h-3 w-3" /> : a === "rotate" ? <RefreshCw className="h-3 w-3" /> : <Scissors className="h-3 w-3" />}
                {actionMeta(a).label} ×{n}
              </span>
            ))}
          </div>
        </div>

        <UptimeChart wl={wl} />

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat label="Uptime (window)" value={`${wl.uptimePct.toFixed(2)}%`} tone={upTone} />
          <Stat label="Worst dip" value={`${wl.minPct.toFixed(0)}%`} tone={wl.minPct >= 100 ? "good" : "warn"} />
          <Stat label="Actuations" value={String(wl.actuations)} tone="muted" />
          <Stat label="Pod-killing acts" value={String(wl.killingActs)} tone={wl.killingActs === 0 ? "good" : "muted"} />
        </div>

        {wl.killingActs === 0 && wl.actuations > 0 && (
          <div className="rounded-md border border-success/30 bg-success/[0.05] px-3 py-2 text-[11px] text-success">
            <ShieldCheck className="mr-1 inline h-3.5 w-3.5" />
            {wl.actuations} defensive action{wl.actuations === 1 ? "" : "s"} on this service — <span className="font-medium">zero pod kills, zero availability cost</span> (in-process kv-reset). The blind R6 timer would have deleted the pod each cycle.
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function UptimePanel({ lens }: { lens: Lens }) {
  const [d, setD] = React.useState<UptimeResult | null>(null);
  const [err, setErr] = React.useState("");
  const [win, setWin] = React.useState("1h");
  React.useEffect(() => {
    let live = true;
    const load = () => api.uptime(lens, win).then((r) => { if (live) setD(r); }).catch((e) => { if (live) setErr(String(e.message || e)); });
    load();
    const iv = setInterval(load, 8000); // live refresh — the sampler appends every 5s
    return () => { live = false; clearInterval(iv); };
  }, [lens, win]);

  if (err) return <ErrorState msg={err} />;
  if (!d) return <Card><CardContent className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> measuring service availability…</CardContent></Card>;

  const totalActs = d.workloads.reduce((s, w) => s + w.actuations, 0);
  const totalKills = d.workloads.reduce((s, w) => s + w.killingActs, 0);
  const meanUp = d.workloads.length ? d.workloads.reduce((s, w) => s + w.uptimePct, 0) / d.workloads.length : 0;

  return (
    <div className="space-y-5">
      <PageHead title="Uptime — what the actuators cost the service" sub="MEASURED from the Kubernetes API (readyReplicas ÷ desired) for every workload Phorvex acted on, overlaid with the exact moments it acted (live decision audit). A quarantine detaches a pod (it leaves the ReplicaSet → brief dip → replacement Ready); a rotate deletes it; a kv-reset is an in-process flush that NEVER kills the pod — so it never dents availability. Nothing here is synthesized." />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="grid grid-cols-3 gap-3">
          <Card><CardContent className="p-3">
            <div className="flex items-center gap-1.5 text-[12px] text-success"><ShieldCheck className="h-3.5 w-3.5" /> Mean uptime</div>
            <div className="mt-0.5 text-2xl font-semibold tabular text-success">{meanUp.toFixed(2)}%</div>
            <div className="text-[10px] text-muted-foreground">across defended services</div>
          </CardContent></Card>
          <Card><CardContent className="p-3">
            <div className="flex items-center gap-1.5 text-[12px] text-primary"><Zap className="h-3.5 w-3.5" /> Actuations</div>
            <div className="mt-0.5 text-2xl font-semibold tabular text-foreground">{totalActs}</div>
            <div className="text-[10px] text-muted-foreground">in this window</div>
          </CardContent></Card>
          <Card><CardContent className="p-3">
            <div className="flex items-center gap-1.5 text-[12px] text-warning"><Scissors className="h-3.5 w-3.5" /> Pod-killing acts</div>
            <div className="mt-0.5 text-2xl font-semibold tabular text-foreground">{totalKills}</div>
            <div className="text-[10px] text-muted-foreground">rotate/quarantine (vs {totalActs - totalKills} no-kill)</div>
          </CardContent></Card>
        </div>
        <Segmented value={win} onChange={setWin} tabs={[{ id: "10m", label: "10m" }, { id: "1h", label: "1h" }, { id: "6h", label: "6h" }]} />
      </div>

      {d.workloads.length === 0 ? (
        <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">No actuations yet in this window — once Phorvex acts on a service (quarantine / rotate / kv-reset), its availability series and the action markers appear here.</CardContent></Card>
      ) : (
        <div className="space-y-4">
          <SectionLabel>Per-service availability vs actuation</SectionLabel>
          {d.workloads.map((wl) => <WorkloadCard key={`${wl.ns}/${wl.workload}`} wl={wl} />)}
        </div>
      )}
    </div>
  );
}
