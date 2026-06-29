"use client";
import * as React from "react";
import { api, Lens, UptimeResult, UptimeWorkload, UptimeMarker, UptimeStrategy, UptimeScenario, UptimeScenarioArm } from "@/lib/api";
import { useSelectedTarget } from "@/lib/provider-store";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Segmented } from "@/components/ui/more";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Activity, ShieldCheck, ShieldOff, Clock, Loader2, Zap, Scissors, RefreshCw } from "lucide-react";

// AttackOutcome — the THIRD baseline the user asked for: what happens to the service if there were
// NO defense at all and an attack lands, next to the blind R6 timer and Phorvex. All MEASURED from
// the benchmark arms (d-nomtd / d-r6blindtimer / d-phorvex). The headline number is "attacks that
// succeed": no defense → ~100% (service owned), blind barely helps, Phorvex cuts it most.
const STRAT_META: Record<string, { Icon: any; text: string; box: string; bar: string; sub: string }> = {
  none:    { Icon: ShieldOff,   text: "text-danger",  box: "border-danger/30 bg-danger/[0.04]",   bar: "bg-danger",  sub: "nothing acts — the attack lands in full" },
  blind:   { Icon: Clock,       text: "text-warning", box: "border-warning/30 bg-warning/[0.04]", bar: "bg-warning", sub: "fixed-cadence rotation, no targeting" },
  phorvex: { Icon: ShieldCheck, text: "text-primary", box: "border-primary/30 bg-primary/[0.04]", bar: "bg-primary", sub: "value-targeted, surgical (kv-reset: no kill)" },
};

function AttackOutcome({ strategies, source, runId }: { strategies: UptimeStrategy[]; source?: string; runId?: string }) {
  if (!strategies || strategies.length === 0) return null;
  const trials = strategies[0]?.trials || 0;
  const live = source === "latest run";
  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <SectionLabel>If an attack hits — what each strategy does to the service</SectionLabel>
            {live ? <Badge variant="real">live · from attack run {runId || ""}</Badge> : <Badge variant="modeled">static benchmark</Badge>}
          </div>
          <div className="mt-0.5 text-[11px] text-muted-foreground">The third “no defense” baseline, beside the blind R6 timer and Phorvex — MEASURED across {trials} trials per strategy {live ? "in the 3-way attack you just ran" : "(run a 3-way attack in the Attack Lab to measure this live)"}. “Attacks succeed” = the attacker reached its objective (the service is effectively <span className="text-danger">owned</span>, even if its pods stay Running).</div>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {strategies.map((s) => {
            const m = STRAT_META[s.key] || STRAT_META.phorvex;
            return (
              <div key={s.key} className={cn("rounded-lg border p-3", m.box)}>
                <div className={cn("flex items-center gap-1.5 text-[12px] font-medium", m.text)}><m.Icon className="h-3.5 w-3.5" /> {s.label}</div>
                <div className="mt-2 flex items-end gap-1.5">
                  <span className={cn("text-3xl font-semibold tabular", m.text)}>{Math.round(s.attackSuccess)}%</span>
                  <span className="mb-1 text-[11px] text-muted-foreground">attacks succeed</span>
                </div>
                <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-elevated">
                  <div className={cn("h-full rounded-full", m.bar)} style={{ width: `${Math.max(2, s.attackSuccess)}%` }} />
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
                  <span>attack disrupted <span className="text-foreground">{Math.round(s.disrupted)}%</span></span>
                  <span>self-actions <span className="text-foreground">{s.defensiveActions.toFixed(2)}</span></span>
                </div>
                <div className="mt-1 text-[10px] text-muted-foreground">{m.sub}</div>
              </div>
            );
          })}
        </div>
        <div className="rounded-md border border-border bg-elevated/30 px-3 py-2 text-[11px] text-muted-foreground">
          The chart below shows the OTHER half: Phorvex achieves this protection at near-zero <span className="text-foreground">availability</span> cost (kv-reset never kills a pod). No defense keeps the pods “up” but hands the service to the attacker; the blind timer tanks neither here nor protects much.
        </div>
      </CardContent>
    </Card>
  );
}

// scenarioTitle prettifies a scenario id ("c1-fast-attacker") into a readable app label.
function scenarioTitle(s: string): string {
  return s.replace(/^[a-z]\d+-/i, "").replace(/[-_]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ArmCell — one defender column for one attacked app: the MEASURED "attacks succeed %" headline
// (bar grows with success → red = bad), with disruption + attacker dwell beneath it.
function ArmCell({ arm }: { arm: UptimeScenarioArm }) {
  const m = STRAT_META[arm.key] || STRAT_META.phorvex;
  return (
    <div className={cn("rounded-lg border p-3", m.box)}>
      <div className={cn("flex items-center gap-1.5 text-[12px] font-medium", m.text)}>
        <m.Icon className="h-3.5 w-3.5" /> {arm.label}
      </div>
      <div className="mt-2 flex items-end gap-1.5">
        <span className={cn("text-3xl font-semibold tabular", m.text)}>{Math.round(arm.attackSuccess)}%</span>
        <span className="mb-1 text-[11px] text-muted-foreground">attacks succeed</span>
      </div>
      <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-elevated">
        <div className={cn("h-full rounded-full", m.bar)} style={{ width: `${Math.max(2, arm.attackSuccess)}%` }} />
      </div>
      <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
        <span>disrupted <span className="text-foreground">{Math.round(arm.disrupted)}%</span></span>
        <span>dwell <span className="text-foreground">{arm.dwell.toFixed(1)}s</span></span>
      </div>
      <div className="mt-1 text-[10px] text-muted-foreground">
        {arm.key === "none" ? "no actions — attack runs free" : <>self-actions <span className="text-foreground">{arm.defensiveActions.toFixed(2)}</span></>}
      </div>
    </div>
  );
}

// ScenarioCard — one attacked app, split three ways: attack landed (no defense) vs defense by
// Phorvex vs defense by R6Blind. Every number is MEASURED across the run's trials for this app.
function ScenarioCard({ s }: { s: UptimeScenario }) {
  const trials = s.arms[0]?.trials || 0;
  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            <span className="font-medium text-[14px] text-foreground">{scenarioTitle(s.scenario)}</span>
            {s.category ? <Badge variant="modeled">{s.category}</Badge> : null}
          </div>
          <span className="text-[10px] text-muted-foreground">{trials} trials/arm</span>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {s.arms.map((arm) => <ArmCell key={arm.key} arm={arm} />)}
        </div>
      </CardContent>
    </Card>
  );
}

// ScenarioBreakdown — the per-app three-way view the dashboard leads with: for EACH attacked app,
// what happens with no defense, under Phorvex, and under the blind R6 timer — all measured.
function ScenarioBreakdown({ scenarios, source, runId }: { scenarios: UptimeScenario[]; source?: string; runId?: string }) {
  if (!scenarios || scenarios.length === 0) return null;
  const live = source === "latest run";
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SectionLabel>Per-app breakdown — attack landed vs Phorvex vs R6Blind</SectionLabel>
        {live ? <Badge variant="real">live · from attack run {runId || ""}</Badge> : <Badge variant="modeled">static benchmark</Badge>}
      </div>
      <div className="text-[11px] text-muted-foreground -mt-1">
        Each app was attacked under all three defenses. “Attacks succeed” = the attacker reached its objective (measured <span className="text-danger">oracleAchieved</span>); lower is better. {live ? "From the 3-way attack you just ran." : "Run a 3-way attack in the Attack Lab to make this live."}
      </div>
      <div className="space-y-4">
        {scenarios.map((s) => <ScenarioCard key={s.scenario} s={s} />)}
      </div>
    </div>
  );
}

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
function UptimeChart({ wl, attacks = [] }: { wl: UptimeWorkload; attacks?: { scenario: string; start: number; end: number }[] }) {
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
  // attack windows that overlap the chart span — drawn as bands so you SEE the attack relative to uptime.
  const bands = attacks.map((a) => ({ a, s: Math.max(a.start, t0), e: Math.min(a.end, tN) })).filter((b) => b.e > b.s);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`Availability of ${wl.workload} over time with actuation markers`}>
      {/* attack-run bands (behind everything) */}
      {bands.map((b, i) => (
        <g key={`b${i}`}>
          <rect x={x(b.s)} y={padT} width={Math.max(1, x(b.e) - x(b.s))} height={innerH} fill="hsl(var(--warning))" fillOpacity={0.1} />
          <line x1={x(b.s)} y1={padT} x2={x(b.s)} y2={padT + innerH} stroke="hsl(var(--warning))" strokeWidth={1} strokeOpacity={0.5} strokeDasharray="2 2" />
          <text x={x(b.s) + 2} y={padT + 9} fontSize={9} fill="hsl(var(--warning))">⚔ {b.a.scenario}</text>
        </g>
      ))}
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

function WorkloadCard({ wl, attacks }: { wl: UptimeWorkload; attacks?: { scenario: string; start: number; end: number }[] }) {
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

        <UptimeChart wl={wl} attacks={attacks} />

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

// parseTs parses a UTC tsNow() string ("2026-06-28 14:30:00 UTC") to epoch ms (for overlaying
// attack-run windows on the availability chart).
function parseTs(s?: string): number {
  if (!s) return NaN;
  const p = s.split(" ");
  return p.length >= 2 ? Date.parse(`${p[0]}T${p[1]}Z`) : Date.parse(s);
}

export function UptimePanel({ lens }: { lens: Lens }) {
  const [d, setD] = React.useState<UptimeResult | null>(null);
  const [err, setErr] = React.useState("");
  const [win, setWin] = React.useState("1h");
  const [attacks, setAttacks] = React.useState<{ scenario: string; start: number; end: number }[]>([]);
  const sel = useSelectedTarget(); // SCOPE uptime to the selected provider
  React.useEffect(() => {
    let live = true;
    const load = () => {
      api.uptime(lens, win, sel.context).then((r) => { if (live) setD(r); }).catch((e) => { if (live) setErr(String(e.message || e)); });
      // attack-run windows (scoped to the provider) to overlay on the chart.
      api.runsList(lens).then((rl) => { if (live) setAttacks((rl.runs || [])
        .filter((r) => !sel.provider || (r.provider || "") === sel.provider)
        .map((r) => ({ scenario: r.config, start: parseTs(r.date), end: r.finished ? parseTs(r.finished) : (r.state === "running" ? Date.now() + 60_000 : parseTs(r.date) + 600_000) }))
        .filter((a) => !isNaN(a.start))); }).catch(() => {});
    };
    load();
    const iv = setInterval(load, 8000); // live refresh — the sampler appends every 5s
    return () => { live = false; clearInterval(iv); };
  }, [lens, win, sel.context, sel.provider]);

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

      {/* THIRD baseline: no-defense / blind-R6 / Phorvex attack outcome — live run or benchmark */}
      <AttackOutcome strategies={d.strategies || []} source={d.strategiesSource} runId={d.strategiesRun} />

      {/* Per-app three-way breakdown: attack landed / defense by Phorvex / defense by R6Blind */}
      <ScenarioBreakdown scenarios={d.scenarios || []} source={d.strategiesSource} runId={d.strategiesRun} />

      {d.workloads.length === 0 ? (
        <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">No actuations yet in this window — once Phorvex acts on a service (quarantine / rotate / kv-reset), its availability series and the action markers appear here.</CardContent></Card>
      ) : (
        <div className="space-y-4">
          <SectionLabel>Per-service availability vs actuation</SectionLabel>
          {d.workloads.map((wl) => <WorkloadCard key={`${wl.ns}/${wl.workload}`} wl={wl} attacks={attacks} />)}
        </div>
      )}
    </div>
  );
}
