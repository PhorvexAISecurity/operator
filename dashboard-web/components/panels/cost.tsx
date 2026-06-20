"use client";
import * as React from "react";
import { api, Lens, CostResult, CostTimeseries } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { ShieldOff, ShieldCheck, TrendingDown, Loader2 } from "lucide-react";

function usd(n: number): string {
  if (n >= 1e6) return `$${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(1)}k`;
  return `$${Math.round(n)}`;
}

// fmtCost renders the unit-less per-decision cost (sum of Cost/BlindCost) WITHOUT a currency
// symbol — these are rotation-cost units, not dollars (matches the Live Ops cards).
function fmtCost(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  if (n >= 100) return n.toFixed(0);
  return n.toFixed(2);
}

// CostOverTimeChart — self-contained inline SVG (no chart lib; matches the BlastGraph pattern).
// Two cumulative lines from the live decision audit: the blind R6 timer (climbs every cycle) vs
// Phorvex (pays only when net-positive), with the savings gap shaded between them.
function CostOverTimeChart({ ts }: { ts: CostTimeseries }) {
  const pts = ts.points;
  if (!pts || pts.length < 2) return null; // self-guard: needs >=2 points to plot a line (caller also routes 1-point to a text summary)
  const W = 720, H = 240, padL = 52, padR = 16, padT = 16, padB = 28;
  const innerW = W - padL - padR, innerH = H - padT - padB;
  const t0 = pts[0].unixMillis;
  const tN = pts[pts.length - 1].unixMillis;
  const tSpan = Math.max(1, tN - t0);
  const yMax = Math.max(1e-6, ...pts.map((p) => p.blindCost)); // blind is the upper envelope
  const x = (p: { unixMillis: number }) => padL + ((p.unixMillis - t0) / tSpan) * innerW;
  const y = (v: number) => padT + innerH - (v / yMax) * innerH;
  const blindLine = pts.map((p) => `${x(p).toFixed(1)},${y(p.blindCost).toFixed(1)}`).join(" ");
  const pxLine = pts.map((p) => `${x(p).toFixed(1)},${y(p.phorvexCost).toFixed(1)}`).join(" ");
  const band = [
    ...pts.map((p) => `${x(p).toFixed(1)},${y(p.blindCost).toFixed(1)}`),
    ...pts.slice().reverse().map((p) => `${x(p).toFixed(1)},${y(p.phorvexCost).toFixed(1)}`),
  ].join(" ");
  const ticks = [0, 0.5, 1].map((f) => ({ v: yMax * f, yPos: y(yMax * f) }));
  const last = pts[pts.length - 1];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Cumulative cost over time: Phorvex vs blind R6 timer">
      {ticks.map((t, i) => (
        <g key={i}>
          <line x1={padL} y1={t.yPos} x2={W - padR} y2={t.yPos} stroke="hsl(var(--border))" strokeWidth={1} strokeDasharray="2 3" />
          <text x={padL - 8} y={t.yPos + 3} textAnchor="end" fontSize={10} fill="hsl(var(--muted-foreground))">{fmtCost(t.v)}</text>
        </g>
      ))}
      <polygon points={band} fill="hsl(var(--success))" fillOpacity={0.12} />
      <polyline points={blindLine} fill="none" stroke="hsl(var(--danger))" strokeWidth={2} />
      <polyline points={pxLine} fill="none" stroke="hsl(var(--primary))" strokeWidth={2} />
      <circle cx={x(last)} cy={y(last.blindCost)} r={3} fill="hsl(var(--danger))" />
      <circle cx={x(last)} cy={y(last.phorvexCost)} r={3} fill="hsl(var(--primary))" />
      <text x={padL} y={H - 8} textAnchor="start" fontSize={10} fill="hsl(var(--muted-foreground))">{new Date(t0).toLocaleTimeString()}</text>
      <text x={W - padR} y={H - 8} textAnchor="end" fontSize={10} fill="hsl(var(--muted-foreground))">{new Date(tN).toLocaleTimeString()}</text>
    </svg>
  );
}

export function CostPanel({ lens }: { lens: Lens }) {
  const [d, setD] = React.useState<CostResult | null>(null);
  const [ts, setTs] = React.useState<CostTimeseries | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => {
    api.cost(lens).then(setD).catch((e) => setErr(String(e.message || e)));
    api.costTimeseries(lens).then(setTs).catch(() => setTs(null)); // optional — never blocks the panel
  }, [lens]);

  if (err) return <ErrorState msg={err} />;
  if (!d) return <Card><CardContent className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> computing cost…</CardContent></Card>;
  if (!d.available || !d.scenarios.length) return <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">No benchmark cost data yet — run the with/without-Phorvex benchmark (or an Attack Lab scenario) to populate it.</CardContent></Card>;

  return (
    <div className="space-y-5">
      <PageHead title="Cost — with vs without Phorvex (real AWS prices)" sub="Grounded entirely in your live AWS on-demand pricing — no fabricated breach figures. The value at risk is your cluster's real infrastructure cost/yr; with Phorvex OFF that infrastructure is exposed, with Phorvex ON the residual exposure shrinks by the measured disruption for a small rotation overhead. The headline is the single infra value at the average disruption — never the same hardware counted N times." />

      {/* headline: OFF vs ON vs savings — single cluster infra value, AWS-priced */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Card><CardContent className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] text-danger"><ShieldOff className="h-3.5 w-3.5" /> Phorvex OFF</div>
          <div className="mt-1 text-3xl font-semibold tabular text-danger">{usd(d.totalWithout)}/yr</div>
          <div className="mt-1 text-[11px] text-muted-foreground">your AWS infrastructure exposed</div>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] text-primary"><ShieldCheck className="h-3.5 w-3.5" /> Phorvex ON</div>
          <div className="mt-1 text-3xl font-semibold tabular text-primary">{usd(d.totalWith)}/yr</div>
          <div className="mt-1 text-[11px] text-muted-foreground">residual exposure + rotation overhead</div>
        </CardContent></Card>
        <Card className="border-success/40"><CardContent className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] text-success"><TrendingDown className="h-3.5 w-3.5" /> Net saving</div>
          <div className="mt-1 text-3xl font-semibold tabular text-success">{usd(d.totalSavings)}/yr</div>
          <div className="mt-1 text-[11px] text-muted-foreground">at avg disruption across {d.scenarios.length} scenarios</div>
        </CardContent></Card>
      </div>

      {/* LIVE cloud pricing — the defense overhead is computed from this, not a placeholder */}
      {d.pricing && d.pricing.available && (
        <Card className="border-info/30"><CardContent className="space-y-2 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <SectionLabel>Live cloud pricing</SectionLabel>
            <Badge variant="accent">{d.pricing.provider}{d.pricing.region ? ` · ${d.pricing.region}` : ""}</Badge>
            <Badge variant="real">detected from your cluster</Badge>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead><tr className="text-left text-muted-foreground"><th className="px-2 py-1">Instance type</th><th className="px-2 py-1">Count</th><th className="px-2 py-1">$/hr (on-demand)</th><th className="px-2 py-1 text-right">$/yr</th></tr></thead>
              <tbody>
                {d.pricing.nodes.map((n) => (
                  <tr key={n.instanceType} className="border-t border-border/40">
                    <td className="px-2 py-1.5 font-mono">{n.instanceType}{n.gpu && <Badge variant="modeled" className="ml-1">GPU</Badge>}{n.estimated && <span className="ml-1 text-[10px] text-warning">est.</span>}</td>
                    <td className="px-2 py-1.5 tabular">{n.count}</td>
                    <td className="px-2 py-1.5 tabular">${n.pricePerHr.toFixed(4)}</td>
                    <td className="px-2 py-1.5 text-right tabular">{usd(n.pricePerHr * n.count * 8760)}</td>
                  </tr>
                ))}
                <tr className="border-t border-border/60 font-medium">
                  <td className="px-2 py-1.5">Total infrastructure</td>
                  <td className="px-2 py-1.5 tabular">${d.pricing.totalPerHr.toFixed(3)}/hr</td>
                  <td className="px-2 py-1.5" />
                  <td className="px-2 py-1.5 text-right tabular text-foreground">{usd(d.pricing.totalPerYear)}/yr</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="text-[11px] text-muted-foreground">
            <span className="text-foreground">Phorvex defense overhead</span> = <span className="font-medium text-primary">{usd(d.defenseOverhead || 0)}/yr</span> — measured directly: {d.overheadBasis || "the operator's CPU/memory footprint"}, priced at that node's on-demand rate. This is the operator's actual resource cost on your cluster (no assumed % — it's what Phorvex really reserves on real hardware). {d.pricing.source}.
          </div>
        </CardContent></Card>
      )}

      {/* per-scenario */}
      <Card><CardContent className="p-0">
        <div className="px-4 pt-4"><SectionLabel>Per scenario</SectionLabel></div>
        <div className="overflow-x-auto p-3">
          <table className="w-full text-[12px]">
            <thead><tr className="text-left text-muted-foreground">
              <th className="px-2 py-1.5">Scenario</th>
              <th className="px-2 py-1.5">Phorvex OFF</th>
              <th className="px-2 py-1.5">Phorvex ON</th>
              <th className="px-2 py-1.5">Disruption</th>
              <th className="px-2 py-1.5 text-right">Saving</th>
            </tr></thead>
            <tbody>
              {d.scenarios.map((s) => (
                <tr key={s.scenario} className="border-t border-border/40">
                  <td className="px-2 py-2 font-mono text-foreground/90">{s.scenario}</td>
                  <td className="px-2 py-2 tabular text-danger">{usd(s.costWithout)}</td>
                  <td className="px-2 py-2 tabular text-primary">{usd(s.costWith)} <span className="text-muted-foreground/60">({usd(s.defenseCost)}/yr)</span></td>
                  <td className="px-2 py-2 tabular text-muted-foreground">{Math.round(s.disruptWith * 100)}%</td>
                  <td className="px-2 py-2 text-right tabular">
                    {s.helps ? <span className="text-success font-medium">{usd(s.savings)}</span> : <Badge variant="pending">no help</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-4 pb-3 text-[11px] text-muted-foreground">{d.note}</div>
      </CardContent></Card>

      {/* COST OVER TIME — cumulative Phorvex vs blind R6 timer, from the live decision audit */}
      {ts && ts.available && ts.points.length > 0 && (
        <Card><CardContent className="space-y-3 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <SectionLabel>Cost over time — while Phorvex is active</SectionLabel>
            <div className="flex items-center gap-4 text-[11px]">
              <span className="flex items-center gap-1.5"><span className="inline-block h-0.5 w-4 bg-danger" /> blind R6 timer</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-0.5 w-4 bg-primary" /> Phorvex</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-3 rounded-sm bg-success/20" /> savings</span>
            </div>
          </div>
          {ts.points.length === 1 ? (
            <div className="rounded-md border border-border bg-elevated/40 p-4 text-center text-[12px] text-muted-foreground">
              Only one decision so far — cumulative cost: Phorvex <span className="text-primary">{fmtCost(ts.totalPhorvex)}</span> vs blind R6 <span className="text-danger">{fmtCost(ts.totalBlind)}</span> (saving <span className="text-success">{fmtCost(ts.totalSavings)}</span>). The trend line appears once more decisions land.
            </div>
          ) : (
            <CostOverTimeChart ts={ts} />
          )}
          {/* headline cumulative totals */}
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="rounded-md border border-primary/30 bg-primary/[0.04] p-2">
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Phorvex (cumulative)</div>
              <div className="text-lg font-semibold tabular text-primary">{fmtCost(ts.totalPhorvex)}</div>
            </div>
            <div className="rounded-md border border-danger/30 bg-danger/[0.04] p-2">
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Blind R6 (cumulative)</div>
              <div className="text-lg font-semibold tabular text-danger">{fmtCost(ts.totalBlind)}</div>
            </div>
            <div className="rounded-md border border-success/30 bg-success/[0.04] p-2">
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Saved by Phorvex</div>
              <div className="text-lg font-semibold tabular text-success">{fmtCost(ts.totalSavings)}</div>
            </div>
          </div>
          <div className="text-[11px] text-muted-foreground">
            Over {ts.decisions} live decision{ts.decisions === 1 ? "" : "s"}, Phorvex incurred a cumulative cost of <span className="font-medium text-primary">{fmtCost(ts.totalPhorvex)}</span> while a blind fixed-timer (R6) — which rotates every cycle regardless of value — would have incurred <span className="font-medium text-danger">{fmtCost(ts.totalBlind)}</span>. The gap (<span className="font-medium text-success">{fmtCost(ts.totalSavings)}</span>) is what Phorvex's value-targeted decisions save, and it widens the longer Phorvex runs. Costs are unit-less rotation-cost units (the same scale as each decision card), not dollars. {ts.note}
          </div>
        </CardContent></Card>
      )}

      {/* HOW THIS IS CALCULATED — full transparency */}
      <Card className="border-info/30">
        <CardContent className="space-y-3 p-5">
          <SectionLabel>How this is calculated</SectionLabel>
          <div className="rounded-md border border-border bg-elevated/40 p-3 font-mono text-[12px] leading-relaxed text-foreground/90">
            valueAtRisk = your cluster's AWS on-demand infra cost ($/yr)<br />
            cost(Phorvex OFF) = valueAtRisk × (1 − disruption<sub>OFF</sub>)<br />
            cost(Phorvex ON)&nbsp; = valueAtRisk × (1 − disruption<sub>ON</sub>) + defenseOverhead<br />
            headline = single valueAtRisk at the AVERAGE disruption (not summed across scenarios)
          </div>
          <div className="text-[12px] text-muted-foreground">Every input is either a <span className="text-success">live AWS price</span> or a <span className="text-success">measured</span> value — nothing is a fabricated breach figure:</div>
          <table className="w-full text-[12px]">
            <thead><tr className="text-left text-muted-foreground"><th className="px-2 py-1">Input</th><th className="px-2 py-1">Value</th><th className="px-2 py-1">Source</th></tr></thead>
            <tbody>
              <tr className="border-t border-border/40">
                <td className="px-2 py-2 font-mono">disruption (OFF / ON)</td>
                <td className="px-2 py-2 tabular">0% / per-scenario above</td>
                <td className="px-2 py-2"><Badge variant="real">measured</Badge> <span className="text-muted-foreground">on your EKS — did the attack land, or did Phorvex stop it</span></td>
              </tr>
              <tr className="border-t border-border/40">
                <td className="px-2 py-2 font-mono">valueAtRisk</td>
                <td className="px-2 py-2 tabular">{usd(d.scenarios[0]?.avoidedBreach || 0)}/yr</td>
                <td className="px-2 py-2"><Badge variant="real">live AWS</Badge> <span className="text-muted-foreground">your cluster's on-demand infrastructure cost (from the detected instance types above)</span></td>
              </tr>
              <tr className="border-t border-border/40">
                <td className="px-2 py-2 font-mono">defenseOverhead</td>
                <td className="px-2 py-2 tabular">{usd(d.defenseOverhead || d.scenarios[0]?.defenseCost || 0)}/yr</td>
                <td className="px-2 py-2"><Badge variant="real">measured</Badge> <span className="text-muted-foreground">= {d.overheadBasis || "operator CPU/mem footprint"} × node $/yr (the operator's real resource cost)</span></td>
              </tr>
            </tbody>
          </table>
          <div className="rounded-md border border-info/25 bg-info/[0.05] p-3 text-[12px] text-muted-foreground">
            <span className="font-medium text-foreground">Honest scope:</span> both the <span className="text-success">disruption %</span> and the <span className="text-success">dollar figures</span> are real — disruption is measured on your cluster, and the dollars are your live AWS on-demand prices. The <span className="font-medium text-foreground">value at risk is your infrastructure cost</span>, not a business-breach estimate: a real-world breach (data, downtime, reputation) typically costs far more, but that isn't on your AWS bill, so we deliberately ground the comparison in what is — the hardware an attack actually compromises.
          </div>
          <div className="text-[11px] text-muted-foreground">Worked example · <span className="font-mono">{d.scenarios[0]?.scenario || "c1-heldout-cve"}</span>: OFF = {usd(d.scenarios[0]?.avoidedBreach || 0)} × (1−0) = {usd(d.scenarios[0]?.avoidedBreach || 0)}/yr exposed; ON = {usd(d.scenarios[0]?.avoidedBreach || 0)} × (1−{(d.scenarios[0]?.disruptWith ?? 1).toFixed(2)}) + {usd(d.scenarios[0]?.defenseCost || 0)} = {usd((d.scenarios[0]?.avoidedBreach || 0) * (1 - (d.scenarios[0]?.disruptWith ?? 1)) + (d.scenarios[0]?.defenseCost || 0))}/yr.</div>
        </CardContent>
      </Card>
    </div>
  );
}
