"use client";
import * as React from "react";
import { api, Lens, CostResult } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { ShieldOff, ShieldCheck, TrendingDown, Loader2 } from "lucide-react";

function usd(n: number): string {
  if (n >= 1e6) return `$${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(1)}k`;
  return `$${Math.round(n)}`;
}

export function CostPanel({ lens }: { lens: Lens }) {
  const [d, setD] = React.useState<CostResult | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => { api.cost(lens).then(setD).catch((e) => setErr(String(e.message || e))); }, [lens]);

  if (err) return <ErrorState msg={err} />;
  if (!d) return <Card><CardContent className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> computing cost…</CardContent></Card>;
  if (!d.available || !d.scenarios.length) return <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">No benchmark cost data yet — run the with/without-Phorvex benchmark (or an Attack Lab scenario) to populate it.</CardContent></Card>;

  return (
    <div className="space-y-5">
      <PageHead title="Cost — with vs without Phorvex" sub="What the platform owner carries per attack: with Phorvex OFF the attack lands and you eat the breach exposure; with Phorvex ON the residual breach shrinks by the measured disruption, for the MTD rotation overhead ($/yr). Every $ traces to the benchmark roi block." />

      {/* headline: OFF vs ON vs savings */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Card><CardContent className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] text-danger"><ShieldOff className="h-3.5 w-3.5" /> Phorvex OFF</div>
          <div className="mt-1 text-3xl font-semibold tabular text-danger">{usd(d.totalWithout)}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">total breach exposure (attacks land)</div>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] text-primary"><ShieldCheck className="h-3.5 w-3.5" /> Phorvex ON</div>
          <div className="mt-1 text-3xl font-semibold tabular text-primary">{usd(d.totalWith)}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">residual breach + MTD overhead</div>
        </CardContent></Card>
        <Card className="border-success/40"><CardContent className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] text-success"><TrendingDown className="h-3.5 w-3.5" /> Net saving</div>
          <div className="mt-1 text-3xl font-semibold tabular text-success">{usd(d.totalSavings)}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">across {d.scenarios.length} scenarios</div>
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
            <span className="text-foreground">Phorvex defense overhead</span> = {usd(d.pricing.totalPerYear)}/yr × {Math.round((d.overheadPercent || 0.015) * 1000) / 10}% rotation overhead = <span className="font-medium text-primary">{usd(d.pricing.totalPerYear * (d.overheadPercent || 0.015))}/yr</span> — this is the live, real cost of running Phorvex on your cluster (replaces the old placeholder). {d.pricing.source}.
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

      {/* HOW THIS IS CALCULATED — full transparency */}
      <Card className="border-info/30">
        <CardContent className="space-y-3 p-5">
          <SectionLabel>How this is calculated</SectionLabel>
          <div className="rounded-md border border-border bg-elevated/40 p-3 font-mono text-[12px] leading-relaxed text-foreground/90">
            cost(Phorvex OFF) = avoidedBreach × (1 − disruption<sub>OFF</sub>)<br />
            cost(Phorvex ON)&nbsp; = avoidedBreach × (1 − disruption<sub>ON</sub>) + defenseOverhead<br />
            saving = cost(OFF) − cost(ON)
          </div>
          <div className="text-[12px] text-muted-foreground">Each input, and whether it is <span className="text-success">measured</span> or an <span className="text-warning">assumed knob</span>:</div>
          <table className="w-full text-[12px]">
            <thead><tr className="text-left text-muted-foreground"><th className="px-2 py-1">Input</th><th className="px-2 py-1">Value</th><th className="px-2 py-1">Source</th></tr></thead>
            <tbody>
              <tr className="border-t border-border/40">
                <td className="px-2 py-2 font-mono">disruption (OFF / ON)</td>
                <td className="px-2 py-2 tabular">0% / per-scenario above</td>
                <td className="px-2 py-2"><Badge variant="real">measured</Badge> <span className="text-muted-foreground">on your EKS — did the attack land, or did Phorvex stop it</span></td>
              </tr>
              <tr className="border-t border-border/40">
                <td className="px-2 py-2 font-mono">avoidedBreach</td>
                <td className="px-2 py-2 tabular">{usd(d.scenarios[0]?.avoidedBreach || 0)}</td>
                <td className="px-2 py-2"><Badge variant="pending">assumed</Badge> <span className="text-muted-foreground">$ a prevented compromise saves — industry-avg placeholder, swap for your number</span></td>
              </tr>
              <tr className="border-t border-border/40">
                <td className="px-2 py-2 font-mono">defenseOverhead</td>
                <td className="px-2 py-2 tabular">{usd(d.scenarios[0]?.defenseCost || 0)}/yr</td>
                <td className="px-2 py-2"><Badge variant="pending">assumed</Badge> <span className="text-muted-foreground">= gpuCount × $/GPU-hr × 8760 × overhead% (MTD rotation cost)</span></td>
              </tr>
            </tbody>
          </table>
          <div className="rounded-md border border-warning/25 bg-warning/[0.05] p-3 text-[12px] text-muted-foreground">
            <span className="font-medium text-foreground">Honest scope:</span> only the <span className="text-success">disruption %</span> is measured on your cluster. The <span className="text-warning">dollar scale</span> follows entirely from the assumed <span className="font-mono">avoidedBreach</span> and GPU-cost knobs — change them and every figure rescales. The structure (Phorvex stops the attack → you avoid that fraction of the breach for a small rotation overhead) is real; the absolute dollars are only as real as the inputs you provide.
          </div>
          <div className="text-[11px] text-muted-foreground">Worked example · <span className="font-mono">c1-heldout-cve</span>: OFF = {usd(d.scenarios[0]?.avoidedBreach || 0)} × (1−0) = {usd(d.scenarios[0]?.avoidedBreach || 0)}; ON = {usd(d.scenarios[0]?.avoidedBreach || 0)} × (1−1.0) + {usd(d.scenarios[0]?.defenseCost || 0)} = {usd(d.scenarios[0]?.defenseCost || 0)}.</div>
        </CardContent>
      </Card>
    </div>
  );
}
