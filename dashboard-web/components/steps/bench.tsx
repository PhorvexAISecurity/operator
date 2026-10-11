"use client";
import * as React from "react";
import { ClaimScopeNote } from "@/components/claim-scope";
import { api, Lens, BenchConfigInput, BenchResult, BenchConfigResult, BenchTemporal, OptimizerProbe, OptimizerProbeArm } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { csvDownload } from "@/components/ui/more";
import { RuntimeParameters } from "@/components/steps/runtime-params";
import { cn } from "@/lib/utils";
import { Sliders, Play, Loader2, ShieldCheck, ShieldAlert, Copy, Trash2, Plus, Download, FlaskConical, Skull, Timer, Clock } from "lucide-react";

const SCENARIOS = [
  { id: "nats-broker", label: "NATS brokers · stateful", hint: "3 RAFT brokers, one under a foothold — the stateful quarantine-not-rotate case" },
  { id: "mixed-fleet", label: "Mixed fleet", hint: "crowns, cheap pods, a stateful DB — targeting + proactivity + no-harm" },
  { id: "ai-gpu", label: "AI / GPU", hint: "2 inference pods, one carrying a poisoned LoRA adapter" },
];

function defaultConfig(label: string, over?: Partial<BenchConfigInput>): BenchConfigInput {
  return {
    label, maxMovesPerTick: 1, normSparsity: 0.4, flowDisruption: 0.6, weightSecrets: 0.8,
    minAvailableReplicas: 2, proactiveFloorSec: 900, reactiveOnly: true, lambda: 0.6,
    tickIntervalSec: 10, antiOverRotationSec: 60, ...over,
  };
}

export function BenchStep({ lens }: { lens: Lens }) {
  const [scenario, setScenario] = React.useState("nats-broker");
  const [configs, setConfigs] = React.useState<BenchConfigInput[]>([
    defaultConfig("Reactive · calm baseline", { reactiveOnly: true, maxMovesPerTick: 1 }),
    defaultConfig("Proactive · B=2", { reactiveOnly: false, maxMovesPerTick: 2 }),
  ]);
  const [horizonSec, setHorizonSec] = React.useState(3600);
  const [r6IntervalSec, setR6IntervalSec] = React.useState(15);
  const [res, setRes] = React.useState<BenchResult | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");

  async function run() {
    setBusy(true); setErr("");
    try { const d = await api.benchmarkSim(scenario, configs, horizonSec, r6IntervalSec, lens); setRes(d); }
    catch (e: any) { setErr(String(e?.message || e)); }
    finally { setBusy(false); }
  }

  const HORIZONS = [{ s: 0, l: "off" }, { s: 1800, l: "30 min" }, { s: 3600, l: "1 hour" }, { s: 21600, l: "6 hours" }];

  const update = (i: number, patch: Partial<BenchConfigInput>) => setConfigs((cs) => cs.map((c, j) => (j === i ? { ...c, ...patch } : c)));
  const dup = (i: number) => setConfigs((cs) => [...cs.slice(0, i + 1), { ...cs[i], label: cs[i].label + " (copy)" }, ...cs.slice(i + 1)]);
  const del = (i: number) => setConfigs((cs) => (cs.length > 1 ? cs.filter((_, j) => j !== i) : cs));
  const add = () => setConfigs((cs) => [...cs, defaultConfig("Config " + (cs.length + 1), { reactiveOnly: cs[cs.length - 1]?.reactiveOnly })]);

  function exportCSV() {
    if (!res) return;
    const head = ["claim.scope", "claim.detectorSetKnown", "claim.note", "claim.detectorSet", "claim.recallCap", "claim.brainImage", "claim.gitSHA", "config", "movesSelected", "modeledCoverage", "totalCost", "perDollar", "ablationRatio", "noHarm", "movesPerHour", "vs_r6_blind_cost", "vs_attack_landed_risk", "temporal_phorvex_moves", "temporal_phorvex_cost", "temporal_r6_moves", "temporal_r6_cost", "temporal_r6_stateful_kills", "temporal_savings"];
    const body = res.configs.map((c) => [res.claim?.scope ?? "modeled", String(res.claim?.detectorSetKnown ?? false), res.claim?.note ?? "Detector-visible, reversible projection; recall and security effect unknown.", JSON.stringify(res.claim?.detectorSet ?? []), res.claim?.recallCap ?? "unknown", res.claim?.brainImage ?? "unavailable", res.claim?.gitSHA ?? "unavailable", c.label, c.movesSelected, c.totalCoverage, c.totalCost, c.perDollar, c.ablationRatio, c.statefulRotated ? "VIOLATED" : "ok", c.phorvexMovesPerHour, res.r6BlindCost, res.attackLandedRisk, c.temporal?.phorvexMoves ?? "", c.temporal?.phorvexCost ?? "", c.temporal?.r6Moves ?? "", c.temporal?.r6Cost ?? "", c.temporal?.r6StatefulKills ?? "", c.temporal?.savingsVsR6 ?? ""]);
    csvDownload("phorvex-optimizer-bench.csv", [head, ...body]);
  }

  return (
    <div className="space-y-6">
      {/* header */}
      <div>
        <div className="mb-1 flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.16em] text-primary"><FlaskConical className="h-3.5 w-3.5" /> Optimizer Bench</div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Tune the optimizer, benchmark the outcome</h1>
        <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-muted-foreground">
          Change the optimizer's parameters and run the <span className="text-foreground">real p1-coverage decision engine</span> against a fixed
          scenario — in-process, no live attack. Each config's genuine decision is scored against two baselines: a <span className="text-warning">blind R6 timer</span> and a <span className="text-danger">landed attack</span>. Nothing is synthetic; where a
          parameter doesn't change the decision, you'll see identical results.
        </p>
      </div>

      {/* live: the same economics on every app's real policy, verified from the brain's decisions */}
      <RuntimeParameters lens={lens} />

      <div className="text-[10px] font-mono uppercase tracking-[0.16em] text-muted-foreground/80">In-process simulation · fixed scenario, no live write</div>

      {/* scenario */}
      <div>
        <div className="mb-2 text-[10px] uppercase tracking-wide text-muted-foreground/70">Scenario fleet</div>
        <div className="flex flex-wrap gap-2">
          {SCENARIOS.map((s) => (
            <button key={s.id} onClick={() => setScenario(s.id)} title={s.hint}
              className={cn("rounded-lg border px-3 py-2 text-left text-[12px] transition-colors",
                scenario === s.id ? "border-primary/50 bg-primary/10 text-foreground" : "border-border bg-panel/40 text-muted-foreground hover:bg-elevated")}>
              <div className="font-medium">{s.label}</div>
              <div className="mt-0.5 max-w-xs text-[10px] text-muted-foreground/70">{s.hint}</div>
            </button>
          ))}
        </div>
      </div>

      {/* temporal window */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"><Clock className="h-3.5 w-3.5" /> Time horizon</span>
        {HORIZONS.map((o) => (
          <button key={o.s} onClick={() => setHorizonSec(o.s)}
            className={cn("rounded-md border px-2.5 py-1 text-[11px] transition-colors", horizonSec === o.s ? "border-primary/50 bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:bg-elevated")}>{o.l}</button>
        ))}
        <span className="ml-3 text-[10px] uppercase tracking-wide text-muted-foreground/70">R6 blind timer</span>
        <input type="number" value={r6IntervalSec} min={1} step={5}
          onChange={(e) => { const n = parseFloat(e.target.value); setR6IntervalSec(Number.isFinite(n) ? n : 15); }}
          className="w-16 rounded-md border border-border bg-background/60 px-2 py-1 font-mono text-[11px] tabular text-foreground focus:border-primary focus:outline-none" />
        <span className="text-[10px] text-muted-foreground">s / cycle</span>
        <span className="ml-1 text-[10px] text-muted-foreground/60">{horizonSec > 0 ? "over-time sim on — tick & anti-rotation take effect" : "single-tick only"}</span>
      </div>

      {/* config editor */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-[12px] font-medium text-foreground"><Sliders className="h-3.5 w-3.5 text-primary" /> Configurations to compare</div>
          <Button size="sm" variant="outline" onClick={add} className="ml-auto gap-1.5"><Plus className="h-3.5 w-3.5" /> Add config</Button>
          <Button size="sm" onClick={run} disabled={busy} className="gap-1.5">
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} Run benchmark
          </Button>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          {configs.map((c, i) => (
            <ConfigCard key={i} c={c} onChange={(p) => update(i, p)} onDup={() => dup(i)} onDel={() => del(i)} canDel={configs.length > 1} />
          ))}
        </div>
      </div>

      {err && <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">error: {err}</div>}

      {/* results */}
      {res && <Results res={res} onCSV={exportCSV} />}
    </div>
  );
}

// --- config editor card ---

function ConfigCard({ c, onChange, onDup, onDel, canDel }: { c: BenchConfigInput; onChange: (p: Partial<BenchConfigInput>) => void; onDup: () => void; onDel: () => void; canDel: boolean }) {
  return (
    <Card>
      <CardContent className="space-y-3 p-3.5">
        <div className="flex items-center gap-2">
          <input value={c.label} onChange={(e) => onChange({ label: e.target.value })}
            className="min-w-0 flex-1 rounded-md border border-border bg-background/60 px-2 py-1 text-[12px] font-medium text-foreground focus:border-primary focus:outline-none" />
          <button onClick={onDup} title="Duplicate" className="rounded p-1 text-muted-foreground hover:bg-elevated hover:text-foreground"><Copy className="h-3.5 w-3.5" /></button>
          <button onClick={onDel} disabled={!canDel} title="Remove" className="rounded p-1 text-muted-foreground hover:bg-elevated hover:text-danger disabled:opacity-30"><Trash2 className="h-3.5 w-3.5" /></button>
        </div>

        <div className="text-[9px] uppercase tracking-wide text-primary/80">Decision-shaping · changes the engine's choice</div>
        <div className="grid grid-cols-3 gap-2">
          <Num label="max moves / tick (B)" v={c.maxMovesPerTick} step={1} min={1} max={6} onChange={(v) => onChange({ maxMovesPerTick: Math.round(v) })} hint="Greedy budget — how many moves per tick" />
          <Num label="min avail replicas" v={c.minAvailableReplicas} step={1} min={0} max={5} onChange={(v) => onChange({ minAvailableReplicas: Math.round(v) })} hint="Availability / quorum floor — feasibility veto" />
          <Num label="proactive floor (s)" v={c.proactiveFloorSec} step={60} min={0} onChange={(v) => onChange({ proactiveFloorSec: v })} hint="Hygiene floor + decoy-provenance weight" />
          <Num label="norm sparsity" v={c.normSparsity} step={0.1} min={0} max={1} onChange={(v) => onChange({ normSparsity: v })} hint="Cost-ceiling term (filters expensive moves)" />
          <Num label="flow disruption" v={c.flowDisruption} step={0.1} min={0} max={1} onChange={(v) => onChange({ flowDisruption: v })} hint="Cost-ceiling term (weights connection churn)" />
          <Num label="weight secrets" v={c.weightSecrets} step={0.1} min={0} max={1} onChange={(v) => onChange({ weightSecrets: v })} hint="Asset-value lift for pods mounting secrets" />
        </div>
        <div className="pt-0.5">
          <Toggle on={c.reactiveOnly} onChange={(v) => onChange({ reactiveOnly: v })} label="reactiveOnly" hint="Calm until attacked — only attack-backed pods are actionable" />
        </div>

        <div className="text-[9px] uppercase tracking-wide text-muted-foreground/60">Cadence &amp; pricing · does NOT change a single p1 decision</div>
        <div className="grid grid-cols-3 gap-2 opacity-90">
          <Num label="λ (p0 / seed)" v={c.lambda} step={0.1} min={0} max={4} onChange={(v) => onChange({ lambda: v })} hint="Budget weight for p0-greedy; p1 solves λ online (seed 0.6) — no single-decision effect on p1" />
          <Num label="tick interval (s)" v={c.tickIntervalSec} step={1} min={1} onChange={(v) => onChange({ tickIntervalSec: v })} hint="Evaluation cadence — bounds moves/hour, not the decision" />
          <Num label="anti-rotate (s)" v={c.antiOverRotationSec} step={5} min={0} onChange={(v) => onChange({ antiOverRotationSec: v })} hint="Re-actuation suppression window — bounds per-asset churn, not the decision" />
        </div>
      </CardContent>
    </Card>
  );
}

function Num({ label, v, onChange, step, min, max, hint }: { label: string; v: number; onChange: (v: number) => void; step: number; min?: number; max?: number; hint?: string }) {
  return (
    <label className="flex flex-col gap-1" title={hint}>
      <span className="text-[9px] uppercase leading-tight tracking-wide text-muted-foreground/70">{label}</span>
      <input type="number" value={v} step={step} min={min} max={max}
        onChange={(e) => { const n = parseFloat(e.target.value); onChange(Number.isFinite(n) ? n : 0); }}
        className="w-full rounded-md border border-border bg-background/60 px-2 py-1 font-mono text-[12px] tabular text-foreground focus:border-primary focus:outline-none" />
    </label>
  );
}

function Toggle({ on, onChange, label, hint }: { on: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <button onClick={() => onChange(!on)} title={hint}
      className={cn("flex items-center gap-2 rounded-md border px-2.5 py-1 text-[11px] font-mono transition-colors",
        on ? "border-primary/40 bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:bg-elevated")}>
      <span className={cn("h-2 w-2 rounded-full", on ? "bg-primary" : "bg-muted-foreground/40")} /> {label} · {on ? "on" : "off"}
    </button>
  );
}

// --- results ---

function Results({ res, onCSV }: { res: BenchResult; onCSV: () => void }) {
  const best = res.configs.reduce<BenchConfigResult | null>((b, c) => (!b || c.perDollar > b.perDollar ? c : b), null);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4">
        <div className="text-[13px] font-medium text-foreground">Benchmark result</div>
        <span className="font-mono text-[11px] text-muted-foreground">{res.scenarioLabel}</span>
        <Badge variant="real" className="gap-1">engine {res.engine}</Badge>
        <span className="text-[11px] text-muted-foreground">{res.pods} pods · {res.stateful} stateful · {res.attacked} attacked</span>
        <span className="font-mono text-[10px] text-muted-foreground/60">ran in {res.computeMs}ms{res.horizonSec > 0 ? ` · ${fmtDur(res.horizonSec)} horizon` : " · single-tick"}</span>
        <Button size="sm" variant="outline" onClick={onCSV} className="ml-auto gap-1.5"><Download className="h-3.5 w-3.5" /> CSV</Button>
      </div>

      {/* the two fixed baselines */}
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="rounded-lg border border-danger/30 bg-danger/5 p-3">
          <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-danger"><Skull className="h-3.5 w-3.5" /> Attack landed · no defense</div>
          <div className="tabular text-[20px] font-semibold text-danger">{fmt(res.attackLandedRisk)}<span className="ml-1 text-[11px] font-normal text-muted-foreground">asset value exposed</span></div>
          <div className="mt-0.5 text-[11px] text-muted-foreground">0 moves — the attacker keeps every foothold.</div>
        </div>
        <div className="rounded-lg border border-warning/30 bg-warning/5 p-3">
          <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-warning"><Timer className="h-3.5 w-3.5" /> R6 blind timer · reference</div>
          <div className="tabular text-[20px] font-semibold text-warning">{fmt(res.r6BlindCost)}<span className="ml-1 text-[11px] font-normal text-muted-foreground">churn cost / cycle</span></div>
          <div className="mt-0.5 text-[11px] text-muted-foreground">
            rotates every pod · {fmt0(res.r6BlindMovesPerHour)} moves/hr
            {res.r6DestroysStateful > 0 && <span className="text-danger"> · DELETES {res.r6DestroysStateful} stateful pod{res.r6DestroysStateful > 1 ? "s" : ""} (data loss)</span>}
          </div>
        </div>
      </div>

      <ClaimScopeNote claim={res.claim} />
      {/* comparison table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full min-w-[720px] text-[12px]">
          <thead>
            <tr className="border-b border-border bg-panel/40 text-[10px] uppercase tracking-wide text-muted-foreground">
              <th className="px-3 py-2 text-left font-semibold">Config</th>
              <th className="px-3 py-2 text-right font-semibold">Moves</th>
              <th className="px-3 py-2 text-right font-semibold">Modeled coverage</th>
              <th className="px-3 py-2 text-right font-semibold">Cost</th>
              <th className="px-3 py-2 text-right font-semibold">Per-$</th>
              <th className="px-3 py-2 text-right font-semibold">vs random</th>
              <th className="px-3 py-2 text-center font-semibold" title="Greedy objective / brute-force optimal objective. 1.000 = the greedy matched the exact optimum. Optimality is PROVEN structurally (asset-disjoint facts => modular => Rado-Edmonds), and that proof does not depend on fleet size; this column is the empirical check, shown only where the brute force is tractable. n/a = not measured, never a score.">Greedy=Optimal</th>
              <th className="px-3 py-2 text-center font-semibold">No-harm</th>
              <th className="px-3 py-2 text-right font-semibold">Moves/hr</th>
            </tr>
          </thead>
          <tbody>
            {res.configs.map((c, i) => (
              <tr key={i} className={cn("border-t border-border/60", c === best && "bg-success/5")}>
                <td className="px-3 py-2 font-medium text-foreground">{c.label}{c === best && <span className="ml-2 rounded bg-success/15 px-1.5 text-[9px] uppercase tracking-wide text-success">best per-$</span>}</td>
                <td className="px-3 py-2 text-right tabular text-foreground">{c.movesSelected}</td>
                <td className="px-3 py-2 text-right tabular text-foreground">{fmt(c.totalCoverage)}</td>
                <td className="px-3 py-2 text-right tabular text-foreground">{fmt(c.totalCost)}</td>
                <td className="px-3 py-2 text-right tabular font-semibold text-primary">{fmt(c.perDollar)}</td>
                <td className="px-3 py-2 text-right tabular text-muted-foreground">{c.ablationRatio.toFixed(2)}×</td>
                <td className="px-3 py-2 text-center">
                  {c.exactSkipped
                    ? <span className="tabular text-muted-foreground/60" title="fleet too large to brute-force">n/a</span>
                    : c.optimalityRatio >= 0.9999
                      ? <span className="inline-flex items-center gap-1 text-success" title={c.coversDisjoint ? "asset-disjoint facts => modular => greedy provably optimal" : "greedy matched the optimum"}><ShieldCheck className="h-3 w-3" /> 1.000</span>
                      : <span className="inline-flex items-center gap-1 text-warning" title={`gap ${c.optimalityGap} — a shared recon fact made the objective submodular`}><ShieldAlert className="h-3 w-3" /> {c.optimalityRatio.toFixed(3)}</span>}
                </td>
                <td className="px-3 py-2 text-center">
                  {c.statefulRotated
                    ? <span className="inline-flex items-center gap-1 text-danger"><ShieldAlert className="h-3 w-3" /> violated</span>
                    : <span className="inline-flex items-center gap-1 text-success"><ShieldCheck className="h-3 w-3" /> ok</span>}
                </td>
                <td className="px-3 py-2 text-right tabular text-muted-foreground">{fmt0(c.phorvexMovesPerHour)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="-mt-1 text-[10px] leading-relaxed text-muted-foreground/70">
        <span className="text-success">Greedy=Optimal 1.000</span> means the greedy's selection equals the brute-force optimum for that objective — guaranteed here because the shipped recon facts are <span className="text-foreground">asset-disjoint</span> (each fact is owned by one pod ⇒ the objective is modular). A gap (&lt;1.000) can only appear if a recon profile lets two pods cover the <span className="text-foreground">same</span> fact (submodular) — the deterministic hub-spoke probe pins that boundary at 0.845, and the <span className="text-success">greedy-then-swaps</span> optimizer closes it to 1.000 (card below).
      </p>

      {res.optimizerProbe && <OptimizerGuarantee probe={res.optimizerProbe} />}

      {/* per-config decision detail */}
      <div className="space-y-3">
        {res.configs.map((c, i) => <ConfigResultCard key={i} c={c} r6Blind={res.r6BlindCost} r6Destroys={res.r6DestroysStateful} landed={res.attackLandedRisk} />)}
      </div>

      <div className="rounded-md border border-border/60 bg-elevated/30 p-3 text-[11px] leading-relaxed text-muted-foreground">
        <span className="font-medium text-foreground">Method · </span>{res.note}
      </div>
    </div>
  );
}

function ConfigResultCard({ c, r6Blind, r6Destroys, landed }: { c: BenchConfigResult; r6Blind: number; r6Destroys: number; landed: number }) {
  const cheaper = c.totalCost > 0 ? r6Blind / c.totalCost : 0;
  return (
    <Card className={cn("border-l-2", c.statefulRotated ? "border-l-danger" : "border-l-success")}>
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[13px] font-medium text-foreground">{c.label}</span>
          <Badge variant={c.statefulRotated ? "pending" : "real"} className="gap-1">
            {c.statefulRotated ? <><ShieldAlert className="h-3 w-3" /> no-harm violated</> : <><ShieldCheck className="h-3 w-3" /> no-harm ok</>}
          </Badge>
          <span className="ml-auto font-mono text-[11px] text-muted-foreground">{c.movesSelected} move{c.movesSelected !== 1 ? "s" : ""} · per-$ <span className="text-primary">{fmt(c.perDollar)}</span></span>
        </div>

        {/* three-way arms */}
        <div className="grid grid-cols-3 gap-2">
          <Arm tone="good" label="With Phorvex" big={fmt(c.totalCost)} bigUnit="cost" sub={`${fmt(c.totalCoverage)} modeled coverage · ${cheaper > 1 ? cheaper.toFixed(1) + "× cheaper than R6" : "targeted"}`} />
          <Arm tone="warn" label="R6 blind timer" big={fmt(r6Blind)} bigUnit="cost" sub={r6Destroys > 0 ? `deletes ${r6Destroys} stateful` : "blind churn"} />
          <Arm tone="bad" label="Attack landed" big={fmt(landed)} bigUnit="risk" sub="0 defense" />
        </div>

        {/* per-pod decisions */}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-[11px]">
            <thead>
              <tr className="text-[9px] uppercase tracking-wide text-muted-foreground/70">
                <th className="px-2 py-1 text-left font-medium">Pod</th>
                <th className="px-2 py-1 text-left font-medium">Action</th>
                <th className="px-2 py-1 text-right font-medium">Cov</th>
                <th className="px-2 py-1 text-right font-medium">Cost</th>
                <th className="px-2 py-1 text-right font-medium">Per-$</th>
                <th className="px-2 py-1 text-left font-medium">Stage</th>
                <th className="px-2 py-1 text-right font-medium">pHold</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {c.moves.map((m) => (
                <tr key={m.pod} className={cn("border-t border-border/40", m.selected && "bg-primary/5")}>
                  <td className="px-2 py-1 text-foreground">
                    {m.pod}
                    {m.stateful && <span className="ml-1 rounded bg-elevated px-1 text-[8px] uppercase text-muted-foreground">sf</span>}
                    {m.attacked && <span className="ml-1 rounded bg-danger/15 px-1 text-[8px] uppercase text-danger">atk</span>}
                  </td>
                  <td className={cn("px-2 py-1", m.selected ? (m.action === "rotate" && m.stateful ? "font-semibold text-danger" : "font-semibold text-primary") : "text-muted-foreground")}>
                    {m.action}{m.selected && <span className="ml-1 text-[8px] uppercase text-success">sel</span>}
                  </td>
                  <td className="px-2 py-1 text-right tabular text-foreground/80">{m.selected ? fmt(m.coverage) : "—"}</td>
                  <td className="px-2 py-1 text-right tabular text-foreground/80">{m.selected ? fmt(m.cost) : "—"}</td>
                  <td className="px-2 py-1 text-right tabular text-foreground/80">{m.selected ? fmt(m.perDollar) : "—"}</td>
                  <td className="px-2 py-1 text-muted-foreground">{m.stage}</td>
                  <td className="px-2 py-1 text-right tabular text-muted-foreground">{m.pHold.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {c.temporal && <TemporalBlock t={c.temporal} />}
      </CardContent>
    </Card>
  );
}

function TemporalBlock({ t }: { t: BenchTemporal }) {
  const cheaper = t.phorvexCost > 0 ? t.r6Cost / t.phorvexCost : 0;
  const acts = Object.entries(t.phorvexByAction).map(([a, n]) => `${n}× ${a}`).join(" · ");
  return (
    <div className="rounded-md border border-border/60 bg-elevated/20 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-wide text-muted-foreground/70">
        <Clock className="h-3.5 w-3.5" /> Over {fmtDur(t.horizonSec)} · tick {t.tickSec}s · {t.ticks} ticks
        <span className="ml-auto normal-case text-muted-foreground/60">cumulative actuation cost</span>
      </div>
      <TemporalChart series={t.series} />
      <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Mini label="Phorvex moves" v={fmt0(t.phorvexMoves)} sub={acts} tone="good" />
        <Mini label="Phorvex cost" v={fmt(t.phorvexCost)} sub={cheaper > 1 ? `${cheaper.toFixed(0)}× cheaper than R6` : ""} tone="good" />
        <Mini label="R6 moves" v={fmt0(t.r6Moves)} sub={`every ${t.r6IntervalSec}s`} tone="warn" />
        <Mini label="R6 stateful kills" v={fmt0(t.r6StatefulKills)} sub={t.r6StatefulKills > 0 ? "data destroyed each cycle" : "none"} tone={t.r6StatefulKills > 0 ? "bad" : "warn"} />
      </div>
    </div>
  );
}

// TemporalChart — cumulative actuation cost over time: Phorvex (success) vs R6 blind timer (warning).
function TemporalChart({ series }: { series: BenchTemporal["series"] }) {
  if (!series || series.length < 2) return null;
  const W = 320, H = 96, PADX = 3, PADT = 6, PADB = 12;
  const maxSec = series[series.length - 1].sec || 1;
  const maxCost = Math.max(1, ...series.map((p) => p.r6Cum), ...series.map((p) => p.phorvexCum));
  const x = (s: number) => PADX + (s / maxSec) * (W - 2 * PADX);
  const y = (c: number) => H - PADB - (c / maxCost) * (H - PADT - PADB);
  const path = (key: "phorvexCum" | "r6Cum") => series.map((p, i) => `${i === 0 ? "M" : "L"}${x(p.sec).toFixed(1)},${y(p[key]).toFixed(1)}`).join(" ");
  const last = series[series.length - 1];
  return (
    <div className="w-full overflow-hidden">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-24 w-full" preserveAspectRatio="none" role="img" aria-label="cumulative cost over time: Phorvex vs R6 blind timer">
        <line x1={PADX} y1={H - PADB} x2={W - PADX} y2={H - PADB} className="stroke-border" strokeWidth={0.5} />
        <path d={path("r6Cum")} fill="none" className="stroke-warning" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
        <path d={path("phorvexCum")} fill="none" className="stroke-success" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
        <circle cx={x(last.sec)} cy={y(last.r6Cum)} r={2} className="fill-warning" />
        <circle cx={x(last.sec)} cy={y(last.phorvexCum)} r={2} className="fill-success" />
      </svg>
      <div className="mt-1 flex items-center justify-between text-[9px] text-muted-foreground/70">
        <span className="flex items-center gap-3">
          <span className="flex items-center gap-1"><span className="inline-block h-1.5 w-3 rounded-sm bg-success" /> Phorvex</span>
          <span className="flex items-center gap-1"><span className="inline-block h-1.5 w-3 rounded-sm bg-warning" /> R6 blind</span>
        </span>
        <span className="tabular">0 → {fmtDur(maxSec)}</span>
      </div>
    </div>
  );
}

function Mini({ label, v, sub, tone }: { label: string; v: string; sub?: string; tone: "good" | "warn" | "bad" }) {
  const txt = tone === "good" ? "text-success" : tone === "warn" ? "text-warning" : "text-danger";
  return (
    <div>
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground/70">{label}</div>
      <div className={cn("tabular text-[15px] font-semibold", txt)}>{v}</div>
      {sub && <div className="text-[9px] leading-tight text-muted-foreground">{sub}</div>}
    </div>
  );
}

function fmtDur(sec: number) {
  if (sec >= 3600) return `${Math.round(sec / 3600)}h`;
  if (sec >= 60) return `${Math.round(sec / 60)}m`;
  return `${Math.round(sec)}s`;
}

// OptimizerGuarantee — the live proof that the greedy is optimal on disjoint facts, and that
// greedy-then-swaps closes the one shared-fact gap the optimization note flagged (0.845 -> 1.000).
function OptimizerGuarantee({ probe }: { probe: OptimizerProbe }) {
  return (
    <div className="rounded-lg border border-border bg-panel/40 p-4">
      <div className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-foreground"><ShieldCheck className="h-3.5 w-3.5 text-primary" /> Optimizer optimality — greedy vs greedy+swaps vs exact</div>
      <p className="mb-3 max-w-3xl text-[11px] leading-relaxed text-muted-foreground">
        Run live on two probes (B={probe.b}, λ={probe.lambda}). On <span className="text-foreground">asset-disjoint</span> facts — like everything the engine ships — the greedy is already provably optimal. On a synthetic <span className="text-foreground">shared-fact</span> stress case the plain greedy drops to 0.845; the <span className="text-foreground">greedy-then-swaps</span> local search closes it to 1.000 with no regression on the disjoint control.
      </p>
      <div className="grid gap-2 md:grid-cols-2">
        <ProbeArm arm={probe.shared} label="Shared facts · hub-spoke stress probe" note="synthetic — does NOT occur under the shipped recon profile" />
        <ProbeArm arm={probe.disjoint} label="Disjoint facts · control (= shipped profile)" note="each fact owned by one pod — modular" />
      </div>
    </div>
  );
}

function ProbeArm({ arm, label, note }: { arm: OptimizerProbeArm; label: string; note: string }) {
  // An arm above the brute-force cap has no exact solve to compare against, so NEITHER ratio was
  // measured. Rendering a number here would state a result that was never computed (PHVX-23).
  const skipped = arm.exactSkipped;
  const closed = !skipped && arm.greedyRatio < 0.999 && arm.swapRatio >= 0.999;
  const ratio = (v: number, tone: string) =>
    skipped
      ? <span className="tabular text-[18px] font-semibold text-muted-foreground/60" title="fleet exceeded the brute-force cap — not measured">n/a</span>
      : <span className={cn("tabular text-[18px] font-semibold", tone)}>{v.toFixed(3)}</span>;
  return (
    <div className="rounded-md border border-border/60 bg-panel/50 p-3">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70">{label}</div>
      <div className="mt-2 flex items-end gap-4">
        <div>
          <div className="text-[9px] uppercase tracking-wide text-muted-foreground/60">Greedy</div>
          {ratio(arm.greedyRatio, arm.greedyRatio >= 0.999 ? "text-success" : "text-warning")}
        </div>
        <div className="pb-1 text-muted-foreground/40">→</div>
        <div>
          <div className="text-[9px] uppercase tracking-wide text-muted-foreground/60">Greedy+swaps</div>
          {ratio(arm.swapRatio, arm.swapRatio >= 0.999 ? "text-success" : "text-warning")}
        </div>
        {closed && <span className="mb-1 ml-auto rounded bg-success/15 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-success">gap closed</span>}
      </div>
      <div className="mt-2 font-mono text-[10px] leading-relaxed text-muted-foreground">
        greedy {arm.greedyObjective} → swaps {arm.swapObjective} · exact {arm.exactObjective}<br />
        picks: <span className="text-foreground/80">[{arm.swapPicks.join(", ")}]</span>
      </div>
      <div className="mt-1 text-[9px] text-muted-foreground/60">{note}</div>
    </div>
  );
}

function Arm({ tone, label, big, bigUnit, sub }: { tone: "good" | "warn" | "bad"; label: string; big: string; bigUnit: string; sub: string }) {
  const txt = tone === "good" ? "text-success" : tone === "warn" ? "text-warning" : "text-danger";
  return (
    <div className="rounded-md border border-border/60 bg-panel/40 p-2">
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground/70">{label}</div>
      <div className={cn("tabular text-[16px] font-semibold", txt)}>{big}<span className="ml-1 text-[9px] font-normal text-muted-foreground">{bigUnit}</span></div>
      <div className="mt-0.5 text-[9px] leading-tight text-muted-foreground">{sub}</div>
    </div>
  );
}

function fmt(n?: number) {
  if (n == null) return "—";
  return (Math.round(n * 100) / 100).toLocaleString(undefined, { maximumFractionDigits: 2 });
}
function fmt0(n?: number) {
  if (n == null) return "—";
  return Math.round(n).toLocaleString();
}
