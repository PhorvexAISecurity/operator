"use client";
import * as React from "react";
import { api, Lens, MatrixResult, AISurface, MetricsResult, CoverageTechnique, liveStream, PodRisk } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Loading, ErrorBox, Empty } from "@/components/ui/more";
import { SectionLabel } from "@/components/panels/effectiveness";
import { cn } from "@/lib/utils";
import { ShieldAlert, Brain, Grid3x3, Flame, TrendingUp, Check, X } from "lucide-react";

/* ---------- (1) UNCOVERED ATT&CK CELLS — the honest gap ---------- */
export function UncoveredFrontier({ lens }: { lens: Lens }) {
  const [tech, setTech] = React.useState<CoverageTechnique[] | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => { api.threatMatrix(lens).then((d) => setTech(d.techniques ?? [])).catch((e) => setErr(String(e.message || e))); }, [lens]);
  if (err) return <ErrorBox msg={err} />;
  if (!tech) return <Loading label="Reading the threat-coverage map…" rows={3} />;
  const uncovered = tech.filter((t) => !t.covered);
  const covered = tech.filter((t) => t.covered);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-baseline gap-1.5"><span className="text-3xl font-semibold tabular text-success">{covered.length}</span><span className="text-sm text-muted-foreground">disrupted</span></div>
        <div className="flex items-baseline gap-1.5"><span className="text-3xl font-semibold tabular text-warning">{uncovered.length}</span><span className="text-sm text-muted-foreground">not yet disrupted (the honest gap)</span></div>
        <div className="text-[12px] text-muted-foreground">of {tech.length} ATT&CK/ATLAS techniques in the catalog</div>
      </div>
      {uncovered.length === 0 ? <Empty msg="Every catalogued technique has at least one PX-disrupted scenario." /> : (
        <Card><CardContent className="p-5">
          <SectionLabel>Uncovered techniques — no PX-disrupting scenario yet</SectionLabel>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {uncovered.map((t) => (
              <span key={t.technique} className="group inline-flex items-center gap-1 rounded-md border border-warning/30 bg-warning/[0.06] px-2 py-1 font-mono text-[11px] text-warning" title={(t.scenarios || []).join(", ")}>
                <X className="h-3 w-3" /> {t.technique}{t.product === "ai" && <Badge variant="pending">AI</Badge>}
              </span>
            ))}
          </div>
          <div className="mt-3 text-[11px] text-muted-foreground">A coverage-claiming product must show its gaps — these are the cells the threat matrix does not yet turn green. Computed live from the catalog × the disrupted-scenario set (no hardcoding).</div>
        </CardContent></Card>
      )}
    </div>
  );
}

/* ---------- (2) AI HONEST BOUNDARY + (5) split-oracle/Schwartau/reuse decode ---------- */
export function AIBoundary({ lens }: { lens: Lens }) {
  const [a, setA] = React.useState<AISurface | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => { api.aiSurface(lens).then(setA).catch((e) => setErr(String(e.message || e))); }, [lens]);
  if (err) return <ErrorBox msg={err} />;
  if (!a) return <Loading label="Decoding the AI attack-surface…" rows={3} />;
  // [P4-dash null-guard] Go marshals a nil map/slice as null; normalize before Object.entries/.length.
  const mtdEffect = a.mtdEffect ?? {}, splitOracle = a.splitOracle ?? {}, atlasIds = a.atlasIds ?? [], owaspIds = a.owaspIds ?? [];
  const mtdTotal = Object.values(mtdEffect).reduce((x, y) => x + y, 0) || 1;
  return (
    <div className="space-y-4">
      <Card><CardContent className="p-5">
        <div className="flex items-center gap-2 text-[13px] font-semibold"><ShieldAlert className="h-4 w-4 text-warning" /> The honest boundary</div>
        <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-success/25 bg-success/[0.04] p-3">
            <div className="text-[12px] font-medium text-success">PROVEN — Kubernetes</div>
            <div className="mt-1 text-[12px] text-muted-foreground">Zero-day disruption, dwell, work-preserved, recon-invalidation — measured with 95% CIs (see Effectiveness / Benchmarks).</div>
          </div>
          <div className="rounded-lg border border-warning/30 bg-warning/[0.05] p-3">
            <div className="text-[12px] font-medium text-warning">[SP-0-PENDING-P4] — AI / inference defense</div>
            <div className="mt-1 text-[12px] text-muted-foreground">The AI defender slot is a stub: <span className="font-mono text-foreground/80">d-phorvex-slot</span> disruption = <span className="tabular font-semibold text-warning">{a.slotDisruptMax}</span> across <span className="tabular">{a.slotRows}</span> rows. No panel derives an AI effectiveness number.</div>
          </div>
        </div>
      </CardContent></Card>

      <Card><CardContent className="p-5">
        <SectionLabel>What MTD can structurally do to the AI attack-surface (mtdEffect)</SectionLabel>
        <div className="mt-2 space-y-2">
          {Object.entries(mtdEffect).sort((x, y) => y[1] - x[1]).map(([k, v]) => (
            <div key={k} className="flex items-center gap-3">
              <span className="w-44 shrink-0 font-mono text-[12px]">{k}</span>
              <div className="h-2.5 flex-1 rounded-full bg-muted/40"><div className={cn("h-2.5 rounded-full", k.includes("CANNOT") ? "bg-warning/70" : k.includes("NEUTRAL") ? "bg-success/70" : "bg-info/60")} style={{ width: `${(v / mtdTotal) * 100}%` }} /></div>
              <span className="w-24 text-right text-[11px] tabular text-muted-foreground">{v} ({((v / mtdTotal) * 100).toFixed(0)}%)</span>
            </div>
          ))}
        </div>
        <div className="mt-2 text-[11px] text-muted-foreground">Honest structural classification of the THREAT — e.g. an in-request prompt-injection is <span className="font-mono">MTD-CANNOT-HELP</span>. This is attack-surface analysis, not a PX defense result.</div>
      </CardContent></Card>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Mini2 label="AI scenarios" value={String(a.scenarios)} />
        <Mini2 label="ATLAS techniques" value={String(atlasIds.length)} />
        <Mini2 label="OWASP-LLM tags" value={String(owaspIds.length)} />
        <Mini2 label="attack-surface rows" value={String(a.totalRows)} />
      </div>
      <Card><CardContent className="p-4">
        <SectionLabel>Split-oracle · Schwartau · reuse decode (attack-surface)</SectionLabel>
        <div className="mt-2 grid grid-cols-1 gap-2 text-[12px] sm:grid-cols-3">
          <div className="rounded-md border border-border/60 px-3 py-2">split-oracle: {Object.entries(splitOracle).map(([k, v]) => `${k}=${v}`).join(", ") || "—"}</div>
          <div className="rounded-md border border-border/60 px-3 py-2">Schwartau P/D/R rows: <span className="tabular">{a.schwartauRows}</span></div>
          <div className="rounded-md border border-border/60 px-3 py-2">replay reuse: {a.replayReduced}</div>
        </div>
        <div className="mt-2 text-[10px] text-muted-foreground/60">All AI rows are attack-surface measurements, honestly NOT PX defense efficacy. IP internals are Investor/Operator-only.</div>
      </CardContent></Card>
    </div>
  );
}

/* ---------- (3) 52×N MATRIX + LEARNABILITY + FALSE-POSITIVE ---------- */
export function MatrixPanel({ lens }: { lens: Lens }) {
  const [m, setM] = React.useState<MatrixResult | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => { api.matrix(lens).then(setM).catch((e) => setErr(String(e.message || e))); }, [lens]);
  if (err) return <ErrorBox msg={err} />;
  if (!m) return <Loading label="Computing the scenario×arm matrix…" rows={4} />;
  // [P4-dash null-guard] normalize every wire array before .length/.map/.find.
  const cells = m.cells ?? [], scenarios = m.scenarios ?? [], arms = m.arms ?? [], learnability = m.learnability ?? [];
  if (scenarios.length === 0 || arms.length === 0) return <Empty msg="No scenario×arm matrix yet — run the benchmark suite (Prove) to populate it." />;
  const cellOf = (s: string, a: string) => cells.find((c) => c.scenario === s && c.arm === a);
  const hue = (d: number) => d >= 0.8 ? "bg-success/70" : d >= 0.4 ? "bg-warning/60" : d > 0 ? "bg-warning/30" : "bg-muted/30";
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Mini2 label="False-positive rate (no-attack)" value={`${(m.fpRate * 100).toFixed(0)}%`} tone={m.fpRate === 0 ? "success" : "warning"} sub={`${m.fpViolations}/${m.fpRows} negative-control rows`} />
        <Mini2 label="Scenarios × arms" value={`${scenarios.length}×${arms.length}`} sub={m.source} />
        <Mini2 label="Matrix cells" value={String(cells.length)} />
      </div>

      <Card><CardContent className="p-4 overflow-x-auto">
        <SectionLabel>Disruption matrix · scenario × defender arm (mean over trials)</SectionLabel>
        <table className="mt-2 w-full border-separate" style={{ borderSpacing: 2 }}>
          <thead><tr><th className="sticky left-0 bg-background text-left text-[10px] font-medium uppercase text-muted-foreground"></th>{arms.map((a) => <th key={a} className="px-1 text-[10px] font-mono text-muted-foreground" title={a}>{a.replace("d-", "")}</th>)}</tr></thead>
          <tbody>{scenarios.map((s) => (
            <tr key={s}>
              <td className="sticky left-0 bg-background pr-2 font-mono text-[11px] text-foreground/80">{s}</td>
              {arms.map((a) => { const c = cellOf(s, a); return (
                <td key={a} className="p-0"><div className={cn("grid h-7 w-12 place-items-center rounded text-[10px] tabular", c ? hue(c.disruption) : "bg-muted/20")} title={c ? `${(c.disruption * 100).toFixed(0)}% (n=${c.n})` : "—"}>{c ? (c.disruption * 100).toFixed(0) : ""}</div></td>
              ); })}
            </tr>
          ))}</tbody>
        </table>
      </CardContent></Card>

      {learnability.length > 0 && (
        <Card><CardContent className="p-5">
          <div className="flex items-center gap-2 text-[13px] font-semibold"><TrendingUp className="h-4 w-4 text-primary" /> Learnability — does the defense survive an adaptive attacker? <span className="font-mono text-[11px] text-muted-foreground">({m.learnScenario})</span></div>
          <div className="mt-3 space-y-2">{learnability.map((L) => (
            <div key={L.arm} className="flex items-center gap-3 text-[12px]">
              <span className="w-32 shrink-0 font-mono">{L.arm.replace("d-", "")}</span>
              <span className="w-28 tabular text-muted-foreground">first {(L.firstHalf * 100).toFixed(0)}% → last {(L.secondHalf * 100).toFixed(0)}%</span>
              <div className="h-2 flex-1 rounded-full bg-muted/40"><div className={cn("h-2 rounded-full", L.mean >= 0.8 ? "bg-success/70" : L.mean >= 0.3 ? "bg-warning/60" : "bg-muted/50")} style={{ width: `${Math.max(2, L.mean * 100)}%` }} /></div>
              <span className="w-12 text-right tabular font-medium">{(L.mean * 100).toFixed(0)}%</span>
            </div>
          ))}</div>
          <div className="mt-3 text-[11px] text-muted-foreground">Phorvex holds disruption as the attacker adapts; a fixed/random policy is learnable and degrades. Computed from the real adaptive-scenario trials.</div>
        </CardContent></Card>
      )}
    </div>
  );
}

/* ---------- (4) RISK HEATMAP (live /metrics scrape, falls back to the live audit) ---------- */
export function RiskHeatmap({ lens }: { lens: Lens }) {
  const [pods, setPods] = React.useState<PodRisk[] | null>(null);
  const [source, setSource] = React.useState("");
  const [err, setErr] = React.useState("");
  React.useEffect(() => {
    let done = false;
    api.metrics(lens).then((m: MetricsResult) => {
      if (m.available && (m.pods ?? []).length) { setSource(`operator /metrics (${m.source})`); setPods(m.pods ?? []); done = true; }
    }).catch(() => {}).finally(() => {
      if (done) return;
      // fallback: build the heatmap from the LIVE decision audit (real per-pod risk/blast).
      const map = new Map<string, PodRisk>();
      const stop = liveStream(lens, (e) => {
        if (!e.pod) return;
        map.set(`${e.namespace}/${e.pod}`, { namespace: e.namespace, pod: e.pod, risk: e.risk ?? 0, blast: e.blastRadius ?? 0, perDollar: e.perDollar ?? 0 });
      });
      setTimeout(() => { stop(); setSource("live decision audit (operator /metrics [PENDING-wire])"); setPods(Array.from(map.values()).sort((a, b) => b.risk - a.risk)); }, 2500);
    });
  }, [lens]);
  if (err) return <ErrorBox msg={err} />;
  if (!pods) return <Loading label="Reading per-pod risk (operator /metrics, then the live audit)…" rows={2} />;
  if (pods.length === 0) return <Empty msg="No per-pod risk yet — start Phorvex (Protect) or run a scenario. The production source is an operator /metrics scrape [PENDING-wire]; the live audit is the fallback." />;
  const max = Math.max(0.01, ...pods.map((p) => p.risk));
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[12px]"><Badge variant="real"><Flame className="h-2.5 w-2.5" /> live</Badge><span className="text-muted-foreground">{pods.length} pods from <span className="font-mono">{source}</span></span></div>
      <Card><CardContent className="p-4">
        <SectionLabel>Per-pod risk (risk score · halo = blast radius)</SectionLabel>
        <div className="mt-2 space-y-1.5">{pods.map((p) => (
          <div key={p.namespace + p.pod} className="flex items-center gap-3 text-[12px]">
            <span className="w-48 shrink-0 truncate font-mono">{p.namespace}/{p.pod}</span>
            <div className="h-3 flex-1 rounded bg-muted/40"><div className="h-3 rounded bg-danger/60" style={{ width: `${(p.risk / max) * 100}%` }} /></div>
            <span className="w-20 text-right tabular text-muted-foreground">risk {p.risk.toFixed(2)}</span>
            <span className="w-16 text-right tabular text-muted-foreground/70">blast {p.blast.toFixed(1)}</span>
          </div>
        ))}</div>
        <div className="mt-2 text-[10px] text-muted-foreground/60">Risk/blast/per-$ are IP — Investor/Operator only.</div>
      </CardContent></Card>
    </div>
  );
}

function Mini2({ label, value, tone, sub }: { label: string; value: string; tone?: string; sub?: string }) {
  const c = tone === "success" ? "text-success" : tone === "warning" ? "text-warning" : "text-foreground";
  return <Card><CardContent className="p-3"><div className={cn("text-2xl font-semibold tabular", c)}>{value}</div><div className="mt-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>{sub && <div className="mt-0.5 text-[10px] text-muted-foreground/60">{sub}</div>}</CardContent></Card>;
}
