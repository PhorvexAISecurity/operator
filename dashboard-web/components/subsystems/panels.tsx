"use client";
import * as React from "react";
import { ClaimScopeNote } from "@/components/claim-scope";
import { api, Lens, liveStream, ScanResult, PolicyView, RegistryView, AblationResult } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Table, THead, TH, TR, TD, Loading, ErrorBox, Empty, Pending, Segmented } from "@/components/ui/more";
import { SectionLabel } from "@/components/panels/effectiveness";
import { cn } from "@/lib/utils";
import { Cpu, Radar, GitBranch, Boxes, Coins, FlaskConical, Activity, Check, X, Loader2 } from "lucide-react";

// collect live audit Records over `ms` (operator/investor get full internals).
function useAudit(lens: Lens, ms = 3000) {
  const [recs, setRecs] = React.useState<any[] | null>(null);
  React.useEffect(() => {
    const map = new Map<string, any>();
    const stop = liveStream(lens, (e) => { if (e.pod) map.set(`${e.namespace}/${e.pod}`, e); });
    const t = setTimeout(() => { stop(); setRecs(Array.from(map.values())); }, ms);
    return () => { stop(); clearTimeout(t); };
  }, [lens]);
  return recs;
}

/* ---------- PHYSICS (from --scan) ---------- */
export function PhysicsPanel({ lens, ns = "scandemo" }: { lens: Lens; ns?: string }) {
  const [scan, setScan] = React.useState<ScanResult | null>(null);
  const [err, setErr] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const run = React.useCallback((n: string) => { setLoading(true); setErr(""); api.scan(n, lens).then(setScan).catch((e) => setErr(String(e.message || e))).finally(() => setLoading(false)); }, [lens]);
  React.useEffect(() => { run(ns); }, [run, ns]);
  if (err) return <ErrorBox msg={err} />;
  if (loading || !scan) return <Loading label="Running phorvex --scan (live physics)…" rows={3} />;

  // [P4-dash null-guard] NEVER read .length/.map on a possibly-null wire field.
  const witness = scan.witness ?? [];
  const killchain = scan.killchain ?? [];
  const scope = ns ? `namespace "${ns}"` : "all namespaces";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
        <Badge variant="accent">{scan.platform || "generic-k8s"}</Badge>
        <span>{scan.nodes} node · {scan.pods || witness.length} pods scanned</span>
        <Badge variant="real">K8s API · live</Badge>
        {witness.some((w) => w.gpuPresent) ? <Badge variant="real">DCGM/GPU · live</Badge> : <Badge variant="pending">DCGM/GPU [SP-0-PENDING-P4a]</Badge>}
      </div>
      {witness.length === 0 ? <Empty msg={`No pods discovered in ${scope}. Start Phorvex (Protect) or run a scenario, or check the cluster context.`} /> : (
        <Card><CardContent className="p-0">
          <Table>
            <THead><TH>Pod</TH><TH>Image-rarity</TH><TH>Co-residency</TH><TH>Sched-slack</TH><TH>EPSS</TH><TH>Stateful</TH><TH>MIG</TH><TH>GPU VRAM</TH><TH>GPU SM</TH></THead>
            <tbody>{witness.map((w) => (
              <TR key={w.pod}>
                <TD className="font-mono text-[12px]">{w.pod}</TD>
                <TD className="tabular"><Bar v={(w.imageRarity - 1)} max={1} tone="primary" label={w.imageRarity.toFixed(2)} /></TD>
                <TD className="tabular"><Bar v={(w.coResidency - 1)} max={1} tone="warning" label={w.coResidency.toFixed(2)} /></TD>
                <TD className="tabular">{w.slack.toFixed(2)}</TD>
                <TD className="tabular">{w.epss.toFixed(2)}</TD>
                <TD>{w.stateful ? <span className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/[0.08] px-1.5 py-0.5 text-[10px] font-medium text-warning" title="StatefulSet/Job-owned or PVC-backed — rotate is auto-vetoed (statefulIntegrity); Phorvex quarantines to preserve state">stateful</span> : <span className="text-muted-foreground/40">—</span>}</TD>
                <TD>{w.migValid ? <Check className="h-3.5 w-3.5 text-success" /> : <X className="h-3.5 w-3.5 text-muted-foreground" />}</TD>
                <TD className="tabular">{w.gpuPresent ? <Bar v={w.vramFraction} max={1} tone="accent" label={`${Math.round(w.vramFraction * 100)}%`} /> : <span className="text-muted-foreground/40">—</span>}</TD>
                <TD className="tabular">{w.gpuPresent ? <Bar v={w.smOccupancy} max={1} tone="accent" label={`${Math.round(w.smOccupancy * 100)}%`} /> : <span className="text-muted-foreground/40">—</span>}</TD>
              </TR>
            ))}</tbody>
          </Table>
        </CardContent></Card>
      )}
      <Card><CardContent className="p-4">
        <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">EMR scarcity ablation (recon-invalidation weighting)</div>
        <div className="flex flex-wrap items-center gap-6 text-[13px]">
          <span>baseline (standard-recon) <span className="tabular font-medium">{scan.emr.baseline.toFixed(3)}</span></span>
          <span>scarcity (ucw-recon) <span className="tabular font-medium">{scan.emr.scarcity.toFixed(3)}</span></span>
          <span>lift <span className={cn("tabular font-semibold", scan.emr.lift >= 1 ? "text-success" : "text-warning")}>{scan.emr.lift.toFixed(2)}×</span></span>
        </div>
        {scan.emr.note && <div className="mt-1.5 text-[11px] text-muted-foreground">{scan.emr.note}</div>}
        <div className="mt-1 text-[10px] text-muted-foreground/60">EMR formula + per-asset scalar are IP — Investor/Operator only; the owner lens never sees this panel.</div>
      </CardContent></Card>
      {killchain.length > 0 && <><SectionLabel>Context · kill-chain stage + moved-before-next-stage horizon</SectionLabel><ContextDetail scan={scan} /></>}
    </div>
  );
}

/* ---------- CONTEXT (from --scan kill-chain) ---------- */
export function ContextDetail({ scan }: { scan: ScanResult }) {
  if (!scan.killchain?.length) return null;
  return (
    <Card><CardContent className="p-0">
      <Table>
        <THead><TH>Pod</TH><TH>Stage</TH><TH>P(hold)</TH><TH>Preempt margin</TH><TH>Moved-before-next-stage</TH></THead>
        <tbody>{scan.killchain.map((k) => (
          <TR key={k.pod}>
            <TD className="font-mono text-[12px]">{k.pod}</TD>
            <TD><Badge variant={k.ai ? "modeled" : "neutral"}>{k.stage}{k.ai ? " · AI" : ""}</Badge></TD>
            <TD className="tabular">{k.pHold.toFixed(2)}</TD>
            <TD className="tabular">{(k.preemptMargin * 100).toFixed(0)}%</TD>
            <TD className="tabular text-primary">{k.projNextStageSec.toFixed(0)}s</TD>
          </TR>
        ))}</tbody>
      </Table>
    </CardContent></Card>
  );
}

/* ---------- MTD / OPTIMIZATION (from live audit) ---------- */
export function OptimizationPanel({ lens }: { lens: Lens }) {
  const recs = useAudit(lens);
  if (!recs) return <Loading label="Reading the optimizer's decisions from the live stream…" rows={3} />;
  if (recs.length === 0) return <Empty msg="No live decisions yet — start Phorvex (Protect) or run a scenario to populate the optimizer view." />;
  const acted = recs.filter((r) => r.selected || r.action !== "noop");
  const rows = acted.length ? acted : recs;
  return (
    <div className="space-y-4">
      <SectionLabel>Modeled selection opportunity − λ·cost scoring · not measured mitigation</SectionLabel>
      <Card><CardContent className="p-0">
        <Table>
          <THead><TH>Workload</TH><TH>Action</TH><TH>Modeled coverage</TH><TH>Cost (ECost)</TH><TH>Net = cov − λ·cost</TH><TH>per-$</TH><TH>λ</TH></THead>
          <tbody>{rows.map((r, i) => (
            <TR key={i} className={cn(r.selected && "bg-primary/[0.04]")}>
              <TD className="font-mono text-[12px]">{r.namespace}/{r.pod}<ClaimScopeNote claim={r.claim} /></TD>
              <TD><Badge variant={r.action === "noop" ? "neutral" : "accent"}>{r.action}</Badge>{r.selected && <Badge variant="real">chosen</Badge>}</TD>
              <TD className="tabular">{(r.coveredWeight ?? r.risk ?? 0).toFixed(2)}{r.coveredFacts ? <span className="text-muted-foreground/60"> · {r.coveredFacts}f</span> : null}</TD>
              <TD className="tabular">{(r.cost ?? 0).toFixed(2)}</TD>
              <TD className={cn("tabular font-medium", (r.net ?? 0) > 0 ? "text-success" : "text-muted-foreground")}>{(r.net ?? 0).toFixed(2)}</TD>
              <TD className="tabular">{(r.perDollar ?? 0).toFixed(2)}</TD>
              <TD className="tabular text-muted-foreground">{(r.lambda ?? 0).toFixed(2)}</TD>
            </TR>
          ))}</tbody>
        </Table>
      </CardContent></Card>
      {rows[0] && <ShapAndR6 rec={rows.find((r) => r.attribution?.length) || rows[0]} />}
      <div className="text-[10px] text-muted-foreground/60">Coverage values describe modeled selection opportunity, not measured mitigation. Coverage/λ/per-$/SHAP/counterfactual are IP — Investor/Operator only; the owner lens sees the outcome (action + why) only.</div>
    </div>
  );
}

function ShapAndR6({ rec }: { rec: any }) {
  const terms: { source: string; contribution: number }[] = rec.attribution || [];
  const max = Math.max(0.001, ...terms.map((t) => Math.abs(t.contribution)));
  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
      <Card><CardContent className="p-4">
        <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Why this move (SHAP attribution) · {rec.namespace}/{rec.pod}</div>
        {terms.length === 0 ? <div className="text-[12px] text-muted-foreground">attribution available on selected coverage-engine decisions</div> : (
          <div className="space-y-1.5">{terms.map((t, i) => (
            <div key={i} className="flex items-center gap-2 text-[12px]">
              <span className="w-40 shrink-0 truncate font-mono text-muted-foreground">{t.source}</span>
              <div className="relative h-3 flex-1">
                <div className={cn("absolute top-0 h-3 rounded", t.contribution >= 0 ? "left-1/2 bg-success/60" : "right-1/2 bg-danger/60")} style={{ width: `${(Math.abs(t.contribution) / max) * 50}%` }} />
                <div className="absolute left-1/2 top-0 h-3 w-px bg-border" />
              </div>
              <span className="w-12 text-right tabular">{t.contribution >= 0 ? "+" : ""}{t.contribution.toFixed(2)}</span>
            </div>
          ))}</div>
        )}
      </CardContent></Card>
      <Card><CardContent className="p-4">
        <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">vs Without Phorvex (counterfactual)</div>
        <div className="text-[13px] text-foreground/90">{rec.counterfactualNote || rec.r6Counterfactual || <span className="text-muted-foreground">No without-Phorvex counterfactual recorded on this decision.</span>}</div>
      </CardContent></Card>
    </div>
  );
}

/* ---------- COST ---------- */
export function CostPanel({ lens }: { lens: Lens }) {
  const recs = useAudit(lens);
  if (!recs) return <Loading label="Reading the cost solution from the live stream…" rows={3} />;
  if (recs.length === 0) return <Empty msg="No live decisions yet — start Phorvex (Protect) to see the cost-vs-coverage tradeoff." />;
  const lambda = recs.find((r) => typeof r.lambda === "number" && r.lambda > 0)?.lambda ?? 0;
  const pts = recs.map((r) => ({ cov: r.coveredWeight ?? r.risk ?? 0, cost: r.cost ?? 0, sel: r.selected }));
  const maxCov = Math.max(0.5, ...pts.map((p) => p.cov)), maxCost = Math.max(0.5, ...pts.map((p) => p.cost));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Mini label="λ shadow-price" value={lambda.toFixed(2)} />
        <Mini label="moves / tick" value={String(recs.filter((r) => r.selected).length)} />
        <Mini label="decisions" value={String(recs.length)} />
        <Mini label="actuated" value={String(recs.filter((r) => r.actuated).length)} />
      </div>
      <Card><CardContent className="p-4">
        <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Cost vs modeled coverage · λ = the shadow-price slope (move fires when per-$ &gt; λ)</div>
        <svg viewBox="0 0 600 260" className="w-full">
          <line x1="40" y1="220" x2="580" y2="220" stroke="hsl(222 18% 16%)" /><line x1="40" y1="20" x2="40" y2="220" stroke="hsl(222 18% 16%)" />
          <text x="300" y="250" textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 10 }}>modeled coverage value →</text>
          {pts.map((p, i) => (
            <circle key={i} cx={40 + (p.cov / maxCov) * 530} cy={220 - (p.cost / maxCost) * 190} r={p.sel ? 6 : 4}
              fill={p.sel ? "hsl(184 78% 46% / 0.7)" : "hsl(215 14% 58% / 0.4)"} stroke={p.sel ? "hsl(184 78% 46%)" : "none"} />
          ))}
          {lambda > 0 && <line x1="40" y1="220" x2={Math.min(580, 40 + (maxCost / (lambda * maxCost) * 530))} y2="20" stroke="hsl(38 92% 56% / 0.5)" strokeDasharray="4 4" />}
        </svg>
        <div className="text-[10px] text-muted-foreground/60">λ/per-$/cost are IP — Investor/Operator only.</div>
      </CardContent></Card>
    </div>
  );
}

/* ---------- ACTUATOR (live registry from /api/handlers) ---------- */
// The AI / served-model actuators (GPU control-plane moves; [PENDING-GPU-VALIDATION]/PHORVEXSEC-87),
// mirroring model.MutatingActions from ActionWarmSwap onward. Everything NOT here is a K8s-native
// move (rotate, quarantine, debugger, custom-inject, identity-rotate, route-rotate). guardrail-rotate,
// adapter-rotate and request-drain are part of the AI P4 set — they were missing here and mis-rendered
// as "K8s live".
const AI_HANDLERS = new Set(["warm-swap", "mig-rebind", "kv-reset", "endpoint-rotate", "model-shard-replace", "adapter-rotate", "request-drain", "guardrail-rotate", "kv-migrate-invalidate"]);
export function ActuatorPanel({ lens }: { lens: Lens }) {
  const recs = useAudit(lens);
  const [reg, setReg] = React.useState<RegistryView | null>(null);
  React.useEffect(() => { api.handlers(lens).then(setReg).catch(() => {}); }, [lens]);
  const enacted = (recs || []).filter((r) => r.actuated);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-[12px]">
        {reg ? <Badge variant={reg.complete ? "real" : "pending"}><Check className="h-2.5 w-2.5" /> {reg.generatables - (reg.missing ?? []).length}/{reg.generatables} generatable actions covered</Badge> : <Badge variant="neutral">reading registry…</Badge>}
        <span className="text-muted-foreground">live from <span className="font-mono">actuator.HandlerRegistry</span> · {reg ? reg.count : "…"} handlers · MissingHandlers={reg ? (reg.missing ?? []).length : "…"}</span>
      </div>
      {reg && (
        <Card><CardContent className="p-4">
          <div className="mb-2.5 text-[11px] uppercase tracking-wider text-muted-foreground">{reg.count}-handler native registry (computed)</div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
            {(reg.names ?? []).map((n) => {
              const ai = AI_HANDLERS.has(n);
              return (
                <div key={n} className="rounded-md border border-border/60 bg-elevated/30 px-2.5 py-2">
                  <div className="flex items-center gap-1.5"><Boxes className={cn("h-3.5 w-3.5", ai ? "text-info" : "text-primary")} /><span className="font-mono text-[12px]">{n}</span></div>
                  <div className="mt-1">{ai
                    ? <Badge variant="accent" title="ungated: the brain can now SELECT this AI actuator on GPU/served-model workloads. Actuation validation [SP-0] still pending — it needs a vLLM-shaped control plane to fire.">AI · enabled</Badge>
                    : <Badge variant="real">K8s live</Badge>}</div>
                </div>
              );
            })}
          </div>
          {(reg.missing ?? []).length > 0 && <div className="mt-2 text-[11px] text-warning">missing handlers: {(reg.missing ?? []).join(", ")}</div>}
        </CardContent></Card>
      )}
      {enacted.length > 0 && (
        <Card><CardContent className="p-4">
          <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Enacted this session · what changed on the platform</div>
          <div className="space-y-1.5">{enacted.map((r, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2 text-[12px]">
              <span className="font-mono">{r.namespace}/{r.pod}</span><Badge variant="accent">{r.handler || r.action}</Badge>
              {r.mutationKind && <Badge variant="neutral">{r.mutationKind}</Badge>}
              {(r.objectsTouched || []).length > 0 && <span className="text-muted-foreground">touched: {(r.objectsTouched || []).join(", ")}</span>}
              {r.rollbackRef && <Badge variant="real">rollback: {r.rollbackRef}</Badge>}
            </div>
          ))}</div>
        </CardContent></Card>
      )}
    </div>
  );
}

/* ---------- ABLATION (live --ablation JSON) ---------- */
export function AblationPanel({ lens, ns = "scandemo" }: { lens: Lens; ns?: string }) {
  const [d, setD] = React.useState<AblationResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState("");
  function run() { setLoading(true); setErr(""); api.ablation(ns, lens).then(setD).catch((e) => setErr(String(e.message || e))).finally(() => setLoading(false)); }
  const flat = d && d.ran && d.ratio <= 1.0001;
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button onClick={run} disabled={loading}>{loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />} Run live ablation (ns: {ns})</Button>
        <span className="text-[12px] text-muted-foreground">seed-pinned recon-per-$: Phorvex vs uniform-random — computed live from <span className="font-mono">phorvex --ablation</span></span>
      </div>
      {err && <ErrorBox msg={err} />}
      {d && d.ran && (
        <Card><CardContent className="p-5">
          <div className="flex items-baseline gap-2"><span className="text-4xl font-semibold tabular text-primary">{d.ratio.toFixed(2)}×</span><span className="text-sm text-muted-foreground">PX recon-per-$ ÷ random</span></div>
          <div className="mt-3 grid grid-cols-2 gap-3 text-[13px]">
            <div className="rounded-md border border-border/60 px-3 py-2">PX per-$ <span className="tabular font-medium">{d.p1PerDollar.toFixed(3)}</span></div>
            <div className="rounded-md border border-border/60 px-3 py-2">random per-$ <span className="tabular font-medium">{d.randomPerDollar.toFixed(3)}</span></div>
          </div>
          <div className="mt-3"><Badge variant="accent">deterministic greedy · empirical ratio shown</Badge></div>
          {flat ? (
            <div className="mt-3 rounded-md border border-warning/30 bg-warning/[0.05] px-3 py-2 text-[12px] text-muted-foreground">
              <span className="font-medium text-warning">Flat-fleet result ({d.ratio.toFixed(2)}×).</span> On a uniform namespace there's no asset tail for the scarcity weighting to exploit, so PX ties random. The headline <span className="font-mono">1.62×</span> is the heavy-tailed designed-fleet result (a Go test) — honestly NOT reproduced on an arbitrary cluster, and never hardcoded into this number.
            </div>
          ) : (
            <div className="mt-2 text-[12px] text-muted-foreground">{d.note}</div>
          )}
        </CardContent></Card>
      )}
      {!d && !loading && <Pending stage="REAL-NOW" msg="Click to exec `phorvex --ablation` live — the ratio is parsed from the brain's JSON output, not a stored number." />}
    </div>
  );
}

/* ---------- HEALTH ---------- */
export function HealthPanel({ lens }: { lens: Lens }) {
  const [d, setD] = React.useState<{ policies: PolicyView[]; available: boolean; note: string } | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => { api.cluster(lens).then(setD).catch((e) => setErr(String(e.message || e))); }, [lens]);
  if (err) return <ErrorBox msg={err} />;
  if (!d) return <Loading label="Reading the operator control-plane…" rows={2} />;
  return (
    <div className="space-y-3">
      {!d.available ? <ErrorBox msg="kubectl could not read PhorvexPolicy CRDs (no cluster access)." />
        : (d.policies ?? []).length === 0 ? <Empty msg="No PhorvexPolicy deployed. Apply a policy (or run a scenario) to see the live operator status: last-tick, decisions, kill-switch, conditions." />
        : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">{(d.policies ?? []).map((p) => (
            <Card key={p.namespace + p.name}><CardContent className="p-4">
              <div className="flex items-center justify-between"><span className="font-mono text-[13px]">{p.namespace}/{p.name}</span><Badge variant={p.mode === "active" ? "real" : "modeled"}>{p.mode || "—"}</Badge></div>
              <div className="mt-2 grid grid-cols-2 gap-2 text-[12px]">
                <Stat2 k="last tick" v={p.status?.lastTickTime?.slice(11, 19) || "—"} />
                <Stat2 k="decisions" v={String(p.status?.decisionsTotal ?? "—")} />
                <Stat2 k="selected pods" v={String(p.status?.selectedPods ?? "—")} />
                <Stat2 k="kill-switch" v={p.status?.killSwitchEngaged ? "engaged" : "off"} />
              </div>
            </CardContent></Card>
          ))}</div>
        )}
      <div className="text-[11px] text-muted-foreground/70">{d.note}</div>
    </div>
  );
}

/* ---------- METHODOLOGY (honesty) ---------- */
const KNOBS = [
  ["Weibull shape k", "2", "hazard IFR"], ["λ seed / step / clamp", "0.6 / 0.05 / [0,10]", "dual descent"],
  ["conformal α / cap", "0.1 / 200", "SLO gate"], ["RLS forgetting", "0.99", "cost calibration"],
  ["MaxDispersionMult", "4", "EMR cap"], ["CoResidencyCap", "4", "co-location"], ["GPUEnvelopeMax", "1.0", "SP-0 fail-safe"],
];
export function MethodologyPanel({ lens }: { lens: Lens }) {
  const owner = lens === "owner";
  return (
    <div className="space-y-5">
      <Card><CardContent className="p-5">
        <div className="text-[13px] font-semibold">No LLM in the decision path</div>
        <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">A deterministic brain: a submodular coverage-minus-λ-cost optimizer over a semi-Markov Weibull kill-chain hazard with Beta-Bernoulli belief. Reproducible at <span className="font-mono text-foreground/80">masterSeed 1337</span> given the same warm state.</p>
      </CardContent></Card>
      <Card><CardContent className="p-5">
        <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">How to read the numbers (honesty legend)</div>
        <div className="space-y-2 text-[12.5px] text-muted-foreground">
          <div><Badge variant="real">REAL</Badge> measured on AWS EKS with a 95% CI (Wilson z=1.96 on rates; Student-t 2.093 n≥20 / 2.262 small-n on continuous).</div>
          <div><Badge variant="modeled">MODELED</Badge> a scenario-config assumption (e.g. ROI $), labeled — never measured production savings.</div>
          <div><Badge variant="pending">SP-0-PENDING-P4</Badge> defined-now, magnitude on real GPU; never implied proven.</div>
          <div className="border-t border-border/50 pt-2">Owner activity reports dispatched actions. Legacy API prevention, preservation and SLO booleans are action-derived assumptions; they do not confirm attacker-objective denial, work preservation or measured service health.</div>
        </div>
      </CardContent></Card>
      {!owner && (
        <Card><CardContent className="p-5">
          <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Flagged hyperparameters · design proposals, never paper values</div>
          <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">{KNOBS.map((k) => (
            <div key={k[0]} className="flex items-center justify-between rounded-md border border-border/50 px-3 py-1.5 text-[12px]"><span className="text-muted-foreground">{k[0]}</span><span className="tabular text-foreground">{k[1]}</span></div>
          ))}</div>
          <div className="mt-2 text-[10px] text-muted-foreground/60">these knobs are tunable design choices — calibrated, never claimed as derived constants.</div>
        </CardContent></Card>
      )}
    </div>
  );
}

/* helpers */
function Bar({ v, max, tone, label }: { v: number; max: number; tone: string; label: string }) {
  const c = tone === "warning" ? "bg-warning/60" : "bg-primary/60";
  return <div className="flex items-center gap-2"><div className="h-1.5 w-16 rounded-full bg-muted/40"><div className={cn("h-1.5 rounded-full", c)} style={{ width: `${Math.max(4, Math.min(100, (v / max) * 100))}%` }} /></div><span>{label}</span></div>;
}
function Mini({ label, value, pending }: { label: string; value: string; pending?: boolean }) {
  return <Card><CardContent className="p-3"><div className={cn("text-xl font-semibold tabular", pending ? "text-warning/80" : "text-foreground")}>{value}</div><div className="mt-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div></CardContent></Card>;
}
function Stat2({ k, v }: { k: string; v: string }) {
  return <div className="flex items-center justify-between rounded bg-elevated/40 px-2 py-1"><span className="text-muted-foreground">{k}</span><span className="tabular text-foreground">{v}</span></div>;
}
