"use client";
import * as React from "react";
import { api, runStream, Lens, ClusterTarget, WorkloadNS, CatalogItem, TimelineEvent } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { PageHead, SectionLabel, ErrorState } from "@/components/panels/effectiveness";
import { cn } from "@/lib/utils";
import {
  Server, Boxes, Swords, Play, Loader2, ShieldCheck, ShieldOff, Crosshair,
  Radio, Terminal, AlertTriangle, CheckCircle2, Skull,
} from "lucide-react";

// one streamed trial outcome (a completed attack attempt under one defender arm).
interface Trial extends TimelineEvent { key: string }

const GPU_CAPS = new Set(["CapGPU", "CapMIG", "CapMultiNode"]);

export function AttackLab({ lens }: { lens: Lens }) {
  const [targets, setTargets] = React.useState<ClusterTarget[]>([]);
  const [target, setTarget] = React.useState("");
  const [nss, setNss] = React.useState<WorkloadNS[]>([]);
  const [nsLoading, setNsLoading] = React.useState(false);
  const [ns, setNs] = React.useState("amtd-attack-test");
  const [scenarios, setScenarios] = React.useState<CatalogItem[]>([]);
  const [scenario, setScenario] = React.useState("");
  const [withPX, setWithPX] = React.useState(true);
  const [runId, setRunId] = React.useState("");
  const [events, setEvents] = React.useState<TimelineEvent[]>([]);
  const [stage, setStage] = React.useState<TimelineEvent | null>(null);
  const [running, setRunning] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [toolchain, setToolchain] = React.useState(true); // harness present? (false on the slim in-cluster pod)

  // load the live clusters + the scenario catalog once.
  React.useEffect(() => {
    api.health(lens).then((h) => setToolchain(!!h.harnessBin)).catch(() => {});
    api.targets(lens).then((d) => {
      setTargets(d.targets || []);
      const run = (d.targets || []).find((t) => t.runnable);
      if (run) setTarget(run.id);
    }).catch((e) => setErr(String(e.message || e)));
    api.catalog(lens).then((d) => {
      const items = (d.items || []).filter((i) => !i.name.endsWith("-apt"));
      setScenarios(items);
      const first = items.find((i) => !i.caps.some((c) => GPU_CAPS.has(c)));
      if (first) setScenario(first.name);
    }).catch(() => {});
  }, [lens]);

  // load the live workloads whenever the target cluster changes.
  React.useEffect(() => {
    if (!target) return;
    setNsLoading(true);
    api.workloads(target, lens)
      .then((d) => setNss(d.namespaces || []))
      .catch((e) => setErr(String(e.message || e)))
      .finally(() => setNsLoading(false));
  }, [target, lens]);

  // subscribe to the attack timeline while a run is live.
  React.useEffect(() => {
    if (!runId) return;
    setEvents([]); setStage(null); setRunning(true);
    const close = runStream(runId, lens, (e) => {
      if (e.type === "stage") setStage(e);
      else if (e.type === "trial") setEvents((prev) => [...prev, e]);
      else if (e.type === "end") { setRunning(false); setStage(null); }
    });
    return close;
  }, [runId, lens]);

  async function launch() {
    if (!scenario || !target) return;
    setBusy(true); setErr("");
    try {
      const { id } = await api.startScenario(scenario, withPX, target, ns, lens);
      setRunId(id);
    } catch (e: any) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  }

  const targetObj = targets.find((t) => t.id === target);
  const isSandbox = ns === "amtd-attack-test";
  const trials = events.filter((e) => e.type === "trial") as Trial[];

  if (err && !targets.length) return <ErrorState msg={err} />;

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead
        title="Attack Lab"
        sub="See the live workloads on your cluster, launch the attacker against a sandbox of your choice, and watch the whole attack play out — with and without Phorvex — in real time. This invokes the real harness; nothing is fabricated."
      />

      {/* STEP 1 — the live cluster + its real workloads */}
      <Card>
        <CardContent className="space-y-4 p-5">
          <div className="flex items-center justify-between">
            <SectionLabel>1 · Live cluster &amp; workloads</SectionLabel>
            {targetObj && <Badge variant="accent"><Server className="h-3 w-3" />{targetObj.label}</Badge>}
          </div>
          {targets.length > 1 && (
            <div className="flex flex-wrap gap-2">
              {targets.map((t) => (
                <button key={t.id} disabled={!t.runnable} onClick={() => setTarget(t.id)}
                  className={cn("rounded-md border px-3 py-1.5 text-[12px] transition-colors",
                    t.id === target ? "border-primary/50 bg-primary/[0.06] text-foreground" : "border-border text-muted-foreground hover:bg-elevated",
                    !t.runnable && "opacity-40")}>
                  {t.label}
                </button>
              ))}
            </div>
          )}
          {nsLoading ? (
            <div className="flex items-center gap-2 py-6 text-[13px] text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Enumerating live workloads…</div>
          ) : (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {nss.map((g) => (
                <div key={g.namespace}
                  className={cn("rounded-lg border p-3", g.system ? "border-border/40 bg-elevated/20" : "border-border bg-elevated/40")}>
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 font-mono text-[12px] text-foreground">
                      <Boxes className="h-3.5 w-3.5 text-muted-foreground" />{g.namespace}
                    </span>
                    <span className="text-[11px] tabular text-muted-foreground">{g.podCount} pods</span>
                  </div>
                  <div className="mt-2 space-y-1">
                    {g.workloads.length === 0 && <div className="text-[11px] text-muted-foreground/60">no controllers</div>}
                    {g.workloads.map((wl) => (
                      <div key={wl.kind + wl.name} className="flex items-center gap-2 text-[11px]">
                        <span className="rounded bg-muted/40 px-1 text-[9px] uppercase text-muted-foreground">{wl.kind.slice(0, 4)}</span>
                        <span className="font-mono text-foreground/90">{wl.name}</span>
                        <span className="text-muted-foreground/70">{wl.ready}/{wl.replicas}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* STEP 2 — pick the sandbox namespace + the scenario, then launch */}
      <Card>
        <CardContent className="space-y-5 p-5">
          <SectionLabel>2 · Arm the attacker</SectionLabel>

          <div>
            <div className="mb-2 flex items-center gap-1.5 text-[12px] text-muted-foreground"><Crosshair className="h-3.5 w-3.5" /> Run the attack inside namespace</div>
            <div className="flex flex-wrap gap-2">
              {["amtd-attack-test", ...nss.map((g) => g.namespace)].filter((n, i, a) => a.indexOf(n) === i).map((name) => (
                <button key={name} onClick={() => setNs(name)}
                  className={cn("rounded-md border px-3 py-1.5 font-mono text-[12px] transition-colors",
                    ns === name ? "border-primary/50 bg-primary/[0.06] text-foreground" : "border-border text-muted-foreground hover:bg-elevated")}>
                  {name}{name === "amtd-attack-test" && " (sandbox)"}
                </button>
              ))}
            </div>
            <div className={cn("mt-2 flex items-start gap-1.5 text-[11px]", isSandbox ? "text-muted-foreground" : "text-warning")}>
              <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
              <span>The harness deploys its own synthetic attacker + victim pods into this namespace and confines every object here. {isSandbox ? "The dedicated sandbox is recommended." : "This is NOT the dedicated sandbox — synthetic test pods will appear alongside your real workloads here."}</span>
            </div>
          </div>

          <div>
            <div className="mb-2 text-[12px] text-muted-foreground">Attack scenario</div>
            <div className="grid max-h-64 grid-cols-1 gap-2 overflow-y-auto sm:grid-cols-2">
              {scenarios.map((s) => {
                const gated = s.caps.some((c) => GPU_CAPS.has(c));
                return (
                  <button key={s.name} disabled={gated} onClick={() => setScenario(s.name)}
                    className={cn("rounded-lg border p-2.5 text-left transition-colors",
                      scenario === s.name ? "border-primary/50 bg-primary/[0.06]" : "border-border bg-elevated/30 hover:bg-elevated/60",
                      gated && "opacity-40")}>
                    <div className="flex items-center gap-2 font-mono text-[12px] text-foreground">
                      <Swords className={cn("h-3 w-3", scenario === s.name ? "text-primary" : "text-muted-foreground")} />{s.name}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1">
                      <span className="rounded bg-muted/40 px-1 text-[9px] uppercase text-muted-foreground">{s.product}</span>
                      <span className="text-[10px] text-muted-foreground/80">{s.r6Tag}</span>
                      {gated && <span className="text-[10px] text-warning">GPU-only</span>}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
            <label className="flex cursor-pointer items-center gap-2.5 text-[13px] text-muted-foreground">
              <button onClick={() => setWithPX((v) => !v)} className={cn("relative h-5 w-9 rounded-full transition-colors", withPX ? "bg-primary" : "bg-muted")}>
                <span className={cn("absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform", withPX ? "translate-x-4" : "translate-x-0.5")} />
              </button>
              {withPX ? <ShieldCheck className="h-3.5 w-3.5 text-primary" /> : <ShieldOff className="h-3.5 w-3.5" />}
              {withPX ? "Defend with Phorvex (compare vs no-MTD)" : "Baselines only (no-MTD vs blind timer)"}
            </label>
            <Button onClick={launch} disabled={busy || running || !scenario || !toolchain}>
              {busy || running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {running ? "Attack running…" : "Launch attack"}
            </Button>
          </div>
          {!toolchain && (
            <div className="flex items-start gap-2 rounded-md border border-warning/30 bg-warning/[0.06] px-3 py-2 text-[12px] text-warning">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>This console is the read-only in-cluster build — the live workload view above is fully functional, but <span className="font-medium">launching the attacker needs the operator toolchain</span> (Go + harness). Run attacks from the operator console (see the deploy runbook); results then appear in Prove / Report.</span>
            </div>
          )}
          {err && <div className="text-[12px] text-danger">{err}</div>}
        </CardContent>
      </Card>

      {/* STEP 3 — the live attack timeline */}
      {runId && (
        <Card className="animate-fade-up">
          <CardContent className="space-y-4 p-5">
            <div className="flex items-center justify-between">
              <SectionLabel>3 · Live attack timeline</SectionLabel>
              {running ? (
                <Badge variant="accent"><Radio className="h-3 w-3 animate-pulse" /> live</Badge>
              ) : (
                <Badge variant="real"><CheckCircle2 className="h-3 w-3" /> complete</Badge>
              )}
            </div>

            {stage && (
              <div className="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/[0.05] px-3 py-2 text-[12px]">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
                <span className="text-muted-foreground">now attacking</span>
                <span className="font-mono text-foreground">{stage.scenario}</span>
                <span className="text-muted-foreground">·</span>
                <ArmTag defender={stage.defender || ""} />
                <span className="text-muted-foreground">trial {stage.trial}</span>
              </div>
            )}

            <ArmSummary trials={trials} />

            <div className="space-y-2">
              {trials.slice().reverse().map((t, i) => <TrialRow key={`${t.defender}-${t.trial}-${i}`} t={t} />)}
              {!trials.length && running && (
                <div className="py-6 text-center text-[13px] text-muted-foreground">Building operators + deploying victims… the first attack lands shortly.</div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function ArmTag({ defender }: { defender: string }) {
  const px = defender === "d-phorvex";
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-[11px]", px ? "text-primary" : "text-muted-foreground")}>
      {px ? <ShieldCheck className="h-3 w-3" /> : <ShieldOff className="h-3 w-3" />}
      {px ? "Phorvex" : defender.replace("d-", "")}
    </span>
  );
}

// per-arm rollup: did the attack land (oracle achieved, ~0 disruption) or get disrupted?
function ArmSummary({ trials }: { trials: TimelineEvent[] }) {
  const byDef: Record<string, TimelineEvent[]> = {};
  for (const t of trials) (byDef[t.defender || ""] ||= []).push(t);
  const defs = Object.keys(byDef).sort((a) => (a === "d-phorvex" ? -1 : 1));
  if (!defs.length) return null;
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {defs.map((def) => {
        const rs = byDef[def];
        const disrupt = rs.reduce((s, r) => s + (r.disruption || 0), 0) / rs.length;
        const dwell = rs.reduce((s, r) => s + (r.dwellSeconds || 0), 0) / rs.length;
        const px = def === "d-phorvex";
        return (
          <div key={def} className={cn("rounded-lg border p-3", px ? "border-primary/40 bg-primary/[0.05]" : "border-border bg-elevated/30")}>
            <div className="flex items-center justify-between">
              <ArmTag defender={def} />
              <span className="text-[11px] tabular text-muted-foreground">{rs.length} trials</span>
            </div>
            <div className="mt-2 h-1.5 w-full rounded-full bg-muted/50">
              <div className={cn("h-1.5 rounded-full", px ? "bg-primary" : "bg-danger/60")} style={{ width: `${Math.round(disrupt * 100)}%` }} />
            </div>
            <div className="mt-1.5 flex justify-between text-[11px] tabular text-muted-foreground">
              <span>disrupted {Math.round(disrupt * 100)}%</span>
              <span>attacker dwell {dwell.toFixed(1)}s</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// one streamed trial: the attacker's command steps + whether the attack landed or was stopped.
function TrialRow({ t }: { t: TimelineEvent }) {
  const [open, setOpen] = React.useState(false);
  const landed = (t.disruption || 0) < 0.5 && t.oracleAchieved;
  const px = t.defender === "d-phorvex";
  return (
    <div className={cn("rounded-md border px-3 py-2", landed ? "border-danger/25 bg-danger/[0.03]" : "border-success/25 bg-success/[0.03]")}>
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-3 text-left">
        {landed ? <Skull className="h-4 w-4 shrink-0 text-danger" /> : <ShieldCheck className="h-4 w-4 shrink-0 text-success" />}
        <ArmTag defender={t.defender || ""} />
        <span className="text-[11px] text-muted-foreground">trial {t.trial}</span>
        <Badge variant={landed ? "danger" : "real"}>{landed ? "attack landed" : "disrupted"}</Badge>
        <span className="ml-auto flex items-center gap-3 text-[11px] tabular text-muted-foreground">
          <span>dwell {(t.dwellSeconds || 0).toFixed(1)}s</span>
          {t.mtdEffect && <span className="hidden sm:inline">{t.mtdEffect}</span>}
          <Terminal className="h-3.5 w-3.5" />
        </span>
      </button>
      {open && (
        <div className="mt-2 space-y-1 border-t border-border/50 pt-2">
          {(t.commands || []).map((c, i) => (
            <div key={i} className="flex gap-2 font-mono text-[11px] leading-relaxed">
              <span className="select-none text-muted-foreground/50">{i + 1}</span>
              <span className={cn("break-all", px ? "text-foreground/80" : "text-foreground/90")}>{c}</span>
            </div>
          ))}
          {t.observed && <div className="pt-1 text-[11px] text-muted-foreground">→ {t.observed}</div>}
          {!t.commands?.length && <div className="text-[11px] text-muted-foreground/60">no command trace recorded for this trial</div>}
        </div>
      )}
    </div>
  );
}
