"use client";
import * as React from "react";
import { api, runStream, Lens, TimelineEvent } from "@/lib/api";
import { useSelectedTarget } from "@/lib/provider-store";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { PageHead, SectionLabel, ErrorState } from "@/components/panels/effectiveness";
import { cn } from "@/lib/utils";
import { isSecurityOutcome, trialOutcomeDisplay } from "@/lib/trial-outcome";
import { clearLiveSelection, selectLiveRecord } from "@/lib/live-selection";
import {
  Server, Boxes, Swords, Play, Loader2, ShieldCheck, ShieldOff, Crosshair, Check,
  Radio, Terminal, AlertTriangle, CheckCircle2, Skull, StopCircle, FileText,
} from "lucide-react";
import { useApiRead, useCatalog, useQueryScope, useTargets, useWorkloads } from "@/lib/query";
import { emitQueryChange } from "@/lib/query-events";
import { ScenarioResponseGuidance, displayActuatorHints } from "@/components/panels/scenario-response-guidance";

// one streamed trial outcome (a completed attack attempt under one defender arm).
interface Trial extends TimelineEvent { key: string }

// live cluster capabilities — a scenario is gated ONLY if a required cap is genuinely unmet.
interface Caps { gpu: boolean; mig: boolean; multiNode: boolean }
function capUnmet(cap: string, caps: Caps): boolean {
  if (cap === "CapGPU") return !caps.gpu;
  if (cap === "CapMIG") return !caps.mig;
  if (cap === "CapMultiNode") return !caps.multiNode;
  return false;
}
const scenarioGated = (scenarioCaps: string[], caps: Caps) => (scenarioCaps || []).some((c) => capUnmet(c, caps));

export function AttackLab({ lens }: { lens: Lens }) {
  const [target, setTarget] = React.useState("");
  const [nsLoading, setNsLoading] = React.useState(false);
  const ns = "amtd-attack-test"; // attacks always run in a dedicated disposable sandbox (backend-enforced)
  const [picked, setPicked] = React.useState<string[]>([]); // BATCH: multi-select scenarios
  const [runScenarios, setRunScenarios] = React.useState<string[]>([]); // the scenarios of the LIVE run (in order)
  // mode: px = Phorvex vs no-defense · base = no-defense vs blind · three = live 3-way (drives cost/uptime)
  const [mode, setMode] = React.useState<"px" | "base" | "three">("three");
  const [runId, setRunId] = React.useState("");
  const [events, setEvents] = React.useState<TimelineEvent[]>([]);
  const [stage, setStage] = React.useState<TimelineEvent | null>(null);
  const [running, setRunning] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [readErr, setReadErr] = React.useState("");
  const [expectedTrials, setExpectedTrials] = React.useState(6);
  const [startedMs, setStartedMs] = React.useState(0);
  const [nowMs, setNowMs] = React.useState(0);
  const [stopping, setStopping] = React.useState(false);
  const [ended, setEnded] = React.useState<string>(""); // "" | "done" | "stopped"
  const [queuePos, setQueuePos] = React.useState(0); // >0 while THIS run waits in the FIFO behind an active run
  const [runScope, setRunScope] = React.useState<{ id: string; lens: Lens; context: string } | null>(null);
  const notifiedTerminalRef = React.useRef("");
  const scopeGenerationRef = React.useRef(0);
  const stopRequestRef = React.useRef(0);
  const sel = useSelectedTarget(); // header provider scope — the attack defaults to this cluster
  const targetQuery = useTargets(lens);
  const catalogQuery = useCatalog(lens);
  const workloadQuery = useWorkloads(target, lens, !!target);
  const diagnosticsQuery = useApiRead({ lens, resource: "diagnostics", fetcher: (signal) => api.diagnostics(lens, signal), staleTime: 60_000 });
  const capabilitiesQuery = useApiRead({ lens, resource: "capabilities", parameters: { target }, fetcher: (signal) => api.capabilities(target, lens, signal), staleTime: 30_000, enabled: !!target });
  const toolchain = diagnosticsQuery.data ? !!diagnosticsQuery.data.harnessBin : null;
  const diagnosticsError = diagnosticsQuery.error ? String((diagnosticsQuery.error as Error).message || diagnosticsQuery.error) : "";
  const caps: Caps = capabilitiesQuery.data ? { gpu: !!capabilitiesQuery.data.gpu, mig: !!capabilitiesQuery.data.mig, multiNode: !!capabilitiesQuery.data.multiNode } : { gpu: false, mig: false, multiNode: false };
  const queryScope = useQueryScope(lens);
  const targets = targetQuery.data?.targets || [];
  // Attack Lab only launches scored security scenarios. Benign functional
  // fixtures remain selectable in the Scenario Catalog, where their claims
  // and controls are presented without attacker/defender language.
  const scenarios = (catalogQuery.data?.items || []).filter((i) => !i.name.endsWith("-apt") && !i.benignControl);
  const nss = workloadQuery.data?.namespaces || [];
  const scopeIdentityRef = React.useRef("");
  scopeIdentityRef.current = `${lens}\u0000${sel.context}\u0000${target}`;

  const invalidateRequests = React.useCallback(() => {
    scopeGenerationRef.current += 1;
    stopRequestRef.current += 1;
    setBusy(false);
    setStopping(false);
  }, []);

  React.useEffect(() => {
    invalidateRequests();
  }, [lens, sel.context, target, invalidateRequests]);

  React.useEffect(() => () => {
    scopeGenerationRef.current += 1;
    stopRequestRef.current += 1;
  }, []);

  // A real presentation/provider scope change invalidates the old target and run display.
  React.useEffect(() => {
    setTarget(""); setPicked([]);
    setRunId(""); setRunScope(null); setEvents([]); setStage(null); setRunning(false); setEnded(""); setQueuePos(0); setErr(""); setReadErr("");
  }, [lens, sel.context]);

  // Background refreshes update choices without stopping a run or discarding valid selections.
  React.useEffect(() => {
    if (targetQuery.data) {
      const ts = targetQuery.data.targets || [];
      setTarget((current) => {
        const stillValid = ts.find((t) => t.id === current && t.runnable && (!sel.context || t.context === sel.context));
        if (stillValid) return current;
        return (sel.context ? ts.find((t) => t.runnable && t.context === sel.context) : ts.find((t) => t.runnable))?.id || "";
      });
    }
    if (catalogQuery.data) {
      const items = (catalogQuery.data.items || []).filter((i) => !i.name.endsWith("-apt") && !i.benignControl);
      setPicked((current) => {
        const valid = current.filter((name) => items.some((item) => item.name === name));
        return valid.length ? valid : items[0] ? [items[0].name] : [];
      });
    }
  }, [sel.context, targetQuery.data, catalogQuery.data]);
  React.useEffect(() => {
    const queryError = targetQuery.error || catalogQuery.error || (target ? workloadQuery.error : null);
    setReadErr(queryError ? String((queryError as Error).message || queryError) : "");
  }, [target, targetQuery.error, catalogQuery.error, workloadQuery.error]);


  // load the live workloads whenever the target cluster changes.
  React.useEffect(() => { setNsLoading(!!target); }, [target]);
  React.useEffect(() => {
    if (!target) { setNsLoading(false); return; }
    setNsLoading(workloadQuery.isPending && !workloadQuery.data);
  }, [target, workloadQuery.data, workloadQuery.error, workloadQuery.isPending]);

  // A target is part of the effective scope. Never leave a prior target's run/timeline visible.
  React.useEffect(() => {
    setRunId(""); setRunScope(null); setEvents([]); setStage(null);
    setRunning(false); setStopping(false); setEnded(""); setQueuePos(0); setRunScenarios([]);
  }, [target, lens]);

  // subscribe to the attack timeline while a run is live.
  React.useEffect(() => {
    if (!runScope || runScope.id !== runId) return;
    let active = true;
    setEvents([]); setStage(null); setRunning(true); setStopping(false); setEnded(""); setQueuePos(0);
    setStartedMs(Date.now()); setNowMs(Date.now());
    const close = runStream(runId, runScope.lens, (e) => {
      if (!active) return;
      if (e.type === "meta") { if (e.expectedTrials) setExpectedTrials(e.expectedTrials); setQueuePos(e.queuePos || 0); if ((e.queuePos || 0) === 0) { setStartedMs(Date.now()); setNowMs(Date.now()); } }
      else if (e.type === "stage") { setQueuePos(0); setStage(e); }
      else if (e.type === "trial") setEvents((prev) => {
        // de-dupe by (scenario,defender,trial) — the SSE replays the file on every reconnect, so the
        // same trial can arrive twice. MUST include the scenario: in a BATCH run, scenario A's
        // d-nomtd-0 and scenario B's d-nomtd-0 share (defender,trial), so a defender+trial-only key
        // silently dropped every scenario after the first.
        const k = `${e.scenario}-${e.defender}-${e.trial}`;
        return prev.some((p) => `${p.scenario}-${p.defender}-${p.trial}` === k) ? prev : [...prev, e];
      });
      else if (e.type === "evidence-error") setEvents((prev) => {
        const k = e.reason || "metric evidence could not be decoded";
        return prev.some((p) => p.type === "evidence-error" && (p.reason || "metric evidence could not be decoded") === k) ? prev : [...prev, e];
      });
      else if (e.type === "end") {
        setRunning(false); setStage(null); setEnded(e.state || "done");
        const terminalKey = `${runScope.lens}:${runId}`;
        if (notifiedTerminalRef.current !== terminalKey) {
          notifiedTerminalRef.current = terminalKey;
          emitQueryChange({ identity: queryScope.identity, providerToken: queryScope.providerToken, context: runScope.context, runId, lens: runScope.lens, resources: ["runs", "runs-summary", "run-status", "run-evidence", "reports", "report", "effectiveness", "posture", "benchmarks", "cost", "cost-timeseries", "uptime", "matrix", "audit-snapshot", "diagnostics"], kind: "completion" });
        }
      }
    });
    return () => { active = false; close(); };
  }, [queryScope.identity, runId, runScope]);

  // tick the elapsed clock while running (for the ETA / progress bar).
  React.useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [running]);

  async function stop() {
    if (!runId || !runScope || runScope.id !== runId || stopping) return;
    const scopeGeneration = scopeGenerationRef.current;
    const scopeIdentity = scopeIdentityRef.current;
    const request = ++stopRequestRef.current;
    const capturedRun = runScope;
    setStopping(true);
    try {
      await api.stopRun(capturedRun.id, capturedRun.lens);
    } catch (e: any) {
      if (scopeGenerationRef.current === scopeGeneration && scopeIdentityRef.current === scopeIdentity && stopRequestRef.current === request) setErr(String(e.message || e));
    } finally {
      if (scopeGenerationRef.current === scopeGeneration && scopeIdentityRef.current === scopeIdentity && stopRequestRef.current === request) setStopping(false);
    }
  }

  async function launch() {
    if (busy || !queryScope.ready) return;
    const capturedTarget = targets.find((t) => t.id === target);
    const authorizedPicked = picked.filter((name) => scenarios.some((scenario) => scenario.name === name));
    if (lens !== "operator" || toolchain !== true || targetQuery.error || catalogQuery.error || workloadQuery.error || authorizedPicked.length === 0 || !capturedTarget?.runnable) {
      setErr(lens !== "operator"
        ? "Attack creation requires the Operator view."
        : toolchain !== true
          ? "Attack launch is unavailable until operator diagnostics confirm the harness is ready."
          : "Select an available runnable target before launching.");
      return;
    }
    const request = ++scopeGenerationRef.current;
    const scopeIdentity = scopeIdentityRef.current;
    const capturedLens = lens;
    const capturedTargetId = capturedTarget.id;
    const capturedContext = capturedTarget.context || capturedTarget.id;
    const capturedPicked = [...authorizedPicked];
    const capturedMode = mode;
    setBusy(true); setErr("");
    clearLiveSelection(capturedLens, capturedContext);
    setRunScenarios(capturedPicked); // freeze the run's scenario list (in order) for the per-attack tracker
    try {
      const { id } = await api.startScenario(capturedPicked, capturedMode === "px", capturedTargetId, ns, capturedLens, capturedMode === "three", capturedContext);
      if (scopeGenerationRef.current !== request || scopeIdentityRef.current !== scopeIdentity) return;
      const captured = { id, lens: capturedLens, context: capturedContext };
      setRunScope(captured);
      setRunId(id);
      selectLiveRecord({ kind: "run", ...captured });
    } catch (e: any) {
      if (scopeGenerationRef.current === request && scopeIdentityRef.current === scopeIdentity) setErr(String(e.message || e));
    } finally {
      if (scopeGenerationRef.current === request && scopeIdentityRef.current === scopeIdentity) setBusy(false);
    }
  }

  const targetObj = targets.find((t) => t.id === target);
  const trials = events.filter((e) => e.type === "trial") as Trial[];
  const evidenceErrors = events.filter((e) => e.type === "evidence-error");
  const failedEvidence = evidenceErrors.length > 0 || trials.some((t) => t.outcome === "test-failed" || t.outcome === "functional-fail");
  const incompleteEvidence = trials.some((t) => t.outcome === "inconclusive" || t.outcome === "unverified" || t.outcome === "skipped");
  const terminalError = ended === "error" || failedEvidence;
  const terminalPartial = ended === "partial" || incompleteEvidence || evidenceErrors.length > 0;

  const displayErr = err || readErr;
  if (displayErr && !targets.length) return <ErrorState msg={displayErr} />;

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
                <button key={t.id} disabled={!t.runnable} onClick={() => { invalidateRequests(); setTarget(t.id); }}
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
          <div className="text-[11px] text-muted-foreground">Benign functional controls run from the Scenario Catalog and are not presented as attacks or security comparisons here.</div>

          <div>
            <div className="mb-2 flex items-center gap-1.5 text-[12px] text-muted-foreground"><Crosshair className="h-3.5 w-3.5" /> Attack sandbox</div>
            <div className="inline-flex items-center gap-2 rounded-md border border-primary/40 bg-primary/[0.06] px-3 py-1.5 font-mono text-[12px] text-foreground">
              <Boxes className="h-3.5 w-3.5 text-primary" /> amtd-attack-test <span className="text-[10px] text-muted-foreground">(dedicated · disposable)</span>
            </div>
            <div className="mt-2 flex items-start gap-1.5 text-[11px] text-muted-foreground">
              <ShieldCheck className="mt-0.5 h-3 w-3 shrink-0 text-success" />
              <span>The attack runs in a <span className="text-foreground">dedicated disposable sandbox</span> — the harness creates its own synthetic attacker + victim there and deletes the whole namespace on teardown. <span className="text-foreground">Your real workloads are never touched or deleted.</span> (Pick a workload above only to see its context; the attack does not run inside it.)</span>
            </div>
          </div>

          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <span className="text-[12px] text-muted-foreground">Attack scenarios — <span className="text-foreground">pick one or many</span> (batch). Actuator badges are catalogue hints; each run needs its own response evidence.</span>
              {picked.length > 0 && <span className="rounded-md bg-primary/15 px-2 py-0.5 text-[11px] font-medium text-primary">{picked.length} selected</span>}
            </div>
            <div className="grid max-h-72 grid-cols-1 gap-2 overflow-y-auto sm:grid-cols-2">
              {scenarios.map((s) => {
                const gated = scenarioGated(s.caps, caps);
                const unmet = (s.caps || []).filter((c) => capUnmet(c, caps)).map((c) => c.replace("Cap", "")).join("+");
                const sel = picked.includes(s.name);
                return (
                  <button key={s.name} disabled={gated}
                    onClick={() => setPicked((p) => (p.includes(s.name) ? p.filter((x) => x !== s.name) : [...p, s.name]))}
                    className={cn("rounded-lg border p-2.5 text-left transition-colors",
                      sel ? "border-primary/50 bg-primary/[0.06]" : "border-border bg-elevated/30 hover:bg-elevated/60",
                      gated && "opacity-40")}>
                    <div className="flex items-center gap-2 font-mono text-[12px] text-foreground">
                      <span className={cn("grid h-3.5 w-3.5 shrink-0 place-items-center rounded-sm border", sel ? "border-primary bg-primary text-primary-foreground" : "border-border")}>
                        {sel && <Check className="h-2.5 w-2.5" strokeWidth={3} />}
                      </span>
                      {s.name}
                    </div>
                    {/* Legacy-compatible actuator hints; case guidance states their basis. */}
                    <div className="mt-1.5 flex flex-wrap items-center gap-1">
                      {displayActuatorHints(s).map((a) => (
                        <span key={a} className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[9px] text-primary" title="Catalogue hint; availability and selection require live evidence">{a}</span>
                      ))}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1">
                      <span className="rounded bg-muted/40 px-1 text-[9px] uppercase text-muted-foreground">{s.product}</span>
                      <span className="text-[10px] text-muted-foreground/80">{s.r6Tag}</span>
                      {gated && <span className="text-[10px] text-warning">needs {unmet}</span>}
                    </div>
                  </button>
                );
              })}
            </div>
            {/* per-attack explanation for the most-recently-picked scenario */}
            {(() => {
              const last = picked[picked.length - 1];
              const s = scenarios.find((x) => x.name === last);
              if (!s) return null;
              return (
                <div className="mt-3 rounded-lg border border-border bg-elevated/30 p-3 text-[11px]">
                  <div className="mb-1 flex items-center gap-1.5 font-mono text-[12px] text-foreground"><Crosshair className="h-3.5 w-3.5 text-primary" />{s.name}</div>
                  {s.meaningfulWhen && <div className="text-muted-foreground"><span className="text-foreground">When it matters:</span> {s.meaningfulWhen}</div>}
                  {s.runnableNote && <div className="mt-1 text-muted-foreground"><span className="text-foreground">Runnable:</span> {s.runnableNote}</div>}
                  {!!(s.prereqs || []).length && (
                    <div className="mt-1.5 flex flex-wrap items-center gap-1">
                      <span className="text-muted-foreground">Prereqs:</span>
                      {(s.prereqs || []).map((p, i) => <span key={i} className="rounded bg-warning/10 px-1.5 py-0.5 text-[10px] text-warning">{p}</span>)}
                    </div>
                  )}
                  <div className="mt-1.5"><ScenarioResponseGuidance item={s} /></div>
                </div>
              );
            })()}
          </div>

          {/* WHICH PROVIDER this attack will hit — explicit so EKS vs vCluster is never ambiguous */}
          {targetObj && (
            <div className="flex items-center gap-2 rounded-md border border-accent/30 bg-accent/[0.05] px-3 py-2 text-[12px]">
              <Crosshair className="h-3.5 w-3.5 text-accent" />
              <span className="text-muted-foreground">This attack will run on</span>
              <ProviderChip provider={targetObj.provider} label={targetObj.label} />
              <span className="text-muted-foreground">· sandbox <span className="font-mono text-foreground/80">amtd-attack-test</span></span>
            </div>
          )}

          <div className="space-y-3 border-t border-border pt-4">
            <div>
              <div className="mb-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">Which strategies to measure this run</div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                {([
                  { id: "three", title: "3-way (live)", desc: "No-defense · Blind R6 · Phorvex — all three, drives the Cost & Uptime panels", icon: Crosshair },
                  { id: "px", title: "Phorvex vs no-defense", desc: "just the headline contrast", icon: ShieldCheck },
                  { id: "base", title: "No-defense vs Blind", desc: "the two baselines", icon: ShieldOff },
                ] as const).map((m) => (
                  <button key={m.id} onClick={() => setMode(m.id)}
                    className={cn("rounded-lg border p-2.5 text-left transition-colors", mode === m.id ? "border-primary/50 bg-primary/[0.06]" : "border-border bg-elevated/30 hover:bg-elevated/60")}>
                    <div className={cn("flex items-center gap-1.5 text-[12px] font-medium", mode === m.id ? "text-primary" : "text-foreground")}><m.icon className="h-3.5 w-3.5" /> {m.title}</div>
                    <div className="mt-0.5 text-[10px] leading-snug text-muted-foreground">{m.desc}</div>
                  </button>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-between gap-3">
              {mode === "three"
                ? <span className="text-[11px] text-success">After this run, the Cost &amp; Uptime panels read THIS attack (not the static benchmark).</span>
                : <span className="text-[11px] text-muted-foreground">For the live Cost/Uptime 3-way, pick “3-way (live)”.</span>}
              <Button onClick={launch} disabled={!queryScope.ready || !!targetQuery.error || !!catalogQuery.error || !!workloadQuery.error || busy || picked.length === 0 || !picked.every((name) => scenarios.some((scenario) => scenario.name === name)) || toolchain !== true || lens !== "operator" || !targetObj?.runnable}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                {running ? `Queue ${picked.length > 1 ? picked.length + " attacks" : "attack"}` : picked.length > 1 ? `Launch ${picked.length} attacks${mode === "three" ? " (3-way)" : ""}` : mode === "three" ? "Launch live 3-way attack" : targetObj ? `Launch attack on ${targetObj.provider}` : "Launch attack"}
              </Button>
            </div>
          </div>
          {diagnosticsError && (
            <div role="alert" className="flex flex-wrap items-center gap-2 rounded-md border border-warning/30 bg-warning/[0.06] px-3 py-2 text-[12px] text-warning">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span className="min-w-0 flex-1">Launch availability could not be verified. Retry diagnostics; no permanent availability decision has been made.</span>
              <Button variant="outline" size="sm" onClick={() => void diagnosticsQuery.refetch()}>Retry diagnostics</Button>
            </div>
          )}
          {toolchain === false && !diagnosticsError && (
            <div className="flex items-start gap-2 rounded-md border border-warning/30 bg-warning/[0.06] px-3 py-2 text-[12px] text-warning">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>The authenticated diagnostics response reports that the attack harness is unavailable in this console. Live workload inspection remains available.</span>
            </div>
          )}
          {lens !== "operator" && <div className="text-[12px] text-muted-foreground">Attack creation requires the Operator view and is still enforced by the server-side session grant.</div>}
          {displayErr && <div className="text-[12px] text-danger">{displayErr}</div>}
        </CardContent>
      </Card>

      {/* STEP 3 — the live attack timeline */}
      {runId && (
        <Card className="animate-fade-up">
          <CardContent className="space-y-4 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <SectionLabel>3 · Live attack timeline</SectionLabel>
                {targetObj && <ProviderChip provider={targetObj.provider} label={targetObj.label} />}
              </div>
              <div className="flex items-center gap-2">
                {queuePos > 0 ? <Badge variant="accent"><Loader2 className="h-3 w-3 animate-spin" /> queued · #{queuePos}</Badge>
                  : running ? <Badge variant="accent"><Radio className="h-3 w-3 animate-pulse" /> running</Badge>
                  : ended === "stopped" ? <Badge variant="danger"><StopCircle className="h-3 w-3" /> stopped</Badge>
                  : terminalError ? <Badge variant="danger"><AlertTriangle className="h-3 w-3" /> complete · failed evidence</Badge>
                  : terminalPartial ? <Badge variant="pending"><AlertTriangle className="h-3 w-3" /> complete · incomplete evidence</Badge>
                  : <Badge variant="neutral"><FileText className="h-3 w-3" /> execution complete · report ready</Badge>}
                {running && (
                  <Button variant="outline" size="sm" onClick={stop} disabled={stopping}>
                    {stopping ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <StopCircle className="h-3.5 w-3.5" />} {stopping ? "stopping…" : "Stop attack"}
                  </Button>
                )}
              </div>
            </div>

            {queuePos > 0 ? (
              <div className="flex items-center gap-3 rounded-lg border border-primary/30 bg-primary/[0.06] px-4 py-4">
                <Loader2 className="h-5 w-5 shrink-0 animate-spin text-primary" />
                <div className="text-[13px]">
                  <div className="font-medium text-foreground">Queued — position #{queuePos}</div>
                  <div className="text-[11px] text-muted-foreground">Waiting for the active attack to finish; this one starts automatically. Runs share one sandbox + fixed operator ports, so they execute one at a time (no collision).</div>
                </div>
              </div>
            ) : (() => {
              // per-scenario progress: a batch run sweeps every selected scenario, so track how many
              // attacks are done / running / pending, NOT just aggregate trials.
              const armsPer = mode === "three" ? 3 : 2;
              const expectedPer = armsPer * 2; // arms × trialsPerArm(2)
              const trialsOf = (s: string) => trials.filter((t) => t.scenario === s);
              const scenList = runScenarios.length ? runScenarios : Array.from(new Set(trials.map((t) => t.scenario).filter(Boolean) as string[]));
              const statusOf = (s: string): "done" | "running" | "pending" => {
                const n = trialsOf(s).length;
                if (n >= expectedPer) return "done";
                if (s === stage?.scenario || n > 0) return "running";
                return "pending";
              };
              const doneN = scenList.filter((s) => statusOf(s) === "done").length;
              const curScen = stage?.scenario || scenList.find((s) => statusOf(s) === "running");
              const curIdx = curScen ? scenList.indexOf(curScen) : -1;
              const done = trials.length, total = Math.max(expectedTrials, done, 1);
              const elapsed = startedMs ? Math.round((nowMs - startedMs) / 1000) : 0;
              const finalizing = running && done >= total;
              const frac = !running ? 1 : finalizing ? 0.97 : done / total;
              const perTrial = done > 0 ? elapsed / done : 45;
              const eta = running && !finalizing ? Math.max(5, Math.round((total - done) * perTrial)) : 0;
              return (
                <div className="space-y-3">
                  {/* attacks done / remaining */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-[13px]">
                      <span className="font-semibold text-foreground">{doneN}/{scenList.length}</span> <span className="text-muted-foreground">attacks complete</span>
                      {running && curScen && <span className="text-muted-foreground"> · now running <span className="font-mono text-primary">{curScen}</span>{curIdx >= 0 ? ` (#${curIdx + 1})` : ""}</span>}
                    </div>
                    <span className="text-[11px] tabular text-muted-foreground">
                      {finalizing ? <span className="inline-flex items-center gap-1"><Loader2 className="h-3 w-3 animate-spin" /> finalizing…</span>
                        : running ? `${done}/${total} trials · elapsed ${elapsed}s · ~${eta}s left`
                        : ended === "stopped" ? "stopped by you"
                        : terminalError ? <span className="inline-flex items-center gap-1 text-danger"><AlertTriangle className="h-3 w-3" /> execution ended with failed evidence</span>
                        : terminalPartial ? <span className="inline-flex items-center gap-1 text-warning"><AlertTriangle className="h-3 w-3" /> execution ended with incomplete evidence</span>
                        : <span className="inline-flex items-center gap-1 text-muted-foreground"><FileText className="h-3 w-3" /> execution complete — typed report ready</span>}
                    </span>
                  </div>
                  {/* progress bar */}
                  <div className="h-2 w-full overflow-hidden rounded-full bg-muted/50">
                    <div className={cn("h-2 rounded-full transition-all", running ? "bg-primary" : ended === "stopped" || terminalError ? "bg-danger/60" : terminalPartial ? "bg-warning/70" : "bg-muted-foreground/60")} style={{ width: `${Math.round(frac * 100)}%` }} />
                  </div>
                  {/* scenario chips — one per attack, with live status */}
                  {scenList.length > 1 && (
                    <div className="flex flex-wrap gap-1.5">
                      {scenList.map((s, i) => {
                        const st = statusOf(s);
                        return (
                          <span key={s} className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[10px]",
                            st === "done" ? "border-border bg-muted/20 text-muted-foreground"
                            : st === "running" ? "border-primary/50 bg-primary/[0.08] text-primary"
                            : "border-border bg-elevated/30 text-muted-foreground/70")}>
                            {st === "done" ? <FileText className="h-3 w-3" /> : st === "running" ? <Loader2 className="h-3 w-3 animate-spin" /> : <span className="text-[9px]">#{i + 1}</span>}
                            {s}
                          </span>
                        );
                      })}
                    </div>
                  )}

                  {/* per-attack results — each scenario's measured arms as it finishes */}
                  <div className="space-y-3">
                    {evidenceErrors.map((event, i) => <div key={`evidence-error-${i}`} className="rounded border border-info/30 bg-info/5 px-3 py-2 text-[11px] text-info">unverified metric row: {event.reason || "decode failed"}</div>)}
                    {scenList.filter((s) => trialsOf(s).length > 0).map((s) => {
                      const st = statusOf(s);
                      return (
                        <div key={s} className="rounded-lg border border-border/60 bg-elevated/20 p-3">
                          <div className="mb-2 flex items-center gap-2 text-[12px]">
                            {st === "done" ? <FileText className="h-3.5 w-3.5 text-muted-foreground" /> : <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />}
                            <span className="font-mono text-foreground">{s}</span>
                            <Badge variant={st === "done" ? "neutral" : "accent"}>{st === "done" ? "execution complete" : "running"}</Badge>
                            <span className="text-[11px] text-muted-foreground">{trialsOf(s).length}/{expectedPer} trials</span>
                          </div>
                          <ArmSummary trials={trialsOf(s)} />
                          {/* per-trial rows: each trial's attack-landed/disrupted state + the attacker's commands */}
                          <div className="mt-2 space-y-1.5">
                            {trialsOf(s).slice().reverse().map((t, i) => <TrialRow key={`${t.defender}-${t.trial}-${i}`} t={t} />)}
                          </div>
                        </div>
                      );
                    })}
                    {!trials.length && running && (
                      <div className="py-6 text-center text-[13px] text-muted-foreground">Building operators + deploying victims… the first attack lands shortly.</div>
                    )}
                  </div>
                </div>
              );
            })()}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ProviderChip makes the attack target unmistakable: which provider (EKS / vCluster / …) and
// the specific cluster. Color-coded per provider so EKS vs vCluster reads at a glance.
function ProviderChip({ provider, label }: { provider?: string; label?: string }) {
  const p = provider || "Kubernetes";
  const isVC = p === "vCluster";
  const isEKS = p === "AWS EKS";
  const Icon = isVC ? Boxes : Server;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-medium",
      isVC ? "border-violet-400/40 bg-violet-400/[0.08] text-violet-300"
      : isEKS ? "border-amber-400/40 bg-amber-400/[0.08] text-amber-300"
      : "border-border bg-elevated/40 text-foreground")}>
      <Icon className="h-3.5 w-3.5" />
      <span className="uppercase tracking-wide">{p}</span>
      {label && <span className="font-mono normal-case text-muted-foreground">· {label.replace(/^.*· /, "")}</span>}
    </span>
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
        const security = rs.filter((r) => isSecurityOutcome(r.outcome));
        const landedCount = security.filter((r) => r.outcome === "security-landed").length;
        const disruptedCount = security.filter((r) => r.outcome === "security-disrupted").length;
        const unresolvedCount = rs.length - security.length;
        const disrupt = security.length ? security.reduce((s, r) => s + (r.disruption || 0), 0) / security.length : 0;
        const dwell = security.length ? security.reduce((s, r) => s + (r.dwellSeconds || 0), 0) / security.length : 0;
        const px = def === "d-phorvex";
        const allLanded = landedCount === rs.length;
        const allDisrupted = disruptedCount === rs.length;
        const summary = allLanded ? "all attacks landed" : allDisrupted ? "all attacks disrupted" : security.length ? "mixed security outcomes" : "no certified security comparison";
        return (
          <div key={def} className={cn("rounded-lg border p-3", allLanded ? "border-danger/30 bg-danger/[0.04]" : allDisrupted ? "border-success/30 bg-success/[0.04]" : "border-border bg-muted/10")}>
            <div className="flex items-center justify-between gap-2">
              <ArmTag defender={def} />
              <Badge variant={allLanded ? "danger" : allDisrupted ? "real" : "pending"}>{summary}</Badge>
            </div>
            {security.length > 0 && <div className="mt-2 h-1.5 w-full rounded-full bg-muted/50">
              <div className={cn("h-1.5 rounded-full", allLanded ? "bg-danger/60" : px ? "bg-primary" : "bg-success/70")} style={{ width: `${Math.round(disrupt * 100)}%` }} />
            </div>}
            <div className="mt-1.5 flex justify-between text-[11px] tabular text-muted-foreground">
              <span>{landedCount} landed · {disruptedCount} disrupted · {unresolvedCount} other</span>
              <span>{rs.length} trials{security.length ? ` · dwell ${dwell.toFixed(1)}s` : ""}</span>
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
  const display = trialOutcomeDisplay(t.outcome);
  const landed = t.outcome === "security-landed";
  const successful = t.outcome === "security-disrupted" || t.outcome === "functional-pass";
  const px = t.defender === "d-phorvex";
  return (
    <div className={cn("rounded-md border px-3 py-2", landed || t.outcome === "test-failed" || t.outcome === "functional-fail" ? "border-danger/25 bg-danger/[0.03]" : successful ? "border-success/25 bg-success/[0.03]" : "border-border bg-muted/10")}>
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-3 text-left">
        {landed ? <Skull className="h-4 w-4 shrink-0 text-danger" />
          : t.outcome === "security-disrupted" ? <ShieldCheck className="h-4 w-4 shrink-0 text-success" />
          : t.outcome === "functional-pass" ? <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />
          : t.outcome === "test-failed" || t.outcome === "functional-fail" ? <AlertTriangle className="h-4 w-4 shrink-0 text-danger" />
          : <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />}
        <ArmTag defender={t.defender || ""} />
        <span className="text-[11px] text-muted-foreground">trial {t.trial}</span>
        <Badge variant={display.variant}>{display.label}</Badge>
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
          {t.outcomeReason && <div className="pt-1 text-[11px] text-muted-foreground">{t.outcomeReason}{t.measurementPhase ? ` · phase ${t.measurementPhase}` : ""}</div>}
          {!t.commands?.length && <div className="text-[11px] text-muted-foreground/60">no command trace recorded for this trial</div>}
        </div>
      )}
    </div>
  );
}
