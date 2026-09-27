"use client";
import * as React from "react";
import { api, Lens, WorkloadAttacks, CompatEntry, CatalogCompat, AttackResult, ClusterTarget, RunStatus } from "@/lib/api";
import { dispatchLiveAttack, liveAttackPollBudgetMs, liveAttackRoute, liveAttackVerdict } from "@/lib/live-attack-dispatch";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Empty } from "@/components/ui/more";
import { useSelectedTarget } from "@/lib/provider-store";
import { Loader2, Swords, ShieldCheck, Crosshair, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { clearLiveSelection, selectLiveRecord } from "@/lib/live-selection";
import { useApiRead, useQueryScope, useTargets, useWorkloads } from "@/lib/query";
import { emitQueryChange } from "@/lib/query-events";
import { canSendCatalogueSignal, isCatalogueSignalResult } from "@/lib/attack-result-truth";
import { CatalogueSignalResult } from "@/components/panels/catalogue-signal-result";
import { ScenarioResponseGuidance, displayActuatorHints } from "@/components/panels/scenario-response-guidance";

// LiveLauncherPanel — the per-app attack launcher with actuator verdicts.
//
// Pick one of YOUR real apps: the backend (GET /api/workload/attacks) reports which attacks its
// STACK supports and which are armed. Fire a LIVE attack and the panel polls /api/attack-results
// to show the observed actuator beside the catalogue expectation on your real pod. Run a CATALOGUE scenario
// and it launches the harness (in its sandbox — the backend forbids firing those at your real
// pods) and streams back the recorded run status without reclassifying valid actuator alternatives.
export function LiveLauncherPanel({ lens }: { lens: Lens }) {
  const sel = useSelectedTarget();
  const [app, setApp] = React.useState("");
  const [err, setErr] = React.useState("");
  const [firing, setFiring] = React.useState("");
  const [msg, setMsg] = React.useState("");
  // per-live-attack verdict, keyed by attack id, filled by polling attack-results after a fire.
  const [verdicts, setVerdicts] = React.useState<Record<string, AttackResult>>({});
  const [verdictNotes, setVerdictNotes] = React.useState<Record<string, string>>({});
  // per-catalogue-scenario run, keyed by scenario name.
  const [runs, setRuns] = React.useState<Record<string, RunStatus>>({});
  const [runNotes, setRunNotes] = React.useState<Record<string, string>>({});
  const runsRef = React.useRef(runs);
  runsRef.current = runs;
  const generation = React.useRef(0);
  const timers = React.useRef<Set<ReturnType<typeof setTimeout>>>(new Set());
  const reads = React.useRef<Set<AbortController>>(new Set());
  const targetQuery = useTargets(lens);
  const workloadQuery = useWorkloads(sel.context, lens, !!sel.context);
  const queryScope = useQueryScope(lens);
  const nss = workloadQuery.data ? (workloadQuery.data.namespaces || []).filter((n) => !n.system && n.workloads.length > 0) : null;
  const selectedTarget = (targetQuery.data?.targets || []).find((t: ClusterTarget) => t.runnable && t.context === sel.context) || null;
  const targetId = selectedTarget?.id || "";
  const readError = targetQuery.error || workloadQuery.error;
  const readErrorMessage = readError ? String((readError as Error).message || readError) : "";

  const cancelPending = React.useCallback((markVerdicts = true) => {
    generation.current++;
    timers.current.forEach(clearTimeout);
    timers.current.clear();
    reads.current.forEach((controller) => controller.abort());
    reads.current.clear();
    if (markVerdicts) {
      setVerdictNotes((notes) => Object.fromEntries(Object.entries(notes).map(([key, note]) => [key,
        note.startsWith("Waiting for exact result") ? "Polling cancelled; this exact result is no longer being followed in this view." : note])));
      setRunNotes((notes) => {
        const next = { ...notes };
        Object.entries(runsRef.current).forEach(([name, run]) => {
          if (run.state === "running" || run.state === "queued") next[name] = "Status follow-up cancelled; this run is no longer being followed in this view.";
        });
        return next;
      });
    }
  }, []);

  React.useEffect(() => () => cancelPending(false), [cancelPending]);
  React.useEffect(() => {
    cancelPending(false);
    setApp("");
    setVerdicts({}); setVerdictNotes({}); setRuns({}); setRunNotes({}); setErr(""); setMsg(""); setFiring("");
  }, [lens, sel.context, cancelPending]);

  const mutatesDefaultContext = !sel.context || (selectedTarget?.context === sel.context && selectedTarget.defaultMutationTarget === true);
  const mutationScopeMessage = selectedTarget
    ? "Live attack controls are unavailable because this named context is not the server-resolved target of unscoped mutation endpoints."
    : "Live attack controls are unavailable because the server could not verify this named context as the target of unscoped mutation endpoints.";
  const compatibilityQuery = useApiRead({ lens, resource: "workload-attacks", parameters: { namespace: app, context: sel.context }, fetcher: (signal) => api.workloadAttacks(app, lens, signal), staleTime: 30_000, enabled: !!app && mutatesDefaultContext });
  const compat = compatibilityQuery.data ?? null;
  const loading = compatibilityQuery.isFetching && !compat;
  const compatibilityError = compatibilityQuery.error ? String((compatibilityQuery.error as Error).message || compatibilityQuery.error) : "";
  const canMutateApp = queryScope.ready && !targetQuery.error && !workloadQuery.error && lens === "operator" && mutatesDefaultContext && !!app && nss?.some((item) => item.namespace === app) === true && compat?.namespace === app;

  const pick = (ns: string) => {
    cancelPending(false); setFiring(""); setApp(ns); setMsg(""); setErr(mutatesDefaultContext ? "" : mutationScopeMessage); setVerdicts({}); setVerdictNotes({}); setRuns({}); setRunNotes({});
  };

  // Follow this record alone. Voice and LiteLLM can observe for 900s; every read and the full follow-up remain bounded.
  const pollVerdict = React.useCallback((key: string, recordId: string | undefined, budgetMs = 150_000) => {
    const request = generation.current;
    if (!recordId) {
      setVerdictNotes((v) => ({ ...v, [key]: "Attack accepted, but this response did not include a record ID. Outcome remains uncorrelated; no namespace/time result will be attributed to this fire." }));
      return;
    }
    setVerdictNotes((v) => ({ ...v, [key]: `Waiting for exact result ${recordId}…` }));
    const deadline = Date.now() + budgetMs;
    let readErrors = 0;
    const tick = () => {
      if (request !== generation.current) return;
      if (Date.now() >= deadline) {
        setVerdictNotes((v) => ({ ...v, [key]: `No completed exact result was confirmed for ${recordId} within the bounded follow-up. Open the record to check its later status.` }));
        return;
      }
      const controller = new AbortController();
      reads.current.add(controller);
      const timeout = setTimeout(() => controller.abort(), 15_000);
      api.attackResultsPage(lens, 1, { id: recordId, includeObservations: "true" }, undefined, controller.signal).then((d) => {
        if (request !== generation.current) return;
        const mine = (d.attacks || []).find((a) => a.id === recordId);
        if (mine && (mine.status === "done" || mine.status === "partial")) {
          setVerdicts((v) => ({ ...v, [key]: mine }));
          setVerdictNotes((v) => { const next = { ...v }; delete next[key]; return next; });
          return; // resolved
        }
        readErrors = 0;
        schedule();
      }).catch(() => {
        if (request !== generation.current) return;
        readErrors++;
        if (readErrors >= 3) {
          setVerdictNotes((v) => ({ ...v, [key]: `Could not read exact result ${recordId} after three bounded attempts. Check the record directly; no outcome is inferred.` }));
        } else schedule();
      }).finally(() => {
        clearTimeout(timeout);
        reads.current.delete(controller);
      });
    };
    const schedule = (delay = 3000) => {
      const timer = setTimeout(() => { timers.current.delete(timer); tick(); }, Math.min(delay, Math.max(0, deadline - Date.now())));
      timers.current.add(timer);
    };
    schedule(2500);
  }, [lens]);

  const fire = async (a: CompatEntry) => {
    if (!canMutateApp || !a.armed || !compat?.live.some((entry) => entry.id === a.id && entry.endpoint === a.endpoint && entry.compatible && entry.armed)) {
      setErr("Live attack refused because the operator lens, default context, selected app, or current compatibility no longer matches this control.");
      return;
    }
    const route = liveAttackRoute(a, app);
    if (!route) { setErr(`Live attack refused: unsupported endpoint or ID for ${a.id}.`); return; }
    cancelPending();
    const request = generation.current;
    setFiring(a.id); setMsg(""); setErr("");
    clearLiveSelection(lens, sel.context);
    setVerdicts((v) => { const n = { ...v }; delete n[a.id]; return n; });
    setVerdictNotes((v) => { const n = { ...v }; delete n[a.id]; return n; });
    try {
      const r = await dispatchLiveAttack(route, lens);
      if (request !== generation.current) return;
      setMsg(r.message || `Fired ${a.name}.`);
      if (r.attackId) selectLiveRecord({ kind: "attack", id: r.attackId, lens, context: sel.context });
      pollVerdict(a.id, r.attackId, liveAttackPollBudgetMs(route));
    } catch (e: any) { if (request === generation.current) setErr(String(e.message || e)); }
    finally { if (request === generation.current) setFiring(""); }
  };

  const clearAttack = async (a: CompatEntry) => {
    const route = liveAttackRoute(a, app, true);
    if (!route) { setErr("Clear is available only for the foothold workload attack."); return; }
    if (!canMutateApp || !a.armed || !compat?.live.some((entry) => entry.id === a.id && entry.endpoint === a.endpoint && entry.compatible && entry.armed)) {
      setErr("Clear refused because the operator lens, default context, selected app, or current compatibility no longer matches this control.");
      return;
    }
    cancelPending();
    clearLiveSelection(lens, sel.context);
    const request = generation.current;
    setFiring(a.id + ":clear"); setMsg(""); setErr("");
    try {
      const r = await dispatchLiveAttack(route, lens);
      if (request !== generation.current) return;
      setMsg(r.message || "Cleared.");
    } catch (e: any) { if (request === generation.current) setErr(String(e.message || e)); }
    finally { if (request === generation.current) setFiring(""); }
  };

  // Launch a catalogue scenario in the harness sandbox, then poll its run status to a verdict.
  const runScenario = async (c: CatalogCompat) => {
    if (!queryScope.ready || targetQuery.error || workloadQuery.error || lens !== "operator" || !selectedTarget || selectedTarget.id !== targetId || selectedTarget.context !== sel.context || nss?.some((item) => item.namespace === app) !== true || compat?.namespace !== app || !c.compatible) {
      setErr("Scenario run refused because the operator lens, selected target, app, or current compatibility no longer matches this control.");
      return;
    }
    cancelPending();
    clearLiveSelection(lens, sel.context);
    const request = generation.current;
    setFiring("scn:" + c.name); setErr("");
    setRunNotes((notes) => { const next = { ...notes }; delete next[c.name]; return next; });
    try {
      const { id } = await api.startScenario([c.name], true, targetId, "", lens, false, selectedTarget.context);
      if (request !== generation.current) return;
      const actualScope = { context: selectedTarget.context, lens };
      selectLiveRecord({ kind: "run", id, ...actualScope });
      let tries = 0;
      const tick = () => {
        if (request !== generation.current) return;
        tries++;
        api.runStatus(id, lens).then((st) => {
        if (request !== generation.current) return;
        setRuns((r) => ({ ...r, [c.name]: st }));
        if (st.state === "running" || st.state === "queued") {
          if (tries < 40) schedule();
          else setRunNotes((notes) => ({ ...notes, [c.name]: "Status polling stopped after the bounded follow-up window; the run may still be active." }));
        } else {
          emitQueryChange({ identity: queryScope.identity, providerToken: queryScope.providerToken, runId: id, ...actualScope, resources: ["runs", "runs-summary", "run-status", "run-evidence", "reports", "report", "effectiveness", "posture", "benchmarks", "cost", "cost-timeseries", "uptime", "matrix", "audit-snapshot", "diagnostics", "workload-attacks"], kind: "completion" });
        }
      }).catch((e) => {
        if (request !== generation.current) return;
        if (tries < 40) schedule();
        else setRunNotes((notes) => ({ ...notes, [c.name]: `Status polling stopped after repeated failures: ${String(e?.message || e)}` }));
      });
      };
      const schedule = () => {
        const timer = setTimeout(() => { timers.current.delete(timer); tick(); }, 3000);
        timers.current.add(timer);
      };
      tick();
    } catch (e: any) { if (request === generation.current) setErr(String(e.message || e)); }
    finally { if (request === generation.current) setFiring(""); }
  };

  // Send a synthetic catalogue signal at the live app's exact pod, then follow only the
  // returned record ID. The result describes signal acceptance and observed response;
  // it does not claim that the named behavioral attack ran or was mitigated.
  const fireScenario = async (c: CatalogCompat) => {
    if (!canMutateApp || !compat?.stack.armed || !compat.catalog.some((entry) => entry.name === c.name && canSendCatalogueSignal(entry, compat.stack.armed))) {
      setErr("Live scenario refused because the operator lens, default context, selected app, or current compatibility no longer matches this control.");
      return;
    }
    cancelPending();
    const request = generation.current;
    setFiring("scnlive:" + c.name); setMsg(""); setErr("");
    clearLiveSelection(lens, sel.context);
    setVerdicts((v) => { const n = { ...v }; delete n["scn:" + c.name]; return n; });
    setVerdictNotes((v) => { const n = { ...v }; delete n["scn:" + c.name]; return n; });
    try {
      const r = await api.fireScenarioLive({
        namespace: app, scenario: c.name,
        mitre: (c.techniques || []).join(", "),
        expected: (c.expectedActuators || [])[0] || "",
        action: "fire",
      }, lens);
      if (request !== generation.current) return;
      setMsg(r.message || `Sent ${c.name} catalogue signal to ${app}.`);
      if (r.attackId) selectLiveRecord({ kind: "attack", id: r.attackId, lens, context: sel.context });
      pollVerdict("scn:" + c.name, r.attackId);
    } catch (e: any) { if (request === generation.current) setErr(String(e.message || e)); }
    finally { if (request === generation.current) setFiring(""); }
  };

  if (readErrorMessage && !nss) return <div className="text-[12px] text-danger">error: {readErrorMessage}</div>;
  if (err && !compat && !nss) return <div className="text-[12px] text-danger">error: {err}</div>;
  if (!nss) return <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading your apps…</div>;
  if (nss.length === 0) return <Empty msg="No non-system workloads found on this cluster." />;

  const liveCompatible = compat?.live.filter((a) => a.compatible) ?? [];
  const catCompatible = compat?.catalog.filter((c) => c.compatible) ?? [];

  return (
    <div className="space-y-4">
      {readErrorMessage && <div className="rounded-md border border-danger/25 bg-danger/[0.06] p-3 text-[12.5px] text-danger">error: {readErrorMessage}</div>}
      {/* app picker */}
      <Card><CardContent className="p-4">
        <div className="mb-2.5 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground"><Crosshair className="h-3.5 w-3.5" /> Pick an app to attack</div>
        <div className="flex flex-wrap gap-2">
          {nss.map((n) => (
            <button key={n.namespace} onClick={() => pick(n.namespace)}
              className={cn("rounded-md border px-3 py-2 text-left text-[13px] transition-colors",
                app === n.namespace ? "border-primary bg-primary/10 text-foreground" : "border-border bg-elevated/30 hover:bg-elevated/60")}>
              <div className="font-medium">{n.namespace}</div>
              <div className="text-[11px] text-muted-foreground">{n.workloads.length} workload{n.workloads.length === 1 ? "" : "s"} · {n.podCount} pods</div>
            </button>
          ))}
        </div>
      </CardContent></Card>

      {loading && <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> reading {app}'s stack…</div>}
      {compatibilityError && <div className="rounded-md border border-warning/30 p-3 text-[12px] text-warning">{compat ? "Showing the last compatibility snapshot; refresh failed." : compatibilityError} <button className="ml-2 underline" onClick={() => void compatibilityQuery.refetch()}>Retry</button></div>}
      {err && !compat && <div className="rounded-md border border-danger/25 bg-danger/[0.06] p-3 text-[12.5px] text-danger">{err}</div>}

      {compat && (
        <>
          {/* stack summary */}
          <Card><CardContent className="p-4">
            <div className="mb-2 flex items-center justify-between">
              <div className="text-[13px] font-medium">{compat.namespace} — detected stack</div>
              <button onClick={() => { cancelPending(); setFiring(""); void compatibilityQuery.refetch(); }} className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"><RefreshCw className="h-3 w-3" /> refresh</button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {compat.stack.vllm && <Badge variant="accent">vLLM serving</Badge>}
              {compat.stack.servedModel && !compat.stack.vllm && <Badge variant="accent">served model</Badge>}
              {compat.stack.gpu && <Badge variant="accent">GPU pool</Badge>}
              {compat.stack.stateful && <Badge variant="pending">stateful</Badge>}
              {compat.stack.armed ? <Badge variant="real">armed for live attack</Badge> : <Badge variant="neutral">not armed</Badge>}
            </div>
          </CardContent></Card>

          {/* live attacks + verdict */}
          <Card><CardContent className="p-4">
            <div className="mb-3 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground"><Swords className="h-3.5 w-3.5" /> Live attacks — real, fired at this app</div>
            <div className="space-y-2">
              {liveCompatible.length === 0 && <div className="text-[12px] text-muted-foreground">No live attack is compatible with this app's stack.</div>}
              {liveCompatible.map((a) => {
                const v = verdicts[a.id];
                const verdictNote = verdictNotes[a.id];
                const verdict = v ? liveAttackVerdict(v) : null;
                const matches = !!(v?.phorvexAction && v.expectedActuator && v.phorvexAction === v.expectedActuator);
                return (
                  <div key={a.id} className={cn("rounded-md border p-3", a.armed ? "border-border" : "border-border/50 opacity-70")}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-[13px]">{a.name}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">{a.mitre}</span>
                      {a.armed ? <Badge variant="real">armed</Badge> : <Badge variant="pending">not armed</Badge>}
                      <span className="ml-auto flex gap-2">
                        <Button size="sm" variant={a.armed ? "primary" : "outline"} disabled={!a.armed || !canMutateApp || firing !== ""} onClick={() => fire(a)}>
                          {firing === a.id ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> firing…</> : <>Fire</>}
                        </Button>
                        {!liveAttackRoute(a, app, true) ? (
                          <span className="inline-flex items-center rounded-md border border-border bg-elevated/30 px-2 py-1 text-[11px] text-muted-foreground" title="Reset is unavailable without durable per-run restoration authority">Reset unavailable</span>
                        ) : (
                          <Button size="sm" variant="ghost" disabled={!a.armed || !canMutateApp || firing !== ""} onClick={() => clearAttack(a)}>
                            {firing === a.id + ":clear" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <>Clear</>}
                          </Button>
                        )}
                      </span>
                    </div>
                    <div className="mt-1 text-[12px] text-muted-foreground">{a.description}</div>
                    <div className="mt-1 text-[11px] text-muted-foreground/80">expected actuator: <span className="font-mono text-foreground/80">{a.expectedActuator}</span> · {a.reason}</div>
                    {/* actuator verdict, once the fire resolves */}
                    {a.armed && (verdicts[a.id] !== undefined || firing === a.id) && (
                      v ? (
                        <div className="mt-2 flex flex-wrap items-center gap-2 rounded-md border border-border bg-elevated/30 p-2 text-[12px]">
                          <span>{v.outcome || (verdict?.noop ? "NOOP" : v.status === "done" ? "UNCONFIRMED" : v.status)}</span>
                          <span className="text-muted-foreground">observed <span className="font-mono text-foreground/80">{verdict?.action}</span></span>
                          <span className="text-muted-foreground">expected <span className="font-mono text-foreground/80">{v.expectedActuator || a.expectedActuator || "—"}</span></span>
                          <span className="ml-auto font-medium text-muted-foreground">{verdict?.noop ? "no actuation recorded" : (matches ? "matches expected" : "differs from expected")}</span>
                          {verdict?.reason && <span className="basis-full text-muted-foreground">reason: {verdict.reason}</span>}
                          {verdict?.blocked.map((candidate) => <span key={candidate} className="basis-full text-muted-foreground">candidate: {candidate}</span>)}
                        </div>
                      ) : (
                        <div className="mt-2 flex items-center gap-2 text-[11px] text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> measuring the outcome…</div>
                      )
                    )}
                    {verdictNote && <div className="mt-2 rounded-md border border-warning/30 bg-warning/[0.06] p-2 text-[11px] text-warning">{verdictNote}</div>}
                  </div>
                );
              })}
            </div>
          </CardContent></Card>

          {/* scenario catalogue — launchable, sandboxed, with a run verdict */}
          <Card><CardContent className="p-4">
            <div className="mb-1 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground"><ShieldCheck className="h-3.5 w-3.5" /> Scenario catalogue — compatible with this app</div>
            <div className="mb-3 text-[11px] text-muted-foreground/70">
              <b>Send signal</b> creates a synthetic catalogue signal for this app&apos;s exact pod and reports signal acceptance, available decision evidence, and any observed target response. It does not execute the named behavioral attack or earn defense, dwell, containment, or ROI credit. <b>Run</b> executes the full harness against synthetic sandbox pods and reports its recorded run status.
            </div>
            {compat.catalogNote ? (
              <div className="text-[12px] text-muted-foreground">{compat.catalogNote}</div>
            ) : catCompatible.length === 0 ? (
              <div className="text-[12px] text-muted-foreground">No catalogue scenario is meaningful against this app's stack.</div>
            ) : (
              <div className="space-y-1.5">
                {catCompatible.map((c) => {
                  const run = runs[c.name];
                  const v = verdicts["scn:" + c.name];
                  const verdictNote = verdictNotes["scn:" + c.name];
                  const matches = !!(v?.phorvexAction && displayActuatorHints(c).includes(v.phorvexAction));
                  const signalResult = !!v && isCatalogueSignalResult(v);
                  return (
                    <div key={c.name} className="rounded-md border border-border/60 p-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[12px]">{c.name}</span>
                        <span className="ml-auto flex items-center gap-2">
                          {run && (
                            <span className={cn("text-[11px]", run.state === "done" ? "text-success" : run.state === "error" ? "text-danger" : "text-muted-foreground")}>
                              <span className="font-mono" title={run.id}>run {run.id}</span> · {run.state === "running" ? <span className="inline-flex items-center gap-1"><Loader2 className="h-3 w-3 animate-spin" /> running · {run.trials}/{run.expectedTrials ?? "?"}</span> : run.state}
                            </span>
                          )}
                          <Button size="sm" variant={canSendCatalogueSignal(c, compat.stack.armed) ? "primary" : "outline"} disabled={!canSendCatalogueSignal(c, compat.stack.armed) || !canMutateApp || firing !== ""} title={c.signalEligible === true ? "Send one bounded injected signal" : c.signalEligibilityReason || "Signal eligibility unavailable from the server"} onClick={() => fireScenario(c)}>
                            {firing === "scnlive:" + c.name ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <>Send signal</>}
                          </Button>
                          <Button size="sm" variant="ghost" disabled={lens !== "operator" || !targetId || selectedTarget?.id !== targetId || selectedTarget.context !== sel.context || compat.namespace !== app || firing !== "" || run?.state === "running"} onClick={() => runScenario(c)}>
                            {firing === "scn:" + c.name ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <>Run</>}
                          </Button>
                        </span>
                      </div>
                      <div className="mt-1"><ScenarioResponseGuidance item={c} /></div>
                      {(v || firing === "scnlive:" + c.name) && (
                        v ? (
                          signalResult ? <div className="mt-2"><CatalogueSignalResult result={v} compact /></div> :
                            <div className="mt-2 flex flex-wrap items-center gap-2 rounded-md border border-border bg-elevated/30 p-2 text-[12px]">
                              <span>{v.outcome || (v.status === "done" ? "UNCONFIRMED" : v.status)}</span>
                              <span className="text-muted-foreground">observed <span className="font-mono text-foreground/80">{v.phorvexAction || "—"}</span></span>
                              <span className="text-muted-foreground">listed hint <span className="font-mono text-foreground/80">{displayActuatorHints(c).join(", ") || "—"}</span></span>
                              <span className="ml-auto font-medium text-muted-foreground">{v.phorvexAction ? (matches ? "matches listed hint" : "differs from listed hint") : "no actuation recorded"}</span>
                            </div>
                        ) : (
                          <div className="mt-2 flex items-center gap-2 text-[11px] text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> sending the signal and following its exact result…</div>
                        )
                      )}
                      {verdictNote && <div className="mt-2 rounded-md border border-warning/30 bg-warning/[0.06] p-2 text-[11px] text-warning">{verdictNote}</div>}
                      {runNotes[c.name] && <div className="mt-2 rounded-md border border-warning/30 bg-warning/[0.06] p-2 text-[11px] text-warning">{runNotes[c.name]}</div>}
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent></Card>

          {msg && <div className="rounded-md border border-success/25 bg-success/[0.06] p-3 text-[12.5px] text-foreground">{msg} <span className="text-muted-foreground">— the exact recorded result appears above and in Live Operations.</span></div>}
          {err && <div className="rounded-md border border-danger/25 bg-danger/[0.06] p-3 text-[12.5px] text-danger">{err}</div>}
        </>
      )}
    </div>
  );
}
