"use client";
import * as React from "react";
import { api, Lens, WorkloadNS, WorkloadAttacks, CompatEntry, CatalogCompat, VllmAttackAction, AttackResult, ClusterTarget, RunStatus } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Empty } from "@/components/ui/more";
import { useSelectedTarget } from "@/lib/provider-store";
import { Loader2, Swords, ShieldCheck, Crosshair, RefreshCw, Check, X } from "lucide-react";
import { cn } from "@/lib/utils";

// LiveLauncherPanel — the per-app attack launcher with actuator verdicts.
//
// Pick one of YOUR real apps: the backend (GET /api/workload/attacks) reports which attacks its
// STACK supports and which are armed. Fire a LIVE attack and the panel polls /api/attack-results
// to show whether Phorvex called the CORRECT actuator on your real pod. Run a CATALOGUE scenario
// and it launches the harness (in its sandbox — the backend forbids firing those at your real
// pods) and streams back the run verdict. Both answer the same question: did the right actuator
// fire, or not.
export function LiveLauncherPanel({ lens }: { lens: Lens }) {
  const sel = useSelectedTarget();
  const [targetId, setTargetId] = React.useState("");
  const [nss, setNss] = React.useState<WorkloadNS[] | null>(null);
  const [app, setApp] = React.useState("");
  const [compat, setCompat] = React.useState<WorkloadAttacks | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [firing, setFiring] = React.useState("");
  const [msg, setMsg] = React.useState("");
  // per-live-attack verdict, keyed by attack id, filled by polling attack-results after a fire.
  const [verdicts, setVerdicts] = React.useState<Record<string, AttackResult>>({});
  // per-catalogue-scenario run, keyed by scenario name.
  const [runs, setRuns] = React.useState<Record<string, RunStatus>>({});

  // Resolve the runnable target id (startScenario keys on it), preferring the header scope.
  React.useEffect(() => {
    let alive = true;
    api.targets(lens).then((d) => {
      if (!alive) return;
      const ts = d.targets || [];
      const pick = ts.find((t: ClusterTarget) => t.runnable && t.context === sel.context) ?? ts.find((t: ClusterTarget) => t.runnable);
      if (pick) setTargetId(pick.id);
    }).catch(() => {});
    return () => { alive = false; };
  }, [lens, sel.context]);

  // Load the real (non-system) apps.
  React.useEffect(() => {
    let alive = true;
    api.workloads(sel.context || "", lens)
      .then((d) => { if (alive) setNss((d.namespaces || []).filter((n) => !n.system && n.workloads.length > 0)); })
      .catch((e) => { if (alive) setErr(String(e.message || e)); });
    return () => { alive = false; };
  }, [sel.context, lens]);

  const loadCompat = React.useCallback((ns: string) => {
    if (!ns) return;
    setLoading(true); setErr(""); setCompat(null);
    api.workloadAttacks(ns, lens).then(setCompat).catch((e) => setErr(String(e.message || e))).finally(() => setLoading(false));
  }, [lens]);

  const pick = (ns: string) => { setApp(ns); setMsg(""); setVerdicts({}); setRuns({}); loadCompat(ns); };

  // After a live fire, poll attack-results for ~60s to surface the actuator + outcome for THIS app.
  const pollVerdict = React.useCallback((attackId: string, ns: string) => {
    let tries = 0;
    const tick = () => {
      tries++;
      api.attackResults(lens).then((d) => {
        const mine = (d.attacks || [])
          .filter((a) => a.namespace === ns || a.service === ns)
          .sort((a, b) => (b.firedAt || "").localeCompare(a.firedAt || ""))[0];
        if (mine && (mine.outcome || mine.status === "done")) {
          setVerdicts((v) => ({ ...v, [attackId]: mine }));
          return; // resolved
        }
        if (tries < 20) setTimeout(tick, 3000);
      }).catch(() => { if (tries < 20) setTimeout(tick, 3000); });
    };
    setTimeout(tick, 2500);
  }, [lens]);

  const fire = async (a: CompatEntry) => {
    setFiring(a.id); setMsg(""); setErr("");
    setVerdicts((v) => { const n = { ...v }; delete n[a.id]; return n; });
    try {
      const r = a.endpoint === "/api/vllm/attack"
        ? await api.vllmAttack(a.id as VllmAttackAction, lens)
        : await api.workloadAttack(app, "foothold", lens);
      setMsg(r.message || `Fired ${a.name}.`);
      pollVerdict(a.id, app);
    } catch (e: any) { setErr(String(e.message || e)); }
    finally { setFiring(""); }
  };

  const clearAttack = async (a: CompatEntry) => {
    setFiring(a.id + ":clear"); setMsg(""); setErr("");
    try {
      const r = a.endpoint === "/api/vllm/attack"
        ? await api.vllmAttack("reset", lens)
        : await api.workloadAttack(app, "clear", lens);
      setMsg(r.message || "Cleared.");
    } catch (e: any) { setErr(String(e.message || e)); }
    finally { setFiring(""); }
  };

  // Launch a catalogue scenario in the harness sandbox, then poll its run status to a verdict.
  const runScenario = async (c: CatalogCompat) => {
    setFiring("scn:" + c.name); setErr("");
    try {
      const { id } = await api.startScenario([c.name], true, targetId, "", lens);
      const tick = () => api.runStatus(id, lens).then((st) => {
        setRuns((r) => ({ ...r, [c.name]: st }));
        if (st.state === "running") setTimeout(tick, 3000);
      }).catch(() => {});
      tick();
    } catch (e: any) { setErr(String(e.message || e)); }
    finally { setFiring(""); }
  };

  if (err && !compat && !nss) return <div className="text-[12px] text-danger">error: {err}</div>;
  if (!nss) return <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading your apps…</div>;
  if (nss.length === 0) return <Empty msg="No non-system workloads found on this cluster." />;

  const liveCompatible = compat?.live.filter((a) => a.compatible) ?? [];
  const catCompatible = compat?.catalog.filter((c) => c.compatible) ?? [];

  return (
    <div className="space-y-4">
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

      {compat && (
        <>
          {/* stack summary */}
          <Card><CardContent className="p-4">
            <div className="mb-2 flex items-center justify-between">
              <div className="text-[13px] font-medium">{compat.namespace} — detected stack</div>
              <button onClick={() => loadCompat(compat.namespace)} className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"><RefreshCw className="h-3 w-3" /> refresh</button>
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
                const correct = v ? (v.phorvexAction && v.expectedActuator && v.phorvexAction === v.expectedActuator) : null;
                return (
                  <div key={a.id} className={cn("rounded-md border p-3", a.armed ? "border-border" : "border-border/50 opacity-70")}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-[13px]">{a.name}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">{a.mitre}</span>
                      {a.armed ? <Badge variant="real">armed</Badge> : <Badge variant="pending">not armed</Badge>}
                      <span className="ml-auto flex gap-2">
                        <Button size="sm" variant={a.armed ? "primary" : "outline"} disabled={!a.armed || firing !== ""} onClick={() => fire(a)}>
                          {firing === a.id ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> firing…</> : <>Fire</>}
                        </Button>
                        <Button size="sm" variant="ghost" disabled={!a.armed || firing !== ""} onClick={() => clearAttack(a)}>
                          {firing === a.id + ":clear" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <>Clear</>}
                        </Button>
                      </span>
                    </div>
                    <div className="mt-1 text-[12px] text-muted-foreground">{a.description}</div>
                    <div className="mt-1 text-[11px] text-muted-foreground/80">expected actuator: <span className="font-mono text-foreground/80">{a.expectedActuator}</span> · {a.reason}</div>
                    {/* actuator verdict, once the fire resolves */}
                    {a.armed && (verdicts[a.id] !== undefined || firing === a.id) && (
                      v ? (
                        <div className={cn("mt-2 flex flex-wrap items-center gap-2 rounded-md border p-2 text-[12px]",
                          correct ? "border-success/30 bg-success/[0.06]" : "border-warning/30 bg-warning/[0.06]")}>
                          {correct ? <Check className="h-3.5 w-3.5 text-success" /> : <X className="h-3.5 w-3.5 text-warning" />}
                          <span>{v.outcome || v.status}</span>
                          <span className="text-muted-foreground">fired <span className="font-mono text-foreground/80">{v.phorvexAction || "—"}</span></span>
                          <span className="text-muted-foreground">expected <span className="font-mono text-foreground/80">{v.expectedActuator}</span></span>
                          <span className={cn("ml-auto font-medium", correct ? "text-success" : "text-warning")}>{correct ? "correct actuator" : v.phorvexAction ? "different actuator" : "no actuation yet"}</span>
                        </div>
                      ) : (
                        <div className="mt-2 flex items-center gap-2 text-[11px] text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> measuring the outcome…</div>
                      )
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent></Card>

          {/* scenario catalogue — launchable, sandboxed, with a run verdict */}
          <Card><CardContent className="p-4">
            <div className="mb-1 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground"><ShieldCheck className="h-3.5 w-3.5" /> Scenario catalogue — compatible with this app</div>
            <div className="mb-3 text-[11px] text-muted-foreground/70">These run the harness against synthetic targets in a disposable sandbox (the backend forbids firing them at your real pods) and report whether the correct actuator fired.</div>
            {compat.catalogNote ? (
              <div className="text-[12px] text-muted-foreground">{compat.catalogNote}</div>
            ) : catCompatible.length === 0 ? (
              <div className="text-[12px] text-muted-foreground">No catalogue scenario is meaningful against this app's stack.</div>
            ) : (
              <div className="space-y-1.5">
                {catCompatible.map((c) => {
                  const run = runs[c.name];
                  return (
                    <div key={c.name} className="flex flex-wrap items-center gap-2 rounded-md border border-border/60 p-2">
                      <span className="font-mono text-[12px]">{c.name}</span>
                      {c.expectedActuators?.length > 0 && <span className="text-[10px] text-muted-foreground">→ <span className="font-mono">{c.expectedActuators.join(", ")}</span></span>}
                      <span className="ml-auto flex items-center gap-2">
                        {run && (
                          <span className={cn("text-[11px]", run.state === "done" ? "text-success" : run.state === "error" ? "text-danger" : "text-muted-foreground")}>
                            {run.state === "running" ? <span className="flex items-center gap-1"><Loader2 className="h-3 w-3 animate-spin" /> running · {run.trials}/{run.expectedTrials ?? "?"}</span> : run.state}
                          </span>
                        )}
                        <Button size="sm" variant="outline" disabled={!targetId || firing !== "" || run?.state === "running"} onClick={() => runScenario(c)}>
                          {firing === "scn:" + c.name ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <>Run</>}
                        </Button>
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent></Card>

          {msg && <div className="rounded-md border border-success/25 bg-success/[0.06] p-3 text-[12.5px] text-foreground">{msg} <span className="text-muted-foreground">— the actuator verdict appears above; results also stream to the Grafana dashboard and the Attack monitoring tab.</span></div>}
          {err && <div className="rounded-md border border-danger/25 bg-danger/[0.06] p-3 text-[12.5px] text-danger">{err}</div>}
        </>
      )}
    </div>
  );
}
