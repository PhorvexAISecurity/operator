"use client";
import * as React from "react";
import { api, Lens, RunStatus, Suite } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Swords, Play, Loader2, CheckCircle2, Hand } from "lucide-react";
import { clearLiveSelection, selectLiveRecord } from "@/lib/live-selection";
import { useSelectedTarget } from "@/lib/provider-store";
import { useApiRead } from "@/lib/query";
import { Loading, ReadStatus } from "@/components/ui/more";

export function RunAttackPanel({ lens }: { lens: Lens }) {
  const target = useSelectedTarget();
  const suitesRead = useApiRead({ lens, resource: "suites", fetcher: (signal) => api.suites(lens, signal), staleTime: 60_000 });
  const suites = suitesRead.data ? (suitesRead.data.suites ?? []) : undefined;
  const [sel, setSel] = React.useState("p3-v3");
  const [native, setNative] = React.useState(true);
  const [run, setRun] = React.useState<RunStatus | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const requestGeneration = React.useRef(0);

  React.useEffect(() => {
    requestGeneration.current++;
    setRun(null); setBusy(false); setErr("");
  }, [lens]);
  React.useEffect(() => () => { requestGeneration.current++; }, []);

  // poll the live status while running.
  React.useEffect(() => {
    if (!run || (run.state !== "running" && run.state !== "queued")) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next = await api.runStatus(run.id, lens);
        if (!alive) return;
        setRun(next);
        if (next.state === "running" || next.state === "queued") timer = setTimeout(poll, 1500);
      } catch { if (alive) timer = setTimeout(poll, 1500); }
    };
    timer = setTimeout(poll, 1500);
    return () => { alive = false; clearTimeout(timer); };
  }, [run?.id, run?.state, lens]);

  async function start() {
    const request = ++requestGeneration.current;
    setBusy(true); setErr("");
    clearLiveSelection(lens, target.context);
    try {
      const { id } = await api.startRun(sel, native, lens);
      if (request !== requestGeneration.current) return;
      const status = await api.runStatus(id, lens);
      if (request !== requestGeneration.current) return;
      if (status.target) selectLiveRecord({ kind: "run", id, lens, context: status.target });
      setRun(status);
    } catch (e: any) { if (request === requestGeneration.current) setErr(String(e.message || e)); }
    finally { if (request === requestGeneration.current) setBusy(false); }
  }

  if (!suites) return suitesRead.error ? <ReadStatus error={suitesRead.error} hasData={false} onRetry={() => void suitesRead.refetch()} /> : <Loading label="Reading attack suites…" rows={2} />;
  if (err && !suites.length) return <ErrorState msg={err} />;

  return (
    <div className="animate-fade-up space-y-6">
      <ReadStatus error={suitesRead.error} hasData updatedAt={suitesRead.dataUpdatedAt} refreshing={suitesRead.isFetching} onRetry={() => void suitesRead.refetch()} />
      <PageHead
        title="Run Attack Agents"
        sub="Trigger a real attack-scenario suite against the live AWS EKS cluster and watch Phorvex defend in real time. This invokes the existing harness — no fabricated results."
      />
      <Card>
        <CardContent className="space-y-4 p-5">
          <div>
            <SectionLabel>Scenario suite</SectionLabel>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {suites.map((s) => (
                <button key={s.Name} onClick={() => setSel(s.Name)}
                  className={cn("rounded-lg border p-3 text-left transition-colors", sel === s.Name ? "border-primary/50 bg-primary/[0.06]" : "border-border bg-elevated/30 hover:bg-elevated/60")}>
                  <div className="flex items-center gap-2 font-mono text-[13px] text-foreground">
                    <Swords className={cn("h-3.5 w-3.5", sel === s.Name ? "text-primary" : "text-muted-foreground")} />{s.Name}
                  </div>
                  <div className="mt-1 text-[12px] leading-snug text-muted-foreground">{s.Desc}</div>
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
            <label className="flex cursor-pointer items-center gap-2.5 text-[13px] text-muted-foreground">
              <button onClick={() => setNative((v) => !v)} className={cn("relative h-5 w-9 rounded-full transition-colors", native ? "bg-primary" : "bg-muted")}>
                <span className={cn("absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform", native ? "translate-x-4" : "translate-x-0.5")} />
              </button>
              <Hand className="h-3.5 w-3.5" /> Native actuator <span className="font-mono text-foreground/70">(PHORVEX_ACTUATOR=native)</span>
            </label>
            <Button onClick={start} disabled={busy || run?.state === "running" || run?.state === "queued"}>
              {busy || run?.state === "running" || run?.state === "queued" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {run?.state === "queued" ? "Queued…" : run?.state === "running" ? "Running…" : "Launch attack run"}
            </Button>
          </div>
          {err && <div className="text-[12px] text-danger">{err}</div>}
        </CardContent>
      </Card>

      {run && (
        <Card className="animate-fade-up">
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm">
                {run.state === "running" || run.state === "queued" ? <Loader2 className="h-4 w-4 animate-spin text-primary" /> : run.state === "done" ? <CheckCircle2 className="h-4 w-4 text-success" /> : <span className="h-2 w-2 rounded-full bg-danger" />}
                <span className="font-medium">{run.config}</span>
                <span className="font-mono text-[10px] text-muted-foreground" title={run.id}>run {run.id}</span>
                <Badge variant={run.state === "done" ? "real" : run.state === "running" || run.state === "queued" ? "accent" : "danger"}>{run.state}</Badge>
                {run.nativeActuator && <Badge variant="accent">native hands</Badge>}
              </div>
              <span className="text-[12px] tabular text-muted-foreground">{run.trials} trials · started {run.started}</span>
            </div>
            <div className="mt-4 space-y-2">
              {(run.arms || []).sort((a, b) => a.defender.localeCompare(b.defender)).map((a) => {
                const px = a.defender === "d-phorvex";
                return (
                  <div key={a.defender} className={cn("flex items-center gap-4 rounded-md border border-border/50 px-3 py-2", px && "bg-primary/[0.04]")}>
                    <span className="w-40 shrink-0 font-mono text-[13px]">{px ? "Phorvex" : a.defender.replace("d-", "")}</span>
                    <div className="flex-1">
                      <div className="h-1.5 w-full rounded-full bg-muted/50">
                        <div className={cn("h-1.5 rounded-full", px ? "bg-primary" : "bg-muted-foreground/50")} style={{ width: `${Math.round(a.disruption * 100)}%` }} />
                      </div>
                    </div>
                    <span className="w-24 text-right text-[12px] tabular text-muted-foreground">disrupt {Math.round(a.disruption * 100)}%</span>
                    {a.dwellMean > 0 && <span className="w-24 text-right text-[12px] tabular text-muted-foreground">dwell {a.dwellMean.toFixed(1)}s</span>}
                  </div>
                );
              })}
              {(run.state === "running" || run.state === "queued") && !(run.arms || []).length && <div className="py-6 text-center text-[13px] text-muted-foreground">{run.state === "queued" ? "Waiting for an execution slot…" : "Deploying victims + arming attack agents…"}</div>}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
