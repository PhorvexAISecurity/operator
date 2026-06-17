"use client";
import * as React from "react";
import { api, Lens, RunStatus, Suite } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Swords, Play, Loader2, CheckCircle2, Hand } from "lucide-react";

export function RunAttackPanel({ lens }: { lens: Lens }) {
  const [suites, setSuites] = React.useState<Suite[]>([]);
  const [sel, setSel] = React.useState("p3-v3");
  const [native, setNative] = React.useState(true);
  const [run, setRun] = React.useState<RunStatus | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");

  React.useEffect(() => { api.suites(lens).then((d) => setSuites(d.suites)).catch((e) => setErr(String(e.message || e))); }, [lens]);

  // poll the live status while running.
  React.useEffect(() => {
    if (!run || run.state !== "running") return;
    const t = setInterval(async () => {
      try { setRun(await api.runStatus(run.id, lens)); } catch { /* keep last */ }
    }, 1500);
    return () => clearInterval(t);
  }, [run, lens]);

  async function start() {
    setBusy(true); setErr("");
    try {
      const { id } = await api.startRun(sel, native, lens);
      setRun(await api.runStatus(id, lens));
    } catch (e: any) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  }

  if (err && !suites.length) return <ErrorState msg={err} />;

  return (
    <div className="animate-fade-up space-y-6">
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
            <Button onClick={start} disabled={busy || run?.state === "running"}>
              {busy || run?.state === "running" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {run?.state === "running" ? "Running…" : "Launch attack run"}
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
                {run.state === "running" ? <Loader2 className="h-4 w-4 animate-spin text-primary" /> : run.state === "done" ? <CheckCircle2 className="h-4 w-4 text-success" /> : <span className="h-2 w-2 rounded-full bg-danger" />}
                <span className="font-medium">{run.config}</span>
                <Badge variant={run.state === "done" ? "real" : run.state === "running" ? "accent" : "danger"}>{run.state}</Badge>
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
              {run.state === "running" && !(run.arms || []).length && <div className="py-6 text-center text-[13px] text-muted-foreground">Deploying victims + arming attack agents…</div>}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
