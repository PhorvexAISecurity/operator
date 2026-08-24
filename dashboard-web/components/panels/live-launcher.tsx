"use client";
import * as React from "react";
import { api, Lens, WorkloadNS, WorkloadAttacks, CompatEntry, VllmAttackAction } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Empty } from "@/components/ui/more";
import { useSelectedTarget } from "@/lib/provider-store";
import { Loader2, Swords, ShieldCheck, Crosshair, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";

// LiveLauncherPanel — the per-app attack launcher.
//
// Pick one of YOUR real apps and it asks the backend (GET /api/workload/attacks) which attacks
// this app's STACK actually supports, which are armed to fire now, and why. Fire one and the
// outcome shows on the Grafana dashboard (the "apps under attack" + decision panels) and in the
// console's own Attack monitoring tab. Compatibility is derived from the app's images and
// workload kind, never hardcoded — so the list is honest for whatever you are running.
export function LiveLauncherPanel({ lens }: { lens: Lens }) {
  const sel = useSelectedTarget();
  const target = sel.context || "";
  const [nss, setNss] = React.useState<WorkloadNS[] | null>(null);
  const [app, setApp] = React.useState("");
  const [compat, setCompat] = React.useState<WorkloadAttacks | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [firing, setFiring] = React.useState("");   // the attack id currently being fired
  const [msg, setMsg] = React.useState("");

  // Load the real (non-system) apps once.
  React.useEffect(() => {
    let alive = true;
    api.workloads(target, lens)
      .then((d) => { if (alive) setNss((d.namespaces || []).filter((n) => !n.system && n.workloads.length > 0)); })
      .catch((e) => { if (alive) setErr(String(e.message || e)); });
    return () => { alive = false; };
  }, [target, lens]);

  // Load the per-app compatible attacks whenever the selected app changes.
  const loadCompat = React.useCallback((ns: string) => {
    if (!ns) return;
    setLoading(true); setErr(""); setCompat(null);
    api.workloadAttacks(ns, lens)
      .then((d) => setCompat(d))
      .catch((e) => setErr(String(e.message || e)))
      .finally(() => setLoading(false));
  }, [lens]);

  const pick = (ns: string) => { setApp(ns); setMsg(""); loadCompat(ns); };

  // Fire a live attack through whichever endpoint it declares. Only armed attacks are fireable;
  // the button is disabled otherwise, so this always has a real endpoint to hit.
  const fire = async (a: CompatEntry) => {
    setFiring(a.id); setMsg(""); setErr("");
    try {
      if (a.endpoint === "/api/vllm/attack") {
        const r = await api.vllmAttack(a.id as VllmAttackAction, lens);
        setMsg(r.message || `Fired ${a.name}.`);
      } else {
        const r = await api.workloadAttack(app, "foothold", lens);
        setMsg(r.message || `Fired ${a.name} at ${app}.`);
      }
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally {
      setFiring("");
    }
  };

  const clearAttack = async (a: CompatEntry) => {
    setFiring(a.id + ":clear"); setMsg(""); setErr("");
    try {
      if (a.endpoint === "/api/vllm/attack") {
        const r = await api.vllmAttack("reset", lens);
        setMsg(r.message || "Cleared.");
      } else {
        const r = await api.workloadAttack(app, "clear", lens);
        setMsg(r.message || "Cleared.");
      }
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally {
      setFiring("");
    }
  };

  if (err && !compat && !nss) return <div className="text-[12px] text-danger">error: {err}</div>;
  if (!nss) return <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading your apps…</div>;
  if (nss.length === 0) return <Empty msg="No non-system workloads found on this cluster." />;

  return (
    <div className="space-y-4">
      {/* app picker */}
      <Card><CardContent className="p-4">
        <div className="mb-2.5 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground">
          <Crosshair className="h-3.5 w-3.5" /> Pick an app to attack
        </div>
        <div className="flex flex-wrap gap-2">
          {nss.map((n) => (
            <button key={n.namespace} onClick={() => pick(n.namespace)}
              className={cn(
                "rounded-md border px-3 py-2 text-left text-[13px] transition-colors",
                app === n.namespace ? "border-primary bg-primary/10 text-foreground" : "border-border bg-elevated/30 hover:bg-elevated/60",
              )}>
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

          {/* live attacks */}
          <Card><CardContent className="p-4">
            <div className="mb-3 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground">
              <Swords className="h-3.5 w-3.5" /> Live attacks — real, fired at this app
            </div>
            <div className="space-y-2">
              {compat.live.filter((a) => a.compatible).length === 0 && (
                <div className="text-[12px] text-muted-foreground">No live attack is compatible with this app's stack.</div>
              )}
              {compat.live.filter((a) => a.compatible).map((a) => (
                <div key={a.id} className={cn("rounded-md border p-3", a.armed ? "border-border" : "border-border/50 opacity-70")}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-[13px]">{a.name}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">{a.mitre}</span>
                    {a.armed ? <Badge variant="real">armed</Badge> : <Badge variant="pending">not armed</Badge>}
                    <span className="ml-auto flex gap-2">
                      <Button size="sm" variant={a.armed ? "primary" : "outline"} disabled={!a.armed || firing !== ""}
                        onClick={() => fire(a)}>
                        {firing === a.id ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> firing…</> : <>Fire</>}
                      </Button>
                      <Button size="sm" variant="ghost" disabled={!a.armed || firing !== ""} onClick={() => clearAttack(a)}>
                        {firing === a.id + ":clear" ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /></> : <>Clear</>}
                      </Button>
                    </span>
                  </div>
                  <div className="mt-1 text-[12px] text-muted-foreground">{a.description}</div>
                  <div className="mt-1 text-[11px] text-muted-foreground/80">expected actuator: <span className="font-mono text-foreground/80">{a.expectedActuator}</span> · {a.reason}</div>
                </div>
              ))}
            </div>
          </CardContent></Card>

          {/* scenario catalogue, filtered per app */}
          <Card><CardContent className="p-4">
            <div className="mb-3 flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground">
              <ShieldCheck className="h-3.5 w-3.5" /> Scenario catalogue — compatible with this app
            </div>
            {compat.catalogNote ? (
              <div className="text-[12px] text-muted-foreground">{compat.catalogNote}</div>
            ) : compat.catalog.filter((c) => c.compatible).length === 0 ? (
              <div className="text-[12px] text-muted-foreground">No catalogue scenario is meaningful against this app's stack.</div>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {compat.catalog.filter((c) => c.compatible).map((c) => (
                  <Badge key={c.name} variant="neutral" className="font-mono">{c.name}</Badge>
                ))}
              </div>
            )}
            <div className="mt-2 text-[11px] text-muted-foreground/70">Scenario runs launch from the Attack Lab (they drive the operator against synthetic events in a sandbox, rather than firing at this pod).</div>
          </CardContent></Card>

          {msg && <div className="rounded-md border border-success/25 bg-success/[0.06] p-3 text-[12.5px] text-foreground">{msg} <span className="text-muted-foreground">— watch the outcome on the Grafana dashboard and in Attack monitoring.</span></div>}
          {err && <div className="rounded-md border border-danger/25 bg-danger/[0.06] p-3 text-[12.5px] text-danger">{err}</div>}
        </>
      )}
    </div>
  );
}
