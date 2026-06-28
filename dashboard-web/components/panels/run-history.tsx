"use client";
import * as React from "react";
import { api, Lens, RunStatus, ArmResult, RunEvidence } from "@/lib/api";
import { useSelectedTarget } from "@/lib/provider-store";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Loader2, CheckCircle2, ShieldCheck, ShieldOff, Clock, FileText, Terminal, Server, Boxes } from "lucide-react";

const arm = (arms: ArmResult[] | undefined, def: string) => (arms || []).find((a) => a.defender === def);
const pct = (x?: number) => (x === undefined ? "—" : `${Math.round(x * 100)}%`);

// which provider a run targeted (EKS / vCluster / …) — color-coded so it reads at a glance.
function ProviderTag({ provider, label }: { provider?: string; label?: string }) {
  const p = provider || (label || "").split(" ")[0] || "—";
  const isVC = p === "vCluster", isEKS = p === "AWS EKS";
  const Icon = isVC ? Boxes : Server;
  if (!provider && !label) return <span className="text-muted-foreground">—</span>;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium",
      isVC ? "border-violet-400/40 bg-violet-400/[0.08] text-violet-300"
      : isEKS ? "border-amber-400/40 bg-amber-400/[0.08] text-amber-300"
      : "border-border text-foreground")}>
      <Icon className="h-3 w-3" />{p}
    </span>
  );
}

// Full per-run evidence ledger (per-arm aggregates + per-trial rows with attack command steps).
function EvidenceDetail({ id, lens, runErr }: { id: string; lens: Lens; runErr?: string }) {
  const [ev, setEv] = React.useState<RunEvidence | null>(null);
  const [err, setErr] = React.useState("");
  const [openTrial, setOpenTrial] = React.useState<string>("");
  React.useEffect(() => { api.runEvidence(id, lens).then(setEv).catch((e) => setErr(String(e.message || e))); }, [id, lens]);
  if (err) return <div className="text-[12px] text-danger">{err}</div>;
  if (!ev) return <div className="flex items-center gap-2 py-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading evidence…</div>;
  const ms = (x: number) => (x > 0 ? `${x.toFixed(1)}s` : "—");
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-muted-foreground">
        <FileText className="h-3.5 w-3.5" /> Evidence · {ev.scenario} · ns={ev.namespace || "—"} · started {ev.date}{ev.finished ? ` · finished ${ev.finished}` : ""}
      </div>

      {/* per-arm evidence ledger */}
      <div className="overflow-x-auto">
        <table className="w-full text-[12px]">
          <thead><tr className="text-left text-muted-foreground">
            <th className="px-2 py-1">Arm</th><th className="px-2 py-1">Trials</th>
            <th className="px-2 py-1">Disruption (95% CI)</th><th className="px-2 py-1">Dwell (95% CI)</th>
            <th className="px-2 py-1">Oracle hit</th><th className="px-2 py-1">Def. actions</th>
            <th className="px-2 py-1">MTD effect</th><th className="px-2 py-1">Sec/$</th>
            <th className="px-2 py-1">Schwartau P/D/R</th><th className="px-2 py-1">Replay</th>
          </tr></thead>
          <tbody>
            {ev.arms.length === 0 && <tr><td colSpan={10} className="px-2 py-2 text-muted-foreground">no measured metrics — the attack was skipped (e.g. victim could not schedule).</td></tr>}
            {ev.arms.map((a) => {
              const isPx = a.defender === "d-phorvex";
              return (
                <tr key={a.defender} className={cn("border-t border-border/30 align-top", isPx && "bg-primary/[0.04]")}>
                  <td className="px-2 py-2 font-mono">{a.label}</td>
                  <td className="px-2 py-2 tabular">{a.trials}</td>
                  <td className="px-2 py-2 tabular">{Math.round(a.disruption.mean * 100)}% <span className="text-muted-foreground/60">[{Math.round(a.disruption.lo * 100)},{Math.round(a.disruption.hi * 100)}]</span></td>
                  <td className="px-2 py-2 tabular">{ms(a.dwell.mean)} <span className="text-muted-foreground/60">[{a.dwell.lo.toFixed(1)},{a.dwell.hi.toFixed(1)}]</span></td>
                  <td className="px-2 py-2 tabular">{Math.round(a.oracleHitPct)}%</td>
                  <td className="px-2 py-2 tabular">{a.defensiveActions.toFixed(1)}</td>
                  <td className="px-2 py-2">{a.mtdEffect ? <Badge variant={a.mtdEffect.includes("NEUTRAL") ? "real" : a.mtdEffect.includes("CANNOT") ? "danger" : "modeled"}>{a.mtdEffect.replace("MTD-", "")}</Badge> : "—"}</td>
                  <td className="px-2 py-2 tabular">{a.securityPerCost ? `$${Math.round(a.securityPerCost).toLocaleString()}` : "—"}</td>
                  <td className="px-2 py-2 tabular text-muted-foreground">{a.schwartauP.toFixed(0)}/{a.schwartauD > 0 ? a.schwartauD.toFixed(0) : "—"}/{a.schwartauR.toFixed(1)}</td>
                  <td className="px-2 py-2 tabular">{a.replayAttempts > 0 ? `${a.replaySuccess}/${a.replayAttempts}` : "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* per-trial rows with the attacker command steps */}
      {ev.trials.length > 0 && (
        <div>
          <SectionLabel>Per-trial detail ({ev.trials.length})</SectionLabel>
          <div className="mt-1 space-y-1">
            {ev.trials.map((t) => {
              const key = `${t.defender}-${t.trial}`;
              const landed = t.disruption < 0.5 && t.oracleAchieved;
              return (
                <div key={key} className="rounded border border-border/40">
                  <button onClick={() => setOpenTrial(openTrial === key ? "" : key)} className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-[11px]">
                    <span className="font-mono text-foreground/80">{armLabel(t.defender)} · trial {t.trial}</span>
                    {t.skipped ? <Badge variant="neutral">skipped</Badge> : <Badge variant={landed ? "danger" : "real"}>{landed ? "attack landed" : "disrupted"}</Badge>}
                    <span className="ml-auto tabular text-muted-foreground">disrupt {Math.round(t.disruption * 100)}% · dwell {ms(t.dwell)} · {t.defensiveActions} act{t.mtdEffect ? ` · ${t.mtdEffect.replace("MTD-", "")}` : ""} <Terminal className="inline h-3 w-3" /></span>
                  </button>
                  {openTrial === key && (
                    <div className="space-y-1 border-t border-border/40 px-2 py-2">
                      {(t.commands || []).map((c, i) => <div key={i} className="flex gap-2 font-mono text-[11px]"><span className="select-none text-muted-foreground/40">{i + 1}</span><span className="break-all text-foreground/80">{c}</span></div>)}
                      {t.observed && <div className="pt-1 text-[11px] text-muted-foreground">→ {t.observed}</div>}
                      {!t.commands?.length && <div className="text-[11px] text-muted-foreground/60">no command trace</div>}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      <div className="text-[11px] text-muted-foreground">{ev.note}</div>
      {runErr && <div className="text-[11px] text-danger">run error: {runErr}</div>}
    </div>
  );
}

const armLabel = (def: string) => def === "d-phorvex" ? "Phorvex" : def === "d-nomtd" ? "Without Phorvex" : def.replace("d-r6blindtimer", "Without Phorvex (blind)").replace("d-", "");

// Post-attack report history: every live attack you launched, newest first, with its date and
// the real with/without-Phorvex metrics. Polls so it refreshes as runs finish.
export function RunHistoryPanel({ lens }: { lens: Lens }) {
  const [allRuns, setRuns] = React.useState<RunStatus[] | null>(null);
  const [err, setErr] = React.useState("");
  const [open, setOpen] = React.useState<string>("");
  const sel = useSelectedTarget(); // SCOPE the report list to the selected provider

  React.useEffect(() => {
    let alive = true;
    const load = () => api.runsList(lens).then((d) => { if (alive) setRuns(d.runs || []); }).catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 4000); // refresh as live attacks finish
    return () => { alive = false; clearInterval(t); };
  }, [lens]);

  if (err && !allRuns) return <ErrorState msg={err} />;
  if (!allRuns) return <Card><CardContent className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> loading attack reports…</CardContent></Card>;
  // show ONLY attacks that ran on the selected provider (header scope).
  const runs = sel.provider ? allRuns.filter((r) => (r.provider || "") === sel.provider) : allRuns;

  return (
    <div className="space-y-5">
      <PageHead title="Attack reports" sub="Every attack you launched from the Attack Lab — newest first, with the date it ran and the real measured metrics: attack disruption without Phorvex vs with Phorvex, attacker dwell, and defensive actions. This list refreshes automatically as live attacks finish." />
      {runs.length === 0 ? (
        <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">No attacks {sel.provider ? <>on <span className="text-foreground">{sel.label || sel.provider}</span></> : "run"} yet — go to <span className="text-primary">Attack Lab</span>, launch a scenario {sel.provider ? "on this provider" : ""}, and its report appears here when it finishes.</CardContent></Card>
      ) : (
        <Card><CardContent className="p-0">
          <div className="overflow-x-auto p-3">
            <table className="w-full text-[12px]">
              <thead><tr className="text-left text-muted-foreground">
                <th className="px-2 py-1.5">Date (UTC)</th>
                <th className="px-2 py-1.5">Scenario</th>
                <th className="px-2 py-1.5">Provider</th>
                <th className="px-2 py-1.5">Namespace</th>
                <th className="px-2 py-1.5">State</th>
                <th className="px-2 py-1.5">Without Phorvex</th>
                <th className="px-2 py-1.5">With Phorvex</th>
                <th className="px-2 py-1.5">Attacker dwell</th>
              </tr></thead>
              <tbody>
                {runs.map((r) => {
                  const without = arm(r.arms, "d-nomtd");
                  const withPx = arm(r.arms, "d-phorvex");
                  const px = withPx || arm(r.arms, "d-r6blindtimer");
                  return (
                    <React.Fragment key={r.id}>
                      <tr className="cursor-pointer border-t border-border/40 hover:bg-elevated/40" onClick={() => setOpen(open === r.id ? "" : r.id)}>
                        <td className="px-2 py-2 tabular text-muted-foreground"><span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" />{r.date || r.started}</span></td>
                        <td className="px-2 py-2 font-mono text-foreground/90">{r.config}</td>
                        <td className="px-2 py-2"><ProviderTag provider={r.provider} label={r.targetLabel || r.target} /></td>
                        <td className="px-2 py-2 font-mono text-muted-foreground">{r.namespace || "—"}</td>
                        <td className="px-2 py-2">
                          {r.state === "running" ? <Badge variant="accent"><Loader2 className="h-3 w-3 animate-spin" />running</Badge>
                            : r.state === "done" ? <Badge variant="real"><CheckCircle2 className="h-3 w-3" />done</Badge>
                            : <Badge variant="danger">error</Badge>}
                        </td>
                        <td className="px-2 py-2"><span className="inline-flex items-center gap-1 text-danger"><ShieldOff className="h-3 w-3" />{without ? `${pct(without.disruption)} disrupted` : "—"}</span></td>
                        <td className="px-2 py-2"><span className="inline-flex items-center gap-1 text-primary"><ShieldCheck className="h-3 w-3" />{px ? `${pct(px.disruption)} disrupted` : (r.state === "running" ? "…" : "—")}</span></td>
                        <td className="px-2 py-2 tabular text-muted-foreground">{px && px.dwellMean > 0 ? `${px.dwellMean.toFixed(1)}s` : without && without.dwellMean > 0 ? `${without.dwellMean.toFixed(1)}s` : "—"}</td>
                      </tr>
                      {open === r.id && (
                        <tr className="border-t border-border/20 bg-elevated/20">
                          <td colSpan={8} className="px-4 py-3">
                            <EvidenceDetail id={r.id} lens={lens} runErr={r.error} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="px-4 pb-3 text-[11px] text-muted-foreground">Click a row for the per-arm breakdown. Metrics are read live from each run's metrics.jsonl; the cost/ROI report is regenerated automatically when a run finishes.</div>
        </CardContent></Card>
      )}
    </div>
  );
}
