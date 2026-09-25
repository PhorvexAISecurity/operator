"use client";
import * as React from "react";
import { api, ApiError, Lens, RunStatus, ArmResult, RunEvidence } from "@/lib/api";
import { useSelectedTarget } from "@/lib/provider-store";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Input } from "@/components/ui/more";
import { DataFreshness, PaginationBar } from "@/components/ui/pagination";
import { useServerPage } from "@/lib/use-server-page";
import { PageHead, SectionLabel, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Loader2, ShieldCheck, ShieldOff, Clock, FileText, Terminal, Server, Boxes } from "lucide-react";
import { LIVE_SELECTION_EVENT, LiveSelectionEvent, clearLiveSelection, readLiveSelection, selectLiveRecord } from "@/lib/live-selection";
import { useExactRecord, useQueryScope, useRunEvidence } from "@/lib/query";
import { emitQueryChange } from "@/lib/query-events";
import { trialOutcomeDisplay } from "@/lib/trial-outcome";
import { NATSClientResponseResult } from "@/components/panels/nats-client-response-result";
import { MongoExposureResult } from "@/components/panels/mongo-exposure-result";
import { GuardrailStaticResultPanel } from "@/components/panels/guardrail-static-result";
import { PodBoundTokenResultPanel } from "@/components/panels/pod-bound-token-result";
import { LiteLLMRoutingResult } from "@/components/panels/litellm-routing-result";
import { GuardrailAvailabilityResultPanel } from "@/components/panels/guardrail-availability-result";

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

function NATSReconcileAction({ run, lens }: { run: RunStatus; lens: Lens }) {
  const [busy, setBusy] = React.useState(false);
  const [uncertain, setUncertain] = React.useState(false);
  const [message, setMessage] = React.useState("");
  if (lens !== "operator" || run.config !== "nats-exposure-baseline" || run.state !== "partial" || !run.unsafeToRetry) return null;
  async function reconcile() {
    setBusy(true); setUncertain(true); setMessage("");
    try {
      await api.reconcileNATSRun(run.id, lens);
      setUncertain(false);
      setMessage("Exact read-only cleanup reconciliation verified. The original measurement remains incomplete; refresh this run's status before a new launch.");
    } catch (error: any) {
      setMessage(error instanceof ApiError && error.status >= 400 && error.status < 500
        ? `Read-only reconciliation refused: ${String(error.message || error)}`
        : "Reconciliation response is uncertain. Refresh exact run status before another request; no fixture was replayed by this control.");
    } finally { setBusy(false); }
  }
  return <div className="mb-3 rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px]">
    <div>Owned NATS cleanup is unverified. This original run cannot be accepted or safely repeated until its exact resources are reconciled.</div>
    <button className="mt-2 text-primary disabled:opacity-50" disabled={busy || uncertain} onClick={reconcile}>{busy ? "Checking exact owned state…" : "Reconcile this run read-only"}</button>
    {message && <div className="mt-2 text-muted-foreground">{message}</div>}
  </div>;
}

// Full per-run evidence ledger (per-arm aggregates + per-trial rows with attack command steps).
function EvidenceDetail({ id, lens, runErr, runConfig, unsafeToRetry }: { id: string; lens: Lens; runErr?: string; runConfig?: string; unsafeToRetry?: boolean }) {
  const [openTrial, setOpenTrial] = React.useState<string>("");
  const evidence = useRunEvidence(id, lens);
  if (evidence.error) return <div className="text-[12px] text-danger">{String((evidence.error as Error).message || evidence.error)} <button className="text-primary" onClick={() => evidence.refetch()}>Retry</button></div>;
  if (!evidence.data) return <div className="flex items-center gap-2 py-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading evidence…</div>;
  const ev = evidence.data;
  const liteLLMRouting = runConfig === "catalogue-litellm-inference-routing" || ev.scenario === "catalogue-litellm-inference-routing";
  const ms = (x: number) => (x > 0 ? `${x.toFixed(1)}s` : "—");
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-muted-foreground">
        <FileText className="h-3.5 w-3.5" /> Evidence · {ev.scenario} · ns={ev.namespace || "—"} · started {ev.date}{ev.finished ? ` · finished ${ev.finished}` : ""}
      </div>

      {ev.functionalResult && <div className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
        <div className="flex flex-wrap items-center gap-2"><Badge variant={trialOutcomeDisplay(ev.functionalResult.outcome).variant}>{trialOutcomeDisplay(ev.functionalResult.outcome).label}</Badge><span className="text-foreground">{ev.functionalResult.summary}</span></div>
        <div className="mt-2 text-muted-foreground">cleanup: <span className="text-foreground">{ev.functionalResult.cleanup.status}</span>{ev.functionalResult.cleanup.verified ? " · verified" : " · unverified"}</div>
        {ev.functionalResult.unsafeToRetry && <div className="mt-1 text-warning">This run remains unsafe to retry; inspect its run status and exact cleanup evidence.</div>}
        {ev.functionalResult.limits?.map((limit) => <div key={limit} className="mt-1 text-muted-foreground">limit: {limit}</div>)}
        {liteLLMRouting ? <div className="mt-2"><LiteLLMRoutingResult evidence={ev.functionalResult.evidence} outcome={ev.functionalResult.outcome} /></div>
          : <div className="mt-2 grid gap-1 md:grid-cols-2">{Object.entries(ev.functionalResult.evidence || {}).map(([key, value]) => <div key={key} className="break-all font-mono text-[11px]"><span className="text-muted-foreground">{key}=</span>{value}</div>)}</div>}
      </div>}
      {liteLLMRouting && !ev.functionalResult && <LiteLLMRoutingResult evidence={undefined} />}

      {ev.configurationResult && <div className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
        <div className="font-medium text-foreground">Accepted synthetic NATS configuration finding: {ev.configurationResult.finding}</div>
        <div className="mt-1 text-muted-foreground">{ev.configurationResult.accepted ? "Complete owned control" : "Observed receipt retained; complete result unverified"} · no signal · no detector · defense efficacy not evaluated</div>
        {!ev.configurationResult.accepted && <div className="mt-1 text-muted-foreground">Unaccepted observer indication: {ev.configurationResult.observedFinding}</div>}
        <div className="mt-1 text-muted-foreground">Separate Pod: {ev.configurationResult.remoteStatus} · legitimate ACK: {ev.configurationResult.legitimateAcked ? "confirmed" : "unverified"} · stream: {ev.configurationResult.streamCleanup} · observer: {ev.configurationResult.observerCleanup} · fixture resources: {ev.configurationResult.fixtureResourcesCleanup}</div>
        {ev.configurationResult.issues?.map((issue) => <div key={issue} className="mt-1 text-warning">unverified: {issue}</div>)}
      </div>}
      {ev.natsResponseResult && <NATSClientResponseResult result={ev.natsResponseResult} unsafeToRetry={unsafeToRetry} />}
      {runConfig === "pod-bound-api-auth-response" && ev.podBoundTokenResult && <PodBoundTokenResultPanel result={ev.podBoundTokenResult} unsafeToRetry={unsafeToRetry} />}
      {runConfig === "pod-bound-api-auth-response" && !ev.podBoundTokenResult && <div className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px]">Exact Pod-bound bearer stage evidence is unavailable. No injected-signal, operation or credential mechanism result is accepted.</div>}
      {ev.guardrailStaticResult && <GuardrailStaticResultPanel result={ev.guardrailStaticResult} />}
      {runConfig === "guardrail-confidentiality-static" && !ev.guardrailStaticResult && <div className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px]">Exact private guardrail comparison evidence is unavailable or incomplete. No static-filter finding is accepted.</div>}
      {runConfig === "guardrail-availability-recovery" && ev.guardrailAvailabilityResult && <GuardrailAvailabilityResultPanel result={ev.guardrailAvailabilityResult} unsafeToRetry={unsafeToRetry} />}
      {runConfig === "guardrail-availability-recovery" && !ev.guardrailAvailabilityResult && <div className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px]">Exact guardrail availability evidence is unavailable. No injected operation or before/after recovery is accepted.</div>}
      {runConfig === "nats-client-response" && !ev.natsResponseResult && <div className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px]">Exact NATS response evidence is unavailable or incomplete. No injected-signal outcome, packet isolation, or defense result is accepted.</div>}
      {ev.mongoExposureResult && <MongoExposureResult result={ev.mongoExposureResult} unsafeToRetry={unsafeToRetry} />}
      {runConfig === "mongo-exposure-baseline" && !ev.mongoExposureResult && <div className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px]">Exact Mongo synthetic-document evidence is unavailable or incomplete. No configuration exposure finding, manager causal claim, or defense result is accepted.</div>}

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
            {ev.arms.length === 0 && <tr><td colSpan={10} className="px-2 py-2 text-muted-foreground">no certified security comparison — see the typed trial results below.</td></tr>}
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
            {ev.trials.map((t, index) => {
              const scenario = t.scenario || ev.scenario || "legacy scenario";
              const key = `${scenario}-${t.defender}-${t.trial}-${index}`;
              const display = trialOutcomeDisplay(t.outcome);
              return (
                <div key={key} className="rounded border border-border/40">
                  <button onClick={() => setOpenTrial(openTrial === key ? "" : key)} className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-[11px]">
                    <span className="font-mono text-foreground/80">{scenario} · {armLabel(t.defender)} · trial {t.trial}</span>
                    <Badge variant={display.variant}>{display.label}</Badge>
                    <span className="ml-auto tabular text-muted-foreground">{t.claimClass === "security" && (t.outcome === "security-landed" || t.outcome === "security-disrupted") ? `disrupt ${Math.round(t.disruption * 100)}% · ` : ""}dwell {ms(t.dwell)} · {t.defensiveActions} act{t.mtdEffect ? ` · ${t.mtdEffect.replace("MTD-", "")}` : ""} <Terminal className="inline h-3 w-3" /></span>
                  </button>
                  {openTrial === key && (
                    <div className="space-y-1 border-t border-border/40 px-2 py-2">
                      {(t.commands || []).map((c, i) => <div key={i} className="flex gap-2 font-mono text-[11px]"><span className="select-none text-muted-foreground/40">{i + 1}</span><span className="break-all text-foreground/80">{c}</span></div>)}
                      {t.observed && <div className="pt-1 text-[11px] text-muted-foreground">→ {t.observed}</div>}
                      <div className="pt-1 text-[11px] text-muted-foreground">{t.outcomeReason}{t.measurementPhase ? ` · phase ${t.measurementPhase}` : ""}</div>
                      {!t.commands?.length && <div className="text-[11px] text-muted-foreground/60">no command trace</div>}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      {(ev.issues || []).map((issue) => <div key={`${issue.line}-${issue.reason}`} className="rounded border border-info/30 bg-info/5 px-2 py-1 text-[11px] text-info">unverified metric row {issue.line}: {issue.reason}</div>)}
      <div className="text-[11px] text-muted-foreground">{ev.note}</div>
      {runErr && <div className="text-[11px] text-danger">run error: {runErr}</div>}
    </div>
  );
}

const armLabel = (def: string) => def === "d-phorvex" ? "Phorvex" : def === "d-nomtd" ? "Without Phorvex" : def.replace("d-r6blindtimer", "Without Phorvex (blind)").replace("d-", "");

// Post-attack report history: every live attack you launched, newest first, with its date and
// the real with/without-Phorvex metrics. Polls so it refreshes as runs finish.
export function RunHistoryPanel({ lens }: { lens: Lens }) {
  const queryScope = useQueryScope(lens);
  const [open, setOpen] = React.useState<string>("");
  const [q, setQ] = React.useState("");
  const sel = useSelectedTarget(); // SCOPE the report list to the selected provider
  const previousStates = React.useRef<Map<string, RunStatus["state"]> | null>(null);
  const matchesSelectedScope = React.useCallback((run: RunStatus) => {
    if (run.target) return !!sel.context && run.target === sel.context;
    return !sel.provider || (run.provider || "") === sel.provider;
  }, [sel.context, sel.provider]);
  React.useEffect(() => {
    const apply = (selection: LiveSelectionEvent | null) => {
      if (!selection) { setOpen(""); return; }
      if (selection?.lens !== lens || selection.context !== sel.context) return;
      if (selection?.kind === "run" && selection.lens === lens && selection.context === sel.context) setOpen(selection.id);
      else setOpen("");
    };
    apply(readLiveSelection(lens, sel.context));
    const onSelection = (event: Event) => apply((event as CustomEvent<LiveSelectionEvent>).detail);
    window.addEventListener(LIVE_SELECTION_EVENT, onSelection);
    return () => window.removeEventListener(LIVE_SELECTION_EVENT, onSelection);
  }, [lens, sel.context]);

  const normalizedQ = q.trim().toLowerCase();
  const scopeKey = `${lens}\u0000${sel.context}\u0000${sel.provider}\u0000${normalizedQ}`;
  const pager = useServerPage<RunStatus>({
    resource: "runs", lens,
    key: scopeKey,
    network: { context: sel.context || undefined, provider: sel.provider || undefined, q: normalizedQ || undefined },
    pageSize: 20,
    pollMs: 4000,
    fetchPage: (cursor, signal) => api.runsPage(lens, 20, { context: sel.context || undefined, provider: sel.provider || undefined, q: normalizedQ || undefined }, cursor, signal)
      .then((d) => ({ items: d.runs || [], page: d.page })),
    legacyFilter: (run) => matchesSelectedScope(run) && (!normalizedQ || `${run.id} ${run.config} ${run.namespace || ""}`.toLowerCase().includes(normalizedQ)),
  });

  React.useEffect(() => { previousStates.current = null; }, [lens, sel.context, sel.provider, normalizedQ]);

  React.useEffect(() => {
    const next = pager.items;
    if (!pager.loading) {
        const states = new Map(next.map((r) => [r.id, r.state]));
        if (previousStates.current) {
          next.forEach((r) => {
            const prior = previousStates.current?.get(r.id);
            if (r.target && matchesSelectedScope(r) && r.state === "done" && (prior === "running" || prior === "queued")) {
              emitQueryChange({ identity: queryScope.identity, providerToken: queryScope.providerToken, context: sel.context || undefined, runId: r.id, lens, resources: ["runs", "runs-summary", "run-status", "run-evidence", "reports", "report", "effectiveness", "posture", "benchmarks", "cost", "cost-timeseries", "uptime", "matrix", "audit-snapshot", "diagnostics"], kind: "completion" });
            }
          });
        }
        previousStates.current = states;
    }
  }, [pager.items, pager.loading, lens, matchesSelectedScope]);

  const openOnPage = !!open && pager.items.some((r) => r.id === open);
  const needsPinned = !!open && (!openOnPage || pager.hasSnapshot || pager.page > 0);
  const pinnedQuery = useExactRecord({ resource: "run-status", context: `${sel.context}\u0000${sel.provider}`, id: open, lens, enabled: needsPinned,
    fetcher: async (signal) => { try { const run = await api.runStatus(open, lens, signal); return matchesSelectedScope(run) ? run : null; } catch (error) { if (error instanceof ApiError && error.status === 404) return null; throw error; } },
    active: (run) => run.state === "running" || run.state === "queued" });
  const pinned = needsPinned ? pinnedQuery.data || null : null;
  const pinnedMissing = needsPinned && pinnedQuery.data === null;
  const pinnedError = pinnedQuery.error ? String((pinnedQuery.error as Error).message || pinnedQuery.error) : "";
  const pinnedPending = needsPinned && pinnedQuery.isPending;
  const runs = pinned
    ? (pager.items.some((r) => r.id === pinned.id) ? pager.items.map((r) => r.id === pinned.id ? pinned : r) : [pinned, ...pager.items])
    : pager.items;

  return (
    <div className="space-y-5">
      <PageHead title="Scenario run reports" sub="Run history with typed per-trial outcomes. Certified security rows include measured attack comparisons; benign, invalid, and legacy rows remain visible without being scored as security efficacy." />
      <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search all reports by run, scenario, or namespace…" aria-label="Search scenario run reports" />
      {pager.legacy && <div className="text-[11px] text-warning">Legacy/preview response: paging and search cover the full history returned by this fixture, not server snapshot pages.</div>}
      {pager.error && <div className="text-[11px] text-danger">Page refresh failed: {pager.error} <button className="text-primary" onClick={pager.retry}>Retry</button></div>}
      <DataFreshness updatedAt={pager.updatedAt} refreshing={pager.refreshing} failed={!!pager.error} />
      {pinned && <div className="text-[11px] text-muted-foreground">The selected run is refreshed independently for this frozen/older view; snapshot membership and page statistics are unchanged.</div>}
      {pinnedMissing && <div className="text-[11px] text-warning">Selected run <span className="font-mono">{open}</span> is missing or outside the authorized scope. <button className="text-primary" onClick={() => pinnedQuery.refetch()}>Retry</button></div>}
      {pinnedError && <div className="text-[11px] text-danger">Could not load selected run: {pinnedError} <button className="text-primary" onClick={() => pinnedQuery.refetch()}>Retry</button></div>}
      {pinnedPending && <div className="flex items-center gap-2 text-[11px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading exact selected run…</div>}
      {pager.loading && !pager.pageMeta ? <Card><CardContent className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> loading scenario reports…</CardContent></Card> : pager.error && !pager.pageMeta ? <ErrorState msg={pager.error} /> : runs.length === 0 ? (
        open && (pinnedPending || pinnedMissing || pinnedError) ? (pinnedPending ? <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">Waiting for exact selected run <span className="font-mono">{open}</span>…</CardContent></Card> : null) : <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">No scenario runs {sel.provider ? <>on <span className="text-foreground">{sel.label || sel.provider}</span></> : "recorded"} yet.</CardContent></Card>
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
                <th className="px-2 py-1.5">Security baseline</th>
                <th className="px-2 py-1.5">Security treatment</th>
                <th className="px-2 py-1.5">Security dwell</th>
              </tr></thead>
              <tbody>
                {runs.map((r) => {
                  const without = arm(r.arms, "d-nomtd");
                  const withPx = arm(r.arms, "d-phorvex");
                  const px = withPx || arm(r.arms, "d-r6blindtimer");
                  const hasSecurityComparison = !!without || !!px;
                  return (
                    <React.Fragment key={r.id}>
                      <tr className={cn("cursor-pointer border-t border-border/40 hover:bg-elevated/40", open === r.id && "bg-primary/[0.04]")} onClick={() => {
                        const next = open === r.id ? "" : r.id;
                        setOpen(next);
                        if (next && r.target && r.target === sel.context) selectLiveRecord({ kind: "run", id: r.id, lens, context: sel.context });
                        else if (!next) clearLiveSelection(lens, sel.context);
                      }}>
                        <td className="px-2 py-2 tabular text-muted-foreground"><span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" />{r.date || r.started}</span></td>
                        <td className="px-2 py-2 font-mono text-foreground/90"><div>{r.config}</div><div className="text-[10px] text-muted-foreground" title={r.id}>run {r.id}</div></td>
                        <td className="px-2 py-2"><ProviderTag provider={r.provider} label={r.targetLabel || r.target} />{!r.target && <div className="mt-1 text-[10px] text-warning">legacy provider match</div>}</td>
                        <td className="px-2 py-2 font-mono text-muted-foreground">{r.namespace || "—"}</td>
                        <td className="px-2 py-2">
                          {r.state === "queued" ? <Badge variant="accent">queued</Badge>
                            : r.state === "running" ? <Badge variant="accent"><Loader2 className="h-3 w-3 animate-spin" />running</Badge>
                            : r.state === "done" ? <Badge variant="neutral"><FileText className="h-3 w-3" />execution done</Badge>
                            : r.state === "partial" ? <Badge variant="pending">incomplete</Badge>
                            : r.state === "stopped" ? <Badge variant="neutral">stopped</Badge>
                            : <Badge variant="danger">error</Badge>}
                        </td>
                        <td className="px-2 py-2">{hasSecurityComparison ? <span className="inline-flex items-center gap-1 text-danger"><ShieldOff className="h-3 w-3" />{without ? `${pct(without.disruption)} disrupted` : "—"}</span> : <span className="text-muted-foreground">typed results</span>}</td>
                        <td className="px-2 py-2">{hasSecurityComparison ? <span className="inline-flex items-center gap-1 text-primary"><ShieldCheck className="h-3 w-3" />{px ? `${pct(px.disruption)} disrupted` : (r.state === "running" ? "…" : "—")}</span> : <span className="text-muted-foreground">not security-scored</span>}</td>
                        <td className="px-2 py-2 tabular text-muted-foreground">{hasSecurityComparison ? (px && px.dwellMean > 0 ? `${px.dwellMean.toFixed(1)}s` : without && without.dwellMean > 0 ? `${without.dwellMean.toFixed(1)}s` : "—") : "—"}</td>
                      </tr>
                      {open === r.id && (
                        <tr className="border-t border-border/20 bg-elevated/20">
                          <td colSpan={8} className="px-4 py-3">
                            <NATSReconcileAction run={r} lens={lens} />
                            <EvidenceDetail id={r.id} lens={lens} runErr={r.error} runConfig={r.config} unsafeToRetry={r.unsafeToRetry} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="px-4 pb-3 text-[11px] text-muted-foreground">Click a row for typed per-trial evidence. Security aggregates include only rows authorized by the shared validity contract.</div>
          <div className="px-4 pb-4"><PaginationBar page={pager.page} pageSize={20} total={pager.pageMeta?.total} hasNext={pager.hasNext} onPrevious={pager.previous} onNext={pager.next} onLatest={pager.latest} showLatest={pager.hasSnapshot || pager.page > 0} loading={pager.loading} /></div>
        </CardContent></Card>
      )}
      {((pager.loading && !pager.pageMeta) || (pager.error && !pager.pageMeta) || runs.length === 0) && <PaginationBar page={pager.page} pageSize={20} total={pager.pageMeta?.total} hasNext={pager.hasNext} onPrevious={pager.previous} onNext={pager.next} onLatest={pager.latest} showLatest={pager.hasSnapshot || pager.page > 0} loading={pager.loading} />}
    </div>
  );
}
