"use client";
import * as React from "react";
import { api, Lens, AttackMonitoring, MonPoint } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { csvDownload, Empty, Input } from "@/components/ui/more";
import { DataFreshness, PaginationBar } from "@/components/ui/pagination";
import { useServerPage } from "@/lib/use-server-page";
import { Loader2, Download, Activity, ShieldCheck, ShieldAlert, TrendingDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSelectedTarget } from "@/lib/provider-store";
import { LIVE_SELECTION_EVENT, LiveSelectionEvent, readLiveSelection } from "@/lib/live-selection";
import { useExactRecord } from "@/lib/query";

// AttackMonitoringPanel — the availability picture AROUND each real live attack, reconstructed
// from the background sampler (5s cadence): a genuine BEFORE baseline, the during-attack trough,
// the recovery tail, and the AWS cost of the capacity that was actually unavailable.
export function AttackMonitoringPanel({ lens }: { lens: Lens }) {
  const target = useSelectedTarget();
  const [selectedId, setSelectedId] = React.useState("");
  const [q, setQ] = React.useState("");
  const normalizedQ = q.trim().toLowerCase();
  const pager = useServerPage<AttackMonitoring, { sampleInterval: number; preWindowSec: number; note: string }>({
    resource: "attack-monitoring", lens,
    key: `${lens}\u0000${normalizedQ}`,
    network: { q: normalizedQ || undefined },
    pageSize: 20,
    pollMs: 5000,
    fetchPage: (cursor, signal) => api.attackMonitoringPage(lens, 20, { q: normalizedQ || undefined }, cursor, signal).then((d) => ({
      items: d.attacks || [], page: d.page, meta: { sampleInterval: d.sampleInterval, preWindowSec: d.preWindowSec, note: d.note },
    })),
    legacyFilter: (r) => !normalizedQ || `${r.id} ${r.service} ${r.namespace} ${r.attack}`.toLowerCase().includes(normalizedQ),
  });
  React.useEffect(() => {
    const apply = (selection: LiveSelectionEvent | null) => {
      if (!selection) { setSelectedId(""); return; }
      if (selection?.lens !== lens || selection.context !== target.context) return;
      setSelectedId(selection.kind === "attack" ? selection.id : "");
    };
    apply(readLiveSelection(lens, target.context));
    const onSelection = (event: Event) => apply((event as CustomEvent<LiveSelectionEvent>).detail);
    window.addEventListener(LIVE_SELECTION_EVENT, onSelection);
    return () => window.removeEventListener(LIVE_SELECTION_EVENT, onSelection);
  }, [lens, target.context]);

  const selectedOnPage = !!selectedId && pager.items.some((r) => r.id === selectedId);
  const needsExact = !!selectedId && (!selectedOnPage || pager.hasSnapshot || pager.page > 0);
  const exactQuery = useExactRecord({ resource: "attack-monitoring", context: target.context, id: selectedId, lens, enabled: needsExact,
    fetcher: (signal) => api.attackMonitoringPage(lens, 1, { id: selectedId }, undefined, signal).then((d) => (d.attacks || []).find((r) => r.id === selectedId) || null),
    active: () => true });
  const exact = needsExact ? exactQuery.data || null : null;
  const exactMissing = needsExact && exactQuery.data === null;
  const exactError = exactQuery.error ? String((exactQuery.error as Error).message || exactQuery.error) : "";
  const exactPending = needsExact && exactQuery.isPending;
  const rows = exact
    ? (pager.items.some((r) => r.id === exact.id) ? pager.items.map((r) => r.id === exact.id ? exact : r) : [exact, ...pager.items])
    : pager.items;

  const impacted = pager.items.filter((r) => r.impacted).length;
  const totalDown = pager.items.reduce((a, r) => a + (r.downtime?.dollars || 0), 0);
  const measurable = pager.items.filter((r) => r.before?.complete).length;

  function exportCSV() {
    const head = ["fired", "service", "workload", "attack", "outcome", "actuator", "before_mean_pct", "during_min_pct", "after_mean_pct", "impacted", "recovered_sec", "unavailable_replica_seconds", "node_rate_per_hr", "downtime_dollars"];
    const body = pager.items.map((r) => [r.firedAt, r.service, r.workload, r.attack, r.outcome, r.phorvexAction,
      r.before?.complete ? r.before.meanPct : "", r.during?.complete ? r.during.minPct : "", r.after?.complete ? r.after.meanPct : "",
      r.impacted ? "yes" : "no", r.recoveredSec >= 0 ? r.recoveredSec : "", r.downtime?.replicaSeconds, r.downtime?.nodeRatePerHr, r.downtime?.dollars]);
    csvDownload("phorvex-attack-monitoring-page.csv", [head, ...body]);
  }

  return (
    <div className="space-y-3">
      <div className="text-[11px] text-muted-foreground">Cluster-wide recorded attack monitoring for this console; changing the selected target does not filter these rows.</div>
      <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search all monitoring by ID, service, namespace, or attack…" aria-label="Search attack monitoring" />
      {pager.legacy && <div className="text-[11px] text-warning">Legacy/preview response: paging and search cover the full history returned by this fixture.</div>}
      {pager.error && <div className="text-[11px] text-danger">Page refresh failed: {pager.error} <button className="text-primary" onClick={pager.retry}>Retry</button></div>}
      <DataFreshness updatedAt={pager.updatedAt} refreshing={pager.refreshing} failed={!!pager.error} />
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-[12px] font-medium"><Activity className="h-3.5 w-3.5 text-primary" /> Availability around each live attack</div>
        <div className="text-[11px] text-muted-foreground">
          Current page: {pager.items.length} attack{pager.items.length === 1 ? "" : "s"} · <span className="text-foreground">{measurable}</span> with a usable before-baseline ·{" "}
          <span className={impacted ? "text-warning" : "text-success"}>{impacted} caused an availability drop</span> · total downtime cost{" "}
          <span className="tabular text-foreground">${totalDown.toFixed(2)}</span>
        </div>
        <Button size="sm" variant="outline" onClick={exportCSV} className="ml-auto gap-1.5"><Download className="h-3.5 w-3.5" /> CSV (page)</Button>
      </div>
      {pager.meta && <div className="text-[11px] text-muted-foreground/80">{pager.meta.note}</div>}
      {exact && <div className="text-[11px] text-muted-foreground">The selected monitoring record is refreshed independently for this frozen/older view; snapshot membership, page statistics, and CSV are unchanged.</div>}
      {selectedId && exactMissing && <div className="text-[11px] text-warning">Exact selected attack <span className="font-mono">{selectedId}</span> has no monitoring record; no other attack was substituted. <button className="text-primary" onClick={() => exactQuery.refetch()}>Retry</button></div>}
      {selectedId && exactError && <div className="text-[11px] text-danger">Could not load exact selected monitoring record: {exactError} <button className="text-primary" onClick={() => exactQuery.refetch()}>Retry</button></div>}
      {exactPending && <div className="flex items-center gap-2 text-[11px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading exact selected monitoring record…</div>}
      {pager.loading && !pager.pageMeta && <div className="flex items-center gap-2 py-8 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading attack monitoring…</div>}
      {rows.length === 0 && !pager.loading && !pager.error && (selectedId
        ? (!exactMissing && !exactError && <div className="text-[12px] text-muted-foreground">Waiting for exact monitoring record <span className="font-mono">{selectedId}</span>…</div>)
        : <Empty msg={q ? "No monitoring records match this search." : "No attacks fired yet. Fire a real attack from Protect → Live theatre — its availability before/during/after and the downtime cost will appear here."} />)}
      {[...rows].sort((a, b) => Number(b.id === selectedId) - Number(a.id === selectedId)).map((r) => <MonitoringCard key={r.id} r={r} selected={r.id === selectedId} />)}
      <PaginationBar page={pager.page} pageSize={20} total={pager.pageMeta?.total} hasNext={pager.hasNext} onPrevious={pager.previous} onNext={pager.next} onLatest={pager.latest} showLatest={pager.hasSnapshot || pager.page > 0} loading={pager.loading} />
    </div>
  );
}

function pctLabel(v: number | undefined, complete: boolean | undefined) {
  if (!complete || v === undefined || v < 0) return "—";
  return `${v.toFixed(1)}%`;
}

function MonitoringCard({ r, selected = false }: { r: AttackMonitoring; selected?: boolean }) {
  const defended = r.outcome === "DEFENDED";
  const base = r.before?.complete ? r.before.meanPct : -1;
  return (
    <Card className={cn("border-l-2", selected && "ring-1 ring-primary/60", r.impacted ? "border-l-warning" : defended ? "border-l-success" : "border-l-border")}>
      <CardContent className="space-y-3 p-4">
        {/* header */}
        <div className="flex flex-wrap items-center gap-2">
          {selected && <Badge variant="accent">selected attack</Badge>}
          {defended
            ? <Badge variant="real" className="gap-1"><ShieldCheck className="h-3 w-3" /> DEFENDED</Badge>
            : <Badge variant="pending" className="gap-1"><ShieldAlert className="h-3 w-3" /> {r.outcome || "—"}</Badge>}
          <span className="font-mono text-[12px] font-medium text-foreground">{r.namespace}/{r.workload}</span>
          <span className="text-[12px] text-muted-foreground">· {r.attack}</span>
          <span className="font-mono text-[10px] text-muted-foreground" title={r.id}>attack {r.id}</span>
          <span className="font-mono text-[11px] text-muted-foreground">→ {r.phorvexAction || "—"}</span>
          <span className="ml-auto font-mono text-[10px] text-muted-foreground/60">{new Date(r.firedAt).toLocaleString()}</span>
        </div>

        {/* before / during / after */}
        <div className="grid grid-cols-3 gap-2">
          <PhaseCell label="Before (baseline)" mean={r.before?.meanPct} min={r.before?.minPct} n={r.before?.samples} complete={r.before?.complete} tone="neutral" />
          <PhaseCell label="During attack" mean={r.during?.meanPct} min={r.during?.minPct} n={r.during?.samples} complete={r.during?.complete} tone={r.impacted ? "warn" : "good"} />
          <PhaseCell label="After (recovery)" mean={r.after?.meanPct} min={r.after?.minPct} n={r.after?.samples} complete={r.after?.complete} tone="good" />
        </div>

        {/* timeline */}
        <MonChart series={r.series} baseline={base} />

        {/* impact + downtime cost */}
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5">
            <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground/70">availability impact</div>
            {r.impacted ? (
              <div className="text-[12px]">
                <span className="text-warning">dropped to {pctLabel(r.during?.minPct, r.during?.complete)}</span>
                <span className="text-muted-foreground"> from a {pctLabel(base, r.before?.complete)} baseline</span>
                {r.recoveredSec >= 0
                  ? <span className="text-muted-foreground"> · recovered after <span className="tabular text-foreground">{r.recoveredSec.toFixed(0)}s</span></span>
                  : <span className="text-muted-foreground"> · <span className="text-warning">not yet back to baseline</span> in the observed window</span>}
              </div>
            ) : (
              <div className="text-[12px] text-success">no drop below the pre-attack baseline</div>
            )}
          </div>
          <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5">
            <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"><TrendingDown className="h-3 w-3" /> downtime cost (real AWS)</div>
            <div className="flex flex-wrap items-baseline gap-x-3 text-[12px]">
              <span className={cn("tabular font-mono text-[15px] font-semibold", r.downtime?.dollars ? "text-warning" : "text-success")}>
                ${(r.downtime?.dollars ?? 0).toFixed(2)}
              </span>
              <span className="text-muted-foreground">
                {(r.downtime?.replicaSeconds ?? 0).toFixed(0)} replica-s unavailable × ${(r.downtime?.nodeRatePerHr ?? 0).toFixed(3)}/hr
              </span>
            </div>
          </div>
        </div>

        {r.note && <div className="text-[11px] text-muted-foreground/80">{r.note}</div>}
        <div className="text-[10px] text-muted-foreground/60">{r.downtime?.basis}</div>
      </CardContent>
    </Card>
  );
}

function PhaseCell({ label, mean, min, n, complete, tone }: { label: string; mean?: number; min?: number; n?: number; complete?: boolean; tone: "good" | "warn" | "neutral" }) {
  const toneCls = !complete ? "text-muted-foreground" : tone === "warn" ? "text-warning" : tone === "good" ? "text-success" : "text-foreground";
  return (
    <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5">
      <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground/70">{label}</div>
      <div className={cn("tabular font-mono text-[15px] font-semibold", toneCls)}>{pctLabel(mean, complete)}</div>
      <div className="mt-0.5 text-[10px] text-muted-foreground">
        {complete ? <>min {pctLabel(min, complete)} · {n} samples</> : "no sampler coverage"}
      </div>
    </div>
  );
}

// MonChart — availability on the attack timeline. x = seconds relative to the attack instant, so
// the attack lands at x=0 and the BEFORE baseline is visibly to its left.
function MonChart({ series, baseline }: { series: MonPoint[]; baseline: number }) {
  if (!series || series.length < 2) {
    return <div className="py-5 text-center text-[11px] text-muted-foreground">no sampler coverage for this attack window</div>;
  }
  const W = 720, H = 150, padL = 38, padR = 12, padT = 10, padB = 24;
  const innerW = W - padL - padR, innerH = H - padT - padB;
  const xs = series.map((p) => p.offsetSec);
  const lo = Math.min(...xs), hi = Math.max(...xs);
  const span = Math.max(1, hi - lo);
  const x = (o: number) => padL + ((o - lo) / span) * innerW;
  const y = (pct: number) => padT + innerH - (pct / 100) * innerH;
  const line = series.map((p) => `${x(p.offsetSec).toFixed(1)},${y(p.pct).toFixed(1)}`).join(" ");
  const area = `${x(lo).toFixed(1)},${y(0).toFixed(1)} ${line} ${x(hi).toFixed(1)},${y(0).toFixed(1)}`;
  const duringEnd = Math.min(hi, 95);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Availability before, during and after the attack">
      {/* during-attack band */}
      {hi > 0 && (
        <rect x={x(Math.max(lo, 0))} y={padT} width={Math.max(0, x(duringEnd) - x(Math.max(lo, 0)))} height={innerH}
              fill="var(--warning)" opacity="0.09" />
      )}
      {/* y grid */}
      {[0, 50, 100].map((t) => (
        <g key={t}>
          <line x1={padL} y1={y(t)} x2={W - padR} y2={y(t)} stroke="currentColor" strokeOpacity="0.10" strokeWidth="1" />
          <text x={padL - 6} y={y(t) + 3} textAnchor="end" fontSize="8" fill="currentColor" fillOpacity="0.45" fontFamily="var(--font-mono, monospace)">{t}</text>
        </g>
      ))}
      {/* pre-attack baseline */}
      {baseline >= 0 && (
        <line x1={padL} y1={y(baseline)} x2={W - padR} y2={y(baseline)} stroke="var(--success)" strokeOpacity="0.55" strokeWidth="1" strokeDasharray="4 3" />
      )}
      <polygon points={area} fill="var(--primary)" opacity="0.10" />
      <polyline points={line} fill="none" stroke="var(--primary)" strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
      {/* the attack instant */}
      {lo <= 0 && hi >= 0 && (
        <>
          <line x1={x(0)} y1={padT} x2={x(0)} y2={padT + innerH} stroke="var(--danger)" strokeWidth="1.4" />
          <text x={x(0) + 4} y={padT + 9} fontSize="8" fill="var(--danger)" fontFamily="var(--font-mono, monospace)">attack</text>
        </>
      )}
      <text x={padL} y={H - 6} fontSize="8" fill="currentColor" fillOpacity="0.45" fontFamily="var(--font-mono, monospace)">{lo.toFixed(0)}s</text>
      <text x={W - padR} y={H - 6} textAnchor="end" fontSize="8" fill="currentColor" fillOpacity="0.45" fontFamily="var(--font-mono, monospace)">+{hi.toFixed(0)}s</text>
    </svg>
  );
}
