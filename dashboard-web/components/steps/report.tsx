"use client";
import * as React from "react";
import { api, Lens, Stat, Posture, BenchGroup } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Loading, csvDownload } from "@/components/ui/more";
import { StepHead } from "./shared";
import { MethodologyPanel } from "@/components/subsystems/panels";
import { ReportsPanel } from "@/components/panels/reports";
import { AttackResultsPanel } from "@/components/panels/attack-report";
import { RunHistoryPanel } from "@/components/panels/run-history";
import { FileText, Download, Printer, Swords } from "lucide-react";
import { useApiRead } from "@/lib/query";

export function ReportStep({ lens }: { lens: Lens }) {
  const effectiveness = useApiRead({ lens, resource: "effectiveness", fetcher: (signal) => api.effectiveness(lens, signal), staleTime: 60_000 });
  const postureRead = useApiRead({ lens, resource: "posture", fetcher: (signal) => api.posture(lens, signal), staleTime: 60_000 });
  const benchmarks = useApiRead({ lens, resource: "benchmarks", fetcher: (signal) => api.benchmarks(lens, signal), staleTime: 60_000 });
  const stats = effectiveness.data?.stats ?? [];
  const posture = postureRead.data ?? null;
  const bench = benchmarks.data?.groups ?? [];
  const errors = [effectiveness.error && "effectiveness metrics", postureRead.error && "posture", benchmarks.error && "benchmarks"].filter(Boolean) as string[];
  const complete = effectiveness.data !== undefined && postureRead.data !== undefined && benchmarks.data !== undefined;
  const pending = !complete && (effectiveness.isPending || effectiveness.isFetching || postureRead.isPending || postureRead.isFetching || benchmarks.isPending || benchmarks.isFetching);
  if (!effectiveness.data && !postureRead.data && !benchmarks.data && (effectiveness.isPending || postureRead.isPending || benchmarks.isPending)) return <Loading label="Assembling the evidence pack…" rows={3} />;

  const real = stats.filter((s) => s.status === "real");
  function exportCSV() {
    if (errors.length || !complete) return;
    const rows: (string | number)[][] = [["metric", "value", "unit", "ci_low", "ci_high", "n", "status", "source"]];
    stats.forEach((s) => rows.push([s.label, s.value, s.unit || "", s.ci?.lo ?? "", s.ci?.hi ?? "", s.ci?.n ?? "", s.status, s.source]));
    csvDownload("phorvex-evidence.csv", rows);
  }

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={7} title="Report" sub="Generate the evidence pack — every metric with its 95% CI and its source file. Honest about what's proven (K8s) and what's pending (AI/GPU)." lens={lens} />
      {errors.length > 0 && <div role="alert" className="rounded-lg border border-warning/40 bg-warning/5 p-4 text-sm">
        <p>Report incomplete: could not load {errors.join(", ")}. Evidence exports remain disabled until every summary source loads successfully.</p>
        <Button variant="outline" className="mt-2" onClick={() => void Promise.all([effectiveness.refetch(), postureRead.refetch(), benchmarks.refetch()])}>Retry report sources</Button>
      </div>}
      {!errors.length && pending && <div role="status" className="rounded-lg border border-border bg-panel/50 p-4 text-sm text-muted-foreground">Report sources are still loading. The available summary remains visible, but exports are disabled until effectiveness, posture, and benchmarks are all present.</div>}
      <div className="flex flex-wrap items-center gap-3">
        <Button disabled={!complete || errors.length > 0} onClick={exportCSV}><Download className="h-4 w-4" /> Export evidence CSV</Button>
        <Button disabled={!complete || errors.length > 0} variant="outline" onClick={() => window.print()}><Printer className="h-4 w-4" /> Print / Save PDF</Button>
        {bench.length > 0 && <span className="text-[12px] text-muted-foreground">· {bench.length} benchmark scenarios in the pack</span>}
      </div>

      {/* LIVE ATTACK RESULTS — every real attack fired from Live Operations: landed vs defended,
          the actuator + why, uptime before/dip/after, and the three-way cost (without / R6 / with). */}
      <Card><CardContent className="p-5">
        <div className="mb-1 flex items-center gap-2 text-[13px] font-semibold"><Swords className="h-4 w-4 text-primary" /> Live attack results — real attacks on live services</div>
        <div className="mb-3 text-[11px] text-muted-foreground">Fire attacks from <b>Protect → Live theatre</b>; each real attack's measured outcome, uptime impact and cost land here.</div>
        <AttackResultsPanel lens={lens} />
      </CardContent></Card>

      {/* Post-attack reports — updates live as Attack Lab runs finish (date + real metrics). */}
      <RunHistoryPanel lens={lens} />

      <Card><CardContent className="p-5">
        <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold"><FileText className="h-4 w-4 text-primary" /> Executive summary</div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {posture && <Tile label="Posture grade (K8s)" value={posture.grade} />}
          {real.filter(s => ["disruption", "work-preserved", "prevention"].includes(s.key)).map((s) => <Tile key={s.key} label={s.label} value={`${s.value}${s.unit === "%" ? "%" : ""}`} />)}
        </div>
      </CardContent></Card>

      <Card><CardContent className="p-5">
        <div className="mb-3 text-[11px] uppercase tracking-wider text-muted-foreground">Evidence ledger · {stats.length} metrics</div>
        <div className="space-y-1.5">
          {stats.map((s) => (
            <div key={s.key} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border/40 pb-1.5 text-[12px]">
              <span className="w-52 shrink-0 text-foreground">{s.label}</span>
              <span className="tabular font-medium">{s.value}{s.unit === "%" ? "%" : s.unit ? " " + s.unit : ""}</span>
              {s.ci?.n ? <span className="tabular text-muted-foreground">95% CI [{s.unit === "%" ? `${(s.ci.lo * 100).toFixed(0)},${(s.ci.hi * 100).toFixed(0)}` : `${s.ci.lo.toFixed(1)},${s.ci.hi.toFixed(1)}`}] n={s.ci.n}</span> : null}
              <Badge variant={s.status === "real" ? "real" : s.status === "modeled" ? "modeled" : "pending"}>{s.status === "pending" ? "SP-0-PENDING-P4" : s.status}</Badge>
              <span className="ml-auto truncate font-mono text-[10px] text-muted-foreground/60">{s.source}</span>
            </div>
          ))}
        </div>
      </CardContent></Card>

      <div><div className="mb-3 mt-2 text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground/80">Curated reports · served live from disk</div><ReportsPanel lens={lens} /></div>

      <div><div className="mb-3 mt-2 text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground/80">Methodology &amp; honesty</div><MethodologyPanel lens={lens} /></div>
    </div>
  );
}

function Tile({ label, value }: { label: string; value: string }) {
  return <Card><CardContent className="p-4"><div className="text-2xl font-semibold tabular tracking-tight">{value}</div><div className="mt-1 text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div></CardContent></Card>;
}
