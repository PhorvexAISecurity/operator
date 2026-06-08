"use client";
import * as React from "react";
import { api, Lens, Stat, Posture, BenchGroup } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Loading, Pending, csvDownload } from "@/components/ui/more";
import { StepHead } from "./shared";
import { MethodologyPanel } from "@/components/subsystems/panels";
import { FileText, Download, Printer } from "lucide-react";

export function ReportStep({ lens }: { lens: Lens }) {
  const [stats, setStats] = React.useState<Stat[]>([]);
  const [posture, setPosture] = React.useState<Posture | null>(null);
  const [bench, setBench] = React.useState<BenchGroup[]>([]);
  const [loading, setLoading] = React.useState(true);
  React.useEffect(() => {
    Promise.allSettled([api.effectiveness(lens), api.posture(lens), api.benchmarks(lens)]).then(([e, p, b]) => {
      if (e.status === "fulfilled") setStats(e.value.stats);
      if (p.status === "fulfilled") setPosture(p.value);
      if (b.status === "fulfilled") setBench(b.value.groups);
      setLoading(false);
    });
  }, [lens]);
  if (loading) return <Loading label="Assembling the evidence pack…" rows={3} />;

  const real = stats.filter((s) => s.status === "real");
  function exportCSV() {
    const rows: (string | number)[][] = [["metric", "value", "unit", "ci_low", "ci_high", "n", "status", "source"]];
    stats.forEach((s) => rows.push([s.label, s.value, s.unit || "", s.ci?.lo ?? "", s.ci?.hi ?? "", s.ci?.n ?? "", s.status, s.source]));
    csvDownload("phorvex-evidence.csv", rows);
  }

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={6} title="Report" sub="Generate the evidence pack — every metric with its 95% CI and its source file. Honest about what's proven (K8s) and what's pending (AI/GPU)." lens={lens} />
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={exportCSV}><Download className="h-4 w-4" /> Export evidence CSV</Button>
        <Button variant="outline" onClick={() => window.print()}><Printer className="h-4 w-4" /> Print / Save PDF</Button>
        <Pending stage="PENDING-wire · Phase 3" msg="A bundled PDF + a reports index (/api/reports over the on-disk *.md) are the Phase-3 wire. CSV + browser print are real now." />
      </div>

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

      <div><div className="mb-3 mt-2 text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground/80">Methodology &amp; honesty</div><MethodologyPanel lens={lens} /></div>
    </div>
  );
}

function Tile({ label, value }: { label: string; value: string }) {
  return <Card><CardContent className="p-4"><div className="text-2xl font-semibold tabular tracking-tight">{value}</div><div className="mt-1 text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div></CardContent></Card>;
}
