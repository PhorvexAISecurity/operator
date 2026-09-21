"use client";
import { api, Lens, BenchGroup } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Table, THead, TH, TR, TD, Loading, ReadStatus, csvDownload } from "@/components/ui/more";
import { PageHead } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Download } from "lucide-react";
import { useApiRead } from "@/lib/query";

const armLabel = (d: string) => d === "d-phorvex" ? "Phorvex" : d === "d-nomtd" ? "No MTD" : d.replace("d-r6blindtimer", "Without Phorvex (blind 15s)").replace("d-blind-", "Blind ");
const fmtPct = (c: any) => c && c.n ? `${(c.mean * 100).toFixed(0)}% [${(c.lo * 100).toFixed(0)},${(c.hi * 100).toFixed(0)}]` : "—";
const fmtS = (c: any) => c && c.n ? `${c.mean.toFixed(1)}s [${c.lo.toFixed(1)},${c.hi.toFixed(1)}]` : "—";

export function BenchmarksPanel({ lens }: { lens: Lens }) {
  const read = useApiRead({ lens, resource: "benchmarks", fetcher: (signal) => api.benchmarks(lens, signal), staleTime: 60_000 });
  const groups = read.data ? (read.data.groups ?? []) : undefined;
  if (!groups) return read.error ? <ReadStatus error={read.error} hasData={false} onRetry={() => void read.refetch()} /> : <Loading label="Aggregating the benchmark corpus…" />;

  function exportCSV() {
    if (!groups) return;
    const rows: (string | number)[][] = [["scenario", "arm", "disruption", "dwell_s", "harm_rate", "trials", "source"]];
    groups.forEach((g) => g.arms.forEach((a) => rows.push([g.scenario, a.defender, fmtPct(a.disruption), fmtS(a.dwell), fmtPct(a.harmRate), a.trials, g.source])));
    csvDownload("phorvex-benchmarks.csv", rows);
  }

  return (
    <div className="animate-fade-up space-y-6">
      <ReadStatus error={read.error} hasData updatedAt={read.dataUpdatedAt} refreshing={read.isFetching} onRetry={() => void read.refetch()} />
      <div className="flex items-start justify-between gap-4">
        <PageHead title="Benchmarks & Evidence" sub="The decisive scenarios across the real metrics corpus — disruption, dwell-to-eviction, and harm, every value with a 95% CI, each row sourced to its metrics file." />
        <Button variant="outline" size="sm" onClick={exportCSV}><Download className="h-3.5 w-3.5" /> Export CSV</Button>
      </div>
      {groups.map((g) => (
        <Card key={g.scenario + g.source}>
          <CardContent className="p-0">
            <div className="flex items-center justify-between border-b border-border px-5 py-3">
              <span className="font-mono text-[13px] text-foreground">{g.scenario}</span>
              <span className="text-[11px] text-muted-foreground">{g.source}</span>
            </div>
            <Table>
              <THead><TH>Arm</TH><TH>Disruption</TH><TH>Dwell-to-eviction</TH><TH>Harm</TH><TH>n</TH></THead>
              <tbody>
                {(g.arms ?? []).map((a) => {
                  const px = a.defender === "d-phorvex";
                  return (
                    <TR key={a.defender} className={cn(px && "bg-primary/[0.04]")}>
                      <TD className="font-medium">{armLabel(a.defender)} {px && <Badge variant="accent">PX</Badge>}</TD>
                      <TD className="tabular">{fmtPct(a.disruption)}</TD>
                      <TD className="tabular">{fmtS(a.dwell)}</TD>
                      <TD className={cn("tabular", a.harmRate.mean > 0 ? "text-danger" : "text-success")}>{fmtPct(a.harmRate)}</TD>
                      <TD className="tabular text-muted-foreground">{a.trials}</TD>
                    </TR>
                  );
                })}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
