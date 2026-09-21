"use client";
import { api, Lens, FrontierRow } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, SectionLabel, Skeleton } from "./effectiveness";
import { ReadStatus } from "@/components/ui/more";
import { cn } from "@/lib/utils";
import { useApiRead } from "@/lib/query";

function pct(c: { mean: number; lo: number; hi: number }) {
  return `${(c.mean * 100).toFixed(0)}% [${(c.lo * 100).toFixed(0)},${(c.hi * 100).toFixed(0)}]`;
}
function WinBadge({ win }: { win: string }) {
  if (win === "WIN") return <Badge variant="accent">★ WIN</Badge>;
  if (win.startsWith("no")) return <Badge variant="danger">{win}</Badge>;
  return <Badge variant="neutral">{win}</Badge>;
}

// readingCards derives the narrative from the LIVE rows (not hardcoded "100%/0%/0%"): the most
// harmful blind arm, the too-late (low-prevention) blind arm, and the Phorvex row — all real.
function readingCards(rows: FrontierRow[]): [string, string, string][] {
  const px = rows.find((r) => r.arm === "d-phorvex");
  const blinds = rows.filter((r) => r.arm !== "d-phorvex" && r.arm !== "d-nomtd");
  const harmful = [...blinds].filter((r) => r.harm.mean > 0 || r.infeasible.mean > 0).sort((a, b) => b.harm.mean - a.harm.mean)[0];
  const tooLate = [...blinds].filter((r) => r.prevention.mean < 0.5).sort((a, b) => a.prevention.mean - b.prevention.mean)[0];
  const out: [string, string, string][] = [];
  if (harmful) out.push([`Fast blind (${harmful.interval})`, `Prevents ${pct(harmful.prevention)} — but harm ${pct(harmful.harm)} + infeasible ${pct(harmful.infeasible)}. It destroys the stateful workload.`, "text-danger"]);
  if (tooLate && tooLate !== harmful) out.push([`Slow blind (${tooLate.interval})`, `Harm ${pct(tooLate.harm)} — but prevention ${pct(tooLate.prevention)}. Too late: the attacker reaches the objective first.`, "text-warning"]);
  if (px) out.push([`Phorvex (${px.interval})`, `${pct(px.prevention)} prevent, ${pct(px.harm)} harm, ${pct(px.infeasible)} infeasible — ${px.win === "WIN" ? "the unique WIN" : px.win}, targeted + harm-free via quarantine.`, "text-success"]);
  return out;
}

export function FrontierPanel({ lens }: { lens: Lens }) {
  const read = useApiRead({ lens, resource: "frontier", fetcher: (signal) => api.frontier(lens, signal), staleTime: 60_000 });
  const rows = read.data ? (read.data.rows ?? []) : undefined;
  if (!rows) return read.error ? <ReadStatus error={read.error} hasData={false} onRetry={() => void read.refetch()} /> : <Skeleton rows={4} />;

  return (
    <div className="animate-fade-up space-y-6">
      <ReadStatus error={read.error} hasData updatedAt={read.dataUpdatedAt} refreshing={read.isFetching} onRetry={() => void read.refetch()} />
      <PageHead
        title="Structural Zero-Day Frontier"
        sub="The decisive certificate (P3-DEEP): on the constrained class, NO blind interval is a clean win — fast intervals prevent but destroy the workload; slow intervals are too late. Phorvex is the unique WIN. The clean blind win on the unconstrained case is reported honestly elsewhere."
      />
      <Card>
        <CardContent className="p-0">
          <div className="border-b border-border px-5 py-3 text-[11px] uppercase tracking-wider text-muted-foreground">
            constrained class · stateful workload · source: out-p3deep/metrics.jsonl · {rows.length} arms · seed 1337
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-5 py-3 font-medium">Arm</th>
                  <th className="px-5 py-3 font-medium">Interval</th>
                  <th className="px-5 py-3 font-medium">Prevention</th>
                  <th className="px-5 py-3 font-medium">Harm</th>
                  <th className="px-5 py-3 font-medium">Infeasible</th>
                  <th className="px-5 py-3 font-medium">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const px = r.arm === "d-phorvex";
                  return (
                    <tr key={r.arm} className={cn("border-b border-border/50 transition-colors hover:bg-elevated/40", px && "bg-primary/[0.04]")}>
                      <td className="px-5 py-3 font-medium">{px ? "Phorvex" : r.arm === "d-nomtd" ? "No MTD" : r.arm.replace("d-r6blindtimer", "Without Phorvex (blind)").replace("d-blind-", "Blind ")}</td>
                      <td className="px-5 py-3 font-mono text-[13px] text-muted-foreground">{r.interval}</td>
                      <td className="px-5 py-3 tabular">{pct(r.prevention)}</td>
                      <td className={cn("px-5 py-3 tabular", r.harm.mean > 0 ? "text-danger" : "text-success")}>{pct(r.harm)}</td>
                      <td className={cn("px-5 py-3 tabular", r.infeasible.mean > 0 ? "text-danger" : "text-success")}>{pct(r.infeasible)}</td>
                      <td className="px-5 py-3"><WinBadge win={r.win} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
      <SectionLabel>Reading · computed from the rows above</SectionLabel>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-sm">
        {readingCards(rows).map(([t, d, c]) => (
          <Card key={t}><CardContent className="p-4">
            <div className={cn("text-[13px] font-semibold", c)}>{t}</div>
            <div className="mt-1.5 text-[12px] leading-relaxed text-muted-foreground">{d}</div>
          </CardContent></Card>
        ))}
      </div>
    </div>
  );
}
