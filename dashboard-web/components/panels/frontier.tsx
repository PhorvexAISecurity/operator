"use client";
import * as React from "react";
import { api, Lens, FrontierRow } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, SectionLabel, Skeleton, ErrorState } from "./effectiveness";
import { cn } from "@/lib/utils";

function pct(c: { mean: number; lo: number; hi: number }) {
  return `${(c.mean * 100).toFixed(0)}% [${(c.lo * 100).toFixed(0)},${(c.hi * 100).toFixed(0)}]`;
}
function WinBadge({ win }: { win: string }) {
  if (win === "WIN") return <Badge variant="accent">★ WIN</Badge>;
  if (win.startsWith("no")) return <Badge variant="danger">{win}</Badge>;
  return <Badge variant="neutral">{win}</Badge>;
}

export function FrontierPanel({ lens }: { lens: Lens }) {
  const [rows, setRows] = React.useState<FrontierRow[] | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => {
    api.frontier(lens).then((d) => setRows(d.rows)).catch((e) => setErr(String(e.message || e)));
  }, [lens]);
  if (err) return <ErrorState msg={err} />;
  if (!rows) return <Skeleton rows={4} />;

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead
        title="Structural Zero-Day Frontier"
        sub="The decisive certificate (P3-DEEP): on the constrained class, NO blind interval is a clean win — fast intervals prevent but destroy the workload; slow intervals are too late. Phorvex is the unique WIN. The clean blind win on the unconstrained case is reported honestly elsewhere."
      />
      <Card>
        <CardContent className="p-0">
          <div className="border-b border-border px-5 py-3 text-[11px] uppercase tracking-wider text-muted-foreground">
            constrained class · stateful workload · out-p3deep/metrics.jsonl (792 rows, seed 1337)
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
                      <td className="px-5 py-3 font-medium">{px ? "Phorvex" : r.arm === "d-nomtd" ? "No MTD" : r.arm.replace("d-r6blindtimer", "R6 blind").replace("d-blind-", "Blind ")}</td>
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
      <SectionLabel>Reading</SectionLabel>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-sm">
        {[
          ["Fast blind (3–15s)", "Prevents — but harm 100% + infeasible 100%. It destroys the stateful workload at any fast rate.", "text-danger"],
          ["Slow blind (30–60s)", "Harm-free — but prevention 0%. Too late: the attacker reaches the objective first.", "text-warning"],
          ["Phorvex (solved rate)", "100% prevent, 0% harm, 0% infeasible — the unique WIN, targeted + harm-free via quarantine.", "text-success"],
        ].map(([t, d, c]) => (
          <Card key={t}><CardContent className="p-4">
            <div className={cn("text-[13px] font-semibold", c)}>{t}</div>
            <div className="mt-1.5 text-[12px] leading-relaxed text-muted-foreground">{d}</div>
          </CardContent></Card>
        ))}
      </div>
    </div>
  );
}
