"use client";
import * as React from "react";
import { api, Lens, ReportMeta } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, Skeleton, ErrorState } from "./effectiveness";
import { Loading, ErrorBox, Empty } from "@/components/ui/more";
import { FileText, Check, Download } from "lucide-react";
import { cn } from "@/lib/utils";
import { useReport, useReports } from "@/lib/query";

// ReportsPanel lists the curated on-disk evidence reports (/api/reports) and renders the SELECTED
// one's live markdown — dynamic from disk, never hardcoded. Optional `only` filters to one group
// (e.g. "Comparison" for the vs-R6 view).
export function ReportsPanel({ lens, only, intro }: { lens: Lens; only?: string; intro?: string }) {
  const [sel, setSel] = React.useState<string>("");
  const reportsQuery = useReports(lens);
  const list = React.useMemo(() => (reportsQuery.data?.reports || []).filter((r) => r.exists && (!only || r.group === only)), [only, reportsQuery.data]);
  React.useEffect(() => { setSel((current) => list.some((r) => r.id === current) ? current : list[0]?.id || ""); }, [list]);
  const reportQuery = useReport(sel, lens);
  const doc = reportQuery.data;
  if (reportsQuery.error) return <ErrorState msg={String((reportsQuery.error as Error).message || reportsQuery.error)} />;
  if (reportsQuery.isPending) return <Skeleton rows={3} />;
  if (list.length === 0) return <Empty msg="No curated reports found on disk. Run the benchmark suites (Prove) to generate them." />;

  const groups = Array.from(new Set(list.map((r) => r.group)));
  return (
    <div className="animate-fade-up space-y-5">
      {!only && <PageHead title="Evidence Reports" sub={intro || "The curated reports — served live from disk (COMPARISON, benchmarks, effectiveness, P3). Regenerate them by running the suites in Prove."} />}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[260px_1fr]">
        {/* index */}
        <div className="space-y-4">
          {groups.map((g) => (
            <div key={g}>
              <div className="mb-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">{g}</div>
              <div className="space-y-1">
                {list.filter((r) => r.group === g).map((r) => (
                  <button key={r.id} onClick={() => setSel(r.id)}
                    className={cn("flex w-full items-center justify-between gap-2 rounded-md border px-3 py-2 text-left text-[12px] transition-colors",
                      sel === r.id ? "border-primary/40 bg-primary/[0.06] text-foreground" : "border-border/60 text-muted-foreground hover:bg-elevated")}>
                    <span className="flex items-center gap-1.5"><FileText className="h-3.5 w-3.5 shrink-0" />{r.title}</span>
                    <span className="shrink-0 text-[10px] text-muted-foreground/60">{r.lines}L</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
        {/* document */}
        <Card><CardContent className="p-0">
          <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
            <span className="flex items-center gap-2 text-[13px] font-medium">{doc?.title || "…"} <Badge variant="real"><Check className="h-2.5 w-2.5" /> report file</Badge></span>
            {doc && <button onClick={() => downloadMd(doc.id, doc.content)} className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> .md</button>}
          </div>
          {reportQuery.dataUpdatedAt > 0 && <div className={cn("border-b border-border px-4 py-1.5 text-[11px]", reportQuery.error ? "text-warning" : "text-muted-foreground")}>
            Updated {new Date(reportQuery.dataUpdatedAt).toLocaleTimeString()}{reportQuery.isFetching ? " · refreshing…" : reportQuery.error ? " · refresh failed" : ""}
          </div>}
          <div className="max-h-[70vh] overflow-y-auto px-5 py-4">
            {reportQuery.error ? <ErrorState msg={String((reportQuery.error as Error).message || reportQuery.error)} /> : reportQuery.isPending || !doc ? <Loading label="Reading report…" rows={6} /> : <Markdown src={doc.content} />}
          </div>
        </CardContent></Card>
      </div>
    </div>
  );
}

function downloadMd(id: string, content: string) {
  const blob = new Blob([content], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = `${id}.md`; a.click(); URL.revokeObjectURL(a.href);
}

// Markdown — a minimal, dependency-free renderer for the report markdown: headings, tables,
// bold/code inline, lists, hr, paragraphs. (Reports lean on tables, which a <pre> would mangle.)
function Markdown({ src }: { src: string }) {
  const lines = src.replace(/\r/g, "").split("\n");
  const out: React.ReactNode[] = [];
  let i = 0, key = 0;
  const inline = (s: string) => {
    const parts: React.ReactNode[] = [];
    const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
    let last = 0, m: RegExpExecArray | null;
    while ((m = re.exec(s))) {
      if (m.index > last) parts.push(s.slice(last, m.index));
      const tok = m[0];
      if (tok.startsWith("**")) parts.push(<strong key={parts.length} className="text-foreground">{tok.slice(2, -2)}</strong>);
      else parts.push(<code key={parts.length} className="rounded bg-elevated px-1 py-0.5 font-mono text-[11px] text-primary">{tok.slice(1, -1)}</code>);
      last = m.index + tok.length;
    }
    if (last < s.length) parts.push(s.slice(last));
    return parts;
  };
  while (i < lines.length) {
    const ln = lines[i];
    if (/^\|(.+)\|\s*$/.test(ln) && i + 1 < lines.length && /^\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const header = ln.split("|").slice(1, -1).map((c) => c.trim());
      i += 2; const rows: string[][] = [];
      while (i < lines.length && /^\|(.+)\|\s*$/.test(lines[i])) { rows.push(lines[i].split("|").slice(1, -1).map((c) => c.trim())); i++; }
      out.push(
        <div key={key++} className="my-3 overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead><tr>{header.map((h, j) => <th key={j} className="border-b border-border px-2 py-1 text-left font-medium text-muted-foreground">{inline(h)}</th>)}</tr></thead>
            <tbody>{rows.map((r, ri) => <tr key={ri} className="border-b border-border/30">{r.map((c, ci) => <td key={ci} className="px-2 py-1 tabular">{inline(c)}</td>)}</tr>)}</tbody>
          </table>
        </div>);
      continue;
    }
    let m: RegExpMatchArray | null;
    if ((m = ln.match(/^(#{1,4})\s+(.*)/))) {
      const lvl = m[1].length;
      const cls = lvl === 1 ? "mt-4 text-[17px] font-semibold" : lvl === 2 ? "mt-4 text-[15px] font-semibold" : "mt-3 text-[13px] font-semibold text-foreground/90";
      out.push(<div key={key++} className={cls}>{inline(m[2])}</div>);
    } else if (/^[-*]\s+/.test(ln)) {
      out.push(<div key={key++} className="ml-3 flex gap-2 text-[13px] text-foreground/85"><span className="text-primary">•</span><span>{inline(ln.replace(/^[-*]\s+/, ""))}</span></div>);
    } else if (/^---+\s*$/.test(ln)) {
      out.push(<hr key={key++} className="my-3 border-border/50" />);
    } else if (ln.trim() === "") {
      out.push(<div key={key++} className="h-2" />);
    } else {
      out.push(<p key={key++} className="text-[13px] leading-relaxed text-foreground/85">{inline(ln)}</p>);
    }
    i++;
  }
  return <div className="space-y-0.5">{out}</div>;
}
