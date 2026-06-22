"use client";
import * as React from "react";
import { api, Lens, liveStream } from "@/lib/api";
import { useOwnerTenant } from "@/lib/owner";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { PageHead, SectionLabel } from "./effectiveness";
import { Pending } from "@/components/ui/more";
import { cn } from "@/lib/utils";
import { Radio, Activity, Lock, Trash2, ChevronDown, ShieldCheck, ShieldOff, Search, ChevronLeft, ChevronRight, ListFilter } from "lucide-react";

const PAGE_SIZE = 15;       // decisions per page
const BUFFER_CAP = 400;     // how many recent decisions we keep client-side for paging/filtering

// format the decision timestamp as a readable local date + time.
function fmtTime(t?: string): { date: string; time: string } {
  if (!t) return { date: "", time: "" };
  const d = new Date(t);
  if (isNaN(d.getTime())) return { date: "", time: "" };
  return {
    date: d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" }),
    time: d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  };
}

export function LiveOpsPanel({ lens }: { lens: Lens }) {
  const [events, setEvents] = React.useState<any[]>([]);
  const [connected, setConnected] = React.useState(false);
  const [clearing, setClearing] = React.useState(false);
  const [reloadKey, setReloadKey] = React.useState(0);
  const [actionFilter, setActionFilter] = React.useState("");  // "" = all actuator types
  const [query, setQuery] = React.useState("");                // pod / namespace text search
  const [page, setPage] = React.useState(0);                   // 0-indexed page (0 = newest/live)
  const owner = lens === "owner";
  const { tenant, tenants, setTenant } = useOwnerTenant(lens);

  React.useEffect(() => {
    // owner stream is tenant-scoped: wait for a tenant before opening the SSE.
    if (owner && !tenant) { setEvents([]); setConnected(false); return; }
    setEvents([]); setConnected(true);
    // tail=80: the server replays only the last 80 decisions on connect (no "fast train" flood
    // after hours of running), then tails live; we keep up to BUFFER_CAP client-side for paging.
    const stop = liveStream(lens, (data) => setEvents((prev) => [data, ...prev].slice(0, BUFFER_CAP)), owner ? tenant : undefined, 80);
    return () => { stop(); setConnected(false); };
  }, [lens, owner, tenant, reloadKey]);

  // clear the persisted decision audit, then reconnect the SSE so the server restarts fresh.
  async function clearDecisions() {
    setClearing(true);
    try { await api.clearLive(lens); } catch { /* ignore — best-effort */ }
    setEvents([]); setPage(0);
    setReloadKey((k) => k + 1); // forces the SSE to close + reopen with a fresh offset
    setClearing(false);
  }

  const actuated = events.filter((e) => e.actuated || e.Actuated).length;
  // distinct actuator types present in the buffer (for the filter dropdown).
  const actions = React.useMemo(() => {
    const s = new Set<string>();
    for (const e of events) if (e.action) s.add(e.action);
    return Array.from(s).sort();
  }, [events]);

  // filter by actuator type + free-text (pod / namespace / tenant).
  const q = query.trim().toLowerCase();
  const filtered = React.useMemo(() => events.filter((e) => {
    if (actionFilter && e.action !== actionFilter) return false;
    if (q && !`${e.namespace || ""}/${e.pod || ""} ${e.tenant || ""}`.toLowerCase().includes(q)) return false;
    return true;
  }), [events, actionFilter, q]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageSafe = Math.min(page, pageCount - 1);
  const pageEvents = filtered.slice(pageSafe * PAGE_SIZE, pageSafe * PAGE_SIZE + PAGE_SIZE);
  // reset to the first (live) page whenever the filter/search/lens changes.
  React.useEffect(() => { setPage(0); }, [actionFilter, query, lens, tenant]);

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title="Live Operations" sub="Phorvex deciding in real time — streamed from the decision audit. Investor/Operator see the full per-decision internals; the Customer-Owner stream is projected through the IP-wall (outcome only). Click any decision to see its date + full reasoning. Filter by actuator, search by pod, and page through the history." />
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 rounded-md border border-border bg-panel/60 px-3 py-1.5 text-[12px]">
          <Radio className={cn("h-3.5 w-3.5", connected ? "animate-pulse-soft text-success" : "text-muted-foreground")} />
          <span className={connected ? "text-foreground" : "text-muted-foreground"}>{connected ? "Streaming /api/live (SSE)" : "Disconnected"}</span>
        </div>
        <div className="text-[12px] text-muted-foreground">{events.length} buffered · {actuated} actuated</div>
        {owner && tenants.length > 0 && (
          <label className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            platform:
            <select value={tenant} onChange={(e) => setTenant(e.target.value)} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[11px] text-foreground">
              {tenants.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
        )}
        {owner && <div className="flex items-center gap-1.5 text-[11px] text-primary"><Lock className="h-3 w-3" /> IP-walled stream (outcome only)</div>}
        {!owner && (
          <Button variant="outline" size="sm" onClick={clearDecisions} disabled={clearing || events.length === 0} className="ml-auto gap-1.5">
            <Trash2 className="h-3.5 w-3.5" /> {clearing ? "Clearing…" : "Clear decisions"}
          </Button>
        )}
      </div>

      {/* FILTER BAR — by actuator type + free-text pod/namespace search */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 rounded-md border border-border bg-panel/60 px-2 py-1.5 text-[12px]">
          <ListFilter className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">actuator</span>
          <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[12px] text-foreground">
            <option value="">all</option>
            {actions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
        <div className="flex items-center gap-1.5 rounded-md border border-border bg-panel/60 px-2 py-1.5">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="search pod / namespace / tenant…"
            className="w-56 bg-transparent text-[12px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none" />
          {query && <button onClick={() => setQuery("")} className="text-[11px] text-muted-foreground hover:text-foreground">clear</button>}
        </div>
        {/* quick actuator chips */}
        <div className="flex flex-wrap items-center gap-1">
          {actions.slice(0, 6).map((a) => (
            <button key={a} onClick={() => setActionFilter(actionFilter === a ? "" : a)}
              className={cn("rounded-full border px-2 py-0.5 font-mono text-[11px] transition-colors",
                actionFilter === a ? "border-primary/50 bg-primary/[0.08] text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
              {a}
            </button>
          ))}
        </div>
        <div className="ml-auto text-[12px] text-muted-foreground">{filtered.length} match{filtered.length === 1 ? "" : "es"}</div>
      </div>

      {events.length === 0 ? (
        <Card><CardContent className="flex flex-col items-center gap-3 py-12 text-center text-sm text-muted-foreground">
          <Activity className="h-5 w-5 animate-pulse-soft" />
          No live decisions yet. Start the Phorvex operator with <span className="font-mono text-foreground/80">--audit-json</span> and apply a <span className="font-mono text-foreground/80">PhorvexPolicy</span> selecting some pods — decisions appear here as they happen.
          <Pending stage="REAL-NOW" msg="The stream is connected; it replays the latest 80 decisions + tails new ones." />
        </CardContent></Card>
      ) : filtered.length === 0 ? (
        <Card><CardContent className="py-10 text-center text-[13px] text-muted-foreground">No decisions match the current filter. <button onClick={() => { setActionFilter(""); setQuery(""); }} className="text-primary hover:underline">reset</button></CardContent></Card>
      ) : (
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <SectionLabel>Decision stream {owner ? "(owner projection)" : "(full internals)"}{pageSafe === 0 ? <span className="ml-2 inline-flex items-center gap-1 text-[10px] font-normal text-success"><span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" /> live</span> : <span className="ml-2 text-[10px] font-normal text-muted-foreground">history · page {pageSafe + 1}</span>}</SectionLabel>
            <Pagination page={pageSafe} pageCount={pageCount} onPage={setPage} />
          </div>
          <div className="space-y-2">
            {pageEvents.map((e, i) => owner ? <OwnerCard key={`${pageSafe}-${i}`} e={e} /> : <DecisionCard key={`${pageSafe}-${i}`} e={e} />)}
          </div>
          {pageCount > 1 && (
            <div className="flex justify-center pt-1"><Pagination page={pageSafe} pageCount={pageCount} onPage={setPage} /></div>
          )}
        </section>
      )}
    </div>
  );
}

// Pagination — Prev / page-of / Next. Page 0 is the newest (live) page.
function Pagination({ page, pageCount, onPage }: { page: number; pageCount: number; onPage: (p: number) => void }) {
  return (
    <div className="flex items-center gap-1.5 text-[12px]">
      <Button variant="outline" size="sm" className="h-7 px-2" disabled={page <= 0} onClick={() => onPage(Math.max(0, page - 1))} aria-label="newer">
        <ChevronLeft className="h-3.5 w-3.5" />
      </Button>
      <span className="tabular text-muted-foreground">{page + 1} / {pageCount}</span>
      <Button variant="outline" size="sm" className="h-7 px-2" disabled={page >= pageCount - 1} onClick={() => onPage(Math.min(pageCount - 1, page + 1))} aria-label="older">
        <ChevronRight className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

// CostCompare contrasts what Phorvex pays for THIS decision against what the blind timer (R6)
// would pay. Phorvex acts only when net-positive (cost 0 when it skips); the blind timer rotates
// every cycle regardless of value, so it always pays the rotate cost. Numbers are unit-less
// cost (no currency symbol) — same scale as the decision ledger.
function CostCompare({ e }: { e: any }) {
  const phorvexCost = typeof e.cost === "number" ? e.cost : null;
  const blindCost = typeof e.blindCost === "number" ? e.blindCost : null;
  if (phorvexCost === null && blindCost === null) return null;
  const acted = e.selected || e.actuated;
  const savings = phorvexCost !== null && blindCost !== null ? blindCost - phorvexCost : null;
  const f = (n: number | null) => (n === null ? "—" : n.toFixed(4));
  return (
    <div>
      <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">Cost · Phorvex vs blind timer</div>
      <div className="grid grid-cols-2 gap-2">
        {/* Phorvex — value-targeted */}
        <div className="rounded-md border border-primary/30 bg-primary/[0.05] p-2.5">
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-primary"><ShieldCheck className="h-3.5 w-3.5" /> Phorvex</div>
          <div className="mt-1 font-mono text-[12px] text-foreground/90">{e.action || "noop"}</div>
          <div className="mt-1 text-[18px] font-semibold tabular text-foreground">{f(phorvexCost)}</div>
          <div className="text-[10px] text-muted-foreground">
            {acted ? <>acts only when net-positive{typeof e.net === "number" ? <> · net +{e.net.toFixed(2)}</> : null}</> : "skipped — not worth the disruption this cycle"}
          </div>
        </div>
        {/* Blind timer — fixed cadence, no value targeting */}
        <div className="rounded-md border border-warning/30 bg-warning/[0.05] p-2.5">
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-warning"><ShieldOff className="h-3.5 w-3.5" /> Blind timer (R6)</div>
          <div className="mt-1 font-mono text-[12px] text-foreground/90">rotate</div>
          <div className="mt-1 text-[18px] font-semibold tabular text-foreground">{f(blindCost)}</div>
          <div className="text-[10px] text-muted-foreground">rotates every cycle regardless of value</div>
        </div>
      </div>
      {savings !== null && (
        <div className={cn("mt-1.5 rounded-md border px-2.5 py-1.5 text-[11px]",
          savings > 0.0001 ? "border-success/30 bg-success/[0.05] text-success" : "border-border bg-elevated/30 text-muted-foreground")}>
          {savings > 0.0001
            ? <>This cycle Phorvex paid <span className="font-mono">{f(phorvexCost)}</span> vs the blind timer’s <span className="font-mono">{f(blindCost)}</span> — <span className="font-medium">saved {savings.toFixed(4)}</span> by not blindly rotating.</>
            : <>Both act this cycle (cost <span className="font-mono">{f(phorvexCost)}</span> vs <span className="font-mono">{f(blindCost)}</span>) — but Phorvex’s is value-justified{typeof e.net === "number" ? <> (net +{e.net.toFixed(2)})</> : null}, the blind timer’s is not.</>}
        </div>
      )}
    </div>
  );
}

// a labeled metric cell in the expanded detail grid.
function Metric({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-md border border-border/60 bg-elevated/30 p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="tabular text-[13px] text-foreground">{value}</div>
      {hint && <div className="text-[10px] text-muted-foreground/70">{hint}</div>}
    </div>
  );
}

function DecisionCard({ e }: { e: any }) {
  const [open, setOpen] = React.useState(false);
  const acted = e.actuated, sel = e.selected;
  const { date, time } = fmtTime(e.time || e.Time);
  const num = (v: any, d = 2) => (typeof v === "number" ? v.toFixed(d) : null);

  return (
    <Card className={cn("transition-colors", acted && "border-primary/20 bg-primary/[0.03]")}>
      <button onClick={() => setOpen((o) => !o)} className="w-full text-left">
        <CardContent className="flex flex-wrap items-center gap-x-4 gap-y-1.5 p-3 text-[12px]">
          <ChevronDown className={cn("h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
          <span className="font-mono text-[13px] text-foreground">{e.namespace}/{e.pod}</span>
          <Badge variant={e.action === "noop" ? "neutral" : "accent"}>{e.action}</Badge>
          {sel && <Badge variant="real">selected</Badge>}
          {acted && <Badge variant="accent">actuated{e.handler ? ` · ${e.handler}` : ""}</Badge>}
          {e.dryRun && !acted && <Badge variant="pending">dry-run</Badge>}
          {e.stage && <span className="text-muted-foreground">stage <span className="text-foreground/80">{e.stage}</span></span>}
          {e.aiClassified && <Badge variant="modeled">AI</Badge>}
          {time && <span className="text-[11px] text-muted-foreground/70">{time}</span>}
          <span className="ml-auto flex items-center gap-3 tabular text-muted-foreground">
            {typeof e.risk === "number" && <span>risk {e.risk.toFixed(2)}</span>}
            {typeof e.lambda === "number" && e.lambda > 0 && <span>λ {e.lambda.toFixed(2)}</span>}
            {typeof e.perDollar === "number" && e.perDollar > 0 && <span>per-$ {e.perDollar.toFixed(2)}</span>}
            {typeof e.preemptMargin === "number" && e.preemptMargin > 0 && <span className="text-primary">preempt {(e.preemptMargin * 100).toFixed(0)}%</span>}
          </span>
        </CardContent>
      </button>

      {open && (
        <CardContent className="space-y-3 border-t border-border/50 p-3 pt-3 text-[12px]">
          {(date || time) && (
            <div className="text-[11px] text-muted-foreground">Decided <span className="text-foreground/80">{date}</span> at <span className="text-foreground/80">{time}</span>{e.node ? <> · node <span className="font-mono text-foreground/70">{e.node}</span></> : null}{e.engine ? <> · brain <span className="font-mono text-foreground/70">{e.engine}</span></> : null}</div>
          )}

          {/* WHY — the human-readable reason for this action */}
          {e.reason && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">Why this action</div>
              <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5 leading-relaxed text-foreground/90">{e.reason}</div>
            </div>
          )}

          {/* COST: Phorvex (value-targeted) vs the blind timer (fixed cadence) — the core $ story */}
          <CostCompare e={e} />

          {/* R6 counterfactual — what a static rule engine would (not) have done */}
          {(e.r6Counterfactual || e.counterfactualNote) && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">vs. Without Phorvex (R6 counterfactual)</div>
              <div className="rounded-md border border-warning/25 bg-warning/[0.05] p-2.5 leading-relaxed text-muted-foreground">
                {e.r6Counterfactual && <>Without Phorvex would: <span className="font-mono text-foreground/80">{e.r6Counterfactual}</span>. </>}
                {e.counterfactualNote}
              </div>
            </div>
          )}

          {/* coverage attribution — what each covered fact contributed to the score */}
          {Array.isArray(e.attribution) && e.attribution.length > 0 && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">Score attribution</div>
              <div className="space-y-1">
                {e.attribution.map((a: any, j: number) => (
                  <div key={j} className="flex items-center justify-between gap-2 rounded border border-border/40 px-2 py-1">
                    <span className="font-mono text-[11px] text-foreground/80">{a.source}</span>
                    <span className={cn("tabular text-[12px]", a.contribution < 0 ? "text-danger" : "text-success")}>{a.contribution > 0 ? "+" : ""}{num(a.contribution)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* full metrics ledger */}
          <div>
            <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">Decision ledger</div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
              {num(e.risk) != null && <Metric label="risk" value={num(e.risk)} />}
              {num(e.cost) != null && <Metric label="cost" value={num(e.cost, 4)} />}
              {num(e.net) != null && <Metric label="net value" value={num(e.net)} />}
              {num(e.perDollar) != null && e.perDollar > 0 && <Metric label="per-$ coverage" value={num(e.perDollar)} />}
              {typeof e.coveredFacts === "number" && e.coveredFacts > 0 && <Metric label="covered facts" value={e.coveredFacts} />}
              {num(e.coveredWeight) != null && e.coveredWeight > 0 && <Metric label="covered weight" value={num(e.coveredWeight)} />}
              {num(e.belief) != null && <Metric label="belief" value={num(e.belief)} />}
              {num(e.assetValue) != null && <Metric label="asset value" value={num(e.assetValue)} />}
              {num(e.blastRadius) != null && <Metric label="blast radius" value={num(e.blastRadius)} />}
              {num(e.sloHeadroom) != null && <Metric label="SLO headroom" value={num(e.sloHeadroom)} />}
              {num(e.exposure) != null && <Metric label="exposure" value={num(e.exposure)} />}
              {num(e.threatPosture) != null && <Metric label="threat posture" value={num(e.threatPosture)} />}
              {num(e.lambda) != null && e.lambda > 0 && <Metric label="λ (cost weight)" value={num(e.lambda)} />}
              {num(e.pHold) != null && e.pHold > 0 && <Metric label="p(hold)" value={num(e.pHold)} />}
              {e.phase && <Metric label="phase" value={e.phase} />}
              {e.stage && <Metric label="kill-chain" value={`${e.stage}${e.nextStage ? ` → ${e.nextStage}` : ""}`} />}
            </div>
          </div>

          {!e.feasible && e.infeasibleWhy && (
            <div className="rounded-md border border-danger/25 bg-danger/[0.05] p-2 text-[11px] text-danger">Infeasible: {e.infeasibleWhy}</div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

function OwnerCard({ e }: { e: any }) {
  const [open, setOpen] = React.useState(false);
  const { date, time } = fmtTime(e.time || e.Time);
  return (
    <Card>
      <button onClick={() => setOpen((o) => !o)} className="w-full text-left">
        <CardContent className="flex flex-wrap items-center gap-x-4 gap-y-1.5 p-3 text-[12px]">
          <ChevronDown className={cn("h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
          <span className="font-mono text-[13px] text-foreground">{e.namespace}/{e.pod}</span>
          <Badge variant="accent">{e.action}</Badge>
          {e.reversible && <Badge variant="real">reversible</Badge>}
          <span className="text-muted-foreground">{e.attackStage}</span>
          {time && <span className="text-[11px] text-muted-foreground/70">{time}</span>}
          <span className="ml-auto max-w-md truncate text-foreground/80">{e.why}</span>
        </CardContent>
      </button>
      {open && (
        <CardContent className="space-y-2 border-t border-border/50 p-3 pt-3 text-[12px]">
          {(date || time) && <div className="text-[11px] text-muted-foreground">Decided <span className="text-foreground/80">{date}</span> at <span className="text-foreground/80">{time}</span></div>}
          {e.why && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">Why this action</div>
              <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5 leading-relaxed text-foreground/90">{e.why}</div>
            </div>
          )}
          {e.attackStage && <div className="text-[11px] text-muted-foreground">Attack stage: <span className="text-foreground/80">{e.attackStage}</span></div>}
        </CardContent>
      )}
    </Card>
  );
}
