"use client";
import * as React from "react";
import { api, Lens, liveStream, RunStatus } from "@/lib/api";
import { AttackResultsPanel } from "@/components/panels/attack-report";
import { useOwnerTenant } from "@/lib/owner";
import { useSelectedTarget } from "@/lib/provider-store";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { PageHead, SectionLabel } from "./effectiveness";
import { Pending } from "@/components/ui/more";
import { cn } from "@/lib/utils";
import { Radio, Activity, Lock, Trash2, ChevronDown, ShieldCheck, ShieldOff, Search, ChevronLeft, ChevronRight, ListFilter, Swords, Loader2 } from "lucide-react";

// parseTs parses a UTC tsNow() string ("2026-06-28 14:30:00 UTC") to epoch ms.
function parseTs(s?: string): number {
  if (!s) return NaN;
  const p = s.split(" ");
  return p.length >= 2 ? Date.parse(`${p[0]}T${p[1]}Z`) : Date.parse(s);
}
// AttackWindow is one attack run's time span, for correlating decisions to the attack that ran then.
interface AttackWindow { id: string; scenario: string; start: number; end: number; running: boolean }

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

// ---- workload-aware LIVE attack: derive a workload's TYPE, then the attacks meaningful for it ----
type WlAttack = { id: string; label: string; actuator: string; runnable: boolean; note?: string };
function wlType(images: string[]): { type: string; label: string } {
  const img = (images || []).join(" ").toLowerCase();
  if (img.includes("vllm")) return { type: "model-server", label: "vLLM model server (real)" };
  if (img.includes("mysql") || img.includes("vitess")) return { type: "database", label: "MySQL database — stateful" };
  if (img.includes("litellm")) return { type: "llm-proxy", label: "LLM gateway / proxy" };
  if (img.includes("mock-rag") || img.includes("chatbot")) return { type: "gpu-inference", label: "GPU inference (mock RAG)" };
  if (img.includes("nats")) return { type: "message-broker", label: "NATS JetStream — stateful broker" };
  return { type: "generic", label: "Generic workload" };
}
// Each attack maps to the actuator Phorvex SHOULD pick for it. vLLM (real serving stack) fires the AI
// signals (kv-reset / adapter-rotate). The other reactiveOnly-armed demo workloads fire a REAL foothold
// detector signal (a SecurityEvent) → the brain rotates the attacked pod (or quarantines a stateful one).
// `armed` namespaces stay CALM until attacked, so the response is a clean, attributable reaction.
function attacksFor(type: string, armed: boolean): WlAttack[] {
  switch (type) {
    case "model-server": return [
      { id: "kvcache", label: "Prefix-cache occupancy oracle (CWE-208)", actuator: "kv-reset", runnable: true },
      { id: "poison", label: "Poisoned LoRA injection (OWASP LLM05 / AML.T0018)", actuator: "adapter-rotate", runnable: true },
    ];
    case "gpu-inference": return [{ id: "foothold", label: "Container-escape foothold (red-team)", actuator: "rotate", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
    case "llm-proxy": return [{ id: "foothold", label: "RCE / credential foothold (red-team)", actuator: "rotate", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
    case "database": return [{ id: "foothold", label: "Lateral-movement foothold (red-team)", actuator: "quarantine (stateful — state preserved)", runnable: armed, note: armed ? undefined : "would isolate a live DB — arm explicitly to fire" }];
    case "message-broker": return [{ id: "foothold", label: "Broker-node compromise / lateral foothold (red-team)", actuator: "quarantine (stateful — data + quorum preserved)", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
    default: return [{ id: "foothold", label: "Recon / CVE foothold (red-team)", actuator: "rotate", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
  }
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
  const sel = useSelectedTarget(); // SCOPE the live stream to the selected provider (EKS vs vCluster)

  React.useEffect(() => {
    // owner stream is tenant-scoped: wait for a tenant before opening the SSE.
    if (owner && !tenant) { setEvents([]); setConnected(false); return; }
    setEvents([]); setConnected(true);
    // tail=80: the server replays only the last 80 decisions on connect (no "fast train" flood
    // after hours of running), then tails live; we keep up to BUFFER_CAP client-side for paging.
    const stop = liveStream(lens, (data) => setEvents((prev) => [data, ...prev].slice(0, BUFFER_CAP)), owner ? tenant : undefined, 80, sel.context);
    return () => { stop(); setConnected(false); };
  }, [lens, owner, tenant, reloadKey, sel.context]);

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

  // ATTACK ↔ DECISION TRACE: pull the attack runs, build their UTC time windows, and correlate each
  // live decision to the attack that was running at that instant — so you can SEE/SEARCH "this
  // decision happened DURING attack X".
  const [runs, setRuns] = React.useState<RunStatus[]>([]);
  const [traceRun, setTraceRun] = React.useState(""); // "" = show all; else only decisions in this attack's window
  React.useEffect(() => {
    let alive = true;
    const load = () => api.runsList(lens).then((d) => { if (alive) setRuns(d.runs || []); }).catch(() => {});
    load();
    const t = setInterval(load, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [lens]);
  const windows: AttackWindow[] = React.useMemo(() => runs
    .filter((r) => !sel.provider || (r.provider || "") === sel.provider)
    .map((r) => {
      const start = parseTs(r.date);
      const running = r.state === "running";
      const end = r.finished ? parseTs(r.finished) : running ? Date.now() + 60_000 : start + 600_000;
      return { id: r.id, scenario: r.config, start, end, running };
    })
    .filter((w) => !isNaN(w.start)), [runs, sel.provider]);
  const attackOf = React.useCallback((timeStr?: string): AttackWindow | null => {
    const t = Date.parse(timeStr || "");
    if (isNaN(t)) return null;
    return windows.find((w) => t >= w.start - 5000 && t <= w.end + 5000) || null; // small margin
  }, [windows]);
  const traceWin = windows.find((w) => w.id === traceRun) || null;

  // filter by actuator type + free-text + (optionally) the traced attack's time window.
  const q = query.trim().toLowerCase();
  const filtered = React.useMemo(() => events.filter((e) => {
    if (actionFilter && e.action !== actionFilter) return false;
    if (q && !`${e.namespace || ""}/${e.pod || ""} ${e.tenant || ""}`.toLowerCase().includes(q)) return false;
    if (traceWin) {
      const t = Date.parse(e.time || e.Time || "");
      if (isNaN(t) || t < traceWin.start - 5000 || t > traceWin.end + 5000) return false;
    }
    return true;
  }), [events, actionFilter, q, traceWin]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageSafe = Math.min(page, pageCount - 1);
  const pageEvents = filtered.slice(pageSafe * PAGE_SIZE, pageSafe * PAGE_SIZE + PAGE_SIZE);
  // reset to the first (live) page whenever the filter/search/lens changes.
  React.useEffect(() => { setPage(0); }, [actionFilter, query, lens, tenant, traceRun]);

  // LIVE vLLM ATTACK: fire a real attack on the live vLLM; the operator's actuator choice streams below.
  const [attacking, setAttacking] = React.useState("");
  const [attackMsg, setAttackMsg] = React.useState("");
  const fireAttack = async (action: string) => {
    setAttacking(action); setAttackMsg("");
    try {
      if (action === "poison" || action === "kvcache" || action === "reset") {
        const r = await api.vllmAttack(action as any, lens);
        setAttackMsg(r.message);
        if (action !== "reset") setActionFilter(action === "poison" ? "adapter-rotate" : "kv-reset");
      } else {
        // foothold | clear — a REAL detector signal on the selected reactiveOnly-armed workload.
        const ns = (selWl.split("/")[0] || "").trim();
        const r = await api.workloadAttack(ns, action as any, lens);
        setAttackMsg(r.message + (r.expect ? "  (expected actuator: " + r.expect + ")" : ""));
        if (action === "foothold") setActionFilter("");
      }
    } catch (e: any) { setAttackMsg("error: " + String(e.message || e)); }
    finally { setAttacking(""); }
  };
  // STEP 1 — pick a workload; STEP 2 shows the attacks meaningful for its type.
  const [wls, setWls] = React.useState<{ ns: string; name: string; images: string[] }[]>([]);
  const [selWl, setSelWl] = React.useState("");
  React.useEffect(() => {
    if (owner) return;
    api.workloads(sel.context || "", lens).then((d) => {
      const flat: { ns: string; name: string; images: string[] }[] = [];
      for (const n of d.namespaces || []) { if (n.system) continue; for (const w of n.workloads || []) flat.push({ ns: n.namespace, name: w.name, images: w.images || [] }); }
      setWls(flat);
      const def = flat.find((w) => w.images.join(" ").toLowerCase().includes("vllm")) || flat[0];
      if (def) setSelWl((cur) => cur || def.ns + "/" + def.name);
    }).catch(() => {});
  }, [sel.context, lens, owner]);
  const curWl = wls.find((w) => w.ns + "/" + w.name === selWl);
  const curType = curWl ? wlType(curWl.images) : null;
  // reactiveOnly-armed namespaces: calm until attacked, so a fired foothold is a clean attributable reaction.
  const ARMED = ["litellm", "mock-rag-chatbot", "phorvex-live-demo", "nats"];
  const armed = !!curWl && ARMED.includes(curWl.ns);

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

      {/* LIVE WORKLOAD ATTACK — step 1: pick a workload; step 2: fire an attack meaningful for its type */}
      {!owner && (
        <div className="space-y-3 rounded-lg border border-primary/25 bg-primary/[0.05] p-3">
          <div className="flex flex-wrap items-center gap-2 text-[12px] font-medium text-foreground">
            <Swords className="h-3.5 w-3.5 text-primary" /> Live attack
            <span className="text-[11px] font-normal text-muted-foreground">— pick a workload, fire a meaningful attack, watch Phorvex pick the actuator below</span>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[12px]">
            <span className="text-[11px] text-muted-foreground">1 · target workload:</span>
            <select value={selWl} onChange={(e) => { setSelWl(e.target.value); setAttackMsg(""); }} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[11px] text-foreground">
              {wls.length === 0 && <option value="">(loading…)</option>}
              {wls.map((w) => <option key={w.ns + "/" + w.name} value={w.ns + "/" + w.name}>{w.ns}/{w.name}</option>)}
            </select>
            {curType && <Badge variant="accent">{curType.label}</Badge>}
          </div>
          {curType && (
            <div className="space-y-1.5">
              <div className="text-[11px] text-muted-foreground">2 · meaningful attacks for this workload:</div>
              <div className="flex flex-wrap items-center gap-2">
                {attacksFor(curType.type, armed).map((a) => a.runnable ? (
                  <Button key={a.id} size="sm" variant="outline" disabled={!!attacking} onClick={() => fireAttack(a.id as any)} className="gap-1.5" title={a.label}>
                    {attacking === a.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5 text-danger" />}
                    {a.label.split(" (")[0]} <span className="text-muted-foreground">→ {a.actuator}</span>
                  </Button>
                ) : (
                  <span key={a.id} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-elevated/30 px-2 py-1 text-[11px] text-muted-foreground" title={a.note}>
                    <Lock className="h-3 w-3" /> {a.label} <span className="font-mono">→ {a.actuator}</span>
                  </span>
                ))}
                <Button size="sm" variant="ghost" disabled={!!attacking} onClick={() => fireAttack(curType.type === "model-server" ? "reset" : "clear")} className="gap-1.5 text-muted-foreground">
                  {(attacking === "reset" || attacking === "clear") ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null} {curType.type === "model-server" ? "Reset" : "Clear attack"}
                </Button>
              </div>
              {attacksFor(curType.type, armed).every((a) => !a.runnable) && (
                <div className="text-[10px] text-warning">This workload’s namespace isn’t armed for live attacks yet — the row shows the attack→actuator mapping honestly. The armed demo workloads (vllm · litellm · mock-rag-chatbot · phorvex-live-demo) run reactiveOnly, so they stay calm until you fire a foothold and Phorvex reacts attributably.</div>
              )}
            </div>
          )}
          {attackMsg && <div className="text-[11px] text-primary">{attackMsg}</div>}
          {/* measured outcome of the attacks you just fired — full detail + cost/uptime in the Report tab */}
          <div className="mt-1 border-t border-border/40 pt-2"><AttackResultsPanel lens={lens} compact /></div>
        </div>
      )}

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
        {/* TRACE AN ATTACK — show only the decisions that fell inside a chosen attack's time window */}
        {windows.length > 0 && (
          <div className="flex items-center gap-1.5 rounded-md border border-border bg-panel/60 px-2 py-1.5 text-[12px]">
            <Swords className="h-3.5 w-3.5 text-warning" />
            <span className="text-muted-foreground">trace attack</span>
            <select value={traceRun} onChange={(e) => setTraceRun(e.target.value)} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[12px] text-foreground">
              <option value="">— none —</option>
              {windows.slice(0, 25).map((w) => (
                <option key={w.id} value={w.id}>{w.scenario} · {new Date(w.start).toLocaleTimeString()}{w.running ? " (running)" : ""}</option>
              ))}
            </select>
          </div>
        )}
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
          {traceWin && (
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-warning/30 bg-warning/[0.05] px-3 py-2 text-[12px] text-warning">
              <Swords className="h-3.5 w-3.5" />
              <span>Tracing decisions during attack <span className="font-mono text-foreground">{traceWin.scenario}</span> — {new Date(traceWin.start).toLocaleTimeString()} → {traceWin.running ? "now (running)" : new Date(traceWin.end).toLocaleTimeString()} · <span className="font-medium">{filtered.length} decisions in this window</span></span>
              <button onClick={() => setTraceRun("")} className="text-muted-foreground hover:text-foreground">clear</button>
            </div>
          )}
          <div className="flex items-center justify-between">
            <SectionLabel>Decision stream {owner ? "(owner projection)" : "(full internals)"}{pageSafe === 0 ? <span className="ml-2 inline-flex items-center gap-1 text-[10px] font-normal text-success"><span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" /> live</span> : <span className="ml-2 text-[10px] font-normal text-muted-foreground">history · page {pageSafe + 1}</span>}</SectionLabel>
            <Pagination page={pageSafe} pageCount={pageCount} onPage={setPage} />
          </div>
          <div className="space-y-2">
            {pageEvents.map((e, i) => owner ? <OwnerCard key={`${pageSafe}-${i}`} e={e} /> : <DecisionCard key={`${pageSafe}-${i}`} e={e} attack={attackOf(e.time || e.Time)} />)}
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

function DecisionCard({ e, attack }: { e: any; attack?: { scenario: string; running: boolean } | null }) {
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
          {attack && <span className="inline-flex items-center gap-1 rounded bg-warning/10 px-1.5 py-0.5 text-[10px] text-warning" title={`a live decision made while attack '${attack.scenario}' was running`}><Swords className="h-3 w-3" /> during {attack.scenario}</span>}
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
