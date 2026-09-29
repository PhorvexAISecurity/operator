"use client";
import * as React from "react";
import { ClaimScopeNote } from "@/components/claim-scope";
import { api, Lens, LiveHistoryPage, RunStatus, AttackResult } from "@/lib/api";
import { dispatchLiveAttack, liveAttackFollowMessage, liveAttackPollBudgetMs, liveAttackRoute, liveAttackVerdict } from "@/lib/live-attack-dispatch";
import { AttackResultsPanel } from "@/components/panels/attack-report";
import { useOwnerTenant } from "@/lib/owner";
import { useSelectedTarget } from "@/lib/provider-store";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { PageHead, SectionLabel } from "./effectiveness";
import { cn } from "@/lib/utils";
import { useApiRead, useExactRecord, useQueryScope, useTargets, useWorkloads } from "@/lib/query";
import { LIVE_SELECTION_EVENT, LiveSelectionEvent, clearLiveSelection, readLiveSelection, selectLiveRecord } from "@/lib/live-selection";
import { Radio, Lock, Trash2, ChevronDown, ShieldCheck, ShieldOff, Search, ChevronLeft, ChevronRight, ListFilter, Swords, Loader2, BarChart3 } from "lucide-react";
import { useLocalPage } from "@/lib/use-local-page";
import { PaginationBar } from "@/components/ui/pagination";

// parseTs parses a UTC tsNow() string ("2026-06-28 14:30:00 UTC") to epoch ms.
function parseTs(s?: string): number {
  if (!s) return NaN;
  const p = s.split(" ");
  return p.length >= 2 ? Date.parse(`${p[0]}T${p[1]}Z`) : Date.parse(s);
}
// AttackWindow is one attack run's time span, for correlating decisions to the attack that ran then.
interface AttackWindow { id: string; scenario: string; start: number; end: number; running: boolean }

const PAGE_SIZE = 15;       // decisions per page

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
function comparisonAttacksFor(type: string, armed: boolean): WlAttack[] {
  switch (type) {
    case "model-server": return [
      { id: "kvcache", label: "KV reset-effect observation (CWE-208)", actuator: "kv-reset", runnable: true },
      { id: "poison", label: "Unapproved LoRA load observation (OWASP LLM05 / AML.T0018)", actuator: "adapter-rotate", runnable: true },
    ];
    case "gpu-inference": return [{ id: "foothold", label: "Container-escape foothold (red-team)", actuator: "rotate", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
    case "llm-proxy": return [{ id: "foothold", label: "RCE / credential foothold (red-team)", actuator: "rotate", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
    case "database": return [{ id: "foothold", label: "Lateral-movement foothold (red-team)", actuator: "quarantine (stateful — state preserved)", runnable: armed, note: armed ? undefined : "would isolate a live DB — arm explicitly to fire" }];
    case "message-broker": return [{ id: "foothold", label: "Broker-node compromise / lateral foothold (red-team)", actuator: "quarantine (stateful — data + quorum preserved)", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
    default: return [{ id: "foothold", label: "Recon / CVE foothold (red-team)", actuator: "rotate", runnable: armed, note: armed ? undefined : "arm this namespace (reactiveOnly) to fire" }];
  }
}

export function LiveOpsPanel({ lens }: { lens: Lens }) {
  const [clearing, setClearing] = React.useState(false);
  const [clearError, setClearError] = React.useState("");
  const [auditClearAvailable,setAuditClearAvailable] = React.useState(false);
  const [reloadKey, setReloadKey] = React.useState(0);
  const [actionFilter, setActionFilter] = React.useState("");  // "" = all actuator types
  const [query, setQuery] = React.useState("");                // pod / namespace text search
  const [actuatedOnly, setActuatedOnly] = React.useState(false);
  const [showNoop, setShowNoop] = React.useState(true);
  const owner = lens === "owner";
  const { tenant, tenants, tenantListPartial, setTenant } = useOwnerTenant(lens);
  const sel = useSelectedTarget(); // SCOPE the live stream to the selected provider (EKS vs vCluster)
  const mutationGeneration = React.useRef(0);
  const targetQuery = useTargets(lens);
  const workloadQuery = useWorkloads(sel.context, lens, !owner && !!sel.context);
  const queryScope = useQueryScope(lens);
  const verifiedSession = queryScope.session;
  const selectedTarget = (targetQuery.data?.targets || []).find((t) => t.runnable && t.context === sel.context) || null;

  const mutatesDefaultContext = !sel.context || (selectedTarget?.context === sel.context && selectedTarget.defaultMutationTarget === true);
  const mutationScopeMessage = selectedTarget
    ? "Controls are unavailable because this named context is not the server-resolved target of unscoped mutation endpoints."
    : "Controls are unavailable because the server could not verify this named context as the target of unscoped mutation endpoints.";

  React.useEffect(() => { setAuditClearAvailable(verifiedSession.auditClearAvailable); }, [verifiedSession]);

  // This remains an explicit destructive action, scoped to the selected provider.
  async function clearDecisions() {
    if (!window.confirm("Clear the current audit file for this provider? Retained rotated history is not deleted.")) return;
    setClearing(true); setClearError("");
    try { await api.clearLive(lens, sel.context); setReloadKey((k) => k + 1); }
    catch (e: any) { setClearError(String(e.message || e)); }
    finally { setClearing(false); }
  }

  // ATTACK ↔ DECISION TRACE: pull the attack runs, build their UTC time windows, and correlate each
  // live decision to the attack that was running at that instant — so you can SEE/SEARCH "this
  // decision happened DURING attack X".
  const runsRead = useApiRead({ lens, resource: "runs-summary", parameters: { context: sel.context, provider: sel.provider }, fetcher: () => api.runsList(lens), staleTime: 5_000, refetchInterval: 5_000 });
  const runs = runsRead.data?.runs || [];
  const [traceRun, setTraceRun] = React.useState(""); // "" = show all; else only decisions in this attack's window
  const [traceQuery, setTraceQuery] = React.useState("");
  React.useEffect(() => { setTraceRun(""); setTraceQuery(""); }, [lens, sel.context, sel.provider]);
  React.useEffect(() => {
    const apply = (selection: LiveSelectionEvent | null) => {
      if (!selection) { setTraceRun(""); return; }
      if (selection?.lens !== lens || selection.context !== sel.context) return;
      if (selection?.kind === "run" && selection.lens === lens && selection.context === sel.context) setTraceRun(selection.id);
      else setTraceRun("");
    };
    apply(readLiveSelection(lens, sel.context));
    const onSelection = (event: Event) => apply((event as CustomEvent<LiveSelectionEvent>).detail);
    window.addEventListener(LIVE_SELECTION_EVENT, onSelection);
    return () => window.removeEventListener(LIVE_SELECTION_EVENT, onSelection);
  }, [lens, sel.context]);
  const windows: AttackWindow[] = React.useMemo(() => runs
    .filter((r) => r.target ? !!sel.context && r.target === sel.context : !!sel.provider && (r.provider || "") === sel.provider)
    .map((r) => {
      const start = parseTs(r.date);
      const running = r.state === "running";
      const end = r.finished ? parseTs(r.finished) : running ? Date.now() + 60_000 : start + 600_000;
      return { id: r.id, scenario: r.config, start, end, running };
    })
    .filter((w) => !isNaN(w.start)), [runs, sel.context, sel.provider]);
  const attackOf = React.useCallback((timeStr?: string): AttackWindow | null => {
    const t = Date.parse(timeStr || "");
    if (isNaN(t)) return null;
    return windows.find((w) => t >= w.start - 5000 && t <= w.end + 5000) || null; // small margin
  }, [windows]);
  const traceWin = windows.find((w) => w.id === traceRun) || null;
  const traceUnavailable = !!traceRun && !traceWin;
  const normalizedTraceQuery = traceQuery.trim().toLowerCase();
  const matchingWindows = windows.filter((w) => !normalizedTraceQuery || `${w.scenario} ${w.id}`.toLowerCase().includes(normalizedTraceQuery));
  const tracePage = useLocalPage(matchingWindows, 20, `${lens}\u0000${sel.context}\u0000${sel.provider}\u0000${traceQuery}`);
  const traceOptions = traceWin && !tracePage.pageItems.some((w) => w.id === traceWin.id) ? [traceWin, ...tracePage.pageItems] : tracePage.pageItems;

  const filters = {
    context: sel.context || "", tenant: owner ? tenant : "", action: actionFilter,
    actuated: actuatedOnly ? "true" : "", q: query.trim(), limit: String(PAGE_SIZE),
    includeNoop: showNoop ? "true" : "false",
    from: traceWin ? new Date(traceWin.start - 5000).toISOString() : "",
    to: traceWin && !traceWin.running ? new Date(traceWin.end + 5000).toISOString() : "",
  };
  const scopeKey = JSON.stringify([lens, filters, traceRun, reloadKey]);
  const [navigation, setNavigation] = React.useState<{ scope: string; cursors: string[]; frozen: boolean }>({ scope: "", cursors: [""], frozen: false });
  const cursors = navigation.scope === scopeKey ? navigation.cursors : [""];
  const frozen = navigation.scope === scopeKey && navigation.frozen;
  const page = cursors.length - 1;
  const cursor = cursors[page];
  const requestKey = JSON.stringify([scopeKey, cursor]);
  const [pageCache, setPageCache] = React.useState<Array<{ scope: string; key: string; data: LiveHistoryPage }>>([]);
  const pageCacheRef = React.useRef(pageCache);
  pageCacheRef.current = pageCache;
  React.useEffect(() => {
    setPageCache((entries) => entries.filter((entry) => entry.scope === scopeKey));
  }, [scopeKey]);
  const [failure, setFailure] = React.useState<{ key: string; message: string }>({ key: "", message: "" });
  const [busyKey, setBusyKey] = React.useState("");
  // Both response writes AND rendering are scope-keyed. A provider/tenant change
  // cannot flash a previous scope's data, even before effect cleanup runs.
  React.useEffect(() => {
    if (owner && !tenant) return;
    if (traceUnavailable) return;
    if (frozen && pageCacheRef.current.some((entry) => entry.key === requestKey)) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    const load = async () => {
      setBusyKey(requestKey);
      try {
        const data = await api.liveHistory(lens, { ...filters, cursor }, controller.signal);
        if (alive) {
          setPageCache((entries) => {
            const current = entries.filter((entry) => entry.scope === scopeKey && entry.key !== requestKey);
            const next = [...current, { scope: scopeKey, key: requestKey, data }];
            const rootKey = JSON.stringify([scopeKey, ""]);
            const root = next.find((entry) => entry.key === rootKey);
            const cursorPages = next.filter((entry) => entry.key !== rootKey);
            return root ? [root, ...cursorPages.slice(-19)] : cursorPages.slice(-20);
          });
          setFailure({ key: requestKey, message: "" });
        }
      } catch (e: any) { if (alive) setFailure({ key: requestKey, message: String(e.message || e) }); }
      finally {
        if (alive) {
          setBusyKey("");
          if (!cursor && !frozen) timer = setTimeout(load, 5000);
        }
      }
    };
    load();
    return () => { alive = false; controller.abort(); clearTimeout(timer); };
    // requestKey contains every request parameter; polling never mutates history pages.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestKey, traceUnavailable, frozen]);
  const result = pageCache.find((entry) => entry.key === requestKey)?.data || null;
  const error = failure.key === requestKey ? failure.message : "";
  const retainedEvents = result?.events || [];
  const events = retainedEvents;
  const actuated = events.filter(({ event }) => event.actuated).length;
  const loading = !result && !error && (!owner || !!tenant);
  const refreshing = busyKey === requestKey;
  const historyStatusTone = traceUnavailable || loading || frozen
    ? "text-muted-foreground"
    : error
      ? "text-danger"
      : result?.partial
        ? "text-warning"
        : page === 0 && result
          ? "text-success"
          : "text-muted-foreground";
  const actions = Array.from(new Set(["noop", "rotate", "quarantine", "kv-reset", "adapter-rotate", ...retainedEvents.map(({ event }) => event.action).filter(Boolean)])).sort();
  const latest = () => { setPageCache([]); setNavigation({ scope: "", cursors: [""], frozen: false }); setReloadKey((k) => k + 1); };
  const newer = () => {
    const nextCursors = cursors.slice(0, -1);
    setNavigation({ scope: scopeKey, cursors: nextCursors, frozen: nextCursors.length > 1 });
  };
  const older = () => { if (result?.nextCursor) setNavigation({ scope: scopeKey, cursors: [...cursors, result.nextCursor], frozen: true }); };
  const clearTraceSelection = () => {
    setTraceRun("");
    if (sel.context) clearLiveSelection(lens, sel.context);
  };

  // LIVE vLLM ATTACK: fire a real attack on the live vLLM; the operator's actuator choice streams below.
  const [attacking, setAttacking] = React.useState("");
  const [attackMsg, setAttackMsg] = React.useState("");
  const [attackRecordId, setAttackRecordId] = React.useState("");
  const [attackFollowUntil, setAttackFollowUntil] = React.useState(0);
  const [completedAttackRecord, setCompletedAttackRecord] = React.useState<AttackResult | null>(null);
  const [lastAttackRecord, setLastAttackRecord] = React.useState<AttackResult | null>(null);
  React.useEffect(() => {
    if (!attackFollowUntil) return;
    const timer = setTimeout(() => setAttackFollowUntil(0), Math.max(0, attackFollowUntil - Date.now()));
    return () => clearTimeout(timer);
  }, [attackFollowUntil]);
  const attackRecordQuery = useExactRecord<AttackResult>({ resource: "attack-results", context: sel.context,
    id: attackRecordId, lens, enabled: !!attackFollowUntil,
    fetcher: (signal) => api.attackResultsPage(lens, 1, { id: attackRecordId, includeObservations: "true" }, undefined, signal)
      .then((page) => (page.attacks || []).find((row) => row.id === attackRecordId) || null),
    active: (row) => row.status === "running" });
  React.useEffect(() => {
    const row = attackRecordQuery.data;
    if (row && row.id === attackRecordId) setLastAttackRecord(row);
    if (row && row.id === attackRecordId && (row.status === "done" || row.status === "partial")) {
      setCompletedAttackRecord(row);
      setAttackFollowUntil(0);
    }
  }, [attackRecordId, attackRecordQuery.data]);
  const attackRecord = completedAttackRecord || attackRecordQuery.data || lastAttackRecord;
  const attackVerdict = attackRecord ? liveAttackVerdict(attackRecord) : null;
  const attackFollowMessage = liveAttackFollowMessage(attackRecordId, attackFollowUntil > 0, attackRecord);
  const fireAttack = async (action: string) => {
    const workload = selWl;
    if (!queryScope.ready || targetQuery.error || workloadQuery.error || lens !== "operator" || !mutatesDefaultContext || !workload || !wls.some((item) => `${item.ns}/${item.name}` === workload)) {
      setAttackMsg(mutationScopeMessage);
      return;
    }
    const entry = compatibleAttacks.find((a) => a.id === (action === "clear" ? "foothold" : action));
    if (!entry?.armed || compatibilityQuery.error || compatibilityQuery.isFetching || compatibilityQuery.data?.namespace !== curWl?.ns) {
      setAttackMsg("Attack compatibility is unavailable or this action is not armed for the selected app.");
      return;
    }
    const route = liveAttackRoute(entry, curWl?.ns || "", action === "clear");
    if (!route) {
      setAttackMsg(`Attack refused: unsupported endpoint or ID for ${entry.id}.`);
      return;
    }
    const request = mutationGeneration.current;
    setAttacking(action); setAttackMsg(""); setAttackRecordId(""); setAttackFollowUntil(0); setCompletedAttackRecord(null); setLastAttackRecord(null);
    clearLiveSelection(lens, sel.context);
    try {
      const r = await dispatchLiveAttack(route, lens);
      if (request !== mutationGeneration.current || workload !== selWl) return;
      setAttackMsg(r.message + ("expect" in r && r.expect ? "  (expected actuator: " + r.expect + ")" : "") + (r.attackId ? "" : " No exact result ID was returned."));
      setActionFilter("");
      if (r.attackId) {
        setAttackRecordId(r.attackId);
        setAttackFollowUntil(Date.now() + liveAttackPollBudgetMs(route));
        selectLiveRecord({ kind: "attack", id: r.attackId, lens, context: sel.context });
      }
    } catch (e: any) { if (request === mutationGeneration.current && workload === selWl) setAttackMsg("error: " + String(e.message || e)); }
    finally { if (request === mutationGeneration.current && workload === selWl) setAttacking(""); }
  };
  // THREE-ARM COMPARISON — user-triggered from here, streams live into Availability: 3-way.
  const [comparing, setComparing] = React.useState("");
  const [compareMsg, setCompareMsg] = React.useState("");
  const runComparison = async (attack: string) => {
    const workload = selWl;
    if (!queryScope.ready || targetQuery.error || workloadQuery.error || lens !== "operator" || !mutatesDefaultContext || !workload || !wls.some((item) => `${item.ns}/${item.name}` === workload)) {
      setCompareMsg(mutationScopeMessage);
      return;
    }
    const ns = (workload.split("/")[0] || "").trim();
    if (!ns) return;
    const request = mutationGeneration.current;
    setComparing(attack); setCompareMsg("");
    try {
      const r = await api.runAvailabilityArms(ns, attack, lens);
      if (request !== mutationGeneration.current || workload !== selWl) return;
      setCompareMsg(r.note || "started");
    } catch (e: any) { if (request === mutationGeneration.current && workload === selWl) setCompareMsg("error: " + String(e.message || e)); }
    finally { if (request === mutationGeneration.current && workload === selWl) setComparing(""); }
  };

  // STEP 1 — pick a workload; STEP 2 shows the attacks meaningful for its type.
  const wls = React.useMemo(() => {
    if (owner || !workloadQuery.data) return [];
    const flat: { ns: string; name: string; images: string[] }[] = [];
    for (const n of workloadQuery.data.namespaces || []) { if (n.system) continue; for (const w of n.workloads || []) flat.push({ ns: n.namespace, name: w.name, images: w.images || [] }); }
    return flat;
  }, [owner, workloadQuery.data]);
  const [selWl, setSelWl] = React.useState("");
  React.useEffect(() => {
    setSelWl(""); setAttackMsg("");
  }, [lens, owner, sel.context]);
  React.useEffect(() => {
    mutationGeneration.current++;
    setAttacking(""); setAttackMsg(""); setComparing(""); setCompareMsg(""); setAttackRecordId(""); setAttackFollowUntil(0); setCompletedAttackRecord(null); setLastAttackRecord(null);
  }, [lens, sel.context, sel.provider, selWl]);
  React.useEffect(() => {
    const def = wls.find((w) => w.images.join(" ").toLowerCase().includes("vllm")) || wls[0];
    setSelWl((current) => wls.some((w) => `${w.ns}/${w.name}` === current) ? current : def ? `${def.ns}/${def.name}` : "");
  }, [wls]);
  const curWl = wls.find((w) => w.ns + "/" + w.name === selWl);
  const curType = curWl ? wlType(curWl.images) : null;
  // reactiveOnly-armed namespaces: calm until attacked, so a fired foothold is a clean attributable reaction.
  const ARMED = ["voice", "nats"];
  const armed = !!curWl && ARMED.includes(curWl.ns);
  const compatibilityQuery = useApiRead({ lens, resource: "workload-attacks", parameters: { namespace: curWl?.ns || "", context: sel.context },
    fetcher: (signal) => api.workloadAttacks(curWl!.ns, lens, signal), staleTime: 30_000,
    enabled: !owner && !!curWl && mutatesDefaultContext });
  const compatibleAttacks = compatibilityQuery.data?.namespace === curWl?.ns ? (compatibilityQuery.data?.live || []).filter((a) => a.compatible) : [];
  const attackControlsDisabled = !queryScope.ready || lens !== "operator" || !!targetQuery.error || !!workloadQuery.error || !!compatibilityQuery.error || compatibilityQuery.isFetching || !!attacking || !mutatesDefaultContext;

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title="Live Operations" sub="Search retained decision history by workload, action or actual actuation. Latest results refresh every 5 seconds; older pages stay paused. Expand a decision for reasoning and record-time claim provenance. Large decisionTrace payloads are omitted from this summary view." />
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 rounded-md border border-border bg-panel/60 px-3 py-1.5 text-[12px]">
          <Radio data-testid="history-status-icon" className={cn("h-3.5 w-3.5", historyStatusTone)} />
          <span>{traceUnavailable ? "Selection unavailable" : error ? "Refresh failed" : result?.partial ? (frozen ? "History incomplete · browsing paused" : "History incomplete · checking every 5s") : frozen ? "History paused · retained page" : refreshing ? "Refreshing latest…" : "Latest · refresh every 5s"}</span>
        </div>
        {!traceUnavailable && <div className="text-[12px] text-muted-foreground">{events.length} on this page · {actuated} actuated</div>}
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
          <Button variant="outline" size="sm" onClick={clearDecisions} disabled={!auditClearAvailable || clearing || events.length === 0} className="ml-auto gap-1.5">
            <Trash2 className="h-3.5 w-3.5" /> {clearing ? "Clearing…" : "Clear current audit"}
          </Button>
        )}
      </div>
      {clearError && <div role="alert" className="text-sm text-danger">Could not clear audit: {clearError}</div>}
      {!owner && !auditClearAvailable && <div role="status" className="text-xs text-muted-foreground">This console reads the manager audit through a read-only connection. Clearing the audit is unavailable here; use the manager retention procedure.</div>}
      {owner && tenantListPartial && <div role="status" className="text-xs text-warning">Tenant choices come from the latest bounded audit window and may omit inactive older tenants. Retained decisions can still be paged in history.</div>}

      {/* LIVE WORKLOAD ATTACK — step 1: pick a workload; step 2: fire an attack meaningful for its type */}
      {!owner && (
        <details className="space-y-3 rounded-lg border border-border bg-panel/50 p-3">
          <summary className="cursor-pointer text-[12px] font-medium text-foreground">
            <Swords className="mr-1.5 inline-block h-3.5 w-3.5 align-text-bottom text-primary" /> Live attack
            <span className="text-[11px] font-normal text-muted-foreground">— pick a workload, fire a meaningful attack, watch Phorvex pick the actuator below</span>
          </summary>
          {!mutatesDefaultContext && <div className="rounded-md border border-warning/30 bg-warning/[0.05] p-2 text-[11px] text-warning">{mutationScopeMessage}</div>}
          <div className="flex flex-wrap items-center gap-2 text-[12px]">
            <span className="text-[11px] text-muted-foreground">1 · target workload:</span>
            <select value={selWl} onChange={(e) => { mutationGeneration.current++; setSelWl(e.target.value); setAttacking(""); setAttackMsg(""); setComparing(""); setCompareMsg(""); }} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[11px] text-foreground">
              {wls.length === 0 && <option value="">(loading…)</option>}
              {wls.map((w) => <option key={w.ns + "/" + w.name} value={w.ns + "/" + w.name}>{w.ns}/{w.name}</option>)}
            </select>
            {curType && <Badge variant="accent">{curType.label}</Badge>}
          </div>
          {curType && (
            <div className="space-y-1.5">
              <div className="text-[11px] text-muted-foreground">2 · meaningful attacks for this workload:</div>
              <div className="flex flex-wrap items-center gap-2">
                {compatibleAttacks.map((a) => a.armed ? (
                  <Button key={a.id} size="sm" variant="outline" disabled={attackControlsDisabled} onClick={() => fireAttack(a.id)} className="gap-1.5" title={a.description}>
                    {attacking === a.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5 text-danger" />}
                    {a.name} <span className="text-muted-foreground">→ {a.expectedActuator}</span>
                  </Button>
                ) : (
                  <span key={a.id} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-elevated/30 px-2 py-1 text-[11px] text-muted-foreground" title={a.reason}>
                    <Lock className="h-3 w-3" /> {a.name} <span className="font-mono">→ {a.expectedActuator}</span>
                  </span>
                ))}
                {curType.type === "model-server" ? (
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-elevated/30 px-2 py-1 text-[11px] text-muted-foreground" title="Reset is unavailable without durable per-run restoration authority">
                    <Lock className="h-3 w-3" /> Reset unavailable
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-elevated/30 px-2 py-1 text-[11px] text-muted-foreground" title="The console refuses manual clears without exact per-run restoration authority; the injected attack event is removed automatically about 5 minutes after it was fired.">
                    <Lock className="h-3 w-3" /> Auto-clears in ~5 min
                  </span>
                )}
              </div>
              {/* Compare all three defenders on THIS app with THIS attack — the result streams into
                  the Availability: 3-way tab while it runs. Kept as an explicit action because it
                  puts the policy in dryRun and rotates pods for ~7 minutes. */}
              {armed && comparisonAttacksFor(curType.type, armed).some((a) => a.runnable) && (
                <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <BarChart3 className="h-3.5 w-3.5 text-primary" />
                    <span className="text-[11px] font-medium text-foreground">Compare availability: no defense vs blind rotator vs Phorvex</span>
                    {comparisonAttacksFor(curType.type, armed).filter((a) => a.runnable).map((a) => (
                      <Button key={"cmp-" + a.id} size="sm" variant="outline" disabled={!queryScope.ready || !!targetQuery.error || !!workloadQuery.error || !!comparing || !mutatesDefaultContext}
                        onClick={() => runComparison(a.id)} className="gap-1.5">
                        {comparing === a.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <BarChart3 className="h-3.5 w-3.5" />}
                        run for {a.label.split(" (")[0]}
                      </Button>
                    ))}
                  </div>
                  <div className="mt-1.5 text-[10px] leading-relaxed text-muted-foreground">
                    Fires this attack three times on <span className="font-mono">{selWl}</span>: once with the
                    policy in dryRun (no defense), once against a blind fixed-interval rotator, and once with
                    Phorvex active. Takes ~7 minutes and rotates pods; the policy is restored to active
                    automatically. Watch it live in <span className="text-foreground">Availability: 3-way</span>.
                  </div>
                  {compareMsg && <div className="mt-1.5 text-[11px] text-primary">{compareMsg}</div>}
                </div>
              )}
              {compatibilityQuery.error && <div role="alert" className="text-[11px] text-warning">Attack compatibility could not be refreshed. <button onClick={() => void compatibilityQuery.refetch()} className="underline">Retry</button></div>}
              {compatibilityQuery.isFetching && !compatibilityQuery.data && <div className="text-[11px] text-muted-foreground">Loading compatible actions…</div>}
              {!compatibilityQuery.isFetching && !compatibilityQuery.error && compatibleAttacks.length > 0 && compatibleAttacks.every((a) => !a.armed) && <div className="text-[11px] text-warning">This app is not armed for live actions.</div>}
            </div>
          )}
          {attackMsg && <div className="text-[11px] text-primary">{attackMsg}</div>}
          {attackRecord && (attackRecord.status === "done" || attackRecord.status === "partial") && (
            <div className="text-[11px] text-muted-foreground">Exact result {attackRecord.id}: {attackRecord.outcome || attackRecord.status}; observed {attackVerdict?.action}.
              {attackVerdict?.reason && <div>Reason: {attackVerdict.reason}</div>}
              {attackVerdict?.blocked.map((candidate) => <div key={candidate}>Candidate: {candidate}</div>)}
            </div>
          )}
          {attackFollowMessage && !attackRecordQuery.error && <div className={`text-[11px] ${attackFollowUntil ? "text-muted-foreground" : "text-warning"}`}>{attackFollowMessage}</div>}
          {attackRecordQuery.error && attackFollowUntil > 0 && <div className="text-[11px] text-warning">Could not read exact result {attackRecordId}: {String((attackRecordQuery.error as Error).message || attackRecordQuery.error)}</div>}
        </details>
      )}
      {!owner && <div aria-label="Selected attack receipt"><AttackResultsPanel lens={lens} compact /></div>}

      {/* FILTER BAR — by actuator type + free-text pod/namespace search */}
      <div className="flex flex-wrap items-center gap-2">
        {!traceUnavailable && <Button variant={actuatedOnly ? "primary" : "outline"} size="sm" aria-pressed={actuatedOnly} onClick={() => setActuatedOnly((v) => !v)}>Actuated only</Button>}
        {!traceUnavailable && <Button variant={!showNoop ? "primary" : "outline"} size="sm" aria-pressed={!showNoop} onClick={() => {
          const next = !showNoop;
          if (!next && actionFilter === "noop") setActionFilter("");
          setShowNoop(next);
        }}>{showNoop ? "Hide no-op" : "No-op hidden"}</Button>}
        {!traceUnavailable && <div className="flex items-center gap-1.5 rounded-md border border-border bg-panel/60 px-2 py-1.5 text-[12px]">
          <ListFilter className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">actuator</span>
          <select value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); if (e.target.value === "noop") setShowNoop(true); }} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[12px] text-foreground">
            <option value="">all</option>
            {actions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>}
        <div className="flex items-center gap-1.5 rounded-md border border-border bg-panel/60 px-2 py-1.5">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="search pod / namespace / tenant…"
            aria-label="Search decision history" className="w-44 max-w-full bg-transparent text-[12px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none" />
          {query && <button onClick={() => setQuery("")} className="text-[11px] text-muted-foreground hover:text-foreground">clear</button>}
        </div>
        {/* TRACE AN ATTACK — show only the decisions that fell inside a chosen attack's time window */}
        {(windows.length > 0 || !!traceRun) && (
          <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-border bg-panel/60 px-2 py-1.5 text-[12px]">
            <Swords className="h-3.5 w-3.5 text-warning" />
            <span className="text-muted-foreground">candidate window</span>
            <input value={traceQuery} onChange={(e) => setTraceQuery(e.target.value)} placeholder="search run…" aria-label="Search candidate attack runs" className="w-28 rounded border border-border bg-panel px-2 py-1 text-[12px] focus:outline-none" />
            <select value={traceRun} onChange={(e) => setTraceRun(e.target.value)} className="rounded border border-border bg-panel px-2 py-1 font-mono text-[12px] text-foreground">
              <option value="">— none —</option>
              {traceUnavailable && <option value={traceRun}>unavailable · run {traceRun}</option>}
              {traceOptions.map((w) => (
                <option key={w.id} value={w.id}>{w.scenario} · run {w.id} · {new Date(w.start).toLocaleTimeString()}{w.running ? " (running)" : ""}</option>
              ))}
            </select>
            <PaginationBar page={tracePage.page} pageSize={20} total={matchingWindows.length} hasNext={tracePage.hasNext} onPrevious={() => tracePage.setPage((p) => Math.max(0, p - 1))} onNext={() => tracePage.setPage((p) => p + 1)} />
          </div>
        )}
        {/* quick actuator chips */}
        {!traceUnavailable && <div className="flex flex-wrap items-center gap-1">
          {actions.slice(0, 6).map((a) => (
            <button key={a} onClick={() => { setActionFilter(actionFilter === a ? "" : a); if (a === "noop" && actionFilter !== a) setShowNoop(true); }}
              className={cn("rounded-full border px-2 py-0.5 font-mono text-[11px] transition-colors",
                actionFilter === a ? "border-primary/50 bg-primary/[0.08] text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
              {a}
            </button>
          ))}
        </div>}
        {!traceUnavailable && <div className="ml-auto text-[12px] text-muted-foreground">Server-filtered retained history · no-op {showNoop ? "included" : "excluded"}</div>}
      </div>

      <section className="min-w-0 space-y-3" aria-label="Decision history">
          {!traceUnavailable && error && <div role="alert" className="rounded-md border border-danger/30 p-3 text-sm text-danger">Could not load history: {error}. {result && "Showing the last successful response; it may be stale."} <button onClick={latest} className="underline">Refresh latest</button></div>}
          {traceWin && (
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-warning/30 bg-warning/[0.05] px-3 py-2 text-[12px] text-warning">
              <Swords className="h-3.5 w-3.5" />
              <span>Showing candidate time-window evidence for <span className="font-mono text-foreground">{traceWin.scenario}</span> — temporal overlap only, not exact run attribution · {new Date(traceWin.start).toLocaleTimeString()} → {traceWin.running ? "now (running)" : new Date(traceWin.end).toLocaleTimeString()}</span>
              <button onClick={clearTraceSelection} className="text-muted-foreground hover:text-foreground">clear</button>
            </div>
          )}
          {traceUnavailable && <div role="alert" className="rounded-md border border-warning/30 p-3 text-sm text-warning">The selected run is not available for this exact target. No all-history fallback is shown. <button onClick={clearTraceSelection} className="underline">Clear selection</button></div>}
          {!traceUnavailable && result?.partial && <div role="alert" className="rounded-md border border-warning/40 bg-warning/[0.08] p-3 text-sm text-warning"><span className="font-medium">Decision history is incomplete.</span> {result.notice || "The backend returned only a partial retained-history result."} Successful refreshes do not confirm that new decisions are being ingested.</div>}
          {!traceUnavailable && <div className="flex flex-wrap items-center justify-between gap-2">
            <SectionLabel>Decision history {owner ? "(owner projection)" : "(summary)"}</SectionLabel>
            <Pagination page={page} hasOlder={!!result?.nextCursor} onNewer={newer} onOlder={older} onLatest={latest} />
          </div>}
          {!traceUnavailable && (loading ? <div role="status" className="flex items-center gap-2 py-8 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading retained history…</div> : !error && events.length === 0 && <div className="rounded-md border border-border p-6 text-sm text-muted-foreground">{owner && !tenant ? "Select a platform tenant to view history." : result?.nextCursor ? "No matches in this scanned portion. Search older to continue through retained history." : result?.partial ? "No readable matches found. Some records could not be read; see the notice below." : "No decisions match in the retained audit history."}</div>)}
          <div className="space-y-2">
            {!traceUnavailable && events.map(({ id, event: e }) => owner ? <OwnerCard key={`${scopeKey}:${id}`} e={e} /> : <DecisionCard key={`${scopeKey}:${id}`} e={e} attack={attackOf(e.time || e.Time)} />)}
          </div>
          {!traceUnavailable && result && !result.partial && result.notice && <div role="status" className="text-[11px] leading-relaxed text-muted-foreground">{result.notice}</div>}
          {!traceUnavailable && !!result?.nextCursor && <div className="flex justify-center pt-1"><Pagination page={page} hasOlder onNewer={newer} onOlder={older} onLatest={latest} /></div>}
        </section>
    </div>
  );
}

// Pagination — Prev / page-of / Next. Page 0 is the newest (live) page.
function Pagination({ page, hasOlder, onNewer, onOlder, onLatest }: { page: number; hasOlder: boolean; onNewer: () => void; onOlder: () => void; onLatest: () => void }) {
  return (
    <div className="flex items-center gap-1.5 text-[12px]">
      {page > 0 && <Button variant="ghost" size="sm" className="h-7 px-2" onClick={onLatest}>Latest</Button>}
      <Button variant="outline" size="sm" className="h-7 px-2" disabled={page <= 0} onClick={onNewer} aria-label="newer">
        <ChevronLeft className="h-3.5 w-3.5" />
      </Button>
      <span className="tabular text-muted-foreground">Page {page + 1}</span>
      <Button variant="outline" size="sm" className="h-7 px-2" disabled={!hasOlder} onClick={onOlder} aria-label="Search older">
        Search older <ChevronRight className="h-3.5 w-3.5" />
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
  const acted = e.actuated;
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
            {acted ? "actuation dispatched; cost is modeled" : e.selected ? "selected, not actuated; cost is modeled" : "not actuated; modeled decision cost"}
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
            ? <>Modeled cost difference: <span className="font-mono">{savings.toFixed(4)}</span> versus the blind timer. This is not measured financial savings.</>
            : <>Modeled Phorvex cost <span className="font-mono">{f(phorvexCost)}</span> versus blind timer <span className="font-mono">{f(blindCost)}</span>; actual outcomes require separate evidence.</>}
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
    <Card className={cn("min-w-0 shadow-none backdrop-blur-none transition-colors", acted && "border-primary/25")}>
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="w-full min-w-0 text-left">
        <CardContent className="min-w-0 space-y-2 p-3 text-[12px]">
          <div className="flex min-w-0 items-start gap-2">
          <ChevronDown className={cn("h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
          <span data-decision-workload className="min-w-0 flex-1 break-words font-mono text-[12px] text-foreground">{e.namespace}/{e.pod}</span>
          {time && <span className="shrink-0 text-[11px] text-muted-foreground" title={date}>{time}</span>}
          </div>
          <div className="flex flex-wrap items-center gap-1.5 pl-5">
          <Badge variant={e.action === "noop" ? "neutral" : "accent"}>{e.action}</Badge>
          {sel && <Badge variant="real">selected</Badge>}
          {acted && <Badge variant="accent">actuated · dispatched</Badge>}
          {!acted && !sel && <Badge variant="neutral">not actuated</Badge>}
          {e.dryRun && <Badge variant="pending">dry-run{acted ? " flag" : ""}</Badge>}
          {attack && <span className="inline-flex items-center gap-1 rounded bg-warning/10 px-1.5 py-0.5 text-[10px] text-warning" title={`candidate evidence: timestamp overlaps '${attack.scenario}', without an exact run identifier`}><Swords className="h-3 w-3" /> overlaps {attack.scenario} window</span>}
          </div>
        </CardContent>
      </button>

      <div className="px-3 pb-2 text-[10px] text-muted-foreground">Detector-visible scope · security effect unconfirmed · expand for provenance</div>
      {open && (
        <CardContent className="space-y-3 border-t border-border/50 p-3 pt-3 text-[12px]">
          <ClaimScopeNote claim={e.claim} />
          {e.handler && <div className="break-all text-muted-foreground">Handler: {e.handler}</div>}
          {e.aiClassified && <Badge variant="modeled">AI classified</Badge>}
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
              {num(e.perDollar) != null && e.perDollar > 0 && <Metric label="per-$ modeled coverage" value={num(e.perDollar)} />}
              {typeof e.coveredFacts === "number" && e.coveredFacts > 0 && <Metric label="modeled covered facts" value={e.coveredFacts} />}
              {num(e.coveredWeight) != null && e.coveredWeight > 0 && <Metric label="modeled selection weight" value={num(e.coveredWeight)} />}
              {num(e.belief) != null && <Metric label="belief" value={num(e.belief)} />}
              {num(e.assetValue) != null && <Metric label="asset value" value={num(e.assetValue)} />}
              {num(e.blastRadius) != null && <Metric label="blast radius" value={num(e.blastRadius)} />}
              {num(e.sloHeadroom) != null && <Metric label="SLO headroom" value={num(e.sloHeadroom)} />}
              {num(e.exposure) != null && <Metric label="exposure" value={num(e.exposure)} />}
              {num(e.threatPosture) != null && <Metric label="threat posture" value={num(e.threatPosture)} />}
              {num(e.lambda) != null && e.lambda > 0 && <Metric label="λ (cost weight)" value={num(e.lambda)} />}
              {num(e.preemptMargin) != null && e.preemptMargin > 0 && <Metric label="preempt margin" value={`${(e.preemptMargin * 100).toFixed(0)}%`} />}
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
    <Card className="min-w-0 shadow-none backdrop-blur-none">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="w-full min-w-0 text-left">
        <CardContent className="min-w-0 space-y-2 p-3 text-[12px]">
          <div className="flex min-w-0 items-start gap-2">
          <ChevronDown className={cn("h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
          <span data-decision-workload className="min-w-0 flex-1 break-words font-mono text-[12px] text-foreground">{e.namespace}/{e.pod}</span>
          {time && <span className="shrink-0 text-[11px] text-muted-foreground" title={date}>{time}</span>}
          </div>
          <div className="flex flex-wrap items-center gap-1.5 pl-5">
          <Badge variant="accent">{e.action}</Badge>
          <Badge variant={e.actuated ? "accent" : "neutral"}>{e.actuated ? "actuated · dispatched" : "not actuated"}</Badge>
          {e.dryRun && <Badge variant="pending">dry-run{e.actuated ? " flag" : ""}</Badge>}
          </div>
        </CardContent>
      </button>
      <div className="px-3 pb-2 text-[10px] text-muted-foreground">Detector-visible scope · security effect unconfirmed · expand for provenance</div>
      {open && (
        <CardContent className="space-y-2 border-t border-border/50 p-3 pt-3 text-[12px]">
          <ClaimScopeNote claim={e.claim} />
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
