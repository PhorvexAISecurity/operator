"use client";
import * as React from "react";
import { ClaimScopeNote } from "@/components/claim-scope";
import { api, Lens, AttackResult, AttackCost } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { csvDownload, Empty, Input } from "@/components/ui/more";
import { DataFreshness, PaginationBar } from "@/components/ui/pagination";
import { useServerPage } from "@/lib/use-server-page";
import { ShieldCheck, ShieldAlert, Loader2, Download, Swords, Activity, Clock, Calculator } from "lucide-react";
import { cn } from "@/lib/utils";
import { LIVE_SELECTION_EVENT, LiveSelectionEvent, readLiveSelection } from "@/lib/live-selection";
import { useSelectedTarget } from "@/lib/provider-store";
import { useExactRecord } from "@/lib/query";
import { attackCSVActuator, isCatalogueSignalResult, isUnversionedResult, showSecurityOutcomeSections } from "@/lib/attack-result-truth";
import { CatalogueSignalResult } from "@/components/panels/catalogue-signal-result";
import { DecisionEvidencePanel } from "@/components/panels/decision-evidence";
import { GuardrailEffectProbe } from "@/components/panels/guardrail-effect-probe";
import { GuardrailOutputProbe } from "@/components/panels/guardrail-output-probe";
import { VoiceMemoryProbe } from "@/components/panels/voice-memory-probe";

// AttackResultsPanel shows persisted behavioral results and explicitly unscored mechanism/signal
// observations. Signal-only rows never contribute behavioral outcomes or economics.
export function AttackResultsPanel({ lens, compact }: { lens: Lens; compact?: boolean }) {
  const target = useSelectedTarget();
  const [selectedId, setSelectedId] = React.useState("");
  const [q, setQ] = React.useState("");
  const pageSize = compact ? 3 : 20;
  const resource = compact ? "attack-observations" : "attack-results";
  const includeObservations = compact ? "true" : undefined;
  const normalizedQ = q.trim().toLowerCase();
  const pager = useServerPage<AttackResult>({
    resource: "attack-results", lens,
    key: `${lens}\u0000${normalizedQ}\u0000${pageSize}`,
    network: { q: normalizedQ || undefined, includeObservations },
    pageSize,
    pollMs: 4000,
    fetchPage: (cursor, signal) => api.attackResultsPage(lens, pageSize, { q: normalizedQ || undefined, includeObservations }, cursor, signal).then((d) => ({ items: d.attacks || [], page: d.page })),
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
  const exactQuery = useExactRecord({ resource, context: target.context, id: selectedId, lens, enabled: needsExact,
    fetcher: (signal) => api.attackResultsPage(lens, 1, { id: selectedId, includeObservations }, undefined, signal).then((d) => (d.attacks || []).find((r) => r.id === selectedId) || null),
    active: (record) => record.status === "running" });
  const exact = needsExact ? exactQuery.data || null : null;
  const exactMissing = needsExact && exactQuery.data === null;
  const exactError = exactQuery.error ? String((exactQuery.error as Error).message || exactQuery.error) : "";
  const exactPending = needsExact && exactQuery.isPending;
  const rows = exact
    ? (pager.items.some((r) => r.id === exact.id) ? pager.items.map((r) => r.id === exact.id ? exact : r) : [exact, ...pager.items])
    : pager.items;
  const shown = selectedId ? [...rows].sort((a, b) => Number(b.id === selectedId) - Number(a.id === selectedId)) : rows;
  function exportCSV() {
    const rs = pager.items;
    const head = ["fired", "service", "attack", "mitre", "outcome", "actuator", "containment", "time_to_action_s", "dwell_s", "dwell_ongoing", "uptime_before", "uptime_dip", "uptime_after", "cost_without", "cost_r6", "cost_with", "savings", "why"];
    const body = rs.map((r) => isCatalogueSignalResult(r)
      ? [r.firedAt, r.service, r.attack, r.mitre, "CATALOGUE SIGNAL · UNSCORED", attackCSVActuator(r), "", "", "", "", "", "", "", "", "", "", "", "", r.observationError || r.stimulusEvidence?.limitation || "behavioral outcome not measured"]
      : [r.firedAt, r.service, r.attack, r.mitre, r.outcome || r.status, attackCSVActuator(r), r.containment, r.timeToDefendSec, r.dwellSec, r.dwellOngoing ? "ongoing" : "bounded", r.uptimeBefore, r.uptimeDip, r.uptimeAfter, r.cost?.without, r.cost?.r6, r.cost?.with, r.cost?.savings, r.why]);
    csvDownload("phorvex-attack-results-page.csv", [head, ...body]);
  }

  const typedBehavioralRows = pager.items.filter((r) => !isCatalogueSignalResult(r) && !isUnversionedResult(r));
  const defended = typedBehavioralRows.filter((r) => r.outcome === "DEFENDED").length;
  const landed = typedBehavioralRows.filter((r) => r.outcome === "LANDED").length;
  const signalRows = pager.items.filter(isCatalogueSignalResult).length;
  const unversionedRows = pager.items.filter(isUnversionedResult);
  const legacyDefended = unversionedRows.filter((r) => r.outcome === "DEFENDED").length;
  const legacyLanded = unversionedRows.filter((r) => r.outcome === "LANDED").length;
  const boundedRows = typedBehavioralRows.filter((r) => (r.containment === "evicted" || r.containment === "contained" || r.containment === "flushed") && r.dwellSec > 0);
  const meanDwell = boundedRows.length ? (boundedRows.reduce((a, r) => a + r.dwellSec, 0) / boundedRows.length).toFixed(1) : null;

  return (
    <div className="space-y-3">
      <div className="text-[11px] text-muted-foreground">Cluster-wide recorded attacks{compact ? " and mechanism observations" : ""} for this console; changing the selected target does not filter these rows.</div>
      <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search all attacks by ID, service, namespace, or attack…" aria-label="Search attack results" />
      {pager.legacy && <div className="text-[11px] text-warning">Legacy/preview response: paging and search cover the full history returned by this fixture.</div>}
      {pager.error && <div className="text-[11px] text-danger">Page refresh failed: {pager.error} <button className="text-primary" onClick={pager.retry}>Retry</button></div>}
      <DataFreshness updatedAt={pager.updatedAt} refreshing={pager.refreshing} failed={!!pager.error} />
      {!compact && (
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 text-[12px] font-medium"><Swords className="h-3.5 w-3.5 text-primary" /> Recorded results</div>
          <div className="text-[11px] text-muted-foreground">Current page: {pager.items.length} records · typed behavioral labels: <span className="text-success">{defended} defended</span> / <span className="text-danger">{landed} landed</span>{signalRows > 0 && <> · {signalRows} unscored catalogue signal{signalRows === 1 ? "" : "s"}</>}{meanDwell && <> · mean typed response time <span className="tabular text-foreground">{meanDwell}s</span></>}</div>
          {unversionedRows.length > 0 && <div className="basis-full text-[11px] text-warning">{unversionedRows.length} legacy/unversioned record{unversionedRows.length === 1 ? "" : "s"} preserve their historical labels ({legacyDefended} recorded DEFENDED / {legacyLanded} recorded LANDED); those labels are excluded from the typed summary and are not revalidated efficacy evidence.</div>}
          <Button size="sm" variant="outline" onClick={exportCSV} className="ml-auto gap-1.5"><Download className="h-3.5 w-3.5" /> CSV (page)</Button>
        </div>
      )}
      {exact && <div className="text-[11px] text-muted-foreground">The selected attack is refreshed independently for this frozen/older view; snapshot membership, page statistics, and CSV are unchanged.</div>}
      {selectedId && exactMissing && <div className="text-[11px] text-warning">Exact selected attack <span className="font-mono">{selectedId}</span> is missing; no other attack was substituted. <button className="text-primary" onClick={() => exactQuery.refetch()}>Retry</button></div>}
      {selectedId && exactError && <div className="text-[11px] text-danger">Could not load exact selected attack: {exactError} <button className="text-primary" onClick={() => exactQuery.refetch()}>Retry</button></div>}
      {exactPending && <div className="flex items-center gap-2 text-[11px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading exact selected attack…</div>}
      {pager.loading && !pager.pageMeta && <div className="flex items-center gap-2 py-8 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading attack results…</div>}
      {rows.length === 0 && !pager.loading && !pager.error && (selectedId
        ? (!exactMissing && !exactError && <div className="text-[12px] text-muted-foreground">Waiting for exact attack result <span className="font-mono">{selectedId}</span>…</div>)
        : <Empty msg={q ? "No recorded results match this search." : "No persisted results yet. Run a supported Live Operations control or a bounded Scenario Catalog observation; each record will show its measured evidence and explicit limitations here."} />)}
      {shown.map((r) => <AttackCard key={r.id} r={r} selected={r.id === selectedId} />)}
      <PaginationBar page={pager.page} pageSize={pageSize} total={pager.pageMeta?.total} hasNext={pager.hasNext} onPrevious={pager.previous} onNext={pager.next} onLatest={pager.latest} showLatest={pager.hasSnapshot || pager.page > 0} loading={pager.loading} />
    </div>
  );
}

// containmentInfo frames what the action actually did to the FOOTHOLD (not just "an action fired").
function containmentInfo(r: AttackResult): { tone: "good" | "warn" | "bad"; cls: string; line: string; dwellNote: string; bounded: boolean } {
  switch (r.containment) {
    case "evicted":
      return { tone: "good", cls: "text-success", line: `${r.pod} rotation recorded; wider attacker access unknown`, dwellNote: "recorded rotation-response time", bounded: true };
    case "contained":
      return { tone: "good", cls: "text-success", line: `${r.pod} quarantined — isolation attempt recorded; effect confirmation required`, dwellNote: "recorded isolation-response time", bounded: true };
    case "flushed":
      return { tone: "good", cls: "text-success", line: `${r.pod} cache reset recorded; wider attacker state unknown`, dwellNote: "recorded reset-response time", bounded: true };
    case "foothold-active":
      return { tone: "warn", cls: "text-warning", line: `neighbor ${r.defendedPod} isolation recorded; no removal evidence for ${r.pod}`, dwellNote: `no confirmed foothold removal or lateral-spread effect`, bounded: false };
    case "landed":
      return { tone: "bad", cls: "text-danger", line: "no defensive response recorded on the foothold", dwellNote: "removal is not confirmed", bounded: false };
    default:
      return { tone: "bad", cls: "text-muted-foreground", line: "", dwellNote: "", bounded: false };
  }
}

function AttackCard({ r, selected = false }: { r: AttackResult; selected?: boolean }) {
  const signal = isCatalogueSignalResult(r);
  const showSecurity = showSecurityOutcomeSections(r);
  const unversioned = isUnversionedResult(r);
  const running = r.status === "running";
  const partial = r.status === "partial";
  const defended = !signal && r.outcome === "DEFENDED";
  const landed = !signal && r.outcome === "LANDED";
  const effectOnly = !defended && !landed && r.effectEvidence?.observed === true;
  const confirmed = defended || landed;
  const cinfo = containmentInfo(r);
  return (
    <Card className={cn("border-l-2", selected && "ring-1 ring-primary/60", defended ? "border-l-success" : landed ? "border-l-danger" : "border-l-warning")}>
      <CardContent className="space-y-3 p-4">
        {/* header */}
        <div className="flex flex-wrap items-center gap-2">
          {selected && <Badge variant="accent">selected attack</Badge>}
          {signal ? <Badge variant="pending">CATALOGUE SIGNAL · UNSCORED</Badge>
            : unversioned && !running ? <Badge variant="neutral">RECORDED LEGACY LABEL · {r.outcome || r.status.toUpperCase()}</Badge>
            : running ? <Badge variant="modeled" className="gap-1"><Loader2 className="h-3 w-3 animate-spin" /> measuring…</Badge>
            : partial ? <Badge variant="pending">PARTIAL RECORD</Badge>
            : defended ? <Badge variant="real" className="gap-1"><ShieldCheck className="h-3 w-3" /> RESPONSE RECORDED</Badge>
              : landed ? <Badge variant="pending" className="gap-1"><ShieldAlert className="h-3 w-3" /> LANDED</Badge>
                : effectOnly ? <Badge variant="modeled">EFFECT OBSERVED · OUTCOME UNVERIFIED</Badge>
                  : <Badge variant="pending" className="gap-1"><ShieldAlert className="h-3 w-3" /> UNCONFIRMED</Badge>}
          <span className="font-mono text-[12px] font-medium text-foreground">{r.service}</span>
          <span className="text-[12px] text-muted-foreground">· {r.attack}</span>
          <span className="font-mono text-[10px] text-muted-foreground" title={r.id}>attack {r.id}</span>
          <span className="rounded border border-border bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{r.mitre}</span>
          {unversioned && <Badge variant="neutral">legacy · unversioned</Badge>}
          <span className="ml-auto font-mono text-[10px] text-muted-foreground/60">{new Date(r.firedAt).toLocaleTimeString()}</span>
        </div>

        <ClaimScopeNote claim={r.claim} />
        {unversioned && <div className="rounded-md border border-border/60 bg-muted/20 p-2 text-[11px] text-muted-foreground">Legacy/unversioned result: the recorded text is preserved, but it predates the typed catalogue-signal provenance contract and must not be reinterpreted as evidence for that producer.</div>}
        {signal && <CatalogueSignalResult result={r} />}
        {r.guardrailEffectProbe && <GuardrailEffectProbe result={r.guardrailEffectProbe} />}
        {r.guardrailOutputProbe && <GuardrailOutputProbe result={r.guardrailOutputProbe} />}
        {r.voiceMemoryProbe && <VoiceMemoryProbe result={r.voiceMemoryProbe} />}
        {!signal && (r.stimulusEvidence || r.effectEvidence) && (
          <div className="rounded-md border border-warning/30 bg-warning/[0.04] p-2.5 text-[11px]">
            <div className="font-medium text-warning">Mechanism evidence</div>
            {r.stimulusEvidence && <div className="mt-1 text-muted-foreground">unique stimulus <span className="font-mono text-foreground/85">{r.stimulusEvidence.eventName}</span> · target UID {r.stimulusEvidence.targetUid.slice(0, 12)}… · behavioral attack executed: {r.stimulusEvidence.behavioralExecuted ? "yes" : "no"}</div>}
            {r.effectEvidence && <div className="mt-1 text-muted-foreground">fresh exact-target effect: <span className="font-mono text-foreground/85">{r.effectEvidence.before || "—"} → {r.effectEvidence.after || "—"}</span> · correlation {r.effectEvidence.correlation}</div>}
            <div className="mt-1 text-warning/90">{r.effectEvidence?.limitation || r.stimulusEvidence?.limitation}</div>
          </div>
        )}
        {/* actuator line */}
        {showSecurity && <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px]">
          <span className="text-muted-foreground">{effectOnly ? "observed effect signature →" : "Phorvex →"}
            <span className={cn("ml-1 font-mono font-semibold", defended ? "text-success" : "text-foreground")}>{r.phorvexAction || "—"}</span>
          </span>
          {!r.phorvexAction && <span className="text-muted-foreground">expected <span className="font-mono text-foreground/80">{r.expectedActuator || "—"}</span> (not observed)</span>}
          {effectOnly && !r.guardrailEffectProbe && <span className="text-muted-foreground">in <span className="tabular text-foreground">{r.effectEvidence?.seconds}s</span> · controller attribution remains temporal</span>}
          {defended && r.timeToDefendSec > 0 && <span className="text-muted-foreground">in <span className="tabular text-foreground">{r.timeToDefendSec}s</span></span>}
          <span className="text-muted-foreground">target pod <span className="font-mono text-[11px] text-foreground/80">{r.pod?.split("-").slice(-1)[0]}</span></span>
          {!running && confirmed && cinfo.line && <span className={cinfo.cls}>{cinfo.line}</span>}
        </div>}

        {/* attacker dwell time — how long the intruder held effective access */}
        {showSecurity && <div>
          <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"><Clock className="h-3 w-3" /> recorded response timing</div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px]">
            {running
              ? <span className="text-muted-foreground">measuring…</span>
              : !confirmed
                ? <span className="text-warning">outcome not confirmed by the recorded result</span>
              : cinfo.bounded
                ? <><span className="tabular text-[15px] font-semibold text-success">{r.dwellSec}s</span><span className="text-muted-foreground">{cinfo.dwellNote}</span></>
                : <><span className="tabular text-[15px] font-semibold text-danger">≥ {r.dwellSec}s</span><span className="text-warning">ongoing — {cinfo.dwellNote}</span></>}
            <span className="ml-auto text-[10px] text-muted-foreground/60">Recorded response timing is not a bound on attacker access or out-of-band gains.</span>
          </div>
        </div>}

        {!signal && !!(r.decisionTraceEvidence?.length || r.temporalDecisionEvidence || r.decisionEvidence) && <DecisionEvidencePanel exact={r.decisionTraceEvidence} temporal={r.temporalDecisionEvidence} legacy={r.decisionEvidence} observationStartedAt={r.observationStartedAt} observationDeadline={r.observationDeadline} />}

        {/* uptime before / dip / after */}
        {showSecurity && <div>
          <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"><Activity className="h-3 w-3" /> availability</div>
          <div className="flex items-center gap-2 text-[12px]">
            <UpCell label="before" v={r.uptimeBefore} />
            <span className="text-muted-foreground/40">→</span>
            <UpCell label="dip" v={r.uptimeDip} warn />
            <span className="text-muted-foreground/40">→</span>
            <UpCell label="after" v={r.uptimeAfter} good={r.uptimeAfter >= 100} />
            <span className="ml-2 text-[11px] text-muted-foreground">{r.uptimeAfter >= 100 && r.uptimeDip < 100 ? "recovered — sibling replica kept serving" : r.uptimeDip >= 100 ? "no availability impact" : ""}</span>
          </div>
        </div>}

        {/* three-way cost */}
        {showSecurity && <div>
          <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground/70">annual cost exposure (real AWS $/yr) · <span className="text-muted-foreground/50">modelled from measured prevention rates — not this attack&apos;s outcome</span></div>
          <div className="grid grid-cols-3 gap-2">
            <CostCell label="Without any defense" v={r.cost?.without} tone="bad" max={r.cost?.without} />
            <CostCell label="R6 blind timer" v={r.cost?.r6} tone="warn" max={r.cost?.without} sub={r.stateful ? "destroys DB data" : "churns · blind rotation"} />
            <CostCell label="With Phorvex" v={r.cost?.with} tone="good" max={r.cost?.without} sub={(r.cost?.savings ?? 0) > 0 ? `saves $${fmt(r.cost?.savings)}/yr` : `costs $${fmt(Math.abs(r.cost?.savings ?? 0))}/yr more`} />
          </div>
          <CostBreakdown c={r.cost} />
        </div>}

        {/* reasoning */}
        {showSecurity && (r.why || r.r6Note) && (
          <div className="rounded-md border border-border/60 bg-elevated/30 p-2.5 text-[11px] leading-relaxed">
            {r.why && <div><span className="text-muted-foreground">why: </span><span className="font-mono text-foreground/85">{r.why}</span></div>}
            <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[10px] text-muted-foreground">
              {r.perDollar > 0 && <span>per-$={r.perDollar.toFixed(2)}</span>}
              {r.stage && <span>stage={r.stage}</span>}
              {r.coveredFacts > 0 && <span>facts={r.coveredFacts}</span>}
              {r.pHold > 0 && <span>pHold={r.pHold.toFixed(2)}</span>}
              <span>λ={r.lambda?.toFixed(2)}</span>
            </div>
            {r.r6Note && <div className="mt-1 text-warning/90"><span className="text-muted-foreground">R6 counterfactual: </span>{r.r6Note}</div>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function UpCell({ label, v, warn, good }: { label: string; v: number; warn?: boolean; good?: boolean }) {
  const bad = v >= 0 && v < 100;
  return (
    <div className="text-center">
      <div className={cn("tabular text-[13px] font-semibold", v < 0 ? "text-muted-foreground" : good ? "text-success" : warn && bad ? "text-warning" : bad ? "text-danger" : "text-foreground")}>{v < 0 ? "—" : `${v}%`}</div>
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground/60">{label}</div>
    </div>
  );
}

// CostBreakdown prints the ARITHMETIC behind the three totals. A reader should never have to take
// a dollar figure on trust: every input is named, sourced, and the formula is shown with this
// attack's own numbers substituted in.
function CostBreakdown({ c }: { c?: AttackCost }) {
  const [open, setOpen] = React.useState(false);
  if (!c || !c.nodeRatePerHr) return null;
  const pct = (x?: number) => `${((x ?? 0) * 100).toFixed(1)}%`;
  const d = (x?: number) => `$${fmt(x)}`;
  const Row = ({ k, v }: { k: string; v: React.ReactNode }) => (
    <div className="flex flex-wrap items-baseline gap-x-2 py-0.5">
      <span className="min-w-[150px] text-muted-foreground">{k}</span>
      <span className="font-mono text-[11px] text-foreground/90">{v}</span>
    </div>
  );
  return (
    <div className="mt-2">
      <button onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[11px] text-primary transition-colors hover:text-primary/80">
        <Calculator className="h-3 w-3" />
        {open ? "Hide" : "How was this calculated?"}
      </button>
      {open && (
        <div className="mt-2 space-y-2 rounded-md border border-border/60 bg-elevated/30 p-3 text-[11px] leading-relaxed">
          <div>
            <div className="mb-1 font-medium text-foreground">1 · What is at risk (real AWS price)</div>
            <Row k="attacked pod runs on" v={`${c.nodeInstance || "node"} @ ${d(c.nodeRatePerHr)}/hr`} />
            <Row k="value at risk / yr" v={`${d(c.nodeRatePerHr)}/hr x 8,760 hr = ${d(c.valueAtRisk)}`} />
            <div className="mt-1 text-muted-foreground/80">
              This is your live AWS on-demand price for the hardware the attack compromises — not a
              breach/reputation estimate.
            </div>
          </div>
          <div>
            <div className="mb-1 font-medium text-foreground">2 · How often each defender actually stops an attack</div>
            <Row k="no defense" v={pct(c.preventNone)} />
            <Row k="R6 blind timer" v={pct(c.preventR6)} />
            <Row k="Phorvex" v={pct(c.preventPhorvex)} />
            <div className="mt-1 text-muted-foreground/80">Measured, not assumed: {c.ratesSource}</div>
          </div>
          <div>
            <div className="mb-1 font-medium text-foreground">3 · The arithmetic</div>
            <Row k="without any defense" v={`${d(c.valueAtRisk)} x (1 - ${pct(c.preventNone)}) = ${d(c.without)}`} />
            <Row k="R6 blind timer" v={`${d(c.valueAtRisk)} x (1 - ${pct(c.preventR6)}) + ${d(c.r6Churn)} churn = ${d(c.r6)}`} />
            <Row k="with Phorvex" v={`${d(c.valueAtRisk)} x (1 - ${pct(c.preventPhorvex)}) + ${d(c.operatorCost)} operator = ${d(c.with)}`} />
            <Row k="difference" v={`${d(c.without)} - ${d(c.with)} = ${d(c.savings)}/yr`} />
          </div>
          <div className="border-t border-border/50 pt-2 text-muted-foreground/80">
            These three are an ANNUAL projection using each defender&apos;s measured stop-rate — they answer
            &quot;what does a year of this cost?&quot;, not &quot;what did this one attack cost?&quot;. This attack&apos;s own
            result is the DEFENDED/LANDED badge and the dwell time above.
          </div>
        </div>
      )}
    </div>
  );
}

function CostCell({ label, v, max, tone, sub }: { label: string; v: number; max: number; tone: "bad" | "warn" | "good"; sub?: string }) {
  const pct = max > 0 ? Math.max(3, Math.min(100, (v / max) * 100)) : 3;
  const bar = tone === "bad" ? "bg-danger" : tone === "warn" ? "bg-warning" : "bg-success";
  const txt = tone === "bad" ? "text-danger" : tone === "warn" ? "text-warning" : "text-success";
  return (
    <div className="rounded-md border border-border/60 bg-panel/40 p-2">
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground/70">{label}</div>
      <div className={cn("tabular text-[15px] font-semibold", txt)}>${fmt(v)}<span className="text-[10px] font-normal text-muted-foreground">/yr</span></div>
      <div className="mt-1 h-1 overflow-hidden rounded bg-border/50"><div className={cn("h-full rounded", bar)} style={{ width: `${pct}%` }} /></div>
      {sub && <div className="mt-1 text-[9px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

function fmt(n?: number) {
  if (n == null) return "—";
  return Math.round(n).toLocaleString();
}
