"use client";
import * as React from "react";
import { Lens, liveStream } from "@/lib/api";
import { decisionEconomics, exactNumber } from "@/lib/economics";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Loader2, Eye, Cpu, Zap, ArrowRight, Pause, Play, ShieldCheck, ShieldOff, Scale } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSelectedTarget } from "@/lib/provider-store";
import { useLocalPage } from "@/lib/use-local-page";
import { PaginationBar } from "@/components/ui/pagination";

/* BrainBreakdown — the whole decision, end to end, for one real tick.
 *
 * Every number on this screen comes from the operator's own decision audit (the same record the
 * engine writes when it decides). Nothing is recomputed in the browser and nothing is invented:
 * if a field is absent from the record it renders as "—" rather than as a plausible-looking value.
 *
 * Three stages, in the order the engine actually runs them:
 *   INPUT      what it observed about this pod
 *   PROCESSING how it scored every candidate and priced the winner
 *   OUTPUT     what it decided, and what a blind rotator would have done instead
 */

type Rec = Record<string, any>;

const n = (v: any, d = 2) => (typeof v === "number" && isFinite(v) ? v.toFixed(d) : "—");
const pct = (v: any) => (typeof v === "number" && isFinite(v) ? `${(v * 100).toFixed(0)}%` : "—");

export function BrainBreakdownPanel({ lens }: { lens: Lens }) {
  const target = useSelectedTarget();
  const [recs, setRecs] = React.useState<Rec[]>([]);
  const [snapshot, setSnapshot] = React.useState<Rec[] | null>(null);
  const [newCount, setNewCount] = React.useState(0);
  const [live, setLive] = React.useState(true);
  const [sel, setSel] = React.useState<Rec | null>(null);
  const [flash, setFlash] = React.useState(0);
  const [dataScope, setDataScope] = React.useState("");
  const [streamError, setStreamError] = React.useState("");
  const [noJournal, setNoJournal] = React.useState(false);
  const liveRef = React.useRef(live);
  const snapshotRef = React.useRef<Rec[] | null>(null);
  const scopeKey = `${lens}\u0000${target.context}`;

  React.useEffect(() => {
    let alive = true;
    liveRef.current = true;
    snapshotRef.current = null;
    setRecs([]); setSnapshot(null); setNewCount(0); setSel(null); setLive(true); setFlash(0);
    setStreamError(""); setNoJournal(false);
    const idleTimer = setTimeout(() => { if (alive) setNoJournal(true); }, 15_000);
    const stop = liveStream(lens, (d) => {
      if (!alive || d?.kind !== "phorvex.decision") return;
      clearTimeout(idleTimer);
      setStreamError(""); setNoJournal(false);
      setDataScope(scopeKey);
      setRecs((prev) => [d, ...prev].slice(0, 60));
      if (snapshotRef.current) setNewCount((count) => count + 1);
      if (liveRef.current) { setSel(d); setFlash((f) => f + 1); }
    }, undefined, 40, target.context, (error) => { if (alive) setStreamError(error.message); });
    return () => { alive = false; liveRef.current = false; clearTimeout(idleTimer); stop(); };
  }, [lens, target.context, scopeKey]);

  const decisionList = dataScope === scopeKey ? (snapshot ?? recs) : [];
  const decisionPage = useLocalPage(decisionList, 12, scopeKey);
  const freezeHistory = () => {
    if (snapshotRef.current) return;
    const frozen = recs.slice(0, 60);
    snapshotRef.current = frozen;
    setSnapshot(frozen);
    setNewCount(0);
  };
  const showLatest = () => {
    snapshotRef.current = null;
    setSnapshot(null);
    setNewCount(0);
    decisionPage.setPage(0);
    if (liveRef.current && recs[0]) { setSel(recs[0]); setFlash((f) => f + 1); }
  };

  if (!sel || dataScope !== scopeKey) {
    return (
      <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
        {streamError ? <span role="alert">Decision stream unavailable: {streamError}. No decision journal is available in this view.</span>
          : noJournal ? <span>No decision journal entry received for this context yet. The operator&apos;s decision state is unverified here.</span>
          : <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Waiting for a decision journal entry…</>}
      </div>
    );
  }

  const selected = !!sel.selected;
  const actuated = !!sel.actuated;
  const isNoop = (sel.action || "noop") === "noop";
  const economics = decisionEconomics(sel);

  return (
    <div className="space-y-4">
      {streamError && <div role="alert" className="text-[12px] text-warning">Decision stream unavailable: {streamError}. Showing the last received journal entry; current decisions are unverified.</div>}
      {/* header + live control */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-[13px] font-medium">
          <Cpu className="h-4 w-4 text-primary" /> Brain breakdown
        </div>
        <span className="text-[11px] text-muted-foreground">
          every value below is read from the operator&apos;s own decision audit — nothing is recomputed here
        </span>
        <button onClick={() => {
          const nextLive = !liveRef.current;
          liveRef.current = nextLive;
          setLive(nextLive);
          if (nextLive && recs[0]) { setSel(recs[0]); setFlash((f) => f + 1); }
        }}
          className={cn("ml-auto flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11px] transition-colors",
            live ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-elevated/40 text-muted-foreground")}>
          {live ? <><Play className="h-3 w-3" /> following incoming decisions</> : <><Pause className="h-3 w-3" /> frozen selection</>}
        </button>
      </div>

      {/* the pipeline */}
      <div key={flash} className="grid gap-3 lg:grid-cols-[1fr_auto_1fr_auto_1fr]">
        <Stage n={1} title="Input" sub="what it observed" Icon={Eye} tone="input" delay={0}>
          <KV k="workload" v={`${sel.namespace}/${(sel.pod || "").split("-").slice(-1)[0]}`} mono />
          <KV k="node" v={(sel.node || "—").split(".")[0]} mono dim />
          <KV k="phase" v={sel.phase || "—"} />
          <Sep label="kill-chain" />
          <KV k="stage" v={`${sel.stage || "—"} → ${sel.nextStage || "—"}`} />
          <Bar k="stage hazard" v={sel.stageHazard} />
          <Bar k="p(hold)" v={sel.pHold} />
          <KV k="projected next stage" v={typeof sel.projectedNextStageSec === "number" && sel.projectedNextStageSec > 0 ? `${n(sel.projectedNextStageSec, 0)}s` : "already due"} />
          <Sep label="asset & exposure" />
          <KV k="asset value" v={n(sel.assetValue)} />
          <Bar k="blast radius" v={sel.blastRadius} />
          <KV k="exposure" v={n(sel.exposure)} />
          <KV k="belief" v={n(sel.belief)} />
          <KV k="threat posture" v={n(sel.threatPosture)} />
          <KV k="physics residual" v={n(sel.residual)} />
          <Sep label="modeled selection opportunity · not measured mitigation" />
          <KV k="modeled covered facts" v={String(sel.coveredFacts ?? "—")} />
          <KV k="modeled selection weight" v={n(sel.coveredWeight)} />
          <KV k="SLO headroom" v={n(sel.sloHeadroom)} />
        </Stage>

        <Flow delay={150} />

        <Stage n={2} title="Processing" sub="how it scored the move" Icon={Scale} tone="proc" delay={150}>
          <KV k="engine" v={sel.engine || "—"} mono />
          <Sep label="the value of acting" />
          <KV k="modeled coverage opportunity" v={n(sel.risk)} strong />
          {Array.isArray(sel.attribution) && sel.attribution.length > 0 && (
            <div className="my-1.5 space-y-1 rounded border border-border/50 bg-panel/40 p-2">
              <div className="text-[9px] uppercase tracking-wide text-muted-foreground/70">where that value came from</div>
              {sel.attribution.map((a: any, i: number) => (
                <Attrib key={i} source={a.source} value={a.contribution} delay={220 + i * 90} />
              ))}
            </div>
          )}
          <Sep label="the price of acting" />
          <KV k="ECost (unitless)" v={n(sel.cost)} strong />
          <KV k="objective version" v={economics.version} mono />
          {economics.independent ? <>
            <KV k="βNorm (fixed preference)" v={exactNumber(economics.norm)} strong />
            <KV k="βFlow (fixed preference)" v={exactNumber(economics.flow)} strong />
          </> : <KV k="common cost coefficient" v={exactNumber(economics.coefficient)} strong />}
          <KV k="λ (legacy move pressure)" v={exactNumber(economics.lambda)} dim />
          <KV k="proactive rate" v={economics.independent ? "—" : n(sel.proactiveRate, 4)} dim />
          <Sep label="recorded objective" />
          <div className="my-1 text-[10px] text-muted-foreground">{economics.formula}. Selection also depends on marginal coverage, gates and budgets; λ is not a resource shadow price.</div>
          <KV k="recorded net" v={n(sel.net, 4)} />
          <KV k="feasible?" v={sel.feasible ? "yes — passed the SLO gate" : "NO — vetoed"} bad={!sel.feasible} />
        </Stage>

        <Flow delay={320} />

        <Stage n={3} title="Output" sub="what it decided" Icon={Zap} tone="out" delay={320}>
          <div className="mb-2 flex flex-wrap items-center gap-1.5">
            {isNoop
              ? <Badge variant="pending" className="gap-1"><ShieldOff className="h-3 w-3" /> no action</Badge>
              : <Badge variant={actuated ? "real" : "modeled"} className="gap-1"><ShieldCheck className="h-3 w-3" /> {sel.action}</Badge>}
            {selected && <Badge variant="modeled">selected</Badge>}
            {sel.dryRun && <Badge variant="pending">dry-run</Badge>}
          </div>
          <KV k="action" v={sel.action || "noop"} mono strong />
          <KV k="selected" v={selected ? "yes" : "no"} />
          <KV k="actuated on cluster" v={actuated ? "yes — really executed" : "no"} bad={selected && !actuated && !sel.dryRun} />
          <Sep label="why, in the engine's words" />
          <div className="rounded border border-border/50 bg-panel/40 p-2 font-mono text-[10px] leading-relaxed text-foreground/85">
            {sel.reason || "—"}
          </div>
          <Sep label="what a blind rotator would do" />
          <KV k="R6 would" v={sel.r6Counterfactual || "—"} mono />
          <KV k="its cost this cycle" v={n(sel.blindCost)} />
          {sel.counterfactualNote && (
            <div className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{sel.counterfactualNote}</div>
          )}
          {sel.infeasibleWhy && (
            <div className="mt-1 rounded border border-danger/40 bg-danger/5 p-2 text-[10px] text-danger">{sel.infeasibleWhy}</div>
          )}
        </Stage>
      </div>

      {/* recent ticks — click to freeze and inspect one */}
      <div>
        <div className="mb-1.5 text-[11px] text-muted-foreground">
          {snapshot ? `frozen history (${decisionList.length} decisions) · ${newCount} new since snapshot` : `incoming decisions (${recs.length} buffered)`}; click one to keep that selection frozen while new decisions continue buffering
        </div>
        <div className="flex flex-wrap gap-1.5">
          {decisionPage.pageItems.map((r, i) => {
            const act = r.action || "noop";
            const on = sel === r;
            return (
              <button key={`${r.time || r.Time || "decision"}-${decisionPage.start + i}`} onClick={() => { liveRef.current = false; setLive(false); setSel(r); setFlash((f) => f + 1); }}
                className={cn("rounded border px-2 py-1 font-mono text-[10px] transition-colors",
                  on ? "border-primary bg-primary/15 text-primary"
                    : act === "noop" ? "border-border bg-elevated/30 text-muted-foreground hover:bg-elevated/60"
                      : "border-success/40 bg-success/10 text-success hover:bg-success/20")}>
                {new Date(r.time).toLocaleTimeString()} · {r.tenant} · {act}
              </button>
            );
          })}
        </div>
        <div className="mt-2">
          <PaginationBar page={decisionPage.page} pageSize={12} total={decisionList.length} hasNext={decisionPage.hasNext} onPrevious={() => decisionPage.setPage((p) => Math.max(0, p - 1))} onNext={() => { freezeHistory(); decisionPage.setPage((p) => p + 1); }} onLatest={showLatest} showLatest={!!snapshot} />
        </div>
      </div>
    </div>
  );
}

/* ---------- pieces ---------- */

function Stage({ n: num, title, sub, Icon, tone, delay, children }: {
  n: number; title: string; sub: string; Icon: any; tone: "input" | "proc" | "out"; delay: number; children: React.ReactNode;
}) {
  const ring = tone === "input" ? "border-t-primary" : tone === "proc" ? "border-t-warning" : "border-t-success";
  const txt = tone === "input" ? "text-primary" : tone === "proc" ? "text-warning" : "text-success";
  return (
    <Card className={cn("border-t-2 motion-safe:animate-fade-up", ring)} style={{ animationDelay: `${delay}ms` }}>
      <CardContent className="p-3.5">
        <div className="mb-2.5 flex items-center gap-2 border-b border-border/60 pb-2">
          <span className={cn("flex h-5 w-5 items-center justify-center rounded-full border text-[10px] font-semibold", txt)}>{num}</span>
          <Icon className={cn("h-4 w-4", txt)} />
          <div>
            <div className="text-[12px] font-semibold text-foreground">{title}</div>
            <div className="text-[10px] text-muted-foreground">{sub}</div>
          </div>
        </div>
        <div className="space-y-0.5">{children}</div>
      </CardContent>
    </Card>
  );
}

function Flow({ delay }: { delay: number }) {
  return (
    <div className="hidden items-center justify-center lg:flex">
      <ArrowRight className="h-4 w-4 text-muted-foreground/50 motion-safe:animate-fade-up"
        style={{ animationDelay: `${delay}ms` }} />
    </div>
  );
}

function KV({ k, v, mono, strong, dim, bad }: { k: string; v: string; mono?: boolean; strong?: boolean; dim?: boolean; bad?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-2 py-0.5 text-[11px]">
      <span className={cn("text-muted-foreground", dim && "text-muted-foreground/60")}>{k}</span>
      <span className={cn("tabular text-right", mono && "font-mono", strong && "font-semibold text-foreground",
        bad ? "text-danger" : !strong && "text-foreground/90")}>{v}</span>
    </div>
  );
}

function Sep({ label }: { label: string }) {
  return (
    <div className="mb-1 mt-2.5 border-t border-border/50 pt-1.5 text-[9px] uppercase tracking-wider text-muted-foreground/60">
      {label}
    </div>
  );
}

// Bar renders a 0..1 quantity as both a number and a proportion, so magnitudes read at a glance.
function Bar({ k, v }: { k: string; v: any }) {
  const ok = typeof v === "number" && isFinite(v);
  const w = ok ? Math.max(0, Math.min(100, v * 100)) : 0;
  return (
    <div className="py-0.5">
      <div className="flex items-baseline justify-between gap-2 text-[11px]">
        <span className="text-muted-foreground">{k}</span>
        <span className="tabular font-mono text-foreground/90">{ok ? v.toFixed(2) : "—"}</span>
      </div>
      <div className="mt-0.5 h-1 overflow-hidden rounded bg-border/50">
        <div className="h-full rounded bg-primary/70 motion-safe:transition-all motion-safe:duration-700" style={{ width: `${w}%` }} />
      </div>
    </div>
  );
}

// Attrib shows one contribution to the score — positive terms add value, the cost term subtracts.
function Attrib({ source, value, delay }: { source: string; value: number; delay: number }) {
  const neg = value < 0;
  const mag = Math.min(100, Math.abs(value) * 22);
  return (
    <div className="motion-safe:animate-fade-up" style={{ animationDelay: `${delay}ms` }}>
      <div className="flex items-baseline justify-between gap-2 text-[10px]">
        <span className="font-mono text-muted-foreground">{source}</span>
        <span className={cn("tabular font-mono", neg ? "text-danger" : "text-success")}>
          {neg ? "" : "+"}{value.toFixed(3)}
        </span>
      </div>
      <div className="mt-0.5 h-1 overflow-hidden rounded bg-border/50">
        <div className={cn("h-full rounded motion-safe:transition-all motion-safe:duration-700", neg ? "bg-danger/70" : "bg-success/70")}
          style={{ width: `${mag}%` }} />
      </div>
    </div>
  );
}
