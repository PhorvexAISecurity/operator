"use client";
import * as React from "react";
import { api, Lens, CatalogItem, ClusterTarget, RunStatus, RunEvidence, AttackResult } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Segmented, Input, Dialog, Loading, ErrorBox, Empty } from "@/components/ui/more";
import { PageHead, SectionLabel } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Search, Play, Loader2, ShieldCheck, Cpu, Boxes } from "lucide-react";
import { clearLiveSelection, selectLiveRecord } from "@/lib/live-selection";
import { useLocalPage } from "@/lib/use-local-page";
import { PaginationBar } from "@/components/ui/pagination";
import { useCatalog, useTargets } from "@/lib/query";
import { setSelectedTarget } from "@/lib/provider-store";

const r6Variant = (t: string) => (t.includes("Covers") ? "real" : t.includes("Partial") ? "modeled" : "danger");

export function CatalogPanel({ lens }: { lens: Lens }) {
  const [target, setTarget] = React.useState("");
  const [prod, setProd] = React.useState<"all" | CatalogItem["product"]>("all");
  const [q, setQ] = React.useState("");
  const [sel, setSel] = React.useState<CatalogItem | null>(null);

  const catalogQuery = useCatalog(lens);
  const targetQuery = useTargets(lens);
  const visibleItems = catalogQuery.data?.items || null;
  const visibleTargets = targetQuery.data?.targets || [];
  React.useEffect(() => { setTarget(""); setSel(null); }, [lens]);
  const filtered = (visibleItems ?? []).filter((it) => {
    const query = q.trim().toLowerCase();
    return (prod === "all" || it.product === prod) && (!query || it.name.toLowerCase().includes(query) || (it.techniques ?? []).join(" ").toLowerCase().includes(query));
  });
  const catalogPage = useLocalPage(filtered, 20, `${lens}\u0000${prod}\u0000${q}`);

  if (catalogQuery.error) return <ErrorBox msg={String((catalogQuery.error as Error).message || catalogQuery.error)} />;
  if (!visibleItems) return <Loading label="Enumerating the attack catalog from the harness registry…" rows={6} />;

  const counts = { all: visibleItems.length, k8s: visibleItems.filter((i) => i.product === "k8s").length, ai: visibleItems.filter((i) => i.product === "ai").length, structural: visibleItems.filter((i) => i.product === "structural").length, application: visibleItems.filter((i) => i.product === "application").length, platform: visibleItems.filter((i) => i.product === "platform").length };

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title="Scenario Catalog" sub={`${visibleItems.length} registered attack and benign functional scenarios, enumerated live from the harness registry. Each entry states whether it measures a security comparison or a bounded functional fixture.`} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented value={prod} onChange={setProd} tabs={[{ id: "all", label: "All", count: counts.all }, { id: "k8s", label: "K8s", count: counts.k8s }, { id: "ai", label: "AI / Inference", count: counts.ai }, { id: "application", label: "Applications", count: counts.application }, { id: "platform", label: "Platform", count: counts.platform }, { id: "structural", label: "Structural", count: counts.structural }]} />
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name or ATT&CK ID…" className="pl-8" />
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
        <span>Target:</span>
        {visibleTargets.map((t) => (
          <button type="button" key={t.id} onClick={() => t.runnable && setTarget(t.id)} disabled={!t.runnable} title={t.note} aria-pressed={target === t.id}
            className={cn("rounded-md border px-2.5 py-1 transition-colors", target === t.id ? "border-primary/50 bg-primary/[0.06] text-foreground" : "border-border text-muted-foreground", !t.runnable && "opacity-50")}>
            {t.label}{!t.runnable && <span className="ml-1 text-warning">·pending</span>}
          </button>
        ))}
      </div>
      {filtered.length === 0 ? <Empty msg="No scenarios match." /> : (
        <>
          <div className="text-[12px] text-muted-foreground">{filtered.length} matching scenarios</div>
          <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
            {catalogPage.pageItems.map((it) => <ScenarioRow key={it.entryID || it.name} it={it} onOpen={() => setSel(it)} />)}
          </div>
          <PaginationBar page={catalogPage.page} pageSize={20} total={filtered.length} hasNext={catalogPage.hasNext} onPrevious={() => catalogPage.setPage((p) => Math.max(0, p - 1))} onNext={() => catalogPage.setPage((p) => p + 1)} />
        </>
      )}
      <ScenarioDialog item={sel} target={visibleTargets.find((entry) => entry.id === target) || null} lens={lens} onClose={() => setSel(null)} />
    </div>
  );
}

function ScenarioRow({ it, onOpen }: { it: CatalogItem; onOpen: () => void }) {
  const Icon = it.product === "ai" ? Cpu : it.product === "structural" ? Boxes : ShieldCheck;
  return (
    <Card className="cursor-pointer transition-colors hover:border-border/80" onClick={onOpen}>
      <CardContent className="flex items-start gap-3 p-3.5">
        <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", it.product === "ai" ? "text-info" : it.product === "structural" ? "text-warning" : "text-primary")} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[13px] text-foreground">{it.name}</span>
            <Badge variant={r6Variant(it.r6Tag) as any}>{it.r6Tag.replace("R6", "")}</Badge>
            {it.hasRun && <Badge variant="accent">ran</Badge>}
            {it.benignControl ? <Badge variant="neutral">benign functional</Badge> : it.product === "ai" && <Badge variant="pending">SP-0</Badge>}
            {it.available === false && <Badge variant="pending">unavailable</Badge>}
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground/70">{it.category}</span>
            {(it.techniques ?? []).slice(0, 4).map((t) => <span key={t} className="rounded bg-muted/40 px-1.5 text-[10px] font-mono text-muted-foreground">{t}</span>)}
            {(it.caps ?? []).includes("CapGPU") && <span className="rounded bg-info/10 px-1.5 text-[10px] text-info">GPU</span>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ScenarioDialog({ item, target, lens, onClose }: { item: CatalogItem | null; target: ClusterTarget | null; lens: Lens; onClose: () => void }) {
  const [running, setRunning] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [fixedRun, setFixedRun] = React.useState<{ id: string; context: string } | null>(null);
  const [fixedStatus, setFixedStatus] = React.useState<RunStatus | null>(null);
  const [fixedEvidence, setFixedEvidence] = React.useState<RunEvidence | null>(null);
  const [fixedReadError, setFixedReadError] = React.useState("");
  const [effectRecordId, setEffectRecordId] = React.useState("");
  const [effectResult, setEffectResult] = React.useState<AttackResult | null>(null);
  const [effectReadError, setEffectReadError] = React.useState("");
  const requestGeneration = React.useRef(0);
  const requestContext = `${item?.name || ""}\u0000${target?.id || ""}\u0000${target?.context || ""}\u0000${lens}`;
  const currentContext = React.useRef(requestContext);
  if (currentContext.current !== requestContext) {
    currentContext.current = requestContext;
    requestGeneration.current++;
  }
  React.useEffect(() => {
    requestGeneration.current++;
    setRunning(""); setMsg(""); setFixedRun(null); setFixedStatus(null); setFixedEvidence(null); setFixedReadError(""); setEffectRecordId(""); setEffectResult(null); setEffectReadError("");
  }, [item?.name, target?.id, target?.context, lens]);
  React.useEffect(() => () => { requestGeneration.current++; }, []);
  React.useEffect(() => {
    if (!fixedRun) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const status = await api.runStatus(fixedRun.id, lens);
        if (!active) return;
        setFixedStatus(status); setFixedReadError("");
        if (["done", "error", "partial", "stopped"].includes(status.state)) {
          try { const evidence = await api.runEvidence(fixedRun.id, lens); if (active) setFixedEvidence(evidence); }
          catch (error: any) { if (active) setFixedReadError(String(error?.message || error)); }
          return;
        }
      } catch (error: any) {
        if (active) setFixedReadError(String(error?.message || error));
      }
      if (active) timer = setTimeout(poll, 2000);
    };
    void poll();
    return () => { active = false; if (timer) clearTimeout(timer); };
  }, [fixedRun, lens]);
  React.useEffect(() => {
    if (!effectRecordId) return;
    const request = requestGeneration.current;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let tries = 0;
    const poll = async () => {
      tries++;
      try {
        const page = await api.attackResultsPage(lens, 1, { id: effectRecordId, includeObservations: "true" });
        if (!active || request !== requestGeneration.current) return;
        const exact = (page.attacks || []).find((entry) => entry.id === effectRecordId);
        if (exact) {
          setEffectResult(exact); setEffectReadError("");
          if (exact.status === "done" || exact.status === "partial") return;
        }
      } catch (error: any) {
        if (!active || request !== requestGeneration.current) return;
        setEffectReadError(String(error?.message || error));
      }
      if (active && tries < 40) timer = setTimeout(poll, 3000);
      else if (active) setEffectReadError((current) => current || `No terminal exact result was confirmed for ${effectRecordId} within the bounded polling window.`);
    };
    void poll();
    return () => { active = false; if (timer) clearTimeout(timer); };
  }, [effectRecordId, lens]);
  if (!item) return null;
  async function run(withPX: boolean) {
    if (lens !== "operator" || item!.available === false) return;
    const scenario = item!.name;
    const selectedTarget = target;
    const selectedLens = lens;
    const selectedContext = requestContext;
    const request = ++requestGeneration.current;
    setRunning(withPX ? "px" : "nopx"); setMsg("");
    if (selectedTarget?.context) clearLiveSelection(selectedLens, selectedTarget.context);
    try {
      if (item!.launchKind === "fixed-suite") {
        const { id, context } = await api.startFunctional(item!.profile || item!.entryID || item!.name, selectedLens);
        if (request !== requestGeneration.current || selectedContext !== currentContext.current) return;
        setFixedRun({ id, context }); setFixedStatus(null); setFixedEvidence(null); setFixedReadError("");
        if (selectedTarget?.context === context) selectLiveRecord({ kind: "run", id, lens: selectedLens, context });
        setMsg(`Started ${id}. Its result reports the functional oracle, evidence, cleanup, and claim limits.`);
        return;
      }
      if (item!.launchKind === "live-vllm-effect") {
        const result = await api.vllmAttack("guardrail-rotate", selectedLens);
        if (!result.attackId) throw new Error("guardrail effect launch returned no correlated attack ID");
        if (request !== requestGeneration.current || selectedContext !== currentContext.current) return;
        const context = item!.runtimeContext || "in-cluster";
        if (selectedTarget?.context === context) selectLiveRecord({ kind: "attack", id: result.attackId, lens: selectedLens, context });
        setEffectRecordId(result.attackId); setEffectResult(null); setEffectReadError("");
        setMsg(`Started ${result.attackId}. The result is effect-only and does not establish behavioral mitigation.`);
        return;
      }
      if (!selectedTarget?.runnable || !selectedTarget.id || !selectedTarget.context) throw new Error("Select a runnable target for this harness scenario.");
      const { id } = await api.startScenario(scenario, withPX, selectedTarget.id, "", selectedLens, false, selectedTarget.context);
      if (request !== requestGeneration.current || selectedContext !== currentContext.current) return;
      setSelectedTarget({ context: selectedTarget.context, provider: selectedTarget.provider, label: selectedTarget.label });
      selectLiveRecord({ kind: "run", id, lens: selectedLens, context: selectedTarget.context });
      setMsg(`Launched ${id} on ${selectedTarget.label || selectedTarget.id} — watch Run Attack Agents / Live Operations.`);
    }
    catch (e: any) { if (request === requestGeneration.current && selectedContext === currentContext.current) setMsg(String(e.message || e)); }
    finally { if (request === requestGeneration.current && selectedContext === currentContext.current) setRunning(""); }
  }
  const runnable = lens === "operator" && item.available !== false && (item.launchKind === "fixed-suite" || item.launchKind === "live-vllm-effect" || (!!target?.runnable && !!target.id && !!target.context));
  return (
    <Dialog open={!!item} onClose={() => { requestGeneration.current++; setRunning(""); setMsg(""); onClose(); }} title={item.name}>
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant="neutral">{item.category}</Badge>
          <Badge variant={r6Variant(item.r6Tag) as any}>Without-PX {item.r6Tag.replace("R6", "")}</Badge>
          <Badge variant={item.product === "ai" ? "modeled" : "accent"}>{item.product.toUpperCase()}</Badge>
          {item.benignControl && <Badge variant="neutral">security outcome not applicable</Badge>}
        </div>
        <div>
          <SectionLabel>ATT&amp;CK techniques</SectionLabel>
          <div className="flex flex-wrap gap-1.5">{(item.techniques ?? []).length === 0 ? <span className="text-[12px] text-muted-foreground">none tagged</span> : (item.techniques ?? []).map((t) => <span key={t} className="rounded bg-muted/40 px-2 py-0.5 text-[12px] font-mono text-foreground/80">{t}</span>)}</div>
        </div>
        {item.benignControl
          ? <div className="rounded-md border border-border bg-muted/20 p-3 text-[12px] text-muted-foreground">{item.launchKind === "fixed-suite" ? "Bounded functional control. It reports only the case-specific service, fixture, or console boundary named below, plus cleanup and explicit limits; it does not establish attack or defense efficacy." : item.launchKind === "live-vllm-effect" ? "Bounded installed effect observation. A fresh exact-target state transition is separate from behavioral mitigation, which this entry does not measure." : "Benign synthetic harness control. It does not establish an attack, defense efficacy, ROI, or behavior of the installed service."} {item.meaningfulWhen}</div>
          : item.product === "ai" && <div className="rounded-md border border-warning/25 bg-warning/[0.05] p-3 text-[12px] text-muted-foreground">AI scenario — the attack surface is real; Phorvex's <span className="text-foreground">defense efficacy is [SP-0-PENDING-P4]</span>, validated on real GPU at P4. No AI effectiveness is implied here.</div>}
        {item.unavailableReason && <div className="text-[11px] text-muted-foreground">{item.unavailableReason}</div>}
        <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4">
          {item.launchKind === "fixed-suite" || item.launchKind === "live-vllm-effect" ? <Button onClick={() => run(true)} disabled={!!running || !runnable}>{running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} {item.launchKind === "fixed-suite" ? "Run bounded functional check" : "Run bounded effect observation"}</Button> : <>
          <Button onClick={() => run(true)} disabled={!!running || !runnable}>{running === "px" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} {item.benignControl ? "Run synthetic fixture · PX/no-action arms" : "Run with Phorvex"}</Button>
          <Button variant="outline" onClick={() => run(false)} disabled={!!running || !runnable}>{running === "nopx" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} {item.benignControl ? "Run synthetic fixture · baseline arms" : "Run without (baseline)"}</Button>
          </>}
          <span className="text-[11px] text-muted-foreground">{item.launchKind === "harness-scenario" || !item.launchKind ? `target: ${target?.label || target?.id || "none selected"}` : "destination: fixed by the server profile"}</span>
        </div>
        {lens !== "operator" && <div className="text-[11px] text-muted-foreground">Scenario launch is available in the operator view.</div>}
        {msg && <div className="text-[12px] text-primary">{msg}</div>}
        {fixedRun && <div className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
          <div className="font-mono text-foreground">run {fixedRun.id}</div>
          <div className="mt-1 text-muted-foreground">server profile context: <span className="font-mono text-foreground/85">{fixedRun.context}</span> · state: <span className="text-foreground">{fixedStatus?.state || "starting"}</span></div>
          {fixedStatus?.error && <div className="mt-1 text-warning">{fixedStatus.error}</div>}
          {fixedEvidence?.functionalResult && <div className="mt-2 space-y-1 border-t border-border pt-2">
            <div>typed outcome: <span className="font-medium text-foreground">{fixedEvidence.functionalResult.outcome}</span> · cleanup: <span className="text-foreground">{fixedEvidence.functionalResult.cleanup.status}</span></div>
            <div className="text-foreground">{fixedEvidence.functionalResult.summary}</div>
            <div className="text-muted-foreground">limits: {fixedEvidence.functionalResult.limits.join(" · ")}</div>
          </div>}
          {(fixedEvidence?.issues || []).map((issue) => <div key={`${issue.line}-${issue.reason}`} className="mt-1 text-warning">unverified evidence: {issue.reason}</div>)}
          {fixedEvidence && !fixedEvidence.functionalResult && (fixedEvidence.issues || []).length === 0 && <div className="mt-1 text-warning">terminal evidence is incomplete; no functional outcome is accepted</div>}
          {fixedReadError && <div className="mt-1 text-warning">result read incomplete: {fixedReadError}</div>}
        </div>}
        {effectRecordId && <div className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px]">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="modeled">EFFECT-ONLY OBSERVATION</Badge>
            <span className="font-mono text-foreground" title={effectRecordId}>{effectRecordId}</span>
            <span className="text-muted-foreground">{effectResult?.status || "waiting for exact result"}</span>
          </div>
          {effectResult ? <div className="mt-2 space-y-1.5">
            {effectResult.effectEvidence?.observed
              ? <div>fresh exact-target effect: <span className="font-mono text-foreground">{effectResult.effectEvidence.before || "—"} → {effectResult.effectEvidence.after || "—"}</span>{effectResult.effectEvidence.seconds > 0 ? ` in ${effectResult.effectEvidence.seconds}s` : ""}</div>
              : <div className="text-warning">No fresh exact-target runtime effect was confirmed by this record.</div>}
            {effectResult.decisionEvidence && <div className="text-muted-foreground">decision candidate: <span className="font-mono text-foreground/85">{effectResult.decisionEvidence.action || "—"}</span>{effectResult.decisionEvidence.reason ? ` · ${effectResult.decisionEvidence.reason}` : ""} · selected {effectResult.decisionEvidence.selected ? "yes" : "no"} · actuated {effectResult.decisionEvidence.actuated ? "yes" : "no"} · correlation {effectResult.decisionEvidence.correlation}</div>}
            {effectResult.observationError && <div className="text-warning">observation error: {effectResult.observationError}</div>}
            <div className="text-warning/90">limits: {effectResult.effectEvidence?.limitation || "This record measures a mechanism effect only; behavioral attack execution, mitigation, defense success, containment, dwell, and ROI are not established."}</div>
          </div> : <div className="mt-2 flex items-center gap-2 text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> polling this exact attack ID with observations enabled…</div>}
          {effectReadError && <div className="mt-2 text-warning">result read incomplete: {effectReadError}</div>}
        </div>}
      </div>
    </Dialog>
  );
}
