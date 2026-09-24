"use client";
import * as React from "react";
import { api, ApiError, Lens, CatalogItem, ClusterTarget, RunStatus, RunEvidence, AttackResult, FunctionalAdmission, FunctionalAdmissionReason } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Segmented, Input, Dialog, Loading, ErrorBox, Empty } from "@/components/ui/more";
import { PageHead, SectionLabel } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Search, Play, Loader2, ShieldCheck, Cpu, Boxes } from "lucide-react";
import { clearLiveSelection, selectLiveRecord } from "@/lib/live-selection";
import { useLocalPage } from "@/lib/use-local-page";
import { PaginationBar } from "@/components/ui/pagination";
import { useCatalog, useQueryScope, useTargets } from "@/lib/query";
import { setSelectedTarget } from "@/lib/provider-store";
import { DecisionEvidencePanel } from "@/components/panels/decision-evidence";
import { GuardrailCalibrationResult } from "@/components/panels/guardrail-calibration-result";
import { NATSClientResponseResult } from "@/components/panels/nats-client-response-result";
import { MongoExposureResult } from "@/components/panels/mongo-exposure-result";

const r6Variant = (t: string) => (t.includes("Covers") ? "real" : t.includes("Partial") ? "modeled" : "danger");

type FixedAdmissionState = { key: string; profile: string; phase: "checking" | "ready" | "blocked" | "error"; reasonCode?: FunctionalAdmissionReason; observedAt?: string };
const admissionReasons = new Set<FunctionalAdmissionReason>(["READY", "CONFIG_UNAVAILABLE", "RUNTIME_UNAVAILABLE", "RETAINED_STATE_UNAVAILABLE", "PRIOR_UNSAFE_FIXED_SUITE", "CONCURRENCY_LIMIT", "RATE_LIMIT"]);
const admissionMessage = (reason?: FunctionalAdmissionReason) => {
  switch (reason) {
    case "PRIOR_UNSAFE_FIXED_SUITE": return "A prior fixed suite needs reconciliation before another can start.";
    case "RETAINED_STATE_UNAVAILABLE": return "Retained run state is unavailable; launch is blocked.";
    case "CONFIG_UNAVAILABLE": return "This fixed-suite profile is not configured.";
    case "RUNTIME_UNAVAILABLE": return "The fixed-suite runtime is unavailable.";
    case "CONCURRENCY_LIMIT": return "The current run limit is reached.";
    case "RATE_LIMIT": return "A recent launch is rate-limited. Refresh admission shortly.";
    case "READY": return "Ready at the observed time. Launch checks admission again.";
    default: return "Current launch admission could not be verified.";
  }
};

export function fixedSuiteAdmissionReady(key: string, profile: string, state: FixedAdmissionState | null): boolean {
  return !!state && state.key === key && state.profile === profile && state.phase === "ready" && state.reasonCode === "READY" && !!profile;
}

export function FixedSuiteAdmissionNotice({ configured, state, onRefresh, refreshes }: { configured: boolean; state: FixedAdmissionState | null; onRefresh: () => void; refreshes: number }) {
  if (!configured) return <div data-fixed-admission="unconfigured" className="text-[11px] text-warning">Profile configuration is unavailable.</div>;
  const phase = state?.phase || "checking";
  return <div data-fixed-admission={phase} className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
    <div>Configuration: <span className="text-foreground">available</span> · Current launch admission: <span className={phase === "ready" ? "text-foreground" : "text-warning"}>{phase === "checking" ? "checking" : phase === "error" ? "unverified" : phase === "ready" ? "ready" : "blocked"}</span></div>
    <div className="mt-1 text-muted-foreground">{phase === "checking" ? "Checking the current server gate." : phase === "error" ? "Admission check failed or was refused. Launch stays disabled." : admissionMessage(state?.reasonCode)}</div>
    {state?.observedAt && <div className="mt-1 text-muted-foreground">Observed {state.observedAt}; launch rechecks current state.</div>}
    {refreshes < 3 && phase !== "checking" && <button type="button" onClick={onRefresh} className="mt-2 text-primary underline">Refresh admission</button>}
  </div>;
}

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
            {it.benignControl ? <Badge variant="neutral">{it.claimClass === "calibration" ? "benign calibration" : "benign functional"}</Badge> : it.product === "ai" && <Badge variant="pending">SP-0</Badge>}
            {it.launchKind === "fixed-suite" && it.available === true ? <Badge variant="neutral">configured · admission checked on open</Badge> : it.available === false && <Badge variant="pending">unavailable</Badge>}
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
  const scope = useQueryScope(lens);
  const [running, setRunning] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [fixedRun, setFixedRun] = React.useState<{ id: string; context: string } | null>(null);
  const [fixedStatus, setFixedStatus] = React.useState<RunStatus | null>(null);
  const [fixedEvidence, setFixedEvidence] = React.useState<RunEvidence | null>(null);
  const [fixedReadError, setFixedReadError] = React.useState("");
  const [effectRecordId, setEffectRecordId] = React.useState("");
  const [effectResult, setEffectResult] = React.useState<AttackResult | null>(null);
  const [effectReadError, setEffectReadError] = React.useState("");
  const [namedLaunchUncertain, setNamedLaunchUncertain] = React.useState(false);
  const [admissionRefreshes, setAdmissionRefreshes] = React.useState(0);
  const [fixedAdmission, setFixedAdmission] = React.useState<FixedAdmissionState | null>(null);
  const admissionGeneration = React.useRef(0);
  const fixedProfile = item?.profile || item?.entryID || item?.name || "";
  const admissionKey = `${scope.identity}\u0000${scope.providerToken}\u0000${scope.ready}\u0000${lens}\u0000${fixedProfile}\u0000${admissionRefreshes}`;
  const requestGeneration = React.useRef(0);
  const requestContext = `${item?.name || ""}\u0000${fixedProfile}\u0000${target?.id || ""}\u0000${target?.context || ""}\u0000${lens}\u0000${scope.identity}\u0000${scope.providerToken}`;
  const currentContext = React.useRef(requestContext);
  if (currentContext.current !== requestContext) {
    currentContext.current = requestContext;
    requestGeneration.current++;
  }
  React.useEffect(() => {
    requestGeneration.current++;
    setRunning(""); setMsg(""); setFixedRun(null); setFixedStatus(null); setFixedEvidence(null); setFixedReadError(""); setEffectRecordId(""); setEffectResult(null); setEffectReadError("");
  }, [item?.name, fixedProfile, target?.id, target?.context, lens, scope.identity, scope.providerToken]);
  React.useEffect(() => { setAdmissionRefreshes(0); }, [item?.name, fixedProfile, lens, scope.identity, scope.providerToken]);
  React.useEffect(() => {
    const generation = ++admissionGeneration.current;
    if (!item || item.launchKind !== "fixed-suite" || item.available === false) {
      setFixedAdmission(null);
      return;
    }
    if (!scope.ready) {
      setFixedAdmission({ key: admissionKey, profile: fixedProfile, phase: "error" });
      return;
    }
    const controller = new AbortController();
    setFixedAdmission({ key: admissionKey, profile: fixedProfile, phase: "checking" });
    void api.functionalAdmission(fixedProfile, lens, controller.signal).then((value: FunctionalAdmission) => {
      if (controller.signal.aborted || generation !== admissionGeneration.current) return;
      if (value.profile !== fixedProfile || typeof value.launchable !== "boolean" || !admissionReasons.has(value.reasonCode) || !value.observedAt || Number.isNaN(Date.parse(value.observedAt)) || value.launchable !== (value.reasonCode === "READY")) {
        setFixedAdmission({ key: admissionKey, profile: fixedProfile, phase: "error" });
        return;
      }
      setFixedAdmission({ key: admissionKey, profile: fixedProfile, phase: value.launchable ? "ready" : "blocked", reasonCode: value.reasonCode, observedAt: value.observedAt });
    }).catch(() => {
      if (!controller.signal.aborted && generation === admissionGeneration.current) setFixedAdmission({ key: admissionKey, profile: fixedProfile, phase: "error" });
    });
    return () => { controller.abort(); };
  }, [admissionKey, fixedProfile, item?.launchKind, item?.available, lens, scope.ready]);
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
    if (item!.launchKind === "fixed-suite" && !fixedSuiteAdmissionReady(admissionKey, fixedProfile, fixedAdmission)) return;
    const scenario = item!.name;
    const selectedTarget = target;
    const selectedLens = lens;
    const selectedContext = requestContext;
    const request = ++requestGeneration.current;
    setRunning(withPX ? "px" : "nopx"); setMsg("");
    let namedLaunchSent = false;
    let namedLaunchConfirmed = false;
    if (selectedTarget?.context) clearLiveSelection(selectedLens, selectedTarget.context);
    try {
      if (item!.launchKind === "fixed-suite") {
        const { id, context } = await api.startFunctional(item!.profile || item!.entryID || item!.name, selectedLens);
        if (request !== requestGeneration.current || selectedContext !== currentContext.current) return;
        setFixedRun({ id, context }); setFixedStatus(null); setFixedEvidence(null); setFixedReadError("");
        if (selectedTarget?.context === context) selectLiveRecord({ kind: "run", id, lens: selectedLens, context });
        setMsg(item!.claimClass === "calibration" ? `Started ${id}. Its result reports only fixed benign classifier calibration, source pins, and cleanup.` : `Started ${id}. Its result reports the functional oracle, evidence, cleanup, and claim limits.`);
        return;
      }
      if (item!.launchKind === "named-suite") {
        if (item!.profile !== "nats-exposure-baseline" && item!.profile !== "nats-client-response" && item!.profile !== "mongo-exposure-baseline") throw new Error("Named suite profile differs from the server-owned case");
        namedLaunchSent = true;
        const { id } = await api.startRun(item!.profile, false, selectedLens);
        namedLaunchConfirmed = true;
        setNamedLaunchUncertain(false);
        if (request !== requestGeneration.current || selectedContext !== currentContext.current) return;
        const context = item!.runtimeContext || selectedTarget?.context || "";
        setFixedRun({ id, context }); setFixedStatus(null); setFixedEvidence(null); setFixedReadError("");
        if (selectedTarget?.context === context) selectLiveRecord({ kind: "run", id, lens: selectedLens, context });
        setMsg(item!.profile === "nats-client-response"
          ? `Started ${id}. The result separately reports the injected signal, installed response, continuing-client and legitimate-peer observations; no defense verdict is inferred from silence.`
          : item!.profile === "mongo-exposure-baseline"
          ? `Started ${id}. The result compares one owned synthetic document against a no-credential Mongo Service read, legitimate controls, manager audit, and exact cleanup; defense efficacy is not evaluated.`
          : `Started ${id}. The result is a synthetic no-signal configuration finding, not a defense verdict.`);
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
    catch (e: any) {
      if (item!.launchKind === "fixed-suite" && request === requestGeneration.current) setFixedAdmission({ key: admissionKey, profile: fixedProfile, phase: "error" });
      if (namedLaunchSent && !namedLaunchConfirmed && !(e instanceof ApiError && e.status >= 400 && e.status < 500)) setNamedLaunchUncertain(true);
      if (request === requestGeneration.current && selectedContext === currentContext.current) setMsg(namedLaunchSent && !namedLaunchConfirmed && !(e instanceof ApiError && e.status >= 400 && e.status < 500)
        ? "Named-suite launch response is uncertain. Inspect Run History for the exact run before any new attempt; do not retry this request blindly."
        : String(e.message || e));
    }
    finally { if (request === requestGeneration.current && selectedContext === currentContext.current) setRunning(""); }
  }
  const runnable = lens === "operator" && item.available !== false && !(item.launchKind === "named-suite" && namedLaunchUncertain) && (item.launchKind === "fixed-suite" ? fixedSuiteAdmissionReady(admissionKey, fixedProfile, fixedAdmission) : item.launchKind === "named-suite" || item.launchKind === "live-vllm-effect" || (!!target?.runnable && !!target.id && !!target.context));
  return (
    <Dialog open={!!item} onClose={() => { requestGeneration.current++; setRunning(""); setMsg(""); onClose(); }} title={item.name}>
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant="neutral">{item.category}</Badge>
          <Badge variant={r6Variant(item.r6Tag) as any}>Without-PX {item.r6Tag.replace("R6", "")}</Badge>
          <Badge variant={item.product === "ai" ? "modeled" : "accent"}>{item.product.toUpperCase()}</Badge>
          {item.benignControl && <Badge variant="neutral">{item.claimClass === "calibration" ? "classifier-only · security not evaluated" : "security outcome not applicable"}</Badge>}
        </div>
        <div>
          <SectionLabel>ATT&amp;CK techniques</SectionLabel>
          <div className="flex flex-wrap gap-1.5">{(item.techniques ?? []).length === 0 ? <span className="text-[12px] text-muted-foreground">none tagged</span> : (item.techniques ?? []).map((t) => <span key={t} className="rounded bg-muted/40 px-2 py-0.5 text-[12px] font-mono text-foreground/80">{t}</span>)}</div>
        </div>
        {item.benignControl
          ? <div className="rounded-md border border-border bg-muted/20 p-3 text-[12px] text-muted-foreground">{item.claimClass === "calibration" ? "Two fixed benign inputs are sent to the reviewed non-forwarding classifier endpoint/source contract. Loaded process behavior and guarded serving remain unverified; this is not a security efficacy result." : item.launchKind === "fixed-suite" ? "Bounded functional control. It reports only the case-specific service, fixture, or console boundary named below, plus cleanup and explicit limits; it does not establish attack or defense efficacy." : item.launchKind === "live-vllm-effect" ? "Bounded installed effect observation. A fresh exact-target state transition is separate from behavioral mitigation, which this entry does not measure." : "Benign synthetic harness control. It does not establish an attack, defense efficacy, ROI, or behavior of the installed service."} {item.meaningfulWhen}</div>
          : item.product === "ai" && <div className="rounded-md border border-warning/25 bg-warning/[0.05] p-3 text-[12px] text-muted-foreground">AI scenario — the attack surface is real; Phorvex's <span className="text-foreground">defense efficacy is [SP-0-PENDING-P4]</span>, validated on real GPU at P4. No AI effectiveness is implied here.</div>}
        {item.unavailableReason && <div className="text-[11px] text-muted-foreground">{item.unavailableReason}</div>}
        {item.eventMode && <div className="text-[12px] text-muted-foreground">Event mode: <span className="text-foreground">{item.eventMode}</span> · brain: NOT_EVALUATED · actuator: NOT_EVALUATED</div>}
        {item.launchKind === "fixed-suite" && <FixedSuiteAdmissionNotice configured={item.available !== false} state={fixedAdmission?.key === admissionKey ? fixedAdmission : null} refreshes={admissionRefreshes} onRefresh={() => setAdmissionRefreshes((count) => Math.min(3, count + 1))} />}
        {item.launchKind === "named-suite" && namedLaunchUncertain && <div className="text-[11px] text-warning">The last launch response was lost or indeterminate. Inspect Run History and reconcile any partial unsafe run before starting a new one. This button stays disabled for this page session.</div>}
        <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4">
          {item.launchKind === "fixed-suite" || item.launchKind === "named-suite" || item.launchKind === "live-vllm-effect" ? <Button onClick={() => run(true)} disabled={!!running || !runnable}>{running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} {item.claimClass === "calibration" ? "Run benign classifier calibration" : item.launchKind === "named-suite" ? item.profile === "nats-client-response" ? "Run NATS client response" : item.profile === "mongo-exposure-baseline" ? "Run Mongo Service exposure control" : "Run NATS exposure control" : item.launchKind === "fixed-suite" ? "Run bounded functional check" : "Run bounded effect observation"}</Button> : <>
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
            {fixedEvidence.functionalResult.unsafeToRetry && <div className="text-warning">This run remains unsafe to retry; inspect its run status and exact cleanup evidence.</div>}
            {item.claimClass === "calibration" && <GuardrailCalibrationResult evidence={fixedEvidence.functionalResult.evidence || {}} />}
            {item.eventMode && <div className="space-y-1 border-t border-border pt-2">{Object.entries(fixedEvidence.functionalResult.evidence || {}).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => <div key={key}><span className="font-mono text-foreground/80">{key}:</span> {value}</div>)}</div>}
            <div className="text-muted-foreground">limits: {fixedEvidence.functionalResult.limits.join(" · ")}</div>
          </div>}
          {fixedEvidence?.configurationResult && <div className="mt-2 space-y-1 border-t border-border pt-2">
            <div>accepted configuration finding: <span className="font-medium text-foreground">{fixedEvidence.configurationResult.finding}</span> · accepted: <span className="text-foreground">{fixedEvidence.configurationResult.accepted ? "yes" : "no"}</span></div>
            {!fixedEvidence.configurationResult.accepted && <div className="text-muted-foreground">Unaccepted observer indication: {fixedEvidence.configurationResult.observedFinding}</div>}
            <div>remote receipt: {fixedEvidence.configurationResult.remoteStatus} · legitimate ACK: {fixedEvidence.configurationResult.legitimateAcked ? "yes" : "unverified"}</div>
            <div>stream cleanup: {fixedEvidence.configurationResult.streamCleanup} · fixture cleanup: {fixedEvidence.configurationResult.fixtureResourcesCleanup}</div>
            <div>brain: {fixedEvidence.configurationResult.brainMode} · defense efficacy: {fixedEvidence.configurationResult.securityEfficacy}</div>
            {(fixedEvidence.configurationResult.issues || []).map((issue, index) => <div key={`${index}-${issue}`} className="text-warning">{issue}</div>)}
          </div>}
          {fixedEvidence?.natsResponseResult && <div className="mt-2 border-t border-border pt-2"><NATSClientResponseResult result={fixedEvidence.natsResponseResult} unsafeToRetry={fixedStatus?.unsafeToRetry} /></div>}
          {fixedEvidence?.mongoExposureResult && <div className="mt-2 border-t border-border pt-2"><MongoExposureResult result={fixedEvidence.mongoExposureResult} unsafeToRetry={fixedStatus?.unsafeToRetry} /></div>}
          {item.profile === "mongo-exposure-baseline" && fixedEvidence && !fixedEvidence.mongoExposureResult && <div className="mt-1 text-warning">Exact Mongo synthetic-document evidence is unavailable or incomplete. No configuration exposure finding or defense result is accepted.</div>}
          {(fixedEvidence?.issues || []).map((issue) => <div key={`${issue.line}-${issue.reason}`} className="mt-1 text-warning">unverified evidence: {issue.reason}</div>)}
          {fixedEvidence && item.profile !== "mongo-exposure-baseline" && !fixedEvidence.functionalResult && !fixedEvidence.configurationResult && !fixedEvidence.natsResponseResult && !fixedEvidence.mongoExposureResult && (fixedEvidence.issues || []).length === 0 && <div className="mt-1 text-warning">terminal evidence is incomplete; no outcome is accepted</div>}
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
            <DecisionEvidencePanel exact={effectResult.decisionTraceEvidence} temporal={effectResult.temporalDecisionEvidence} legacy={effectResult.decisionEvidence} compact observationStartedAt={effectResult.observationStartedAt} observationDeadline={effectResult.observationDeadline} />
            {effectResult.observationError && <div className="text-warning">observation error: {effectResult.observationError}</div>}
            <div className="text-warning/90">limits: {effectResult.effectEvidence?.limitation || "This record measures a mechanism effect only; behavioral attack execution, mitigation, defense success, containment, dwell, and ROI are not established."}</div>
          </div> : <div className="mt-2 flex items-center gap-2 text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> polling this exact attack ID with observations enabled…</div>}
          {effectReadError && <div className="mt-2 text-warning">result read incomplete: {effectReadError}</div>}
        </div>}
      </div>
    </Dialog>
  );
}
