"use client";

import * as React from "react";
import { Loader2 } from "lucide-react";
import { api, type Lens, type NewstackCatalog, type NewstackCheck, type NewstackCleanup, type NewstackRun } from "@/lib/api";
import { useApiRead } from "@/lib/query";
import { Badge, Button, Card, CardContent } from "@/components/ui/primitives";

const stagingNamespace = "phorvex-staging";

function admittedCatalog(catalog?: NewstackCatalog): catalog is NewstackCatalog {
  return catalog?.schema === "newstack-catalog-v1" && catalog.enabled === true && catalog.namespace === stagingNamespace;
}

function observed(value: boolean | undefined): string {
  return value === true ? "yes" : value === false ? "no" : "unavailable";
}

export function NewstackRunResult({ run }: { run: NewstackRun }) {
  return (
    <div className="mt-2 space-y-1 rounded-md border border-border bg-elevated/30 p-2 text-[11px]" aria-live="polite">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="neutral">{run.verdict || "UNKNOWN"}</Badge>
        <span>status: {run.status || "unavailable"}</span>
        <span className="break-all font-mono text-muted-foreground">{run.runId}</span>
      </div>
      <div className="text-muted-foreground">cleanup complete: {observed(run.cleanupComplete)} · postflight clean: {observed(run.postflightClean)}</div>
      <div className="text-muted-foreground">decision action: {run.decision?.action || "unavailable"} · dispatch: {run.decision?.dispatchOutcome || "unavailable"}</div>
      {(run.issues || []).map((issue, index) => <div key={index} className="text-warning">{issue}</div>)}
      {run.limitation && <div className="text-muted-foreground">{run.limitation}</div>}
      <details>
        <summary className="cursor-pointer text-muted-foreground">Full run and decision details</summary>
        <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all text-[10px]">{JSON.stringify(run, null, 2)}</pre>
      </details>
    </div>
  );
}

export function NewstackLoopsPanel({ lens, allowMutations }: { lens: Lens; allowMutations: boolean }) {
  const catalogQuery = useApiRead({ lens, resource: "newstack-catalog", fetcher: (signal) => api.newstackCatalog(lens, signal), staleTime: 30_000 });
  const catalog = catalogQuery.error ? undefined : catalogQuery.data;
  const [busy, setBusy] = React.useState("");
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const [runs, setRuns] = React.useState<Record<string, NewstackRun>>({});
  const [checks, setChecks] = React.useState<Record<string, NewstackCheck>>({});
  const [cleanups, setCleanups] = React.useState<Record<string, NewstackCleanup>>({});
  const busyRef = React.useRef(false);
  const authorized = React.useRef(false);
  authorized.current = lens === "operator" && allowMutations && !catalogQuery.error && admittedCatalog(catalog);
  const mounted = React.useRef(true);
  React.useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  const perform = async (caseId: string, action: "check" | "fire" | "cleanup") => {
    if (busyRef.current || lens !== "operator" || !allowMutations || catalogQuery.error || !admittedCatalog(catalog) || !catalog.items.some((item) => item.id === caseId)) return;
    busyRef.current = true;
    setBusy(`${action}:${caseId}`);
    setErrors((current) => { const next = { ...current }; delete next[caseId]; return next; });
    if (action === "fire") setRuns((current) => { const next = { ...current }; delete next[caseId]; return next; });
    if (action === "fire" || action === "cleanup") setCleanups((current) => { const next = { ...current }; delete next[caseId]; return next; });
    try {
      if (action === "cleanup") {
        const result = await api.newstackCleanup(caseId, lens);
        if (mounted.current) setCleanups((current) => ({ ...current, [caseId]: result }));
      } else {
        const check = await api.newstackCheck(caseId, lens);
        if (!mounted.current || !authorized.current) return;
        if (check.ok !== true || check.ready === false || check.caseId !== caseId || check.namespace !== stagingNamespace) throw new Error(check.error || "Fixture preflight did not confirm this staging case.");
        setChecks((current) => ({ ...current, [caseId]: check }));
        if (action === "fire") {
          const result = await api.newstackFire(caseId, lens);
          if (!mounted.current) return;
          if (result.schema !== "newstack-run-v1" || result.caseId !== caseId || result.namespace !== stagingNamespace || !result.runId) throw new Error("The returned run identity did not match this staging case.");
          setRuns((current) => ({ ...current, [caseId]: result }));
        }
      }
    } catch (error) {
      if (mounted.current) setErrors((current) => ({ ...current, [caseId]: String((error as Error)?.message || error) }));
    } finally {
      busyRef.current = false;
      if (mounted.current) setBusy("");
    }
  };

  if (!admittedCatalog(catalog)) return null;
  const disabled = lens !== "operator" || !allowMutations || busy !== "";
  return (
    <Card><CardContent className="space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Disposable staging loops</span>
        <Badge variant="neutral">{stagingNamespace}</Badge>
        <span className="text-[11px] text-muted-foreground">up to {catalog.maximumSeconds} seconds per run</span>
      </div>
      <p className="text-[11px] text-muted-foreground">Rotate tests proactive hygiene with a simulated pod-resident marker. These fixtures do not run the real Voice or LiteLLM pipeline or evaluate natural detection. CRM uses synthetic accounts and a test-injected signal after the refund lands.</p>
      {!allowMutations && <p className="text-[11px] text-warning">Controls require the operator lens and the server&apos;s default mutation target.</p>}
      <div className="space-y-2">
        {catalog.items.map((item) => (
          <div key={item.id} className="rounded-md border border-border/70 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[12px] font-medium">{item.name}</span>
              <span className="ml-auto flex items-center gap-2">
                <Button size="sm" variant="ghost" disabled={disabled} onClick={() => void perform(item.id, "check")}>Check</Button>
                <Button size="sm" disabled={disabled} onClick={() => void perform(item.id, "fire")}>{busy === `fire:${item.id}` ? <><Loader2 className="h-3 w-3 animate-spin" /> Running…</> : "Fire"}</Button>
                <Button size="sm" variant="outline" disabled={disabled} onClick={() => void perform(item.id, "cleanup")}>Cleanup</Button>
              </span>
            </div>
            <div className="mt-1 text-[11px] text-muted-foreground">{item.class} · expected actuator <span className="font-mono">{item.expectedActuator}</span></div>
            <div className="mt-1 text-[11px] text-muted-foreground">{item.limitation}</div>
            {busy.endsWith(`:${item.id}`) && <div role="status" className="mt-2 text-[11px] text-muted-foreground">{busy.startsWith("fire:") ? "Checking the fixture, running the bounded loop, and waiting for its terminal record…" : busy.startsWith("cleanup:") ? "Cleaning the retained fixture…" : "Checking fixture readiness…"}</div>}
            {checks[item.id] && !runs[item.id] && !errors[item.id] && !busy && <div className="mt-2 text-[11px] text-muted-foreground">Preflight passed. No run verdict has been recorded.</div>}
            {errors[item.id] && <div role="alert" className="mt-2 text-[11px] text-danger">Error: {errors[item.id]} The run outcome is unconfirmed; inspect retained state before retrying.</div>}
            {runs[item.id] && <NewstackRunResult run={runs[item.id]} />}
            {cleanups[item.id] && <div className="mt-2 text-[11px] text-muted-foreground">Cleanup complete: {observed(cleanups[item.id].cleanupComplete)} · postflight clean: {observed(cleanups[item.id].postflightClean)}{cleanups[item.id].message ? ` · ${cleanups[item.id].message}` : ""}<details><summary className="cursor-pointer">Cleanup details</summary><pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(cleanups[item.id], null, 2)}</pre></details></div>}
          </div>
        ))}
      </div>
    </CardContent></Card>
  );
}
