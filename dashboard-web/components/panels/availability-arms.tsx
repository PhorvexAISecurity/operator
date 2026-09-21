"use client";
import * as React from "react";
import { api, Lens, ArmResult, ArmRun, ArmsJob } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Empty, Input } from "@/components/ui/more";
import { DataFreshness, PaginationBar } from "@/components/ui/pagination";
import { useServerPage } from "@/lib/use-server-page";
import { Loader2, ShieldCheck, ShieldAlert, ShieldQuestion, Activity, Info } from "lucide-react";
import { cn } from "@/lib/utils";

// AvailabilityArmsPanel — for every three-arm experiment that has been run, what the SAME attack
// did to the SAME app under three defenders. Listed newest-first with the time it ran.
export function AvailabilityArmsPanel({ lens }: { lens: Lens }) {
  const [q, setQ] = React.useState("");
  const [liveMeta, setLiveMeta] = React.useState<{ lens: Lens; running: ArmsJob[]; available: boolean; note: string; howItRan: string; whyNoDrop: string } | null>(null);
  const [jobError, setJobError] = React.useState<{ lens: Lens; message: string } | null>(null);
  const normalizedQ = q.trim().toLowerCase();
  const pager = useServerPage<ArmRun, { running: ArmsJob[]; available: boolean; note: string; howItRan: string; whyNoDrop: string }>({
    resource: "availability-arms", lens,
    key: `${lens}\u0000${normalizedQ}`,
    network: { q: normalizedQ || undefined },
    pageSize: 10,
    pollMs: 10000,
    fetchPage: (cursor, signal) => api.availabilityArmsPage(lens, 10, { q: normalizedQ || undefined }, cursor, signal).then((d) => ({
      items: d.runs || [], page: d.page,
      meta: { running: d.running || [], available: d.available, note: d.note, howItRan: d.howItRan, whyNoDrop: d.whyNoDrop },
    })),
    legacyFilter: (r) => !normalizedQ || `${r.namespace} ${r.deploy} ${r.attack}`.toLowerCase().includes(normalizedQ),
  });

  React.useEffect(() => {
    if (pager.meta) {
      setLiveMeta({ lens, ...pager.meta });
      setJobError(null);
    }
  }, [lens, pager.meta]);

  const pollJobsIndependently = pager.hasSnapshot || pager.page > 0 || !!pager.error;
  React.useEffect(() => {
    if (!pollJobsIndependently) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = () => api.availabilityArmsPage(lens, 1, {}, undefined, controller.signal).then((d) => {
      if (controller.signal.aborted) return;
      setLiveMeta({ lens, running: d.running || [], available: d.available, note: d.note, howItRan: d.howItRan, whyNoDrop: d.whyNoDrop });
      setJobError(null);
      timer = setTimeout(load, 10000);
    }).catch((e) => {
      if (!controller.signal.aborted) {
        setJobError({ lens, message: String(e?.message || e) });
        timer = setTimeout(load, 10000);
      }
    });
    load();
    return () => { controller.abort(); if (timer) clearTimeout(timer); };
  }, [lens, pollJobsIndependently]);

  const d = pollJobsIndependently || !pager.meta ? (liveMeta?.lens === lens ? liveMeta : pager.meta) : pager.meta;
  const scopedJobError = jobError?.lens === lens ? jobError.message : "";
  const running = (d?.running || []).filter((j) => j.phase !== "done");
  return (
    <div className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
          <Activity className="h-4 w-4 text-primary" />
          Availability under attack — no defense vs blind rotator vs Phorvex
        </div>
        <p className="mt-1 max-w-[74ch] text-[12px] leading-relaxed text-muted-foreground">
          {d?.howItRan} One entry per experiment, newest first.
        </p>
      </div>
      <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search all experiments by namespace, deployment, or attack…" aria-label="Search availability experiments" />
      {pager.legacy && <div className="text-[11px] text-warning">Legacy/preview response: paging and search cover the full history returned by this fixture.</div>}
      {pager.error && <div className="text-[11px] text-danger">Page refresh failed: {pager.error} <button className="text-primary" onClick={pager.retry}>Retry</button></div>}
      <DataFreshness updatedAt={pager.updatedAt} refreshing={pager.refreshing} failed={!!pager.error} />
      {scopedJobError && <div className="text-[11px] text-danger">Showing last known job state; background refresh failed: {scopedJobError}. Retry is scheduled.</div>}
      {pager.loading && !pager.pageMeta && <div className="flex items-center gap-2 py-8 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading…</div>}

      {/* the honest explanation, given prominence rather than buried in a footnote */}
      <Card className="border-l-2 border-l-warning">
        <CardContent className="flex gap-2.5 p-4">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          <div className="space-y-1.5 text-[12px] leading-relaxed">
            <div className="font-medium text-foreground">Why does &quot;no defense&quot; show full availability?</div>
            <p className="text-muted-foreground">{d?.whyNoDrop}</p>
          </div>
        </CardContent>
      </Card>

      {/* live progress for any experiment currently running */}
      {running.map((j) => (
        <Card key={`${j.namespace}:${j.deploy}:${j.attack}:${j.startedAt}`} className={cn("border-l-2", j.phase === "failed" ? "border-l-danger" : "border-l-primary")}>
          <CardContent className="space-y-2 p-4">
            <div className="flex flex-wrap items-center gap-2">
              {j.phase === "failed"
                ? <ShieldAlert className="h-4 w-4 text-danger" />
                : scopedJobError ? <ShieldAlert className="h-4 w-4 text-warning" />
                : <Loader2 className="h-4 w-4 animate-spin text-primary" />}
              <span className="font-mono text-[12px] font-medium text-foreground">{j.namespace}/{j.deploy}</span>
              <span className="text-[11px] text-muted-foreground">· {j.attack}</span>
              <span className="ml-auto font-mono text-[10px] text-muted-foreground/70">started {new Date(j.startedAt).toLocaleTimeString()}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded bg-border/50">
              <div className={cn("h-full rounded transition-all", j.phase === "failed" ? "bg-danger" : "bg-primary")}
                   style={{ width: `${Math.max(2, j.progress)}%` }} />
            </div>
            <div className="text-[11px] text-muted-foreground">{j.error || j.detail}</div>
            {scopedJobError && j.phase !== "failed" && <div className="text-[11px] text-warning">last known state — live refresh unavailable</div>}
          </CardContent>
        </Card>
      ))}

      {pager.items.map((run, index) => <RunBlock key={run.operation || `${pager.page}:${index}:${run.runAt}:${run.namespace}:${run.deploy}:${run.attack}`} run={run} />)}
      {pager.items.length === 0 && running.length === 0 && !pager.loading && !pager.error && <Empty msg={q ? "No availability experiments match this search." : d?.note || "No availability experiments recorded."} />}

      <PaginationBar page={pager.page} pageSize={10} total={pager.pageMeta?.total} hasNext={pager.hasNext} onPrevious={pager.previous} onNext={pager.next} onLatest={pager.latest} showLatest={pager.hasSnapshot || pager.page > 0} loading={pager.loading} />
      <div className="text-[11px] text-muted-foreground/70">{d?.note}</div>
    </div>
  );
}

function RunBlock({ run }: { run: ArmRun }) {
  const arms = run.arms.filter((a) => a.complete);
  const blind = arms.find((a) => a.arm === "r6blind");
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-border/60 pb-1.5">
        <span className="font-mono text-[12px] font-medium text-primary">{run.namespace}/{run.deploy}</span>
        <span className="text-[11px] text-muted-foreground">{run.attack}</span>
        <span className="ml-auto font-mono text-[10px] text-muted-foreground/70">
          {new Date(run.runAt).toLocaleString()}
        </span>
      </div>

      {arms.length === 0 ? (
        <div className="py-3 text-[11px] text-muted-foreground">no sampler coverage for this experiment window</div>
      ) : (
        <>
          <div className="grid gap-3 md:grid-cols-3">
            {arms.map((a) => <ArmCard key={a.arm} a={a} />)}
          </div>
          <p className="text-[11px] leading-relaxed text-muted-foreground">
            Every arm received the same synthetic detector signal. <span className="text-warning">The blind rotator</span>{" "}
            responded on its fixed cadence and dipped {blind?.dipCount ?? "—"} times for{" "}
            {blind?.secondsDegraded.toFixed(0) ?? "—"}s in the registered window. Identity-bound workload responses are
            reported separately from availability; this producer does not establish attacker presence, access, or mitigation.
          </p>
        </>
      )}
    </div>
  );
}

function ArmCard({ a }: { a: ArmResult }) {
  const tone =
    a.attackerStopped === "yes"
      ? { ring: "border-l-success", txt: "text-success", bar: "bg-success", Icon: ShieldCheck, chip: "real" as const, label: "attacker evicted" }
      : a.attackerStopped === "no"
        ? { ring: "border-l-danger", txt: "text-danger", bar: "bg-danger", Icon: ShieldAlert, chip: "pending" as const, label: "attacker kept access" }
        : { ring: "border-l-warning", txt: "text-warning", bar: "bg-warning", Icon: ShieldQuestion, chip: "modeled" as const, label: "attacker effect unknown" };
  const pct = Math.max(0, Math.min(100, a.meanPct));
  return (
    <Card className={cn("border-l-2", tone.ring)}>
      <CardContent className="space-y-2.5 p-4">
        <div className="flex items-center gap-2">
          <tone.Icon className={cn("h-4 w-4", tone.txt)} />
          <span className="text-[13px] font-medium text-foreground">{a.label}</span>
        </div>

        <div>
          <div className="flex items-baseline gap-2">
            <span className={cn("tabular font-mono text-[26px] font-semibold leading-none", tone.txt)}>{a.meanPct.toFixed(1)}%</span>
            <span className="text-[11px] text-muted-foreground">average availability</span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded bg-border/50">
            <div className={cn("h-full rounded", tone.bar)} style={{ width: `${pct}%` }} />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
          <Stat k="worst dip" v={`${a.minPct.toFixed(0)}%`} />
          <Stat k="times it dipped" v={String(a.dipCount)} />
          <Stat k="degraded for" v={`${a.secondsDegraded.toFixed(0)}s`} />
          <Stat k="downtime cost" v={`$${a.downtimeUsd.toFixed(4)}`} />
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-border/50 pt-2">
          <Badge variant={tone.chip}>{tone.label}</Badge>
          <Badge variant={a.responseObserved ? "real" : "pending"}>{a.responseObserved ? "target response observed" : "no target response observed"}</Badge>
          {!a.complete && <Badge variant="pending">incomplete evidence</Badge>}
        </div>
        <p className="text-[11px] leading-relaxed text-muted-foreground">{a.verdict}</p>
      </CardContent>
    </Card>
  );
}

function Stat({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <span className="text-muted-foreground">{k}</span>
      <span className="tabular font-mono text-foreground">{v}</span>
    </div>
  );
}
