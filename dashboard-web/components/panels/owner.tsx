"use client";
import * as React from "react";
import { ClaimScopeNote } from "@/components/claim-scope";
import { ownerNarrative } from "@/lib/owner-narrative";
import { api, Lens, OwnerEvent } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead, SectionLabel, Skeleton } from "./effectiveness";
import { ShieldCheck, CheckCircle2, RotateCcw, Lock, Building2, Boxes } from "lucide-react";
import { useOwnerTenant } from "@/lib/owner";
import { useApiRead } from "@/lib/query";
import { ReadStatus } from "@/components/ui/more";

export function OwnerPanel({ lens }: { lens: Lens }) {
  const { tenant } = useOwnerTenant(lens);
  const read = useApiRead({ lens, resource: "owner-events", parameters: { tenant }, fetcher: (signal) => api.ownerEvents(lens, tenant, signal), staleTime: 15_000, enabled: !!tenant });
  if (read.error && !read.data) return <ReadStatus error={read.error} hasData={false} onRetry={() => void read.refetch()} />;
  if (!tenant) return <div className="text-[12px] text-muted-foreground">Select a platform tenant to view owner activity.</div>;
  if (!read.data) return <Skeleton rows={3} />;

  const current = read.data;
  const ev = current.events ?? [];


  return (
    <div className="animate-fade-up space-y-7">
      <ReadStatus error={read.error} hasData updatedAt={read.dataUpdatedAt} refreshing={read.isFetching} onRetry={() => void read.refetch()} />
      <PageHead
        title="My Platform"
        sub="Recorded actions on your platform; security effects require independent confirmation. The outcome only: no internal scoring, no algorithms, no proprietary math."
      />
      <div className="flex items-center gap-2 rounded-lg border border-primary/20 bg-primary/[0.06] px-4 py-2.5 text-[12px] text-muted-foreground">
        <Lock className="h-3.5 w-3.5 text-primary" />
        <span><span className="font-medium text-foreground">IP-protected view.</span> Served by a server-side whitelist — Phorvex's decision internals are never sent to this view (enforced by a redaction test that is the eligibility gate).</span>
      </div>

      {current.partial && <div role="status" className="rounded-md border border-warning/40 p-3 text-[12px] text-warning">Actions and totals cover only the latest audit window{current.coveredFrom ? ` (${new Date(current.coveredFrom).toLocaleString()} to ${new Date(current.coveredTo || current.coveredFrom).toLocaleString()})` : ""}. Older actions remain in paged Live Ops history.</div>}

      <OwnerSummary events={ev} />

      <section>
        <SectionLabel>Activity — requests and recorded outcomes</SectionLabel>
        {current.empty ? (
          <Card><CardContent className="p-6 text-center text-sm text-muted-foreground">
            No protective actions recorded yet for your platform. Run an attack scenario (Operator lens) or point the backend at a decision audit trail.
            <div className="mt-2 text-[11px] text-muted-foreground/70">{current.note}</div>
          </CardContent></Card>
        ) : (
          <div className="space-y-2.5">
            {ev.map((e, i) => <EventRow key={i} e={e} />)}
            <div className="px-1 pt-1 text-[11px] text-muted-foreground/70">{current.note}</div>
          </div>
        )}
      </section>
    </div>
  );
}

function Outcome({ icon: Icon, label, value, tone }: { icon: React.ElementType; label: string; value: string; tone: string }) {
  const color = tone === "success" ? "text-success" : tone === "warning" ? "text-warning" : "text-primary";
  return (
    <Card><CardContent className="p-4">
      <Icon className={`h-4 w-4 ${color}`} />
      <div className="mt-2.5 text-2xl font-semibold tabular tracking-tight">{value}</div>
      <div className="mt-0.5 text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
    </CardContent></Card>
  );
}

export function EventRow({ e }: { e: OwnerEvent }) {
  return (
    <Card className="transition-colors hover:border-border/80">
      <CardContent className="flex flex-wrap items-start gap-x-4 gap-y-2 p-4">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-elevated ring-1 ring-border">
          <Building2 className="h-4 w-4 text-primary" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[13px] text-foreground">{e.namespace}/{e.pod}</span>
            <Badge variant="accent">{e.action}</Badge>
            {e.outcomeEvidence === "emitted-unconfirmed" && e.reversible && <Badge variant="neutral"><RotateCcw className="h-2.5 w-2.5" /> rollback supported</Badge>}
            <Badge variant="neutral">{e.attackStage}</Badge>
            {e.dryRun && <Badge variant="modeled">dry-run</Badge>}
          </div>
          <div className="mt-1.5 text-[13px] text-foreground/90">{ownerNarrative(e)}</div>
          <ClaimScopeNote claim={e.claim} />
          <div className="mt-1 text-[12px] text-muted-foreground">No verified comparison with a scheduled defense is available.</div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1.5 text-[11px]">
          {e.outcomeEvidence === "emitted-unconfirmed" && e.action === "quarantine" && <span className="flex items-center gap-1 text-success"><CheckCircle2 className="h-3 w-3" /> isolation dispatched</span>}
          <span className="text-muted-foreground">SLO confirmation unavailable</span>
          {!e.harmCaused && <span className="text-muted-foreground">disruption not independently confirmed</span>}
        </div>
      </CardContent>
    </Card>
  );
}

export function OwnerSummary({ events: ev }: { events: OwnerEvent[] }) {
  const known = (e: OwnerEvent) => ["emitted-unconfirmed", "not-emitted", "not-attempted", "selected", "dry-run"].includes(e.outcomeEvidence ?? "");
  const dispatched = ev.every(known) ? ev.filter((e) => e.outcomeEvidence === "emitted-unconfirmed").length : null;
  const isolation = ev.filter((e) => e.action === "quarantine");
  const attempts = isolation.every(known) ? isolation.filter((e) => e.outcomeEvidence === "emitted-unconfirmed").length : null;
  return (
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Outcome icon={Boxes} label="Protective actions" value={String(ev.length)} tone="primary" />
        <Outcome icon={ShieldCheck} label="Actions dispatched" value={dispatched == null ? "—" : String(dispatched)} tone="success" />
        <Outcome icon={CheckCircle2} label="Isolation attempts" value={attempts == null ? "—" : String(attempts)} tone="success" />
        <Outcome icon={ShieldCheck} label="Effect confirmation" value="Unavailable" tone="warning" />
      </div>
  );
}
