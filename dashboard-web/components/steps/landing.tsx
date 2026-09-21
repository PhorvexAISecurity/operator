"use client";
import * as React from "react";
import { api, Lens, Stat, Posture, OwnerRollup } from "@/lib/api";
import { useOwnerTenant } from "@/lib/owner";
import { STEPS, StepId, JourneySignals, stepState } from "@/lib/journey";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { ArrowRight, PlayCircle, Plug, Radar, Network, Radio, Swords, FileText, Check, Lock, FlaskConical } from "lucide-react";
import { useApiRead } from "@/lib/query";

const ICON: Record<StepId, React.ElementType> = { landing: Plug, connect: Plug, scan: Radar, discovered: Network, attacklab: Swords, protect: Radio, prove: Swords, report: FileText, bench: FlaskConical };

export function Landing({ lens, signals, go, onDemo }: { lens: Lens; signals: JourneySignals; go: (s: StepId) => void; onDemo: () => void }) {
  const { tenant } = useOwnerTenant(lens);
  const effectiveness = useApiRead({ lens, resource: "effectiveness", fetcher: (signal) => api.effectiveness(lens, signal), staleTime: 60_000, enabled: lens !== "owner" });
  const postureRead = useApiRead({ lens, resource: "posture", fetcher: (signal) => api.posture(lens, signal), staleTime: 60_000, enabled: lens !== "owner" });
  const ownerRead = useApiRead({ lens, resource: "owner-events", parameters: { tenant }, fetcher: (signal) => api.ownerEvents(lens, tenant, signal), staleTime: 15_000, enabled: lens === "owner" && !!tenant });
  const posture = postureRead.data ?? null;
  const rollup = ownerRead.data?.rollup ?? null;
  const scoped = lens === "owner" ? !!ownerRead.data : !!(effectiveness.data || postureRead.data);
  const hero = (effectiveness.data?.stats ?? []).filter((s) => ["disruption", "work-preserved", "prevention", "explainability"].includes(s.key));

  return (
    <div className="animate-fade-up space-y-8">
      {/* hero */}
      <section className="pt-2">
        <div className="flex items-center gap-2 text-[12px] font-medium uppercase tracking-[0.16em] text-primary/80">
          <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse-soft" /> Adaptive moving-target defense
        </div>
        <h1 className="mt-3 max-w-3xl text-3xl font-semibold leading-tight tracking-tight sm:text-[2.6rem]">
          Phorvex watches your platform and <span className="text-primary">attempts targeted disruption</span> within its modeled scope.
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted-foreground">
          A deterministic intelligence layer — no LLM in the decision path. K8s is proven on AWS EKS; the AI/inference product is structurally first-class with defense efficacy honestly <span className="text-warning">[SP-0-PENDING-P4]</span>.
        </p>
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <Button onClick={() => go("connect")}>Start the journey <ArrowRight className="h-4 w-4" /></Button>
          <Button variant="outline" onClick={() => go("protect")}><Radio className="h-4 w-4 text-primary" /> Run my methods</Button>
          <Button variant="ghost" onClick={onDemo}><PlayCircle className="h-4 w-4 text-primary" /> Guided demo</Button>
        </div>
      </section>

      {/* journey map */}
      <section>
        <div className="mb-3 text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground/80">The journey · click any step</div>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {STEPS.map((s) => {
            const st = stepState(s.id, signals, "landing");
            const Icon = ICON[s.id];
            const center = s.id === "protect";
            return (
              <button key={s.id} onClick={() => st !== "locked" && go(s.id)} disabled={st === "locked"}
                className={cn("group flex flex-col gap-2 rounded-lg border bg-panel/70 p-3.5 text-left transition-all",
                  center ? "border-primary/40 ring-1 ring-primary/20" : "border-border hover:border-border/80",
                  st === "locked" && "opacity-50")}>
                <div className="flex items-center justify-between">
                  <Icon className={cn("h-4 w-4", center ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
                  {st === "done" ? <Badge variant="real"><Check className="h-2.5 w-2.5" /> ready</Badge> : st === "locked" ? <Badge variant="neutral"><Lock className="h-2.5 w-2.5" /></Badge> : <span className="text-[10px] tabular text-muted-foreground/60">{s.n}/{STEPS.length}</span>}
                </div>
                <div className="text-[13px] font-semibold">{s.label}</div>
                <div className="text-[11px] leading-snug text-muted-foreground">{s.tagline}</div>
                {center && <div className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-primary">where every method runs</div>}
              </button>
            );
          })}
        </div>
      </section>

      {/* live proof strip */}
      <section>
        <div className="mb-3 text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground/80">Recorded activity {lens === "owner" ? "· your activity" : "· live from the evidence"}</div>
        {lens === "owner" ? (
          <OwnerLandingSummary rollup={scoped ? rollup : null} />
        ) : (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
            {hero.map((s) => <ProofTile key={s.key} label={s.label} value={`${s.value}${s.unit === "%" ? "%" : s.unit === "" ? "" : " " + s.unit}`} tone="primary" />)}
            {scoped && posture && <ProofTile label="Posture grade (K8s)" value={posture.grade} tone="success" />}
          </div>
        )}
      </section>

      <div className="rounded-lg border border-border bg-elevated/40 px-4 py-3 text-[12px] text-muted-foreground">
        <span className="font-medium text-foreground">Deterministic brain.</span> Every number traces to a real metrics/audit file; the Customer-Owner lens is IP-walled (server-side); nothing is fabricated and pending items are labeled. Reproducible at <span className="font-mono text-foreground/80">seed 1337</span>.
      </div>
    </div>
  );
}

function ProofTile({ label, value, tone = "primary" }: { label: string; value: string; tone?: string }) {
  const c = tone === "success" ? "text-success" : "text-foreground";
  return (
    <Card><CardContent className="p-4">
      <div className={cn("text-2xl font-semibold tabular tracking-tight", c)}>{value}</div>
      <div className="mt-1 text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
    </CardContent></Card>
  );
}

export function OwnerLandingSummary({ rollup }: { rollup: OwnerRollup | null }) {
 return (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <ProofTile label="Protective actions" value={rollup ? String(rollup.actions) : "—"} />
            <ProofTile label="Selected actions dispatched" value={rollup?.dispatched == null ? "—" : String(rollup.dispatched)} tone="success" />
            <ProofTile label="Isolation attempts" value={rollup?.isolationAttempts == null ? "—" : String(rollup.isolationAttempts)} tone="success" />
            <ProofTile label="Effect confirmation" value="Unavailable" />
          </div>
 );
}
