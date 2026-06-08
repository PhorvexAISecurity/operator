"use client";
import * as React from "react";
import { cn } from "@/lib/utils";
import { Lens } from "@/lib/api";
import { STEPS, StepId, JourneySignals, stepState } from "@/lib/journey";
import { Activity, ShieldCheck, Lock, Check, PlayCircle, Home, ChevronRight } from "lucide-react";

const LENS_META: Record<Lens, { label: string; hint: string }> = {
  investor: { label: "Investor", hint: "the moat + the proofs" },
  operator: { label: "Operator", hint: "live defense + run methods" },
  owner: { label: "Customer-Owner", hint: "what changed in my platform (IP-walled)" },
};

export function Shell({
  lens, setLens, active, go, signals, onDemo, children,
}: {
  lens: Lens; setLens: (l: Lens) => void;
  active: StepId; go: (s: StepId) => void;
  signals: JourneySignals; onDemo: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-screen flex-col">
      {/* header */}
      <header className="sticky top-0 z-30 flex h-16 items-center justify-between gap-4 border-b border-border bg-background/80 px-6 backdrop-blur-xl">
        <button onClick={() => go("landing")} className="flex items-center gap-2.5">
          <div className="grid h-8 w-8 place-items-center rounded-md bg-primary/15 ring-1 ring-primary/30">
            <Activity className="h-4 w-4 text-primary" strokeWidth={2.5} />
          </div>
          <div className="leading-none text-left">
            <div className="text-[15px] font-semibold tracking-tight">Phorvex</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-[0.18em] text-muted-foreground">Console</div>
          </div>
        </button>
        <div className="hidden items-center gap-2 text-[12px] text-muted-foreground md:flex">
          <ShieldCheck className="h-4 w-4 text-success" />
          <span className="font-medium text-foreground">K8s proven on kind</span>
          <span className="text-muted-foreground/50">·</span>
          <span>AI defense <span className="text-warning">[SP-0-PENDING-P4]</span></span>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={onDemo} className="hidden items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-[12px] text-muted-foreground transition-colors hover:bg-elevated hover:text-foreground sm:flex">
            <PlayCircle className="h-3.5 w-3.5 text-primary" /> Guided demo
          </button>
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-1 text-[10px] text-muted-foreground/70 xl:flex" title="The owner IP-wall redaction is enforced server-side. Lens SELECTION is demo-trust until real authn (P-VCLUSTER).">
              <Lock className="h-3 w-3" /> demo-trust lens · redaction enforced
            </span>
            <div className="flex items-center gap-1 rounded-lg border border-border bg-panel/60 p-1">
              {(Object.keys(LENS_META) as Lens[]).map((l) => (
                <button key={l} onClick={() => setLens(l)} title={LENS_META[l].hint}
                  className={cn("rounded-md px-3 py-1.5 text-[12px] font-medium transition-all", lens === l ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}>
                  {LENS_META[l].label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </header>

      {/* journey bar (the navigation) */}
      <div className="sticky top-16 z-20 border-b border-border bg-panel/40 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1400px] items-center gap-1 overflow-x-auto px-4 py-2.5">
          <button onClick={() => go("landing")} title="Overview"
            className={cn("flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[12px] transition-colors", active === "landing" ? "bg-elevated text-foreground" : "text-muted-foreground hover:text-foreground")}>
            <Home className="h-3.5 w-3.5" />
          </button>
          {STEPS.map((s, i) => {
            const st = stepState(s.id, signals, active);
            const on = active === s.id;
            return (
              <React.Fragment key={s.id}>
                {i > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground/40" />}
                <button onClick={() => go(s.id)} disabled={st === "locked"}
                  className={cn("group flex shrink-0 items-center gap-2 rounded-md px-2.5 py-1.5 text-[12px] transition-all",
                    on ? "bg-primary/15 text-foreground ring-1 ring-primary/40" : st === "locked" ? "text-muted-foreground/40" : "text-muted-foreground hover:bg-elevated hover:text-foreground",
                    s.id === "protect" && !on && "ring-1 ring-primary/20")}>
                  <StateDot state={st} n={s.n} />
                  <span className="font-medium">{s.label}</span>
                  {s.id === "protect" && <span className="hidden rounded bg-primary/15 px-1.5 text-[9px] uppercase tracking-wide text-primary lg:inline">run methods</span>}
                </button>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* step canvas */}
      <main className="relative flex-1 overflow-y-auto">
        <div className="bg-grid pointer-events-none absolute inset-0 h-56" />
        <div className="relative mx-auto max-w-[1400px] px-6 py-7">{children}</div>
      </main>
    </div>
  );
}

function StateDot({ state, n }: { state: string; n: number }) {
  if (state === "done") return <span className="grid h-4 w-4 place-items-center rounded-full bg-success/20 text-success"><Check className="h-2.5 w-2.5" strokeWidth={3} /></span>;
  if (state === "active") return <span className="grid h-4 w-4 place-items-center rounded-full bg-primary text-primary-foreground text-[9px] font-bold">{n}</span>;
  if (state === "locked") return <span className="grid h-4 w-4 place-items-center rounded-full bg-muted/40 text-muted-foreground/50"><Lock className="h-2.5 w-2.5" /></span>;
  return <span className="grid h-4 w-4 place-items-center rounded-full border border-border text-[9px] text-muted-foreground">{n}</span>;
}
