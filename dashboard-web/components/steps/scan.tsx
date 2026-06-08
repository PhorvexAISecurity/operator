"use client";
import * as React from "react";
import { api, Lens } from "@/lib/api";
import { StepId } from "@/lib/journey";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Pending } from "@/components/ui/more";
import { StepHead } from "./shared";
import { cn } from "@/lib/utils";
import { Radar, Check, Loader2, ArrowRight } from "lucide-react";

const PHASES = [
  { k: "ingest", label: "Ingest cluster snapshot", detail: "nodes · PDBs · image digests · requests" },
  { k: "physics", label: "Derive physics witness", detail: "image-rarity · co-residency · slack · EPSS · MIG" },
  { k: "context", label: "Context / kill-chain", detail: "stage · P(hold) · moved-before-next-stage" },
  { k: "emr", label: "Scarcity (EMR) ablation", detail: "recon-per-dollar invalidation weighting" },
];

export function ScanStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const [phase, setPhase] = React.useState(-1);
  const [done, setDone] = React.useState(false);
  const [hasCorpus, setHasCorpus] = React.useState(false);
  React.useEffect(() => { api.health().then((h) => setHasCorpus(!!(h.hasP3Deep || h.hasPactuator))).catch(() => {}); }, []);

  function run() {
    setPhase(0); setDone(false);
    let i = 0;
    const t = setInterval(() => {
      i++; setPhase(i);
      if (i >= PHASES.length) { clearInterval(t); setDone(true); }
    }, 650);
  }

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={2} title="Scan" sub="Derive the platform's real physics — the discovered, both-products signal Phorvex optimizes over. On a CPU/kind cluster the GPU half is honestly [SP-0-PENDING-P4]." />

      <Pending stage="LIVE TRIGGER [PENDING-wire · Phase 3]" msg="A live POST /api/scan that execs `phorvex --scan` is the Phase-3 wire. Today this loads the latest discovered corpus from the real metrics + audit — never a fake animation over nothing." />

      <Card>
        <CardContent className="flex flex-col items-center gap-5 py-10">
          <div className={cn("grid h-16 w-16 place-items-center rounded-2xl ring-1 transition-colors", phase < 0 ? "bg-primary/10 ring-primary/30" : done ? "bg-success/10 ring-success/30" : "bg-primary/15 ring-primary/40")}>
            {phase < 0 ? <Radar className="h-7 w-7 text-primary" /> : done ? <Check className="h-7 w-7 text-success" /> : <Loader2 className="h-7 w-7 animate-spin text-primary" />}
          </div>
          {phase < 0 ? (
            <>
              <div className="text-center text-sm text-muted-foreground">Run the platform-physics scan to map this environment.</div>
              <Button onClick={run} disabled={!hasCorpus}>{hasCorpus ? "Run platform-physics scan" : "No scan corpus found"}</Button>
              {!hasCorpus && <div className="text-[12px] text-warning">No metrics corpus on disk yet — run an attack/benchmark first (Prove step).</div>}
            </>
          ) : (
            <div className="w-full max-w-md space-y-2.5">
              {PHASES.map((p, i) => {
                const st = i < phase ? "done" : i === phase ? "run" : "wait";
                return (
                  <div key={p.k} className={cn("flex items-center gap-3 rounded-md border px-3 py-2", st === "done" ? "border-success/20 bg-success/[0.04]" : st === "run" ? "border-primary/30 bg-primary/[0.05]" : "border-border/50 opacity-50")}>
                    {st === "done" ? <Check className="h-4 w-4 text-success" /> : st === "run" ? <Loader2 className="h-4 w-4 animate-spin text-primary" /> : <span className="h-4 w-4 rounded-full border border-border" />}
                    <div><div className="text-[13px] text-foreground">{p.label}</div><div className="text-[11px] text-muted-foreground">{p.detail}</div></div>
                  </div>
                );
              })}
            </div>
          )}
          {done && <Button onClick={() => go("discovered")}>See what was discovered <ArrowRight className="h-4 w-4" /></Button>}
        </CardContent>
      </Card>
    </div>
  );
}
