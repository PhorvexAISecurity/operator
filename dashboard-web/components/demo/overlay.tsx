"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { StepId } from "@/lib/journey";
import { cn } from "@/lib/utils";
import { Play, Pause, ChevronLeft, ChevronRight, X } from "lucide-react";

interface Beat { step: StepId; dwell: number; investor: string; customer: string }

export const DEMO_BEATS: Beat[] = [
  { step: "landing", dwell: 11000,
    investor: "Phorvex is deterministic moving-target defense — it evicts attackers before they reach their objective. Six steps; PROTECT is where every method runs.",
    customer: "This is how Phorvex protects your platform — six simple steps, from connecting your cluster to a downloadable report." },
  { step: "connect", dwell: 9000,
    investor: "We connect to your live AWS EKS cluster, reproducible at seed 1337. K8s defense is proven live on EKS; GPU magnitudes are pending a GPU node pool.",
    customer: "First we connect to your environment. Today that's a live Kubernetes cluster; your cloud and GPU clusters slot in next." },
  { step: "scan", dwell: 12000,
    investor: "One scan derives the platform's real physics — image-rarity, co-residency, scheduler slack, EPSS — plus the kill-chain context. No hardcoded inputs; it's all discovered.",
    customer: "One click maps your platform — what's running, what's exposed, and where the risk concentrates." },
  { step: "discovered", dwell: 16000,
    investor: "The discovered map: your crown jewels, each workload's kill-chain stage, and the blast radius. This asset-aware, stage-aware context is what makes the defense targeted, not blind.",
    customer: "Here's what we found — your most valuable workloads and how an attacker could move toward them." },
  { step: "protect", dwell: 20000,
    investor: "PROTECT is the engine room. The optimizer scores every candidate move by coverage minus cost, picks the best under budget, and the native actuator enacts it — live, explainable, with the without-Phorvex counterfactual beside it.",
    customer: "Phorvex now defends in real time — you can see exactly what it did to each threat, and that your workloads kept running." },
  { step: "prove", dwell: 16000,
    investor: "Now we prove it: 52 real attack scenarios, with and without Phorvex. The structural zero-day frontier shows no blind interval wins; Phorvex evicts at one-third the dwell with zero harm.",
    customer: "We attack your platform on purpose — with and without Phorvex — so you can see the difference yourself." },
  { step: "report", dwell: 11000,
    investor: "Every number traces to a real file with a 95% CI. K8s is proven; AI defense is honestly pending real-GPU validation. Export the pack and the moat math stays behind the vendor lens.",
    customer: "And it's all in one evidence pack — every result, with its confidence interval, ready to download." },
];

export function DemoOverlay({ lens, go, onClose }: { lens: Lens; go: (s: StepId) => void; onClose: () => void }) {
  const [i, setI] = React.useState(0);
  const [playing, setPlaying] = React.useState(true);
  const audience: "investor" | "customer" = lens === "owner" ? "customer" : "investor";
  const beat = DEMO_BEATS[i];

  React.useEffect(() => { go(beat.step); }, [i]); // eslint-disable-line
  React.useEffect(() => {
    if (!playing) return;
    const t = setTimeout(() => setI((x) => Math.min(DEMO_BEATS.length - 1, x + 1)), beat.dwell);
    return () => clearTimeout(t);
  }, [i, playing]); // eslint-disable-line

  const last = i === DEMO_BEATS.length - 1;
  return (
    <div className="fixed inset-x-0 bottom-6 z-50 flex justify-center px-4">
      <div className="animate-fade-up w-full max-w-2xl rounded-xl border border-primary/20 bg-panel/95 p-4 shadow-2xl backdrop-blur-xl">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full bg-primary/15 text-[12px] font-bold text-primary ring-1 ring-primary/30">{i + 1}</span>
          <div className="flex-1">
            <div className="text-[11px] font-medium uppercase tracking-wider text-primary/80">{beat.step} · {audience} walkthrough</div>
            <p className="mt-1 text-[13.5px] leading-relaxed text-foreground">{audience === "investor" ? beat.investor : beat.customer}</p>
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-muted-foreground hover:bg-elevated hover:text-foreground"><X className="h-4 w-4" /></button>
        </div>
        <div className="mt-3 flex items-center justify-between border-t border-border/60 pt-3">
          <div className="flex items-center gap-1.5">
            {DEMO_BEATS.map((_, k) => <span key={k} className={cn("h-1.5 rounded-full transition-all", k === i ? "w-5 bg-primary" : "w-1.5 bg-muted")} />)}
          </div>
          <div className="flex items-center gap-1">
            <button onClick={() => setI((x) => Math.max(0, x - 1))} disabled={i === 0} className="rounded-md p-1.5 text-muted-foreground hover:bg-elevated hover:text-foreground disabled:opacity-40"><ChevronLeft className="h-4 w-4" /></button>
            <button onClick={() => setPlaying((p) => !p)} className="rounded-md p-1.5 text-primary hover:bg-elevated">{playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}</button>
            {last ? <button onClick={onClose} className="rounded-md px-3 py-1.5 text-[12px] font-medium text-primary hover:bg-elevated">Finish</button>
              : <button onClick={() => setI((x) => Math.min(DEMO_BEATS.length - 1, x + 1))} className="rounded-md p-1.5 text-muted-foreground hover:bg-elevated hover:text-foreground"><ChevronRight className="h-4 w-4" /></button>}
          </div>
        </div>
      </div>
    </div>
  );
}
