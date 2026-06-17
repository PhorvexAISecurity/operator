"use client";
import * as React from "react";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead } from "./effectiveness";
import { Lock } from "lucide-react";

const SLOTS: Record<string, { title: string; sub: string; stage: string; bullets: string[] }> = {
  actuator: {
    title: "Native Actuator", stage: "wired now · live detail at P-DASHBOARD-2",
    sub: "Phorvex's own 12-handler native actuator — proven 13 PASS / 0 FAIL on AWS EKS.",
    bullets: ["7 K8s handlers live (rotate, quarantine, identity/route-rotate, inject)", "5 AI/GPU state machines present; magnitudes [SP-0-PENDING-P4]", "Completeness is a CI + startup-enforced invariant"],
  },
  physics: {
    title: "Platform Physics Scan", stage: "Wave 3 · data ready (phorvex --scan)",
    sub: "The discovered PhysicsWitness per pod — image-rarity dispersion, co-residency, scheduler slack, MIG geometry, EPSS, and the residual r_i.",
    bullets: ["Values real-now on K8s (imgRarity/coRes/slack/PDB/migValid/epss)", "GPU half [SP-0-PENDING-P4]", "EMR scarcity scalar is Investor/Operator-only (owner-redacted)"],
  },
  context: {
    title: "Context / Kill-Chain", stage: "Wave 3 · audit + --scan",
    sub: "Kill-chain stage (incl. the 4 AI stages), the predictive horizon (moved-before-next-stage), P(hold)/belief, value/blast-radius.",
    bullets: ["Stage/hazard/pHold from the audit Record (now serialized)", "PreemptMargin/ProjectedNextStageSec horizon", "Owner sees a coarse stage label only"],
  },
  mtd: {
    title: "MTD / Decisions", stage: "Wave 3 · vendor scope",
    sub: "The dynamic action-set generation, the coverage-minus-lambda-cost scoring, the optimizer's choices, SHAP attribution, and the without-Phorvex counterfactual.",
    bullets: ["Investor/vendor scope only (the moat math)", "Source: phorvex --audit-json + --ablation", "Owner sees the sanitized outcome only"],
  },
  decisions: {
    title: "Decisions / Audit", stage: "vendor-scope · docks next",
    sub: "The full per-decision rationale stream — SHAP attribution, the without-Phorvex counterfactual, the predictive horizon.",
    bullets: ["Investor/vendor scope only (IP)", "Source: phorvex --audit-json", "moved-before-next-stage [PENDING-serialize]"],
  },
  redteam: {
    title: "RL Red-Team", stage: "P-REDTEAM",
    sub: "A cutting-edge reinforcement-learning pentester that continuously co-trains against the live Phorvex decision loop.",
    bullets: ["Human-approved promotion gates", "Feeds new adversarial scenarios into the benchmark", "Attacker-side only — Phorvex stays deterministic"],
  },
  vcluster: {
    title: "Multi-Tenant + Auth", stage: "P-VCLUSTER",
    sub: "Per-tenant physics/context with a hard isolation proof, plus real authentication / SSO.",
    bullets: ["Tenant/namespace partitioning is already real (the owner view is scoped today)", "Identity / SSO + isolation evidence pending", "Per-tenant cost attribution + SLA history"],
  },
  gpu: {
    title: "Real-Fleet / GPU", stage: "P4 · CoreWeave",
    sub: "SP-0 magnitude calibration on real GPUs — the AI actuator state machines validated, AI defense efficacy measured, real-fleet recon-per-dollar.",
    bullets: ["All AI/GPU magnitudes calibrated here", "AI defense efficacy validated (today a stub: disruptionVsOracle=0)", "1.62×/P3 parity re-established with GPU magnitudes active"],
  },
};

export function PendingPanel({ id }: { id: string }) {
  const s = SLOTS[id] || { title: "Coming soon", sub: "", stage: "", bullets: [] };
  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title={s.title} sub={s.sub} />
      <Card className="relative overflow-hidden border-dashed">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <CardContent className="relative flex flex-col items-center gap-4 px-6 py-14 text-center">
          <div className="grid h-12 w-12 place-items-center rounded-xl bg-warning/10 ring-1 ring-warning/30">
            <Lock className="h-5 w-5 text-warning" />
          </div>
          <Badge variant="pending">PENDING · {s.stage}</Badge>
          <div className="max-w-md text-sm leading-relaxed text-muted-foreground">
            This panel is a pre-wired slot in the growing shell. It docks with <span className="text-foreground">no rebuild</span> when its stage ships — and renders only honest data, never a fabricated number.
          </div>
          <ul className="mt-1 space-y-1.5 text-left text-[12px] text-muted-foreground">
            {s.bullets.map((b, i) => (
              <li key={i} className="flex items-start gap-2"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />{b}</li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
