"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { Segmented } from "@/components/ui/more";
import { StepHead } from "./shared";
import { CatalogPanel } from "@/components/panels/catalog";
import { EffectivenessPanel } from "@/components/panels/effectiveness";
import { FrontierPanel } from "@/components/panels/frontier";
import { BenchmarksPanel } from "@/components/panels/benchmarks";
import { ThreatMatrixPanel, PosturePanel } from "@/components/panels/coverage";
import { RunAttackPanel } from "@/components/panels/run-attack";
import { AblationPanel } from "@/components/subsystems/panels";
import { UncoveredFrontier, MatrixPanel, AIBoundary } from "@/components/subsystems/analytics";
import { ReportsPanel } from "@/components/panels/reports";
import { RedTeamPanel } from "@/components/panels/redteam";

type Sub = "launch" | "run" | "effectiveness" | "frontier" | "benchmarks" | "coverage" | "gap" | "matrix" | "aiboundary" | "posture" | "ablation" | "comparison" | "redteam";

export function ProveStep({ lens }: { lens: Lens }) {
  const [sub, setSub] = React.useState<Sub>("launch");
  const owner = lens === "owner";
  const tabs = [
    { id: "launch", label: "Attack catalog" },
    { id: "run", label: "Live run" },
    { id: "effectiveness", label: "Effectiveness" },
    { id: "frontier", label: "Zero-day frontier" },
    { id: "benchmarks", label: "Benchmarks" },
    { id: "comparison", label: "vs R6" },
    { id: "coverage", label: "Threat coverage" },
    ...(owner ? [] : [
      { id: "gap", label: "Coverage gap" },
      { id: "matrix", label: "52×N matrix" },
      { id: "aiboundary", label: "AI boundary" },
      { id: "ablation", label: "Recon-per-$" },
      { id: "redteam", label: "RL red-team" },
    ]),
    { id: "posture", label: "Posture" },
  ];
  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={5} title="Prove" sub="Attack the platform — with and without Phorvex — and watch the proof land: live eviction, the effectiveness board, the structural zero-day certificate, the scenario×arm matrix, the honest coverage gaps, and the benchmark evidence. AI defense is honestly [SP-0-PENDING-P4]." lens={lens} />
      <Segmented value={sub} onChange={(v) => setSub(v as Sub)} tabs={tabs} />
      <div>
        {sub === "launch" && <CatalogPanel lens={lens} />}
        {sub === "run" && <RunAttackPanel lens={lens} />}
        {sub === "effectiveness" && <EffectivenessPanel lens={lens} />}
        {sub === "frontier" && <FrontierPanel lens={lens} />}
        {sub === "benchmarks" && <BenchmarksPanel lens={lens} />}
        {sub === "comparison" && <ReportsPanel lens={lens} only="Comparison" intro="Phorvex vs R6 — the head-to-head, served live from COMPARISON.md." />}
        {sub === "coverage" && <ThreatMatrixPanel lens={lens} />}
        {sub === "gap" && <UncoveredFrontier lens={lens} />}
        {sub === "matrix" && <MatrixPanel lens={lens} />}
        {sub === "aiboundary" && <AIBoundary lens={lens} />}
        {sub === "ablation" && <AblationPanel lens={lens} />}
        {sub === "redteam" && <RedTeamPanel lens={lens} />}
        {sub === "posture" && <PosturePanel lens={lens} />}
      </div>
    </div>
  );
}
