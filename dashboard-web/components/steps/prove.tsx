"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { GroupedSegmented } from "@/components/ui/more";
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
import { CostPanel } from "@/components/panels/cost";
import { useSelectedTarget } from "@/lib/provider-store";
import { useScopedUIState } from "@/lib/use-scoped-ui-state";

type Sub = "launch" | "run" | "effectiveness" | "cost" | "frontier" | "benchmarks" | "coverage" | "gap" | "matrix" | "aiboundary" | "posture" | "ablation" | "comparison";

export function ProveStep({ lens }: { lens: Lens }) {
  const selected = useSelectedTarget();
  const [sub, setSub] = useScopedUIState<Sub>(`prove-tab\u0000${lens}\u0000${selected.context}`, "launch");
  const owner = lens === "owner";
  const primaryTabs: { id: Sub; label: string }[] = [
    { id: "launch", label: "Attack catalog" },
    { id: "run", label: "Live run" },
    { id: "effectiveness", label: "Effectiveness" },
    { id: "coverage", label: "Threat coverage" },
    { id: "posture", label: "Posture" },
  ];
  const operatorDetailTabs: { id: Sub; label: string }[] = owner ? [] : [
    { id: "gap", label: "Coverage gap" },
    { id: "matrix", label: "52×N matrix" },
    { id: "aiboundary", label: "AI boundary" },
    { id: "ablation", label: "Recon-per-$" },
  ];
  const detailTabs: { id: Sub; label: string }[] = [
    { id: "cost", label: "Cost (with/without)" },
    { id: "frontier", label: "Zero-day frontier" },
    { id: "benchmarks", label: "Benchmarks" },
    { id: "comparison", label: "vs Without-Phorvex" },
    ...operatorDetailTabs,
  ];
  const availableTabs = [...primaryTabs, ...detailTabs];
  const activeSub = availableTabs.some((tab) => tab.id === sub) ? sub : "launch";
  React.useEffect(() => {
    if (activeSub !== sub) setSub(activeSub);
  }, [activeSub, sub]);
  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={6} title="Prove" sub="Attack the platform — with and without Phorvex — and watch the proof land: live eviction, the effectiveness board, the structural zero-day certificate, the scenario×arm matrix, the honest coverage gaps, and the benchmark evidence. AI defense is honestly [SP-0-PENDING-P4]." lens={lens} />
      <GroupedSegmented value={activeSub} onChange={setSub} primary={primaryTabs} secondary={detailTabs} />
      <div>
        {activeSub === "launch" && <CatalogPanel lens={lens} />}
        {activeSub === "run" && <RunAttackPanel lens={lens} />}
        {activeSub === "effectiveness" && <EffectivenessPanel lens={lens} />}
        {activeSub === "cost" && <CostPanel lens={lens} />}
        {activeSub === "frontier" && <FrontierPanel lens={lens} />}
        {activeSub === "benchmarks" && <BenchmarksPanel lens={lens} />}
        {activeSub === "comparison" && <ReportsPanel lens={lens} only="Comparison" intro="Phorvex vs Without-Phorvex (baseline Phoenix) — the head-to-head, served live from COMPARISON.md." />}
        {activeSub === "coverage" && <ThreatMatrixPanel lens={lens} />}
        {activeSub === "gap" && <UncoveredFrontier lens={lens} />}
        {activeSub === "matrix" && <MatrixPanel lens={lens} />}
        {activeSub === "aiboundary" && <AIBoundary lens={lens} />}
        {activeSub === "ablation" && <AblationPanel lens={lens} />}
        {activeSub === "posture" && <PosturePanel lens={lens} />}
      </div>
    </div>
  );
}
