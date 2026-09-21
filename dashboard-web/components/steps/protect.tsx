"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { StepId } from "@/lib/journey";
import { Card, CardContent, Button } from "@/components/ui/primitives";
import { GroupedSegmented } from "@/components/ui/more";
import { StepHead } from "./shared";
import { LiveOpsPanel } from "@/components/panels/liveops";
import { LiveLauncherPanel } from "@/components/panels/live-launcher";
import { PolicyControlPanel } from "@/components/panels/policy-control";
import { UptimePanel } from "@/components/panels/uptime";
import { AttackMonitoringPanel } from "@/components/panels/attack-monitoring";
import { AvailabilityArmsPanel } from "@/components/panels/availability-arms";
import { BrainBreakdownPanel } from "@/components/panels/brain-breakdown";
import { OptimizationPanel, CostPanel, ActuatorPanel, HealthPanel } from "@/components/subsystems/panels";
import { RiskHeatmap } from "@/components/subsystems/analytics";
import { ApplyFixPanel } from "@/components/panels/apply-fix";
import { Radar, Swords } from "lucide-react";
import { useSelectedTarget } from "@/lib/provider-store";
import { useScopedUIState } from "@/lib/use-scoped-ui-state";

type Sub = "live" | "launcher" | "policy" | "mtd" | "cost" | "uptime" | "monitoring" | "arms" | "brain" | "actuator" | "health" | "risk" | "applyfix";

export function ProtectStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const selected = useSelectedTarget();
  const [sub, setSub] = useScopedUIState<Sub>(`protect-tab\u0000${lens}\u0000${selected.context}`, "live");
  const owner = lens === "owner";
  const operator = lens === "operator";
  const activeSub = !operator && sub === "policy" ? "live" : sub;
  React.useEffect(() => {
    if (activeSub !== sub) setSub(activeSub);
  }, [activeSub, sub]);
  const primaryTabs: { id: Sub; label: string }[] = [
    { id: "live", label: "Live theatre" }, { id: "launcher", label: "Attack launcher" },
    ...(operator ? [{ id: "policy" as const, label: "Policy control" }] : []),
    { id: "brain", label: "Brain / reason" },
  ];
  const detailTabs: { id: Sub; label: string }[] = [
    { id: "mtd", label: "MTD / Optimization" },
    { id: "cost", label: "Cost" }, { id: "uptime", label: "Uptime" },
    { id: "monitoring", label: "Attack monitoring" }, { id: "arms", label: "Availability: 3-way" },
    { id: "actuator", label: "Actuator" }, { id: "applyfix", label: "Apply-fix" },
    { id: "risk", label: "Risk heatmap" }, { id: "health", label: "Health" },
  ];
  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={5} title="Protect / Run" sub={owner ? "Phorvex protecting your platform, in plain language — what it did and that it helped." : "The home for every method. Start Phorvex, watch the optimizer DECIDE and the actuator ACTUATE in real time, and drill into the action set, the coverage−λ·cost scoring, and why each move was chosen."} lens={lens} />
      {!owner && <GroupedSegmented value={activeSub} onChange={setSub} primary={primaryTabs} secondary={detailTabs} />}

      {owner || activeSub === "live" ? (
        <>
          {operator && (
            <Card><CardContent className="flex flex-wrap items-center justify-between gap-4 p-4">
              <div className="flex min-w-0 flex-wrap items-center gap-3">
                <Button variant="outline" onClick={() => setSub("policy")}>Open policy control</Button>
                <span className="min-w-0 text-sm text-muted-foreground">Change Active / Dry-run mode and allowed actions in Policy control. Starting or stopping the operator service requires cluster administration.</span>
              </div>
            </CardContent></Card>
          )}
          <LiveOpsPanel lens={lens} />
          {!owner && (
            <Card><CardContent className="p-4">
              <div className="mb-2.5 text-[11px] uppercase tracking-wider text-muted-foreground">Run a method</div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <button onClick={() => go("scan")} className="flex items-center gap-2.5 rounded-md border border-border bg-elevated/30 px-3 py-2.5 text-left text-[13px] transition-colors hover:bg-elevated/60"><Radar className="h-4 w-4 text-primary" /> Re-scan platform physics</button>
                <button onClick={() => go("prove")} className="flex items-center gap-2.5 rounded-md border border-border bg-elevated/30 px-3 py-2.5 text-left text-[13px] transition-colors hover:bg-elevated/60"><Swords className="h-4 w-4 text-primary" /> Run an attack scenario</button>
                <button onClick={() => go("discovered")} className="flex items-center gap-2.5 rounded-md border border-border bg-elevated/30 px-3 py-2.5 text-left text-[13px] transition-colors hover:bg-elevated/60"><Radar className="h-4 w-4 text-primary" /> View the platform map</button>
              </div>
            </CardContent></Card>
          )}
        </>
      ) : activeSub === "launcher" ? <LiveLauncherPanel lens={lens} />
        : activeSub === "policy" && operator ? <PolicyControlPanel lens={lens} />
        : activeSub === "brain" ? <BrainBreakdownPanel lens={lens} />
        : activeSub === "mtd" ? <OptimizationPanel lens={lens} />
        : activeSub === "cost" ? <CostPanel lens={lens} />
        : activeSub === "uptime" ? <UptimePanel lens={lens} />
        : activeSub === "monitoring" ? <AttackMonitoringPanel lens={lens} />
        : activeSub === "arms" ? <AvailabilityArmsPanel lens={lens} />
        : activeSub === "actuator" ? <ActuatorPanel lens={lens} />
        : activeSub === "applyfix" ? <ApplyFixPanel lens={lens} />
        : activeSub === "risk" ? <RiskHeatmap lens={lens} />
        : <HealthPanel lens={lens} />}
    </div>
  );
}
