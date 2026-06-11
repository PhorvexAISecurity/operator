"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { StepId } from "@/lib/journey";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Segmented } from "@/components/ui/more";
import { StepHead } from "./shared";
import { LiveOpsPanel } from "@/components/panels/liveops";
import { OptimizationPanel, CostPanel, ActuatorPanel, HealthPanel } from "@/components/subsystems/panels";
import { RiskHeatmap } from "@/components/subsystems/analytics";
import { ApplyFixPanel } from "@/components/panels/apply-fix";
import { cn } from "@/lib/utils";
import { Play, Pause, Radar, Swords, Hand } from "lucide-react";

export function ProtectStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const [sub, setSub] = React.useState<"live" | "mtd" | "cost" | "actuator" | "health" | "risk" | "applyfix">("live");
  const owner = lens === "owner";
  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={4} title="Protect / Run" sub={owner ? "Phorvex protecting your platform, in plain language — what it did and that it helped." : "The home for every method. Start Phorvex, watch the optimizer DECIDE and the actuator ACTUATE in real time, and drill into the action set, the coverage−λ·cost scoring, and why each move was chosen."} lens={lens} />
      {!owner && <Segmented value={sub} onChange={setSub} tabs={[{ id: "live", label: "Live theatre" }, { id: "mtd", label: "MTD / Optimization" }, { id: "cost", label: "Cost" }, { id: "actuator", label: "Actuator" }, { id: "applyfix", label: "Apply-fix" }, { id: "risk", label: "Risk heatmap" }, { id: "health", label: "Health" }]} />}

      {owner || sub === "live" ? (
        <>
          {!owner && (
            <Card><CardContent className="flex flex-wrap items-center justify-between gap-4 p-4">
              <div className="flex items-center gap-3">
                {/* [P2 #2] The operator MODE control is a cluster WRITE (patch the PhorvexPolicy mode /
                    start-stop the operator). The console is read-only + safe-triggers only, so this is
                    HONESTLY DISABLED ([coming]) rather than a dead button that looks live. The operator
                    is controlled out-of-band (kubectl/Helm); the dashboard streams its real audit. */}
                <div className="flex items-center gap-1 rounded-lg border border-border/60 bg-panel/40 p-1 opacity-60">
                  <span className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[12px] font-medium text-muted-foreground"><Play className="h-3 w-3" /> Active</span>
                  <span className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[12px] font-medium text-muted-foreground"><Pause className="h-3 w-3" /> Dry-run</span>
                </div>
                <Badge variant="pending">operator control · coming</Badge>
                <span className="text-[12px] text-muted-foreground">start/stop &amp; mode are an out-of-band cluster write (kubectl/Helm); this view streams the operator's real decision audit.</span>
              </div>
              <div className="flex items-center gap-2"><span className="flex items-center gap-1.5 text-[12px] text-muted-foreground"><Hand className="h-3.5 w-3.5" /> native actuator</span><Badge variant="real">streaming the live decision audit</Badge></div>
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
      ) : sub === "mtd" ? <OptimizationPanel lens={lens} />
        : sub === "cost" ? <CostPanel lens={lens} />
        : sub === "actuator" ? <ActuatorPanel lens={lens} />
        : sub === "applyfix" ? <ApplyFixPanel lens={lens} />
        : sub === "risk" ? <RiskHeatmap lens={lens} />
        : <HealthPanel lens={lens} />}
    </div>
  );
}
