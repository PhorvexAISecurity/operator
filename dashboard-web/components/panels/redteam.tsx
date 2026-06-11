"use client";
import * as React from "react";
import { api, Lens, RTCampaign } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { PageHead } from "./effectiveness";
import { RedTeamFindings } from "@/components/redteam/findings";
import { RedTeamGates } from "@/components/redteam/gates";
import { Swords } from "lucide-react";

// RedTeamPanel wires the BUILDABLE red-team read endpoints (findings / gates / campaigns) into the React
// dashboard — previously these were backend-only (the UI-wiring audit gap). The RL run / continuous
// co-training / live-actuation endpoints trigger compute or need a real cluster, so they are surfaced as
// labeled [PENDING-CLUSTER-VALIDATION] actions (run out-of-band), not auto-run from the browser.
export function RedTeamPanel({ lens }: { lens: Lens }) {
  const [campaigns, setCampaigns] = React.useState<RTCampaign[]>([]);
  React.useEffect(() => {
    api.redteamCampaigns(lens).then((d) => setCampaigns(d.campaigns || [])).catch(() => {});
  }, [lens]);

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead
        title="RL Red-Team"
        sub="The reinforcement-learning pentester's co-evolution findings, the live regression gates, and the campaign results (Phorvex vs reactive/blind/random). Phorvex stays deterministic; the attacker side is the RL agent."
      />

      <RedTeamGates lens={lens} />
      <RedTeamFindings lens={lens} />

      <Card>
        <CardContent className="space-y-3 p-5">
          <div className="flex items-center gap-2">
            <Swords className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Campaigns — Phorvex vs baselines</h3>
          </div>
          {campaigns.length === 0 && <p className="text-sm text-muted-foreground">No campaign results recorded yet.</p>}
          {campaigns.map((c) => (
            <div key={c.scenario + c.product} className="rounded-md border border-border bg-panel/40 p-3">
              <div className="mb-1 flex items-center gap-2">
                <span className="text-sm font-medium text-foreground">{c.scenario}</span>
                <Badge variant={c.product === "ai" ? "accent" : "neutral"}>{c.product}</Badge>
              </div>
              <div className="grid grid-cols-2 gap-1 text-xs sm:grid-cols-4">
                {c.arms.map((a) => (
                  <div key={a.arm} className="rounded border border-border/60 px-2 py-1">
                    <div className="text-muted-foreground">{a.arm}</div>
                    <div className="text-foreground">disrupt {a.disruption.toFixed(2)} · n={a.n}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-4 text-xs text-muted-foreground">
          <Badge variant="pending">[PENDING-CLUSTER-VALIDATION]</Badge>{" "}
          <span className="ml-1">
            The RL <span className="text-foreground">run</span>, <span className="text-foreground">continuous co-training</span>, and{" "}
            <span className="text-foreground">live-actuation</span> endpoints trigger real compute / need a live cluster — run them out-of-band
            (see REAL-ENV-VALIDATION.md), not from the browser.
          </span>
        </CardContent>
      </Card>
    </div>
  );
}
