"use client";
import * as React from "react";
import { api, Lens, RTFinding } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Bug } from "lucide-react";
import { useApiRead } from "@/lib/query";

// RedTeamFindings renders the RL co-evolution findings (reasoning + fix + review status) from the now-
// wired /api/redteam/findings endpoint. Read-only display of real harness output; honest empty state.
export function RedTeamFindings({ lens }: { lens: Lens }) {
  const read = useApiRead({ lens, resource: "redteam-findings", fetcher: (signal) => api.redteamFindings(lens, signal), staleTime: 60_000 });
  const findings = read.data?.findings || [];
  const err = read.error && !read.data ? String((read.error as Error).message || read.error) : "";

  return (
    <Card>
      <CardContent className="space-y-3 p-5">
        <div className="flex items-center gap-2">
          <Bug className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">RL co-evolution findings</h3>
        </div>
        {err && <p className="text-sm text-danger">{err}</p>}
        {!err && findings.length === 0 && <p className="text-sm text-muted-foreground">No findings recorded yet.</p>}
        {findings.map((f) => (
          <div key={f.id} className="rounded-md border border-border bg-panel/40 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-foreground">{f.title}</span>
              <Badge variant={f.product === "ai" ? "accent" : "neutral"}>{f.product}</Badge>
              {f.cycle && <Badge variant="neutral">cycle {f.cycle}</Badge>}
              {f.status && <Badge variant={/address|neutral|fixed/i.test(f.status) ? "real" : "pending"}>{f.status}</Badge>}
            </div>
            {f.reasoning && <p className="mt-1 text-xs text-muted-foreground">{f.reasoning}</p>}
            {f.fix && (
              <p className="mt-1 text-xs">
                <span className="text-success">fix:</span> <span className="text-muted-foreground">{f.fix}</span>
                {f.fixFile && <span className="text-muted-foreground/70"> ({f.fixFile})</span>}
              </p>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
