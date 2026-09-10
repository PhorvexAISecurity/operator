"use client";
import * as React from "react";
import { applyFixApi, AFScope, AFAuditEntry, Lens } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";

type V = "real" | "danger" | "pending" | "neutral" | "accent";
const EVENT_META: Record<string, { label: string; variant: V }> = {
  "apply-fix.submitted": { label: "submitted", variant: "pending" },
  "apply-fix.applied": { label: "applied", variant: "real" },
  "apply-fix.rejected.allowlist": { label: "rejected · allowlist", variant: "danger" },
  "apply-fix.rejected.gate": { label: "rejected · gate", variant: "danger" },
  "apply-fix.rejected.twokey": { label: "refused · two-key", variant: "danger" },
  "apply-fix.apply.error": { label: "apply error", variant: "danger" },
};

export function AuditTrail({ scope, lens, refreshKey }: { scope: AFScope; lens: Lens; refreshKey: number }) {
  const [entries, setEntries] = React.useState<AFAuditEntry[]>([]);
  React.useEffect(() => {
    if (!scope.tenant) return;
    applyFixApi
      .audit(scope, lens)
      .then((d) => setEntries((d.audit || []).slice().reverse()))
      .catch(() => {});
  }, [scope, lens, refreshKey]);

  return (
    <Card>
      <CardContent className="space-y-2 p-5">
        <h3 className="text-sm font-semibold text-foreground">Audit trail</h3>
        {entries.length === 0 && (
          <p className="text-sm text-muted-foreground">No apply-fix events yet for tenant {scope.tenant || "?"}.</p>
        )}
        <ul className="space-y-1.5">
          {entries.map((e, i) => {
            const m = EVENT_META[e.event] || { label: e.event, variant: "neutral" as V };
            return (
              <li key={i} className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant={m.variant}>{m.label}</Badge>
                <span className="text-muted-foreground">id={String(e.fields.id ?? "")}</span>
                {e.fields.requester ? <span className="text-muted-foreground">by {String(e.fields.requester)}</span> : null}
                {e.fields.approver ? <span className="text-muted-foreground">approver {String(e.fields.approver)}</span> : null}
                {e.fields.error ? <span className="text-danger">{String(e.fields.error)}</span> : null}
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}
