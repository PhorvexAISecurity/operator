"use client";
import * as React from "react";
import { applyFixApi, AFIdentity, AFPending, Lens } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Loader2, KeyRound, Ban } from "lucide-react";

export function ApproveQueue({
  id,
  lens,
  refreshKey,
  onApproved,
}: {
  id: AFIdentity;
  lens: Lens;
  refreshKey: number;
  onApproved: () => void;
}) {
  const [pending, setPending] = React.useState<AFPending[]>([]);
  const [applierMode, setApplierMode] = React.useState("record-only");
  const [busy, setBusy] = React.useState("");
  const [msg, setMsg] = React.useState<{ id: string; ok: boolean; text: string } | null>(null);
  const ready = !!id.user;

  const load = React.useCallback(() => {
    if (!id.tenant) return;
    applyFixApi
      .pending(id, lens)
      .then((d) => {
        setPending(d.pending || []);
        setApplierMode(d.applierMode || "record-only");
      })
      .catch(() => {});
  }, [id, lens]);

  React.useEffect(() => {
    load();
  }, [load, refreshKey]);

  async function approve(reqId: string) {
    setBusy(reqId);
    setMsg(null);
    try {
      await applyFixApi.approve(reqId, id, lens);
      setMsg({ id: reqId, ok: true, text: `Approved + applied (${applierMode})` });
      onApproved();
      load();
    } catch (e: any) {
      setMsg({ id: reqId, ok: false, text: `${e.status === 422 ? "REFUSED (422)" : "Error"}: ${String(e.message || e)}` });
    } finally {
      setBusy("");
    }
  }

  return (
    <Card>
      <CardContent className="space-y-3 p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-foreground">Two-key approval queue</h3>
          <Badge variant={applierMode === "live" ? "real" : "pending"}>
            applier: {applierMode}
            {applierMode === "record-only" ? " · [PENDING deploy-wire]" : ""}
          </Badge>
        </div>

        {pending.length === 0 && (
          <p className="text-sm text-muted-foreground">No pending submissions for tenant {id.tenant || "?"}.</p>
        )}

        {pending.map((p) => {
          const selfApprove = p.requester === id.user;
          return (
            <div key={p.id} className="flex items-center justify-between gap-3 rounded-md border border-border bg-panel/40 px-3 py-2.5">
              <div className="min-w-0 text-sm">
                <div className="truncate font-medium text-foreground">{p.id}</div>
                <div className="text-xs text-muted-foreground">
                  requested by <span className="text-foreground">{p.requester}</span> · {p.reason} · Δ{p.deltaHash}
                </div>
                {msg && msg.id === p.id && <div className={"mt-1 text-xs " + (msg.ok ? "text-success" : "text-danger")}>{msg.text}</div>}
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {selfApprove && (
                  <span className="flex items-center gap-1 text-xs text-danger">
                    <Ban className="h-3.5 w-3.5" />
                    you are the requester
                  </span>
                )}
                <Button size="sm" variant={selfApprove ? "outline" : "primary"} onClick={() => approve(p.id)} disabled={!ready || busy === p.id}>
                  {busy === p.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                  Approve
                </Button>
              </div>
            </div>
          );
        })}

        <p className="text-xs text-muted-foreground">
          Two-key: the approver must be a <span className="text-foreground">DISTINCT</span> verified identity from the
          requester — a self-approval is refused server-side (422). Switch your user above to approve as a different
          person. The applier is <span className="text-warning">record-only</span> until a deployment wires the
          per-namespace-SA CRD patch.
        </p>
      </CardContent>
    </Card>
  );
}
