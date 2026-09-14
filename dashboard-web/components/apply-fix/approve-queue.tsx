"use client";
import * as React from "react";
import { applyFixApi, AFScope, AFPending, AFApproveOutcome, Lens, Session } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Loader2, KeyRound, Ban } from "lucide-react";

// outcomeText renders the server's status for ONE approval. Only "applied" is a success; nothing is
// inferred from the HTTP code or from the applier label.
function outcomeText(o: AFApproveOutcome): { ok: boolean; text: string } {
  const detail = o.error ? ` — ${o.error}` : "";
  switch (o.status) {
    case "applied":
      return { ok: true, text: o.retry ? "Applied (already applied by this approval; not re-run)" : "Applied — the applier accepted the candidate" };
    case "applier-unavailable":
      return { ok: false, text: "Not applied — no applier is wired in this deployment; the request stays pending" };
    case "in-progress":
      return { ok: false, text: `Not applied — another approval by ${o.approver || "someone"} is being applied right now` };
    case "conflict":
      return { ok: false, text: `Not applied — this request already ended as ${o.state} by ${o.approver || "another approver"}` };
    case "stale-generation":
      return { ok: false, text: "Not applied — the request changed (or the console restarted) since this list loaded; reload and re-check" };
    case "stale":
      return { ok: false, text: "Not applied — the tenant's base policy changed since submit; resubmit against the current policy" };
    case "refused":
      return { ok: false, text: `Refused — two-key: the approver must differ from the requester${detail}` };
    case "rejected":
      return { ok: false, text: `Rejected by the safety gate at approval${detail}` };
    case "failed":
      return { ok: false, text: `Apply FAILED — the cluster effect is unknown; reconcile before submitting again${detail}` };
    case "not-found":
      return { ok: false, text: "Not applied — no such request for this tenant" };
    default:
      return { ok: false, text: `Not applied — ${o.status}${detail}` };
  }
}

export function ApproveQueue({
  session,
  scope,
  lens,
  refreshKey,
  onApproved,
}: {
  session: Session | null;
  scope: AFScope;
  lens: Lens;
  refreshKey: number;
  onApproved: () => void;
}) {
  const [pending, setPending] = React.useState<AFPending[]>([]);
  const [applierMode, setApplierMode] = React.useState("record-only");
  const [applierWired, setApplierWired] = React.useState(false);
  const [busy, setBusy] = React.useState("");
  const [msg, setMsg] = React.useState<{ id: string; ok: boolean; text: string } | null>(null);
  // Approving is an operator control; a read-only grant sees the queue but cannot act.
  const ready = !!session?.canEdit;

  const load = React.useCallback(() => {
    if (!scope.tenant) return;
    applyFixApi
      .pending(scope, lens)
      .then((d) => {
        setPending(d.pending || []);
        setApplierMode(d.applierMode || "record-only");
        setApplierWired(!!d.applierWired);
      })
      .catch(() => {});
  }, [scope, lens]);

  React.useEffect(() => {
    load();
  }, [load, refreshKey]);

  // The approval names the exact pending generation and the selected tenant (sent as ?tenant= by
  // the API client), so it can only ever act on the record this row shows.
  async function approve(p: AFPending) {
    setBusy(p.id);
    setMsg(null);
    try {
      const outcome = await applyFixApi.approve({ id: p.id, generation: p.generation }, scope, lens);
      const r = outcomeText(outcome);
      setMsg({ id: p.id, ...r });
      if (r.ok) onApproved();
      load();
    } catch (e: any) {
      setMsg({ id: p.id, ok: false, text: `Error (${e.status ?? "network"}): ${String(e.message || e)}` });
    } finally {
      setBusy("");
    }
  }

  return (
    <Card>
      <CardContent className="space-y-3 p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-foreground">Two-key approval queue</h3>
          <Badge variant={applierWired ? "real" : "pending"}>
            applier: {applierMode}
            {applierWired ? "" : " · not wired — approvals cannot apply"}
          </Badge>
        </div>

        {pending.length === 0 && (
          <p className="text-sm text-muted-foreground">No open submissions for tenant {scope.tenant || "?"}.</p>
        )}

        {pending.map((p) => {
          // The requester is the verified subject the server recorded ("<issuer>#<subject>").
          const selfApprove = !!session && p.requester.endsWith("#" + session.subject);
          const applying = p.state === "applying";
          return (
            <div key={p.generation} className="flex items-center justify-between gap-3 rounded-md border border-border bg-panel/40 px-3 py-2.5">
              <div className="min-w-0 text-sm">
                <div className="flex items-center gap-2">
                  <span className="truncate font-medium text-foreground">{p.id}</span>
                  <Badge variant={applying ? "accent" : "pending"}>{p.state}</Badge>
                </div>
                <div className="text-xs text-muted-foreground">
                  requested by <span className="text-foreground">{p.requester}</span> · {p.reason} · Δ{p.deltaHash} · gen {p.generation}
                  {applying && p.approver ? <> · applying by <span className="text-foreground">{p.approver}</span></> : null}
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
                <Button size="sm" variant={selfApprove ? "outline" : "primary"} onClick={() => approve(p)} disabled={!ready || applying || busy === p.id}>
                  {busy === p.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                  Approve
                </Button>
              </div>
            </div>
          );
        })}

        <p className="text-xs text-muted-foreground">
          Two-key: the approver must be a <span className="text-foreground">DISTINCT</span> verified identity from the
          requester — a self-approval is refused server-side. Each approval names the exact request generation shown here and
          is applied at most once; a competing approval is answered as in-progress or conflict, never applied twice.
          {applierWired ? null : (
            <>
              {" "}
              With <span className="text-warning">no applier wired</span>, an approval is answered as not applied and the request stays
              pending.
            </>
          )}
        </p>
      </CardContent>
    </Card>
  );
}
