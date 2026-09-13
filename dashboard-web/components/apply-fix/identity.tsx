"use client";
import * as React from "react";
import { AFScope, Session, api, isUnauthenticated } from "@/lib/api";
import { Badge } from "@/components/ui/primitives";
import { ShieldCheck, ShieldAlert, Lock } from "lucide-react";

// [M-136] The acting principal is the VERIFIED session — there are no editable user/tenant
// inputs any more, because those were the demo-trust identity this fix removed. What remains
// selectable is which of the caller's GRANTED tenants it is acting on, and the server refuses
// anything outside that grant regardless of what is selected here.
export function useApplyFixIdentity() {
  const [session, setSession] = React.useState<Session | null>(null);
  const [error, setError] = React.useState<string>("");
  const [scope, setScope] = React.useState<AFScope>({});

  React.useEffect(() => {
    let live = true;
    api
      .session()
      .then((s) => {
        if (!live) return;
        setSession(s);
        // Pre-select when there is exactly one granted tenant; never guess otherwise.
        const concrete = s.tenants.filter((t) => t !== "*");
        setScope(concrete.length === 1 ? { tenant: concrete[0] } : {});
      })
      .catch((e) => {
        if (!live) return;
        setError(isUnauthenticated(e) ? "Your console session has expired — reload to sign in again." : String(e.message || e));
      });
    return () => {
      live = false;
    };
  }, []);

  const update = (next: Partial<AFScope>) => setScope((p) => ({ ...p, ...next }));
  return { session, scope, update, error };
}

const field =
  "rounded-md border border-border bg-background/60 px-2.5 py-1.5 text-sm text-foreground focus:border-primary focus:outline-none";

// IdentityBar shows WHO the server says you are and WHAT it has granted you. It is a readout of
// server state, not an input to it.
export function IdentityBar({
  session, scope, update, error,
}: {
  session: Session | null;
  scope: AFScope;
  update: (n: Partial<AFScope>) => void;
  error: string;
}) {
  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/5 px-4 py-3 text-sm">
        <ShieldAlert className="h-4 w-4 text-amber-400" />
        <span className="text-muted-foreground">{error}</span>
      </div>
    );
  }
  if (!session) {
    return <div className="rounded-lg border border-border bg-panel/50 px-4 py-3 text-sm text-muted-foreground">Resolving your console session…</div>;
  }
  const selectable = session.tenants.filter((t) => t !== "*");
  const wildcard = session.tenants.includes("*");
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-panel/50 px-4 py-3">
      <span className="flex items-center gap-2 text-sm">
        <ShieldCheck className="h-4 w-4 text-emerald-400" />
        <span className="text-muted-foreground">Signed in as</span>
        <span className="font-medium text-foreground">{session.subject}</span>
        <Badge variant="neutral">{session.roles.join(" · ") || "no role"}</Badge>
        <Badge variant="neutral">{session.source === "alb" ? "ALB Cognito" : "bearer"}</Badge>
      </span>

      {wildcard ? (
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          acting on tenant
          <input
            className={field}
            placeholder="tenant"
            value={scope.tenant ?? ""}
            onChange={(e) => update({ tenant: e.target.value.trim() })}
          />
          <span className="text-[11px]">cross-tenant grant — name the tenant explicitly</span>
        </label>
      ) : selectable.length > 1 ? (
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          acting on tenant
          <select className={field} value={scope.tenant ?? ""} onChange={(e) => update({ tenant: e.target.value })}>
            <option value="">select…</option>
            {selectable.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </label>
      ) : (
        <Badge variant="neutral">tenant {selectable[0] ?? "none granted"}</Badge>
      )}

      {!session.canEdit && (
        <span className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <Lock className="h-3 w-3" /> read-only grant — submitting and approving require the operator role
        </span>
      )}
      {!session.grantsConfigured && (
        <Badge variant="pending">no subject grants configured on this deployment</Badge>
      )}
    </div>
  );
}
