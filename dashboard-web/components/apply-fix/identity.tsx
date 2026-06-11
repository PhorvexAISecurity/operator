"use client";
import * as React from "react";
import { AFIdentity } from "@/lib/api";
import { Badge } from "@/components/ui/primitives";
import { ShieldCheck, UserCog } from "lucide-react";

const KEY = "phorvex-af-identity";

// useApplyFixIdentity resolves the acting principal for the apply-fix flows. With OIDC configured the
// token is authoritative (tenant/subject from verified claims); without it, the demo-trust user/tenant
// inputs drive a local click-through of the two-key flow. Persisted so submit + approve share it.
export function useApplyFixIdentity() {
  const [id, setId] = React.useState<AFIdentity>({ user: "", tenant: "" });
  React.useEffect(() => {
    try {
      const s = localStorage.getItem(KEY);
      if (s) setId(JSON.parse(s));
    } catch {}
  }, []);
  const update = (next: Partial<AFIdentity>) =>
    setId((p) => {
      const v = { ...p, ...next };
      try {
        localStorage.setItem(KEY, JSON.stringify(v));
      } catch {}
      return v;
    });
  return { id, update };
}

const field =
  "w-40 rounded-md border border-border bg-background/60 px-2.5 py-1.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none";

// IdentityBar — the verified-identity panel. OIDC mode (a token present) is shown read-only; demo-trust
// mode exposes editable user/tenant so an operator can switch principals to exercise the two-key flow.
export function IdentityBar({ id, update }: { id: AFIdentity; update: (n: Partial<AFIdentity>) => void }) {
  const oidc = !!id.token;
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-panel/50 px-4 py-3">
      {oidc ? (
        <span className="flex items-center gap-2 text-sm">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          <span className="text-muted-foreground">Verified identity (OIDC):</span>
          <span className="font-medium text-foreground">{id.user || "subject"}</span>
          <Badge variant="neutral">tenant {id.tenant || "?"}</Badge>
        </span>
      ) : (
        <>
          <span className="flex items-center gap-2 text-sm text-muted-foreground">
            <UserCog className="h-4 w-4 text-amber-400" />
            Acting as (demo-trust)
          </span>
          <input
            className={field}
            placeholder="user (e.g. alice)"
            value={id.user}
            onChange={(e) => update({ user: e.target.value.trim() })}
          />
          <input
            className={field}
            placeholder="tenant (e.g. acme)"
            value={id.tenant}
            onChange={(e) => update({ tenant: e.target.value.trim() })}
          />
          <Badge variant="pending">
            demo-trust · OIDC supersedes in prod
          </Badge>
        </>
      )}
    </div>
  );
}
