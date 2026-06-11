"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { PageHead } from "./effectiveness";
import { useApplyFixIdentity, IdentityBar } from "@/components/apply-fix/identity";
import { SubmitFlow } from "@/components/apply-fix/submit-flow";
import { ApproveQueue } from "@/components/apply-fix/approve-queue";
import { AuditTrail } from "@/components/apply-fix/audit-trail";

// ApplyFixPanel composes the safe write-path flows (P-VCLUSTER Pass 2) wired to the proven backend:
// identity → submit (gate-checked) → two-key approve → audit. Demo-trust identity for local click-
// through; OIDC supersedes in production.
export function ApplyFixPanel({ lens }: { lens: Lens }) {
  const { id, update } = useApplyFixIdentity();
  const [refresh, setRefresh] = React.useState(0);
  const bump = () => setRefresh((n) => n + 1);
  return (
    <div className="animate-fade-up space-y-6">
      <PageHead
        title="Apply-Fix · safe policy write-path"
        sub="Propose a tenant policy change from an RL finding, gate-checked server-side (1.62× · P3 · no-harm) BEFORE any cluster write, applied only with a DISTINCT two-key approver, via the per-namespace ServiceAccount, fully audited. Allowlisted parameters only — no free-form YAML, no RCE actions."
      />
      <IdentityBar id={id} update={update} />
      <SubmitFlow id={id} lens={lens} onSubmitted={bump} />
      <ApproveQueue id={id} lens={lens} refreshKey={refresh} onApproved={bump} />
      <AuditTrail id={id} lens={lens} refreshKey={refresh} />
    </div>
  );
}
