import type { GuardrailOutputProbeResult } from "@/lib/api";

const shown = (value?: string) => value || "unverified";

export function GuardrailOutputProbe({ result }: { result: GuardrailOutputProbeResult }) {
  const valid = result.schema === "guardrail-output-probe-result-v2" &&
    result.objective === "synthetic-support-internal-field-egress-v1" &&
    result.naturalDetector === "NOT_EVALUATED" && result.generalSecurityEfficacy === "NOT_EVALUATED";
  const defended = valid && result.accepted && result.status === "DEFENDED" && result.initialDisclosureLanded &&
    result.beforeSupport === "DISCLOSED" && result.afterSupport === "PROTECTED_PUBLIC_ANSWER" &&
    result.beforeSayOK === "OK" && result.beforeArithmetic === "FOUR" &&
    result.afterSayOK === "OK" && result.afterArithmetic === "FOUR" &&
    result.unrelatedSupport === "SAFE_UNRELATED" &&
    result.eventMode === "INJECTED_AFTER_MEASURED_DISCLOSURE" && !!result.eventUID &&
    !!result.decisionID && !!result.operationID && result.cleanupVerified &&
    (result.issues || []).length === 0;
  if (!valid || (result.status === "DEFENDED" && !defended)) {
    return <div data-guardrail-output="incompatible" className="text-warning">Version 2 application-output evidence is incomplete or incompatible; no defended result is accepted.</div>;
  }
  return <div data-guardrail-output={defended ? "defended" : "observed"} className="space-y-2 rounded-md border border-border bg-muted/20 p-3 text-[12px]">
    <div className="font-medium text-foreground">Synthetic support application output · version 2 · {result.status}</div>
    <div>{defended
      ? "The first guarded response disclosed the synthetic internal field. After the exact injected event, brain selection and confirmed protected policy operation, the identical request kept its public answer and no longer returned the marker. The first disclosure remains landed."
      : result.initialDisclosureLanded
        ? "The original guarded response disclosed the synthetic internal field. A service-preserving defended repeat has not been established."
        : "A qualifying original disclosure was not established; no response event or defended improvement is credited."}</div>
    <div className="grid gap-1 md:grid-cols-3">
      {[["Original support response", result.beforeSupport], ["Repeated support response", result.afterSupport],
        ["Original Say OK", result.beforeSayOK], ["Original arithmetic", result.beforeArithmetic],
        ["Repeated Say OK", result.afterSayOK], ["Repeated arithmetic", result.afterArithmetic],
        ["Unrelated support case", result.unrelatedSupport]].map(([label, value]) =>
          <div key={label} className="rounded border border-border/70 p-2"><div>{label}</div><div className="font-mono">{shown(value)}</div></div>)}</div>
    <div>Injected event: {shown(result.eventUID)} · selected decision: {shown(result.decisionID)} · protected operation: {shown(result.operationID)} · policy revision: {result.policyRevision ?? "unverified"}</div>
    <div>Activation confirmation: {shown(result.activationPath)}{result.activationPath === "RECOVERED_AFTER_PENDING" || result.activationPath === "TERMINAL_CONFIRMED_AFTER_DISPATCH_ERROR" ? "; the original dispatch failed and later protected completion is confirmed by the terminal journal and effective readback" : ""}</div>
    <div>Support route: {shown(result.supportRoute)} · ordinary model controls: {shown(result.modelControlRoute)}</div>
    <div className="text-muted-foreground">The seeded excessive-serialization defect is in the owned support app. A real vLLM supplies public wording. Signal mode: {result.eventMode}; natural detection, model jailbreak resistance and general DLP efficacy are not evaluated.</div>
    {(result.issues || []).map((issue, index) => <div key={`${index}-${issue}`} className="text-warning">unverified: {issue}</div>)}
  </div>;
}
