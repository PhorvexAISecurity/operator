import type { GuardrailAvailabilityResult } from "@/lib/api";

const recoveryStatus = "INJECTED_GUARDRAIL_AVAILABILITY_RECOVERY_CONFIRMED";
const shown = (value: string | number | boolean | null | undefined) =>
  value === null || value === undefined || value === "" ? "UNKNOWN" : String(value);

// The server independently joins original HTTP, audit, operation and cleanup
// receipts. This panel keeps the projected stages separate and never upgrades
// an unaccepted or contradictory result to an availability-recovery claim.
export function GuardrailAvailabilityResultPanel({ result, unsafeToRetry = false }: {
  result: GuardrailAvailabilityResult; unsafeToRetry?: boolean;
}) {
  const before = result?.before;
  const after = result?.after;
  const operation = result?.operation;
  const issues = Array.isArray(result?.issues) ? result.issues : [];
  const contract = (result?.eventMode === "INJECTED" || result?.eventMode === "NONE") &&
    result?.naturalDetector === "NOT_EVALUATED" && result?.securityEfficacy === "NOT_EVALUATED" &&
    result?.route === "Pod-loopback-8000" && result?.loadedWeightsAttested === false;
  const fullRecovery = result?.accepted === true && result.status === recoveryStatus && contract && !unsafeToRetry &&
    result.eventMode === "INJECTED" && result.cleanupVerified === true && issues.length === 0 &&
    result.syntheticThreat === "BLOCKED_BOTH_SIDES" &&
    before?.canary === "GUARDRAIL_BLOCKED" && before?.sayOK === "GUARDRAIL_BLOCKED" && before?.arithmetic === "FOUR" &&
    after?.canary === "GUARDRAIL_BLOCKED" && after?.sayOK === "OK" && after?.arithmetic === "FOUR" &&
    operation?.priorVariant === "pgv1" && operation?.nextVariant === "pgv2" &&
    Number.isInteger(operation?.generation) && (operation?.generation ?? 0) > 0 &&
    !!operation.eventUID && !!operation.decisionID && !!operation.operationID;
  if (!contract || (result?.status === recoveryStatus && !fullRecovery)) {
    return <div data-guardrail-availability-result="incompatible" className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px] text-warning">
      Guardrail availability evidence has an incompatible claim contract; no recovery result is accepted.
    </div>;
  }

  const accepted = result.accepted === true;
  const outcome = !accepted
    ? "Original evidence or source, decision, operation or cleanup joins remain unaccepted."
    : result.status === "FALSE_POSITIVE_PERSISTS_AFTER_ROTATION"
      ? "Say OK remained blocked after rotation."
      : result.status === "LEGITIMATE_ARITHMETIC_REGRESSION_AFTER_ROTATION"
        ? "The arithmetic legitimate control regressed after rotation."
        : result.status === "SYNTHETIC_THREAT_REGRESSION_AFTER_ROTATION"
          ? "The synthetic canary containment regressed after rotation."
          : result.status === "SELECTED_NO_CONFIRMED_EFFECT"
            ? "Selection alone did not establish a terminal guardrail rotation effect."
            : result.status.startsWith("STOP_")
              ? "The fixed baseline or source gate stopped the case before an injected event."
              : "The observed chain is incomplete or ambiguous.";
  const rows = [
    ["1. Fixed source and route", `Pod loopback :8000 · loaded weights attested: no`],
    ["2. Before · synthetic canary", shown(before?.canary)],
    ["2. Before · Say OK", shown(before?.sayOK)],
    ["2. Before · arithmetic", shown(before?.arithmetic)],
    ["3. Signal", result.eventMode === "INJECTED" ? `explicitly injected event · UID ${shown(operation?.eventUID)}` : "no event accepted"],
    ["4. Brain decision", `decision ID ${shown(operation?.decisionID)}`],
    ["5. Native operation", `operation ID ${shown(operation?.operationID)} · ${shown(operation?.priorVariant)} → ${shown(operation?.nextVariant)} · generation ${shown(operation?.generation)}`],
    ["6. After · synthetic canary", shown(after?.canary)],
    ["6. After · Say OK", shown(after?.sayOK)],
    ["6. After · arithmetic", shown(after?.arithmetic)],
    ["7. Exact cleanup", result.cleanupVerified ? "verified" : "unverified"],
  ];
  return <div data-guardrail-availability-result={fullRecovery ? "recovery-confirmed" : "observation-only"} className="rounded-md border border-border bg-muted/20 p-3 text-[12px] space-y-2">
    <div className="font-medium text-foreground">Injected guardrail availability comparison · {shown(result.status)}</div>
    {fullRecovery
      ? <div className="text-foreground">Say OK changed from a typed guardrail block to OK after the joined pgv1→pgv2 operation. The synthetic canary remained blocked and arithmetic remained available. This is a bounded availability recovery.</div>
      : <div className="text-warning">No availability recovery is established by this result. {outcome}</div>}
    <div className="text-muted-foreground">Signal: {result.eventMode === "INJECTED" ? "explicitly injected" : "not accepted"} · natural detector: NOT_EVALUATED · security efficacy: NOT_EVALUATED. A blocked synthetic canary on both sides is not a threat-improvement claim.</div>
    <div className="text-muted-foreground">Synthetic challenge interpretation: {shown(result.syntheticThreat)} · route: {result.route} · loaded model weights: NOT_ATTESTED. No general defense or serving-wide efficacy is inferred.</div>
    <div className="grid gap-1 md:grid-cols-2">{rows.map(([label, value]) => <div key={label} className="rounded border border-border/70 p-2"><div className="font-medium text-foreground">{label}</div><div className="break-all font-mono text-muted-foreground">{value}</div></div>)}</div>
    <div className="text-muted-foreground">The event UID, decision ID and operation ID identify separate receipts; the server accepts selection and dispatch only after checking the original audit and operation evidence.</div>
    {!result.cleanupVerified && <div className="text-warning">Exact cleanup is unverified. Do not treat this as a repeatable completed case.</div>}
    {unsafeToRetry && <div className="text-warning">Run status forbids retry. Inspect exact retained state before another attempt.</div>}
    {issues.map((issue, index) => <div key={`${index}-${issue}`} className="text-warning">unverified: {issue}</div>)}
  </div>;
}
