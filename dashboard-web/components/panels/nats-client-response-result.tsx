import type { NATSResponseResult } from "@/lib/api";

// This is a typed observation ledger, not a security score. In particular an
// object effect and a missing M1 receipt do not prove packet isolation.
export function NATSClientResponseResult({ result, unsafeToRetry = false }: { result: NATSResponseResult; unsafeToRetry?: boolean }) {
  const measured = (value?: { present: boolean; value: number | boolean }) => value?.present ? String(value.value) : "unavailable";
  const negativeOutcome = result.securityEfficacy === "CONTAINMENT_NOT_ACHIEVED";
  const trace = result.decisionTrace;
  if ((result.securityEfficacy !== "NOT_EVALUATED" && !negativeOutcome) || typeof result.accepted !== "boolean" ||
      (negativeOutcome && (!result.accepted || result.m1Status !== "CONTINUING_EXPOSURE")) ||
      (result.accepted && (!trace || !result.cleanupVerified || result.cleanupStatus !== "CONFIRMED_ABSENT")) ||
      (trace && (trace.schema !== "nats-client-response-decision-evidence-v1" ||
        trace.selectedAction !== result.selectedAction || trace.dispatchOutcome !== result.dispatchOutcome))) {
    return <div className="text-warning">NATS response evidence has an incompatible claim contract; no outcome is accepted.</div>;
  }
  const rows = [
    ["Initial client M0", result.m0Status],
    ["Injected signal", result.signalStatus],
    ["Exact manager decision", result.decisionStatus],
    ["Selected action", result.selectedAction],
    ["Dispatch", result.dispatchOutcome],
    ["Observed object effect", result.effectStatus],
    ["Same-connection M1", result.m1Status],
    ["Legitimate peer", result.peerStatus],
    ["Owned cleanup", `${result.cleanupStatus || "UNKNOWN"}${result.cleanupVerified ? " · verified" : " · unverified"}`],
  ];
  return <div data-nats-response-result={result.accepted ? "joined" : "unverified"} className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
    <div className="font-medium text-foreground">Synthetic NATS client response · {result.accepted ? "exact-run evidence joined" : "evidence incomplete"}</div>
    <div className="mt-1 text-muted-foreground">The signal is an injected SecurityEvent, not natural detector coverage. Object changes and NATS packet delivery are separate observations. Security outcome: {negativeOutcome ? "CONTAINMENT NOT ACHIEVED in this owned trial" : "NOT EVALUATED"}.</div>
    {result.m0Status === "EXPOSED" && <div className="mt-1 text-warning">Initial owned synthetic payload exposure observed.</div>}
    {result.m1Status === "CONTINUING_EXPOSURE" && <div className="mt-1 text-warning">Continuing access observed on the same established NATS connection after the recorded response.</div>}
    <dl className="mt-2 grid gap-x-4 gap-y-1 md:grid-cols-2">{rows.map(([label, value]) => <div key={label} className="flex min-w-0 gap-2"><dt className="shrink-0 text-muted-foreground">{label}:</dt><dd className="break-all font-mono text-foreground">{value || "UNKNOWN"}</dd></div>)}</dl>
    {trace && <div className="mt-3 space-y-1 border-t border-border pt-2">
      <div className="font-medium text-foreground">Exact event-bound brain trace</div>
      <div className="text-muted-foreground">decision <span className="font-mono text-foreground">{trace.decisionId}</span> · input {trace.inputPhase || "unknown"}/{trace.inputStage || "unknown"} · source {trace.gitSHA || "unavailable"} · image SHA-256 {trace.brainImageSHA256 || "unavailable"}</div>
      <div className="text-muted-foreground">pHold {measured(trace.pHold)} · threat {measured(trace.threatPosture)} · SLO headroom {measured(trace.sloHeadroom)}</div>
      <div className="text-muted-foreground">NOOP reason: {trace.noopReason || "none recorded"} · dispatch reason: {trace.dispatchReason || "none recorded"}</div>
      {Array.isArray(trace.facts) && trace.facts.length > 0 && <div>Inputs: {trace.facts.slice(0, 16).map((fact) => `${fact.type} (${fact.source}, weight ${fact.weight})`).join(" · ")}</div>}
      {Array.isArray(trace.candidates) && trace.candidates.length > 0 && <div>Brain candidates: {trace.candidates.slice(0, 12).map((candidate) => `${candidate.action}: ${candidate.selected ? "selected" : candidate.exclusion || "not selected"}; feasible ${measured(candidate.feasible)}, marginal ${measured(candidate.marginalCoverage)}, cost ${measured(candidate.expectedCost)}, net gain ${measured(candidate.netGain)}`).join(" · ")}</div>}
      {Array.isArray(trace.actionStatus) && trace.actionStatus.length > 0 && <div>Action gates: {trace.actionStatus.slice(0, 12).map((action) => `${action.action}: ${action.status}${action.exclusionKind ? ` (${action.exclusionKind})` : ""}${action.reason ? ` — ${action.reason}` : ""}`).join(" · ")}</div>}
      <div className="text-muted-foreground">These are manager inputs and candidate reasons for this exact event, not an independent packet-path oracle.</div>
    </div>}
    <div className="mt-2 text-muted-foreground">M1 measures the same established client connection after the observed policy response. A missing M1 receipt alone does not prove isolation or fresh-connection denial; effects on existing connections depend on the network implementation.</div>
    {unsafeToRetry && <div className="mt-2 text-warning">This run requires reconciliation before retry; review the recorded effect and cleanup evidence.</div>}
    {(Array.isArray(result.issues) ? result.issues : []).map((issue, index) => <div key={`${index}-${issue}`} className="mt-1 text-warning">unverified: {issue}</div>)}
  </div>;
}
