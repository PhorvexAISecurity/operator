import type { VoiceAgencyProbeResult } from "@/lib/api";

export function VoiceAgencyProbe({ result }: { result: VoiceAgencyProbeResult }) {
  return <div className="rounded-md border border-border bg-muted/20 p-3 text-[11px] space-y-1">
    <div className="font-medium">Voice refund response · {result.status}</div>
    <div>First run-owned other-order refund: model callback {result.firstModelCallback ? "observed" : "unverified"}; CRM write {result.firstCRMRefund ? "observed" : "unverified"}. Historical first loss {result.firstLanded ? "landed" : "not established"}.</div>
    <div>Signal: {result.eventUID ? "test-injected after the measured first loss" : "not created"}. Natural detection was not evaluated.</div>
    <div>Brain choice: {result.selectedAction || "unverified"}{result.selectedDecisionId ? ` · decision ${result.selectedDecisionId.slice(0, 12)}…` : ""}.</div>
    <div>Protected response: journal {result.protectedJournalTerminal ? "terminal" : "unverified"}; all serving Pods {result.everyServingPodEffective ? "effective" : "unverified"}{result.recoveredAfterPending ? " · recovered after pending" : ""}.</div>
    <div>Same-pair replay: callback {result.repeatCallbackDenied ? "exact policy denial observed" : "not proven denied"}; CRM write {result.repeatCRMRefundAbsent ? "absent" : "not proven absent"}.</div>
    <div>Legitimate controls: own-order refund {result.ownOrderControlMaintained ? "maintained" : "unverified"}; status lookup {result.benignStatusMaintained ? "maintained" : "unverified"}.</div>
    <div>Run-owned CRM/transcript cleanup: {result.cleanup}.</div>
    {(result.issues || []).map((issue, i) => <div className="text-warning" key={i}>Limit: {issue}</div>)}
    <div className="text-muted-foreground">The first refund remains a loss. A DEFENDED result applies only to the exact asserted caller and other owned order pair on a fresh repeat. The caller assertion is not authentication; other pairs and general Voice safety were not measured.</div>
  </div>;
}
