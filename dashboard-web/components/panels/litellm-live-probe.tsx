import type { LiteLLMLiveProbeResult } from "@/lib/api";

export function LiteLLMLiveProbe({ result }: { result: LiteLLMLiveProbeResult }) {
  return <div className="rounded-md border border-border bg-muted/20 p-3 text-[11px] space-y-1">
    <div className="font-medium">LiteLLM client containment · {result.status}</div>
    <div>Original requests: {result.initialAcceptedWork ? `accepted by the real backend (${result.initialUsageTokens} tokens)` : "not verified"}.</div>
    <div>Signal: {result.signalMode}{result.eventUID ? ` (${result.eventUID})` : ""}. Test-generated signals do not establish natural detection.</div>
    <div>Brain choice: {result.selectedAction || "not verified"}{result.selectionDecisionID ? ` · ${result.selectionDecisionID}` : ""}.</div>
    <div>Native completion: {result.terminalJournal ? "confirmed" : "unverified"}; both gateways: {result.bothGatewaysActive ? "confirmed" : "unverified"}.</div>
    <div>Same client replay: {result.replayBlockedBeforeUpstream ? "blocked before inference" : "not confirmed blocked"}; benign completion: {result.benignContinuity ? "preserved" : "unverified"}.</div>
    {result.issues?.map((issue, index) => <div key={index} className="text-warning">{issue}</div>)}
    <div className="text-muted-foreground">Measures this client's access through the installed gateway. The original accepted work is not undone; unlimited spending, model replication and protection against a stolen backend master key are not established.</div>
  </div>;
}
