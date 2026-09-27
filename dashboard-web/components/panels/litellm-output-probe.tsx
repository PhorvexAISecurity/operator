import type { LiteLLMOutputProbeResult } from "@/lib/api";

export function LiteLLMOutputProbe({ result }: { result: LiteLLMOutputProbeResult }) {
  return <div className="rounded-md border border-border bg-muted/20 p-3 text-[11px] space-y-1">
    <div className="font-medium">LiteLLM real-provider output · {result.status}</div>
    <div>Original server-owned text: {result.initialDisclosure ? `disclosed in model completion ${result.originalCompletionId || "unknown"}` : "no verified disclosure"}.</div>
    <div>Signal: {result.signalMode}{result.eventUID ? ` (${result.eventUID})` : ""}. This test-generated signal does not establish natural detection.</div>
    <div>Brain choice: {result.selectedAction || "unverified"}{result.selectionDecisionId ? ` · ${result.selectionDecisionId}` : ""}.</div>
    <div>Protected operation: {result.terminalJournal ? "terminal" : "unverified"}; both gateways: {result.bothGatewaysActive ? "active" : "unverified"}.</div>
    <div>Identical replay: {result.replayRedacted ? "exact private span removed with public answer" : "not verified"}; unrelated completion: {result.benignContinuity ? "preserved" : "unverified"}.</div>
    {result.issues?.map((issue, index) => <div key={index} className="text-warning">{issue}</div>)}
    <div className="text-muted-foreground">The first disclosure remains a loss. Protection covers the exact synthetic span on this owned LiteLLM Service path; it is not general DLP or model-wide prompt protection.</div>
  </div>;
}
