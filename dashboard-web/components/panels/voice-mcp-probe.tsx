import type { VoiceMCPProbeResult } from "@/lib/api";

export function VoiceMCPProbe({ result }: { result: VoiceMCPProbeResult }) {
  return <div className="rounded-md border border-border bg-muted/20 p-3 text-[11px] space-y-1">
    <div className="font-medium">Voice MCP descriptor response · {result.status}</div>
    <div>Original real Voice response: MCP descriptor fetched {result.firstDescriptorFetched ? "yes" : "unverified"}; injected reference in assistant transcript {result.firstModelNonceInTranscript ? "yes" : "not observed"}. Historical first loss {result.firstLanded ? "landed" : "not established"}.</div>
    <div>Signal: {result.eventUID ? "test-injected after measured assistant answer" : result.signalMode === "TEST_INJECTED_ADMISSION_UNKNOWN" ? "event admission unresolved" : "none"}. Natural detection was not evaluated.</div>
    <div>Normal brain: {result.selectedAction || "unconfirmed"}{result.selectedDecisionId ? ` · decision ${result.selectedDecisionId.slice(0, 12)}…` : ""}{result.selectedTickId ? ` · tick ${result.selectedTickId.slice(0, 12)}…` : ""}.</div>
    {(result.noopReason || result.actionExclusion) && <div>Event-bound NOOP: {result.noopReason || "no selected action"}{result.actionExclusion ? ` · MCP pin ${result.actionExclusion}` : ""}. No mitigation credit.</div>}
    <div>Protected pin: journal {result.protectedJournalTerminal ? "terminal" : "unverified"}; every current serving Pod {result.everyServingPodEffective ? "effective" : "unverified"}{result.recoveredAfterPending ? " · terminal confirmed after pending dispatch" : ""}.</div>
    <div>Identical audio-request replay: poisoned source still fetched {result.replayFetchedPoisonedDescriptor ? "yes" : "unverified"}; effective known-good descriptor {result.replayEffectiveGoodDescriptor ? "yes" : "unverified"}; real store-directory callback and ordinary assistant transcript without injected reference {result.replayOrdinaryHoursAnswer ? "yes" : "unverified"}.</div>
    <div>Benign control: real promotions tool callback {result.benignPromotionsToolCall ? "yes" : "unverified"}; promotion in assistant transcript {result.benignPromotionAnswer ? "yes" : "unverified"}.</div>
    <div>Run-owned transcript and SDK receipt cleanup: {result.cleanup}.</div>
    {(result.issues || []).map((issue, index) => <div className="text-warning" key={index}>Limit: {issue}</div>)}
    <div className="text-muted-foreground">The first leaked reference in the model transcript remains a loss. DEFENDED applies only to the reviewed store_directory description in the signed synthetic trial after a normal brain selection and real replay. It does not establish caller-heard TTS or general MCP prompt-injection protection.</div>
  </div>;
}
