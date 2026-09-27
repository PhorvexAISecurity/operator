import type { VoiceOutputProbeResult } from "@/lib/api";

export function VoiceOutputProbe({ result }: { result: VoiceOutputProbeResult }) {
  return <div className="rounded-md border border-border bg-muted/20 p-3 text-[11px] space-y-1">
    <div className="font-medium">Voice output response · {result.status}</div>
    <div>First real Voice session: raw model marker {result.firstRawModelMarker ? "observed" : "unverified"}; persisted assistant transcript {result.firstAssistantDisclosure ? "disclosed" : "unverified"}; audio frames {result.firstAudioEmitted ? "emitted" : "unverified"}. Historical first loss {result.firstLanded ? "landed" : "not established"}.</div>
    <div>Signal: {result.eventUID ? "test-injected after the measured first loss" : "not created"}. Natural detection was not evaluated.</div>
    <div>Brain choice: {result.selectedAction || "unverified"}{result.selectedDecisionId ? ` · decision ${result.selectedDecisionId.slice(0, 12)}…` : ""}.</div>
    <div>Protected response: journal {result.protectedJournalTerminal ? "terminal" : "unverified"}; all serving Pods {result.everyServingPodEffective ? "effective" : "unverified"}{result.recoveredAfterPending ? " · recovered after pending" : ""}.</div>
    <div>Identical replay: raw model marker {result.repeatRawModelMarker ? "observed again" : "unverified"}; complete-response output guard {result.repeatOutputBlocked ? "blocked before TTS and assistant transcript" : "not proven to block"}.</div>
    <div>Legitimate public speech and persisted transcript: {result.benignSpeechMaintained ? "maintained" : "unverified"}.</div>
    <div>Run-derived transcript cleanup: {result.cleanup}.</div>
    {(result.issues || []).map((issue, i) => <div className="text-warning" key={i}>Limit: {issue}</div>)}
    <div className="text-muted-foreground">The first disclosure remains a loss. DEFENDED covers only this synthetic noncredential marker after an exact selected policy append. Audio emission was observed; marker phonemes were not decoded from audio. Other private instructions and natural detection were not measured.</div>
  </div>;
}
