import type { VoiceAdmissionProbeResult } from "@/lib/api";

export function VoiceAdmissionProbe({ result }: { result: VoiceAdmissionProbeResult }) {
  return <div className="rounded-md border border-border bg-muted/20 p-3 text-[11px] space-y-1">
    <div className="font-medium">Voice media admission response · {result.status}</div>
    <div>Historical unsigned use: {result.firstLanded ? `observed ${result.firstSTTFrames} STT frames, ${result.firstModelCompletions} model completions, ${result.firstTTSAudioBytes} TTS bytes and ${result.firstSentAudioBytes} outbound audio bytes` : "real provider use unconfirmed"}.</div>
    <div>Signal: {result.eventUID ? "test-injected after observed unsigned STT/model/TTS and outbound audio" : result.signalMode === "TEST_INJECTED_ADMISSION_UNKNOWN" ? "event admission unresolved" : "none"}. Natural detection was not evaluated.</div>
    <div>Normal brain: {result.selectedAction || "unconfirmed"}{result.selectedDecisionId ? ` · decision ${result.selectedDecisionId.slice(0, 12)}…` : ""}.</div>
    {(result.noopReason || result.actionExclusion) && <div>Event-bound NOOP: {result.noopReason || "no selected action"}{result.actionExclusion ? ` · ${result.actionExclusion}` : ""}. No defense credit.</div>}
    <div>Permanent authentication: protected journal {result.protectedJournalTerminal ? "terminal" : "unconfirmed"}; all serving Pods {result.everyServingPodSettled ? "settled" : "unconfirmed"}; pending and active unsigned sessions {result.unsignedSessionsEnded ? "ended with delegated cleanup" : "unconfirmed"}.</div>
    <div>Fresh unsigned replay: every Pod {result.everyPodReplayRejected ? "rejected" : "unconfirmed"}; Service {result.serviceReplayRejected ? "rejected" : "unconfirmed"}; malformed signature {result.malformedReplayRejected ? "rejected" : "unconfirmed"}.</div>
    <div>Useful signed audio: existing session {result.signedSurvivorAudio ? "continued through STT/model/TTS" : "unconfirmed"}; new session {result.newSignedAudio ? "completed through STT/model/TTS" : "unconfirmed"}.</div>
    <div>Run-owned cleanup: {result.cleanup}.</div>
    {(result.issues || []).map((issue, index) => <div className="text-warning" key={index}>Limit: {issue}</div>)}
    <div className="text-muted-foreground">The initial unsigned provider use remains a loss. DEFENDED covers further unsigned media setup and local session teardown after the normal brain response. Synthetic signatures use the production verifier. The telephone network, stolen-signature replay and remote inference cancellation were not tested. Authentication stays enforced; later Fire reports already protected.</div>
  </div>;
}
