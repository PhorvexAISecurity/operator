import type { VoiceMemoryProbeResult } from "@/lib/api";

export function VoiceMemoryProbe({ result }: { result: VoiceMemoryProbeResult }) {
  return <div className="rounded-md border border-border bg-muted/20 p-3 text-[11px] space-y-1">
    <div className="font-medium">Voice memory context · {result.status}</div>
    <div>First direct WebSocket session: poisoned note {result.firstContextObserved ? "entered the real system context" : "unverified"}; benign note {result.firstBenignObserved ? "entered" : "unverified"}.</div>
    <div>Signal: {result.eventUID ? `test-generated after first exposure (${result.eventName})` : "not created"}. Natural detection was not evaluated.</div>
    <div>Brain choice: {result.selectedAction || "not verified"}{result.actuated ? " · emitted" : " · effect unverified"}.</div>
    <div>Fresh session: poisoned note {result.repeatPoisonObserved ? "still entered context" : "not observed"}; benign note {result.repeatBenignObserved ? "preserved" : "unverified"}.</div>
    <div>Run-owned Mongo cleanup: {result.cleanup}.</div>
    {result.issue && <div className="text-warning">Limit: {result.issue}</div>}
    <div className="text-muted-foreground">The first contamination remains landed. This measures one exact caller and note digest in the installed Voice memory path; it does not establish model obedience, refund effects, caller authentication, or general injection protection.</div>
  </div>;
}
