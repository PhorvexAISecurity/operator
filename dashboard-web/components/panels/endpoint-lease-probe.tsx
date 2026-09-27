import type { EndpointLeaseProbeResult } from "@/lib/api";

export function EndpointLeaseProbe({ result }: { result: EndpointLeaseProbeResult }) {
  const valid = result.schema === "vllm-endpoint-lease-live-v1" && result.scenarioId === "ai2-endpoint-security";
  const defended = valid && result.status === "DEFENDED" && result.firstAccepted &&
    result.initialAStatus === 200 && result.initialBStatus === 200 &&
    result.signalMode === "TEST_INJECTED_AFTER_A_AND_B_200" && !!result.eventUID &&
    result.selectedAction === "endpoint-lease-revoke" && !!result.selectedDecisionId && !!result.selectedTickId &&
    result.protectedJournalTerminal && result.everyServingPodEffective &&
    result.postAStatus === 401 && result.postAExactDenial &&
    result.postBStatus === 200 && result.postBValidCompletion &&
    (result.issues || []).length === 0;
  if (!valid || (result.status === "DEFENDED" && !defended)) {
    return <div data-endpoint-lease="incomplete" className="text-warning">Exact endpoint lease evidence is incomplete; no defended outcome is accepted.</div>;
  }
  return <div data-endpoint-lease={defended ? "defended" : "observed"} className="space-y-2 rounded-md border border-border bg-muted/20 p-3 text-[12px]">
    <div className="font-medium text-foreground">Owned vLLM caller credential reuse · {result.status}</div>
    <div>{defended
      ? "The first request with owned credential A reached the real model. After an explicitly injected signal and normal selected decision, the protected revocation is effective: a fresh A request is denied while legitimate B still receives a real completion. The first accepted request remains a loss."
      : result.firstAccepted
        ? "Owned credential A reached the real model. A confirmed prospective revocation with B continuity has not been established."
        : "No new accepted A request was proven. Existing denial or missing baseline earns no new response credit."}</div>
    <div>Public Service: A {result.initialAStatus ?? "unverified"} and B {result.initialBStatus ?? "unverified"} before; A {result.postAStatus ?? "unverified"} and B {result.postBStatus ?? "unverified"} after.</div>
    <div>Event {result.eventUID || "none"} · decision {result.selectedDecisionId || "none"} · tick {result.selectedTickId || "none"} · selected action {result.selectedAction || "none"}</div>
    {result.terminalAfterDispatchError && <div>Original dispatch was not credited; the exact protected operation was confirmed later.</div>}
    {result.noopReason && <div>Brain NOOP: {result.noopReason}{result.actionExclusion ? ` · ${result.actionExclusion}` : ""}</div>}
    <div className="text-muted-foreground">Scope: {result.defenseScope} The test signal does not establish natural detection, SSRF prevention, extraction prevention or protection of other credentials.</div>
    {(result.issues || []).map((issue, index) => <div key={`${index}-${issue}`} className="text-warning">unverified: {issue}</div>)}
  </div>;
}
