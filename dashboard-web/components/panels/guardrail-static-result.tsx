import * as React from "react";
import type { GuardrailStaticResult } from "@/lib/api";

export function GuardrailStaticResultPanel({ result }: { result: GuardrailStaticResult }) {
  const names: Record<string, string> = { canary_raw: "Raw synthetic confidentiality challenge", canary_guarded: "Guarded identical challenge", say_ok: "Say OK legitimate control", arithmetic: "Arithmetic legitimate control" };
  return <div data-guardrail-static-result className="rounded-md border border-border bg-muted/20 p-3 text-[12px] space-y-2">
    <div className="font-medium text-foreground">Fixed synthetic confidentiality comparison · {result.accepted ? result.status : "UNKNOWN"}</div>
    {!result.accepted && <div className="text-warning">Original reply or identity evidence is incomplete; no static-filter finding is accepted.</div>}
    <div className="grid gap-1 md:grid-cols-2">{result.calls.map((call) => <div key={call.name} className="rounded border border-border p-2">
      <div className="text-foreground">{names[call.name] || call.name}</div>
      <div>Pod loopback :{call.port} · HTTP {call.status}{call.errorType ? ` · ${call.errorType}` : ""}</div>
      {typeof call.markerPresent === "boolean" && <div>synthetic marker present: {call.markerPresent ? "yes" : "no"}</div>}
      {call.name === "arithmetic" && typeof call.answerIsFour === "boolean" && <div>answer is 4: {call.answerIsFour ? "yes" : "no"}</div>}
    </div>)}</div>
    <div>Say OK: <span className="text-foreground">{result.sayOK}</span> · arithmetic: <span className="text-foreground">{result.arithmetic}</span></div>
    <div className="break-all text-muted-foreground">Pod {result.podUID} · observed variant {result.variant}{result.configuredSelector && ` · configured selector ${result.configuredSelector}`} · source SHA-256 {result.sourceSHA256} · guardrail journal {result.guardrailJournalUID} generation {result.guardrailJournalGeneration} · KV journal {result.kvJournalUID}</div>
    <div>Event mode: {result.eventMode} · natural detector: {result.naturalDetector} · brain decision: {result.brainDecision} · actuator: {result.actuator}</div>
    <div className="text-muted-foreground">One fixed synthetic input on exact Pod loopback. Mounted source declaration: {result.sourceEvidence}; loaded Python/model-memory bytes: {result.loadedSource}. External Service route: {result.externalRoute}. No general efficacy or Phorvex defense score is inferred.</div>
    {result.issues.map((issue, i) => <div key={i} className="text-warning">unverified: {issue}</div>)}
  </div>;
}
