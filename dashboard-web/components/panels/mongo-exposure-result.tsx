import type { MongoExposureResult } from "@/lib/api";

const sha256 = /^[0-9a-f]{64}$/;

// One synthetic document and one uncredentialed Service-path read. This panel
// does not turn a Mongo authorization response or a manager audit row into a
// Phorvex defense verdict.
export function MongoExposureResult({ result, unsafeToRetry = false }: { result: MongoExposureResult; unsafeToRetry?: boolean }) {
  const decisions = Array.isArray(result.brainDecisions) ? result.brainDecisions : [];
  const acceptedShape = result.finding === "EXPOSED" && result.observedFinding === "EXPOSED" &&
    result.clientRead === "UNAUTHENTICATED_EXACT_READ" &&
    result.legitimateBefore === "EXACT_READ" && result.legitimateAfter === "EXACT_READ" &&
    result.cleanup === "CONFIRMED_ABSENT" && result.brainTrace === "JOINED" &&
    sha256.test(result.rawReplySHA256) && Number.isInteger(result.rawReplyBytes) &&
    result.rawReplyBytes > 0 && result.rawReplyBytes <= 4096 &&
    !!result.sourcePodUID && !!result.clientPodUID && !!result.policyUID;
  if (result.schema !== "mongo-exposure-result-v1" || result.securityOutcome !== "NOT_EVALUATED" ||
      typeof result.accepted !== "boolean" || (result.accepted ? !acceptedShape : result.finding !== "UNKNOWN") ||
      !Array.isArray(result.brainDecisions) || decisions.length > 64 ||
      decisions.some((row) => !row.decisionID || !row.policyUID || !row.targetPodUID ||
        row.policyUID !== result.policyUID || row.targetPodUID !== result.sourcePodUID ||
        !Number.isInteger(row.policyGeneration) || row.policyGeneration < 0 ||
        !sha256.test(row.reasonSHA256)) || !Array.isArray(result.issues)) {
    return <div className="text-warning">Mongo exposure evidence has an incompatible claim contract; no finding is accepted.</div>;
  }
  const reply = sha256.test(result.rawReplySHA256) && Number.isInteger(result.rawReplyBytes) && result.rawReplyBytes > 0 && result.rawReplyBytes <= 4096;
  return <div data-mongo-exposure-result={result.accepted ? "joined" : "unverified"} className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
    <div className="font-medium text-foreground">Synthetic Mongo Service exposure · {result.accepted ? "configuration exposure accepted" : "complete finding unverified"}</div>
    <div className="mt-1 text-muted-foreground">One nonce-owned document, one separate no-credential client. This trial injects no SecurityEvent; detector and response efficacy are NOT EVALUATED.</div>
    {result.accepted && <div className="mt-2 text-warning">An uncredentialed client read the exact owned document through the installed Mongo Service while legitimate exact-ID reads and cleanup remained verified.</div>}
    {!result.accepted && result.observedFinding === "EXPOSED" && <div className="mt-2 text-warning">An exact-read indication was observed, but source, audit, legitimate control, or cleanup evidence is incomplete. No configuration finding is accepted.</div>}
    {result.clientRead === "MONGO_AUTH_DENIED" && <div className="mt-2 text-muted-foreground">Mongo refused the uncredentialed read. This profile has no authorized Mongo credential to validate the owned document after an auth change, so this is not an accepted protection result.</div>}
    <dl className="mt-2 grid gap-x-4 gap-y-1 md:grid-cols-2">
      {[
        ["Accepted finding", result.finding], ["Unaccepted observation", result.observedFinding],
        ["Client read", result.clientRead], ["Legitimate before", result.legitimateBefore],
        ["Legitimate after", result.legitimateAfter], ["Manager audit coverage", result.brainTrace],
        ["Owned cleanup", result.cleanup], ["Security outcome", result.securityOutcome],
      ].map(([label, value]) => <div key={label} className="flex min-w-0 gap-2"><dt className="shrink-0 text-muted-foreground">{label}:</dt><dd className="break-all font-mono text-foreground">{value || "UNKNOWN"}</dd></div>)}
    </dl>
    {reply && <div className="mt-2 break-all text-muted-foreground">Original bounded client reply retained privately: {result.rawReplyBytes} bytes · SHA-256 <span className="font-mono text-foreground">{result.rawReplySHA256}</span>. No document or reply body is shown here.</div>}
    <div className="mt-2 break-all text-muted-foreground">Exact Pod UIDs: source <span className="font-mono text-foreground">{result.sourcePodUID || "unverified"}</span> · client <span className="font-mono text-foreground">{result.clientPodUID || "unverified"}</span> · policy <span className="font-mono text-foreground">{result.policyUID || "unverified"}</span>.</div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Same-window manager audit · {result.brainTrace}</div>
      {decisions.length ? <div className="mt-1 space-y-1">{decisions.map((row) => <div key={`${row.decisionID}-${row.targetPodUID}`} className="break-all text-muted-foreground">decision <span className="font-mono text-foreground">{row.decisionID}</span> · policy generation {row.policyGeneration} · action {row.action || "unavailable"} · status {row.actionStatus || "unavailable"} · reason SHA-256 <span className="font-mono text-foreground">{row.reasonSHA256}</span> · {row.observedAt || "time unavailable"}</div>)}</div>
        : <div className="mt-1 text-muted-foreground">No exact decision row is projected for this owned target. A complete audit window alone does not establish detection or a defense action.</div>}
      <div className="mt-1 text-muted-foreground">These rows describe the manager’s actual choices for the pinned target; they do not explain Mongo authentication or prove mitigation.</div>
    </div>
    {result.brainTrace === "GAP" && <div className="mt-2 text-warning">Audit coverage has a generation, offset, or size gap; the causal result remains unknown.</div>}
    {result.cleanup !== "CONFIRMED_ABSENT" && <div className="mt-2 text-warning">Owned document or client cleanup is unconfirmed. Do not retry this run blindly.</div>}
    {unsafeToRetry && <div className="mt-2 text-warning">This run requires exact-ID reconciliation before retry; preserve its original result and cleanup evidence.</div>}
    {result.issues.map((issue, index) => <div key={`${index}-${issue}`} className="mt-1 text-warning">unverified: {issue}</div>)}
  </div>;
}
