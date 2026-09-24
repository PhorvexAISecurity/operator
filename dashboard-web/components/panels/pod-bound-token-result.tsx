import type { PodBoundTokenResult } from "@/lib/api";

const sha256 = /^[a-f0-9]{64}$/;
const stageOrder = ["ADMISSION", "OWNED_FIXTURE", "CREDENTIAL_AND_ROUTE_BASELINE", "AUDIT_START", "SOLE_TYPED_SIGNAL", "BRAIN_DECISION", "NATIVE_OPERATION", "INDEPENDENT_OUTCOME", "CLEANUP"];
const stageStatuses = new Set(["CONFIRMED", "REFUSED", "UNKNOWN"]);
const known = (value: string | number | boolean | undefined | null) =>
  value === undefined || value === null || value === "" ? "UNKNOWN" : String(value);
const utcNanos = (value: string | undefined): bigint | null => {
  const match = /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z$/.exec(value || "");
  if (!match) return null;
  const millis = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(millis) || new Date(millis).toISOString().slice(0, 19) !== match[1]) return null;
  return BigInt(millis) * BigInt(1_000_000) + BigInt((match[2] || "").padEnd(9, "0"));
};
const beforeExpiry = (after: string, expiry: string) => {
  const observed = utcNanos(after);
  const expires = utcNanos(expiry);
  return observed !== null && expires !== null && observed < expires;
};

// The typed result is a causal observation, not a calibrated security score.
// Keep each receipt separate; selected rotate alone never establishes bearer invalidation.
export function PodBoundTokenResultPanel({ result, unsafeToRetry = false }: { result: PodBoundTokenResult; unsafeToRetry?: boolean }) {
  const stages = Array.isArray(result?.stages) ? result.stages : [];
  const admission = result?.admission ?? {};
  const event = result?.event ?? {};
  const decision = result?.decision ?? {};
  const operation = result?.operation ?? {};
  const replay = result?.replay ?? {};
  const cleanup = result?.cleanup ?? {};
  const brainBranch = stages.find((stage) => stage.name === "BRAIN_DECISION")?.reason;
  const nativeBranch = stages.find((stage) => stage.name === "NATIVE_OPERATION")?.reason;
  const noOpBranch = decision.selectedAction === "noop" &&
    (brainBranch === "NOOP_COST_GATE" || brainBranch === "NOOP_CAPACITY" || brainBranch === "NOOP_COST_GATE_AND_CAPACITY");
  const missingRequestRate = decision.requestRateStatus === "MISSING_REQUEST_RATE";
  const completeStages = stages.length === stageOrder.length && stages.every((stage, index) =>
    stage.name === stageOrder[index] && stage.status === "CONFIRMED" && !!stage.observedAt && sha256.test(stage.evidenceSHA256 || ""));
  const stageTimes = stages.map((stage) => utcNanos(stage.observedAt));
  const orderedTimes = stageTimes.length === stageOrder.length && stageTimes.every((time, index) =>
    time !== null && (index === 0 || (stageTimes[index - 1] !== null && time > stageTimes[index - 1]!)));
  const replayTime = utcNanos(replay.sourceAfterAt);
  const replayAfterOperation = replayTime !== null && stageTimes.length === stageOrder.length &&
    stageTimes[2] !== null && stageTimes[4] !== null && stageTimes[6] !== null && stageTimes[7] !== null &&
    replayTime > stageTimes[2]! && replayTime > stageTimes[4]! && replayTime > stageTimes[6]! &&
    replayTime <= stageTimes[7]!;
  const mechanismChain = !!(result.runID && result.nonce && admission?.available &&
    admission.clusterUID && admission.namespaceUID && admission.managerPodUID && admission.policyUID &&
    typeof admission.policyGeneration === "number" && admission.policyGeneration > 0 &&
    sha256.test(admission.policySpecSHA256 || "") && sha256.test(admission.profileSHA256 || "") &&
    admission.sourcePodUID && admission.peerPodUID && admission.sourcePodUID !== admission.peerPodUID && admission.serviceUID &&
    event?.uid && event.creator && event.trustVerified && event.sourcePodUID &&
    admission?.namespace === "voice" && admission.sourcePodUID === event.sourcePodUID &&
    event.kind === "phorvex.attack.pod-bound-api-auth" && decision?.id &&
    decision.auditCoverage === "COMPLETE" && decision.requestRateStatus === "MEASURED_FRESH" &&
    !brainBranch?.startsWith("NOOP_") && nativeBranch !== "NOT_DISPATCHED" &&
    decision.selectedAction === "rotate" && decision.dispatchOutcome === "emitted" &&
    operation?.terminationStatus === "REQUEST_CONFIRMED" && operation.originalPodAbsent && sha256.test(operation.receiptSHA256 || "") &&
    replay?.sameSourceHandle && replay?.samePeerHandle && replay.sourceBeforeHTTP === 200 &&
    replay.sourceAfterHTTP === 401 && replayAfterOperation && beforeExpiry(replay.sourceAfterAt || "", replay.sourceExpiry || "") &&
    replay.peerBeforeHTTP === 200 && replay.peerAfterHTTP === 200 &&
    replay.serviceBeforeHTTP === 200 && replay.serviceAfterHTTP === 200 &&
    cleanup?.status === "CONFIRMED_ABSENT" && cleanup.absent && sha256.test(cleanup.inventorySHA256 || "") && completeStages && orderedTimes);
  if (result?.schema !== "pod-bound-token-result-v1" || result.securityEfficacy !== "NOT_EVALUATED" ||
      result.signalMode !== "explicit-injected-typed-event" || typeof result.mechanismObserved !== "boolean" ||
      !["COMPLETE", "INCOMPLETE", "UNSAFE"].includes(result.terminalStatus) || stages.length > stageOrder.length ||
      stages.some((stage, index) => !stage || stage.name !== stageOrder[index] || !stageStatuses.has(stage.status) ||
        (stage.evidenceSHA256 && !sha256.test(stage.evidenceSHA256))) ||
      (result.mechanismObserved && (result.terminalStatus !== "COMPLETE" || unsafeToRetry || !mechanismChain))) {
    return <div className="text-warning">Pod-bound bearer evidence has an incompatible claim contract; no mechanism result is accepted.</div>;
  }

  const stageRows = stages.map((stage, index) => <div key={`${index}-${stage.name}`} className="rounded border border-border/70 p-2">
    <div className="flex flex-wrap gap-x-2"><span className="font-medium text-foreground">{index + 1}. {stage.name}</span><span className="font-mono">{stage.status}</span><span>{known(stage.observedAt)}</span></div>
    <div className="break-all text-[11px]">evidence SHA-256 {known(stage.evidenceSHA256)}{stage.reason ? ` · ${stage.reason}` : ""}</div>
  </div>);
  const observationRows: [string, string | number | boolean | undefined | null][] = [
    ["Admission", admission.available ? "READY" : known(admission.unavailableReason)],
    ["Injected event", event.trustVerified ? `trusted UID ${known(event.uid)}` : "UNKNOWN / untrusted"],
    ["Decision", decision.id], ["Selected action", decision.selectedAction],
    ["Emitted request", decision.dispatchOutcome], ["Exact termination receipt", operation.terminationStatus],
    ["Original Pod absent", operation.originalPodAbsent ? "yes" : "UNKNOWN"],
    ["Source bearer before", replay.sourceBeforeHTTP], ["Source bearer after", replay.sourceAfterHTTP],
    ["Peer bearer before", replay.peerBeforeHTTP], ["Peer bearer after", replay.peerAfterHTTP],
    ["Service before", replay.serviceBeforeHTTP], ["Service after", replay.serviceAfterHTTP],
    ["Cleanup", cleanup.status],
  ];
  return <div data-pod-bound-token-result={result.mechanismObserved ? "mechanism-observed" : "observation-only"} className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
    <div className="font-medium text-foreground">Injected Pod-bound API bearer response · {known(result.terminalStatus)}</div>
    <div className="mt-1 text-muted-foreground">The SecurityEvent is explicitly injected. Selection, request emission, exact Pod retirement, source-bearer replay, peer access, Service routing and cleanup are separate observations. Natural detection and calibrated defense efficacy are NOT EVALUATED.</div>
    {result.mechanismObserved ? <div className="mt-2 text-foreground">ROTATE_CREDENTIAL_MECHANISM_OBSERVED: the same captured source bearer changed from API 200 to 401 before expiry while the captured peer bearer and owned Service still returned 200, with exact retirement and cleanup receipts.</div>
      : <div className="mt-2 text-warning">No credential-rotation mechanism is established by this observation. A complete no-op is a valid negative case result, not a defense success.</div>}
    <dl className="mt-2 grid gap-x-4 gap-y-1 md:grid-cols-2">{observationRows.map(([label, value]) => <div key={label} className="flex min-w-0 gap-2"><dt className="shrink-0 text-muted-foreground">{label}:</dt><dd className="break-all font-mono text-foreground">{known(value)}</dd></div>)}</dl>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Ordered stage ledger ({stages.length})</div>
      <div className="mt-1 space-y-1 text-muted-foreground">{stageRows.length ? stageRows : <div>UNKNOWN: no stage receipts projected.</div>}</div>
    </div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Exact identities and authority</div>
      <div className="mt-1 break-all text-muted-foreground">run {known(result.runID)} · cluster {known(admission.clusterUID)} · namespace {known(admission.namespace)} / UID {known(admission.namespaceUID)} · manager Pod UID {known(admission.managerPodUID)} · policy UID {known(admission.policyUID)} / generation {known(admission.policyGeneration)} · policy spec SHA-256 {known(admission.policySpecSHA256)} · profile SHA-256 {known(admission.profileSHA256)}</div>
      <div className="mt-1 break-all text-muted-foreground">source Pod UID {known(admission.sourcePodUID)} · peer Pod UID {known(admission.peerPodUID)} · Service UID {known(admission.serviceUID)} · event UID {known(event.uid)} · kind {known(event.kind)} · stamped creator {known(event.creator)} · event source Pod UID {known(event.sourcePodUID)} · decision {known(decision.id)}</div>
    </div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Brain candidates and measured gates</div>
      <div className="mt-1 text-muted-foreground">Rotate: {known(decision.rotateStatus)} · expected cost {known(decision.rotateExpectedCost)} · high cost {known(decision.rotateHighCost)} · ceiling {known(decision.costCeiling)} · {known(decision.rotateReason)}</div>
      <div className="mt-1 text-muted-foreground">Request rate: {known(decision.requestRateStatus)} · flow regime: {known(decision.flowRegime)} · audit coverage: {known(decision.auditCoverage)}</div>
      <div className="mt-1 text-muted-foreground">Quarantine: {known(decision.quarantineStatus)} · capacity {known(decision.quarantineUsed)}/{known(decision.quarantineLimit)} · {known(decision.quarantineReason)}</div>
      {(noOpBranch || missingRequestRate) && <div className="mt-1 text-warning">Recorded gate evidence: {[noOpBranch && brainBranch, missingRequestRate && "MISSING_REQUEST_RATE"].filter(Boolean).join(" · ")}. These codes come from the typed decision/stage receipts; no action was forced and no mechanism credit follows.</div>}
    </div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Same-handle API and Service controls</div>
      <div className="mt-1 text-muted-foreground">Source captured handle reused: {replay.sameSourceHandle ? "yes" : "unverified"} · peer captured handle reused: {replay.samePeerHandle ? "yes" : "unverified"} · source replay {known(replay.sourceAfterAt)} · source expiry {known(replay.sourceExpiry)} · replay before expiry: {beforeExpiry(replay.sourceAfterAt || "", replay.sourceExpiry || "") ? "yes" : "unverified"}</div>
      <div className="mt-1 break-all text-muted-foreground">Exact operation receipt SHA-256 {known(operation.receiptSHA256)} · cleanup inventory SHA-256 {known(cleanup.inventorySHA256)} · all owned resources absent: {cleanup.absent ? "yes" : "unverified"}</div>
    </div>
    {(unsafeToRetry || result.terminalStatus === "UNSAFE" || !cleanup.absent) && <div className="mt-2 text-warning">Cleanup or protected capacity may remain unresolved. Do not retry this run until exact reconciliation confirms safety.</div>}
  </div>;
}
