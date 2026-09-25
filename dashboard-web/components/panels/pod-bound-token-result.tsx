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
const beforeExpiryMargin = (started: string | undefined, ended: string | undefined, expiry: string | undefined) => {
  const start = utcNanos(started);
  const end = utcNanos(ended);
  const expires = utcNanos(expiry);
  return start !== null && end !== null && expires !== null && start < end && end + BigInt(30_000_000_000) < expires;
};

// The typed result is a causal observation, not a calibrated security score.
// Keep each receipt separate; selected rotate alone never establishes bearer invalidation.
export function PodBoundTokenResultPanel({ result, unsafeToRetry = false, caseProfile = "voice" }: { result: PodBoundTokenResult; unsafeToRetry?: boolean; caseProfile?: "voice" | "cpu" }) {
  const cpu = caseProfile === "cpu";
  const expectedNamespace = cpu ? "phorvex-catalogue-cpu" : "voice";
  const expectedCreator = cpu ? "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector-cpu" : "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector";
  const stages = Array.isArray(result?.stages) ? result.stages : [];
  const admission = result?.admission ?? {};
  const event = result?.event ?? {};
  const decision = result?.decision ?? {};
  const operation = result?.operation ?? {};
  const replay = result?.replay ?? {};
  const cleanup = result?.cleanup ?? {};
  const telemetry = result?.telemetry ?? {};
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
  const serviceTime = utcNanos(replay.serviceAfterAt);
  const firstMetricTime = utcNanos(telemetry.firstAt);
  const secondMetricTime = utcNanos(telemetry.secondAt);
  const replayAfterOperation = replayTime !== null && stageTimes.length === stageOrder.length &&
    stageTimes[2] !== null && stageTimes[4] !== null && stageTimes[6] !== null && stageTimes[7] !== null &&
    replayTime > stageTimes[2]! && replayTime > stageTimes[4]! && replayTime > stageTimes[6]! &&
    replayTime <= stageTimes[7]!;
  const serviceAfterOperation = serviceTime !== null && stageTimes.length === stageOrder.length &&
    stageTimes[6] !== null && stageTimes[7] !== null && serviceTime > stageTimes[6]! && serviceTime <= stageTimes[7]!;
  const cpuReplayTimeline = !cpu || (beforeExpiryMargin(replay.sourceBeforeRequestAt, replay.sourceBeforeAt, replay.sourceExpiry) &&
    beforeExpiryMargin(replay.sourceAfterRequestAt, replay.sourceAfterAt, replay.sourceExpiry) &&
    beforeExpiryMargin(replay.peerBeforeRequestAt, replay.peerBeforeAt, replay.peerExpiry) &&
    beforeExpiryMargin(replay.peerAfterRequestAt, replay.peerAfterAt, replay.peerExpiry) &&
    stageTimes.length === stageOrder.length && stageTimes[2] !== null && stageTimes[6] !== null && stageTimes[7] !== null &&
    utcNanos(replay.sourceBeforeAt)! <= stageTimes[2]! && utcNanos(replay.peerBeforeAt)! <= stageTimes[2]! &&
    utcNanos(replay.sourceAfterRequestAt)! > stageTimes[6]! && utcNanos(replay.peerAfterRequestAt)! > stageTimes[6]! &&
    utcNanos(replay.peerAfterAt)! <= stageTimes[7]!);
  const sourceCaptureJoined = !!(replay.sourceBeforeCaptureID &&
    replay.sourceBeforeCaptureID === replay.sourceAfterCaptureID);
  const peerCaptureJoined = !!(replay.peerBeforeCaptureID &&
    replay.peerBeforeCaptureID === replay.peerAfterCaptureID &&
    replay.peerBeforeCaptureID !== replay.sourceBeforeCaptureID);
  const measuredFixture = telemetry.producerStatus === "MEASURED_FRESH" &&
    !!telemetry.sourcePodName && !!telemetry.podMonitorUID && sha256.test(telemetry.querySHA256 || "") &&
    typeof telemetry.firstValue === "number" && Number.isFinite(telemetry.firstValue) && telemetry.firstValue >= 0 &&
    typeof telemetry.secondValue === "number" && Number.isFinite(telemetry.secondValue) && telemetry.secondValue >= 0 &&
    firstMetricTime !== null && secondMetricTime !== null && firstMetricTime < secondMetricTime &&
    stageTimes.length === stageOrder.length && stageTimes[4] !== null && secondMetricTime <= stageTimes[4]!;
  const telemetryMismatch = telemetry.producerStatus === "MEASURED_FRESH" &&
    decision.requestRateStatus !== "MEASURED_FRESH";
  const mechanismChain = !!(result.runID && result.nonce && admission?.available &&
    admission.clusterUID && admission.namespaceUID && admission.managerPodUID &&
    admission.managerContainerID && admission.managerImageID && admission.policyUID &&
    typeof admission.policyGeneration === "number" && admission.policyGeneration > 0 &&
    sha256.test(admission.policySpecSHA256 || "") && sha256.test(admission.profileSHA256 || "") &&
    admission.sourcePodUID && admission.peerPodUID && admission.sourcePodUID !== admission.peerPodUID &&
    admission.serviceUID && admission.deploymentUID && admission.replicaSetUID &&
    event?.uid && event.creator === expectedCreator &&
    event.trustVerified && event.sourcePodUID &&
    admission?.namespace === expectedNamespace && admission.sourcePodUID === event.sourcePodUID &&
    event.kind === "phorvex.attack.pod-bound-api-auth" && decision?.id &&
    decision.auditCoverage === "COMPLETE" && decision.requestRateStatus === "MEASURED_FRESH" && measuredFixture &&
    !brainBranch?.startsWith("NOOP_") && nativeBranch !== "NOT_DISPATCHED" &&
    decision.selectedAction === "rotate" && decision.dispatchOutcome === "emitted" &&
    operation?.terminationStatus === "REQUEST_CONFIRMED" && operation.originalPodAbsent && sha256.test(operation.receiptSHA256 || "") &&
    replay?.sameSourceHandle && replay?.samePeerHandle && sourceCaptureJoined && peerCaptureJoined &&
    replay.sourceBeforeHTTP === 200 &&
    replay.sourceAfterHTTP === 401 && replayAfterOperation && beforeExpiry(replay.sourceAfterAt || "", replay.sourceExpiry || "") && cpuReplayTimeline &&
    replay.peerBeforeHTTP === 200 && replay.peerAfterHTTP === 200 &&
    replay.serviceBeforeHTTP === 200 && replay.serviceAfterHTTP === 200 && serviceAfterOperation &&
    replay.serviceAfterServiceUID === admission.serviceUID && replay.serviceAfterEndpointSliceUID &&
    replay.serviceMemberPodUID && replay.serviceMemberPodUID !== admission.sourcePodUID &&
    replay.serviceMemberReady && replay.serviceMemberOwnerDeploymentUID === admission.deploymentUID &&
    cleanup?.status === "CONFIRMED_ABSENT" && cleanup.absent && sha256.test(cleanup.inventorySHA256 || "") && completeStages && orderedTimes);
  if (result?.schema !== "pod-bound-token-result-v1" || result.securityEfficacy !== "NOT_EVALUATED" ||
      (cpu ? result.caseID !== "c2-pod-bound-api-auth-response-cpu" : !!result.caseID && result.caseID !== "c2-pod-bound-api-auth-response") ||
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
    ["This-run cleanup", cleanup.status],
  ];
  if (cpu) observationRows.push(
    ["Source baseline request/response", `${known(replay.sourceBeforeRequestAt)} → ${known(replay.sourceBeforeAt)}`],
    ["Source post request/response", `${known(replay.sourceAfterRequestAt)} → ${known(replay.sourceAfterAt)}`],
    ["Peer baseline request/response", `${known(replay.peerBeforeRequestAt)} → ${known(replay.peerBeforeAt)}`],
    ["Peer post request/response", `${known(replay.peerAfterRequestAt)} → ${known(replay.peerAfterAt)}`],
    ["Source / peer expiry", `${known(replay.sourceExpiry)} / ${known(replay.peerExpiry)}`],
  );
  return <div data-pod-bound-token-result={result.mechanismObserved ? "mechanism-observed" : "observation-only"} className="rounded-md border border-border bg-muted/20 p-3 text-[12px]">
    <div className="font-medium text-foreground">{cpu ? "CPU fixture · injected Pod-bound API bearer response" : "Injected Pod-bound API bearer response"} · {known(result.terminalStatus)}</div>
    <div className="mt-1 text-muted-foreground">The SecurityEvent is explicitly injected. Selection, request emission, exact Pod retirement, source-bearer replay, peer access, Service routing and cleanup are separate observations. Natural detection and calibrated defense efficacy are NOT EVALUATED.{cpu ? " Availability is sampled at the recorded peer and routed Service checks, not continuous uptime." : ""}</div>
    {result.mechanismObserved ? <div className="mt-2 text-foreground">ROTATE_CREDENTIAL_MECHANISM_OBSERVED: the same captured source bearer changed from API 200 to 401 {cpu ? "with request starts and response ends at least 30 seconds before expiry" : "before expiry"} while the captured peer bearer and owned Service returned 200 at the recorded samples, with exact retirement and cleanup receipts. {cpu ? "This does not establish zero downtime." : ""}</div>
      : <div className="mt-2 text-warning">No credential-rotation mechanism is established by this observation. A complete no-op is a valid negative case result, not a defense success.</div>}
    <dl className="mt-2 grid gap-x-4 gap-y-1 md:grid-cols-2">{observationRows.map(([label, value]) => <div key={label} className="flex min-w-0 gap-2"><dt className="shrink-0 text-muted-foreground">{label}:</dt><dd className="break-all font-mono text-foreground">{known(value)}</dd></div>)}</dl>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Ordered stage ledger ({stages.length})</div>
      <div className="mt-1 space-y-1 text-muted-foreground">{stageRows.length ? stageRows : <div>UNKNOWN: no stage receipts projected.</div>}</div>
    </div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Exact identities and authority</div>
      <div className="mt-1 break-all text-muted-foreground">{cpu ? `case ${known(result.caseID)} · ` : ""}run {known(result.runID)} · cluster {known(admission.clusterUID)} · namespace {known(admission.namespace)} / UID {known(admission.namespaceUID)} · manager Pod UID {known(admission.managerPodUID)} · container {known(admission.managerContainerID)} · image {known(admission.managerImageID)} · policy UID {known(admission.policyUID)} / generation {known(admission.policyGeneration)} · policy spec SHA-256 {known(admission.policySpecSHA256)} · profile SHA-256 {known(admission.profileSHA256)}</div>
      <div className="mt-1 break-all text-muted-foreground">source Pod UID {known(admission.sourcePodUID)} · peer Pod UID {known(admission.peerPodUID)} · Deployment UID {known(admission.deploymentUID)} · ReplicaSet UID {known(admission.replicaSetUID)} · Service UID {known(admission.serviceUID)} · event UID {known(event.uid)} · kind {known(event.kind)} · stamped creator {known(event.creator)} · event source Pod UID {known(event.sourcePodUID)} · decision {known(decision.id)}</div>
    </div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Brain candidates and measured gates</div>
      <div className="mt-1 text-muted-foreground">Rotate: {known(decision.rotateStatus)} · expected cost {known(decision.rotateExpectedCost)} · high cost {known(decision.rotateHighCost)} · ceiling {known(decision.costCeiling)} · {known(decision.rotateReason)}</div>
      <div className="mt-1 text-muted-foreground">Request rate: {known(decision.requestRateStatus)} · flow regime: {known(decision.flowRegime)} · audit coverage: {known(decision.auditCoverage)}</div>
      <div className="mt-1 text-muted-foreground">Quarantine: {known(decision.quarantineStatus)} · capacity {known(decision.quarantineUsed)}/{known(decision.quarantineLimit)} · {known(decision.quarantineReason)}</div>
      {noOpBranch && <div className="mt-1 text-warning">Recorded no-op gate: {brainBranch}. This code comes from the typed brain stage; no action was forced and no mechanism credit follows.</div>}
      {missingRequestRate && <div className="mt-1 text-warning">MISSING_REQUEST_RATE: the manager did not record a fresh source-Pod request-rate input for this decision. No mechanism credit follows from this telemetry state.</div>}
    </div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Request-rate evidence · producer and manager separately</div>
      <div className="mt-1 text-muted-foreground">Fixture scrape: {known(telemetry.producerStatus)} · source Pod {known(telemetry.sourcePodName)} · PodMonitor UID {known(telemetry.podMonitorUID)} · query SHA-256 {known(telemetry.querySHA256)}</div>
      <div className="mt-1 text-muted-foreground">Samples: {known(telemetry.firstValue)} at {known(telemetry.firstAt)} → {known(telemetry.secondValue)} at {known(telemetry.secondAt)} · manager decision: {known(decision.requestRateStatus)}</div>
      {telemetryMismatch && <div className="mt-1 text-warning">The fixture recorded fresh source-Pod samples, but the manager did not record a fresh request-rate input for this decision. This remains an observed telemetry gap with no mechanism credit.</div>}
    </div>
    <div className="mt-3 border-t border-border pt-2">
      <div className="font-medium text-foreground">Same-handle API and Service controls</div>
      <div className="mt-1 text-muted-foreground">Source captured handle reused: {sourceCaptureJoined && replay.sameSourceHandle ? "yes" : "unverified"} ({known(replay.sourceBeforeCaptureID)} → {known(replay.sourceAfterCaptureID)}) · peer captured handle reused: {peerCaptureJoined && replay.samePeerHandle ? "yes" : "unverified"} ({known(replay.peerBeforeCaptureID)} → {known(replay.peerAfterCaptureID)}) · source replay {known(replay.sourceAfterAt)} · source expiry {known(replay.sourceExpiry)} · {cpu ? "all recorded source/peer requests and responses before expiry−30s" : "replay before expiry"}: {cpu ? cpuReplayTimeline ? "yes" : "unverified" : beforeExpiry(replay.sourceAfterAt || "", replay.sourceExpiry || "") ? "yes" : "unverified"}</div>
      <div className="mt-1 break-all text-muted-foreground">Service routed member UID {known(replay.serviceMemberPodUID)} · Ready {replay.serviceMemberReady ? "yes" : "unverified"} · owner Deployment UID {known(replay.serviceMemberOwnerDeploymentUID)} · Service UID {known(replay.serviceAfterServiceUID)} · EndpointSlice UID {known(replay.serviceAfterEndpointSliceUID)} · observed {known(replay.serviceAfterAt)}</div>
      <div className="mt-1 break-all text-muted-foreground">Exact operation receipt SHA-256 {known(operation.receiptSHA256)} · this-run cleanup inventory SHA-256 {known(cleanup.inventorySHA256)} · this-run owned graph and source reservation absent: {cleanup.absent ? "yes" : "unverified"}</div>
    </div>
    {(result.terminalStatus === "UNSAFE" || !cleanup.absent) && <div className="mt-2 text-warning">This run's exact cleanup or source reservation remains unresolved. Do not retry until exact reconciliation confirms safety.</div>}
    {unsafeToRetry && <div className="mt-2 text-warning">Run status forbids retry. Inspect this result and the separate prior-reservation ledger before another attempt.</div>}
    {cpu && <div className="mt-2 text-muted-foreground">CPU case limits: one explicitly injected event arm, exact original source and peer bearers, before-expiry replay, and sampled owned Service routing. An ordinary platform restart arm, continuous availability, natural detection and calibrated security efficacy are not measured.</div>}
    <div className="mt-2 text-muted-foreground">This-run cleanup does not certify that unrelated earlier {cpu ? "CPU, Voice" : "Voice"} or quarantine reservations are absent. Prior debt is checked separately by server admission.</div>
  </div>;
}
