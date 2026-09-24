const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/pod-bound-token-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);
const render = (result, unsafeToRetry = false) => renderToStaticMarkup(React.createElement(subject.exports.PodBoundTokenResultPanel, { result, unsafeToRetry }));
const stageNames = ["ADMISSION", "OWNED_FIXTURE", "CREDENTIAL_AND_ROUTE_BASELINE", "AUDIT_START", "SOLE_TYPED_SIGNAL", "BRAIN_DECISION", "NATIVE_OPERATION", "INDEPENDENT_OUTCOME", "CLEANUP"];
const stages = stageNames.map((name, index) => ({ name, status: "CONFIRMED", observedAt: `2026-09-24T15:00:0${index}Z`, evidenceSHA256: "a".repeat(64), reason: "" }));
const observation = {
  schema: "pod-bound-token-result-v1", runID: "run-1", nonce: "owned-nonce", terminalStatus: "COMPLETE",
  mechanismObserved: false, securityEfficacy: "NOT_EVALUATED", signalMode: "explicit-injected-typed-event",
  stages,
  admission: { clusterUID: "cluster-uid", namespace: "voice", namespaceUID: "namespace-uid", managerPodUID: "manager-uid", policyUID: "policy-uid", policyGeneration: 4, policySpecSHA256: "b".repeat(64), profileSHA256: "c".repeat(64), sourcePodUID: "source-uid", peerPodUID: "peer-uid", serviceUID: "service-uid", available: true, unavailableReason: "" },
  event: { uid: "event-uid", kind: "phorvex.attack.pod-bound-api-auth", creator: "admitted-creator", sourcePodUID: "source-uid", trustVerified: true },
  decision: { id: "decision-id", selectedAction: "noop", dispatchOutcome: "not-attempted", costCeiling: 1.2, rotateStatus: "conformal-slo", rotateReason: "conformal-slo: worst-case cost 1.60 > ceiling 1.20", rotateExpectedCost: 0.82, rotateHighCost: 1.6, requestRateStatus: "MISSING_REQUEST_RATE", flowRegime: "missing-load", quarantineStatus: "infeasible", quarantineReason: "quarantine-capacity-exhausted: used=1 limit=1", quarantineUsed: 1, quarantineLimit: 1, auditCoverage: "COMPLETE" },
  operation: { terminationStatus: "NOT_DISPATCHED", originalPodAbsent: false, receiptSHA256: "" },
  replay: { sourceBeforeHTTP: 200, sourceAfterHTTP: 200, sourceExpiry: "2026-09-24T15:10:00Z", sourceAfterAt: "2026-09-24T15:00:06.500Z", peerBeforeHTTP: 200, peerAfterHTTP: 200, serviceBeforeHTTP: 200, serviceAfterHTTP: 200, sameSourceHandle: true, samePeerHandle: true },
  cleanup: { status: "CONFIRMED_ABSENT", inventorySHA256: "d".repeat(64), absent: true },
};

test("complete injected no-op shows real cost, capacity and telemetry causes without mechanism credit", () => {
  const row = { ...observation, stages: stages.map((s) => s.name === "BRAIN_DECISION" ? { ...s, reason: "NOOP_COST_GATE_AND_CAPACITY" } : s) };
  const html = render(row);
  assert.match(html, /data-pod-bound-token-result="observation-only"/);
  for (const code of ["NOOP_COST_GATE_AND_CAPACITY", "MISSING_REQUEST_RATE", "NOT_DISPATCHED", "source-uid", "peer-uid", "service-uid", "policy-uid", "1\.6", "1\.2"]) assert.match(html, new RegExp(code));
  assert.match(html, /explicitly injected/);
  assert.match(html, /Natural detection and calibrated defense efficacy are NOT EVALUATED/);
  assert.doesNotMatch(html, /ROTATE_CREDENTIAL_MECHANISM_OBSERVED|data-pod-bound-token-result="mechanism-observed"/);
});

test("only full same-handle 200-to-401 before-expiry chain displays mechanism observation", () => {
  const positive = { ...observation, mechanismObserved: true,
    decision: { ...observation.decision, selectedAction: "rotate", dispatchOutcome: "emitted", requestRateStatus: "MEASURED_FRESH" },
    operation: { terminationStatus: "REQUEST_CONFIRMED", originalPodAbsent: true, receiptSHA256: "e".repeat(64) },
    replay: { ...observation.replay, sourceAfterHTTP: 401 } };
  const html = render(positive);
  assert.match(html, /data-pod-bound-token-result="mechanism-observed"/);
  assert.match(html, /ROTATE_CREDENTIAL_MECHANISM_OBSERVED/);
  for (const changed of [
    { ...positive, decision: { ...positive.decision, dispatchOutcome: "not-attempted" } },
    { ...positive, decision: { ...positive.decision, requestRateStatus: "MISSING_REQUEST_RATE" } },
    { ...positive, admission: { ...positive.admission, peerPodUID: "source-uid" } },
    { ...positive, operation: { ...positive.operation, originalPodAbsent: false } },
    { ...positive, replay: { ...positive.replay, sourceAfterHTTP: 403 } },
    { ...positive, replay: { ...positive.replay, sourceAfterAt: "2026-09-24T15:11:00Z" } },
    { ...positive, replay: { ...positive.replay, sourceAfterAt: "2026-09-24T15:00:03Z" } },
    { ...positive, replay: { ...positive.replay, sourceAfterAt: "2026-09-24T15:00:08.500Z" } },
    { ...positive, replay: { ...positive.replay, peerAfterHTTP: 401 } },
    { ...positive, replay: { ...positive.replay, sameSourceHandle: false } },
    { ...positive, cleanup: { ...positive.cleanup, absent: false } },
    { ...positive, stages: stages.map((s) => s.name === "BRAIN_DECISION" ? { ...s, status: "UNKNOWN" } : s) },
    { ...positive, stages: stages.map((s) => ({ ...s, observedAt: "2026-09-24T15:00:00Z" })) },
    { ...positive, stages: stages.map((s) => s.name === "BRAIN_DECISION" ? { ...s, observedAt: "2026-09-24T15:00:02Z" } : s) },
    { ...positive, stages: stages.map((s) => s.name === "BRAIN_DECISION" ? { ...s, reason: "NOOP_COST_GATE_AND_CAPACITY" } : s) },
    { ...positive, stages: stages.map((s) => s.name === "NATIVE_OPERATION" ? { ...s, reason: "NOT_DISPATCHED" } : s) },
    { ...positive, event: { ...positive.event, trustVerified: false } },
  ]) {
    const refused = render(changed);
    assert.match(refused, /incompatible claim contract/);
    assert.doesNotMatch(refused, /data-pod-bound-token-result=/);
  }
  assert.match(render(positive, true), /incompatible claim contract/);
});

test("missing witnesses stay visibly UNKNOWN with no credential claim", () => {
  const html = render({ schema: observation.schema, terminalStatus: "INCOMPLETE", mechanismObserved: false,
    securityEfficacy: "NOT_EVALUATED", signalMode: "explicit-injected-typed-event", stages: [] }, true);
  assert.match(html, /data-pod-bound-token-result="observation-only"/);
  assert.match(html, /UNKNOWN: no stage receipts projected/);
  assert.match(html, /Cleanup or protected capacity may remain unresolved/);
  assert.doesNotMatch(html, /ROTATE_CREDENTIAL_MECHANISM_OBSERVED/);
  const unsafe = render({ ...observation, terminalStatus: "UNSAFE" });
  assert.match(unsafe, /Do not retry this run until exact reconciliation confirms safety/);
});

test("wrong schema or asserted defense efficacy is never rendered as accepted", () => {
  for (const changed of [{ ...observation, schema: "other" }, { ...observation, securityEfficacy: "DEFENDED" }, { ...observation, signalMode: "natural" }]) {
    assert.match(render(changed), /incompatible claim contract/);
  }
});
