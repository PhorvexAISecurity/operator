const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/guardrail-availability-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);
const render = (result, unsafeToRetry = false) => renderToStaticMarkup(React.createElement(subject.exports.GuardrailAvailabilityResultPanel, { result, unsafeToRetry }));

const complete = {
  accepted: true, status: "INJECTED_GUARDRAIL_AVAILABILITY_RECOVERY_CONFIRMED", issues: [],
  eventMode: "INJECTED", naturalDetector: "NOT_EVALUATED", securityEfficacy: "NOT_EVALUATED",
  syntheticThreat: "BLOCKED_BOTH_SIDES", route: "Pod-loopback-8000", loadedWeightsAttested: false,
  before: { canary: "GUARDRAIL_BLOCKED", sayOK: "GUARDRAIL_BLOCKED", arithmetic: "FOUR" },
  after: { canary: "GUARDRAIL_BLOCKED", sayOK: "OK", arithmetic: "FOUR" },
  operation: { eventUID: "event-uid", decisionID: "decision-id", operationID: "operation-id", priorVariant: "pgv1", nextVariant: "pgv2", generation: 3 },
  cleanupVerified: true,
};

test("accepted injected recovery renders all three before/after controls and separate chain receipts", () => {
  const html = render(complete);
  assert.match(html, /data-guardrail-availability-result="recovery-confirmed"/);
  for (const witness of ["Before · synthetic canary", "Before · Say OK", "Before · arithmetic", "After · synthetic canary", "After · Say OK", "After · arithmetic", "event-uid", "decision-id", "operation-id", "pgv1", "pgv2", "generation 3", "Exact cleanup", "verified"]) assert.ok(html.includes(witness), witness);
  assert.match(html, /Say OK changed from a typed guardrail block to OK/);
  assert.match(html, /synthetic canary remained blocked and arithmetic remained available/);
  assert.match(html, /natural detector: NOT_EVALUATED.*security efficacy: NOT_EVALUATED/);
  assert.match(html, /loaded model weights: NOT_ATTESTED/);
  assert.match(html, /not a threat-improvement claim/);
  assert.doesNotMatch(html, /defended|defense success|security efficacy: (?!NOT_EVALUATED)/i);
});

test("persistent false positive, arithmetic regression, pre-gate stop and unknown stay observation-only", () => {
  const cases = [
    { ...complete, status: "FALSE_POSITIVE_PERSISTS_AFTER_ROTATION", after: { ...complete.after, sayOK: "GUARDRAIL_BLOCKED" } },
    { ...complete, status: "LEGITIMATE_ARITHMETIC_REGRESSION_AFTER_ROTATION", after: { ...complete.after, arithmetic: "OTHER_200" } },
    { ...complete, status: "SYNTHETIC_THREAT_REGRESSION_AFTER_ROTATION", after: { ...complete.after, canary: "DISCLOSED" } },
    { ...complete, status: "STOP_BASELINE_NOT_DISCRIMINATING", eventMode: "NONE", after: { canary: "UNKNOWN_PRE_GATE", sayOK: "UNKNOWN_PRE_GATE", arithmetic: "UNKNOWN_PRE_GATE" }, operation: { eventUID: "", decisionID: "", operationID: "", priorVariant: "", nextVariant: "", generation: 0 } },
    { ...complete, accepted: false, status: "UNKNOWN", before: { canary: "UNKNOWN_AUDIT", sayOK: "UNKNOWN_AUDIT", arithmetic: "UNKNOWN_AUDIT" }, cleanupVerified: false, issues: ["audit gap"] },
  ];
  for (const row of cases) {
    const html = render(row);
    assert.match(html, /data-guardrail-availability-result="observation-only"/);
    assert.match(html, /No availability recovery is established/);
    assert.doesNotMatch(html, /data-guardrail-availability-result="recovery-confirmed"|Say OK changed from a typed guardrail block to OK/);
  }
  const stopped = render(cases[3]);
  assert.match(stopped, /no event accepted/);
  assert.match(stopped, /UNKNOWN_PRE_GATE/);
  assert.match(stopped, /stopped the case before an injected event/);
  const unknown = render(cases[4]);
  assert.match(unknown, /audit gap/);
  assert.match(unknown, /Injected guardrail availability comparison · UNKNOWN/);
  assert.match(unknown, /Exact cleanup is unverified/);
  assert.match(render({ ...complete, status: "SELECTED_NO_CONFIRMED_EFFECT" }), /Selection alone did not establish a terminal guardrail rotation effect/);
  assert.match(render(cases[0]), /Say OK remained blocked after rotation/);
  assert.match(render(cases[1]), /arithmetic legitimate control regressed/);
  assert.match(render(cases[2]), /synthetic canary containment regressed/);
});

test("contradictory strongest status, unsafe run or altered claim mode never earns recovery", () => {
  const invalid = [
    { ...complete, accepted: false },
    { ...complete, eventMode: "NONE" },
    { ...complete, naturalDetector: "DETECTED" },
    { ...complete, securityEfficacy: "DEFENDED" },
    { ...complete, route: "Service" },
    { ...complete, loadedWeightsAttested: true },
    { ...complete, syntheticThreat: "DISCLOSED" },
    { ...complete, before: { ...complete.before, sayOK: "OK" } },
    { ...complete, after: { ...complete.after, canary: "DISCLOSED" } },
    { ...complete, operation: { ...complete.operation, operationID: "" } },
    { ...complete, cleanupVerified: false },
    { ...complete, issues: ["unverified audit"] },
  ];
  for (const row of invalid) {
    const html = render(row);
    assert.match(html, /data-guardrail-availability-result="incompatible"/);
    assert.doesNotMatch(html, /data-guardrail-availability-result="recovery-confirmed"|Say OK changed from a typed guardrail block to OK/);
  }
  assert.match(render(complete, true), /incompatible claim contract/);
});
