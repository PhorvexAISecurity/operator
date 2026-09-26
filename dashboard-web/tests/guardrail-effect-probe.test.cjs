const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/guardrail-effect-probe.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);
const render = (result) => renderToStaticMarkup(React.createElement(subject.exports.GuardrailEffectProbe, { result }));

const joined = {
  schema: "guardrail-effect-probe-result-v1", status: "INJECTED_SYNTHETIC_OBJECTIVE_STOPPED", accepted: true, issues: [],
  eventMode: "INJECTED", naturalDetector: "NOT_EVALUATED", generalSecurityEfficacy: "NOT_EVALUATED",
  route: "Pod-loopback-8000", profileSHA256: "a".repeat(64), markerSHA256: "b".repeat(64),
  before: { canary: "DISCLOSED", sayOK: "OK", arithmetic: "FOUR" },
  after: { canary: "GUARDRAIL_BLOCKED", sayOK: "OK", arithmetic: "FOUR" },
  guardedChatsAttempted: 6, consoleLaunchPOSTs: 1, securityEventsAttempted: 1,
  eventUID: "event-uid", decisionID: "decision-id", operationID: "operation-id",
  priorVariant: "pgv1", nextVariant: "pgv2", cleanupVerified: true,
};

test("joined same-request change shows separate objective, benign controls and chain receipts", () => {
  const html = render(joined);
  assert.match(html, /data-guardrail-effect="objective-stopped"/);
  for (const value of ["DISCLOSED", "GUARDRAIL_BLOCKED", "Before Say OK", "After arithmetic", "event-uid", "decision-id", "operation-id", "SecurityEvents attempted: 1", "NOT_EVALUATED"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /DEFENDED|natural detection confirmed|general security efficacy confirmed/);
});

test("already-blocked baseline has zero events and never earns an injected improvement", () => {
  const stopped = { ...joined, status: "STOP_STATIC_BLOCKED_NO_RESPONSE_NEEDED", eventMode: "NONE", before: { canary: "GUARDRAIL_BLOCKED", sayOK: "OK", arithmetic: "FOUR" }, after: { canary: "", sayOK: "", arithmetic: "" }, guardedChatsAttempted: 3, securityEventsAttempted: 0, eventUID: "", decisionID: "", operationID: "" };
  assert.match(render(stopped), /data-guardrail-effect="pre-event-stop"/);
  assert.match(render(stopped), /already blocked before any SecurityEvent or actuation/);
  assert.match(render({ ...stopped, status: "STOP_STATIC_BLOCKED_LEGITIMATE_BASELINE_FAILED", before: { canary: "GUARDRAIL_BLOCKED", sayOK: "GUARDRAIL_BLOCKED", arithmetic: "FOUR" } }), /legitimate baseline request failed/);
  assert.match(render({ ...stopped, status: "STOP_LEGITIMATE_BASELINE_FAILED", before: { canary: "DISCLOSED", sayOK: "GUARDRAIL_BLOCKED", arithmetic: "FOUR" } }), /cannot establish a service-preserving defense/);
  assert.match(render({ ...stopped, status: "STOP_STATIC_BLOCKED_LEGITIMATE_BASELINE_FAILED" }), /data-guardrail-effect="incompatible"/);
  assert.match(render({ ...stopped, securityEventsAttempted: 1 }), /data-guardrail-effect="incompatible"/);
  assert.match(render({ ...joined, eventUID: "" }), /data-guardrail-effect="incompatible"/);
  assert.match(render({ ...joined, issues: ["missing audit" ] }), /data-guardrail-effect="incompatible"/);
});

test("joined negative outcomes distinguish continued disclosure and legitimate regression", () => {
  const disclosed = { ...joined, status: "SYNTHETIC_OBJECTIVE_STILL_DISCLOSED", after: { canary: "DISCLOSED", sayOK: "OK", arithmetic: "FOUR" } };
  assert.match(render(disclosed), /marker was still disclosed after the exactly joined rotation/);
  assert.doesNotMatch(render(disclosed), /This defends only the declared synthetic objective/);
  assert.match(render({ ...disclosed, decisionID: "" }), /data-guardrail-effect="incompatible"/);
  assert.match(render({ ...disclosed, issues: ["incomplete originals"] }), /data-guardrail-effect="incompatible"/);
  const regression = { ...joined, status: "OBJECTIVE_STOPPED_WITH_LEGITIMATE_REGRESSION", after: { canary: "GUARDRAIL_BLOCKED", sayOK: "GUARDRAIL_BLOCKED", arithmetic: "FOUR" } };
  assert.match(render(regression), /Service-preserving defense was not established/);
  assert.doesNotMatch(render(regression), /This defends only the declared synthetic objective/);
  assert.match(render({ ...regression, after: joined.after }), /data-guardrail-effect="incompatible"/);
  assert.match(render({ ...regression, after: { canary: "GUARDRAIL_BLOCKED", sayOK: "UNKNOWN_HTTP_RECEIPT", arithmetic: "FOUR" } }), /data-guardrail-effect="incompatible"/);
});
