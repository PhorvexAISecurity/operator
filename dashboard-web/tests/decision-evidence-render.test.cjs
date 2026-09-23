const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "components/panels/decision-evidence.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022,
    jsx: ts.JsxEmit.ReactJSX,
    esModuleInterop: true,
  },
}).outputText;
const moduleUnderTest = { exports: {} };
new Function("require", "module", "exports", compiled)(require, moduleUnderTest, moduleUnderTest.exports);
const { DecisionEvidenceTrace, DecisionEvidencePanel } = moduleUnderTest.exports;
const render = (decision, props = {}) => renderToStaticMarkup(React.createElement(DecisionEvidenceTrace, { decision, ...props }));

test("renders an exact event-bound NOOP without defense credit", () => {
  const html = render({
    correlation: "exact-event-uid",
    source: "decision-trace-steered-event",
    eventName: "signal-1",
    eventUid: "11111111-1111-4111-8111-111111111111",
    eventRule: "phorvex.signal",
    trustVerdict: "trusted",
    targetUid: "22222222-2222-4222-8222-222222222222",
    decisionId: "decision-1",
    tickId: "tick-1",
    policyNamespace: "vllm",
    policyName: "vllm-defense",
    action: "noop",
    selected: false,
    feasible: false,
    infeasibleWhy: "no feasible candidate",
    dispatchOutcome: "not-attempted",
    dispatchReason: "no-selection",
    actionStatus: [{ action: "request-drain", status: "excluded", exclusionKind: "capability", reason: "service authority unavailable" }],
  }, { observationStartedAt: "2026-09-23T20:00:00Z", observationDeadline: "2026-09-23T20:02:00Z" });
  assert.match(html, /Exact event match/);
  assert.match(html, /NOOP \/ NOT DISPATCHED/);
  assert.match(html, /service authority unavailable/);
  assert.match(html, /observation window/);
  assert.match(html, /2026-09-23T20:02:00Z/);
  assert.match(html, /no DEFENDED, containment, dwell, or ROI credit/);
  assert.doesNotMatch(html, />DEFENDED</);
});

test("renders a temporal candidate as weak even when selected and actuated", () => {
  const html = render({
    correlation: "temporal-workload",
    source: "temporal-candidate",
    time: "2026-09-23T20:00:00Z",
    action: "guardrail-rotate",
    selected: true,
    actuated: true,
    dispatchOutcome: "emitted",
  });
  assert.match(html, /Weak temporal candidate/);
  assert.match(html, /Name\/time proximity is a candidate only/);
  assert.match(html, /selected yes/);
  assert.match(html, /no DEFENDED, containment, dwell, or ROI credit/);
  assert.doesNotMatch(html, /Exact event match/);
});

test("renders missing decision evidence as unavailable rather than refusal", () => {
  const html = render(undefined);
  assert.match(html, /Manager decision unavailable/);
  assert.match(html, /not a refusal, NOOP, failed actuator, or defense result/);
});

test("does not call incomplete identity an exact match", () => {
  const html = render({ correlation: "exact-event-uid", eventUid: "event-only", action: "rotate" });
  assert.match(html, /Decision identity incomplete/);
  assert.match(html, /insufficient for an exact event-to-decision join/);
  assert.doesNotMatch(html, /Exact event match/);
});

test("keeps an exact generic input match while marking decision authority incomplete", () => {
  const html = render({
    correlation: "exact-event-uid",
    source: "generic-event-evidence",
    eventName: "signal-generic",
    eventUid: "generic-event-uid",
    targetUid: "generic-target-uid",
  });
  assert.match(html, /Exact event match/);
  assert.match(html, /Exact input match; decision identity is incomplete/);
  assert.match(html, /Unavailable: creator identity, decision ID, tick ID, complete policy identity, brain image, git SHA/);
  assert.match(html, /decision <span[^>]*>—<\/span> · tick <span[^>]*>—<\/span>/);
  assert.match(html, /policy <span[^>]*>unavailable<\/span>/);
  assert.match(html, /no DEFENDED, containment, dwell, or ROI credit/);
  assert.doesNotMatch(html, />DEFENDED</);
});

test("keeps exact rows and a weaker temporal candidate visibly separate", () => {
  const exact = [{
    correlation: "exact-event-uid", source: "generic-event-evidence",
    eventName: "signal-2", eventUid: "event-2", targetUid: "target-2",
    trustVerdict: "untrusted", decisionId: "decision-noop", action: "noop",
    dispatchOutcome: "not-attempted", dispatchReason: "untrusted-event",
  }];
  const temporal = { correlation: "temporal-workload", source: "temporal-candidate", action: "rotate", selected: true, actuated: true };
  const html = renderToStaticMarkup(React.createElement(DecisionEvidencePanel, { exact, temporal }));
  assert.match(html, /Exact event match/);
  assert.match(html, /trust untrusted/);
  assert.match(html, /Separate weaker candidate/);
  assert.match(html, /Weak temporal candidate/);
  assert.match(html, /does not itself prove trusted influence or sole cause/);
  assert.doesNotMatch(html, />DEFENDED</);
});

test("emitted-unconfirmed manager actuation is not called runtime confirmation", () => {
  const html = render({
    correlation: "exact-event-uid", source: "decision-trace-steered-event",
    eventName: "signal-3", eventUid: "33333333-3333-4333-8333-333333333333",
    targetUid: "44444444-4444-4444-8444-444444444444",
    creatorIdentity: "system:serviceaccount:test:producer",
    policyNamespace: "vllm", policyName: "vllm-defense", policyUid: "55555555-5555-4555-8555-555555555555",
    brainImage: "registry.example/brain@sha256:abcdef", gitSha: "0123456789abcdef",
    action: "guardrail-rotate", selected: true, actuated: true,
    dispatchOutcome: "emitted", dispatchReason: "emitted-unconfirmed",
  });
  assert.match(html, /manager actuation report yes/);
  assert.match(html, /manager actuation report is not runtime effect confirmation/);
  assert.match(html, /emitted-unconfirmed remains unconfirmed/);
  assert.doesNotMatch(html, /actuator confirmation yes/);
  assert.match(html, /policyUid=55555555-5555-4555-8555-555555555555/);
  assert.match(html, /creatorIdentity=system:serviceaccount:test:producer/);
  assert.match(html, /brainImage=registry.example\/brain@sha256:abcdef/);
  assert.match(html, /gitSha=0123456789abcdef/);
});

test("compact rendering retains candidate exclusion reasons", () => {
  const html = renderToStaticMarkup(React.createElement(DecisionEvidenceTrace, { compact: true, decision: {
    correlation: "temporal-workload", source: "temporal-candidate", action: "noop",
    actionStatus: [{ action: "request-drain", status: "excluded", exclusionKind: "capability", reason: "serving selector unavailable" }],
  } }));
  assert.match(html, /Candidate status/);
  assert.match(html, /request-drain/);
  assert.match(html, /serving selector unavailable/);
});
