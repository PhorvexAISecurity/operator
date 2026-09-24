const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/nats-client-response-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const moduleUnderTest = { exports: {} };
new Function("require", "module", "exports", compiled)(require, moduleUnderTest, moduleUnderTest.exports);
const render = (result, unsafeToRetry = false) => renderToStaticMarkup(React.createElement(moduleUnderTest.exports.NATSClientResponseResult, { result, unsafeToRetry }));
const observed = {
  accepted: true, cleanupVerified: true, m0Status: "EXPOSED", signalStatus: "INJECTED_EVENT_UID_JOINED",
  decisionStatus: "EXACT_EVENT_DECISION", selectedAction: "quarantine", dispatchOutcome: "emitted",
  effectStatus: "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED", m1Status: "CONTINUING_EXPOSURE",
  peerStatus: "READY_AND_RESPONSIVE", cleanupStatus: "CONFIRMED_ABSENT", securityEfficacy: "NOT_EVALUATED", issues: [],
  decisionTrace: { schema: "nats-client-response-decision-evidence-v1", decisionId: "decision-1", tickId: "tick-1",
    eventName: "event-1", eventUID: "event-uid-1", brainImage: "manager@sha256:abc", gitSHA: "git-1",
    inputPhase: "delivery", inputStage: "execution", pHold: { present: false, value: 0 },
    threatPosture: { present: true, value: 0 }, sloHeadroom: { present: true, value: 0.5 },
    selectedAction: "quarantine", noopReason: "",
    dispatchOutcome: "emitted", dispatchReason: "", claim: "OBJECT_EFFECT_AND_PACKET_OUTCOME_SEPARATE_SECURITY_NOT_EVALUATED",
    facts: [{ type: "owned-client-signal", source: "trusted-event", weight: 1, coveredBefore: false }],
    candidates: [{ action: "quarantine", selected: true, exclusion: "", feasible: { present: true, value: true },
      marginalCoverage: { present: true, value: 0 }, expectedCost: { present: true, value: 0 }, netGain: { present: false, value: 0 } },
    { action: "rotate", selected: false, exclusion: "capacity", feasible: { present: false, value: false },
      marginalCoverage: { present: false, value: 0 }, expectedCost: { present: false, value: 0 }, netGain: { present: false, value: 0 } }],
    actionStatus: [{ action: "rotate", status: "excluded", exclusionKind: "capacity", reason: "peer capacity gate", scored: false, rbacUnknown: false }] },
};

test("joined source and object effects remain separate from packet isolation", () => {
  const html = render(observed);
  assert.match(html, /data-nats-response-result="joined"/);
  assert.match(html, /Initial client M0/);
  assert.match(html, /Injected signal/);
  assert.match(html, /Selected action/);
  assert.match(html, /Same-connection M1/);
  assert.match(html, /Legitimate peer/);
  assert.match(html, /Exact event-bound brain trace/);
  assert.match(html, /rotate: capacity/);
  assert.match(html, /peer capacity gate/);
  assert.match(html, /pHold unavailable · threat 0 · SLO headroom 0\.5/);
  assert.match(html, /marginal 0, cost 0, net gain unavailable/);
  assert.match(html, /Continuing access observed/);
  assert.match(html, /Security outcome: NOT EVALUATED/);
  assert.doesNotMatch(html, />DEFENDED<|packet isolation confirmed|natural detector coverage observed/);
});

test("missing M1 or cleanup leaves original observation unaccepted and unsafe", () => {
  const html = render({ ...observed, accepted: false, cleanupVerified: false, m1Status: "UNKNOWN", cleanupStatus: "UNVERIFIED", issues: ["exact owned cleanup missing"] }, true);
  assert.match(html, /data-nats-response-result="unverified"/);
  assert.match(html, /missing M1 receipt alone does not prove isolation/);
  assert.match(html, /requires reconciliation before retry/);
  assert.match(html, /exact owned cleanup missing/);
  assert.doesNotMatch(html, /Continuing access observed/);
  assert.doesNotMatch(html, />DEFENDED</);
});

test("a terminal negative containment outcome names continuing access without defense credit", () => {
  const html = render({ ...observed, securityEfficacy: "CONTAINMENT_NOT_ACHIEVED" });
  assert.match(html, /CONTAINMENT NOT ACHIEVED in this owned trial/);
  assert.match(html, /Continuing access observed/);
  assert.doesNotMatch(html, />DEFENDED</);
});

test("incompatible security claim is refused by the presentation boundary", () => {
  const html = render({ ...observed, securityEfficacy: "DEFENDED" });
  assert.match(html, /incompatible claim contract/);
  assert.doesNotMatch(html, /data-nats-response-result=/);
  const mismatch = render({ ...observed, m1Status: "UNKNOWN", securityEfficacy: "CONTAINMENT_NOT_ACHIEVED" });
  assert.match(mismatch, /incompatible claim contract/);
  const unbound = render({ ...observed, decisionTrace: { ...observed.decisionTrace, selectedAction: "rotate" } });
  assert.match(unbound, /incompatible claim contract/);
});
