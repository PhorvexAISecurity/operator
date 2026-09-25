const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const root = path.resolve(__dirname, "..");
const primitives = { Badge: ({ children }) => React.createElement("span", null, children) };
function load(relative) {
  const source = fs.readFileSync(path.join(root, relative), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const subject = { exports: {} };
  new Function("require", "module", "exports", compiled)((name) => {
    if (name === "@/components/ui/primitives") return primitives;
    if (name === "@/lib/attack-result-truth") return truth;
    if (name === "@/components/panels/decision-evidence") return decision;
    return require(name);
  }, subject, subject.exports);
  return subject.exports;
}
const truth = load("lib/attack-result-truth.ts");
const decision = load("components/panels/decision-evidence.tsx");
const { CatalogueSignalResult } = load("components/panels/catalogue-signal-result.tsx");
const stimulusEvidence = { observed: true, eventName: "signal-a", eventUid: "event-a", eventRule: "PromptInjection", targetUid: "pod-a", limitation: "Signal-only." };
const exact = { correlation: "exact-event-uid", eventName: "signal-a", eventUid: "event-a", eventRule: "PromptInjection", targetUid: "pod-a", action: "quarantine", selected: true, dispatchOutcome: "emitted-unconfirmed" };
const base = { id: "record-a", status: "done", responseObserved: true, responseAction: "rotate", responsePod: "demo-0", responseSeconds: 4, expectedActuator: "guardrail-rotate", stimulusEvidence };
const render = (row, compact = true) => renderToStaticMarkup(React.createElement(CatalogueSignalResult, { result: row, compact }));

test("real card does not turn target UID replacement into a selected action or completion", () => {
  const html = render(base);
  assert.match(html, /TARGET UID CHANGED/);
  assert.match(html, /cause not established/);
  assert.match(html, /signal-a/);
  assert.match(html, /PromptInjection/);
  assert.match(html, /listed name-derived hint.*guardrail-rotate/);
  assert.match(html, /exactly joined selected action.*not established/);
  assert.match(html, /brain decision unavailable/);
  assert.match(html, /actuator\/operation completion: not established/);
  assert.match(html, /behavioral outcome and landed reason:.*not evaluated/);
  assert.doesNotMatch(html, /selected action.*rotate/);
});

test("real card distinguishes temporal candidate from exact selected action", () => {
  const temporal = render({ ...base, temporalDecisionEvidence: { source: "temporal-candidate", correlation: "temporal-workload", action: "rotate", selected: true } });
  assert.match(temporal, /brain decision temporal candidate only/);
  assert.match(temporal, /exactly joined selected action.*not established/);
  assert.match(temporal, /Weak temporal candidate/);
  const joined = render({ ...base, decisionTraceEvidence: [exact] });
  assert.match(joined, /brain decision exact event\/target decision join/);
  assert.match(joined, /exactly joined selected action.*quarantine/);
  assert.match(joined, /dispatch.*emitted-unconfirmed/);
  assert.match(joined, /actuator\/operation completion: not established/);
  const wrongTarget = render({ ...base, decisionTraceEvidence: [{ ...exact, targetUid: "other-pod" }] });
  assert.match(wrongTarget, /exactly joined selected action.*not established/);
  assert.doesNotMatch(wrongTarget, /selected action.*quarantine/);
  const noop = render({ ...base, decisionTraceEvidence: [{ ...exact, action: "noop", selected: false, dispatchOutcome: "not-attempted" }] });
  assert.match(noop, /exactly joined selected action.*not established/);
  assert.match(noop, /decision action.*noop.*selected no/);
});
