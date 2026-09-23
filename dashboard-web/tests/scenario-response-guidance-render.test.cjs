const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/scenario-response-guidance.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const moduleUnderTest = { exports: {} };
new Function("require", "module", "exports", compiled)(require, moduleUnderTest, moduleUnderTest.exports);
const render = (item) => renderToStaticMarkup(React.createElement(moduleUnderTest.exports.ScenarioResponseGuidance, { item }));
const { displayActuatorHints } = moduleUnderTest.exports;

test("current credential item identifies heuristic and the off-Pod limitation", () => {
  const html = render({ name: "c1-credtheft-rbac", benignControl: false, expectedActuators: ["rotate"], responseGuidanceBasis: "name-heuristic", responseGuidance: "server guidance" });
  assert.match(html, /data-guidance-basis="name-heuristic"/);
  assert.match(html, /Name-based actuator hints/);
  assert.match(html, /initial disclosure persists/);
  assert.match(html, /Quarantine cannot revoke an off-Pod bearer token/);
  assert.match(html, /No automatic detector or manager response is asserted/);
  assert.deepEqual(displayActuatorHints({ name: "c1-credtheft-rbac", expectedActuators: ["rotate", "quarantine"] }), ["rotate"]);
  assert.doesNotMatch(html, /server guidance/);
});

test("legacy metadata does not imply an enabled or correct actuator", () => {
  const html = render({ name: "c1-credtheft-rbac", expectedActuators: ["rotate", "quarantine"] });
  assert.match(html, /Legacy actuator hints \(basis unverified\)/);
  assert.match(html, /off-Pod bearer token/);
  assert.doesNotMatch(html, /rotate, quarantine/);
  assert.doesNotMatch(html, /enabled|should trigger|DEFENDED/);
});

test("unmapped nonbenign and unknown legacy rows are not called functional controls", () => {
  for (const row of [
    { name: "unmapped-attack", benignControl: false, expectedActuators: [] },
    { name: "unmapped-legacy", expectedActuators: [] },
  ]) {
    const html = render(row);
    assert.match(html, /Response mapping unestablished/);
    assert.match(html, /No automatic response or defense is established/);
    assert.doesNotMatch(html, /functional control|DEFENDED|enabled/);
  }
});

test("benign control remains without actuator hint", () => {
  const html = render({ name: "c2-voice-websocket-continuity", benignControl: true, expectedActuators: [], responseGuidanceBasis: "none", responseGuidance: "Benign functional control; no actuator response or security outcome is asserted." });
  assert.match(html, /No actuator response asserted/);
  assert.match(html, /Benign functional control/);
  assert.doesNotMatch(html, /Name-based actuator hints/);
});

test("explicit V1 effect operation remains separate from mitigation", () => {
  const html = render({ name: "limited-v1-vllm-guardrail-effect", expectedActuators: ["guardrail-rotate"], responseGuidanceBasis: "explicit-effect", responseGuidance: "An exact-target variant effect does not establish behavioral bypass or mitigation." });
  assert.match(html, /Expected effect operation/);
  assert.match(html, /guardrail-rotate/);
  assert.match(html, /does not establish behavioral bypass or mitigation/);
});
