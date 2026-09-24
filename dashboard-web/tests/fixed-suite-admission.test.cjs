const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/catalog.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
const requireSource = (id) => id.startsWith("@/") || id.startsWith("./") || id === "lucide-react" ? {} : require(id);
new Function("require", "module", "exports", compiled)(requireSource, subject, subject.exports);
const { FixedSuiteAdmissionNotice, fixedSuiteAdmissionReady } = subject.exports;
const render = (state, refreshes = 0, configured = true) => renderToStaticMarkup(React.createElement(FixedSuiteAdmissionNotice, { configured, state, refreshes, onRefresh: () => {} }));

test("exact profile and request key are required for fixed-suite launch", () => {
  const state = { key: "identity-a/profile-a/0", profile: "profile-a", phase: "ready", reasonCode: "READY", observedAt: "2026-09-24T10:30:00Z" };
  assert.equal(fixedSuiteAdmissionReady(state.key, "profile-a", state), true);
  assert.equal(fixedSuiteAdmissionReady("identity-a/profile-b/0", "profile-b", state), false);
  assert.equal(fixedSuiteAdmissionReady("identity-b/profile-a/0", "profile-a", state), false);
  assert.equal(fixedSuiteAdmissionReady(state.key, "profile-b", state), false);
  assert.equal(fixedSuiteAdmissionReady(state.key, "profile-a", { ...state, phase: "checking" }), false);
  assert.equal(fixedSuiteAdmissionReady(state.key, "profile-a", { ...state, phase: "error" }), false);
  assert.equal(fixedSuiteAdmissionReady(state.key, "profile-a", { ...state, reasonCode: "PRIOR_UNSAFE_FIXED_SUITE" }), false);
});

test("configuration and current admission render separately with bounded refresh", () => {
  const ready = render({ key: "a", profile: "p", phase: "ready", reasonCode: "READY", observedAt: "2026-09-24T10:30:00Z" });
  assert.match(ready, /Configuration:.*available.*Current launch admission:.*ready/);
  assert.match(ready, /launch rechecks current state/);
  assert.match(ready, /Refresh admission/);
  const blocked = render({ key: "a", profile: "p", phase: "blocked", reasonCode: "PRIOR_UNSAFE_FIXED_SUITE" }, 3);
  assert.match(blocked, /Current launch admission:.*blocked/);
  assert.match(blocked, /needs reconciliation/);
  assert.doesNotMatch(blocked, /Refresh admission|v1run-|foreign-owner/);
  const failed = render({ key: "a", profile: "p", phase: "error" });
  assert.match(failed, /Admission check failed or was refused. Launch stays disabled/);
  assert.match(render(null), /checking the current server gate/i);
  assert.match(render(null, 0, false), /Profile configuration is unavailable/);
});
