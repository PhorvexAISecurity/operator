const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/nats-configuration-clarity.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);
const render = (result) => renderToStaticMarkup(React.createElement(subject.exports.NATSConfigurationClarity, { result }));

test("accepted direct NATS control does not call stimulus metadata a brain outcome", () => {
  const html = render({ brainMode: "NO_SIGNAL", securityEfficacy: "NOT_EVALUATED" });
  assert.match(html, /stimulus: no SecurityEvent injected/);
  assert.match(html, /brain\/actuator: not evaluated/);
  assert.match(html, /defense efficacy: not evaluated/);
  assert.doesNotMatch(html, /brain: NO_SIGNAL|NOOP/);
});

test("unexpected legacy values retain an honest unknown label", () => {
  const html = render({ brainMode: "SURPRISE", securityEfficacy: "SURPRISE" });
  assert.match(html, /unknown \(unexpected stimulus metadata\)/);
  assert.match(html, /brain\/actuator: unknown \(unexpected metadata\)/);
  assert.match(html, /defense efficacy: unknown \(unexpected metadata\)/);
  assert.doesNotMatch(html, /NOOP|exposed/);
});
