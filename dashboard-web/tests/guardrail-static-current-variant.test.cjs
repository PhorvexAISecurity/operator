const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/guardrail-static-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  fileName: "guardrail-static-result.tsx",
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);

test("observe-current static evidence renders the actual variant without defense credit", () => {
  for (const variant of ["pgv1", "pgv2"]) {
    const result = {
      accepted: true, status: "RAW_DISCLOSED_GUARDED_TYPED_403_STATIC_FILTER_FOR_FIXED_PROBE", calls: [], issues: [],
      sayOK: variant === "pgv1" ? "SAY_OK_FALSE_POSITIVE_OBSERVED" : "NOT_EVALUATED", arithmetic: "ARITHMETIC_AVAILABLE",
      podUID: "reviewed-pod", variant, configuredSelector: "observe-current", sourceSHA256: "a".repeat(64),
      guardrailJournalUID: "journal-uid", guardrailJournalGeneration: 1, kvJournalUID: "kv-uid",
      eventMode: "DIRECT_STATIC", naturalDetector: "NOT_EVALUATED", brainDecision: "NOT_EVALUATED", actuator: "NOT_EVALUATED",
      sourceEvidence: "configmap-mount-declaration", loadedSource: "NOT_ATTESTED", externalRoute: "NOT_TESTED",
    };
    const html = renderToStaticMarkup(React.createElement(subject.exports.GuardrailStaticResultPanel, { result }));
    assert.match(html, new RegExp(`observed variant ${variant} · configured selector observe-current`));
    assert.match(html, /brain decision: NOT_EVALUATED · actuator: NOT_EVALUATED/);
    assert.match(html, /No general efficacy or Phorvex defense score is inferred/);
  }
});
