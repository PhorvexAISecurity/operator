const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/guardrail-calibration-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const moduleUnderTest = { exports: {} };
new Function("require", "module", "exports", compiled)(require, moduleUnderTest, moduleUnderTest.exports);
const render = (evidence) => renderToStaticMarkup(React.createElement(moduleUnderTest.exports.GuardrailCalibrationResult, { evidence }));

test("valid benign false positive stays a classifier finding", () => {
  const html = render({ classifierOnly: "true", classifierRequests: "2", authorityAfterSHA256: "a".repeat(64),
    sourceEvidence: "configmap-mount-declaration", loadedSource: "NOT_ATTESTED", modelRevision: "NOT_ATTESTED",
    servingOutcome: "NOT_MEASURED", injectedResponse: "NOT_RUN", securityEfficacy: "NOT_EVALUATED",
    pgv1Threshold: "0.5", pgv2Threshold: "0.5", pgv1sayOKScore: "0.999", pgv2sayOKScore: "0.03",
    pgv1arithmeticScore: "0.000001", pgv2arithmeticScore: "0.00005", pgv1sayOKFalsePositive: "true",
    pgv2sayOKFalsePositive: "false", calibrationQuality: "fixed-benign-false-positive-observed",
    activeVariant: "pgv2", targetPodUID: "pod-uid", sourceSHA256: "b".repeat(64) });
  assert.match(html, /data-calibration-result="classifier-only"/);
  assert.match(html, /0\.999.*benign false positive/);
  assert.match(html, /Guarded serving: NOT MEASURED/);
  assert.match(html, /security efficacy: NOT EVALUATED/);
  assert.match(html, /loaded process source and model revisions were not attested/);
  assert.match(html, /loaded process and forwarding behavior were not attested/);
  assert.doesNotMatch(html, /DEFENDED|mitigated|HTTP 403/);
});

test("incomplete or legacy evidence cannot render per-variant findings", () => {
  for (const evidence of [{}, { classifierOnly: "true", classifierRequests: "1", servingOutcome: "NOT_MEASURED", injectedResponse: "NOT_RUN", securityEfficacy: "NOT_EVALUATED" }]) {
    const html = render(evidence);
    assert.match(html, /Calibration evidence is incomplete/);
    assert.doesNotMatch(html, /benign false positive|data-calibration-result/);
  }
});
