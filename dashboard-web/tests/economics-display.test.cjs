const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const source = fs.readFileSync(path.join(__dirname, "../lib/economics.ts"), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const subject = { exports: {} };
new Function("module", "exports", compiled)(subject, subject.exports);
const { decisionEconomics, exactNumber, INDEPENDENT_PREFERENCES } = subject.exports;

test("P2 audit metadata keeps zero/full coefficients and never exposes a scalar threshold", () => {
 const e = decisionEconomics({ lambda: 9, economics: {
  version: INDEPENDENT_PREFERENCES, normPreference: { present: true, value: 0 },
  flowPreference: { present: true, value: 0.12345678912345678 },
  lambdaRuntimeLegacy: { present: true, value: 0 }, effectiveCostCoefficient: 9,
 } });
 assert.equal(e.independent, true);
 assert.equal(e.preferences, "βNorm=0 · βFlow=0.12345678912345678");
 assert.equal(e.lambda, 0); assert.equal(e.coefficient, undefined);
 assert.equal(e.formula, "security − βNorm·CNorm − βFlow·CFlow");
});

test("flattened attack metadata preserves explicit zero and unavailable fields", () => {
 const e = decisionEconomics({ economicsAvailable: true, economicsVersion: INDEPENDENT_PREFERENCES,
  normPreference: { present: true, value: 0 }, flowPreference: { present: false, value: 0 },
  lambdaAvailable: false, lambda: 0,
 });
 assert.equal(e.preferences, "βNorm=0 · βFlow=—");
 assert.equal(e.lambda, undefined); assert.equal(exactNumber(e.flow), "—");
});

test("invalidated metadata and missing observations never become configured zeros", () => {
 const e = decisionEconomics({ economicsAvailable: false, economicsVersion: INDEPENDENT_PREFERENCES,
  normPreference: { present: true, value: 0 }, flowPreference: { present: true, value: 1 },
  lambdaAvailable: false, lambda: 0,
 });
 assert.equal(e.version, "not recorded"); assert.equal(e.preferences, "βNorm=— · βFlow=—");
 assert.equal(e.coefficient, undefined); assert.equal(exactNumber(NaN), "—"); assert.equal(exactNumber(Infinity), "—");
});

test("legacy and fixed-common records retain their recorded coefficient including zero", () => {
 for (const version of ["legacy-runtime-lambda-v1", "fixed-disruption-aversion-v1"]) {
  const e = decisionEconomics({ economics: { version, effectiveCostCoefficient: 0,
   lambdaRuntimeLegacy: { present: true, value: 0.6 } } });
  assert.equal(e.independent, false); assert.equal(e.coefficient, 0);
  assert.equal(e.lambda, 0.6); assert.equal(e.version, version);
 }
});
