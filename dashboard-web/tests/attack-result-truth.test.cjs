const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "lib/attack-result-truth.ts"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const moduleUnderTest = { exports: {} };
new Function("require", "module", "exports", compiled)(require, moduleUnderTest, moduleUnderTest.exports);
const { catalogueSignalState, isCatalogueSignalResult, isUnversionedResult, showSecurityOutcomeSections } = moduleUnderTest.exports;

const base = {
  id: "atk-signal-1",
  status: "done",
  outcome: "",
  outcomeClass: "response-only",
  evidenceKind: "catalogue-signal",
  producerRoute: "/api/workload/fire-scenario",
  resultSchemaVersion: "catalogue-signal-v1",
  responseObserved: true,
  responseAction: "rotate",
  responsePod: "vllm-new",
  responseSeconds: 4.5,
  stimulusEvidence: {
    behavioralExecuted: false,
    limitation: "Synthetic signal only; behavioral outcome not measured.",
  },
};

test("catalogue signal remains unscored despite a contradictory legacy outcome", () => {
  const row = { ...base, outcome: "DEFENDED", containment: "contained", perDollar: 99 };
  assert.equal(isCatalogueSignalResult(row), true);
  assert.equal(showSecurityOutcomeSections(row), false);
  assert.equal(catalogueSignalState(row).label, "SIGNAL ACCEPTED");
  assert.equal(catalogueSignalState(row).response, "RESPONSE OBSERVED");
});

test("unconfirmed and unavailable observations remain distinct", () => {
  const unconfirmed = {
    ...base,
    status: "partial",
    responseObserved: false,
    responseAction: "",
    responsePod: "",
    responseSeconds: 0,
    outcomeClass: "response-unconfirmed",
    observationError: "no exact target response observed within registered window",
  };
  assert.equal(catalogueSignalState(unconfirmed).response, "RESPONSE UNCONFIRMED");
  assert.equal(catalogueSignalState(unconfirmed).responseDetail, "no exact target response observed within registered window");
  const unavailable = { ...unconfirmed, status: "partial", outcomeClass: "observation-unavailable", observationError: "pod watch failed" };
  assert.equal(catalogueSignalState(unavailable).label, "SIGNAL RECORD PARTIAL");
  assert.equal(catalogueSignalState(unavailable).response, "OBSERVATION UNAVAILABLE");
  assert.equal(catalogueSignalState(unavailable).responseDetail, "pod watch failed");
  const responseWithDecisionError = { ...base, status: "partial", observationError: "decision correlation unavailable" };
  assert.equal(catalogueSignalState(responseWithDecisionError).response, "RESPONSE OBSERVED");
  assert.equal(catalogueSignalState(responseWithDecisionError).label, "SIGNAL RECORD PARTIAL");
});

test("a generic behavioral observation failure is not reclassified as a synthetic signal", () => {
  const behavioral = { id: "atk-behavioral", status: "partial", outcome: "", outcomeClass: "observation-unavailable", observationError: "watch failed" };
  assert.equal(isCatalogueSignalResult(behavioral), false);
  assert.equal(showSecurityOutcomeSections(behavioral), true);
});

test("unversioned historical rows retain a separate provenance classification", () => {
  const legacy = { id: "atk-old", status: "done", outcome: "LANDED" };
  assert.equal(isCatalogueSignalResult(legacy), false);
  assert.equal(isUnversionedResult(legacy), true);
  assert.equal(showSecurityOutcomeSections(legacy), true);
});
