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
const { attackCSVActuator, catalogueSignalState, exactCatalogueDecision, canSendCatalogueSignal, isCatalogueSignalResult, isUnversionedResult, showSecurityOutcomeSections } = moduleUnderTest.exports;
const { attackCSVRow } = moduleUnderTest.exports;

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
  assert.equal(catalogueSignalState(row).response, "TARGET UID CHANGED");
  assert.match(catalogueSignalState(row).responseDetail, /cause not established/);
  assert.equal(attackCSVActuator({ ...row, phorvexAction: "rotate", responseAction: "rotate", decisionEvidence: { correlation: "exact-event-uid", selected: true, action: "rotate" } }), "");
});

test("vLLM effect and unsupported observations export no invented availability or cost", () => {
  for (const evidenceKind of ["vllm-in-place-effect", "vllm-unsupported-stimulus"]) {
    const row = attackCSVRow({ ...base, evidenceKind, producerRoute: "/api/vllm/attack", resultSchemaVersion: "vllm-effect-v1", uptimeBefore: 0, uptimeDip: 0, uptimeAfter: 0,
      cost: { without: 0, r6: 0, with: 0, savings: 0 } });
    assert.deepEqual(row.slice(10, 17), Array(7).fill(""));
  }
});

test("synthetic detector signal v2 remains unscored despite contradictory outcome labels", () => {
  const row = {
    ...base,
    evidenceKind: "synthetic-detector-signal",
    resultSchemaVersion: "synthetic-detector-signal-v2",
    producerRoute: "/api/workload/attack",
    outcome: "LANDED",
    containment: "landed",
    perDollar: 88,
  };
  assert.equal(isCatalogueSignalResult(row), true);
  assert.equal(showSecurityOutcomeSections(row), false);
  assert.equal(catalogueSignalState(row).response, "TARGET UID CHANGED");

  const schemaOnly = { ...row, evidenceKind: "", outcome: "DEFENDED" };
  assert.equal(isCatalogueSignalResult(schemaOnly), true);
  assert.equal(showSecurityOutcomeSections(schemaOnly), false);
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
  assert.equal(catalogueSignalState(unconfirmed).response, "TARGET CHANGE UNCONFIRMED");
  assert.equal(catalogueSignalState(unconfirmed).responseDetail, "no exact target response observed within registered window");
  const unavailable = { ...unconfirmed, status: "partial", outcomeClass: "observation-unavailable", observationError: "pod watch failed" };
  assert.equal(catalogueSignalState(unavailable).label, "SIGNAL RECORD PARTIAL");
  assert.equal(catalogueSignalState(unavailable).response, "OBSERVATION UNAVAILABLE");
  assert.equal(catalogueSignalState(unavailable).responseDetail, "pod watch failed");
  const responseWithDecisionError = { ...base, status: "partial", observationError: "decision correlation unavailable" };
  assert.equal(catalogueSignalState(responseWithDecisionError).response, "TARGET UID CHANGED");
  assert.equal(catalogueSignalState(responseWithDecisionError).label, "SIGNAL RECORD PARTIAL");
});

test("compatibility and explicit signal eligibility are independent", () => {
  assert.equal(canSendCatalogueSignal({ compatible: true, signalEligible: true }, true), true);
  for (const row of [{ compatible: true }, { compatible: true, signalEligible: false }, { compatible: false, signalEligible: true }]) {
    assert.equal(canSendCatalogueSignal(row, true), false);
  }
  assert.equal(canSendCatalogueSignal({ compatible: true, signalEligible: true }, false), false);
});

test("selected action requires the injected event UID, name, rule and target join", () => {
  const stimulusEvidence = { observed: true, eventUid: "event-1", eventName: "signal-1", eventRule: "PromptInjection", targetUid: "pod-1" };
  const joined = { correlation: "exact-event-uid", eventUid: "event-1", eventName: "signal-1", eventRule: "PromptInjection", targetUid: "pod-1", selected: true, action: "quarantine" };
  assert.equal(exactCatalogueDecision({ ...base, stimulusEvidence, decisionTraceEvidence: [joined] })?.action, "quarantine");
  for (const field of ["eventUid", "eventName", "eventRule", "targetUid", "correlation"]) {
    assert.equal(exactCatalogueDecision({ ...base, stimulusEvidence, decisionTraceEvidence: [{ ...joined, [field]: "foreign" }] }), undefined, field);
  }
  assert.equal(exactCatalogueDecision({ ...base, stimulusEvidence, decisionTraceEvidence: [], responseAction: "rotate" }), undefined);
});

test("a generic behavioral observation failure is not reclassified as a synthetic signal", () => {
  const behavioral = { id: "atk-behavioral", status: "partial", outcome: "", outcomeClass: "observation-unavailable", observationError: "watch failed" };
  assert.equal(isCatalogueSignalResult(behavioral), false);
  assert.equal(showSecurityOutcomeSections(behavioral), true);
  assert.equal(attackCSVActuator({ ...behavioral, phorvexAction: "quarantine" }), "quarantine");
});

test("unversioned historical rows retain a separate provenance classification", () => {
  const legacy = { id: "atk-old", status: "done", outcome: "LANDED" };
  assert.equal(isCatalogueSignalResult(legacy), false);
  assert.equal(isUnversionedResult(legacy), true);
  assert.equal(showSecurityOutcomeSections(legacy), true);
});

test("scoped Live CSV leaves unmeasured dwell, availability and economics blank", () => {
  for (const evidenceKind of ["voice-memory-live", "litellm-live-client-policy"]) {
    const r = { evidenceKind, status: "done", outcome: "DEFENDED", actuated: true, phorvexAction: "native-action",
      containment: "exact-scope", dwellOngoing: false, dwellSec: 0, timeToDefendSec: 0,
      uptimeBefore: 0, uptimeDip: 0, uptimeAfter: 0, cost: { without: 0, r6: 0, with: 0, savings: 0 } };
    const cells = attackCSVRow(r);
    assert.equal(cells.length, 18);
    assert.equal(cells[4], "DEFENDED");
    assert.equal(cells[5], "native-action");
    assert.deepEqual(cells.slice(7, 17), Array(10).fill(""));
    assert.match(cells[17], /not measured/);
    assert.equal(attackCSVRow({ ...r, actuated: false })[5], "");
  }
  assert.equal(attackCSVRow(base).length, 18);
});
