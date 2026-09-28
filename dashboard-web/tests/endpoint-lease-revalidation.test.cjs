const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const crypto = require("node:crypto");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
function load(file, aliases = {}) {
  const code = ts.transpileModule(fs.readFileSync(path.join(__dirname, "..", file), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", code)((name) => aliases[name] || require(name), module, module.exports);
  return module.exports;
}
const truth = load("lib/attack-result-truth.ts");
const { EndpointLeaseProbe } = load("components/panels/endpoint-lease-probe.tsx", { "@/lib/attack-result-truth": truth });
const dispatch = load("lib/live-attack-dispatch.ts", { "@/lib/api": { api: {} }, "@/lib/attack-result-truth": truth });
function fixture() {
  return {
    status: "done", outcome: "PROTECTION_REVALIDATED", actuated: false, phorvexAction: "", timeToDefendSec: 0,
    dwellSec: 0, dwellOngoing: false, containment: "", defendedPod: "", why: "",
    evidenceKind: "vllm-endpoint-lease-live", producerRoute: "/api/vllm/attack", resultSchemaVersion: "vllm-endpoint-lease-live-v1",
    outcomeClass: "endpoint-lease-PROTECTION_REVALIDATED",
    endpointLeaseProbe: {
      schema: "vllm-endpoint-lease-live-v1", scenarioId: "ai2-endpoint-security", status: "PROTECTION_REVALIDATED",
      signalMode: "EXISTING_PROTECTION_REVALIDATION", protectionRevalidated: true, firstAccepted: false, cleanup: "NOT_NEEDED",
      protectedJournalTerminal: true, everyServingPodEffective: true, postAStatus: 401, postAExactDenial: true,
      postBStatus: 200, postBValidCompletion: true, postAResponseSHA256: "a".repeat(64), postBResponseSHA256: "b".repeat(64),
      historicalJournalSHA256: "c".repeat(64), currentStateSHA256: "d".repeat(64), currentRevision: 2,
      historicalOperationId: "e".repeat(64), historicalEventName: "original-event",
      historicalEventUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", historicalTickId: "original-tick", issues: [],
    },
  };
}
function render(record) {
  return renderToStaticMarkup(React.createElement(EndpointLeaseProbe, { result: record.endpointLeaseProbe, attackResult: record }));
}
test("complete revalidation renders separately without new defense or latency credit", () => {
  const r = fixture();
  assert.equal(truth.isEndpointProtectionRevalidated(r), true);
  assert.match(render(r), /Existing protection verified/);
  assert.match(render(r), /Original operation/);
  assert.match(render(r), /No new security event, brain selection, actuation, or response-time credit/);
  assert.equal(dispatch.liveAttackVerdict(r).action, "existing protection");
  assert.equal(dispatch.liveAttackVerdict(r).revalidated, true);
  assert.equal(truth.showSecurityOutcomeSections(r), false);
  assert.equal(truth.hasAvailabilityCostEvidence(r), false);
  assert.equal(truth.attackCSVActuator(r), "");
  const report = fs.readFileSync(path.join(__dirname, "../components/panels/attack-report.tsx"), "utf8");
  const countExpression = report.match(/const defended = (typedBehavioralRows\.filter\([^\n]+\)\.length);/);
  assert.ok(countExpression, "typed defense count changed; review accounting");
  assert.equal(new Function("typedBehavioralRows", `return ${countExpression[1]}`)([r]), 0);
});
test("exact release-400 API row with legacy null issues renders existing protection without new credit", () => {
  const raw = fs.readFileSync(path.join(__dirname, "fixtures/endpoint-revalidation-release400-api.json"));
  assert.equal(crypto.createHash("sha256").update(raw).digest("hex"), "0ded2f90b9f171b82031d4e51a0524cc71e6eb0c174eef87dcda39ebd6dde7d1");
  const rows = JSON.parse(raw).attacks;
  assert.equal(rows.length, 1);
  const r = rows[0];
  assert.equal(r.id, "endpoint-lease-6982f1adacd1862a67f61aef2eb3ef29");
  assert.equal(r.endpointLeaseProbe.issues, null);
  assert.equal(truth.isEndpointProtectionRevalidated(r), true);
  assert.match(render(r), /data-endpoint-lease="revalidated"/);
  assert.match(render(r), /Existing protection verified/);
  assert.match(render(r), /No new security event, brain selection, actuation, or response-time credit/);
  assert.equal(dispatch.liveAttackVerdict(r).action, "existing protection");
  assert.equal(truth.showSecurityOutcomeSections(r), false);
  assert.equal(truth.hasAvailabilityCostEvidence(r), false);
  assert.equal(truth.attackCSVActuator(r), "");
  assert.equal(r.actuated, false);
  assert.equal(r.timeToDefendSec, 0);
  for (const [name, mutate] of [
    ["missing issues", r => { delete r.endpointLeaseProbe.issues; }],
    ["nonempty issues", r => { r.endpointLeaseProbe.issues = ["unverified"]; }],
    ["string issues", r => { r.endpointLeaseProbe.issues = "[]"; }],
    ["object issues", r => { r.endpointLeaseProbe.issues = { length: 0 }; }],
    ["boolean issues", r => { r.endpointLeaseProbe.issues = false; }],
    ["numeric issues", r => { r.endpointLeaseProbe.issues = 0; }],
    ["missing proxy proof with null issues", r => { delete r.endpointLeaseProbe.everyServingPodEffective; }],
    ["untyped journal proof with null issues", r => { r.endpointLeaseProbe.protectedJournalTerminal = "true"; }],
    ["untyped A denial with null issues", r => { r.endpointLeaseProbe.postAExactDenial = "true"; }],
    ["B incomplete with null issues", r => { r.endpointLeaseProbe.postBValidCompletion = false; }],
    ["missing historical SHA with null issues", r => { delete r.endpointLeaseProbe.historicalJournalSHA256; }],
    ["actuation with null issues", r => { r.actuated = true; }],
  ]) {
    const bad = structuredClone(r); mutate(bad);
    assert.equal(truth.isEndpointProtectionRevalidated(bad), false, name);
    assert.equal(dispatch.liveAttackVerdict(bad).revalidated, false, name);
    assert.match(render(bad), /data-endpoint-lease="incomplete"/, name);
    assert.doesNotMatch(render(bad), /Existing protection verified/, name);
  }
});
test("incomplete or cross-wired outer results cannot label a valid nested probe as verified", () => {
  for (const [name, mutate] of [
    ["route", r => { r.producerRoute = "/api/workload/fire-scenario"; }],
    ["evidence kind", r => { r.evidenceKind = "catalogue-signal"; }],
    ["schema", r => { r.resultSchemaVersion = "different"; }],
    ["partial persistence", r => { r.status = "partial"; r.outcome = ""; }],
    ["cleanup", r => { r.endpointLeaseProbe.cleanup = "UNCONFIRMED"; }],
    ["actuation", r => { r.actuated = true; }],
    ["action", r => { r.phorvexAction = "endpoint-lease-revoke"; }],
    ["latency", r => { r.timeToDefendSec = 1; }],
    ["response latency", r => { r.responseSeconds = 1; }],
    ["dwell", r => { r.dwellSec = 1; }],
    ["current decision", r => { r.decisionEvidence = { action: "endpoint-lease-revoke" }; }],
    ["current event", r => { r.endpointLeaseProbe.eventUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; }],
    ["current event name", r => { r.endpointLeaseProbe.eventName = "fresh-event"; }],
    ["current tick", r => { r.endpointLeaseProbe.selectedTickId = "fresh-tick"; }],
    ["initial loss", r => { r.endpointLeaseProbe.firstAccepted = true; }],
    ["A denial", r => { r.endpointLeaseProbe.postAStatus = 200; }],
    ["B completion", r => { r.endpointLeaseProbe.postBValidCompletion = false; }],
    ["proxy proof", r => { r.endpointLeaseProbe.everyServingPodEffective = undefined; }],
    ["journal truthiness", r => { r.endpointLeaseProbe.protectedJournalTerminal = "true"; }],
    ["A truthiness", r => { r.endpointLeaseProbe.postAExactDenial = "true"; }],
    ["B truthiness", r => { r.endpointLeaseProbe.postBValidCompletion = 1; }],
    ["history", r => { r.endpointLeaseProbe.historicalJournalSHA256 = ""; }],
    ["historic event", r => { r.endpointLeaseProbe.historicalEventUID = "-".repeat(36); }],
    ["issues", r => { r.endpointLeaseProbe.issues = ["unverified"]; }],
  ]) {
    const r = fixture(); mutate(r);
    assert.equal(truth.isEndpointProtectionRevalidated(r), false, name);
    assert.equal(dispatch.liveAttackVerdict(r).revalidated, false, name);
    assert.match(render(r), /data-endpoint-lease="incomplete"/, name);
    assert.doesNotMatch(render(r), /Existing protection verified/, name);
  }
  const r = fixture();
  const nestedOnly = renderToStaticMarkup(React.createElement(EndpointLeaseProbe, { result: r.endpointLeaseProbe }));
  assert.match(nestedOnly, /data-endpoint-lease="incomplete"/);
});
test("original first-loss and selected revoke evidence still renders defended", () => {
  const r = fixture();
  Object.assign(r.endpointLeaseProbe, { status: "DEFENDED", firstAccepted: true, initialAStatus: 200, initialBStatus: 200,
    signalMode: "TEST_INJECTED_AFTER_A_AND_B_200", eventUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    selectedAction: "endpoint-lease-revoke", selectedDecisionId: "fresh-decision", selectedTickId: "fresh-tick" });
  assert.match(render(r), /data-endpoint-lease="defended"/);
  assert.match(render(r), /The first accepted request remains a loss/);
  assert.doesNotMatch(render(r), /Existing protection verified/);
});

test("actual revoked A completion reports failed current protection without new first-loss credit", () => {
  const r = fixture();
  r.outcome = "LANDED";
  Object.assign(r.endpointLeaseProbe, { status: "LANDED", protectionRevalidated: false, postAStatus: 200,
    postAExactDenial: false, firstAccepted: false, issues: ["revoked A reached the real completion endpoint"] });
  assert.match(render(r), /The revoked credential A reached the real model during this rerun/);
  assert.match(render(r), /Current protection failed/);
  assert.doesNotMatch(render(r), /No new accepted A request was proven|Existing protection verified/);
  assert.equal(dispatch.liveAttackVerdict(r).revalidated, false);
  r.outcome = ""; r.endpointLeaseProbe.status = "UNKNOWN"; r.endpointLeaseProbe.postAStatus = undefined;
  assert.match(render(r), /Existing protection verification is incomplete/);
  assert.doesNotMatch(render(r), /Current protection failed|Existing protection verified/);
});
