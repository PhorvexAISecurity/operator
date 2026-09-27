const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.join(__dirname, "../lib/discovered-projection.ts"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const moduleObject = { exports: {} };
new Function("module", "exports", compiled)(moduleObject, moduleObject.exports);
const { projectDiscoveredPods, stageGroup } = moduleObject.exports;

const graph = [{ key: "vllm/current", uid: "pod-new", blast: 0.949, ai: true }];
const decision = (assetUID, assetValue, stage, time) => ({
  namespace: "vllm", pod: "current", decisionTrace: { assetUID }, assetValue,
  blastRadius: 0.6, stage, time,
});

test("a replaced Pod does not inherit the prior epoch's jewel value or stage", () => {
  const rows = projectDiscoveredPods(graph, [decision("pod-old", 8.2, "impact", "2026-09-27T16:30:00Z")]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].asset, null);
  assert.equal(rows[0].stage, null);
  assert.equal(rows[0].blast, 0.949);
  assert.equal(rows[0].source, "scan");
});

test("the newest exact UID decision supplies asset and stage; zero is a real value", () => {
  const rows = projectDiscoveredPods(graph, [
    decision("pod-new", 2.5494, "prompt-inject-persist", "2026-09-27T16:32:00Z"),
    decision("pod-new", 0, "recon", "2026-09-27T16:34:00Z"),
    decision("pod-old", 9, "impact", "2026-09-27T16:35:00Z"),
  ]);
  assert.equal(rows[0].asset, 0);
  assert.equal(rows[0].stage, "recon");
  assert.equal(rows[0].evidenceTime, "2026-09-27T16:34:00Z");
  assert.equal(rows[0].blast, 0.949);
});

test("legacy scan without UID and audit-only rows remain explicitly unverified", () => {
  const legacy = projectDiscoveredPods([{ key: "vllm/current", blast: 0.5, ai: false }], [decision("pod-new", 2, "model-theft", "2026-09-27T16:32:00Z")]);
  assert.equal(legacy[0].asset, null);
  assert.equal(legacy[0].stage, null);
  const auditOnly = projectDiscoveredPods([], [decision("pod-new", 2, "model-theft", "2026-09-27T16:32:00Z")]);
  assert.equal(auditOnly[0].source, "decision");
  assert.equal(auditOnly[0].asset, 2);
  assert.equal(auditOnly[0].evidenceTime, "2026-09-27T16:32:00Z");
});

test("missing and AI stages do not count as reconnaissance", () => {
  assert.equal(stageGroup(null), "unknown");
  assert.equal(stageGroup("prompt-inject-persist"), "ai");
  assert.equal(stageGroup("gpu-side-channel"), "ai");
  assert.equal(stageGroup("future-stage"), "other");
  assert.equal(stageGroup("recon"), "recon");
});
