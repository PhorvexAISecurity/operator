const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

function load(relative, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, relative), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const moduleObject = { exports: {} };
  new Function("require", "module", "exports", compiled)((name) => dependencies[name] ?? require(name), moduleObject, moduleObject.exports);
  return moduleObject.exports;
}
const snapshot = load("../lib/audit-snapshot.ts");
const { projectDiscoveredPods, stageGroup } = load("../lib/discovered-projection.ts", { "@/lib/audit-snapshot": snapshot });
const { recordAuditSnapshot, auditTimeMillis } = snapshot;

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

test("bounded stream keeps an exact UID decision despite later same-name evidence from another epoch", () => {
  const records = new Map();
  recordAuditSnapshot(records, { kind: "phorvex.event", ...decision("pod-new", 99, "impact", "2026-09-27T16:29:00Z") }, "operator", true);
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 2.5494, "recon", "2026-09-27T16:30:00Z") }, "operator", true);
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-old", 8.2, "impact", "2026-09-27T16:31:00Z") }, "operator", true);
  assert.equal(records.size, 2);
  const [row] = projectDiscoveredPods(graph, Array.from(records.values()));
  assert.equal(row.asset, 2.5494);
  assert.equal(row.stage, "recon");
  assert.equal(row.evidenceTime, "2026-09-27T16:30:00Z");
});

test("stream sample stays bounded and an older replay cannot replace the latest same-UID decision", () => {
  const records = new Map();
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 2.5, "recon", "2026-09-27T16:32:00Z") }, "operator", true);
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 1.1, "impact", "2026-09-27T16:30:00Z") }, "operator", true);
  assert.equal(Array.from(records.values())[0].assetValue, 2.5);
  for (let i = 0; i < 81; i++) {
    recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision(`pod-${i}`, i, "recon", `2026-09-27T16:33:${String(i % 60).padStart(2, "0")}Z`) }, "operator", true);
  }
  assert.equal(records.size, 80);
});

test("default shared snapshot retains one row per workload name", () => {
  const records = new Map();
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 2.5, "recon", "2026-09-27T16:30:00Z") }, "operator");
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-old", 8.2, "impact", "2026-09-27T16:31:00Z") }, "operator");
  assert.equal(records.size, 1);
  assert.equal(Array.from(records.values())[0].assetValue, 8.2);
});

test("fractional RFC3339Nano time outranks a later-arriving whole-second row in both paths", () => {
  const fraction = "2026-09-27T12:00:00.1Z";
  const whole = "2026-09-27T12:00:00Z";
  assert.ok(auditTimeMillis(fraction) > auditTimeMillis(whole));
  const records = new Map();
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 2.5, "exploit", fraction) }, "operator", true);
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 1.1, "recon", whole) }, "operator", true);
  assert.equal(Array.from(records.values())[0].assetValue, 2.5);
  const [projected] = projectDiscoveredPods(graph, [decision("pod-new", 2.5, "exploit", fraction), decision("pod-new", 1.1, "recon", whole)]);
  assert.equal(projected.asset, 2.5);
  assert.equal(projected.stage, "exploit");
});

test("invalid or missing time cannot displace a valid decision", () => {
  assert.equal(auditTimeMillis("not-a-time"), null);
  assert.equal(auditTimeMillis(undefined), null);
  const records = new Map();
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 2.5, "exploit", "2026-09-27T12:00:00Z") }, "operator", true);
  recordAuditSnapshot(records, { kind: "phorvex.decision", ...decision("pod-new", 0, "recon", "not-a-time") }, "operator", true);
  assert.equal(Array.from(records.values())[0].assetValue, 2.5);
  const [projected] = projectDiscoveredPods(graph, [decision("pod-new", 2.5, "exploit", "2026-09-27T12:00:00Z"), decision("pod-new", 0, "recon", "not-a-time")]);
  assert.equal(projected.asset, 2.5);
});
