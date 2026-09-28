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
const { recordAuditSnapshot, auditTimeMillis, sampleAuditSnapshot } = snapshot;

function fakeClock() {
  let now = 0, next = 0;
  const timers = new Map();
  return {
    set(callback, ms) { const id = ++next; timers.set(id, { at: now + ms, callback }); return id; },
    clear(id) { timers.delete(id); },
    advance(ms) {
      const end = now + ms;
      while (true) {
        const due = [...timers.entries()].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        now = due[1].at;
        timers.delete(due[0]);
        due[1].callback();
      }
      now = end;
    },
    get pending() { return timers.size; },
  };
}

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

test("Discovered waits for delayed remote replay and retains the current UID match", async () => {
  const clock = fakeClock();
  const abort = new AbortController();
  let emit, stopped = 0, resolved = false;
  const sample = sampleAuditSnapshot({ lens: "operator", signal: abort.signal, preserveEpochs: true, clock,
    eligible: (event) => event.kind === "phorvex.decision" && event.decisionTrace?.assetUID === "pod-new",
    subscribe: (onEvent) => { emit = onEvent; return () => { stopped++; }; },
  }).then((rows) => { resolved = true; return rows; });
  clock.advance(2_500);
  await Promise.resolve();
  assert.equal(resolved, false, "the old 2.5s cutoff would commit an empty sample");
  clock.advance(174); // observed first decision arrived at 2.674s, for another Pod
  emit({ kind: "phorvex.decision", ...decision("pod-old", 9, "impact", "2026-09-27T17:49:49Z") });
  clock.advance(179); // exact current-Pod match arrived at 2.853s
  emit({ kind: "phorvex.decision", ...decision("pod-new", 2.5504, "recon", "2026-09-27T17:49:50Z") });
  clock.advance(2_499);
  await Promise.resolve();
  assert.equal(resolved, false, "matching replay receives its own settle window");
  clock.advance(1);
  const rows = await sample;
  assert.equal(rows.length, 2);
  assert.equal(projectDiscoveredPods(graph, rows)[0].asset, 2.5504);
  assert.equal(projectDiscoveredPods(graph, rows)[0].stage, "recon");
  assert.equal(stopped, 1);
  assert.equal(clock.pending, 0);
  emit({ kind: "phorvex.decision", ...decision("pod-new", 7, "impact", "2026-09-27T17:50:00Z") });
  assert.equal(clock.pending, 0, "queued event after closure cannot restart settlement");
});

test("Discovered no-event sample stays bounded; abort and stream errors close owned listeners", async () => {
  for (const mode of ["empty", "abort", "error"]) {
    const clock = fakeClock();
    const controller = new AbortController();
    let emit, fail, stopped = 0;
    const sample = sampleAuditSnapshot({ lens: "operator", signal: controller.signal, preserveEpochs: true, clock,
      eligible: (event) => event.decisionTrace?.assetUID === "pod-new",
      subscribe: (onEvent, onError) => { emit = onEvent; fail = onError; return () => { stopped++; }; },
    });
    if (mode === "empty") {
      clock.advance(14_999);
      assert.equal(clock.pending, 1);
      clock.advance(1);
      assert.deepEqual(await sample, []);
    } else if (mode === "abort") {
      emit({ kind: "phorvex.decision", ...decision("pod-new", 2, "recon", "2026-09-27T17:49:50Z") });
      assert.equal(clock.pending, 2);
      controller.abort();
      await assert.rejects(sample, { name: "AbortError" });
    } else {
      emit({ kind: "phorvex.decision", ...decision("pod-new", 2, "recon", "2026-09-27T17:49:50Z") });
      assert.equal(clock.pending, 2);
      fail(new Error("audit unavailable"));
      await assert.rejects(sample, /audit unavailable/);
    }
    assert.equal(stopped, 1, mode);
    assert.equal(clock.pending, 0, mode);
  }
});

test("late matching replay still stops at the absolute 15s bound", async () => {
  const clock = fakeClock();
  let emit, stopped = 0;
  const sample = sampleAuditSnapshot({ lens: "operator", signal: new AbortController().signal, preserveEpochs: true, clock,
    eligible: (event) => event.decisionTrace?.assetUID === "pod-new",
    subscribe: (onEvent) => { emit = onEvent; return () => { stopped++; }; },
  });
  clock.advance(14_000);
  emit({ kind: "phorvex.decision", ...decision("pod-new", 2, "recon", "2026-09-27T17:49:50Z") });
  assert.equal(clock.pending, 2);
  clock.advance(1_000);
  assert.equal((await sample)[0].assetValue, 2);
  assert.equal(stopped, 1);
  assert.equal(clock.pending, 0);
});

test("shared non-Discovered snapshot keeps its 2.5s bound", async () => {
  const clock = fakeClock();
  let stopped = 0;
  const sample = sampleAuditSnapshot({ lens: "operator", signal: new AbortController().signal, preserveEpochs: false, clock,
    subscribe: () => () => { stopped++; },
  });
  clock.advance(2_500);
  assert.deepEqual(await sample, []);
  assert.equal(stopped, 1);
});

// --- Fleet-wide sampling -----------------------------------------------------
// Discovered must hold one row per scanned Pod. The shared default retains 80, which silently
// drops every workload past that on a larger fleet and renders it as "stage not sampled".

test("retention default keeps the shared 80-row bound", () => {
  const records = new Map();
  for (let i = 0; i < 120; i++) {
    recordAuditSnapshot(records, {
      kind: "phorvex.decision", namespace: "ns", pod: `pod-${i}`,
      decisionTrace: { assetUID: `uid-${i}` }, time: "2026-09-28T10:00:00Z",
    }, "operator", true);
  }
  assert.equal(records.size, 80);
  assert.equal(snapshot.DEFAULT_SNAPSHOT_LIMIT, 80);
});

test("a caller can retain one row per Pod on a fleet larger than the default", () => {
  const records = new Map();
  for (let i = 0; i < 120; i++) {
    recordAuditSnapshot(records, {
      kind: "phorvex.decision", namespace: "ns", pod: `pod-${i}`,
      decisionTrace: { assetUID: `uid-${i}` }, time: "2026-09-28T10:00:00Z",
    }, "operator", true, 120);
  }
  assert.equal(records.size, 120);
  // every scanned Pod is still addressable, so none projects as "stage not sampled"
  assert.ok(records.has(JSON.stringify(["ns", "pod-0", "uid-0"])));
  assert.ok(records.has(JSON.stringify(["ns", "pod-119", "uid-119"])));
});

test("sampleAuditSnapshot honours the caller's retention limit", async () => {
  const clock = fakeClock();
  const controller = new AbortController();
  const events = Array.from({ length: 150 }, (_, i) => ({
    kind: "phorvex.decision", namespace: "ns", pod: `pod-${i}`,
    decisionTrace: { assetUID: `uid-${i}` }, time: "2026-09-28T10:00:00Z",
  }));
  const pending = sampleAuditSnapshot({
    lens: "operator", signal: controller.signal, preserveEpochs: true, limit: 150, clock,
    subscribe: (onEvent) => { events.forEach(onEvent); return () => {}; },
  });
  clock.advance(15_000);
  const rows = await pending;
  assert.equal(rows.length, 150, "a busy tenant must not evict the quiet ones");
});

test("a quiet workload survives a replay dominated by a busy tenant", async () => {
  const clock = fakeClock();
  const controller = new AbortController();
  // 200 decisions from one hot policy, then a single decision for the quiet Pod.
  const events = Array.from({ length: 200 }, (_, i) => ({
    kind: "phorvex.decision", namespace: "litellm", pod: `litellm-${i}`,
    decisionTrace: { assetUID: `hot-${i}` }, time: "2026-09-28T10:00:00Z",
  }));
  events.push({
    kind: "phorvex.decision", namespace: "voice", pod: "voice-bot-1",
    decisionTrace: { assetUID: "quiet-1" }, stage: "recon", assetValue: 0.42,
    time: "2026-09-28T10:00:01Z",
  });
  const pending = sampleAuditSnapshot({
    lens: "operator", signal: controller.signal, preserveEpochs: true, limit: 250, clock,
    subscribe: (onEvent) => { events.forEach(onEvent); return () => {}; },
  });
  clock.advance(15_000);
  const rows = await pending;
  const quiet = rows.find((r) => r.pod === "voice-bot-1");
  assert.ok(quiet, "the quiet workload must be retained");
  // and it must project with a real stage and asset, not as "stage not sampled"
  const projected = projectDiscoveredPods(
    [{ key: "voice/voice-bot-1", uid: "quiet-1", blast: 0.5, ai: false }], rows);
  assert.equal(projected[0].stage, "recon");
  assert.equal(projected[0].asset, 0.42);
  assert.equal(stageGroup(projected[0].stage), "recon");
});
