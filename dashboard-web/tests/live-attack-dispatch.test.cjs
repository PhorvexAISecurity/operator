const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const calls = [];
const response = { message: "accepted", attackId: "exact-1" };
const api = {
  vllmAttack: async (...args) => { calls.push(["vllm", ...args]); return response; },
  voiceMemoryFire: async (...args) => { calls.push(["voice", ...args]); return response; },
  litellmLiveFire: async (...args) => { calls.push(["litellm", ...args]); return response; },
  workloadAttack: async (...args) => { calls.push(["workload", ...args]); return response; },
};
const source = fs.readFileSync(path.join(__dirname, "../lib/live-attack-dispatch.ts"), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)((name) => {
  assert.equal(name, "@/lib/api");
  return { api };
}, subject, subject.exports);
const { liveAttackRoute, dispatchLiveAttack, liveAttackPollBudgetMs, liveAttackVerdict, liveAttackFollowMessage } = subject.exports;

test("only exact advertised endpoint, ID and namespace pairs dispatch", async () => {
  const positives = [
    [{ id: "request-drain", endpoint: "/api/vllm/attack" }, "vllm", "vllm"],
    [{ id: "ai2-agent-memory-contamination", endpoint: "/api/voice/live/fire" }, "voice", "voice"],
    [{ id: "ai2-unbounded-consumption", endpoint: "/api/litellm/live/fire" }, "litellm", "litellm"],
    [{ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "litellm", "litellm"],
    [{ id: "foothold", endpoint: "/api/workload/attack" }, "nats", "foothold"],
  ];
  for (const [entry, namespace, kind] of positives) {
    const route = liveAttackRoute(entry, namespace);
    assert.equal(route.kind, kind);
    assert.equal((await dispatchLiveAttack(route, "operator")).attackId, "exact-1");
  }
  assert.deepEqual(calls.map((call) => call[0]), ["vllm", "voice", "litellm", "litellm", "workload"]);
  assert.deepEqual(calls.at(-1), ["workload", "nats", "foothold", "operator"]);
});

test("unsupported and cross-wired routes refuse without fallback; clear is foothold-only", () => {
  const bad = [
    [{ id: "request-drain", endpoint: "/api/vllm/attack" }, "voice"],
    [{ id: "reset", endpoint: "/api/vllm/attack" }, "vllm"],
    [{ id: "ai2-agent-memory-contamination", endpoint: "/api/workload/attack" }, "voice"],
    [{ id: "foothold", endpoint: "/api/voice/live/fire" }, "voice"],
    [{ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "vllm"],
    [{ id: "unknown", endpoint: "/api/workload/attack" }, "nats"],
    [{ id: "foothold", endpoint: "/unknown" }, "nats"],
  ];
  for (const [entry, namespace] of bad) assert.equal(liveAttackRoute(entry, namespace), null);
  assert.equal(liveAttackRoute({ id: "request-drain", endpoint: "/api/vllm/attack" }, "vllm", true), null);
  assert.equal(liveAttackRoute({ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "litellm", true), null);
  assert.deepEqual(liveAttackRoute({ id: "foothold", endpoint: "/api/workload/attack" }, "voice", true),
    { kind: "foothold", namespace: "voice", action: "clear" });
});

test("typed observation budgets cover 900-second runs and stay finite", () => {
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "litellm")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-agent-memory-contamination", endpoint: "/api/voice/live/fire" }, "voice")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "request-drain", endpoint: "/api/vllm/attack" }, "vllm")), 150_000);
});

test("completed exact NOOP shows reason and blocked candidate without inventing defense", () => {
  const verdict = liveAttackVerdict({ id: "exact-1", status: "done", outcome: "", phorvexAction: "", why: "",
    decisionEvidence: { action: "noop", reason: "no eligible candidate", actionStatus: [
      { action: "request-drain", status: "ineligible", reason: "missing serving selector" },
    ] } });
  assert.equal(verdict.action, "NOOP");
  assert.equal(verdict.reason, "no eligible candidate");
  assert.deepEqual(verdict.blocked, ["request-drain: ineligible — missing serving selector"]);
  assert.equal(liveAttackVerdict({ status: "partial", phorvexAction: "", why: "observer failed" }).action, "UNCONFIRMED");
});

test("cached running record changes from bounded follow-up to explicit timeout, never a final verdict", () => {
  const running = { id: "exact-2", status: "running", observationDeadline: "2026-09-27T09:24:00Z" };
  assert.match(liveAttackFollowMessage("exact-2", true, running), /still running.*observation deadline/);
  assert.match(liveAttackFollowMessage("exact-2", false, running), /last read was running.*no final outcome is inferred/);
  assert.equal(liveAttackFollowMessage("exact-2", false, { ...running, status: "done", decisionEvidence: { action: "noop" } }), "");
});
