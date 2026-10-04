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
  voiceAgencyFire: async (...args) => { calls.push(["voice-agency", ...args]); return response; },
  voiceOutputFire: async (...args) => { calls.push(["voice-output", ...args]); return response; },
  voiceAdmissionFire: async (...args) => { calls.push(["voice-admission", ...args]); return response; },
  voiceMCPFire: async (...args) => { calls.push(["voice-mcp", ...args]); return response; },
  litellmLiveFire: async (...args) => { calls.push(["litellm", ...args]); return response; },
  litellmOutputFire: async (...args) => { calls.push(["litellm-output", ...args]); return response; },
  crmRefundFire: async (...args) => { calls.push(["crm", ...args]); return response; },
  workloadAttack: async (...args) => { calls.push(["workload", ...args]); return response; },
};
const source = fs.readFileSync(path.join(__dirname, "../lib/live-attack-dispatch.ts"), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const subject = { exports: {} };
const truth = { exports: {} };
const truthCompiled = ts.transpileModule(fs.readFileSync(path.join(__dirname, "../lib/attack-result-truth.ts"), "utf8"),
  { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
new Function("module", "exports", truthCompiled)(truth, truth.exports);
new Function("require", "module", "exports", compiled)((name) => {
  if (name === "@/lib/attack-result-truth") return truth.exports;
  assert.equal(name, "@/lib/api");
  return { api };
}, subject, subject.exports);
const { liveAttackRoute, dispatchLiveAttack, liveAttackPollBudgetMs, liveAttackVerdict, liveAttackFollowMessage } = subject.exports;

test("only exact advertised endpoint, ID and namespace pairs dispatch", async () => {
  const positives = [
    [{ id: "request-drain", endpoint: "/api/vllm/attack" }, "vllm", "vllm"],
    [{ id: "endpoint-lease-revoke", endpoint: "/api/vllm/attack" }, "vllm", "vllm"],
    [{ id: "ai2-agent-memory-contamination", endpoint: "/api/voice/live/fire" }, "voice", "voice"],
    [{ id: "ai2-agent-excessive-agency", endpoint: "/api/voice/agency/live/fire" }, "voice", "voice-agency"],
    [{ id: "ai2-system-prompt-leakage", endpoint: "/api/voice/output/live/fire" }, "voice", "voice-output"],
    [{ id: "ai2-mcp-tool-poisoning", endpoint: "/api/voice/mcp/live/fire" }, "voice", "voice-mcp"],
    [{ id: "voice-unauthenticated-media-admission", endpoint: "/api/voice/admission/live/fire" }, "voice", "voice-admission"],
    [{ id: "ai2-unbounded-consumption", endpoint: "/api/litellm/live/fire" }, "litellm", "litellm"],
    [{ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "litellm", "litellm"],
    [{ id: "ai2-sensitive-info-disclosure", endpoint: "/api/litellm/output/fire" }, "litellm", "litellm-output"],
    [{ id: "ai2-system-prompt-leakage", endpoint: "/api/litellm/output/fire" }, "litellm", "litellm-output"],
    [{ id: "ai2-cross-record-refund", endpoint: "/api/crm/live/fire" }, "crm", "crm"],
    [{ id: "foothold", endpoint: "/api/workload/attack" }, "nats", "foothold"],
  ];
  for (const [entry, namespace, kind] of positives) {
    const route = liveAttackRoute(entry, namespace);
    assert.equal(route.kind, kind);
    assert.equal((await dispatchLiveAttack(route, "operator")).attackId, "exact-1");
  }
  assert.deepEqual(calls.map((call) => call[0]), ["vllm", "vllm", "voice", "voice-agency", "voice-output", "voice-mcp", "voice-admission", "litellm", "litellm", "litellm-output", "litellm-output", "crm", "workload"]);
  assert.deepEqual(calls.at(-1), ["workload", "nats", "foothold", "operator"]);
});

test("unsupported and cross-wired routes refuse without fallback; clear is foothold-only", () => {
  const bad = [
    [{ id: "request-drain", endpoint: "/api/vllm/attack" }, "voice"],
    [{ id: "endpoint-lease-revoke", endpoint: "/api/vllm/attack" }, "voice"],
    [{ id: "reset", endpoint: "/api/vllm/attack" }, "vllm"],
    [{ id: "ai2-agent-memory-contamination", endpoint: "/api/workload/attack" }, "voice"],
    [{ id: "ai2-agent-excessive-agency", endpoint: "/api/voice/live/fire" }, "voice"],
    [{ id: "ai2-agent-memory-contamination", endpoint: "/api/voice/agency/live/fire" }, "voice"],
    [{ id: "ai2-agent-excessive-agency", endpoint: "/api/voice/agency/live/fire" }, "vllm"],
    [{ id: "ai2-system-prompt-leakage", endpoint: "/api/voice/agency/live/fire" }, "voice"],
    [{ id: "ai2-agent-excessive-agency", endpoint: "/api/voice/output/live/fire" }, "voice"],
    [{ id: "ai2-system-prompt-leakage", endpoint: "/api/voice/output/live/fire" }, "vllm"],
    [{ id: "ai2-mcp-tool-poisoning", endpoint: "/api/voice/live/fire" }, "voice"],
    [{ id: "ai2-mcp-tool-poisoning", endpoint: "/api/voice/mcp/live/fire" }, "vllm"],
    [{ id: "voice-unauthenticated-media-admission", endpoint: "/api/voice/admission/live/fire" }, "vllm"],
    [{ id: "voice-unauthenticated-media-admission", endpoint: "/api/voice/live/fire" }, "voice"],
    [{ id: "foothold", endpoint: "/api/voice/live/fire" }, "voice"],
    [{ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "vllm"],
    [{ id: "ai2-sensitive-info-disclosure", endpoint: "/api/litellm/live/fire" }, "litellm"],
    [{ id: "ai2-sensitive-info-disclosure", endpoint: "/api/litellm/output/fire" }, "voice"],
    [{ id: "ai2-unbounded-consumption", endpoint: "/api/litellm/output/fire" }, "litellm"],
    [{ id: "unknown", endpoint: "/api/workload/attack" }, "nats"],
    [{ id: "foothold", endpoint: "/unknown" }, "nats"],
  ];
  for (const [entry, namespace] of bad) assert.equal(liveAttackRoute(entry, namespace), null);
  assert.equal(liveAttackRoute({ id: "request-drain", endpoint: "/api/vllm/attack" }, "vllm", true), null);
  assert.equal(liveAttackRoute({ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "litellm", true), null);
  assert.equal(liveAttackRoute({ id: "ai2-system-prompt-leakage", endpoint: "/api/litellm/output/fire" }, "litellm", true), null);
  assert.equal(liveAttackRoute({ id: "ai2-mcp-tool-poisoning", endpoint: "/api/voice/mcp/live/fire" }, "voice", true), null);
  assert.deepEqual(liveAttackRoute({ id: "foothold", endpoint: "/api/workload/attack" }, "voice", true),
    { kind: "foothold", namespace: "voice", action: "clear" });
});

test("typed observation budgets cover server windows and stay finite", () => {
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-query-extraction", endpoint: "/api/litellm/live/fire" }, "litellm")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-agent-memory-contamination", endpoint: "/api/voice/live/fire" }, "voice")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-agent-excessive-agency", endpoint: "/api/voice/agency/live/fire" }, "voice")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-sensitive-info-disclosure", endpoint: "/api/litellm/output/fire" }, "litellm")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-system-prompt-leakage", endpoint: "/api/voice/output/live/fire" }, "voice")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "ai2-mcp-tool-poisoning", endpoint: "/api/voice/mcp/live/fire" }, "voice")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "request-drain", endpoint: "/api/vllm/attack" }, "vllm")), 270_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "endpoint-lease-revoke", endpoint: "/api/vllm/attack" }, "vllm")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "guardrail-rotate", endpoint: "/api/vllm/attack" }, "vllm")), 630_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "guardrail-output-v2", endpoint: "/api/vllm/attack" }, "vllm")), 960_000);
  assert.equal(liveAttackPollBudgetMs(liveAttackRoute({ id: "poison", endpoint: "/api/vllm/attack" }, "vllm")), 150_000);
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
