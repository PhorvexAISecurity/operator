const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const root = path.resolve(__dirname, "..");
function load(relative, imports) {
  const compiled = ts.transpileModule(fs.readFileSync(path.join(root, relative), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React },
  }).outputText;
  const subject = { exports: {} };
  new Function("require", "module", "exports", compiled)((name) => {
    if (name in imports) return imports[name];
    throw new Error(`Unexpected import: ${name}`);
  }, subject, subject.exports);
  return subject.exports;
}
const ids = ["newstack:voice-rotate", "newstack:litellm-rotate", "newstack:crm-refund-revoke"];
const catalog = {
  schema: "newstack-catalog-v1", namespace: "phorvex-staging", enabled: true, maximumSeconds: 300,
  fireEndpoint: "https://untrusted.invalid/fire", items: ids.map((id) => ({ id, name: id, class: "fixture", expectedActuator: id.endsWith("revoke") ? "crm-refund-revoke" : "rotate", limitation: "Disposable fixture only." })),
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
function harness(overrides = {}) {
  const slots = [];
  let cursor = 0;
  let query = { data: catalog };
  const calls = [];
  const React = {
    createElement: (type, props, ...children) => ({ type, props: { ...props, children } }),
    useState: (initial) => {
      const index = cursor++;
      if (!(index in slots)) slots[index] = initial;
      return [slots[index], (value) => { slots[index] = typeof value === "function" ? value(slots[index]) : value; }];
    },
    useRef: (initial) => {
      const index = cursor++;
      if (!(index in slots)) slots[index] = { current: initial };
      return slots[index];
    },
    useEffect: () => {},
  };
  const api = {
    newstackCheck: async (caseId) => { calls.push(["check", caseId]); return { ok: true, caseId, namespace: catalog.namespace }; },
    newstackFire: async (caseId) => { calls.push(["fire", caseId]); return { schema: "newstack-run-v1", runId: "run-1", caseId, namespace: catalog.namespace, status: "done", verdict: "UNKNOWN", cleanupComplete: false, postflightClean: false, issues: ["Effect unconfirmed."] }; },
    newstackCleanup: async (caseId) => { calls.push(["cleanup", caseId]); return { ok: true, caseId, cleanupComplete: true }; },
    ...overrides,
  };
  const subject = load("components/panels/newstack-loops.tsx", {
    react: React, "lucide-react": { Loader2: "i" }, "@/lib/api": { api },
    "@/lib/query": { useApiRead: () => query },
    "@/components/ui/primitives": { Badge: "span", Button: "button", Card: "section", CardContent: "div" },
  });
  return { calls, ...subject, setQuery: (value) => { query = value; }, render: (props = {}) => {
    cursor = 0;
    return subject.NewstackLoopsPanel({ lens: "operator", allowMutations: true, ...props });
  } };
}
function nodes(node) {
  if (node == null || typeof node === "boolean") return [];
  if (Array.isArray(node)) return node.flatMap(nodes);
  if (typeof node !== "object") return [node];
  if (typeof node.type === "function") return nodes(node.type(node.props));
  return [node, ...nodes(node.props?.children)];
}
const text = (node) => nodes(node).filter((value) => typeof value === "string" || typeof value === "number").join(" ");
const buttons = (node) => nodes(node).filter((value) => value?.type === "button");
const button = (node, label, index = 0) => buttons(node).filter((value) => text(value) === label)[index];

test("panel hides disabled, wrong-namespace, failed and unavailable catalogs", () => {
  const h = harness();
  for (const query of [{}, { data: { ...catalog, enabled: false } }, { data: { ...catalog, namespace: "crm" } }, { data: catalog, error: new Error("denied") }]) {
    h.setQuery(query);
    assert.equal(h.render(), null);
  }
});

test("all three cases display fixture limits and honor explicit mutation scope", () => {
  const h = harness();
  const tree = h.render({ allowMutations: false });
  assert.equal(buttons(tree).filter((node) => text(node) === "Fire").length, 3);
  assert.ok(buttons(tree).every((node) => node.props.disabled));
  assert.match(text(tree), /simulated pod-resident marker/);
  assert.match(text(tree), /real Voice or LiteLLM pipeline/);
  assert.match(text(tree), /natural detection/);
  assert.ok(buttons(h.render({ lens: "investor" })).every((node) => node.props.disabled));
});

test("one synchronous busy lock prevents concurrent fire and disables every case", async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const h = harness({ newstackCheck: () => pending });
  const tree = h.render();
  button(tree, "Fire").props.onClick();
  button(tree, "Fire", 1).props.onClick();
  assert.ok(buttons(h.render()).every((node) => node.props.disabled));
  release({ ok: true, caseId: ids[0], namespace: catalog.namespace });
  await tick();
  assert.deepEqual(h.calls, [["fire", ids[0]]]);
  const rendered = text(h.render());
  assert.match(rendered, /UNKNOWN/);
  assert.match(rendered, /cleanup complete:.*no/);
  assert.match(rendered, /postflight clean:.*no/);
  assert.match(rendered, /Effect unconfirmed/);
  assert.doesNotMatch(rendered, /DEFENDED/);
});

test("scope retirement during preflight prevents the subsequent mutation", async () => {
  let release;
  const h = harness({ newstackCheck: () => new Promise((resolve) => { release = resolve; }) });
  button(h.render(), "Fire").props.onClick();
  h.render({ allowMutations: false });
  release({ ok: true, caseId: ids[0], namespace: catalog.namespace });
  await tick();
  assert.deepEqual(h.calls, []);
});

test("preflight and network failures remain errors without a run verdict", async () => {
  for (const newstackCheck of [async () => ({ ok: true, ready: false, caseId: ids[0], namespace: catalog.namespace }), async () => { throw new Error("Backend unavailable"); }]) {
    const h = harness({ newstackCheck });
    button(h.render(), "Fire").props.onClick();
    await tick();
    const rendered = text(h.render());
    assert.match(rendered, /Error:/);
    assert.match(rendered, /run outcome is unconfirmed/);
    assert.doesNotMatch(rendered, /Preflight passed|DEFENDED/);
    assert.deepEqual(h.calls, []);
  }
});

test("verdict, cleanup flags, issues and complete decision details are shown without reclassification", () => {
  const h = harness();
  const run = { runId: "exact-run", status: "cleanup-required", verdict: "PROACTIVE_HYGIENE_EFFECT", cleanupComplete: false, postflightClean: false,
    decision: { action: "rotate", decisionId: "decision-1", dispatchOutcome: "emitted-unconfirmed" }, issues: ["Cleanup pending."], limitation: "Marker only." };
  const tree = h.NewstackRunResult({ run });
  assert.match(text(tree), /PROACTIVE_HYGIENE_EFFECT/);
  assert.match(text(tree), /cleanup-required/);
  assert.match(text(tree), /emitted-unconfirmed/);
  assert.match(text(tree), /decision-1/);
  assert.match(text(tree), /Cleanup pending/);
  assert.ok(nodes(tree).filter((node) => node?.type === "span" && node.props.variant).every((node) => node.props.variant === "neutral"));
  assert.doesNotMatch(text(tree), /DEFENDED/);
});

test("typed methods preserve fixed paths, case bodies and authenticated request options", async () => {
  const calls = [];
  const previous = global.fetch;
  global.fetch = async (url, options) => { calls.push([url, options]); return { ok: true, json: async () => ({ ok: true }) }; };
  try {
    const { api } = load("lib/api.ts", { "@/lib/query-events": { captureQueryEventProvider: () => null, isCurrentQueryEventProvider: () => true, emitQueryChange: () => {} } });
    await api.newstackCatalog("operator");
    await api.newstackCheck(ids[0], "operator");
    await api.newstackFire(ids[1], "operator");
    await api.newstackCleanup(ids[2], "operator");
    const base = process.env.NEXT_PUBLIC_API_BASE || "";
    assert.deepEqual(calls.map(([url]) => url), [base + "/api/newstack/catalog", base + "/api/newstack/check?caseId=newstack%3Avoice-rotate", base + "/api/newstack/fire", base + "/api/newstack/cleanup"]);
    assert.deepEqual(calls.slice(2).map(([, options]) => JSON.parse(options.body)), [{ caseId: ids[1] }, { caseId: ids[2] }]);
    assert.ok(calls.every(([, options]) => options.credentials === "include" && options.headers["X-Phorvex-Lens"] === "operator"));
  } finally { global.fetch = previous; }
});
