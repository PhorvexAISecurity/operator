const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/mongo-exposure-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);
const render = (result, unsafeToRetry = false) => renderToStaticMarkup(React.createElement(subject.exports.MongoExposureResult, { result, unsafeToRetry }));
const accepted = {
  schema: "mongo-exposure-result-v1", accepted: true, finding: "EXPOSED", observedFinding: "EXPOSED",
  clientRead: "UNAUTHENTICATED_EXACT_READ", legitimateBefore: "EXACT_READ", legitimateAfter: "EXACT_READ",
  cleanup: "CONFIRMED_ABSENT", brainTrace: "JOINED", securityOutcome: "NOT_EVALUATED",
  rawReplySHA256: "a".repeat(64), rawReplyBytes: 175, sourcePodUID: "source-uid", clientPodUID: "client-uid", policyUID: "policy-uid", issues: [],
  brainDecisions: [{ decisionID: "decision-1", policyUID: "policy-uid", policyGeneration: 4, targetPodUID: "source-uid",
    action: "noop", actionStatus: "not-attempted", reasonSHA256: "b".repeat(64), observedAt: "2026-09-24T11:35:00Z" }],
};

test("accepted configuration finding keeps the manager decision distinct from efficacy", () => {
  const html = render(accepted);
  assert.match(html, /data-mongo-exposure-result="joined"/);
  assert.match(html, /configuration exposure accepted/);
  assert.match(html, /Client read:.*UNAUTHENTICATED_EXACT_READ/);
  assert.match(html, /Legitimate before:.*EXACT_READ/);
  assert.match(html, /Owned cleanup:.*CONFIRMED_ABSENT/);
  assert.match(html, /action noop · status not-attempted/);
  assert.match(html, /reason SHA-256.*b{64}/);
  assert.match(html, /Security outcome:.*NOT_EVALUATED/);
  assert.doesNotMatch(html, />DEFENDED<|mitigation succeeded|response prevented/);
});

test("observed read with audit gap stays unaccepted while retaining evidence and debt", () => {
  const html = render({ ...accepted, accepted: false, finding: "UNKNOWN", brainTrace: "GAP", cleanup: "UNCONFIRMED", issues: ["audit generation changed"] }, true);
  assert.match(html, /data-mongo-exposure-result="unverified"/);
  assert.match(html, /exact-read indication was observed/);
  assert.match(html, /Audit coverage has a generation, offset, or size gap/);
  assert.match(html, /Do not retry this run blindly/);
  assert.match(html, /audit generation changed/);
  assert.doesNotMatch(html, /configuration exposure accepted/);
});

test("Mongo code-13 denial is an observed branch, never protection credit", () => {
  const html = render({ ...accepted, accepted: false, finding: "UNKNOWN", observedFinding: "UNKNOWN", clientRead: "MONGO_AUTH_DENIED", legitimateAfter: "UNKNOWN" });
  assert.match(html, /Mongo refused the uncredentialed read/);
  assert.match(html, /not an accepted protection result/);
  assert.doesNotMatch(html, /configuration exposure accepted/);
});

test("incompatible accepted or security claim refuses presentation", () => {
  for (const row of [
    { ...accepted, securityOutcome: "DEFENDED" },
    { ...accepted, brainTrace: "GAP" },
    { ...accepted, rawReplySHA256: "bad" },
    { ...accepted, accepted: false, finding: "EXPOSED" },
    { ...accepted, brainDecisions: [{ ...accepted.brainDecisions[0], targetPodUID: "different-pod" }] },
    { ...accepted, brainDecisions: Array.from({ length: 65 }, (_, i) => ({ ...accepted.brainDecisions[0], decisionID: String(i) })) },
  ]) {
    const html = render(row);
    assert.match(html, /incompatible claim contract/);
    assert.doesNotMatch(html, /data-mongo-exposure-result=/);
  }
});
