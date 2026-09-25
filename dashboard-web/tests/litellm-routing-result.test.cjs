const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/litellm-routing-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);
const render = (evidence, outcome = "functional-pass") => renderToStaticMarkup(React.createElement(subject.exports.LiteLLMRoutingResult, { evidence, outcome }));

const valid = {
  eventMode: "none", securityEvent: "NOT_REQUIRED", brain: "NOT_EVALUATED", actuator: "NOT_EVALUATED", securityOutcome: "NOT_EVALUATED",
  authorityBeforeSHA256: "a".repeat(64), authorityAfterSHA256: "a".repeat(64), configSHA256: "b".repeat(64),
  modelAlias: "reviewed-model", requestCount: "4", knownModelState: "COMPLETION_SERVED", unknownModelState: "MODEL_REJECTED",
  "pod1.name": "litellm-0", "pod1.uid": "11111111-1111-4111-8111-111111111111", "pod1.imageID": "docker.io/litellm@sha256:" + "c".repeat(64), "pod1.version": "1.95.0",
  "pod1.known.status": "200", "pod1.known.state": "COMPLETION_SERVED", "pod1.known.reason": "VALID_ASSISTANT_COMPLETION",
  "pod1.known.returnedModel": "reviewed-model", "pod1.known.returnedModelSHA256": "c".repeat(64), "pod1.known.modelRelation": "REQUEST_ALIAS", "pod1.known.usagePromptCount": "7", "pod1.known.usageCompletionCount": "3",
  "pod1.unknown.status": "400", "pod1.unknown.state": "MODEL_REJECTED", "pod1.unknown.reason": "MODEL_NOT_FOUND",
  "pod2.name": "litellm-1", "pod2.uid": "22222222-2222-4222-8222-222222222222", "pod2.imageID": "docker.io/litellm@sha256:" + "d".repeat(64), "pod2.version": "1.98.0",
  "pod2.known.status": "200", "pod2.known.state": "COMPLETION_SERVED", "pod2.known.reason": "VALID_ASSISTANT_COMPLETION",
  "pod2.known.returnedModel": "", "pod2.known.returnedModelSHA256": "d".repeat(64), "pod2.known.modelRelation": "OTHER_REDACTED", "pod2.known.usagePromptCount": "8", "pod2.known.usageCompletionCount": "4",
  "pod2.unknown.status": "404", "pod2.unknown.state": "MODEL_REJECTED", "pod2.unknown.reason": "MODEL_NOT_FOUND",
};

test("both exact Pods show separate serving, rejection, identity and token usage without defense credit", () => {
  const html = render(valid);
  assert.match(html, /data-litellm-routing-result="typed"/);
  assert.match(html, /Pod 1: litellm-0 · version 1.95.0/);
  assert.match(html, /Pod 2: litellm-1 · version 1.98.0/);
  assert.match(html, /HTTP 200 · COMPLETION_SERVED · reason VALID_ASSISTANT_COMPLETION/);
  assert.match(html, /HTTP 400 · MODEL_REJECTED · reason MODEL_NOT_FOUND/);
  assert.match(html, /HTTP 404 · MODEL_REJECTED · reason MODEL_NOT_FOUND/);
  assert.match(html, /returned model relation OTHER_REDACTED · model SHA-256/);
  assert.match(html, /usage 7 prompt \/ 3 completion tokens/);
  assert.match(html, /brain, actuator and security outcome: NOT_EVALUATED/);
  assert.doesNotMatch(html, /scoped-key allowed|defended|mitigation succeeded|provider internals verified/i);
});

test("mixed Pod provider, database, auth and rate-limit errors stay unverified per stage", () => {
  for (const [status, reason] of [["503", "PROVIDER_OR_GATEWAY_ERROR"], ["400", "NO_CONNECTED_DB"], ["401", "AUTH_DENIED"], ["429", "RATE_LIMITED"]]) {
    const row = { ...valid, knownModelState: "UNVERIFIED", unknownModelState: "UNVERIFIED",
      "pod2.known.status": status, "pod2.known.state": "UNVERIFIED", "pod2.known.reason": reason,
      "pod2.known.returnedModel": "", "pod2.known.returnedModelSHA256": "", "pod2.known.modelRelation": "", "pod2.known.usagePromptCount": "", "pod2.known.usageCompletionCount": "",
      "pod2.unknown.status": status, "pod2.unknown.state": "UNVERIFIED", "pod2.unknown.reason": reason };
    const html = render(row, "inconclusive");
    assert.match(html, /data-litellm-routing-result="typed"/);
    assert.match(html, new RegExp(`Pod 2:[\\s\\S]*HTTP ${status} · UNVERIFIED · reason ${reason}`));
    assert.match(html, /completion unverified/);
    assert.doesNotMatch(html, /data-litellm-routing-result="unverified"/);
  }
});

test("generic HTTP 400, conflicting aggregate and unreviewed reason cannot become model rejection", () => {
  for (const row of [
    { ...valid, "pod2.unknown.reason": "NO_CONNECTED_DB" },
    { ...valid, "pod2.unknown.status": "401" },
    { ...valid, "pod2.unknown.state": "UNVERIFIED" },
    { ...valid, "pod2.known.state": "UNVERIFIED" },
    { ...valid, securityOutcome: "DEFENDED" },
    { ...valid, authorityAfterSHA256: "0".repeat(64) },
    { ...valid, "pod2.known.reason": "secret bearer sk-should-not-render" },
    { ...valid, "pod1.known.returnedModel": "sk-local-routing-boundary-do-not-retain" },
    { ...valid, modelAlias: "sk-local-routing-boundary-do-not-retain", "pod1.known.returnedModel": "sk-local-routing-boundary-do-not-retain" },
    { ...valid, "pod2.known.modelRelation": "REQUEST_ALIAS", "pod2.known.returnedModel": "" },
  ]) {
    const html = render(row);
    assert.match(html, /data-litellm-routing-result="unverified"/);
    assert.doesNotMatch(html, /MODEL_REJECTED|COMPLETION_SERVED|sk-should-not-render|sk-local-routing-boundary-do-not-retain/);
  }
  assert.match(render(valid, "inconclusive"), /data-litellm-routing-result="unverified"/);
  assert.match(render({ ...valid, unknownModelState: "UNVERIFIED", "pod2.unknown.state": "UNVERIFIED" }, "functional-pass"), /data-litellm-routing-result="unverified"/);
  assert.match(render({ ...valid, unknownModelState: "UNVERIFIED", "pod2.unknown.state": "UNVERIFIED", "pod2.unknown.reason": "NO_CONNECTED_DB" }, "functional-fail"), /data-litellm-routing-result="unverified"/);
});

test("unknown alias valid completion is a visible functional failure with redacted model metadata", () => {
  const row = { ...valid, unknownModelState: "UNVERIFIED",
    "pod2.unknown.status": "200", "pod2.unknown.state": "UNVERIFIED", "pod2.unknown.reason": "VALID_ASSISTANT_COMPLETION",
    "pod2.unknown.returnedModelSHA256": "e".repeat(64), "pod2.unknown.modelRelation": "OTHER_REDACTED" };
  const html = render(row, "functional-fail");
  assert.match(html, /data-litellm-routing-result="typed"/);
  assert.match(html, /Deliberately unknown model: HTTP 200 · UNVERIFIED · reason VALID_ASSISTANT_COMPLETION · unexpected completion/);
  assert.match(html, /returned model relation OTHER_REDACTED · model SHA-256 e{64}/);
  assert.doesNotMatch(html, /unknown model: MODEL_REJECTED|sk-local-routing-boundary-do-not-retain/);
});

test("lost final authority receipt keeps earlier sanitized Pod stages visible but unaccepted", () => {
  const html = render({ ...valid, authorityAfterSHA256: "", "pod2.known.status": "503", "pod2.known.state": "UNVERIFIED", "pod2.known.reason": "PROVIDER_OR_GATEWAY_ERROR" }, "inconclusive");
  assert.match(html, /data-litellm-routing-result="unverified"/);
  assert.match(html, /Pod 1: litellm-0/);
  assert.match(html, /Pod 2: litellm-1/);
  assert.match(html, /Known-model stage unverified: HTTP 503 · reason PROVIDER_OR_GATEWAY_ERROR/);
  assert.doesNotMatch(html, /MODEL_REJECTED|COMPLETION_SERVED/);
});

test("unknown evidence keys containing a prompt, completion or secret are never rendered", () => {
  const html = render({ ...valid, prompt: "private-prompt-123", completionBody: "private-answer-456", authorization: "sk-private-789" });
  assert.match(html, /data-litellm-routing-result="typed"/);
  assert.doesNotMatch(html, /private-prompt|private-answer|sk-private/);
});
