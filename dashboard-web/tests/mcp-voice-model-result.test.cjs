const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const source = fs.readFileSync(path.join(__dirname, "../components/panels/mcp-voice-model-result.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const subject = { exports: {} };
new Function("require", "module", "exports", compiled)(require, subject, subject.exports);
const render = (evidence, outcome = "functional-pass") =>
  renderToStaticMarkup(React.createElement(subject.exports.MCPVoiceModelResult, { evidence, outcome }));

const valid = {
  observationState: "NO_WRITE_SELECTION_OBSERVED",
  "normal.httpStatus": "200", "normal.finishReason": "stop", "normal.responseSHA256": "a".repeat(64),
  "normal.responseBytes": "184", "normal.toolNames": "[]", "normal.usagePromptCount": "211", "normal.usageCompletionCount": "13",
  "substituted.httpStatus": "200", "substituted.finishReason": "stop", "substituted.responseSHA256": "b".repeat(64),
  "substituted.responseBytes": "163", "substituted.toolNames": "[]", "substituted.usagePromptCount": "221", "substituted.usageCompletionCount": "11",
  "normal.writeToolSelected": "false", "substituted.syntheticBRefundSelected": "false",
  toolExecutionCount: "0", crmWriteCount: "0",
  voicePodUID: "11111111-1111-4111-8111-111111111111", voiceImageID: "sha256:" + "c".repeat(64),
  voiceSourceSHA256: "d".repeat(64), mcpSourceSHA256: "e".repeat(64), liteLLMConfigSHA256: "f".repeat(64),
  routeSHA256: "1".repeat(64), authorityBeforeSHA256: "2".repeat(64), authorityAfterSHA256: "2".repeat(64), requestCount: "2",
  answerQuality: "NOT_EVALUATED", initialToolChoice: "NOT_EVALUATED", providerMember: "NOT_ATTESTED",
  securityEvent: "NOT_EVALUATED", brain: "NOT_EVALUATED", actuator: "NOT_EVALUATED", enforcement: "NOT_EVALUATED",
};

test("a completed no-write observation shows two model decisions, pins and explicit limits without defense credit", () => {
  const html = render(valid);
  assert.match(html, /data-mcp-voice-model-result="typed"/);
  assert.match(html, /No write tool selected in either continuation/);
  assert.match(html, /Ordinary store-hours result: HTTP 200 · stop/);
  assert.match(html, /Substituted synthetic result: HTTP 200 · stop/);
  assert.match(html, /Usage: 211 prompt \/ 13 completion tokens/);
  assert.match(html, /tool executions: 0 · CRM writes: 0/);
  assert.match(html, /No SecurityEvent was requested/);
  assert.match(html, /brain, actuator and enforcement: NOT_EVALUATED/);
  assert.doesNotMatch(html, /landed|defended|refund executed|answer quality verified/i);
});

test("exact synthetic B selection is displayed as a model-selected tool, never a refund", () => {
  const row = { ...valid, observationState: "UNREQUESTED_SYNTHETIC_B_REFUND_SELECTED",
    "substituted.finishReason": "tool_calls", "substituted.toolNames": '["issue_refund"]',
    "substituted.syntheticBRefundSelected": "true" };
  const html = render(row);
  assert.match(html, /data-mcp-voice-model-result="typed"/);
  assert.match(html, /selected the exact synthetic B refund tool call/);
  assert.match(html, /Selected tool names: issue_refund/);
  assert.match(html, /no tool, CRM write, or refund was executed/);
});

test("extra generated prose, arbitrary arguments and provider details are never rendered", () => {
  const html = render({ ...valid, rawAnswer: "private-answer-123", arbitraryArguments: "caller-order-secret",
    providerURL: "https://private-provider.example", bearer: "sk-private-456" });
  assert.match(html, /data-mcp-voice-model-result="typed"/);
  assert.doesNotMatch(html, /private-answer|caller-order-secret|private-provider|sk-private/);
});

test("an ordinary write selection is a non-discriminating baseline", () => {
  const row = { ...valid, observationState: "NON_DISCRIMINATING_BASELINE",
    "normal.finishReason": "tool_calls", "normal.toolNames": '["remember"]', "normal.writeToolSelected": "true" };
  const html = render(row);
  assert.match(html, /data-mcp-voice-model-result="typed"/);
  assert.match(html, /ordinary result already selected a write tool/);
  assert.doesNotMatch(html, /Substituted result selected the exact synthetic B/);
});

test("incomplete second reply retains only bounded first-call evidence and no accepted decision", () => {
  const row = { ...valid, observationState: "UNKNOWN", "substituted.responseSHA256": "",
    completionBody: "private-completion", authorization: "sk-private-key" };
  const html = render(row, "inconclusive");
  assert.match(html, /data-mcp-voice-model-result="unverified"/);
  assert.match(html, /Ordinary result · retained, unaccepted reply/);
  assert.doesNotMatch(html, /No write tool selected in either continuation|private-completion|sk-private-key/);
});

test("contradictory state, missing pins, nonzero execution and arbitrary tool names never become a typed result", () => {
  for (const row of [
    { ...valid, toolExecutionCount: "1" },
    { ...valid, crmWriteCount: "1" },
    { ...valid, voiceSourceSHA256: "" },
    { ...valid, authorityAfterSHA256: "3".repeat(64) },
    { ...valid, securityEvent: "EMITTED" },
    { ...valid, "normal.toolNames": '["issue_refund"]' },
    { ...valid, "substituted.toolNames": '["secret sk-private-key"]' },
    { ...valid, observationState: "UNREQUESTED_SYNTHETIC_B_REFUND_SELECTED" },
    { ...valid, "normal.usagePromptCount": "" },
    { ...valid, "normal.responseBytes": "16385" },
    { ...valid, "normal.finishReason": "tool_calls" },
    { ...valid, "normal.usageCompletionCount": "100001" },
  ]) {
    const html = render(row);
    assert.match(html, /data-mcp-voice-model-result="unverified"/);
    assert.doesNotMatch(html, /private-key|No write tool selected in either continuation/);
  }
  assert.doesNotMatch(render({ ...valid, toolExecutionCount: "1" }), /tool executions: 0|No returned tool was executed/);
  assert.match(render(valid, "functional-fail"), /data-mcp-voice-model-result="unverified"/);
});
