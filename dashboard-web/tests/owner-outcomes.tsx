import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { EventRow, OwnerSummary } from "../components/panels/owner";
import { OwnerLandingSummary } from "../components/steps/landing";
import type { OwnerEvent } from "../lib/api";

// Input is produced by TestM014OwnerHTTPReplay through the real server handler.
const { events } = JSON.parse(readFileSync(process.argv[2], "utf8")) as { events: OwnerEvent[] };
assert.equal(events.length, 4);
for (const e of events) {
  const html = renderToStaticMarkup(<EventRow e={e} />);
  assert.ok(html.includes(e.why));
  assert.ok(html.includes("SLO confirmation unavailable"));
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("forward-only"));
  assert.ok(!html.includes("destroying its state"));
}
const stale = { ...events[0], outcomeEvidence: "dispatch-only", why: "Replaced the compromised instance with a clean one." };
const html = renderToStaticMarkup(<EventRow e={stale} />);
assert.ok(html.includes("Action outcome unknown"));
assert.ok(!html.includes("clean one"));
console.log("PASS: HTTP projection -> rendered owner rows, escaped identifiers, honest badges, stale-payload fallback");

// Exercise the actual summary components used by Landing and OwnerPanel.
const legacyRollup = { actions: 4, attacksPrevented: 4, workPreserved: 2, sloKept: 4 };
for (const [rollup, unknown] of [[legacyRollup, true], [{ ...legacyRollup, dispatched: 0, isolationAttempts: 0 }, false]] as const) {
 const markup = renderToStaticMarkup(<OwnerLandingSummary rollup={rollup} />);
 assert.equal((markup.match(/>—</g) ?? []).length, unknown ? 2 : 0);
 if (!unknown) assert.equal((markup.match(/>0</g) ?? []).length, 2);
}
const legacy = { ...events[0], action: "quarantine", outcomeEvidence: undefined };
for (const entry of [legacy, { ...legacy, outcomeEvidence: "dispatch-only" }, { ...legacy, outcomeEvidence: "unknown" }]) {
 const markup = renderToStaticMarkup(<OwnerSummary events={[entry]} />);
 assert.equal((markup.match(/>—</g) ?? []).length, 2);
 assert.ok(!markup.includes(">0<"));
}
const zero = renderToStaticMarkup(<OwnerSummary events={[{ ...legacy, outcomeEvidence: "not-emitted" }]} />);
assert.equal((zero.match(/>0</g) ?? []).length, 2);
const mixed = renderToStaticMarkup(<OwnerSummary events={[legacy, { ...legacy, outcomeEvidence: "emitted-unconfirmed" }]} />);
assert.equal((mixed.match(/>—</g) ?? []).length, 2);
console.log("PASS: legacy/mixed summaries preserve unknown; explicit measured zero remains zero");
