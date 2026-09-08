import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { EventRow } from "../components/panels/owner";
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
