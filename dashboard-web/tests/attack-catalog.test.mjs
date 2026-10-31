import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const panel = readFileSync(join(root, "components/panels/catalog.tsx"), "utf8");
const history = readFileSync(join(root, "components/panels/run-history.tsx"), "utf8");
const api = readFileSync(join(root, "lib/api.ts"), "utf8");

test("catalogue rows filter and render review metadata", () => {
  for (const field of ["description", "family", "expectedAction", "reactiveCompatible", "catalogueOrder"]) {
    assert.match(panel, new RegExp(`it\\.${field}`));
  }
  assert.match(panel, /including \$\{pinnedCount\} review-pinned catalogue entries/);
});

test("catalogue launch sends only the allowlisted ID", () => {
  assert.match(api, /post<\{ id: string; context: string; catalogueID: string \}>\("\/api\/catalog\/launch", \{ id \}, lens\)/);
  assert.doesNotMatch(api, /launchCatalogEntry:[^\n]*(command|path|manifest|shell)/i);
  assert.doesNotMatch(panel, /catalogueID\s*!==\s*["']AML\.T0012["']/);
});

test("typed result keeps every truth stage separate", () => {
  for (const label of ["visible", "available", "launched", "signal observed", "decided", "actuated", "physically validated", "cleaned", "defended"]) {
    assert.ok(panel.includes(`\"${label}\"`), `missing stage ${label}`);
  }
  assert.match(panel, /result\.verdict === "DEFENDED"/);
  assert.match(panel, /result\.executionMode/);
  assert.match(panel, /result\.triggerMode/);
});

test("persisted catalogue evidence remains reviewable from run history", () => {
  assert.match(panel, /export function AttackCatalogueResultPanel/);
  assert.match(history, /ev\.attackCatalogueResult/);
  assert.match(history, /<AttackCatalogueResultPanel result=\{ev\.attackCatalogueResult\}/);
  assert.match(history, /normalizeLocalTarget/);
  assert.match(history, /sameTarget\(run\.target, sel\.context\)/);
});
