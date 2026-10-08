import { mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { join, sep } from 'node:path';
import { ObjectiveAccumulator, ObjectiveSummaryReader, emptyObjectiveSummary, OBJECTIVE_SCHEMA_VERSION } from '../src/objective';

const LEGACY = 'legacy-runtime-lambda-v1';
const FIXED = 'fixed-disruption-aversion-v1';
// Reduced, sanitized run-12 trace; other modes below are synthetic variants of this envelope.
const sample = JSON.parse(readFileSync(join(__dirname, __dirname.includes(`${sep}dist${sep}`) ? '../../test/fixtures' : 'fixtures', 'objective-legacy.json'), 'utf8'));
const window = { startedAt: '2026-10-08T17:03:55.604Z', finishedAt: '2026-10-08T17:16:54.282Z' };
function record(id: string, fields: Record<string, unknown> = {}) {
  return { ...sample, decisionTrace: { ...sample.decisionTrace, decisionID: id, ...fields } };
}
function retained(records: unknown[], manifest: unknown = window) {
  const dataDirectory = mkdtempSync(join(tmpdir(), 'benchmark-objective-'));
  const id = randomUUID();
  const directory = join(dataDirectory, 'runs', id);
  mkdirSync(join(directory, 'raw'), { recursive: true });
  const audit = join(directory, 'raw', 'audit-vllm.jsonl');
  writeFileSync(audit, records.map(value => JSON.stringify(value)).join('\n') + '\n');
  writeFileSync(join(directory, 'manifest.json'), JSON.stringify(manifest));
  const reader = new ObjectiveSummaryReader(dataDirectory);
  const run = { id, status: 'completed', ...window };
  return { directory, dataDirectory, audit, reader, run,
    read: (bounds = {}) => reader.read(directory, { ...run, ...bounds }, 2000),
    cleanup: () => rmSync(dataDirectory, { recursive: true, force: true }) };
}

test('legacy traces record the runtime zero, never the policy seed or a requested beta', async () => {
  const fixture = retained([sample, sample, record('second')]);
  try {
    writeFileSync(join(fixture.directory, 'request.json'), JSON.stringify({ request: 'Fixed Beta beta=1.0', objectiveMode: FIXED }));
    const before = readFileSync(fixture.audit), metadata = statSync(fixture.audit);
    const summary = await fixture.read();
    assert.deepEqual(summary, { ...emptyObjectiveSummary(), decisionCount: 2,
      modes: [{ objectiveMode: LEGACY, count: 2 }],
      coefficients: [{ objectiveMode: LEGACY, source: 'lambdaRuntimeLegacy', min: 0, max: 0, count: 2 }] });
    assert.deepEqual(readFileSync(fixture.audit), before);
    assert.equal(statSync(fixture.audit).mtimeMs, metadata.mtimeMs);
    assert.deepEqual(readdirSync(fixture.directory).sort(), ['manifest.json', 'raw', 'request.json']);
  } finally { fixture.cleanup(); }
});

test('fixed traces retain explicit zero and summarize variable coefficients with a counted min/max', async () => {
  const fixture = retained([record('fixed-zero', { economicsVersion: FIXED, costCoefficientSource: 'disruptionAversion', effectiveCostCoefficient: 0 }),
    record('fixed-one', { economicsVersion: FIXED, costCoefficientSource: 'disruptionAversion', effectiveCostCoefficient: 1 })]);
  try {
    const summary = await fixture.read();
    assert.deepEqual(summary.modes, [{ objectiveMode: FIXED, count: 2 }]);
    assert.deepEqual(summary.coefficients, [{ objectiveMode: FIXED, source: 'disruptionAversion', min: 0, max: 1, count: 2 }]);
  } finally { fixture.cleanup(); }
});

test('mixed modes keep separate mode/source counts and missing coefficients', async () => {
  const fixture = retained([record('legacy'), record('fixed', { economicsVersion: FIXED, effectiveCostCoefficient: 1, costCoefficientSource: 'disruptionAversion' }),
    record('absent-fixed', { economicsVersion: FIXED, effectiveCostCoefficient: null, costCoefficientSource: 'disruptionAversion' })]);
  try {
    const summary = await fixture.read();
    assert.equal(summary.decisionCount, 3);
    assert.equal(summary.mixedModes, true);
    assert.deepEqual(summary.modes, [{ objectiveMode: LEGACY, count: 1 }, { objectiveMode: FIXED, count: 2 }]);
    assert.deepEqual(summary.coefficients, [
      { objectiveMode: LEGACY, source: 'lambdaRuntimeLegacy', min: 0, max: 0, count: 1 },
      { objectiveMode: FIXED, source: 'disruptionAversion', min: 1, max: 1, count: 1 },
      { objectiveMode: FIXED, source: 'disruptionAversion', min: null, max: null, count: 1 },
    ]);
  } finally { fixture.cleanup(); }
});

test('missing fields never use runtime lambda, policy defaults or a literal objectiveMode alias', async () => {
  const trace = record('missing');
  delete trace.decisionTrace.economicsVersion;
  delete trace.decisionTrace.effectiveCostCoefficient;
  delete trace.decisionTrace.costCoefficientSource;
  trace.decisionTrace.objectiveMode = FIXED;
  const fixture = retained([trace]);
  try {
    const summary = await fixture.read();
    assert.deepEqual(summary.modes, [{ objectiveMode: null, count: 1 }]);
    assert.deepEqual(summary.coefficients, [{ objectiveMode: null, source: null, min: null, max: null, count: 1 }]);
  } finally { fixture.cleanup(); }
});

test('optional absent, invalid numeric values and missing sources remain distinct from recorded zero', () => {
  const accumulator = new ObjectiveAccumulator();
  for (const value of [undefined, null, false, '0', NaN, Infinity, { present: false, value: 0 }]) accumulator.add({ effectiveCostCoefficient: value });
  for (const value of [0, { present: true, value: 0 }]) accumulator.add({ effectiveCostCoefficient: value });
  assert.deepEqual(accumulator.summary.coefficients, [
    { objectiveMode: null, source: null, min: null, max: null, count: 7 },
    { objectiveMode: null, source: null, min: 0, max: 0, count: 2 },
  ]);
});

test('window and scoped identities match the exporter across files, with first retained duplicate winning', async () => {
  const fixture = retained([record('same'), record('same', { economicsVersion: FIXED }),
    record('same', { assetUID: 'different-asset' }), record('outside', { timestamp: '2026-10-08T17:16:54.2829Z' }),
    record('before', { timestamp: '2026-10-08T17:03:55.6039Z' }),
    record('submicro-boundary', { timestamp: '2026-10-08T17:16:54.2820009Z' }),
    record('boundary', { timestamp: window.finishedAt }), record('invalid-time', { timestamp: 'invalid' }),
    record('incomplete-id', { assetUID: null }), { kind: 'unrelated' }]);
  try {
    writeFileSync(join(fixture.directory, 'raw', 'audit-voice.jsonl'), JSON.stringify(record('same')) + '\n');
    const summary = await fixture.read({ startedAt: '2026-10-08T17:00:00Z', finishedAt: '2026-10-08T17:20:00Z' });
    assert.equal(summary.decisionCount, 4);
    assert.deepEqual(summary.modes, [{ objectiveMode: LEGACY, count: 4 }]);
    assert.equal(summary.skippedRecordCount, 2);
  } finally { fixture.cleanup(); }
});

test('cache reuses unchanged evidence, then refreshes on append, new audit file and changed run window', async () => {
  const fixture = retained([record('first')]);
  try {
    const first = await fixture.read();
    assert.equal(await fixture.read(), first);
    appendFileSync(fixture.audit, JSON.stringify(record('second')) + '\n');
    assert.equal((await fixture.read()).decisionCount, 2);
    writeFileSync(join(fixture.directory, 'raw', 'audit-voice.jsonl'), JSON.stringify(record('third')) + '\n');
    assert.equal((await fixture.read()).decisionCount, 3);
    writeFileSync(join(fixture.directory, 'manifest.json'), JSON.stringify({ ...window, finishedAt: '2026-10-08T17:04:00Z' }));
    assert.equal((await fixture.read()).decisionCount, 0);
  } finally { fixture.cleanup(); }
});

test('terminal runs without evidence cache an empty summary and invalidate when files arrive', async () => {
  const fixture = retained([]);
  try {
    rmSync(fixture.directory, { recursive: true });
    assert.deepEqual(await fixture.read(), emptyObjectiveSummary());
    mkdirSync(join(fixture.directory, 'raw'), { recursive: true });
    writeFileSync(fixture.audit, JSON.stringify(record('new')) + '\n');
    assert.equal((await fixture.read()).decisionCount, 1);
    assert.equal((await fixture.read({ finishedAt: '2026-10-08T17:04:00Z' })).decisionCount, 0);
  } finally { fixture.cleanup(); }
});

test('summary responses stay bounded while preserving overflow counts and missing mode counts', () => {
  const accumulator = new ObjectiveAccumulator();
  for (let index = 0; index < 2000; index++) accumulator.add({ economicsVersion: `mode-${index}`, costCoefficientSource: `source-${index}`, effectiveCostCoefficient: index });
  accumulator.add({});
  accumulator.add({ economicsVersion: 'x'.repeat(1000), costCoefficientSource: 'y'.repeat(1000) });
  const summary = accumulator.summary;
  assert.equal(summary.decisionCount, 2002);
  assert.equal(summary.mixedModes, true);
  assert.ok(summary.modes.length <= 33);
  assert.ok(summary.coefficients.length <= 64);
  assert.equal(summary.modes.reduce((total, mode) => total + mode.count, 0) + summary.unlistedModeCount, 2002);
  assert.equal(summary.coefficients.reduce((total, group) => total + group.count, 0) + summary.unlistedCoefficientCount, 2002);
  assert.deepEqual(summary.modes.find(mode => mode.objectiveMode === null), { objectiveMode: null, count: 1 });
  assert.ok(JSON.stringify(summary).length < 20000);
});

test('mixed mode detection also covers raw labels too long to list in the bounded response', () => {
  const accumulator = new ObjectiveAccumulator();
  accumulator.add({ economicsVersion: 'first-' + 'x'.repeat(300) });
  accumulator.add({ economicsVersion: 'second-' + 'x'.repeat(300) });
  assert.equal(accumulator.summary.mixedModes, true);
  assert.deepEqual(accumulator.summary.modes, []);
  assert.equal(accumulator.summary.unlistedModeCount, 2);
});

test('streaming tolerates chunk boundaries and malformed/oversized lines, and refreshes an incomplete append', async () => {
  const fixture = retained([{ ...record('large'), opaque: 'ی'.repeat(40000) }]);
  try {
    appendFileSync(fixture.audit, 'invalid-json\n' + 'x'.repeat(8 * 1024 * 1024 + 1) + '\n' + JSON.stringify(record('tail')).slice(0, -1));
    const partial = await fixture.read();
    assert.equal(partial.decisionCount, 1); assert.equal(partial.skippedRecordCount, 3);
    appendFileSync(fixture.audit, '}\n');
    const complete = await fixture.read();
    assert.equal(complete.decisionCount, 2); assert.equal(complete.skippedRecordCount, 2);
  } finally { fixture.cleanup(); }
});

test('audit symlinks cannot substitute files outside the retained run directory', async () => {
  const fixture = retained([record('inside')]);
  const external = retained([record('outside')]);
  try {
    symlinkSync(external.audit, join(fixture.directory, 'raw', 'audit-linked.jsonl'));
    const summary = await fixture.read();
    assert.equal(summary.decisionCount, 1);
  } finally { fixture.cleanup(); external.cleanup(); }
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}
function within<T>(promise: Promise<T>, milliseconds = 1000): Promise<T> {
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error('Timed out waiting for test operation')), milliseconds);
    promise.then(value => { clearTimeout(timer); resolvePromise(value); }, error => { clearTimeout(timer); reject(error); });
  });
}

test('every non-terminal status returns pending without filesystem discovery or raw scanning', async () => {
  const fixture = retained([record('active-evidence')]);
  const inspect = mock.method(fixture.reader as any, 'inspect', () => { throw new Error('Active evidence must not even be discovered'); });
  const scan = mock.method(fixture.reader as any, 'summarize');
  try {
    for (const status of ['queued', 'running', 'starting', 'capturing', 'cancelling', 'planning', 'cancel_requested', 'future-status']) {
      appendFileSync(fixture.audit, JSON.stringify(record(status)) + '\n');
      assert.deepEqual(await fixture.reader.read(fixture.directory, { ...fixture.run, status }, 2000), emptyObjectiveSummary('pending'));
    }
    assert.equal(inspect.mock.callCount(), 0); assert.equal(scan.mock.callCount(), 0);
    assert.equal(readdirSync(fixture.dataDirectory).includes('objective-summaries'), false);
  } finally { inspect.mock.restore(); scan.mock.restore(); await fixture.reader.close(); fixture.cleanup(); }
});

test('private persisted cache survives a reader restart with no scan and leaves retained files unchanged', async () => {
  const fixture = retained([record('persisted')]);
  const before = readFileSync(fixture.audit), metadata = statSync(fixture.audit);
  try {
    const first = await fixture.read();
    const path = join(fixture.reader.cacheDirectory, fixture.run.id + '.json');
    const envelope = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(envelope.schemaVersion, OBJECTIVE_SCHEMA_VERSION);
    assert.match(envelope.sourceSignature, /^[a-f0-9]{64}$/);
    assert.deepEqual(envelope.summary, first);
    assert.equal(statSync(fixture.reader.cacheDirectory).mode & 0o777, 0o700);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    await fixture.reader.close();
    const restarted = new ObjectiveSummaryReader(fixture.dataDirectory);
    const scan = mock.method(restarted as any, 'summarize', () => { throw new Error('Persisted cache must avoid raw scanning'); });
    try {
      assert.deepEqual(await restarted.read(fixture.directory, fixture.run), first);
      assert.deepEqual(await restarted.read(fixture.directory, { ...fixture.run, status: 'running' }, 2000), emptyObjectiveSummary('pending'));
      assert.equal(scan.mock.callCount(), 0);
    } finally { scan.mock.restore(); await restarted.close(); }
    assert.deepEqual(readFileSync(fixture.audit), before);
    assert.equal(statSync(fixture.audit).mtimeMs, metadata.mtimeMs);
    assert.deepEqual(readdirSync(fixture.directory).sort(), ['manifest.json', 'raw']);
    assert.deepEqual(readdirSync(fixture.reader.cacheDirectory), [fixture.run.id + '.json']);
  } finally { await fixture.reader.close(); fixture.cleanup(); }
});

test('terminal source changes invalidate the persisted cache after a restart', async () => {
  const fixture = retained([record('first')]);
  try {
    await fixture.read(); await fixture.reader.close();
    const path = join(fixture.reader.cacheDirectory, fixture.run.id + '.json');
    const signature = JSON.parse(readFileSync(path, 'utf8')).sourceSignature;
    appendFileSync(fixture.audit, JSON.stringify(record('second')) + '\n');
    const restarted = new ObjectiveSummaryReader(fixture.dataDirectory);
    const scan = mock.method(restarted as any, 'summarize');
    try {
      assert.equal((await restarted.read(fixture.directory, fixture.run)).state, 'calculating');
      const next = await restarted.read(fixture.directory, fixture.run, 2000);
      assert.equal(next.state, 'ready'); assert.equal(next.decisionCount, 2);
      assert.equal(scan.mock.callCount(), 1);
      assert.notEqual(JSON.parse(readFileSync(path, 'utf8')).sourceSignature, signature);
    } finally { scan.mock.restore(); await restarted.close(); }
  } finally { fixture.cleanup(); }
});

for (const invalid of ['schema', 'corrupt']) test(`${invalid} persisted caches are recomputed in the background`, async () => {
  const fixture = retained([record('source')]);
  try {
    await fixture.read(); await fixture.reader.close();
    const path = join(fixture.reader.cacheDirectory, fixture.run.id + '.json');
    const envelope = JSON.parse(readFileSync(path, 'utf8'));
    writeFileSync(path, invalid === 'corrupt' ? 'partial-json' : JSON.stringify({ ...envelope, schemaVersion: 0 }));
    const restarted = new ObjectiveSummaryReader(fixture.dataDirectory);
    const scan = mock.method(restarted as any, 'summarize');
    try {
      assert.equal((await restarted.read(fixture.directory, fixture.run)).state, 'calculating');
      assert.equal((await restarted.read(fixture.directory, fixture.run, 2000)).decisionCount, 1);
      assert.equal(scan.mock.callCount(), 1);
    } finally { scan.mock.restore(); await restarted.close(); }
  } finally { fixture.cleanup(); }
});

test('process-wide single-flight covers overlapping requests, different runs and different readers', async () => {
  const first = retained([record('first')]), second = retained([record('second')]);
  const started = deferred(), release = deferred();
  let concurrent = 0, maximum = 0;
  const mocks = [first, second].map((fixture, index) => {
    const original = (fixture.reader as any).summarize.bind(fixture.reader);
    return mock.method(fixture.reader as any, 'summarize', async (...args: unknown[]) => {
      concurrent++; maximum = Math.max(maximum, concurrent);
      try { if (index === 0) { started.resolve(); await release.promise; } return await original(...args); }
      finally { concurrent--; }
    });
  });
  try {
    assert.equal((await first.reader.read(first.directory, first.run)).state, 'calculating');
    await within(started.promise);
    await Promise.all(Array.from({ length: 8 }, () => first.reader.read(first.directory, first.run)));
    assert.equal((await second.reader.read(second.directory, second.run)).state, 'calculating');
    assert.equal(mocks[0].mock.callCount(), 1); assert.equal(mocks[1].mock.callCount(), 0);
    release.resolve();
    const summaries = await Promise.all([first.read(), second.read()]);
    assert.ok(summaries.every(summary => summary.state === 'ready' && summary.decisionCount === 1));
    assert.equal(maximum, 1); assert.equal(mocks[0].mock.callCount(), 1); assert.equal(mocks[1].mock.callCount(), 1);
  } finally {
    release.resolve(); await Promise.all([first.reader.close(), second.reader.close()]);
    mocks.forEach(method => method.mock.restore()); first.cleanup(); second.cleanup();
  }
});

test('non-waiting reads return while a scan is held; detail waiting stays bounded', async () => {
  const fixture = retained([record('held')]);
  const started = deferred(), release = deferred();
  const original = (fixture.reader as any).summarize.bind(fixture.reader);
  const scan = mock.method(fixture.reader as any, 'summarize', async (...args: unknown[]) => {
    started.resolve(); await release.promise; return original(...args);
  });
  try {
    assert.equal((await fixture.reader.read(fixture.directory, fixture.run)).state, 'calculating');
    await within(started.promise);
    assert.equal((await within(fixture.reader.read(fixture.directory, fixture.run), 500)).state, 'calculating');
    assert.equal((await within(fixture.reader.read(fixture.directory, fixture.run, 50), 500)).state, 'calculating');
    assert.equal(scan.mock.callCount(), 1);
    release.resolve(); assert.equal((await fixture.read()).state, 'ready');
  } finally { release.resolve(); await fixture.reader.close(); scan.mock.restore(); fixture.cleanup(); }
});

test('a worker activity guard defers scans and aborts an ongoing scan between chunks', async () => {
  const fixture = retained(Array.from({ length: 40 }, (_, index) => ({ ...record(String(index)), opaque: 'x'.repeat(64000) })));
  let allowed = false, pause = true;
  const reader = new ObjectiveSummaryReader(fixture.dataDirectory, () => allowed);
  const scan = mock.method(reader as any, 'summarize');
  const firstChunk = deferred();
  const original = (reader as any).record.bind(reader);
  const consume = mock.method(reader as any, 'record', (...args: unknown[]) => {
    original(...args);
    if (pause) { pause = false; allowed = false; firstChunk.resolve(); }
  });
  try {
    assert.equal((await reader.read(fixture.directory, fixture.run, 25)).state, 'calculating');
    assert.equal(scan.mock.callCount(), 0);
    allowed = true;
    await within(firstChunk.promise, 2000);
    assert.equal((await reader.read(fixture.directory, fixture.run, 25)).state, 'calculating');
    const consumed = consume.mock.callCount();
    assert.ok(consumed < 40, 'scan did not pause at a chunk boundary');
    assert.equal(readdirSync(fixture.dataDirectory).includes('objective-summaries'), false);
    allowed = true;
    const summary = await reader.read(fixture.directory, fixture.run, 2000);
    assert.equal(summary.state, 'ready'); assert.equal(summary.decisionCount, 40);
    assert.equal(scan.mock.callCount(), 2);
  } finally { await reader.close(); scan.mock.restore(); consume.mock.restore(); fixture.cleanup(); }
});
