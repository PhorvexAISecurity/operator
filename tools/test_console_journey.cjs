// Run with dashboard-web dependencies installed: node tools/test_console_journey.cjs
const assert = require('assert').strict;
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const ts = require('../dashboard-web/node_modules/typescript');
const root = path.resolve(__dirname, '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'console-journey-test-'));
// Execute the actual client and journey projection, including HTTP status handling.
for (const name of ['api', 'journey']) {
  const source = fs.readFileSync(path.join(root, 'dashboard-web/lib', name + '.ts'), 'utf8');
  fs.writeFileSync(path.join(temp, name + '.js'), ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 }
  }).outputText);
}
process.env.NODE_PATH = path.join(root, 'dashboard-web/node_modules');
Module._initPaths();
let effect;
const writes = [];
const hooks = {
  useState: initial => [initial, next => writes.push(next)],
  useEffect: callback => { effect = callback; },
};
const originalLoad = Module._load;
Module._load = function(request, ...args) {
  return request === 'react' ? hooks : originalLoad.call(this, request, ...args);
};
const { loadCorpusSignal, stepState, useJourneySignals } = require(path.join(temp, 'journey.js'));
Module._load = originalLoad;
(async () => {
  for (const test of [
    { status: 200, body: { hasP3Deep: true }, corpus: true },
    { status: 200, body: { hasPactuator: true }, corpus: true },
    { status: 200, body: {}, corpus: false },
    { status: 403, body: { error: 'scope denied' }, corpus: false, error: 'scope denied' },
    { status: 401, body: { error: 'identity rejected' }, corpus: false, error: 'identity rejected' },
    { status: 503, body: { error: 'unavailable' }, corpus: false, error: 'unavailable' },
  ]) {
    global.fetch = async (url, options) => {
      assert.equal(url, '/api/diagnostics');
      assert.equal(options.credentials, 'include');
      assert.equal(options.headers['X-Phorvex-Lens'], 'operator');
      return { ok: test.status === 200, status: test.status, json: async () => test.body };
    };
    const signal = await loadCorpusSignal('operator');
    assert.equal(signal.hasCorpus, test.corpus);
    assert.equal(signal.diagnosticsError, test.error);
    const state = { connected: true, hasAudit: false, hasBench: false, loading: false, ...signal };
    assert.equal(stepState('discovered', state, 'landing'), test.corpus ? 'ready' : 'locked');
    assert.equal(stepState('protect', state, 'landing'), test.corpus ? 'ready' : 'locked');
  }
  global.fetch = async () => { throw new Error('network'); };
  const unavailable = await loadCorpusSignal('operator');
  assert.equal(unavailable.hasCorpus, false);
  assert.equal(unavailable.diagnosticsError, 'BACKEND_UNREACHABLE');
  // Execute the real hook with controlled hook scheduling: the old investor request
  // arrives after a newer operator result. It must not overwrite the new lens state.
  let resolveOld;
  const oldDiagnostics = new Promise(resolve => { resolveOld = resolve; });
  const response = body => ({ ok: true, status: 200, json: async () => body });
  global.fetch = async (url, options) => {
    if (url === '/api/diagnostics') {
      return options.headers['X-Phorvex-Lens'] === 'investor'
        ? oldDiagnostics : response({ hasP3Deep: true });
    }
    if (url === '/api/targets') return response({ targets: [{ runnable: true }] });
    if (url === '/api/benchmarks') return response({ groups: [] });
    throw new Error('unexpected request: ' + url);
  };
  const originalTimeout = global.setTimeout;
  global.setTimeout = callback => originalTimeout(callback, 0);
  global.EventSource = class { close() {} };
  try {
    useJourneySignals('investor');
    const cancelOld = effect();
    cancelOld();
    useJourneySignals('operator');
    const cancelNew = effect();
    for (let i = 0; writes.length === 0 && i < 100; i++) {
      await new Promise(resolve => originalTimeout(resolve, 1));
    }
    assert.equal(writes.length, 1, 'new lens must finish independently');
    assert.equal(writes[0].hasCorpus, true);
    resolveOld(response({ hasP3Deep: false, hasPactuator: false }));
    await new Promise(resolve => originalTimeout(resolve, 20));
    assert.equal(writes.length, 1, 'late old lens must not publish stale state');
    cancelNew();
  } finally {
    global.setTimeout = originalTimeout;
  }
  console.log('PASS: late obsolete-lens diagnostics cannot overwrite current navigation state');
  console.log('PASS: authenticated diagnostics unlocks corpus navigation; denied/unavailable diagnostics stay locked with visible error');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => fs.rmSync(temp, { recursive: true, force: true }));
