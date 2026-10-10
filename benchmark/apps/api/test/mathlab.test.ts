import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Config } from '../src/config';
import { Store } from '../src/store';
import { EXPERIMENT_INPUT, MathLabService } from '../src/mathlab';

function config(directory: string) {
  process.env.DASHBOARD_PASSWORD = 'unit-test-password-only';
  process.env.SESSION_SECRET = 'unit-test-only-secret-with-more-than-32-characters';
  process.env.DASHBOARD_ORIGIN = 'https://dashboard.test';
  process.env.DATA_DIR = directory;
  process.env.MATHLAB_POLICIES = 'vllm/vllm-defense';
  delete process.env.MATHLAB_LOCAL_BINARY;
  return new Config();
}
const valid = {
  title: 'ceiling sweep', mode: 'REPLAY', parameter_id: 'P-FEA-006', policy: 'vllm/vllm-defense',
  arms: [{ arm_id: 'control', value_source: 'RECORDED_EFFECTIVE' }, { arm_id: 'c2', value: 2 }], primary_metric_id: 'M-P21',
};

test('experiment requests are strict: no extra fields, no non-numeric values, bounded arms, replay only', () => {
  assert.equal(EXPERIMENT_INPUT.safeParse(valid).success, true);
  assert.equal(EXPERIMENT_INPUT.safeParse({ ...valid, command: 'rm -rf /' }).success, false);
  assert.equal(EXPERIMENT_INPUT.safeParse({ ...valid, mode: 'SANDBOX' }).success, false);
  assert.equal(EXPERIMENT_INPUT.safeParse({ ...valid, arms: [valid.arms[0], { arm_id: 'x', value: '2' }] }).success, false);
  assert.equal(EXPERIMENT_INPUT.safeParse({ ...valid, arms: [valid.arms[0], { arm_id: 'x', value: 2, unset: true }] }).success, false);
  assert.equal(EXPERIMENT_INPUT.safeParse({ ...valid, arms: Array.from({ length: 13 }, (_, i) => ({ arm_id: 'a' + i, value: i + 1 })) }).success, false);
  assert.equal(EXPERIMENT_INPUT.safeParse({ ...valid, policy: '../etc/passwd' }).success, false);
  assert.equal(EXPERIMENT_INPUT.safeParse({ ...valid, parameter_id: 'P-FEA-006; drop' }).success, false);
});

test('registry is served, unknown policies are refused, and preflight runs the real worker fail-closed', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'mathlab-'));
  const store = new Store(':memory:');
  try {
    const service = new MathLabService(config(directory), store);
    service.onModuleInit();
    const registry: any = service.registry();
    assert.equal(registry.schema_version, 'math-lab.parameters.v1');
    assert.ok(registry.items.length >= 198);
    assert.deepEqual(registry.items.filter((i: any) => i.control === 'EXPERIMENT_KNOB').map((i: any) => i.param_id).sort(), ['P-FEA-005', 'P-FEA-006', 'P-OBJ-003']);
    assert.throws(() => service.registry('other/policy'));
    assert.throws(() => service.sync({ policy: 'other/policy' }));
    await assert.rejects(() => service.create({ ...valid, policy: 'other/policy' }));
    const pf: any = await service.preflight(valid);
    assert.equal(pf.status, 'FAIL');
    assert.ok(pf.errors.some((e: any) => e.error_code === 'EMPTY_COHORT'));
    await assert.rejects(() => service.create(valid), (e: any) => JSON.stringify(e.response ?? {}).includes('PREFLIGHT_FAILED'));
    assert.equal(service.list().length, 0);
  } finally { store.close(); rmSync(directory, { recursive: true }); }
});

test('interrupted experiments are never re-run and artifacts refuse traversal and unregistered names', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mathlab-'));
  const store = new Store(':memory:');
  try {
    const service = new MathLabService(config(directory), store);
    const id = '6f1d2c3a-0000-4000-8000-000000000001';
    store.db.prepare('INSERT INTO math_experiments VALUES (?,?,?,?)').run(id, 'RUNNING', new Date().toISOString(),
      JSON.stringify({ id, status: 'RUNNING', createdAt: new Date().toISOString(), request: { title: 't', namespace: 'vllm', policy: 'vllm-defense' } }));
    service.onModuleInit();
    assert.equal(service.detail(id).status, 'INTERRUPTED');
    const dir = join(directory, 'mathlab', 'experiments', id);
    mkdirSync(join(dir, 'plots'), { recursive: true });
    writeFileSync(join(dir, 'report.md'), 'ok');
    writeFileSync(join(dir, 'plots', 'PL-01_M-P21.svg'), '<svg/>');
    writeFileSync(join(directory, 'secret.txt'), 'nope');
    symlinkSync(join(directory, 'secret.txt'), join(dir, 'result.json'));
    assert.equal(service.artifact(id, 'report.md').name, 'report.md');
    assert.equal(service.artifact(id, 'plots/PL-01_M-P21.svg').name, 'PL-01_M-P21.svg');
    assert.throws(() => service.artifact(id, '../../secret.txt'));
    assert.throws(() => service.artifact(id, 'request.json'));
    assert.throws(() => service.artifact(id, 'result.json'), 'symlink escaping the experiment directory must be refused');
    assert.throws(() => service.detail('not-a-uuid'));
  } finally { store.close(); rmSync(directory, { recursive: true }); }
});
