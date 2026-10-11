import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { spawn, ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { z } from 'zod';
import { Config } from './config';
import { Store } from './store';
import { BadRequestException, ConflictException, NotFoundException, ServiceUnavailableException } from './errors';

// Math/OR Benchmark Lab orchestration. The service validates requests, records jobs and
// experiments durably, and runs ONE Math Lab worker at a time. It has no production write
// path: the worker only reads recorded snapshots through the Console relay and replays them
// offline. Interrupted work is marked INTERRUPTED and never re-run automatically.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NAME = '[a-z0-9]([-a-z0-9]*[a-z0-9])?';
const POLICY = new RegExp(`^${NAME}/${NAME}$`);
const ARM_ID = z.string().regex(/^[A-Za-z0-9._-]{1,40}$/);
const ARM = z.union([
  z.object({ arm_id: ARM_ID, value_source: z.literal('RECORDED_EFFECTIVE') }).strict(),
  z.object({ arm_id: ARM_ID, value: z.number().finite() }).strict(),
  z.object({ arm_id: ARM_ID, unset: z.literal(true) }).strict(),
]);
const METRIC = z.string().regex(/^M-[A-Z]\d{2}[A-Z]?$/);
export const EXPERIMENT_INPUT = z.object({
  title: z.string().trim().min(1).max(200),
  mode: z.literal('REPLAY'),
  parameter_id: z.string().regex(/^P-[A-Z]{3}-\d{3}$/),
  policy: z.string().regex(POLICY),
  arms: z.array(ARM).min(2).max(12),
  cohort: z.object({
    since: z.string().datetime({ offset: true }).optional(),
    until: z.string().datetime({ offset: true }).optional(),
    max_snapshots: z.number().int().min(1).max(5000).optional(),
    spacing: z.enum(['latest', 'even']).optional(),
  }).strict().optional(),
  hypothesis: z.string().max(2000).optional(),
  primary_metric_id: METRIC,
  secondary_metric_ids: z.array(METRIC).max(20).default([]),
  safety_metric_ids: z.array(METRIC).max(20).default([]),
  allow_cross_version: z.boolean().optional(),
}).strict();
const SYNC_INPUT = z.object({ policy: z.string().regex(POLICY) }).strict();
export type ExperimentStatus = 'QUEUED' | 'RUNNING' | 'COMPLETE' | 'PARTIAL' | 'INVALID' | 'PREFLIGHT_FAILED' | 'FAILED' | 'INTERRUPTED';
const TERMINAL = new Set(['COMPLETE', 'PARTIAL', 'INVALID', 'PREFLIGHT_FAILED', 'FAILED', 'INTERRUPTED']);
const ARTIFACT = /^(experiment_manifest\.json|preflight\.json|arms\.json|replay-summary\.json|result\.json|metrics\.json|plots\.json|sweep_results\.csv|candidate_gate_trace\.csv|decision_funnel\.csv|cost_truth\.csv|candidates\.csv|Phorvex_Math_Lab_Results\.xlsx|report\.md|replay\.jsonl|inspect\.jsonl|evidence\.zip|plots\/PL-0[19]_M-[A-Z]\d{2}[A-Z]?\.svg)$/;

interface Job { id: string; kind: 'sync' | 'run'; status: string; createdAt: string; startedAt?: string; finishedAt?: string; policy?: string; experimentId?: string; message?: string; }
interface Experiment { id: string; status: ExperimentStatus; createdAt: string; request: Record<string, unknown>; preflight?: unknown; jobId?: string; finishedAt?: string; message?: string; }

@Injectable()
export class MathLabService implements OnModuleInit, OnModuleDestroy {
  private queue: Job[] = [];
  private child?: ChildProcess;
  private stopping = false;
  readonly policies: string[];
  constructor(readonly config: Config, readonly store: Store) {
    this.policies = (process.env.MATHLAB_POLICIES || 'vllm/vllm-defense').split(',').map(x => x.trim()).filter(x => POLICY.test(x));
    store.db.exec(`CREATE TABLE IF NOT EXISTS math_jobs(id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS math_experiments(id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL);`);
  }
  get root() { return resolve(this.config.dataDir, 'mathlab'); }
  onModuleInit() {
    for (const job of this.jobs()) if (!TERMINAL.has(job.status) && job.status !== 'COMPLETE') { job.status = 'INTERRUPTED'; job.finishedAt = new Date().toISOString(); job.message = 'API restarted; not re-run automatically.'; this.saveJob(job); }
    for (const exp of this.experiments()) if (!TERMINAL.has(exp.status)) { exp.status = 'INTERRUPTED'; exp.message = 'API restarted during execution; start a new experiment to re-run.'; this.saveExperiment(exp); }
  }
  onModuleDestroy() { this.stopping = true; if (this.child) this.child.kill('SIGTERM'); }

  // ── persistence ────────────────────────────────────────────────────────────────────
  private saveJob(job: Job) { this.store.db.prepare('INSERT INTO math_jobs VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, body=excluded.body').run(job.id, job.status, job.createdAt, JSON.stringify(job)); }
  private saveExperiment(e: Experiment) { this.store.db.prepare('INSERT INTO math_experiments VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, body=excluded.body').run(e.id, e.status, e.createdAt, JSON.stringify(e)); }
  private jobs(): Job[] { return this.store.db.prepare('SELECT body FROM math_jobs ORDER BY created_at DESC LIMIT 200').all().map((r: any) => JSON.parse(r.body)); }
  experiments(): Experiment[] { return this.store.db.prepare('SELECT body FROM math_experiments ORDER BY created_at DESC LIMIT 200').all().map((r: any) => JSON.parse(r.body)); }
  private experiment(id: string): Experiment {
    if (!UUID.test(id)) throw new NotFoundException('Experiment not found');
    const row: any = this.store.db.prepare('SELECT body FROM math_experiments WHERE id=?').get(id);
    if (!row) throw new NotFoundException('Experiment not found');
    return JSON.parse(row.body);
  }
  private readJson(path: string): unknown { try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return undefined; } }

  // ── read models ────────────────────────────────────────────────────────────────────
  registry(policy?: string) {
    if (policy !== undefined && !this.policies.includes(policy)) throw new BadRequestException('Unknown capture policy');
    const base = this.readJson(join(this.config.root, 'mathlab', 'registry', 'parameter_registry.json')) as { registry_version?: string } | undefined;
    if (!base) throw new ServiceUnavailableException('Parameter registry is missing from this release');
    if (policy) {
      const [ns, name] = policy.split('/');
      // The overlay is written at sync time; after a release ships a new registry it is stale until the next sync.
      const overlay = this.readJson(join(this.root, 'registry-effective', `${ns}--${name}.json`)) as { registry_version?: string } | undefined;
      if (overlay && overlay.registry_version === base.registry_version) return overlay;
    }
    return { ...base, inspection: null };
  }
  policyStatus() {
    const binary = this.readJson(join(this.root, 'bin', 'current.json'));
    return {
      binary: binary ?? null,
      policies: this.policies.map(policy => {
        const [ns, name] = policy.split('/');
        const dir = join(this.root, 'snapshots', ns, name);
        let held = 0;
        try { held = readdirSync(dir).filter(f => f.endsWith('.pxms')).length; } catch { /* none yet */ }
        return { policy, snapshots_held: held, last_sync: this.readJson(join(dir, 'last-sync.json')) ?? null,
          inspection: this.readJson(join(this.root, 'inspections', `${ns}--${name}.json`)) ? { available: true } : { available: false } };
      }),
    };
  }
  job(id: string) {
    if (!UUID.test(id)) throw new NotFoundException('Job not found');
    const row: any = this.store.db.prepare('SELECT body FROM math_jobs WHERE id=?').get(id);
    if (!row) throw new NotFoundException('Job not found');
    return { ...JSON.parse(row.body), progress: this.readJson(join(this.root, 'jobs', `${id}.json`)) ?? null };
  }
  list() {
    return this.experiments().map(e => ({ id: e.id, status: e.status, createdAt: e.createdAt, finishedAt: e.finishedAt,
      title: e.request.title, parameter_id: e.request.parameter_id, policy: `${e.request.namespace}/${e.request.policy}`,
      arms: (e.request.arms as unknown[] | undefined)?.length ?? 0, progress: this.readJson(join(this.root, 'experiments', e.id, 'status.json')) ?? null }));
  }
  detail(id: string) {
    const e = this.experiment(id);
    const dir = join(this.root, 'experiments', id);
    return { ...e, progress: this.readJson(join(dir, 'status.json')) ?? null, result: this.readJson(join(dir, 'result.json')) ?? null,
      manifest: this.readJson(join(dir, 'experiment_manifest.json')) ?? null,
      artifacts: [...(existsSync(join(dir, 'evidence.zip')) ? ['evidence.zip'] : []), ...((this.readJson(join(dir, 'artifacts.json')) as any)?.artifacts ?? [])] };
  }
  metrics(id: string) { this.experiment(id); return this.readJson(join(this.root, 'experiments', id, 'metrics.json')) ?? []; }
  plots(id: string) { this.experiment(id); return this.readJson(join(this.root, 'experiments', id, 'plots.json')) ?? {}; }
  artifact(id: string, name: string) {
    this.experiment(id);
    if (!ARTIFACT.test(name)) throw new NotFoundException('Artifact not found');
    const dir = realpathSync(join(this.root, 'experiments', id));
    const path = resolve(dir, name);
    if (!path.startsWith(dir + sep) || !existsSync(path) || !statSync(path).isFile()) throw new NotFoundException('Artifact not found');
    const real = realpathSync(path);
    if (!real.startsWith(dir + sep)) throw new NotFoundException('Artifact not found');
    return { path: real, name: name.split('/').pop() as string };
  }

  // ── actions ────────────────────────────────────────────────────────────────────────
  sync(body: unknown) {
    const parsed = SYNC_INPUT.safeParse(body);
    if (!parsed.success || !this.policies.includes(parsed.data.policy)) throw new BadRequestException('Unknown capture policy');
    if (this.queue.some(j => j.kind === 'sync' && j.policy === parsed.data.policy)) throw new ConflictException('A sync for this policy is already queued');
    const job: Job = { id: randomUUID(), kind: 'sync', status: 'QUEUED', createdAt: new Date().toISOString(), policy: parsed.data.policy };
    this.saveJob(job); this.queue.push(job); this.pump();
    return job;
  }
  private request(body: unknown) {
    const parsed = EXPERIMENT_INPUT.safeParse(body);
    if (!parsed.success) throw new BadRequestException({ error_code: 'INVALID_REQUEST', issues: parsed.error.issues.map(i => ({ field: i.path.join('.'), reason: i.message })) });
    const input = parsed.data;
    if (!this.policies.includes(input.policy)) throw new BadRequestException({ error_code: 'UNKNOWN_POLICY', field: 'policy', reason: 'not a configured capture policy' });
    const [namespace, policy] = input.policy.split('/');
    return { schema_version: 'math-lab.experiment.v1', ...input, namespace, policy };
  }
  async preflight(body: unknown) {
    const request = this.request(body);
    return this.runPreflight(request);
  }
  private runPreflight(request: Record<string, unknown>): Promise<any> {
    mkdirSync(join(this.root, 'preflight'), { recursive: true, mode: 0o700 });
    const file = join(this.root, 'preflight', `${randomUUID()}.json`);
    writeFileSync(file, JSON.stringify(request), { mode: 0o600 });
    return new Promise((resolvePromise, reject) => {
      const child = spawn(this.config.python, [join(this.config.root, 'worker', 'mathlab_cli.py'), 'preflight', '--data', this.config.dataDir, '--request', file],
        { cwd: this.config.root, env: process.env, stdio: ['ignore', 'pipe', 'ignore'], shell: false, timeout: 60_000 });
      let out = '';
      child.stdout?.on('data', d => { if (out.length < 4_000_000) out += d; });
      child.on('error', () => reject(new ServiceUnavailableException('Math Lab worker could not start')));
      child.on('close', code => {
        try { resolvePromise(JSON.parse(out)); } catch { reject(new ServiceUnavailableException(`Math Lab preflight failed (exit ${code})`)); }
      });
    });
  }
  async create(body: unknown) {
    const request = this.request(body);
    const preflight = await this.runPreflight(request);
    if (preflight?.status !== 'PASS') throw new BadRequestException({ error_code: 'PREFLIGHT_FAILED', preflight });
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    const dir = join(this.root, 'experiments', id);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const full = { ...request, experiment_id: id, created_at: createdAt, run_owner: 'benchmark-dashboard' };
    writeFileSync(join(dir, 'request.json'), JSON.stringify(full, null, 2), { mode: 0o600 });
    const job: Job = { id: randomUUID(), kind: 'run', status: 'QUEUED', createdAt, experimentId: id };
    const experiment: Experiment = { id, status: 'QUEUED', createdAt, request: full, preflight, jobId: job.id };
    this.saveExperiment(experiment); this.saveJob(job); this.queue.push(job); this.pump();
    return experiment;
  }

  private pump() {
    if (this.child || this.stopping) return;
    const job = this.queue.shift();
    if (!job) return;
    job.status = 'RUNNING'; job.startedAt = new Date().toISOString(); this.saveJob(job);
    const args = [join(this.config.root, 'worker', 'mathlab_cli.py')];
    if (job.kind === 'sync') {
      const [ns, name] = (job.policy as string).split('/');
      args.push('sync', '--data', this.config.dataDir, '--namespace', ns, '--policy', name, '--job', job.id);
    } else {
      args.push('run', '--data', this.config.dataDir, '--experiment', job.experimentId as string, '--job', job.id);
      const e = this.experiment(job.experimentId as string); e.status = 'RUNNING'; this.saveExperiment(e);
    }
    const child = spawn(this.config.python, args, { cwd: this.config.root, env: process.env, stdio: ['ignore', 'ignore', 'ignore'], shell: false });
    this.child = child;
    const finish = (code: number | null) => {
      this.child = undefined;
      job.finishedAt = new Date().toISOString();
      const progress: any = this.readJson(join(this.root, 'jobs', `${job.id}.json`));
      job.status = code === 0 ? 'COMPLETE' : 'FAILED';
      job.message = progress?.message;
      this.saveJob(job);
      if (job.kind === 'run') {
        const e = this.experiment(job.experimentId as string);
        const status: any = this.readJson(join(this.root, 'experiments', e.id, 'status.json'));
        const state = status?.state as ExperimentStatus | undefined;
        e.status = state && TERMINAL.has(state) ? state : 'FAILED';
        e.message = status?.message; e.finishedAt = job.finishedAt; this.saveExperiment(e);
      }
      if (!this.stopping) this.pump();
    };
    child.on('error', () => finish(-1));
    child.on('exit', code => finish(code));
  }
}
