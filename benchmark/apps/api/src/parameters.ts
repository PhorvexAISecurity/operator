import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { Config } from './config';
import { ServiceUnavailableException } from './errors';

// Brain-verified runtime optimizer parameters. The worker reads the Console's Optimizer Bench
// endpoints (the knobs of every app's live policy, each checked against the brain's newest
// decision trace, plus the audited change log) and appends an observation timeline under
// DATA_DIR/parameters. Read-only: nothing here writes to the cluster.

const CACHE_MS = 15_000;
const POLL_MS = 5 * 60_000;
const TIMEOUT_MS = 90_000;
const MAX_OUTPUT = 16 * 1024 * 1024;

@Injectable()
export class ParametersService implements OnModuleInit, OnModuleDestroy {
  private cached?: { at: number; body: unknown };
  private inflight?: Promise<unknown>;
  private timer?: NodeJS.Timeout;

  constructor(readonly config: Config) {}

  onModuleInit() {
    if (process.env.BENCHMARK_PARAMETER_POLL !== 'off') {
      this.timer = setInterval(() => { void this.snapshot(true).catch(() => undefined); }, POLL_MS);
      this.timer.unref();
    }
  }
  onModuleDestroy() { if (this.timer) clearInterval(this.timer); }

  snapshot(fresh = false): Promise<unknown> {
    if (!fresh && this.cached && Date.now() - this.cached.at < CACHE_MS) return Promise.resolve(this.cached.body);
    if (this.inflight) return this.inflight;
    this.inflight = this.run().then((body) => { this.cached = { at: Date.now(), body }; return body; }).finally(() => { this.inflight = undefined; });
    return this.inflight;
  }

  private run(): Promise<unknown> {
    return new Promise((resolvePromise, reject) => {
      const child = spawn(this.config.python, [join(this.config.root, 'worker', 'parameters_cli.py'), 'snapshot', '--data', this.config.dataDir],
        { cwd: join(this.config.root, 'worker'), env: process.env, stdio: ['ignore', 'pipe', 'ignore'], shell: false });
      const chunks: Buffer[] = [];
      let size = 0;
      const timer = setTimeout(() => child.kill('SIGTERM'), TIMEOUT_MS);
      child.stdout.on('data', (chunk: Buffer) => { size += chunk.length; if (size <= MAX_OUTPUT) chunks.push(chunk); else child.kill('SIGTERM'); });
      child.on('error', () => { clearTimeout(timer); reject(new ServiceUnavailableException('Parameter reader could not start; check PYTHON and BENCHMARK_ROOT.')); });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code !== 0 || size > MAX_OUTPUT) { reject(new ServiceUnavailableException('Console parameter read failed (Console unreachable, token or port-forward unavailable).')); return; }
        try { resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new ServiceUnavailableException('Console parameter read returned invalid JSON.')); }
      });
    });
  }
}
