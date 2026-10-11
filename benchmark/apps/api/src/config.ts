import { resolve, sep } from 'node:path';

export const APPLICATIONS = ['vllm', 'voice', 'litellm', 'crm'] as const;
export const REQUEST_MAX_CHARACTERS = 32_000;
export const ARTIFACT_NAMES = new Set([
  'Phorvex_Cost_Measured_vs_Expected.xlsx',
  'Phorvex_Tick_Action_Gates.xlsx', 'Brain_Parameters.csv', 'evidence.zip',
]);

export class Config {
  readonly root = resolve(process.env.BENCHMARK_ROOT || resolve(__dirname, __dirname.includes(`${sep}dist${sep}`) ? '../../../..' : '../../..'));
  readonly dataDir = resolve(process.env.DATA_DIR || resolve(this.root, 'data'));
  readonly python = process.env.PYTHON || 'python3';
  readonly password = process.env.DASHBOARD_PASSWORD || '';
  readonly sessionSecret = process.env.SESSION_SECRET || '';
  readonly metricsToken = process.env.METRICS_TOKEN || '';
  readonly origin = process.env.DASHBOARD_ORIGIN || process.env.PUBLIC_ORIGIN || 'http://localhost:4100';
  readonly secureCookie = process.env.COOKIE_SECURE !== 'false';
  readonly grafanaUrl = process.env.GRAFANA_URL || '';
  readonly models = (process.env.LLM_MODELS || 'gpt-6.1-sol').split(',').map(x => x.trim()).filter(Boolean);
  readonly llmKey = process.env.LLM_API_KEY || '';
  readonly sourceCommit = process.env.BENCHMARK_SOURCE_SHA || process.env.SOURCE_COMMIT || '';
  // Opt-in: the release this replaced never enforced the pause key, so enforcement stays off
  // until the operator who owns server configuration sets BENCHMARK_ENFORCE_MUTATIONS_PAUSE=true.
  readonly mutationsPausedReason = process.env.BENCHMARK_ENFORCE_MUTATIONS_PAUSE === 'true'
    ? (process.env.BENCHMARK_MUTATIONS_PAUSED_REASON || '').trim() : '';
  readonly shutdownGraceMs = 980_000;
  constructor() {
    if (this.password.length < 12) throw new Error('DASHBOARD_PASSWORD must contain at least 12 characters');
    if (this.sessionSecret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters');
    const origin = new URL(this.origin);
    if (!['https:', 'http:'].includes(origin.protocol) || origin.origin !== this.origin) throw new Error('DASHBOARD_ORIGIN must be an HTTP origin without a path');
    if (!this.models.length || this.models.some(m => !/^[a-zA-Z0-9._-]{1,100}$/.test(m))) throw new Error('Invalid LLM_MODELS');
    if (this.grafanaUrl && !['https:', 'http:'].includes(new URL(this.grafanaUrl).protocol)) throw new Error('Invalid GRAFANA_URL');
  }
}
