export class ApiError extends Error {
  constructor(message: string, public readonly status: number) { super(message); }
}

export async function api<T>(path: string, init: RequestInit = {}, timeout = 20_000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(`/api${path}`, {
      ...init,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
      signal: controller.signal,
    });
    const body = await response.json().catch(() => null) as unknown;
    if (!response.ok) {
      const error = body && typeof body === 'object' ? body as Record<string, unknown> : {};
      const message = Array.isArray(error.message) ? error.message.join(' · ') : error.message;
      throw new ApiError(typeof message === 'string' ? message : 'ارتباط با سرویس برقرار نشد.', response.status);
    }
    return body as T;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw new ApiError('پاسخ سرویس زمان بیشتری نیاز دارد؛ وضعیت اجرا را بررسی کنید.', 408);
    throw error;
  } finally { clearTimeout(timer); }
}

export type Mode = 'serial' | 'parallel';
export type Version = string | Record<string, unknown>;
export type App = string | { namespace: string; name?: string; label?: string };
export type Model = string | { id: string; name?: string; label?: string };
export interface Meta { models: Model[]; applications: App[]; version?: Version; grafanaUrl?: string; errors?: unknown[] }
export interface Case {
  id: string; namespace: string; name?: string; endpoint?: string;
  armed?: boolean; compatible?: boolean; reason?: string; expectedActuator?: string;
  status?: string; outcome?: string | Record<string, unknown>; observedActuator?: string;
  action?: string; evidence?: unknown; errors?: unknown[]; error?: string;
  evidenceStatus?: string; evidenceCounts?: Record<string, unknown>; evidenceKind?: string;
  result?: Record<string, unknown>; actuated?: boolean;
  startedAt?: string; finishedAt?: string; resultId?: string; limitations?: string[];
  [key: string]: unknown;
}
export interface Plan {
  id: string; summary: string; mode: Mode; model: string; request: string;
  context: string; applications: string[]; cases: Case[]; limitations?: string[]; llmStatus?: string;
}
export type Artifact = string | { name: string; label?: string; filename?: string; size?: number; available?: boolean };
export interface Run {
  id: string; status: string; mode: Mode; model: string; request: string; context?: string;
  startedAt?: string; createdAt?: string; finishedAt?: string;
  progress?: { total: number; completed: number }; cases?: Case[];
  version?: Version; artifacts?: Artifact[] | Record<string, unknown>; errors?: unknown[];
  grafanaUrl?: string;
}
export interface Event { time: string; level: string; message: string }

export const activeStatuses = new Set(['queued', 'running', 'starting', 'capturing', 'cancelling', 'cancel_requested', 'planning']);
export function namespace(app: App) { return typeof app === 'string' ? app : app.namespace; }
export function appLabel(app: App) { return typeof app === 'string' ? app : app.label || app.name || app.namespace; }
export function modelId(model: Model) { return typeof model === 'string' ? model : model.id; }
export function modelLabel(model: Model) { return typeof model === 'string' ? model : model.label || model.name || model.id; }
export function display(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'ثبت نشده';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}
export function versionLabel(version?: Version) {
  if (!version) return 'در انتظار بررسی نسخه';
  if (typeof version === 'string') return version;
  const apiVersion = version.apiVersion && typeof version.apiVersion === 'object' ? version.apiVersion as Record<string, unknown> : {};
  return display(version.manager || version.release || version.version || version.operator || apiVersion.version || version.tag || version);
}
export function safeExternalUrl(value?: string): string | undefined {
  if (!value) return undefined;
  try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined; }
  catch { return undefined; }
}
