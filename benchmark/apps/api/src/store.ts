import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export type RunStatus = 'queued' | 'running' | 'cancelling' | 'completed' | 'incomplete' | 'failed' | 'cancelled' | 'interrupted';
export interface Plan {
  id: string; summary: string; mode: 'serial' | 'parallel'; model: string;
  request: string; context: string; applications: string[]; cases: Record<string, unknown>[];
  version: unknown; limitations: string[]; createdAt: string; llmStatus: string;
}
export interface Run {
  id: string; plan: Plan; status: RunStatus; createdAt: string; startedAt?: string;
  finishedAt?: string; workerPid?: number; workerExitedAt?: string; progress: { total: number; completed: number };
  cases: Record<string, unknown>[]; artifacts: { name: string; label?: string }[];
  errors: string[]; version: unknown; events: Record<string, unknown>[];
}

export class Store {
  readonly db: Database.Database;
  constructor(filename: string) {
    if (filename !== ':memory:') mkdirSync(dirname(filename), { recursive: true, mode: 0o700 });
    this.db = new Database(filename);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('busy_timeout = 5000');
    this.db.exec(`CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS scheduler_owner(id INTEGER PRIMARY KEY CHECK(id=1),pid INTEGER NOT NULL,instance TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS run_status ON runs(status,created_at);`);
  }
  savePlan(plan: Plan) { this.db.prepare('INSERT INTO plans VALUES (?,?)').run(plan.id, JSON.stringify(plan)); }
  plan(id: string): Plan | undefined { return this.decode(this.db.prepare('SELECT body FROM plans WHERE id=?').get(id)); }
  insertRun(run: Run) { this.db.prepare('INSERT INTO runs VALUES (?,?,?,?)').run(run.id, run.status, run.createdAt, JSON.stringify(run)); }
  saveRun(run: Run) { this.db.prepare('UPDATE runs SET status=?,body=? WHERE id=?').run(run.status, JSON.stringify(run), run.id); }
  run(id: string): Run | undefined { return this.decode(this.db.prepare('SELECT body FROM runs WHERE id=?').get(id)); }
  runs(limit = 100): Run[] { return this.db.prepare('SELECT body FROM runs ORDER BY created_at DESC LIMIT ?').all(limit).map(r => this.decode<Run>(r)!); }
  allRuns(): Run[] { return this.db.prepare('SELECT body FROM runs ORDER BY created_at DESC').all().map(r => this.decode<Run>(r)!); }
  claimNext(): Run | undefined {
    return this.db.transaction(() => {
      if (this.db.prepare("SELECT id FROM runs WHERE status IN ('running','cancelling') LIMIT 1").get()) return undefined;
      const next = this.decode<Run>(this.db.prepare("SELECT body FROM runs WHERE status='queued' ORDER BY created_at,id LIMIT 1").get());
      if (!next) return undefined;
      next.status = 'running'; next.startedAt = new Date().toISOString(); this.saveRun(next); return next;
    }).immediate();
  }
  reconcileInterrupted(): Run[] {
    const interrupted = this.db.prepare("SELECT body FROM runs WHERE status IN ('running','cancelling')").all().map(r => this.decode<Run>(r)!);
    for (const run of interrupted) {
      run.status = 'interrupted'; run.finishedAt = new Date().toISOString();
      run.errors.push('API restarted during execution. Remaining live outcomes are UNKNOWN; no attack was automatically retried.');
      this.saveRun(run);
    }
    return interrupted;
  }
  claimOwner(pid:number,instance:string,isAlive:(pid:number)=>boolean):boolean {
    return this.db.transaction(()=>{
      const owner=this.db.prepare('SELECT pid FROM scheduler_owner WHERE id=1').get() as {pid:number}|undefined;
      if(owner && isAlive(owner.pid))return false;
      this.db.prepare('INSERT INTO scheduler_owner VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET pid=excluded.pid,instance=excluded.instance').run(pid,instance);
      return true;
    }).immediate();
  }
  releaseOwner(instance:string) {this.db.prepare('DELETE FROM scheduler_owner WHERE id=1 AND instance=?').run(instance);}
  createSession(id: string, expires: number) { this.db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()); this.db.prepare('INSERT INTO sessions VALUES (?,?)').run(id, expires); }
  validSession(id: string, expires: number) { return Boolean(this.db.prepare('SELECT id FROM sessions WHERE id=? AND expires=? AND expires>?').get(id, expires, Date.now())); }
  revokeSession(id: string) { this.db.prepare('DELETE FROM sessions WHERE id=?').run(id); }
  close() { this.db.close(); }
  private decode<T>(row: unknown): T | undefined { return row ? JSON.parse((row as {body:string}).body) : undefined; }
}
