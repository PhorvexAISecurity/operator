import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { ForbiddenException, TooManyRequestsException, UnauthorizedException } from './errors';
import type { Request, Response } from 'express';
import { Config } from './config';
import { Store } from './store';

export const COOKIE = 'phorvex_benchmark';
export function constantEqual(a: string, b: string): boolean {
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export class Auth {
  private readonly passwordHash: Buffer;
  private readonly attempts = new Map<string, {count:number; until:number}>();
  constructor(private readonly config: Config, private readonly store: Store) {
    this.passwordHash = scryptSync(config.password, config.sessionSecret, 32);
  }
  checkOrigin(request: Pick<Request,'headers'>) {
    if (request.headers.origin !== this.config.origin) throw new ForbiddenException('Request origin is not allowed');
    if (request.headers['sec-fetch-site'] === 'cross-site') throw new ForbiddenException('Cross-site mutation is not allowed');
  }
  login(password: unknown, request: Request, response: Response) {
    this.checkOrigin(request);
    const key = request.ip || request.socket.remoteAddress || 'unknown'; const now = Date.now();
    const prior = this.attempts.get(key); const entry = !prior || prior.until < now ? { count: 0, until: now + 60_000 } : prior;
    entry.count++; this.attempts.set(key, entry);
    if (this.attempts.size > 1000) for (const [ip,a] of this.attempts) if (a.until < now) this.attempts.delete(ip);
    if (entry.count > 10) throw new TooManyRequestsException('Too many login attempts; retry in one minute');
    if (typeof password !== 'string' || password.length > 256 || !timingSafeEqual(this.passwordHash, scryptSync(password, this.config.sessionSecret, 32))) throw new UnauthorizedException('Invalid password');
    const sid = randomBytes(32).toString('hex'); const expires = now + 12 * 60 * 60_000;
    this.store.createSession(sid, expires);
    response.cookie(COOKIE, this.sign(`${sid}.${expires}`), { httpOnly: true, secure: this.config.secureCookie, sameSite: 'strict', path: '/api', maxAge: expires - now });
    return { authenticated: true };
  }
  authenticated(request: Pick<Request,'headers'>): boolean {
    const session = this.parse(request); return Boolean(session && this.store.validSession(session.id, session.expires));
  }
  require(request: Request) {
    if (!this.authenticated(request)) throw new UnauthorizedException('Login required');
    if (!['GET','HEAD','OPTIONS'].includes(request.method)) this.checkOrigin(request);
  }
  logout(request: Request, response: Response) {
    this.require(request); const session = this.parse(request); if (session) this.store.revokeSession(session.id);
    response.clearCookie(COOKIE, { path: '/api', httpOnly: true, secure: this.config.secureCookie, sameSite: 'strict' });
    return { authenticated: false };
  }
  metrics(request: Request) {
    const token = this.config.metricsToken;
    if (token.length < 24 || !constantEqual(String(request.headers.authorization || ''), `Bearer ${token}`)) throw new UnauthorizedException('Metrics token required');
  }
  private sign(payload: string): string { return `${payload}.${createHmac('sha256', this.config.sessionSecret).update(payload).digest('hex')}`; }
  private parse(request: Pick<Request,'headers'>): {id:string;expires:number} | undefined {
    const part = String(request.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith(`${COOKIE}=`));
    if (!part) return undefined;
    const value = part.substring(COOKIE.length + 1);
    if (!/^[0-9a-f]{64}\.[0-9]{13}\.[0-9a-f]{64}$/.test(value)) return undefined;
    const [id,exp] = value.split('.');
    if (!constantEqual(value, this.sign(`${id}.${exp}`))) return undefined;
    const expires = Number(exp); if (expires <= Date.now()) return undefined;
    return { id, expires };
  }
}
