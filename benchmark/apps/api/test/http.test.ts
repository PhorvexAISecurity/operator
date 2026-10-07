import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { bootstrap } from '../src/main';

test('HTTP routes protect data and metrics, require same-origin login and revoke cookies',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-http-'));
  Object.assign(process.env,{DATA_DIR:directory,DASHBOARD_PASSWORD:'http-unit-test-password',SESSION_SECRET:'http-unit-test-secret-more-than-32-characters',DASHBOARD_ORIGIN:'https://dashboard.test',METRICS_TOKEN:'http-unit-test-metrics-token',PORT:'0',HOST:'127.0.0.1',COOKIE_SECURE:'true'});
  const app=await bootstrap();
  try {
    const server=app.getHttpServer();const origin=`http://127.0.0.1:${server.address().port}`;
    assert.equal((await fetch(`${origin}/health`)).status,200);
    assert.deepEqual(await (await fetch(`${origin}/api/auth/session`)).json(),{authenticated:false});
    for(const route of ['/api/meta','/api/catalogue','/api/runs','/api/runs/fake/events','/api/runs/fake/artifacts/evidence.zip'])assert.equal((await fetch(origin+route)).status,401);
    assert.equal((await fetch(`${origin}/metrics`)).status,401);
    assert.equal((await fetch(`${origin}/metrics`,{headers:{Authorization:'Bearer http-unit-test-metrics-token'}})).status,200);
    const body=JSON.stringify({password:'http-unit-test-password'});
    assert.equal((await fetch(`${origin}/api/auth/login`,{method:'POST',headers:{'Content-Type':'application/json',Origin:'https://evil.test'},body})).status,403);
    const login=await fetch(`${origin}/api/auth/login`,{method:'POST',headers:{'Content-Type':'application/json',Origin:'https://dashboard.test'},body});
    assert.equal(login.status,200);const setCookie=login.headers.get('set-cookie')!;
    assert.match(setCookie,/HttpOnly/);assert.match(setCookie,/Secure/);assert.match(setCookie,/SameSite=Strict/);
    const cookie=setCookie.split(';')[0];
    assert.deepEqual(await(await fetch(`${origin}/api/auth/session`,{headers:{Cookie:cookie}})).json(),{authenticated:true});
    assert.equal((await fetch(`${origin}/api/runs`,{headers:{Cookie:cookie}})).status,200);
    assert.equal((await fetch(`${origin}/api/runs`,{method:'POST',headers:{Cookie:cookie,Origin:'https://evil.test','Content-Type':'application/json'},body:'{}'})).status,403);
    assert.equal((await fetch(`${origin}/api/auth/logout`,{method:'POST',headers:{Cookie:cookie,Origin:'https://dashboard.test'}})).status,200);
    assert.deepEqual(await(await fetch(`${origin}/api/auth/session`,{headers:{Cookie:cookie}})).json(),{authenticated:false});
  }finally{await app.close();rmSync(directory,{recursive:true});}
});
