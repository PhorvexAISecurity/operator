import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { bootstrap } from '../src/main';
import { CampaignService } from '../src/campaign';
import { Store } from '../src/store';

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

test('HTTP plans retain 32000 request characters and reject 32001 with a clear 400',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-request-limit-'));
  Object.assign(process.env,{BENCHMARK_ROOT:directory,DATA_DIR:directory,DASHBOARD_PASSWORD:'limit-unit-test-password',SESSION_SECRET:'limit-unit-test-secret-more-than-32-characters',DASHBOARD_ORIGIN:'https://dashboard.test',PORT:'0',HOST:'127.0.0.1',COOKIE_SECURE:'true',LLM_MODELS:'gpt-6.1-sol',LLM_API_KEY:'',BENCHMARK_ENFORCE_MUTATIONS_PAUSE:''});
  const app=await bootstrap();
  try {
    const service=app.get(CampaignService);let catalogueReads=0;
    // No worker, Console or annotation network calls; exercise the real HTTP parser/schema/store.
    service.catalogue=async()=>{
      catalogueReads++;
      return {applications:[{namespace:'vllm',live:[{id:'opaque-fixture',name:'Opaque fixture',endpoint:'/api/fixture',armed:true,compatible:true}]}],version:'offline-request-limit'};
    };
    const base=`http://127.0.0.1:${app.getHttpServer().address().port}`;
    const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{Origin:'https://dashboard.test','Content-Type':'application/json'},body:JSON.stringify({password:'limit-unit-test-password'})});
    assert.equal(login.status,200);
    const headers={Cookie:login.headers.get('set-cookie')!.split(';')[0],Origin:'https://dashboard.test','Content-Type':'application/json'};
    const input={mode:'serial',model:'gpt-6.1-sol',applications:['vllm']};
    // Unicode and escaped data catch byte limits below the character limits, including full context.
    for(const character of ['x','ی','\u0000']) {
      const request=character.repeat(32_000),context=character.repeat(16_000);
      const accepted=await fetch(base+'/api/plans',{method:'POST',headers,body:JSON.stringify({...input,request,context})});
      assert.equal(accepted.status,201);
      const plan=await accepted.json() as {id:string;request:string;context:string};
      assert.equal(plan.request,request);assert.equal(plan.context,context);
      assert.equal(app.get(Store).plan(plan.id)?.request,request);
      const rejected=await fetch(base+'/api/plans',{method:'POST',headers,body:JSON.stringify({...input,request:character.repeat(32_001),context})});
      assert.equal(rejected.status,400);
      const error=await rejected.json() as {statusCode:number;message:string};
      assert.equal(error.statusCode,400);assert.equal(error.message,'Request must be 32,000 characters or fewer.');
    }
    const trailingSpace=await fetch(base+'/api/plans',{method:'POST',headers,body:JSON.stringify({...input,request:'x'.repeat(32_000)+' '})});
    assert.equal(trailingSpace.status,400);
    assert.equal((await trailingSpace.json() as {message:string}).message,'Request must be 32,000 characters or fewer.');
    const longContext=await fetch(base+'/api/plans',{method:'POST',headers,body:JSON.stringify({...input,request:'Opaque request',context:'x'.repeat(16_001)})});
    assert.equal(longContext.status,400);
    assert.equal(catalogueReads,3);assert.equal(app.get(Store).allRuns().length,0);
  }finally{await app.close();rmSync(directory,{recursive:true});}
});
