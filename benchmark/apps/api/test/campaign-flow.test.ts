import { mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { bootstrap } from '../src/main';
import { Config } from '../src/config';
import { CampaignService } from '../src/campaign';
import { Store, Plan, Run } from '../src/store';
import { ServiceUnavailableException } from '../src/errors';
import { selection } from '../src/selection';

const project=resolve(__dirname,'../../../..');
const input={mode:'serial',model:'gpt-6.1-sol',request:'Offline catalogue protocol fixture'};
function settings(root:string,data:string,paused='') {
  Object.assign(process.env,{BENCHMARK_ROOT:root,DATA_DIR:data,PYTHON:process.env.BENCHMARK_TEST_PYTHON || (existsSync(join(project,'.venv/bin/python'))?join(project,'.venv/bin/python'):'python3'),BENCHMARK_TEST_WORKER_ROOT:project,
    DASHBOARD_PASSWORD:'flow-unit-test-password',SESSION_SECRET:'flow-unit-test-secret-with-more-than-32-characters',DASHBOARD_ORIGIN:'https://dashboard.test',METRICS_TOKEN:'flow-unit-test-metrics-token',PORT:'0',HOST:'127.0.0.1',LLM_API_KEY:'',
    BENCHMARK_MUTATIONS_PAUSED_REASON:paused,BENCHMARK_ENFORCE_MUTATIONS_PAUSE:paused?'true':'',BENCHMARK_BLOCKED_CASES:'',BENCHMARK_BLOCK_REASON:'',BENCHMARK_POLL_SECONDS:'0.001'});
}
function fixtureRoot(directory:string) {
  const root=join(directory,'benchmark');mkdirSync(join(root,'worker'),{recursive:true});
  copyFileSync(join(project,'apps/api/test/mock-worker.py'),join(root,'worker/runner.py'));return root;
}
async function login(base:string) {
  const response=await fetch(base+'/api/auth/login',{method:'POST',headers:{Origin:'https://dashboard.test','Content-Type':'application/json'},body:JSON.stringify({password:'flow-unit-test-password'})});
  assert.equal(response.status,200);return {Cookie:response.headers.get('set-cookie')!.split(';')[0],Origin:'https://dashboard.test','Content-Type':'application/json'};
}

test('offline authenticated create-plan -> spawn production worker -> exact rows -> exports',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-flow-'));settings(fixtureRoot(directory),join(directory,'data'));
  const app=await bootstrap();
  try {
    const base=`http://127.0.0.1:${app.getHttpServer().address().port}`;const headers=await login(base);
    const planned=await fetch(base+'/api/plans',{method:'POST',headers,body:JSON.stringify(input)});
    assert.equal(planned.status,201);const plan=await planned.json() as any;
    assert.equal(plan.cases.length,12);assert.equal(plan.selection.total,12);assert.equal(plan.selection.ready,8);assert.equal(plan.selection.launchable,4);
    assert.equal(plan.cases.filter((c:any)=>c.benchmarkBlocked).length,4);
    const created=await fetch(base+'/api/runs',{method:'POST',headers,body:JSON.stringify({planId:plan.id})});assert.equal(created.status,201);
    let run=await created.json() as any;assert.equal(run.progress.total,12);
    const deadline=Date.now()+15000;
    while(['queued','running'].includes(run.status) && Date.now()<deadline) {
      await new Promise(r=>setTimeout(r,30));
      const detail=await fetch(base+'/api/runs/'+run.id,{headers});assert.equal(detail.status,200);run=await detail.json();
    }
    assert.equal(run.status,'completed',JSON.stringify(run.errors));assert.deepEqual(run.progress,{total:12,completed:12});assert.equal(run.selection.total,12);
    assert.equal(run.cases.length,12);assert.equal(run.cases.filter((c:any)=>c.status==='blocked').length,8);
    assert.ok(run.cases.filter((c:any)=>c.status==='completed').every((c:any)=>c.outcome==='UNKNOWN' && c.actuated===false && c.resultId));
    assert.ok(run.cases.filter((c:any)=>c.status==='blocked').every((c:any)=>c.reason && !c.resultId && !c.outcome));
    assert.equal(run.artifacts.length,4);
    for(const artifact of run.artifacts) {
      const response=await fetch(base+artifact.url,{headers});assert.equal(response.status,200);
      assert.match(response.headers.get('content-disposition')!,/attachment/);
      const bytes=Buffer.from(await response.arrayBuffer());
      // The brain-parameter table is a CSV (headers only when the Console predates the endpoint).
      if(artifact.name==='Brain_Parameters.csv') { assert.match(bytes.toString('utf8'),/^namespace,policy,parameter,/); continue; }
      assert.equal(bytes.subarray(0,2).toString(),'PK');assert.ok(bytes.length>100);
    }
    const duplicate=await fetch(base+'/api/runs',{method:'POST',headers,body:JSON.stringify({planId:plan.id})});
    assert.equal(duplicate.status,409);const conflict=await duplicate.json() as any;assert.equal(conflict.code,'PLAN_ALREADY_HAS_RUN');assert.equal(conflict.runId,run.id);assert.equal(conflict.runStatus,'completed');
    assert.equal((await(await fetch(base+'/api/runs/'+run.id+'/events',{headers})).json() as any).events.length>0,true);
  } finally {await app.close();rmSync(directory,{recursive:true});}
});

test('paused HTTP path permits planning/history/exports/cancel and distinguishes duplicate, invalid and paused run requests',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-pause-http-'));settings(fixtureRoot(directory),join(directory,'data'),'Producer reconciliation pending');
  const app=await bootstrap();
  try {
    const base=`http://127.0.0.1:${app.getHttpServer().address().port}`;const headers=await login(base);
    const meta=await(await fetch(base+'/api/meta',{headers})).json() as any;
    assert.match(meta.executionBlockedReason,/Producer reconciliation pending/);assert.match(meta.executionBlockedReason,/History, plans, exports and metrics remain available/);assert.match(meta.executionBlockedReason,/clear BENCHMARK_MUTATIONS_PAUSED_REASON/);
    const response=await fetch(base+'/api/plans',{method:'POST',headers,body:JSON.stringify(input)});assert.equal(response.status,201);const plan=await response.json() as any;
    assert.equal(plan.executionBlockedReason,meta.executionBlockedReason);assert.ok(plan.limitations.includes(meta.executionBlockedReason));
    const paused=await fetch(base+'/api/runs',{method:'POST',headers,body:JSON.stringify({planId:plan.id})});assert.equal(paused.status,503);
    const error=await paused.json() as any;assert.equal(error.code,'BENCHMARK_EXECUTION_PAUSED');assert.equal(error.message,meta.executionBlockedReason);
    assert.equal((await fetch(base+'/api/runs',{method:'POST',headers,body:'{}'})).status,400);
    assert.equal((await fetch(base+'/api/runs',{method:'POST',headers,body:JSON.stringify({planId:randomUUID()})})).status,404);
    assert.equal((await fetch(base+'/api/runs',{method:'POST',headers:{...headers,Origin:'https://evil.test'},body:JSON.stringify({planId:plan.id})})).status,403);
    const store=app.get(Store);assert.equal(store.allRuns().length,0);
    const existing:Run={id:randomUUID(),plan,status:'queued',createdAt:new Date().toISOString(),progress:{total:12,completed:0},cases:[],artifacts:[],errors:[],version:plan.version,events:[]};store.insertRun(existing);
    const service=app.get(CampaignService);await (service as any).tick();assert.equal(store.run(existing.id)?.status,'queued');assert.equal(existsSync(join(directory,'data/runs',existing.id)),false);
    const duplicate=await fetch(base+'/api/runs',{method:'POST',headers,body:JSON.stringify({planId:plan.id})});assert.equal(duplicate.status,409);assert.equal((await duplicate.json() as any).runId,existing.id);
    const runDirectory=join(directory,'data/runs',existing.id);mkdirSync(runDirectory,{recursive:true});writeFileSync(join(runDirectory,'evidence.zip'),'retained offline fixture');
    writeFileSync(join(runDirectory,'manifest.json'),JSON.stringify({artifacts:['evidence.zip']}));
    assert.equal((await fetch(base+'/api/runs',{headers})).status,200);assert.equal((await fetch(base+'/api/runs/'+existing.id,{headers})).status,200);
    assert.equal((await fetch(base+'/api/runs/'+existing.id+'/artifacts/evidence.zip',{headers})).status,200);
    assert.equal((await fetch(base+'/api/runs/'+existing.id+'/cancel',{method:'POST',headers})).status,200);
    assert.equal(store.run(existing.id)?.status,'cancelled');
    assert.equal((await fetch(base+'/metrics',{headers:{Authorization:'Bearer flow-unit-test-metrics-token'}})).status,200);
    service.catalogue=async()=>({applications:[],version:null,errors:['Console HTTP 403']});
    const empty=await fetch(base+'/api/plans',{method:'POST',headers,body:JSON.stringify(input)});
    assert.equal(empty.status,503);const catalogueError=await empty.json() as any;assert.equal(catalogueError.code,'LIVE_CATALOGUE_UNAVAILABLE');assert.match(catalogueError.message,/Check authenticated Console catalogue access/);assert.ok(catalogueError.errors.includes('Console HTTP 403'));
    service.catalogue=async()=>{throw new ServiceUnavailableException('Catalogue fixture unavailable');};
    const outage=await(await fetch(base+'/api/meta',{headers})).json() as any;assert.equal(outage.executionBlockedReason,meta.executionBlockedReason);assert.deepEqual(outage.errors,['Catalogue fixture unavailable']);
  } finally {await app.close();rmSync(directory,{recursive:true});}
});

test('80 selected rows retain blocked entries; a single application selects 20; corrupt progress cannot inflate completion',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-counts-'));settings(directory,directory);
  const store=new Store(':memory:');const service=new CampaignService(new Config(),store);(service as any).stopping=true;
  try {
    const applications=['vllm','voice','litellm','crm'].map(namespace=>({namespace,live:Array.from({length:20},(_,i)=>({id:i===18||i===19?'shared-id':`opaque-${i}`,name:'Opaque fixture',endpoint:i===19?'/api/fixture-b':'/api/fixture-a',armed:i<6,compatible:i<10,reason:i<6?'Armed fixture':'Incompatible or unarmed fixture',benchmarkBlocked:i===0,benchmarkBlockReason:i===0?'Known fixture defect':undefined}))}));
    service.catalogue=async()=>({applications,version:'offline-counts'} as any);
    const plan=await service.createPlan(input);assert.equal(plan.cases.length,80);assert.equal(plan.selection?.ready,24);assert.equal(plan.selection?.launchable,20);assert.equal(plan.selection?.benchmarkBlocked,4);
    assert.equal(plan.cases.filter(c=>c.id==='shared-id').length,8);
    const single=await service.createPlan({...input,applications:['voice']});assert.equal(single.cases.length,20);assert.equal(single.selection?.ready,6);
    assert.match(single.summary,/Selected all 20 current Live catalogue entries for voice\./);
    const run=service.queue({planId:plan.id});assert.deepEqual(run.progress,{total:80,completed:0});
    const out=join(directory,'runs',run.id);mkdirSync(out,{recursive:true});
    writeFileSync(join(out,'progress.json'),JSON.stringify({total:2,completed:3}));assert.deepEqual((await service.detail(run.id)).progress,{total:80,completed:0});
    const workerRows=[{namespace:'voice',armed:true,compatible:true},{namespace:'voice',armed:false,compatible:false}];
    writeFileSync(join(out,'progress.json'),JSON.stringify({total:2,completed:2,selection:selection(workerRows,['voice'])}));
    const refreshed=await service.detail(run.id);assert.deepEqual(refreshed.progress,{total:2,completed:2});assert.equal(refreshed.selection?.total,2);
  } finally {store.close();rmSync(directory,{recursive:true});}
});

test('missing worker executable reports actionable start failure and retains the planned total',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-spawn-error-'));const root=fixtureRoot(directory);settings(root,join(directory,'data'));
  process.env.PYTHON=join(directory,'missing-python');const store=new Store(':memory:');const service=new CampaignService(new Config(),store);
  try {
    const plan:Plan={id:randomUUID(),...input,mode:'serial',summary:'Offline spawn failure',context:'',applications:['vllm'],cases:[{namespace:'vllm',id:'opaque'}],version:null,limitations:[],createdAt:new Date().toISOString(),llmStatus:'unavailable'};store.savePlan(plan);
    const run=service.queue({planId:plan.id});
    const deadline=Date.now()+2000;while(store.run(run.id)?.status==='running' && Date.now()<deadline)await new Promise(r=>setTimeout(r,10));
    const failed=await service.detail(run.id);assert.equal(failed.status,'failed');assert.equal(failed.progress.total,1);assert.match(failed.errors.join(' '),/ENOENT.*PYTHON.*No automatic retry/);
  } finally {await service.onModuleDestroy();rmSync(directory,{recursive:true});}
});

test('a plan created while paused can queue after configured resume without a stale pause warning',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-resume-'));settings(directory,directory,'Fixture reconciliation pending');
  const store=new Store(':memory:');
  try {
    const paused=new CampaignService(new Config(),store);
    paused.catalogue=async()=>({applications:[{namespace:'vllm',live:[{id:'opaque',name:'Opaque',endpoint:'/api/fixture',armed:false,compatible:false,reason:'Fixture is blocked'}]}],version:null});
    const plan=await paused.createPlan({...input,applications:['vllm']});assert.ok(plan.executionBlockedReason);assert.throws(()=>paused.queue({planId:plan.id}),/paused/);
    settings(directory,directory,''); // Simulate an operator configuration reload only in this fixture.
    const resumed=new CampaignService(new Config(),store);(resumed as any).stopping=true;
    const run=resumed.queue({planId:plan.id});assert.equal(run.status,'queued');assert.equal(run.executionBlockedReason,undefined);
    assert.ok(!run.limitations.includes(plan.executionBlockedReason!));assert.equal(store.plan(plan.id)?.executionBlockedReason,plan.executionBlockedReason);
  } finally {store.close();rmSync(directory,{recursive:true});}
});

test('a configured pause reason is not enforced without the explicit opt-in',()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-optin-'));settings(directory,directory,'Fixture reconciliation pending');
  try {
    process.env.BENCHMARK_ENFORCE_MUTATIONS_PAUSE='';
    assert.equal(new Config().mutationsPausedReason,'');
    process.env.BENCHMARK_ENFORCE_MUTATIONS_PAUSE='true';
    assert.equal(new Config().mutationsPausedReason,'Fixture reconciliation pending');
  } finally {settings(directory,directory,'');rmSync(directory,{recursive:true});}
});

test('detail and history backfill objectives from retained audit files and refresh for new decisions',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-objective-flow-'));settings(directory,directory);
  const store=new Store(':memory:');const service=new CampaignService(new Config(),store);(service as any).tick=async()=>{};
  try {
    const plan:Plan={id:randomUUID(),...input,request:'Fixed Beta beta=1.0 (opaque request)',mode:'serial',summary:'Opaque plan annotation',context:'',applications:['vllm'],cases:[],version:null,limitations:[],createdAt:'2026-10-08T17:03:00Z',llmStatus:'unavailable'};
    store.savePlan(plan);
    const queued=service.queue({planId:plan.id});assert.equal(queued.objectiveSummary.decisionCount,0);assert.equal(queued.objectiveSummary.state,'pending');
    const saved=store.run(queued.id)!;saved.status='completed';saved.startedAt='2026-10-08T17:03:55.604Z';saved.finishedAt='2026-10-08T17:16:54.282Z';store.saveRun(saved);
    const out=join(directory,'runs',saved.id);mkdirSync(join(out,'raw'),{recursive:true});
    const trace=JSON.parse(readFileSync(join(project,'apps/api/test/fixtures/objective-legacy.json'),'utf8'));
    const audit=join(out,'raw/audit-vllm.jsonl');writeFileSync(audit,JSON.stringify(trace)+'\n');
    const before=readFileSync(audit);
    const detail=await service.detail(saved.id);const history=await service.list();
    assert.equal(detail.request,plan.request);assert.equal(detail.objectiveSummary.decisionCount,1);
    assert.deepEqual(detail.objectiveSummary.modes,[{objectiveMode:'legacy-runtime-lambda-v1',count:1}]);
    assert.deepEqual(detail.objectiveSummary.coefficients,[{objectiveMode:'legacy-runtime-lambda-v1',source:'lambdaRuntimeLegacy',min:0,max:0,count:1}]);
    assert.deepEqual(history.runs[0].objectiveSummary,detail.objectiveSummary);assert.deepEqual(readFileSync(audit),before);
    const fixed={...trace,decisionTrace:{...trace.decisionTrace,decisionID:'synthetic-fixed',economicsVersion:'fixed-disruption-aversion-v1',effectiveCostCoefficient:1,costCoefficientSource:'disruptionAversion'}};
    writeFileSync(audit,JSON.stringify(trace)+'\n'+JSON.stringify(fixed)+'\n');
    const updated=await service.detail(saved.id);assert.equal(updated.objectiveSummary.decisionCount,2);assert.equal(updated.objectiveSummary.modes.length,2);
    assert.deepEqual((await service.list()).runs[0].objectiveSummary,updated.objectiveSummary);
  } finally {await service.onModuleDestroy();rmSync(directory,{recursive:true});}
});

function objectivePlan(): Plan {
  return { id:randomUUID(), ...input, mode:'serial', summary:'Retained objective fixture', context:'', applications:['vllm'],
    cases:[], version:null, limitations:[], createdAt:'2026-10-08T17:03:00Z', llmStatus:'unavailable' };
}
function objectiveRun(plan: Plan, status: Run['status'] = 'completed'): Run {
  return { id:randomUUID(), plan, status, createdAt:plan.createdAt, startedAt:'2026-10-08T17:03:55.604Z',
    finishedAt:status === 'completed' ? '2026-10-08T17:16:54.282Z' : undefined,
    progress:{total:0,completed:0}, cases:[], artifacts:[], errors:[], version:null, events:[] };
}
function retainObjective(directory: string, run: Run) {
  const out=join(directory,'runs',run.id);mkdirSync(join(out,'raw'),{recursive:true});
  const trace=JSON.parse(readFileSync(join(project,'apps/api/test/fixtures/objective-legacy.json'),'utf8'));
  writeFileSync(join(out,'raw/audit-vllm.jsonl'),JSON.stringify(trace)+'\n');
}
async function bounded<T>(promise: Promise<T>, milliseconds=1000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try { return await Promise.race([promise, new Promise<never>((_, reject) => {
    timer=setTimeout(()=>reject(new Error('List waited for the raw scan')),milliseconds);
  })]); } finally { if(timer)clearTimeout(timer); }
}

test('authenticated GET /api/runs returns before a held scan and polls reuse the same flight',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-objective-list-'));settings(directory,directory);
  const app=await bootstrap();const service=app.get(CampaignService), store=app.get(Store);
  let release!:()=>void, started!:()=>void;
  const held=new Promise<void>(done=>{release=done;}), scanning=new Promise<void>(done=>{started=done;});
  const reader=(service as any).objectives;
  const original=reader.summarize.bind(reader);
  const scan=mock.method(reader,'summarize',async(...args:unknown[])=>{started();await held;return original(...args);});
  try {
    const plan=objectivePlan(), run=objectiveRun(plan);store.savePlan(plan);store.insertRun(run);retainObjective(directory,run);
    const base=`http://127.0.0.1:${app.getHttpServer().address().port}`, headers=await login(base);
    const list=async()=>{const response=await fetch(base+'/api/runs',{headers});assert.equal(response.status,200);return response.json() as Promise<any>;};
    assert.equal((await bounded(list())).runs[0].objectiveSummary.state,'calculating');
    await bounded(scanning);
    assert.equal((await bounded(list())).runs[0].objectiveSummary.state,'calculating');
    const detail=await bounded(service.detail(run.id),3000);
    assert.equal(detail.objectiveSummary.state,'calculating');assert.equal(scan.mock.callCount(),1);
    release();
    assert.equal((await service.detail(run.id)).objectiveSummary.decisionCount,1);
    assert.equal((await list()).runs[0].objectiveSummary.state,'ready');assert.equal(scan.mock.callCount(),1);
  } finally {release();await app.close();scan.mock.restore();rmSync(directory,{recursive:true});}
});

test('active runs are pending and defer terminal history scans until the worker is idle',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-objective-active-'));settings(directory,directory,'Offline fixture pause');
  const store=new Store(':memory:'), service=new CampaignService(new Config(),store);
  const scan=mock.method((service as any).objectives,'summarize');
  try {
    const plan=objectivePlan(), terminal=objectiveRun(plan), active=objectiveRun(plan,'running');
    store.savePlan(plan);store.insertRun(terminal);store.insertRun(active);retainObjective(directory,terminal);retainObjective(directory,active);
    const list=await bounded(service.list());
    assert.equal(list.runs.find(run=>run.id===active.id)!.objectiveSummary.state,'pending');
    assert.equal(list.runs.find(run=>run.id===terminal.id)!.objectiveSummary.state,'calculating');
    assert.equal((await service.detail(active.id)).objectiveSummary.state,'pending');
    await new Promise(done=>setTimeout(done,30));assert.equal(scan.mock.callCount(),0);
    active.status='completed';active.finishedAt=terminal.finishedAt;store.saveRun(active);
    assert.equal((await service.detail(terminal.id)).objectiveSummary.decisionCount,1);
    assert.equal(scan.mock.callCount(),1);
  } finally {await service.onModuleDestroy();scan.mock.restore();rmSync(directory,{recursive:true});}
});
