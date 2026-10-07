import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Config } from '../src/config';
import { CampaignService } from '../src/campaign';
import { Store, Plan } from '../src/store';

test('graceful shutdown waits for accepted worker observation/export and persists its final state before closing SQLite',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'benchmark-shutdown-'));const root=join(directory,'benchmark');const data=join(directory,'data');
  mkdirSync(join(root,'worker'),{recursive:true});
  writeFileSync(join(root,'worker','runner.py'),`
const fs=require('node:fs');const path=require('node:path');
const out=process.argv[process.argv.indexOf('--out')+1];
const timer=setInterval(()=>{if(!fs.existsSync(path.join(out,'cancel.flag')))return;clearInterval(timer);
  setTimeout(()=>{
    for(const name of ['Phorvex_Cost_Measured_vs_Expected.xlsx','Phorvex_Tick_Action_Gates.xlsx','evidence.zip'])fs.writeFileSync(path.join(out,name),'retained-test-artifact');
    fs.writeFileSync(path.join(out,'cases.jsonl'),JSON.stringify({namespace:'voice',id:'fixed-live-case',status:'completed',outcome:'UNKNOWN',observedActuator:'quarantine'})+'\\n');
    fs.writeFileSync(path.join(out,'progress.json'),JSON.stringify({total:1,completed:1}));
    fs.writeFileSync(path.join(out,'manifest.json'),JSON.stringify({status:'cancelled',finishedAt:new Date().toISOString(),artifacts:['Phorvex_Cost_Measured_vs_Expected.xlsx','Phorvex_Tick_Action_Gates.xlsx','evidence.zip']}));
    process.exit(0);
  },120);
},10);
`);
  Object.assign(process.env,{BENCHMARK_ROOT:root,DATA_DIR:data,PYTHON:process.execPath,DASHBOARD_PASSWORD:'shutdown-unit-test-password',SESSION_SECRET:'shutdown-unit-test-secret-with-more-than-32-characters',DASHBOARD_ORIGIN:'https://dashboard.test'});
  const settings=new Config();Object.defineProperty(settings,'shutdownGraceMs',{value:5000});
  const filename=join(data,'queue.sqlite');const store=new Store(filename);const service=new CampaignService(settings,store);
  const plan:Plan={id:randomUUID(),mode:'serial',model:'gpt-6.1-sol',summary:'test',request:'test',context:'',applications:['vllm','voice','litellm','crm'],cases:[{namespace:'voice',id:'fixed-live-case'}],version:'pinned',limitations:[],createdAt:new Date().toISOString(),llmStatus:'unavailable'};
  try {
    store.savePlan(plan);service.onModuleInit();const run=service.queue({planId:plan.id});
    const started=Date.now();await service.onModuleDestroy();assert.ok(Date.now()-started>=100,'shutdown returned before the worker observation/export delay');
    const reopened=new Store(filename);
    try {
      const retained=reopened.run(run.id)!;assert.equal(retained.status,'cancelled');assert.equal(retained.progress.completed,1);assert.equal(retained.cases[0].outcome,'UNKNOWN');
      assert.equal(retained.artifacts.length,3);assert.ok(retained.workerExitedAt);assert.equal(retained.errors.length,0);
      assert.equal(reopened.claimOwner(process.pid,'replacement',()=>true),true,'scheduler ownership must release only after child completion');
    } finally {reopened.close();}
  } finally {await service.onModuleDestroy();rmSync(directory,{recursive:true});}
});
