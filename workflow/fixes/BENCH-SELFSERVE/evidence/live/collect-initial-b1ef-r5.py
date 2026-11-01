import pathlib,json,tarfile,sys,hashlib,io
r=pathlib.Path('/home/hami/phorvex-benchmark')
a=r/'stage-data/live/selfserve-bot-initial-225877a8ecb4-b1ef-r5'
s=json.loads((a/'acceptance-status.json').read_text());assert s['state']=='PASS' and s['restoration']=='PASS'
files=[]
for p in a.iterdir():
 if p.is_file() and not p.is_symlink(): files.append((p,'acceptance/'+p.name))
for j in s['jobs']:
 ids=[j['id']]+[x['job'] for x in j['batch']['results']]
 for i in ids:
  d=r/'bot/jobs'/i
  for p in d.rglob('*'):
   if p.is_file():
    assert not p.is_symlink();files.append((p,'jobs/'+i+'/'+str(p.relative_to(d))))
ex=r/'stage-data/mathlab/experiments/88aa343c-e701-4d37-ad62-22b88bb66125'
req=json.loads((ex/'request.json').read_text());assert req['title']=='Telegram 18e300921b28: P-FEA-006 1.0 1.2 1.5'
for p in ex.rglob('*'):
 if p.is_file():
  assert not p.is_symlink();files.append((p,'experiment/'+str(p.relative_to(ex))))
assert sum(p.stat().st_size for p,n in files)<64*1024*1024
manifest=[{'path':n,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p,n in files]
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as t:
 for p,n in files:t.add(p,arcname=n,recursive=False)
 data=(json.dumps(manifest,indent=2)+'\n').encode();info=tarfile.TarInfo('MANIFEST.json');info.size=len(data);t.addfile(info,io.BytesIO(data))
