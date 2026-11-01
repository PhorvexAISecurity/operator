import pathlib,json,tarfile,sys,hashlib,io
r=pathlib.Path('/home/hami/phorvex-benchmark')
a=r/'stage-data/live/selfserve-bot-initial-225877a8ecb4'
s=json.loads((a/'acceptance-status.json').read_text());assert s['state']=='FAIL' and s['restoration']=='PASS'
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
assert sum(p.stat().st_size for p,n in files)<16*1024*1024
manifest=[{'path':n,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p,n in files]
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as t:
 for p,n in files:t.add(p,arcname=n,recursive=False)
 data=(json.dumps(manifest,indent=2)+'\n').encode();info=tarfile.TarInfo('MANIFEST.json');info.size=len(data);t.addfile(info,io.BytesIO(data))
