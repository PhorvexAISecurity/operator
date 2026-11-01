# Read-only collection of this registered fixture acceptance; no live data mutation.
import pathlib,json,tarfile,sys,hashlib,io,re
r=pathlib.Path('/home/hami/phorvex-benchmark')
a=r/'stage-data/live/selfserve-bot-fixture-225877a8ecb4-b1ef-r5'
s=json.loads((a/'acceptance-status.json').read_text())
assert s['state']=='PASS' and s['restoration']=='PASS' and s['phase']=='fixture'
assert {j['request'] for j in s['jobs']}=={'fixture-endpoint-600s.txt','fixture-endpoint-custom.txt'}
assert all(j['state']=='DONE' for j in s['jobs'])
files=[]
for p in a.iterdir():
 if p.is_file() and not p.is_symlink():files.append((p,'acceptance/'+p.name))
for j in s['jobs']:
 ids=[j['id']]+[x['job'] for x in j['batch']['results']]
 for i in ids:
  assert re.fullmatch('[a-f0-9]{12}',i)
  d=r/'bot/jobs'/i
  for p in d.rglob('*'):
   if p.is_file():
    assert not p.is_symlink();files.append((p,'jobs/'+i+'/'+str(p.relative_to(d))))
assert len({n for p,n in files})==len(files)
assert sum(p.stat().st_size for p,n in files)<128*1024*1024
manifest=[{'path':n,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p,n in files]
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as t:
 for p,n in files:t.add(p,arcname=n,recursive=False)
 data=(json.dumps(manifest,indent=2)+'\n').encode();info=tarfile.TarInfo('MANIFEST.json');info.size=len(data);t.addfile(info,io.BytesIO(data))
