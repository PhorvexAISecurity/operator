"""Read only: selected grant and image-layer inventory; no URL/token output."""
import datetime
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

CTX='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
out={'read_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
command=['kubectl','--context',CTX,'get','configmap','staging-phorvex-console-grants','-n','phorvex-staging','-o','json','--request-timeout=20s']
p=subprocess.run(command,capture_output=True,text=True,timeout=30)
out['grant_command']={'argv':command,'rc':p.returncode}
if p.returncode:out['grant_error']=p.stderr[-1000:]
else:
    cm=json.loads(p.stdout)
    out['grant_configmap_identity']={k:cm['metadata'].get(k)for k in ('name','namespace','uid','resourceVersion')}
    out['benchmark_grants']=[]
    out['grant_data_keys']=sorted(cm.get('data',{}))
    for key,value in cm.get('data',{}).items():
        try:g=json.loads(value)
        except ValueError:continue
        out['benchmark_grants'].extend(s for s in g.get('subjects',[]) if s.get('subject')=='system:serviceaccount:phorvex-staging:staging-brain-benchmark')
tool=Path('/home/hami/.local/bin/crane')
p=subprocess.run([str(tool),'version'],capture_output=True,text=True,timeout=10)
out['crane']={'path':str(tool),'sha256':hashlib.sha256(tool.read_bytes()).hexdigest(),'version':p.stdout.strip(),'rc':p.returncode}
layer='sha256:de185c5cb71c57ee1b64b6d9e07c09ca2e5ac17339b49fce3a19b1e12d629d7c'
command=['aws','ecr','get-download-url-for-layer','--registry-id','753556437180','--repository-name','phorvex/staging/brain','--layer-digest',layer,'--region','us-east-2','--output','json']
p=subprocess.run(command,capture_output=True,text=True,timeout=60)
out['layer_command']={'argv':command,'rc':p.returncode}
if p.returncode:out['layer_error']=p.stderr[-1000:]
else:
    url=json.loads(p.stdout)['downloadUrl']
    assert url.startswith('https://')
    with urllib.request.urlopen(url,timeout=60)as response:raw=response.read((32<<20)+1)
    assert len(raw)<=32<<20
    actual='sha256:'+hashlib.sha256(raw).hexdigest();assert actual==layer
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz')as archive:
        member=next(m for m in archive.getmembers()if m.name.lstrip('./')=='brain-replay'and m.isfile())
        assert member.size<=256<<20
        binary=archive.extractfile(member).read()
    out['native_companion_layer']={'layer_digest':layer,'verified_layer_sha256':actual,'compressed_bytes':len(raw),'member_name':member.name,'binary_bytes':len(binary),'binary_sha256':hashlib.sha256(binary).hexdigest(),'storage':'memory only; no remote binary installation','actual_runtime_version_evidence':'raw-selected.json pods[].native_replay_version'}
print(json.dumps(out,sort_keys=True))
