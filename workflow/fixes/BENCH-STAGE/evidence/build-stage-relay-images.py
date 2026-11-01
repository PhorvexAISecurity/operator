#!/usr/bin/env python3
"""Build reviewed stage relay binaries; never publishes or deploys by itself."""
import argparse, hashlib, json, os, pathlib, subprocess, tarfile, time
p=argparse.ArgumentParser();p.add_argument('--checkout',required=True);p.add_argument('--source',required=True);p.add_argument('--output',required=True);p.add_argument('--go',required=True);a=p.parse_args()
root=pathlib.Path(a.checkout).resolve();out=pathlib.Path(a.output).resolve();go=pathlib.Path(a.go).resolve()
def git(*args):return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
assert git('rev-parse','HEAD')==a.source and len(a.source)==40
assert not git('status','--porcelain','--untracked-files=all'), 'clean reviewed source required'
assert subprocess.check_output([str(go),'version'],text=True).strip()=='go version go1.26.10 linux/amd64'
assert not out.exists(), 'fresh output directory required'
out.mkdir(parents=True,mode=0o700); bins=out/'bin';bins.mkdir()
env={'PATH':str(go.parent)+':/usr/bin:/bin','LANG':'C.UTF-8','GOTOOLCHAIN':'local','GOPATH':'/workspace/.phorvex-go/gopath','GOCACHE':'/workspace/.phorvex-go/capture-cache','TMPDIR':'/workspace/.phorvex-test-tmp','GOTMPDIR':'/workspace/.phorvex-test-tmp','GOMAXPROCS':'2','GOFLAGS':'-p=2','CGO_ENABLED':'0','GOOS':'linux','GOARCH':'amd64'}
version='stage-benchmark-relay';identity='-s -w -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA='+a.source+' -X github.com/phorvex/phorvex/internal/buildinfo.linkedVersion='+version
commands=[]
def run(args):
 commands.append(args);print(json.dumps({'command':args}),flush=True)
 subprocess.run(args,cwd=root/'phorvex',env=env,check=True,timeout=600)
run([str(go),'run','./cmd/pendingcheck','-root','.','-inventory','PENDING-INVENTORY.md'])
targets={'manager':('./cmd',True),'service':('./cmd/brain',True),'brain-replay':('./cmd/brain-replay',True),'phorvex-recovery':('./cmd/recovery',False),'phorvex-mig-allocation-helper':('./cmd/mig-allocation-helper',False),'loss-observer':('./cmd/loss-observer',False),'current-inventory-observer':('./cmd/current-inventory-observer',False),'persistence-observer':('./cmd/persistence-observer',False),'cost-budget-admin':('./cmd/cost-budget-admin',False)}
for name,(pkg,linked) in targets.items():run([str(go),'build','-trimpath','-ldflags='+ (identity if linked else '-s -w'),'-o',str(bins/name),pkg])
receipt={'source_revision':a.source,'clean_tree':True,'go_version':'go1.26.10','platform':'linux/amd64','cgo_enabled':False,'release_version':version,'runtime_base':'gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99','builder_source':'docker.io/library/golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c','recipe':'User-level static build matching reviewed Dockerfiles, OCI composition recorded separately; isolated stage development image, not official main release','commands':commands,'env':env,'binaries':{},'layers':{}}
for name in targets:
 f=bins/name; meta=subprocess.check_output([str(go),'version','-m',str(f)],text=True);(out/(name+'.buildinfo.txt')).write_text(meta)
 receipt['binaries'][name]={'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'size':f.stat().st_size}
for name in ('service','manager','brain-replay'):
 args=[str(bins/name),'--version' if name!='brain-replay' else '-version']
 value=json.loads(subprocess.check_output(args,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},text=True));assert value['gitSHA']==a.source
 receipt['binaries'][name]['embedded_version']=value
stamp=int(git('show','-s','--format=%ct','HEAD'))
for component,names in {'brain':['service','brain-replay'],'manager':[x for x in targets if x!='service']}.items():
 layer=out/(component+'-binaries.tar')
 with tarfile.open(layer,'w',format=tarfile.PAX_FORMAT) as tar:
  for name in sorted(names):
   f=bins/name;info=tarfile.TarInfo(name);info.mode=0o755;info.size=f.stat().st_size;info.uid=info.gid=0;info.mtime=stamp
   with f.open('rb') as stream:tar.addfile(info,stream)
 receipt['layers'][component]={'sha256':hashlib.sha256(layer.read_bytes()).hexdigest(),'files':sorted(names),'size':layer.stat().st_size}
assert not git('status','--porcelain','--untracked-files=all')
(out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'result':'PASS','source_revision':a.source,'output':str(out)}),flush=True)
