import sys, pathlib, subprocess, json, os
repo=pathlib.Path('/workspace/operator-benchmark-stage')
sys.path.insert(0,str(repo/'benchmark/bot'))
import replay_build
out=repo/'workflow/fixes/BENCH-STAGE/evidence/engine-build'
artifacts=pathlib.Path('/workspace/.phorvex-test-tmp/stage-study-engines');artifacts.mkdir(exist_ok=True)
receipt={'schema':'phorvex-bench.engine-build.v1','build_helper_sha256':replay_build.sha256_file(repo/'benchmark/bot/replay_build.py'),'engines':{}}
for role,sha in [('base','ef94fad362dabb51469211388ef80cdfa6eee1d4'),('candidate','d552ad0c03cdc3fce8120fe8889b2efe5d55d393')]:
 src=artifacts/(role+'-source')
 replay_build.checkout(repo,sha,src)
 binary=artifacts/(role+'-brain-replay')
 digest=replay_build.build(src,sha,binary,go='/workspace/.phorvex-go/go/bin/go',toolchain='go1.26.10',cache_dir='/workspace/.phorvex-go/capture-cache',log=out/(role+'-build.log'))
 version=json.loads(subprocess.check_output([str(binary),'--version'],text=True))
 assert version['gitSHA']==sha
 receipt['engines'][role]={'source':sha,'binary':str(binary),'sha256':digest,'version':version,'toolchain':replay_build.deployed_toolchain(binary,go='/workspace/.phorvex-go/go/bin/go')}
 (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(role,digest,flush=True)
subprocess.run([sys.executable,str(artifacts/'candidate-source/benchmark/endpointv3/build.py')],env=dict(os.environ,ENDPOINT_GO='/workspace/.phorvex-go/go/bin/go'),check=True)
print('PASS',flush=True)
