"""Build the reference CLI from the same endpoint kernel used by brain-replay."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
repo = root.parents[1]
go = os.environ.get('ENDPOINT_GO', 'go')
sources = sorted([repo/'phorvex/go.mod', repo/'phorvex/go.sum',
                  *(repo/'phorvex/internal/cost/endpoint').glob('*.go'),
                  *(repo/'phorvex/cmd/endpoint-v3').glob('*.go')])
hashes = {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
target = root/'bin/endpoint-v3'
target.parent.mkdir(exist_ok=True)
env = dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off')
subprocess.run([go, 'build', '-trimpath', '-buildvcs=false', '-o', str(target), './cmd/endpoint-v3'],
               cwd=repo/'phorvex', env=env, check=True)
assert hashes == {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}, 'source changed during build'
identity = {'schema':'phorvex-bench.endpoint-build.v2', 'sources':hashes,
            'kernel':'phorvex/internal/cost/endpoint',
            'binary_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
            'compiler':subprocess.check_output([go, 'version'], env=env, text=True).strip()}
(root/'BUILD.json').write_text(json.dumps(identity, indent=2)+'\n')
print(json.dumps({'binary':str(target), 'binary_sha256':identity['binary_sha256'], 'source_files':len(hashes)}))
