"""Build the offline Go runner and bind its binary to the exact source files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
go = os.environ.get('ENDPOINT_GO', 'go')
sources = sorted([root/'go.mod', *root.rglob('*.go')])
hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
target = root/'bin/endpoint-v3'
target.parent.mkdir(exist_ok=True)
env = dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off')
subprocess.run([go, 'build', '-trimpath', '-buildvcs=false', '-o', str(target), './cmd/endpoint-v3'],
               cwd=root, env=env, check=True)
assert hashes == {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}, 'source changed during build'
identity = {'schema':'phorvex-bench.endpoint-build.v1', 'sources':hashes,
            'binary_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
            'compiler':subprocess.check_output([go, 'version'], env=env, text=True).strip()}
(root/'BUILD.json').write_text(json.dumps(identity, indent=2)+'\n')
print(json.dumps({'binary':str(target), 'binary_sha256':identity['binary_sha256'], 'source_files':len(hashes)}))
