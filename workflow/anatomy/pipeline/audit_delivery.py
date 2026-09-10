#!/usr/bin/env python3
"""Is an executable actually AVAILABLE at runtime? Compose the image AND the deployment.

I claimed Trivy was absent because `operator.Dockerfile` COPYs only `/manager`. K3 showed the
Helm chart injects it: an `aquasec/trivy` initContainer copies the binary into a shared emptyDir
that the feed container mounts, with the path passed as `--epss-feed-trivy`. The claim was false
because the audit stopped at the image boundary and treated it as the whole delivery path — the
same shape as scoping the anatomy to the Go module and calling it the anatomy.

So availability is decided by BOTH mechanisms, and each is verified from source anchors:
  IMAGE       a final-stage COPY installs the binary
  INJECTED    an initContainer writes it into a volume the consuming container mounts, and the
              consuming container is told where to find it
An executable that neither provides is a genuine gap and MUST be a recorded seam.
"""
import csv, os, re, sys
from findings import Findings
import paths

F = Findings('audit_delivery')
HERE = os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
nodes, rels, seams = load('NODES.tsv'), load('RELATIONS.tsv'), load('SEAMS.tsv')
drawn = {(r['from'], r['to']) for r in rels}
# Containment is already expressed by NODES.tsv `parent` (bin.kubectl's parent IS image.console).
# Requiring a duplicate relation would state the same fact twice, and two statements of one fact
# can disagree. A parent link therefore satisfies a delivery relation.
parent_of = {n['id']: n['parent'] for n in nodes}
def linked(a, b): return (a, b) in drawn or parent_of.get(b) == a
seam_targets = {s['attaches_to'].split('->')[-1].strip() for s in seams}

# binary node -> (mechanism, [(file, needle) ...], [required relations])
# Every needle is a fact that must still be in the source; every relation must still be drawn.
PROVISIONING = {
 'bin.phorvex_cli': ('IMAGE', [
    ('deploy/docker/console.Dockerfile', 'COPY --from=gobuild /phorvex /data/phorvex/bin/phorvex.exe')],
    [('image.console', 'bin.phorvex_cli')]),
 'bin.harness': ('IMAGE', [
    ('deploy/docker/console.Dockerfile', 'COPY --from=harnessbuild /harness /data/build/test-harness/bin/harness.exe')],
    [('image.console', 'bin.harness')]),
 'bin.kubectl': ('IMAGE', [
    ('deploy/docker/console.Dockerfile', 'COPY --from=kubectl /kubectl /usr/local/bin/kubectl')],
    [('image.console', 'bin.kubectl')]),
 'bin.trivy': ('INJECTED', [
    ('charts/phorvex/templates/epss-feed.yaml', 'initContainers'),
    ('charts/phorvex/templates/epss-feed.yaml', 'cp /usr/local/bin/trivy /tools/trivy'),
    ('charts/phorvex/templates/epss-feed.yaml', 'name: trivy-bin'),
    ('charts/phorvex/templates/epss-feed.yaml', '--epss-feed-trivy='),
    ('charts/phorvex/values.yaml', 'trivyPath: /tools/trivy')],
    [('image.trivy', 'vol.trivy_bin'), ('vol.trivy_bin', 'epssfeed')]),
}

for n in nodes:
    if not n['id'].startswith('bin.'): continue
    b = n['id']
    if b not in PROVISIONING:
        # Not provisioned by any known mechanism. That is only acceptable as a recorded gap.
        if b not in seam_targets:
            F.add('DELIVERY_UNPROVISIONED',
                  f'{b} is exec\'d but no image COPY or deployment injection provides it, '
                  f'and no seam records the gap')
        continue
    mech, facts, need = PROVISIONING[b]
    for f_, needle in facts:
        if not paths.exists(f_):
            F.add('DELIVERY_EVIDENCE_STALE', f'{b} [{mech}]: {f_} no longer exists'); continue
        if needle not in open(paths.full(f_), errors='ignore').read():
            F.add('DELIVERY_EVIDENCE_STALE',
                  f'{b} [{mech}]: {f_} no longer contains {needle!r} — the availability claim is unsupported')
    for a, c in need:
        if not linked(a, c):
            F.add('DELIVERY_EDGE_MISSING', f'{b} [{mech}]: the {a} -> {c} delivery relation is not drawn')
    if b in seam_targets:
        F.add('DELIVERY_FALSE_GAP',
              f'{b} is recorded as an absence seam but {mech} provisioning is verified in source — '
              f'exactly the false claim this audit exists to prevent')

prov = {b: m for b, (m, _, _) in PROVISIONING.items()}
print(f'binaries: {len([n for n in nodes if n["id"].startswith("bin.")])}   '
      f'provisioned by image: {sum(1 for m in prov.values() if m=="IMAGE")}   '
      f'injected at deploy time: {sum(1 for m in prov.values() if m=="INJECTED")}   '
      f'recorded gaps: {len([n for n in nodes if n["id"].startswith("bin.") and n["id"] in seam_targets])}')
print('an image-only check would call the injected ones absent; that is the mistake this prevents')
F.report('every exec\'d binary is provisioned by a verified mechanism or is a recorded gap')
