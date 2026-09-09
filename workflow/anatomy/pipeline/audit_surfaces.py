#!/usr/bin/env python3
"""Completeness for the NON-Go surfaces: the SPA, the two images, and the external boundaries.

Every completeness check until now read Go. The dashboard's calls into the console, the
Dockerfile COPYs that compose the shipped images, and the points where our code crosses into
Kubernetes, Phoenix, Prometheus and the serving stack are all invisible to a Go call graph — so
each was drawn by hand and nothing could falsify it. These are the probes that can.

A probe is a triple: a source fact that must exist, and the relation it obliges. If the fact is
gone the probe is stale (the source changed); if the relation is gone the map is wrong. Both fail.
"""
import csv, os, re, sys
from findings import Findings
import paths

F = Findings('audit_surfaces')
HERE = os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
rels = load('RELATIONS.tsv')
drawn = {(r['from'], r['to']) for r in rels}

# (file, literal that must appear, from-node, to-node, what the crossing is)
PROBES = [
 ('dashboard-web/lib/api.ts', 'fetch(API_BASE + path', 'dashboard.api', 'console.server',
  'the SPA reads the console REST API'),
 ('dashboard-web/lib/api.ts', 'new EventSource(`${API_BASE}/api/live', 'dashboard.api', 'console.live',
  'the SPA holds an SSE stream open against /api/live'),
 ('deploy/docker/console.Dockerfile', 'COPY --from=web /web/out /app/web', 'image.console', 'dashboard',
  'the console image bakes the static SPA export'),
 ('deploy/docker/console.Dockerfile', 'COPY --from=gobuild /console /app/console', 'image.console', 'console',
  'the console image bakes the console binary'),
 ('deploy/docker/operator.Dockerfile', 'COPY --from=builder /manager', 'image.operator', 'cmd.main',
  'the operator image bakes the operator binary'),
 ('.github/workflows/ci.yml', 'deploy/docker/console.Dockerfile', 'ci.release', 'image.console',
  'CI builds and publishes the console image'),
 # --- external boundaries: where our code crosses into a system we do not own ---
 # K3 204: Phorvex never calls the Phoenix controller. It WRITES CRs through Kubernetes and
 # Phoenix watches them, so the crossing is a chain and the middle link is evidenced in the
 # vendored controller, not in our own construction of a struct.
 ('build/phoenix-extended/internal/controller/adaptivemovingtargetdefense_controller.go',
  'For(&amtdv1beta1.AdaptiveMovingTargetDefense{})', 'ext.k8s', 'ext.phoenix',
  'the Phoenix controller reconciles the AMTD CRs Phorvex wrote'),
 ('go.mod', 'replace github.com/r6security/phoenix => ../build/phoenix-extended',
  'actuator.phoenix', 'phoenix.module',
  'the Phoenix API types compiled in are THIS local fork, not upstream'),
 ('internal/actuator/phoenix.go', 'p.Client.Create(ctx, se)', 'actuator.phoenix', 'ext.k8s',
  'the SecurityEvent write crosses into the API server'),
 ('internal/ingest/prometheus.go', '/api/v1/query', 'ingest', 'ext.prometheus',
  'telemetry ingest queries Prometheus over HTTP'),
 # K3 204: one node merged four external systems with different transports, lifecycles and
 # confirmation contracts. vLLM/guardrail/KV share an HTTP transport but are distinct control
 # surfaces; MIG is not HTTP at all — it execs into a privileged node-agent through the API server.
 ('internal/actuator/gpu_stack.go', 'http.NewRequestWithContext', 'actuator.native.handlers', 'ext.vllm',
  'the serving API: ModelReady / ResetPrefixCache / adapter / drain'),
 ('internal/actuator/gpu_stack_p4set.go', 'ep.base()+ep.guardPath', 'actuator.native.handlers', 'ext.guardrail',
  'guardrail variant rotation, a different control surface on the same transport'),
 ('internal/actuator/gpu_stack_p4set.go', 'ep.base()+ep.kvInvPath', 'actuator.native.handlers', 'ext.kv_local',
  'LOCAL KV-cache invalidation — the only KV path that actually crosses'),
 ('internal/actuator/gpu_stack_p4set.go', 'r.exec(ctx, ns, pod, migAgentContaine, argv)', 'ext.k8s', 'ext.mig_agent',
  'MIG reconfiguration execs into a privileged node-agent pod, not an HTTP call'),
 ('internal/epssfeed/sync.go', 'https://api.first.org/data/v1/epss', 'epssfeed', 'ext.first_epss',
  'the EPSS feed resolves CVEs through the FIRST API'),
]

for path, needle, a, b, what in PROBES:
    if not paths.exists(path):
        F.add('SURFACE_PROBE_STALE', f'{path} no longer exists; the {a} -> {b} probe cannot be evaluated')
        continue
    text = open(paths.full(path), errors='ignore').read()
    if needle not in text:
        F.add('SURFACE_PROBE_STALE',
              f'{path} no longer contains {needle!r} — the evidence for {a} -> {b} ({what}) is gone')
    elif (a, b) not in drawn:
        F.add('SURFACE_EDGE_MISSING',
              f'{path} shows {what}, but no {a} -> {b} relation is drawn')

# ---------------------------------------------------------------------------
# THE THREE CLASSES (K3 205). A named controller is not a reachable one.
#   implemented       a real crossing happens on a shipped path
#   declared-unwired  the transport exists in source but nothing wires it
#   absent-stub       the operation returns an error unconditionally
# Anything not `implemented` MUST carry a seam, and a NEGATIVE probe must prove the absence is
# still true — otherwise a fix would silently leave the anatomy claiming a gap that closed.
NEGATIVE = {
 ('ext.k8s', 'ext.mig_agent'): [
   ('internal/actuator/nodeexec.go', 'func WireRemoteNodeExec(', 'the wiring entry point still exists'),
 ],
 ('actuator.native.handlers', 'ext.kv_local'): [
   ('internal/actuator/gpu_stack_p4set.go', 'kv MigrateRemote not built', 'MigrateRemote is still an unconditional error'),
 ],
}
nodes_ = load('NODES.tsv')
role_of = {n['id']: n['runtime_role'] for n in nodes_}
seams = load('SEAMS.tsv')
seam_edges = {s_['attaches_to'].replace(' ', '') for s_ in seams}
import subprocess
for r in rels:
    st = r.get('crossing_status', '-')
    # An unwired endpoint cannot be on an implemented crossing — that is precisely how conditional
    # dead code came to look like a runtime path.
    if st == 'implemented' and 'unwired' in (role_of.get(r['from']), role_of.get(r['to'])):
        F.add('CROSSING_UNRECORDED',
              f'{r["from"]}->{r["to"]} is marked implemented but an endpoint is unwired')
    if st in ('-', 'implemented'): continue
    edge = f'{r["from"]}->{r["to"]}'
    if edge not in seam_edges:
        F.add('CROSSING_UNRECORDED',
              f'{edge} is {st} but no seam records the negative space')
    for f_, needle, why in NEGATIVE.get((r['from'], r['to']), []):
        if needle not in open(paths.full(f_), errors='ignore').read():
            F.add('CROSSING_STALE', f'{edge} is claimed {st} but {f_} no longer shows {why}')

# WireRemoteNodeExec having zero callers is the whole basis of the declared-unwired claim; if a
# caller appears the boundary became real and the anatomy must stop calling it unwired.
callers = subprocess.run(['grep','-rn','WireRemoteNodeExec','--include=*.go', paths.MODULE],
                         capture_output=True, text=True).stdout.strip().split('\n')
callers = [c for c in callers if c and '_test.go' not in c and 'func WireRemoteNodeExec' not in c
           and not c.split(':', 2)[-1].strip().startswith('//')]
if callers:
    F.add('CROSSING_STALE',
          f'WireRemoteNodeExec now has {len(callers)} caller(s) — ext.mig_agent may no longer be unwired: {callers[0][:110]}')

print(f'crossing classes: '
      f'{sum(1 for r in rels if r.get("crossing_status")=="implemented")} implemented, '
      f'{sum(1 for r in rels if r.get("crossing_status")=="declared-unwired")} declared-unwired, '
      f'{sum(1 for r in rels if r.get("crossing_status")=="absent-stub")} absent-stub')
print(f'surface probes: {len(PROBES)} '
      f'({sum(1 for p in PROBES if p[3].startswith("ext."))} external boundaries, '
      f'{sum(1 for p in PROBES if "Dockerfile" in p[0] or "ci.yml" in p[0])} composition/release, '
      f'{sum(1 for p in PROBES if p[0].startswith("dashboard-web"))} product surface)')
F.report('every non-Go surface fact still holds and its relation is drawn')
