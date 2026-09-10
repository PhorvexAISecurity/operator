#!/usr/bin/env python3
"""EFFECT_MATRIX.tsv — generated call inventory + CURATED per-branch semantics.

Every column is labelled by how it was derived. Regex can enumerate calls and pair a
MutationKind with the Emitted in its own literal; it cannot read what a branch means.
The `credits_when_stack_unreachable` and `security_goal_confirmation` columns are curated
from source with anchors, and marked as such.
"""
import re, json, csv

inv = json.load(open('CALL_INVENTORY.json'))

# --- CURATED: read per branch from source, one entry per control-plane call ---
LEDGER = {
 'rotate':'internal/runner/manager.go:1088 — trackRotationWithFloor; falls back to OutcomeEmitted if tracking fails',
 'identity-rotate':'internal/runner/manager.go:1093 — OutcomeCompleted from declared zero replica impact',
 'route-rotate':'internal/runner/manager.go:1093 — OutcomeCompleted from declared zero replica impact',
}
MISSING = {
 'rotate':'internal/runner/manager.go:1088 observes replacement and recovery; no check that attacker state is gone',
 'kv-reset':'internal/actuator/handlers_ai.go:305 — epoch stamped after the flush; the cache is never re-read',
 'guardrail-rotate':'internal/actuator/handlers_ai_p4set.go:351 — variant persisted; never read back from the service',
 'adapter-rotate':'internal/actuator/handlers_ai_p4set.go:229 — no adapter-list re-read after eviction',
 'request-drain':'internal/actuator/handlers_ai_p4set.go:281 — aborted count recorded; in-flight state not verified',
 'kv-migrate-invalidate':'internal/actuator/handlers_ai_p4set.go:424 — remote half is a deferred stub, credited anyway',
 'quarantine':'internal/actuator/handlers_k8s.go:122 — NetworkPolicy created; existence never re-read',
}
CURATED = {
 'kv-reset': dict(proto='internal/actuator/handlers_ai.go:283 ResetPrefixCache — nil means flushed', credits='NO — errStackUnreachable returns Emitted:false with a fail-closed comment '
                  'naming the false-success bug it fixes (handlers_ai.go:288-298)',
                  sec='PROTOCOL_ACKNOWLEDGED — the stack confirms the flush; not re-read'),
 'guardrail-rotate': dict(proto='internal/actuator/handlers_ai_p4set.go:330 ApplyVariant — nil means applied', credits='NO — unreachable returns Emitted:false; if the K8s persist fails the '
                  'live variant is restored so runtime and cluster cannot diverge (handlers_ai_p4set.go:331-357)',
                  sec='PROTOCOL_ACKNOWLEDGED — code calls this a confirmed live transition'),
 'adapter-rotate': dict(proto='internal/actuator/handlers_ai_p4set.go:170 UnloadAdapter — nil or errAdapterAbsent means evicted', credits='NO — unload success or errAdapterAbsent counts as the eviction goal; '
                  'the poison marker clears only then (handlers_ai_p4set.go:167-232)',
                  sec='PROTOCOL_ACKNOWLEDGED — eviction acknowledged; optional clean-reload check'),
 'kv-migrate-invalidate': dict(proto='internal/actuator/handlers_ai_p4set.go:399 InvalidateLocal — nil means local cache invalidated; MigrateRemote always errors', credits='SPLIT — local invalidation is fail-closed (an error aborts); '
                  'the REMOTE half is credited regardless: MigrateRemote always returns an error '
                  '(gpu_stack_p4set.go:193-196, DEFERRED by design) and the handler appends that error '
                  'text to the note, stamps the epoch and returns Emitted:true '
                  '(handlers_ai_p4set.go:420-437)',
                  sec='PARTIAL — local: PROTOCOL_ACKNOWLEDGED when InvalidateLocal returns nil; '
                      'remote: NOT_IMPLEMENTED / NOT_CONFIRMED. Poisoned KV can remain on remote '
                      'decode workers while the action reports success'),
 'request-drain': dict(proto='internal/actuator/handlers_ai_p4set.go:271 DrainRequests — returns an aborted count; unreachable sets pending', credits='YES — stack unreachable sets pending=true but the K8s stop-admit is real, '
                  'so the handler still returns Emitted:true (handlers_ai_p4set.go:270-287)',
                  sec='PARTIAL — admits stopped in K8s; in-flight abort may be unperformed and is '
                      'noted [PENDING-GPU-VALIDATION]'),
 'mig-rebind': dict(proto='internal/actuator/handlers_ai.go:215 Available/DrainRequests/Repartition — differing failure semantics per call', credits='MIXED — DrainRequests pending and Repartition failure have different '
                  'semantics and cannot share one statement',
                  sec='PROTOCOL_ACKNOWLEDGED (partial) — per-call outcomes differ; needs per-op review'),
 'warm-swap': dict(proto='internal/actuator/handlers_ai.go:57 ModelReady — a readiness PROBE gating promotion, not an effect acknowledgement', credits='N/A — control-plane calls are readiness PROBES (ModelReady/DrainRequests) '
                  'reached via warmCutover->pickReadyShadow->shadowModelReady, not the mutation',
                  sec='NONE — probes gate promotion; nothing confirms the swap achieved its goal'),
 'model-shard-replace': dict(proto='internal/actuator/handlers_ai.go:57 ModelReady — probe only, as warm-swap', credits='N/A — same probe chain as warm-swap',
                  sec='NONE — probes gate promotion only'),
 'rotate': dict(credits='N/A — no control-plane call',
                  sec='PARTIAL — UID replacement, readiness and disruption recovery ARE observed '
                      '(trackRotationWithFloor); that attacker state is gone is inferred from '
                      'replacement, not measured'),
}
DEFAULT = dict(credits='N/A — no control-plane call',
               sec='NONE — K8s write acknowledgement only')

rows = []
for act, v in inv.items():
    kinds = [k.split('@') for k in v['mutation_kind_literals']]
    emits = [e.split('@') for e in v['emitted_literals']]
    succ, other = set(), set()
    for kv, kl in kinds:
        f, l = kl.rsplit(':', 1)
        near = [ev for ev, el in emits if el.rsplit(':', 1)[0] == f
                and abs(int(el.rsplit(':', 1)[1]) - int(l)) <= 2]
        (succ if near and near[0] == 'true' else other).add(kv)
    c = CURATED.get(act, DEFAULT)
    rows.append(dict(
        action=act, handler=v['handler'],
        k8s_call_sites_GEN=' '.join(v['k8s_call_sites']) or 'none',
        control_plane_call_sites_GEN=' '.join(v['control_plane_call_sites']) or 'none',
        success_mutation_kind_GEN='/'.join(sorted(succ)) or '?',
        other_branch_kinds_GEN='/'.join(sorted(other)) or 'NO_OTHER_BRANCH',
        functions_visited_GEN=len(v['functions_visited']),
        inventory_status_GEN=v['status'],
        target_resource_operation_GEN=('pod/' + ' '.join(sorted({x.split('@')[0] for x in v['k8s_call_sites']}))
                                       + (' | stack:' + ' '.join(sorted({x.split('@')[0] for x in v['control_plane_call_sites']}))
                                          if v['control_plane_call_sites'] else '')),
        write_command_ack_GEN=('K8s API accepted the write (' +
                               ' '.join(sorted({x.split('@')[0] for x in v['k8s_call_sites']})) + ')')
                              if v['k8s_call_sites'] else 'none',
        protocol_effect_ack_CURATED=c.get('proto', 'none — no control-plane call'),
        availability_recovery_observation=('internal/runner/manager.go:1088 trackRotationWithFloor — '
            'UID replacement, readiness and disruption recovery' if act == 'rotate' else 'none'),
        runner_ledger_outcome=LEDGER.get(act, 'internal/runner/manager.go:1095 — OutcomeEmitted '
                                              '(emitted_outcome_unobserved)'),
        credits_when_stack_unreachable_CURATED=c['credits'],
        postcondition_readback='NO_GENERATOR-DETECTED_K8S_GET_AFTER_MUTATION '
                               '(call order not proven; non-Get protocol reads not counted)',
        security_goal_confirmation_CURATED=c['sec'],
        missing_confirmation_CURATED=c.get('missing', MISSING.get(act, 'no per-action confirmation contract '
            'is evidenced in source; internal/slo/bound.go is an AVAILABILITY bound and is not cited as one'))))

with open('EFFECT_MATRIX.tsv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter='\t')
    w.writeheader(); w.writerows(rows)

import collections
c = collections.Counter(r['security_goal_confirmation_CURATED'].split(' ')[0] for r in rows)
print(f"{'action':24}{'success kind':16}{'ctl-plane':30}{'credits?':10}{'security goal'}")
for r in rows:
    print(f"{r['action']:24}{r['success_mutation_kind_GEN']:16}"
          f"{' '.join(sorted({c.split('@')[0] for c in r['control_plane_call_sites_GEN'].split()}))[:29]:30}"
          f"{r['credits_when_stack_unreachable_CURATED'].split(' ')[0]:10}"
          f"{r['security_goal_confirmation_CURATED'].split(' ')[0]}")
print('\nsecurity-goal: ' + ' · '.join(f'{k} {v}' for k, v in c.most_common()))
print('columns marked _GEN are generated; _CURATED are read from source by hand with anchors')
