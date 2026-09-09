#!/usr/bin/env python3
"""Mutation test. A green check is worthless unless corrupting the data makes it red — and,
K3's correction, unless it goes red FOR THE RIGHT REASON.

The previous harness counted any nonzero exit as "caught". A NameError therefore scored as a
successful catch, and one literally did: `audit_reachability.py` appended to `rel_findings`
before the list existed, so the `tool edge pollutes common` mutation crashed the audit and the
crash was reported as a pass. Two of the five checks it claimed to verify were vacuous.

So each mutation now names the diagnostic code it expects, and four outcomes are distinguished:
  CAUGHT      nonzero exit, no traceback, and the expected FINDING code on stdout
  WRONG-CODE  it failed, but for some other reason — the check under test may still be vacuous
  CRASH       the tool raised; a crash proves nothing and is never a pass
  MISSED      exit 0: the invariant is not enforced at all
A self-test at the end proves the harness itself reports CRASH rather than CAUGHT.
"""
import csv, subprocess, shutil, sys, os, tempfile, json

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ['NODES.tsv','RELATIONS.tsv','SEAMS.tsv','INTENTIONAL_BOUNDARIES.tsv',
         'EFFECT_MATRIX.tsv','ANCHOR_FINGERPRINTS.tsv','SURFACES.tsv',
         'OPERATION_MATRIX.tsv','OPERATIONS_CURATED.tsv']

def load(p):
    with open(p, newline='') as f: r = list(csv.DictReader(f, delimiter='\t'))
    return r, list(r[0].keys())

def save(p, rows, hdr):
    with open(p, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=hdr, delimiter='\t'); w.writeheader(); w.writerows(rows)

def run(tool):
    r = subprocess.run([sys.executable, tool], cwd=HERE, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def classify(expect, rc, out, err):
    if 'Traceback' in err or 'SyntaxError' in err: return 'CRASH'
    if rc == 0:                                    return 'MISSED'
    if f'FINDING {expect}' in out:                 return 'CAUGHT'
    return 'WRONG-CODE'

# ---------------------------------------------------------------- mutations
def dup_relation(rows, hdr): rows.append(dict(rows[0]))
def bad_endpoint(rows, hdr): rows[0]['to'] = 'does.not.exist'
def prose_anchor(rows, hdr): rows[0]['anchor'] = 'somewhere in the runner'
def bad_line(rows, hdr):
    p = rows[0]['anchor'].split(':')[0]; rows[0]['anchor'] = f'{p}:999999 — bogus'
def bad_scope(rows, hdr): rows[0]['engine_scope'] = 'MAYBE'
def orphan_parent(rows, hdr):
    for r in rows:
        if r['parent']: r['parent'] = 'ghost'; break
def unassign_package(rows, hdr):
    for r in rows:
        if r['id'] == 'audit': r['packages_or_files'] = ''; break
def handler_one_mode(rows, hdr):
    for r in rows:
        if r['parent'] == 'actuator.native.handlers' and r['runtime_role'] == 'production':
            r['deployment_mode'] = 'optional-native'; break
def drop_p0_edge(rows, hdr):
    for i, r in enumerate(rows):
        if (r['from'], r['to']) == ('cmd.main','decision.p0'): rows.pop(i); break
def flip_ingest_graph(rows, hdr):
    for r in rows:
        if (r['from'], r['to']) == ('ingest','graph'): r['engine_scope'] = 'NONE'; break
def seam_prose(rows, hdr): rows[0]['negative_evidence'] = 'it is just missing'
def boundary_prose(rows, hdr): rows[0]['contract_evidence'] = 'by design'
def drop_matrix_col(rows, hdr):
    hdr.remove('security_goal_confirmation_CURATED')
    for r in rows: r.pop('security_goal_confirmation_CURATED', None)
def symbol_child_no_line(rows, hdr):
    for r in rows:
        if r['id'] == 'runner.emit': r['source_anchor'] = 'internal/runner/manager.go'; break
def sibling_mask(rows, hdr):
    """Delete a child edge while its sibling keeps one — the masking bug K3 found."""
    for i, r in enumerate(rows):
        if (r['from'], r['to']) == ('runner.assembly','metrics'): rows.pop(i); return
def retarget_native_to_router(rows, hdr):
    for r in rows:
        if (r['from'], r['to']) == ('cmd.main','actuator.native'): r['to'] = 'actuator.router'; return
def unjustified_scope(rows, hdr):
    for r in rows:
        if r['id'] == 'actionset': r['scope_justification'] = ''; return
def drop_p0_ctxprov(rows, hdr):
    """K3's circularity proof: delete the edge and the wrong label must STILL be caught,
    because the source cross-check does not read RELATIONS.tsv."""
    for i, r in enumerate(rows):
        if (r['from'], r['to']) == ('decision.p0','ctxprov'): rows.pop(i); return
def mislabel_relation_scope(rows, hdr):
    for r in rows:
        if (r['from'], r['to']) == ('decision.p0','belief'): r['engine_scope'] = 'P1'; return
def overbroad_relation_scope(rows, hdr):
    """K3 198: an overbroad BOTH on a single-engine edge used to pass — only OPPOSITE
    P0/P1 labels were rejected."""
    for r in rows:
        if (r['from'], r['to']) == ('decision.p0','belief'): r['engine_scope'] = 'BOTH'; return
def unreachable_claimed_mode(rows, hdr):
    for r in rows:
        if r['id'] == 'actuator.phoenix': r['deployment_mode'] = 'optional-native'; return
def wrong_reachable_mode(rows, hdr):
    """K3 198: a mode that IS reachable but is not the one this edge runs in. `default` is a
    real mode; the native actuator is simply never selected in it."""
    for r in rows:
        if (r['from'], r['to']) == ('runner.emit','actuator.native'): r['deployment_mode'] = 'default'; return
def tool_edge_pollutes_common(rows, hdr):
    for r in rows:
        if (r['from'], r['to']) == ('cmd.main','actuator.native'):
            r['runtime_role'] = 'production'; r['engine_scope'] = 'BOTH'; return
def branch_role_wrong(rows, hdr):
    """The error the branch roots actually found: an anchor inside runIntegrationEmit,
    a one-shot branch of cmd/main.go, labelled production."""
    for r in rows:
        if (r['from'], r['to']) == ('cmd.main','actuator.phoenix'): r['runtime_role'] = 'production'; return
def production_edge_to_unwired(rows, hdr):
    for r in rows:
        if (r['from'], r['to']) == ('console.applyfix','applier'): r['runtime_role'] = 'production'; return
def retarget_envelope_symbol(rows, hdr):
    for r in rows:
        if (r['from'], r['to']) == ('cmd.main','cost.rls'): r['to'] = 'cost.p1'; return
def drop_entrypoint_edge(rows, hdr):
    for i, r in enumerate(rows):
        if (r['from'], r['to']) == ('cmd.console','console'): rows.pop(i); return
def drift_anchor(rows, hdr):
    """v0.4.59-64 slid three anchors onto different statements and every audit passed.
    Corrupting a fingerprint stands in for the source moving underneath us."""
    for r in rows:
        if r['file'] == 'internal/actuator/phoenix.go': r['fingerprint'] = 'something else entirely'; return
    rows[0]['fingerprint'] = 'something else entirely'
def drop_handler_row(rows, hdr):
    """Narrowing the actuator side of the CRD-vocabulary relation."""
    for i, r in enumerate(rows):
        if r['parent'] == 'actuator.native.handlers' and r['id'].endswith('kv-reset'): rows.pop(i); return

def _drop(rows, a, b):
    for i, r in enumerate(rows):
        if (r['from'], r['to']) == (a, b): rows.pop(i); return
def drop_dashboard_edge(rows, hdr):
    """bus 202: the SPA's read of the console API — invisible to any Go call graph."""
    _drop(rows, 'dashboard.api', 'console.server')
def drop_image_edge(rows, hdr):
    """the Dockerfile COPY that bakes the SPA into the console image."""
    _drop(rows, 'image.console', 'dashboard')
def drop_external_edge(rows, hdr):
    """The vLLM serving crossing. This used to target actuator.phoenix -> ext.phoenix, an edge
    K3 showed does not exist: Phorvex writes CRs through Kubernetes and Phoenix watches them."""
    _drop(rows, 'actuator.native.handlers', 'ext.vllm')
def drop_exec_edge(rows, hdr):
    """the console execs the OPERATOR binary for --scan; a process boundary, not a call."""
    _drop(rows, 'console.live', 'bin.phorvex_cli')
def drop_tool_root_edge(rows, hdr):
    """leaves cmd.pendingcheck a declared entrypoint that reaches nothing."""
    _drop(rows, 'cmd.pendingcheck', 'pendinggate')
def orphan_a_node(rows, hdr):
    """leaves `redteam` reachable from no declared root."""
    _drop(rows, 'cmd.redteam', 'redteam')
def unclassify_surface(rows, hdr):
    for i, r in enumerate(rows):
        if r['path'] == 'dashboard-web': rows.pop(i); return
def break_injection_edge(rows, hdr):
    """K3 203: remove the initContainer->volume edge. An image-only check called Trivy absent;
    this proves the composed check notices when the injection path really does break."""
    _drop(rows, 'image.trivy', 'vol.trivy_bin')
def false_gap_seam(rows, hdr):
    """Record Trivy as absent when its injection is verified — the exact false claim I made."""
    rows.append({k: v for k, v in zip(hdr, (
        'trivy-absent-from-image', 'epssfeed -> bin.trivy',
        'internal/epssfeed/sync.go:394 — s.Path defaults to "/trivy"',
        'deploy/docker/operator.Dockerfile:44 — the final stage COPYs only /manager', 'gap'))})
def drop_gomod_replace_edge(rows, hdr):
    """K3 204: the fact proving THIS fork is compiled in was unpinned prose until go.mod became
    a fingerprinted anchor."""
    _drop(rows, 'actuator.phoenix', 'phoenix.module')
def drop_k8s_phoenix_link(rows, hdr):
    """The middle link of the real chain: Phorvex writes CRs, Phoenix watches them."""
    _drop(rows, 'ext.k8s', 'ext.phoenix')
def drop_guardrail_edge(rows, hdr):
    """A split external: guardrail rides the vLLM transport but is a distinct control surface."""
    _drop(rows, 'actuator.native.handlers', 'ext.guardrail')
def drop_mig_exec_edge(rows, hdr):
    """MIG is not HTTP: it execs into a privileged node-agent through the API server."""
    _drop(rows, 'ext.k8s', 'ext.mig_agent')
def drop_first_epss_edge(rows, hdr):
    _drop(rows, 'epssfeed', 'ext.first_epss')
def claim_unwired_is_implemented(rows, hdr):
    """K3 205: mark the MIG boundary implemented though WireRemoteNodeExec has zero callers —
    the exact shape of dead code looking like a runtime crossing."""
    for r in rows:
        if (r['from'], r['to']) == ('ext.k8s', 'ext.mig_agent'): r['crossing_status'] = 'implemented'; return
def drop_negative_space_seam(rows, hdr):
    """Remove the seam recording that the MIG transport is never wired."""
    for i, r in enumerate(rows):
        if r['seam'] == 'mig-node-exec-never-wired': rows.pop(i); return
def drift_gomod_anchor(rows, hdr):
    """Proof that `.mod` is genuinely in the fingerprint set, not merely accepted in prose."""
    for r in rows:
        if r['file'] == 'go.mod': r['fingerprint'] = 'replace something => somewhere/else'; return
    raise AssertionError('go.mod is NOT fingerprinted — the .mod extension never took effect')
def break_op_anchor(rows, hdr):
    """Point a quarantine operation at a line that is not that operation. The compound cell
    `pod/Create Get Update` had nowhere to be wrong; a row does."""
    for r in rows:
        if r['action_GEN'] == 'quarantine' and r['operation_GEN'] == 'Create':
            r['source_anchor_GEN'] = 'internal/actuator/handlers_k8s.go:30'; return
def unanchor_curation(rows, hdr):
    for r in rows:
        if r['acknowledgement_level_CURATED'] != 'NOT-YET-CURATED':
            r['curation_anchor_CURATED'] = '-'; return
def orphan_curation(rows, hdr):
    """A curated effect for an operation that does not exist."""
    rows.append({k: v for k, v in zip(hdr, (
        'quarantine', 'internal/actuator/handlers_k8s.go:9999', 'Patch',
        'API accepted', 'none', 'none', 'CONFIRMED', 'OutcomeEmitted', 'fabricated',
        'internal/actuator/handlers_k8s.go:1'))})
def op_implemented_on_unwired(rows, hdr):
    """The whole point of crossing_status: mig.Repartition must not read as a working effect."""
    for r in rows:
        if r['target_node_GEN'] == 'ext.mig_agent': r['crossing_status_GEN'] = 'implemented'; return
def effect_on_unreached(rows, hdr):
    """K3 207's finding: mig-rebind's Pod.Delete read `implemented` + `OutcomeEmitted` although
    the guard at :232 always fails. Scoring a would-be success path as if it happened."""
    for r in rows:
        if r['action_GEN'] == 'mig-rebind' and r['operation_GEN'] == 'Delete':
            r['runner_ledger_outcome_CURATED'] = 'OutcomeEmitted'; return
def unexplained_unreached(rows, hdr):
    for r in rows:
        if r['shipped_reachability_GEN'] != 'reachable': r['unreached_because_GEN'] = '-'; return
def reach_is_a_statement(rows, hdr):
    """The original polarity bug: a raw preceding statement stored as a precondition."""
    for r in rows:
        if r['action_GEN'] == 'quarantine' and r['operation_GEN'] == 'Create':
            r['reach_condition_GEN'] = 'ec.Client.Update(ctx, pod)'; return
def unreached_left_in_backlog(rows, hdr):
    """K3 208: an unreached row is DONE, not queued. There is no effect to curate for a path
    that cannot run."""
    for r in rows:
        if r['shipped_reachability_GEN'] != 'reachable':
            r['runner_ledger_outcome_CURATED'] = 'NOT-YET-CURATED'; return
def unreached_by_a_wired_guard(rows, hdr):
    """Proof the guarded-unreached rule is DERIVED, not a hardcoded `ec.mig()`: claim a row is
    unreached because of a guard on ext.vllm, which IS wired. (Flipping ext.mig_agent's node role
    alone does not work, and correctly so — the relation still marks it declared-unwired, and
    either signal is enough.)"""
    for r in rows:
        if r['shipped_reachability_GEN'] != 'reachable':
            r['unreached_because_GEN'] = 'if err := ec.vllm().ModelReady(ctx, ep); err != nil {'; return
def reachable_claims_na(rows, hdr):
    for r in rows:
        if r['shipped_reachability_GEN'] == 'reachable' and r['action_GEN'] == 'quarantine':
            r['acknowledgement_level_CURATED'] = 'n/a — not reached in the shipped binary'; return
def compensation_claims_success(rows, hdr):
    """K3 211: the ledger was derived from an ACTION property while success-vs-compensation is a
    BRANCH property. route-rotate's restoreRoutePodLabels ran only on the Service.Update error
    path and was scored OutcomeCompleted."""
    for r in rows:
        if r['path_class_GEN'] == 'compensation' and r['operation_GEN'] not in ('Get', 'List'):
            r['runner_ledger_outcome_CURATED'] = 'OutcomeCompleted'; return
def discarded_error_claims_ack(rows, hdr):
    """`_ = ec.Client.Update(...)` cannot report failure, so it cannot claim API acceptance."""
    for r in rows:
        if r['error_handling_GEN'] == 'DISCARDED' and r['operation_GEN'] not in ('Get', 'List'):
            r['acknowledgement_level_CURATED'] = 'API accepted'; return
def route_stamped_on_native(rows, hdr):
    """K3 214: a hybrid route on a native row scores a path that does not run — in hybrid, rotate
    and quarantine never reach the native handlers."""
    for r in rows:
        if r['surface_GEN'] == 'native-enact' and r['action_GEN'] == 'rotate':
            r['surface_GEN'] = 'hybrid'; return
def phoenix_claims_the_effect(rows, hdr):
    """Phorvex writes a CR; the Phoenix controller may or may not act. Claiming confirmation here
    is the readback seam collapsed into a success."""
    for r in rows:
        if r['surface_GEN'] == 'phoenix' and r['operation_GEN'] == 'Create':
            r['security_goal_confirmation_CURATED'] = 'CONFIRMED'; return
def rollback_claims_reachable(rows, hdr):
    """The rollback layer's only invoker is the native-demo one-shot."""
    for r in rows:
        if r['shipped_reachability_GEN'] == 'tool-only':
            r['unreached_because_GEN'] = 'reached from the operator tick path'; return
def create_if_absent_as_compensation(rows, hdr):
    """K3 215: phoenix.go:93 Create-on-NotFound is EnsurePolicy's intended create path, not an
    undo. Compensation means undoing a prior failed MUTATION; here the failed operation was a
    Get."""
    for r in rows:
        if r['surface_GEN'] == 'phoenix' and r['operation_GEN'] == 'Create':
            r['path_class_GEN'] = 'compensation'; return
def citation_to_a_comment(rows, hdr):
    """The accuracy pass found two curated cells citing COMMENT lines — the same anchor error the
    node/relation audit has caught four times, recurring in the curated layer where nothing
    checked it."""
    for r in rows:
        if r['action_GEN'] == 'rotate' and r['operation_GEN'] == 'Delete':
            r['notes_CURATED'] = 'see internal/runner/manager.go:58'; return
def readback_none_but_reads(rows, hdr):
    """A readback-NONE claim on a write that IS followed by a read of the same kind."""
    for r in rows:
        if r['action'] == 'route-rotate' and r['verb'] == 'Update':
            r['postcondition_readback'] = 'NONE — no later read confirms the resulting state'
            r['anchor'] = 'internal/actuator/handlers_k8s.go:359'; return
def seam_quote_off_by_one(rows, hdr):
    """K3 220: restore the MigrateRemote seam to :195, the COMMENT above the error string. The
    seam comment-exemption is correct and stays; what this proves is that a cell which QUOTES
    code must land on the line containing it."""
    for r in rows:
        if r['seam'] == 'kv-remote-migrate-not-built':
            r['negative_evidence'] = r['negative_evidence'].replace(
                'gpu_stack_p4set.go:196', 'gpu_stack_p4set.go:195'); return
def uninstall_binary(rows, hdr):
    """remove the seam that records redteam-rl's absence: an unrecorded gap must not pass."""
    for i, r in enumerate(rows):
        if r['seam'] == 'redteam-binary-absent-from-image': rows.pop(i); return

# (name, file, mutate, tool, expected diagnostic code)
MUTATIONS = [
 ('duplicate relation key',        'RELATIONS.tsv', dup_relation,            'validate.py', 'REL_DUPLICATE_KEY'),
 ('relation endpoint missing',     'RELATIONS.tsv', bad_endpoint,            'validate.py', 'REL_ENDPOINT_MISSING'),
 ('relation anchor is prose',      'RELATIONS.tsv', prose_anchor,            'validate.py', 'REL_ANCHOR_NONCANONICAL'),
 ('relation anchor line past EOF', 'RELATIONS.tsv', bad_line,                'validate.py', 'REL_ANCHOR_LINE_PAST_EOF'),
 ('relation scope not in vocab',   'RELATIONS.tsv', bad_scope,               'validate.py', 'REL_ENGINE_BAD'),
 ('P0 wiring edge deleted',        'RELATIONS.tsv', drop_p0_edge,            'validate.py', 'SEM_ENGINE_WIRING'),
 ('ingest->graph mis-scoped',      'RELATIONS.tsv', flip_ingest_graph,       'validate.py', 'SEM_INGEST_GRAPH'),
 ('node parent does not exist',    'NODES.tsv',     orphan_parent,           'validate.py', 'NODE_PARENT_MISSING'),
 ('package assigned to no node',   'NODES.tsv',     unassign_package,        'validate.py', 'PKG_UNASSIGNED'),
 ('handler missing hybrid mode',   'NODES.tsv',     handler_one_mode,        'validate.py', 'SEM_HANDLER_MODES'),
 ('symbol-scoped child no line',   'NODES.tsv',     symbol_child_no_line,    'validate.py', 'NODE_SYMBOL_CHILD_NO_LINE'),
 ('handler row deleted',           'NODES.tsv',     drop_handler_row,        'validate.py', 'CRD_VOCAB_EXTRA'),
 ('seam evidence is prose',        'SEAMS.tsv',     seam_prose,              'validate.py', 'SEAM_EVIDENCE_PROSE'),
 ('boundary evidence is prose',    'INTENTIONAL_BOUNDARIES.tsv', boundary_prose, 'validate.py', 'SEAM_EVIDENCE_PROSE'),
 ('matrix column removed',         'EFFECT_MATRIX.tsv', drop_matrix_col,     'validate.py', 'MATRIX_COLUMN_MISSING'),
 ('sibling masks missing edge',    'RELATIONS.tsv', sibling_mask,            'audit_completeness.py', 'COMPLETENESS_EDGE_MISSING'),
 ('cmd/* entrypoint edge deleted', 'RELATIONS.tsv', drop_entrypoint_edge,    'audit_entrypoints.py',  'ENTRY_EDGE_MISSING'),
 ('native symbol edge -> router',  'RELATIONS.tsv', retarget_native_to_router,'audit_entrypoints.py', 'ENTRY_EDGE_WRONG_TARGET'),
 ('envelope symbol -> cost.p1',    'RELATIONS.tsv', retarget_envelope_symbol,'audit_entrypoints.py',  'ENTRY_EDGE_WRONG_TARGET'),
 ('scope divergence unjustified',  'NODES.tsv',     unjustified_scope,       'audit_reachability.py', 'NODE_ENGINE_UNJUSTIFIED'),
 ('P0->ctxprov edge deleted',      'RELATIONS.tsv', drop_p0_ctxprov,         'audit_reachability.py', 'SOURCE_EDGE_MISSING'),
 ('relation engine scope wrong',   'RELATIONS.tsv', mislabel_relation_scope, 'audit_reachability.py', 'REL_ENGINE_CONTRADICTS'),
 ('relation engine scope overbroad','RELATIONS.tsv',overbroad_relation_scope,'audit_reachability.py', 'REL_ENGINE_OVERBROAD'),
 ('claimed mode unreachable',      'NODES.tsv',     unreachable_claimed_mode,'audit_reachability.py', 'MODE_MISMATCH'),
 ('wrong but reachable mode',      'RELATIONS.tsv', wrong_reachable_mode,    'audit_reachability.py', 'REL_MODE_CONTRADICTS'),
 ('tool edge pollutes common',     'RELATIONS.tsv', tool_edge_pollutes_common,'audit_reachability.py','BRANCH_ROLE_CONTRADICTS'),
 ('one-shot branch role wrong',    'RELATIONS.tsv', branch_role_wrong,       'audit_reachability.py', 'BRANCH_ROLE_CONTRADICTS'),
 ('production edge to unwired',    'RELATIONS.tsv', production_edge_to_unwired,'audit_reachability.py','REL_ROLE_CONTRADICTS'),
 ('anchor drifted off its line',   'ANCHOR_FINGERPRINTS.tsv', drift_anchor,  'audit_anchors.py',      'ANCHOR_DRIFTED'),
 ('seam quote off by one line',    'SEAMS.tsv',     seam_quote_off_by_one,   'audit_anchors.py',      'SEAM_QUOTE_NOT_AT_LINE'),
 # --- bus 202: the widened surface ---
 ('dashboard -> console edge gone','RELATIONS.tsv', drop_dashboard_edge,     'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 ('image composition edge gone',   'RELATIONS.tsv', drop_image_edge,         'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 ('external boundary edge gone',   'RELATIONS.tsv', drop_external_edge,      'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 ('exec boundary edge gone',       'RELATIONS.tsv', drop_exec_edge,          'audit_exec_boundaries.py','EXEC_EDGE_MISSING'),
 ('binary gap seam removed',       'SEAMS.tsv',     uninstall_binary,        'audit_delivery.py',     'DELIVERY_UNPROVISIONED'),
 ('tool root reaches nothing',     'RELATIONS.tsv', drop_tool_root_edge,     'audit_reachability.py', 'ROOT_REACHES_NOTHING'),
 ('node reachable from no root',   'RELATIONS.tsv', orphan_a_node,           'audit_reachability.py', 'NODE_NO_ROOT'),
 ('repo surface unclassified',     'SURFACES.tsv',  unclassify_surface,      'repo_census.py',        'CENSUS_UNCLASSIFIED'),
 # --- bus 203: image alone is not the delivery path ---
 ('deploy injection edge gone',    'RELATIONS.tsv', break_injection_edge,    'audit_delivery.py',     'DELIVERY_EDGE_MISSING'),
 ('verified gap recorded as gap',  'SEAMS.tsv',     false_gap_seam,          'audit_delivery.py',     'DELIVERY_FALSE_GAP'),
 # --- bus 204: vendored evidence and split external targets ---
 ('go.mod replace edge gone',      'RELATIONS.tsv', drop_gomod_replace_edge, 'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 ('k8s -> phoenix link gone',      'RELATIONS.tsv', drop_k8s_phoenix_link,   'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 ('guardrail boundary gone',       'RELATIONS.tsv', drop_guardrail_edge,     'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 ('MIG exec boundary gone',        'RELATIONS.tsv', drop_mig_exec_edge,      'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 ('FIRST EPSS boundary gone',      'RELATIONS.tsv', drop_first_epss_edge,    'audit_surfaces.py',     'SURFACE_EDGE_MISSING'),
 # --- bus 205: implemented vs declared-unwired vs absent-stub ---
 ('unwired claimed implemented',   'RELATIONS.tsv', claim_unwired_is_implemented,'audit_surfaces.py', 'CROSSING_UNRECORDED'),
 ('negative-space seam removed',   'SEAMS.tsv',     drop_negative_space_seam,'audit_surfaces.py',     'CROSSING_UNRECORDED'),
 ('go.mod anchor drifted',         'ANCHOR_FINGERPRINTS.tsv', drift_gomod_anchor,'audit_anchors.py',   'ANCHOR_DRIFTED'),
 # --- bus 206: the normalized operation matrix ---
 ('operation anchor wrong line',   'OPERATION_MATRIX.tsv', break_op_anchor,    'audit_operations.py',   'OP_ANCHOR_BAD'),
 ('curated cell unanchored',       'OPERATION_MATRIX.tsv', unanchor_curation,  'audit_operations.py',   'OP_CURATION_UNANCHORED'),
 ('curation without an operation', 'OPERATIONS_CURATED.tsv', orphan_curation,  'audit_operations.py',   'OP_CURATION_ORPHAN'),
 ('unwired op claimed implemented','OPERATION_MATRIX.tsv', op_implemented_on_unwired,'audit_operations.py','OP_STATUS_CONTRADICTS'),
 # --- bus 207: reachability is not the same fact as the destination being wired ---
 ('effect claimed on unreached op','OPERATION_MATRIX.tsv', effect_on_unreached,   'audit_operations.py','OP_EFFECT_ON_UNREACHED'),
 ('unreached with no guard named','OPERATION_MATRIX.tsv', unexplained_unreached, 'audit_operations.py','OP_UNREACHED_UNEXPLAINED'),
 ('reach condition is a statement','OPERATION_MATRIX.tsv', reach_is_a_statement, 'audit_operations.py','OP_REACH_NOT_A_CONDITION'),
 # --- bus 208: unreached rows are done, and the rule must stay derived ---
 ('unreached left in backlog',     'OPERATION_MATRIX.tsv', unreached_left_in_backlog,'audit_operations.py','OP_UNREACHED_IN_BACKLOG'),
 ('unreached by a WIRED guard',    'OPERATION_MATRIX.tsv', unreached_by_a_wired_guard,'audit_operations.py','OP_UNREACHED_NOT_DERIVED'),
 ('reachable row claims not-run',  'OPERATION_MATRIX.tsv', reachable_claims_na, 'audit_operations.py','OP_REACHED_CLAIMS_NA'),
 # --- bus 211: success-vs-compensation is a BRANCH property ---
 ('compensation claims success',   'OPERATION_MATRIX.tsv', compensation_claims_success,'audit_operations.py','OP_COMPENSATION_LEDGER'),
 ('discarded error claims ack',    'OPERATION_MATRIX.tsv', discarded_error_claims_ack, 'audit_operations.py','OP_DISCARDED_ERROR_ACK'),
 # --- bus 213/214: the unparked surfaces ---
 ('route stamped on native row',   'OPERATION_MATRIX.tsv', route_stamped_on_native,  'audit_operations.py','OP_SURFACE_MISMATCH'),
 ('phoenix claims the effect',     'OPERATION_MATRIX.tsv', phoenix_claims_the_effect,'audit_operations.py','OP_PHOENIX_CONFIRMS'),
 ('create-if-absent as undo',      'OPERATION_MATRIX.tsv', create_if_absent_as_compensation,'audit_operations.py','OP_COMPENSATION_NOT_UNDO'),
 # --- the accuracy pass: curated cells are evidence too ---
 ('curated cell cites a comment',  'OPERATION_MATRIX.tsv', citation_to_a_comment,'audit_curation_accuracy.py','CURATION_CITATION_NOT_CODE'),
 ('tool-only claimed production',  'OPERATION_MATRIX.tsv', rollback_claims_reachable,'audit_operations.py','OP_UNREACHED_NOT_DERIVED'),
]

backup = tempfile.mkdtemp()
for f in FILES: shutil.copy(os.path.join(HERE, f), backup)

TOOLS = sorted({t for _, _, _, t, _ in MUTATIONS})
for t in TOOLS:
    rc, out, err = run(t)
    assert rc == 0, f'{t} is not green before mutation testing — fix that first\n{out}\n{err}'

print(f"{'mutation':34}{'tool':24}{'expected diagnostic':30}{'outcome'}")
bad = []
try:
    for name, fn, mut, tool, expect in MUTATIONS:
        p = os.path.join(HERE, fn)
        rows, hdr = load(p); mut(rows, hdr); save(p, rows, hdr)
        verdict = classify(expect, *run(tool))
        print(f'{name:34}{tool:24}{expect:30}{verdict}')
        if verdict != 'CAUGHT': bad.append((name, verdict, expect))
        shutil.copy(os.path.join(backup, fn), p)
finally:
    for f in FILES: shutil.copy(os.path.join(backup, f), os.path.join(HERE, f))

for t in TOOLS:
    rc, out, err = run(t)
    assert rc == 0, f'{t} not restored cleanly after mutation\n{out}\n{err}'

# ---------------------------------------------------------------- harness self-test
# The whole point of this rewrite: prove a crash is NOT scored as a pass.
probe = os.path.join(HERE, '_crash_probe.py')
open(probe, 'w').write('import sys\nundefined_name.append(1)\n')
selftest = classify('ANY_CODE', *run('_crash_probe.py'))
os.remove(probe)
print(f'\nharness self-test: a tool that raises NameError is reported {selftest}')
if selftest != 'CRASH':
    print('SELF-TEST FAILED — the harness would score a crash as a catch'); sys.exit(1)

print(f'\n{len(MUTATIONS)-len(bad)}/{len(MUTATIONS)} mutations caught by their own diagnostic')
if bad:
    print('NOT PROVEN:')
    for n, v, e in bad: print(f'  - {n:34} {v:12} expected {e}')
    sys.exit(1)
print('every invariant is falsifiable, and falsifiable for the stated reason')
