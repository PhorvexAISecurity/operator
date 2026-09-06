#!/usr/bin/env python3
"""Stable diagnostic codes for every check.

K3's finding: `mutation_test.py` counted ANY nonzero exit as "caught". A NameError, a syntax
error or a missing file therefore scored as a successful catch — and one of them literally
did. A mutation must assert the identity of the diagnostic it expects, which means every
check needs a stable name. This is that registry.

The registry is CLOSED: emitting an unregistered code raises, so a typo cannot silently
create a code that no mutation will ever match.
"""
import sys

CODES = {
 # --- validate.py: shape ---
 'NODE_ID_DUPLICATE':        'two node rows share an id',
 'NODE_PARENT_MISSING':      'parent id is not a node',
 'NODE_PARENT_CYCLE':        'parent chain loops',
 'NODE_LANE_BAD':            'lane outside the closed vocabulary',
 'NODE_ROLE_BAD':            'runtime_role outside the closed vocabulary',
 'NODE_ENGINE_BAD':          'engine_scope outside the closed vocabulary',
 'NODE_MODE_BAD':            'deployment_mode outside the closed vocabulary',
 'NODE_ANCHOR_MISSING':      'source_anchor empty, file absent, or line past EOF',
 'NODE_ANCHOR_NO_LINE':      'a displayed (childless) node has no :line',
 'NODE_SYMBOL_CHILD_NO_LINE':'a child sharing its ancestor file has no line anchor',
 'NODE_CHILD_EMPTY':         'a child owns neither files nor a line anchor',
 # --- validate.py: relations ---
 'REL_ENDPOINT_MISSING':     'relation from/to is not a node id',
 'REL_ENGINE_BAD':           'relation engine_scope outside the vocabulary',
 'REL_MODE_BAD':             'relation deployment_mode outside the vocabulary',
 'REL_ROLE_BAD':             'relation runtime_role outside the vocabulary',
 'REL_ANCHOR_NONCANONICAL':  'anchor does not start with a resolvable path:line',
 'REL_ANCHOR_LINE_PAST_EOF': 'anchor line number exceeds the file',
 'REL_ANCHOR_FILE_MISSING':  'anchor names a file that does not exist',
 'REL_DUPLICATE_KEY':        'two relations share (from,to,kind)',
 # --- validate.py: seams / boundaries ---
 'SEAM_TARGET_MISSING':      'seam attaches to an unknown node',
 'SEAM_STATUS_BAD':          'seam status outside the vocabulary',
 'SEAM_EVIDENCE_PROSE':      'seam evidence is not a resolvable anchor',
 'BOUNDARY_TARGET_MISSING':  'boundary attaches to an unknown node',
 'BOUNDARY_STATUS_BAD':      'boundary status is not an intentional-boundary status',
 'BOUNDARY_EVIDENCE_PROSE':  'boundary evidence is not a resolvable anchor',
 # --- validate.py: ownership ---
 'PKG_UNASSIGNED':           'a package belongs to no node',
 'PKG_MULTI_OWNED':          'a package is in several nodes without a declared split',
 'SPLIT_FILE_UNOWNED':       'a file in a split package belongs to no node',
 'SPLIT_FILE_MULTI_OWNED':   'a file in a split package belongs to several nodes',
 # --- validate.py: expected shape and semantics ---
 'SHAPE_HANDLER_COUNT':      'handler row count changed',
 'SHAPE_GENERATABLE_COUNT':  'generatable-handler count changed',
 'SHAPE_SYMBOL_SCOPED_COUNT':'symbol-scoped child count changed',
 'SEM_HANDLER_MODES':        'a generatable handler is not reachable in both native and hybrid',
 'SEM_ENGINE_WIRING':        'a required engine wiring/invocation edge is missing',
 'SEM_INGEST_GRAPH':         'ingest -> graph is not a production BOTH-engine call',
 'CRD_VOCAB_EXTRA':          'the CRD action enum admits a value no handler implements',
 'CRD_VOCAB_MISSING':        'a registered handler is absent from the CRD enum',
 'CURATION_READBACK_WRONG':  'a readback-NONE claim is contradicted by a later read',
 'CURATION_ACK_WRONG':       'a pre-read ack sits on a mutating operation',
 'CURATION_LEDGER_UNKNOWN':  'a ledger cell names an outcome that does not exist',
 'CURATION_CITATION_DEAD':   'a curated cell cites a line that does not resolve',
 'CURATION_CITATION_NOT_CODE':'a curated cell cites a comment or blank line',
 'OP_TARGET_UNKNOWN':        'an operation target is unresolved and uncurated',
 'OP_TARGET_NOT_A_NODE':     'an operation targets something that is not a node',
 'OP_ANCHOR_BAD':            'an operation anchor does not resolve to its claimed operation',
 'OP_CURATION_UNANCHORED':   'a curated operation cell carries no anchor',
 'OP_STATUS_CONTRADICTS':    'an operation claims implemented against an unwired target',
 'OP_COMPENSATION_LEDGER':   'a compensation-path row claims a success ledger outcome',
 'OP_DISCARDED_ERROR_ACK':   'an ack claims acceptance where the error is discarded',
 'OP_COMPENSATION_NOT_UNDO':  'a compensation row does not undo a prior failed mutation',
 'OP_SURFACE_MISMATCH':      'a row claims a surface its anchor does not belong to',
 'OP_PHOENIX_CONFIRMS':      'a Phoenix CR write claims a confirmed security goal',
 'OP_AVAIL_TOKEN_BAD':       'availability value is outside the closed vocabulary or is a paragraph',
 'OP_REACHED_CLAIMS_NA':     'a reachable row claims it is not reached',
 'OP_UNREACHED_NOT_DERIVED': 'an unreached row names a guard that calls no unwired target',
 'OP_UNREACHED_IN_BACKLOG':  'an unreached row is still queued for curation',
 'OP_EFFECT_ON_UNREACHED':   'an effect claim on a call site that cannot execute',
 'OP_UNREACHED_UNEXPLAINED': 'a row is unreached with no stated guard',
 'OP_REACH_NOT_A_CONDITION': 'a reach condition is a raw statement, not a condition',
 'OP_CURATION_ORPHAN':       'a curated row matches no generated operation',
 'MATRIX_COLUMN_MISSING':    'the effect matrix lost a required column',
 # --- audit_reachability.py ---
 'NODE_ENGINE_UNJUSTIFIED':  'node engine label differs from reachability with no written reason',
 'REL_ENGINE_CONTRADICTS':   'relation engine_scope contradicts an endpoint that derives P0/P1',
 'REL_ENGINE_OVERBROAD':     'relation is labelled BOTH but both endpoints derive one engine only',
 'REL_ROLE_CONTRADICTS':     'relation runtime_role is impossible for its anchor branch or endpoints',
 'REL_MODE_CONTRADICTS':     'relation deployment_mode is not admitted by both endpoints',
 'MODE_UNREACHABLE':         'a node claims a deployment mode nothing reaches',
 'MODE_MISMATCH':            'reached modes differ from the claimed set',
 'SOURCE_EDGE_MISSING':      'an engine file references a node with no relation drawn from that engine',
 'SOURCE_XCHECK_DISAGREES':  'engine label disagrees with what the engine file references',
 'CENSUS_UNCLASSIFIED':      'a tracked top-level path is neither included nor excluded',
 'CENSUS_STALE':             'a declared surface no longer exists in the repository',
 'ROOT_REACHES_NOTHING':     'a declared entrypoint root reaches no node',
 'NODE_NO_ROOT':             'a node is reachable from no declared entrypoint',
 'BRANCH_SET_CHANGED':       'the detected cmd/main.go branch set is not the declared one',
 'BRANCH_ROLE_CONTRADICTS':  'an anchor executes only in tool branches but claims a steady role',
 'BRANCH_NODE_TOOL_ONLY':    'a node is reached only from one-shot/tool roots but claims production',
 # --- audit_entrypoints.py / audit_completeness.py / audit_anchors.py ---
 'ENTRY_EDGE_MISSING':       'a cmd/* entrypoint has no relation for a symbol it constructs',
 'ENTRY_EDGE_WRONG_TARGET':  'an entrypoint edge points at a node that does not define the symbol',
 'COMPLETENESS_UNMAPPED_FUNC':'a function in a shared file is attributed to no node',
 'COMPLETENESS_EDGE_MISSING':'a source reference has no corresponding relation',
 'REL_CROSSING_BAD':         'crossing_status outside the closed vocabulary',
 'CROSSING_UNRECORDED':      'a non-implemented crossing has no seam recording the negative space',
 'CROSSING_STALE':           'an absence claim is no longer true in source',
 'SURFACE_PROBE_STALE':      'the source fact a non-Go probe depends on is gone',
 'SURFACE_EDGE_MISSING':     'a non-Go surface fact holds but its relation is not drawn',
 'DELIVERY_UNPROVISIONED':   'an exec target is provided by neither the image nor deployment injection',
 'DELIVERY_EVIDENCE_STALE':  'the source fact behind an availability claim is gone',
 'DELIVERY_EDGE_MISSING':    'a verified delivery mechanism has no relation drawn',
 'DELIVERY_FALSE_GAP':       'a binary is recorded as absent but its provisioning is verified',
 'EXEC_TARGET_UNKNOWN':      'a process-exec target cannot be resolved to a node',
 'EXEC_EDGE_MISSING':        'an exec call site has no corresponding relation',
 'SEAM_QUOTE_NOT_AT_LINE':   'seam evidence quotes text that is not on the line it cites',
 'ANCHOR_DRIFTED':           'the source line an anchor cites no longer reads as verified',
 'ANCHOR_UNPINNED':          'an anchor has no recorded fingerprint',
 'ANCHOR_NOT_CODE':          'an anchor points at a declaration, import, comment or blank line',
}

class Findings:
    def __init__(self, tool):
        self.tool, self.items = tool, []
    def add(self, code, detail):
        if code not in CODES:
            raise KeyError(f'unregistered diagnostic code {code!r} — add it to findings.CODES')
        self.items.append((code, detail))
    def check(self, cond, code, detail):
        if not cond: self.add(code, detail)
    def report(self, ok_msg=''):
        for code, detail in self.items:
            print(f'FINDING {code}  {detail}')
        if self.items:
            print(f'RESULT {self.tool} FAIL {len(self.items)}')
            sys.exit(1)
        print(f'RESULT {self.tool} PASS' + (f'  {ok_msg}' if ok_msg else ''))
        return 0
