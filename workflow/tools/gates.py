"""Fix contracts shared by transitions, inspection, and release finalization.

Signatures are accountable local attestations, not authentication. Artifact hashes
and source pins prevent accidental reuse; substantive review remains a human task.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import attacks
from pathlib import Path

STAGES = ('TRIAGED DESIGNING CRITIQUED AGREED IMPLEMENTED OFFLINE_VERIFIED '
          'DIFF_REVIEW_PASSED PR_READY IN_PR MERGED DEPLOYED LIVE_VERIFIED '
          'SYNCHRONIZED CLOSED').split()
CHECK_ROLES = {
    'critique': 'skeptic', 'decision': 'skeptic', 'base_review': 'skeptic', 'implementation': 'implementer',
    'red': 'implementer', 'l0': 'implementer', 'l1': 'implementer', 'l2': 'implementer',
    'positive_control': 'implementer', 'incident': 'skeptic', 'p3': 'skeptic', 'patch_equivalence': 'skeptic',
    'l3': 'live_verifier', 'l4': 'live_verifier', 'final': 'skeptic',
}
BASELINE_CHECKS = {'critique', 'decision', 'red'}
LIVE_CHECKS = {'l3', 'l4', 'final'}
ARTIFACTS = {
    'DESIGNING': ['00-intake.md'],
    'CRITIQUED': ['01-proposal.md', '02A-blind-derivation.md', '02B-critique.md'],
    'AGREED': ['03-decision.md'],
    'IMPLEMENTED': ['04-diff.patch'],
    'OFFLINE_VERIFIED': ['05-evidence.md'],
    'DIFF_REVIEW_PASSED': ['evidence/incident.md', 'evidence/p3/verdict.md'],
    'CLOSED': ['06-verdict.md', 'verify.sh'],
}
REVIEW_FILES = {'critique': '02B-critique.md', 'decision': '03-decision.md',
                'implementation': '04-diff.patch', 'incident': 'evidence/incident.md',
                'p3': 'evidence/p3/verdict.md',
                'final': '06-verdict.md'}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assigned(value) -> bool:
    return isinstance(value, str) and value.strip().lower() not in {'', 'unassigned', 'unset', 'replace_me'}


def contract_digest(status: dict) -> str:
    import json
    verification = status.get('verification', {})
    value = {'change_class': status.get('change_class'),
             'verification': {k: verification.get(k) for k in ('required', 'live_required', 'soak_required')}}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def source_for(status: dict, key: str) -> str | None:
    if key == 'base_review':
        return status.get('implementation', {}).get('base_sha')
    if key in BASELINE_CHECKS:
        return status.get('baseline', {}).get('code_sha')
    if key in LIVE_CHECKS:
        return status.get('deployment', {}).get('git_sha')
    return status.get('implementation', {}).get('head_sha')


def local_file(root: Path, relative: str) -> Path | None:
    path = (root / str(relative)).resolve()
    return path if root.resolve() in path.parents and path.is_file() else None


def substantive(fix: Path, relative: str) -> bool:
    path = local_file(fix, relative)
    if not path or not path.read_text().strip():
        return False
    template = fix.parent / '_template' / relative
    return not template.is_file() or path.read_bytes() != template.read_bytes()


def check_errors(root: Path, fix: Path, status: dict, key: str) -> list[str]:
    check = status.get('checks', {}).get(key, {})
    problems = []
    result = check.get('result')
    if result not in {'PASS', 'NOT_REQUIRED'}:
        return [f'checks.{key}: needs PASS evidence or an explicit NOT_REQUIRED ruling']
    roles = status.get('roles', {})
    if result == 'NOT_REQUIRED':
        if key not in {'l2', 'l3', 'l4', 'positive_control'}:
            problems.append(f'{key}: cannot waive this check')
        if check.get('by') != roles.get('human_owner') or not check.get('approval_ref') or not check.get('rationale'):
            problems.append(f'{key}: waiver requires human_owner, approval_ref, and rationale')
    elif check.get('by') != roles.get(CHECK_ROLES[key]) or not assigned(check.get('by')):
        problems.append(f'{key}: signer must be assigned {CHECK_ROLES[key]}')
    if key == 'decision' and check.get('contract_sha256') != contract_digest(status):
        problems.append('decision: verification plan changed after agreement')
    if key in {'incident', 'base_review'} and (not status.get('baseline', {}).get('code_sha')
            or check.get('baseline_sha') != status.get('baseline', {}).get('code_sha')):
        problems.append(f'{key}: evidence baseline differs from current baseline')
    if key == 'p3':
        incident = status.get('checks', {}).get('incident', {})
        if not incident.get('sha256') or check.get('incident_sha256') != incident.get('sha256'):
            problems.append('p3: incident evidence changed or was not reviewed; re-sign P3')
    expected = source_for(status, key)
    if not expected or check.get('source_sha') != expected:
        problems.append(f'{key}: evidence source_sha differs from current {expected}')
    path = local_file(fix, check.get('artifact', ''))
    if not path or not substantive(fix, check.get('artifact', '')):
        problems.append(f'{key}: missing or unchanged template artifact')
    elif check.get('sha256') != digest(path):
        problems.append(f'{key}: artifact changed after attestation')
    expected_file = REVIEW_FILES.get(key)
    if expected_file and check.get('artifact') != expected_file:
        problems.append(f'{key}: must attest {expected_file}')
    if not check.get('at'):
        problems.append(f'{key}: missing observation/review time')
    if key in LIVE_CHECKS and (fix / 'attack-plan.yaml').exists():
        if check.get('attack_plan_sha256') != digest(fix / 'attack-plan.yaml'):
            problems.append(f'{key}: selected attack plan changed; re-sign aggregate evidence')
    if key in LIVE_CHECKS and result == 'PASS':
        deployment = status.get('deployment', {})
        if check.get('deployment_digest') != deployment.get('digest') or not deployment.get('digest'):
            problems.append(f'{key}: evidence deployment digest differs')
    # A check is useful only if its raw artifact is retained and hash-indexed.
    import yaml
    manifest_path = fix / 'evidence/manifest.yaml'
    manifest = yaml.safe_load(manifest_path.read_text()) if manifest_path.is_file() else {}
    indexed = any(a.get('path') == check.get('artifact') and a.get('sha256') == check.get('sha256')
                  for a in (manifest or {}).get('artifacts', []))
    if not indexed:
        problems.append(f'{key}: artifact not indexed in evidence/manifest.yaml')
    return problems


def prerequisites(root: Path, fix: Path, status: dict, target: str, *, finalizing=False) -> list[str]:
    if target not in STAGES or target == 'TRIAGED':
        return []
    rank = STAGES.index(target)
    reached = lambda stage: rank >= STAGES.index(stage)
    missing = []
    roles = status.get('roles', {})
    for role in ('human_owner', 'proposer', 'implementer', 'skeptic', 'live_verifier', 'coordinator'):
        if not assigned(roles.get(role)):
            missing.append(f'roles.{role}: assign a participant')
    if roles.get('skeptic') in {roles.get('proposer'), roles.get('implementer')}:
        missing.append('skeptic must differ from proposer and implementer')
    baseline = status.get('baseline', {})
    if not re.fullmatch(r'[0-9a-f]{7,40}', str(baseline.get('code_sha', ''))):
        missing.append('baseline.code_sha: pin source before design')
    if status.get('profile') not in {'standard', 'light', 'batch', 'legacy-migrated'}:
        missing.append('unsupported code-fix profile; route no-code decisions through intake/issue')
    for stage, paths in ARTIFACTS.items():
        if reached(stage) and not (status.get('profile') == 'legacy-migrated' and stage in {'DESIGNING', 'CRITIQUED'}):
            for path in paths:
                if not substantive(fix, path):
                    missing.append(f'{path}: missing or unchanged template')
    if reached('CRITIQUED') and status.get('profile') != 'legacy-migrated':
        blind = status.get('blind_derivation', {})
        path = local_file(fix, '02A-blind-derivation.md')
        if (blind.get('status') != 'sealed' or not path or blind.get('sha256') != digest(path)
                or blind.get('by') != roles.get('skeptic') or blind.get('source_sha') != baseline.get('code_sha')):
            missing.append('blind derivation: seal by skeptic at current baseline required')
        missing += check_errors(root, fix, status, 'critique')
    if reached('AGREED'):
        missing += check_errors(root, fix, status, 'decision')
        if status.get('change_class') not in {'A', 'B'}:
            missing.append('change_class must be A or B')
        required = status.get('verification', {}).get('required', [])
        if not {'L0', 'L1', 'L2'} <= set(required):
            missing.append('verification.required must include L0, L1, L2 (waive explicitly if applicable)')
        if any(v not in {'L0', 'L1', 'L2', 'L3', 'L4'} for v in required):
            missing.append('verification.required contains unknown level')
        for field in ('live_required', 'soak_required'):
            if not isinstance(status.get('verification', {}).get(field), bool):
                missing.append(f'verification.{field}: declare before implementation')
        if status.get('verification', {}).get('live_required') and 'L3' not in required:
            missing.append('live_required needs L3')
        if status.get('verification', {}).get('soak_required') and 'L4' not in required:
            missing.append('soak_required needs L4')
    if reached('IMPLEMENTED'):
        impl = status.get('implementation', {})
        for field in ('branch', 'base_sha', 'head_sha'):
            if not impl.get(field):
                missing.append(f'implementation.{field}')
        if impl.get('base_sha') != baseline.get('code_sha'):
            missing += check_errors(root, fix, status, 'base_review')
        missing += check_errors(root, fix, status, 'implementation')
        if impl.get('base_sha') and impl.get('head_sha'):
            result = subprocess.run(['git', '-C', str(root.parent), 'diff', '--binary',
                                     str(impl['base_sha']), str(impl['head_sha'])],
                                    capture_output=True)
            patch = local_file(fix, '04-diff.patch')
            if result.returncode or not patch or not result.stdout or patch.read_bytes() != result.stdout:
                missing.append('04-diff.patch must equal nonempty git diff --binary base_sha head_sha')
    if reached('OFFLINE_VERIFIED'):
        for key in ('red', 'l0', 'l1', 'l2', 'positive_control'):
            missing += check_errors(root, fix, status, key)
    if reached('DIFF_REVIEW_PASSED'):
        missing += check_errors(root, fix, status, 'incident')
        missing += check_errors(root, fix, status, 'p3')
    if reached('IN_PR'):
        pr = status.get('pull_request', {})
        if not pr.get('url'):
            missing.append('pull_request.url')
        if pr.get('reviewed_head') != status.get('implementation', {}).get('head_sha'):
            missing += check_errors(root, fix, status, 'patch_equivalence')
    if reached('MERGED'):
        pr = status.get('pull_request', {})
        if not pr.get('merge_sha') or pr.get('checks') != 'PASS':
            missing.append('merge requires pull_request.merge_sha and checks PASS')
        import yaml
        dependencies = set(status.get('dependencies', [])) | set(status.get('implementation', {}).get('stacked_on', []))
        for dependency in dependencies:
            dependency_file = local_file(root, f'fixes/{dependency}/STATUS.yaml')
            parent = yaml.safe_load(dependency_file.read_text()) if dependency_file else {}
            if (parent or {}).get('state') not in {'MERGED', 'DEPLOYED', 'LIVE_VERIFIED', 'SYNCHRONIZED', 'CLOSED'}:
                missing.append(f'dependency {dependency} must merge before this fix')
    if reached('DEPLOYED'):
        dep = status.get('deployment', {})
        for field in ('image', 'digest', 'git_sha', 'rolled_out_at'):
            if not dep.get(field):
                missing.append(f'deployment.{field}')
        if dep.get('git_sha') and status.get('pull_request', {}).get('merge_sha'):
            result = subprocess.run(['git', '-C', str(root.parent), 'merge-base', '--is-ancestor',
                                     str(status['pull_request']['merge_sha']), str(dep['git_sha'])], capture_output=True)
            if result.returncode:
                missing.append('deployed source does not contain recorded merge')
    if reached('LIVE_VERIFIED'):
        missing += attacks.gate_errors(root, fix)
        for key in ('l3', 'l4'):
            missing += check_errors(root, fix, status, key)
        if roles.get('live_verifier') == roles.get('implementer'):
            missing.append('live verifier must differ from implementer')
    if reached('SYNCHRONIZED') and not finalizing:
        sync = status.get('synchronization', {})
        for key in ('issue_entries', 'master_register', 'anatomy_release', 'permanent_tests'):
            if not str(sync.get(key, '')).startswith('PASS:'):
                missing.append(f'synchronization.{key}: needs PASS:<artifact>')
            elif not local_file(root, str(sync[key])[5:]):
                missing.append(f'synchronization.{key}: referenced artifact missing')
        import yaml
        current = yaml.safe_load((root / 'releases/CURRENT.yaml').read_text())
        pin = yaml.safe_load((root / 'anatomy/PIN.yaml').read_text())
        dep_sha = status.get('deployment', {}).get('git_sha')
        if not (current.get('anatomy', {}).get('current_for_deployed_release')
                and current.get('deployed', {}).get('embedded_git_sha') == dep_sha
                and pin.get('anatomy', {}).get('source_commit') == dep_sha):
            missing.append('release/anatomy pins are not synchronized to deployment')
    if reached('CLOSED'):
        missing += check_errors(root, fix, status, 'final')
    return list(dict.fromkeys(missing))
