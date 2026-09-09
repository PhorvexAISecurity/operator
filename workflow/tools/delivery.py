"""Role-bound handoff transactions and small review packets, using existing gates."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import yaml
import evidence_scope
import preflight


def invoke(fn, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(argparse.Namespace(**kwargs))
    if code:
        raise ValueError(err.getvalue().strip() or out.getvalue().strip() or 'workflow command failed')


def sign(w, fix_id, key, spec, by):
    if not isinstance(spec, dict) or set(spec) - {'artifact', 'command', 'result', 'inputs'}:
        raise ValueError(f'{key}: use artifact, exact command, result and optional dependency inputs')
    if not spec.get('command') or not isinstance(spec.get('command'), str):
        raise ValueError(f'{key}: exact command is required')
    if spec.get('result', 'PASS') not in {'PASS', 'FAIL', 'UNAVAILABLE', 'NON_DISCRIMINATING'}:
        raise ValueError('batch handoffs cannot create evidence waivers')
    invoke(w.cmd_record_check, fix_id=fix_id, check=key, by=by, artifact=spec['artifact'],
           command=spec['command'], result=spec.get('result', 'PASS'), inputs=spec.get('inputs'),
           approval_ref=None, rationale=None,
           expect_revision=w.load_yaml(w.FIXES/fix_id/'STATUS.yaml')['revision'])


def reuse(w, fix, fix_id, key, by):
    status = w.load_yaml(fix/'STATUS.yaml')
    proof = evidence_scope.prepare_reuse(w, fix, status, key, by)
    old = proof['old']
    sign(w, fix_id, key, {'artifact': old['artifact'], 'inputs': old['inputs'],
                         'command': f'Reuse retained evidence from {old["source_sha"]}; no rerun; approved inputs unchanged.'}, by)
    status = w.load_yaml(fix/'STATUS.yaml')
    current = status['checks'][key]
    current['observed_source_sha'] = old.get('observed_source_sha', old['source_sha'])
    current['reused_from'] = {'source_sha': old['source_sha'], 'check_sha256': evidence_scope.signature(old)}
    current['reuse_approval'] = proof['approval']
    w.write_yaml(fix/'STATUS.yaml', status)


def advance(w, fix_id, target, by, owner, action):
    invoke(w.cmd_transition, fix_id=fix_id, target=target, by=by,
           expect_revision=w.load_yaml(w.FIXES/fix_id/'STATUS.yaml')['revision'],
           next_owner=owner, next_action=action, artifact=None, note='Validated role handoff',
           approval_ref=None, force=False)


def notification(w, fix_id, by):
    """Retry notification without repeating attestations; ambiguous transport may duplicate mail."""
    with w.workflow_lock():
        status = w.load_yaml(w.FIXES/fix_id/'STATUS.yaml')
        handoff = status.get('handoff', {})
        if by != handoff.get('from'):
            raise ValueError('only the recorded handoff sender can retry its notification')
        if by == handoff['to']:
            return 'next action is owned by this participant; no self-message'
        common = Path(preflight.git(w.ROOT.parent,'rev-parse','--path-format=absolute','--git-common-dir').decode().strip())
        folder = common/'phorvex-workflow/bus/.runtime/handoffs'
        folder.mkdir(parents=True,exist_ok=True)
        key = evidence_scope.signature({'workflow_root':str(w.ROOT),'handoff':handoff})
        receipt = folder/(key+'.json')
        if receipt.is_file(): return 'handoff already queued: '+receipt.read_text().strip()
        command = [sys.executable, str(w.ROOT/'coordination/bus.py'), 'send', '--from', by,
                   '--to', handoff['to'], '--fix', fix_id, '--role', handoff['role'],
                   '--state-from', status['state'], '--request', status['state'],
                   '--subject', f'{fix_id}: {handoff["kind"]} at revision {handoff["revision"]}',
                   '--ref', f'fixes/{fix_id}/STATUS.yaml', '--needs-reply', '--body',
                   f'Role handoff {handoff["id"]}. {status["next_action"]["action"]} '
                   f'Head: {status["implementation"].get("head_sha")}. Read this workflow_root. No new authorization.']
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise ValueError('state committed; notification failed. Retry handoff-notify only: '+result.stderr.strip())
        receipt.write_text(json.dumps({'message':result.stdout.strip()})+'\n')
        return result.stdout.strip()


def transaction(w, args, mode):
    try:
        w.validate_fix_id(args.fix_id)
        fix = w.FIXES/args.fix_id
        with w.workflow_lock():
            original = w.load_yaml(fix/'STATUS.yaml')
            if original['revision'] != args.expect_revision:
                raise ValueError('stale revision; read brief again')
            role = 'implementer' if mode == 'submit' else 'skeptic'
            if args.by != original['roles'].get(role):
                raise ValueError(f'this command belongs to the assigned {role}')
            if mode == 'review' and args.by in {original['roles']['proposer'], original['roles']['implementer']}:
                raise ValueError('review must be independent')
            allowed_states = {'AGREED','IMPLEMENTED','OFFLINE_VERIFIED','IN_PR'} if mode == 'submit' else {'OFFLINE_VERIFIED','IN_PR'}
            if original['state'] not in allowed_states:
                raise ValueError(f'{mode} is not valid from {original["state"]}')
            data = w.load_yaml(Path(args.file))
            allowed = {'checks','reuse','source','preflight'} if mode == 'submit' else {'checks','reuse','approve_reuse'}
            if not isinstance(data, dict) or set(data)-allowed:
                raise ValueError('unknown handoff fields')
            checks, reuses = data.get('checks', {}), data.get('reuse', [])
            allowed_checks = {'implementation','red','l0','l1','l2','positive_control'} if mode == 'submit' else {'red','incident','p3'}
            if (not isinstance(checks, dict) or not isinstance(reuses, list)
                    or any(not isinstance(spec, dict) for spec in checks.values())
                    or any(not isinstance(key, str) for key in reuses)
                    or set(checks)&set(reuses) or (set(checks)|set(reuses))-allowed_checks):
                raise ValueError('handoff contains duplicate or unauthorized check types')
            if mode == 'review' and ('p3' not in checks or checks['p3'].get('result','PASS') != args.result):
                raise ValueError('p3 evidence must match the explicit reviewer verdict')
            paths = [fix/'STATUS.yaml', fix/'04-diff.patch', fix/'evidence/manifest.yaml',
                     w.FIXES/'INDEX.yaml', w.ISSUES/'MASTER_ISSUES.md']
            paths += [w.ISSUES/'entries'/f'{w.pad_issue(i)}.md' for i in original.get('issues', [])]
            approvals = data.get('approve_reuse', [])
            archive = None
            if approvals:
                if mode != 'review' or args.result != 'PASS' or not isinstance(approvals, list):
                    raise ValueError('only a passing reviewer may approve dependency scopes')
                verdict = w.gates.local_file(fix, checks['p3']['artifact'])
                if not verdict: raise ValueError('review artifact missing')
                archive = fix/'evidence/reviews'/f'{w.sha256(verdict)}.md'
                paths.append(archive)
            with w.workflow_transaction(paths):
                if mode == 'submit':
                    if data.get('source'):
                        pins = data['source']
                        if not isinstance(pins, dict) or set(pins)-{'head_sha','base_sha','branch'}:
                            raise ValueError('source accepts only implementation pins')
                        # Reuse the implementer pin validator without another agent turn.
                        for key in ('head_sha','base_sha'):
                            value = pins.get(key, original['implementation'].get(key))
                            if not value or preflight.git(w.ROOT.parent,'rev-parse',value+'^{commit}').decode().strip()!=value:
                                raise ValueError('source pins must be existing full commit SHAs')
                        updated = {**original['implementation'], **pins}
                        if subprocess.run(['git','merge-base','--is-ancestor',updated['base_sha'],updated['head_sha']],cwd=w.ROOT.parent).returncode:
                            raise ValueError('head must descend from base')
                        status = w.load_yaml(fix/'STATUS.yaml'); status['implementation']=updated
                        status.setdefault('configuration_history', []).append({'at': w.utcnow(), 'by': args.by, 'fields': ['implementation'], 'approval_ref': None})
                        w.write_yaml(fix/'STATUS.yaml',status)
                    status = w.load_yaml(fix/'STATUS.yaml')
                    impl = status['implementation']
                    if not all(isinstance(impl.get(k), str) and impl[k] for k in ('base_sha','head_sha','branch')):
                        raise ValueError('provide source branch/base_sha/head_sha before submission')
                    (fix/'04-diff.patch').write_bytes(preflight.git(w.ROOT.parent,'diff','--binary',impl['base_sha'],impl['head_sha']))
                    receipt = w.gates.local_file(fix, data.get('preflight',''))
                    if not receipt: raise ValueError('run local preflight before submission')
                    preflight.validate_receipt(w.ROOT.parent,receipt,impl['base_sha'],impl['head_sha'])
                    sign(w,args.fix_id,'preflight',{'artifact':data['preflight'],'command':f'workflow.py preflight {args.fix_id} --run'},args.by)
                    required = {'implementation','l0','l1','l2','positive_control'}
                    if required-(set(checks)|set(reuses)):
                        raise ValueError('submission needs implementation, l0, l1, l2 and positive_control')
                for key in ['implementation','red','l0','l1','l2','positive_control','incident','p3']:
                    if key in checks: sign(w,args.fix_id,key,checks[key],args.by)
                    if key in reuses: reuse(w,fix,args.fix_id,key,args.by)
                if mode == 'submit':
                    current = w.load_yaml(fix/'STATUS.yaml')['state']
                    if current == 'AGREED': advance(w,args.fix_id,'IMPLEMENTED',args.by,'skeptic','Review submitted evidence and incident.')
                    if current != 'IN_PR' and w.load_yaml(fix/'STATUS.yaml')['state'] == 'IMPLEMENTED':
                        advance(w,args.fix_id,'OFFLINE_VERIFIED',args.by,'skeptic','Review submitted evidence and incident.')
                    errors = w.gates.prerequisites(w.ROOT,fix,w.load_yaml(fix/'STATUS.yaml'),'OFFLINE_VERIFIED')
                    if errors: raise ValueError('; '.join(errors))
                    owner, action = 'skeptic','Independently review the source delta, incident and submitted checks; return review-verdict.'
                elif args.result == 'PASS':
                    status = w.load_yaml(fix/'STATUS.yaml')
                    errors = w.gates.prerequisites(w.ROOT,fix,status,'DIFF_REVIEW_PASSED')
                    if errors: raise ValueError('; '.join(errors))
                    if status['state'] != 'IN_PR':
                        advance(w,args.fix_id,'DIFF_REVIEW_PASSED',args.by,'coordinator','Deliver authorized PR.')
                        advance(w,args.fix_id,'PR_READY',args.by,'coordinator','Push/open authorized PR; live obligations remain.')
                    owner, action = 'coordinator','Push/open or update the reviewed PR under existing scope; record its actual head and CI. No merge/deploy.'
                else:
                    if original['state'] != 'IN_PR': advance(w,args.fix_id,'IMPLEMENTED',args.by,'implementer','Repair reviewer counterexamples.')
                    owner, action = 'implementer','Repair the concrete findings in evidence/p3/verdict.md and resubmit; preserve prior evidence.'
                status = w.load_yaml(fix/'STATUS.yaml')
                if approvals:
                    archive.parent.mkdir(parents=True,exist_ok=True)
                    archive.write_bytes(w.gates.local_file(fix,checks['p3']['artifact']).read_bytes())
                    for key in approvals:
                        check = status.get('checks',{}).get(key,{})
                        if key not in evidence_scope.REUSABLE or not check.get('inputs') or w.gates.check_errors(w.ROOT,fix,status,key):
                            raise ValueError(f'{key}: approve only current passing checks with complete declared inputs')
                        status.setdefault('reuse_approvals',{})[key] = {
                            'by':args.by,'check_sha256':evidence_scope.signature(check),'inputs':check['inputs'],
                            'inputs_sha256':check['inputs_sha256'],'artifact':str(archive.relative_to(fix)),
                            'sha256':w.sha256(archive),'source_sha':status['implementation']['head_sha']}
                status['revision']=original['revision']+1
                status['updated_at']=w.utcnow()
                status['next_action']={'owner':owner,'action':action}
                status['handoff']={'id':f'{args.fix_id}:{status["revision"]}:{mode}','from':args.by,
                                   'to':status['roles'][owner],'role':owner,'kind':mode,'revision':status['revision']}
                errors = []
                w.validate_schema_instance('fix-status.schema.json', status, args.fix_id, errors)
                w.validate_schema_instance('evidence-manifest.schema.json', w.load_yaml(fix/'evidence/manifest.yaml'), args.fix_id, errors)
                if errors: raise ValueError('; '.join(errors))
                w.write_yaml(fix/'STATUS.yaml',status)
                w.write_yaml(w.FIXES/'INDEX.yaml',w.synchronized_index(w.load_yaml(w.FIXES/'INDEX.yaml')))
            print(f'{args.fix_id}: {status["state"]}; revision={status["revision"]}; next={owner}')
        if not args.no_notify: print(notification(w,args.fix_id,args.by))
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,yaml.YAMLError) as exc:
        print(f'FAIL: {exc}',file=sys.stderr); return 1


def delta(w,args):
    try:
        w.validate_fix_id(args.fix_id);fix=w.FIXES/args.fix_id;status=w.load_yaml(fix/'STATUS.yaml')
        if args.agent not in status['roles'].values(): raise ValueError('participant is unassigned')
        if args.agent==status['roles']['skeptic'] and status.get('blind_derivation',{}).get('status')!='sealed':
            raise ValueError('seal independent analysis before inspecting implementation deltas')
        reviews=[x for x in status.get('check_history',[]) if x.get('check')=='p3' and x.get('result')=='PASS']
        if status.get('checks',{}).get('p3',{}).get('result')=='PASS': reviews.append(status['checks']['p3'])
        last=sorted(reviews,key=lambda x:x.get('at',''))[-1]['source_sha'] if reviews else status['implementation']['base_sha']
        head=status['implementation']['head_sha']
        changed=preflight.git(w.ROOT.parent,'diff','--name-status',last,head).decode().splitlines()
        candidates=[]
        for key in status.get('reuse_approvals',{}):
            try:evidence_scope.prepare_reuse(w,fix,status,key,status['checks'][key]['by']);candidates.append(key)
            except (ValueError,KeyError):pass
        print(yaml.safe_dump({'from_reviewed_head':last,'head':head,'changed':changed,
                              'reusable_with_explicit_signoff':candidates,'always_review':['full delta','current incident/P3 verdict','changed packaging and deployment effects']},sort_keys=False))
        return 0
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as exc:
        print(f'FAIL: {exc}',file=sys.stderr);return 1
