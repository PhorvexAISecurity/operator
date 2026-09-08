"""Reusable test catalogue; execution evidence belongs to a fix or campaign round.

Only preflight/observe-health execute commands, and those issue kubectl GETs.
All mutating attack procedures are guided and require the recorded run scope.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

RESULTS = {'PASS', 'FAIL', 'BLOCKED', 'NOT_APPLICABLE', 'NOT_RUN'}
OUTCOMES = {'mitigated', 'bounded', 'unmitigated', 'not_evaluated'}
PERMISSIONS = {'read-only': 0, 'controlled-mutation': 1, 'attack': 2}


def now():
    return datetime.now(timezone.utc).isoformat()


def load(path):
    return yaml.safe_load(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def safe_file(base, value):
    path = (base / str(value)).resolve()
    if base.resolve() not in path.parents or not path.is_file():
        raise ValueError(f'missing/outside artifact: {value}')
    return path


def catalogue(root):
    data = load(root / 'attacks/catalogue.yaml')
    return data, {c['id']: c for c in data['cases']}


def resolve(data, cases, identifier):
    if identifier in cases:
        return identifier
    redirect = data.get('redirects', {}).get(identifier)
    if redirect:
        if len(redirect) == 1:
            return redirect[0]
        raise ValueError(f'{identifier} spans cases {redirect}; select an explicit case')
    aliases = [c['id'] for c in cases.values() if identifier in c.get('aliases', [])]
    if len(aliases) != 1:
        raise ValueError(f'unknown/ambiguous attack {identifier}')
    return aliases[0]


def parent(root, owner):
    """Allow only existing fix records or real campaign round directories."""
    path = (root / owner).resolve()
    rel = path.relative_to(root.resolve()).parts
    if len(rel) == 2 and rel[0] == 'fixes' and rel[1] != '_template':
        status = load(safe_file(path, 'STATUS.yaml'))
        return path, status, 'fix', status.get('roles', {}).get('live_verifier')
    if len(rel) == 4 and rel[0] == 'campaigns' and rel[1] != '_template' and rel[2] == 'rounds':
        campaign = root / 'campaigns' / rel[1]
        status = load(safe_file(campaign, 'STATUS.yaml'))
        if rel[3] not in {r['id'] for r in status.get('rounds', [])} or not path.is_dir():
            raise ValueError('unknown campaign round')
        return path, status, 'campaign', status.get('roles', {}).get('campaign_lead')
    raise ValueError('plan owner must be an existing fix or campaign round')


def pinned(status, kind):
    p = status.get('deployment' if kind == 'fix' else 'pins', {})
    return {'image': p.get('image'), 'digest': p.get('digest'),
            'source_sha': p.get('git_sha' if kind == 'fix' else 'embedded_git_sha')}


def inspect_cluster(context, namespaces, operator_namespace, source_sha=None):
    if not context or not namespaces:
        raise ValueError('explicit context and at least one namespace are required')
    errors = []
    def get(resource, namespace):
        cmd = ['kubectl', '--context', context, '--request-timeout=15s', 'get', resource,
               '-n', namespace, '-o', 'json']
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if p.returncode:
                errors.append(f'{namespace}/{resource}: read unavailable')
                return None
            return json.loads(p.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            errors.append(f'{namespace}/{resource}: read unavailable')
            return None
    # Never dump raw objects: env values, tokens, arbitrary ConfigMaps and logs
    # do not belong in this baseline evidence.
    operator = get('pods', operator_namespace)
    pods = []
    for ns in namespaces:
        result = get('pods', ns)
        for p in (result or {}).get('items', []):
            pods.append({'namespace': ns, 'name': p['metadata']['name'],
                         'phase': p.get('status', {}).get('phase'),
                         'ready': all(c.get('ready', False) for c in p.get('status', {}).get('containerStatuses', []))
                                  and bool(p.get('status', {}).get('containerStatuses'))})
    policies = []
    for ns in namespaces:
        result = get('phorvexpolicies', ns)
        for p in (result or {}).get('items', []):
            policies.append({'namespace': ns, 'name': p['metadata']['name'],
                             'mode': p.get('spec', {}).get('mode', 'dryRun'),
                             'actions': p.get('spec', {}).get('actions', {}).get('enabled', [])})
    managers = []
    for p in (operator or {}).get('items', []):
        specs = {c['name']: c for c in p.get('spec', {}).get('containers', [])}
        for c in p.get('status', {}).get('containerStatuses', []):
            spec = specs.get(c['name'], {})
            image = spec.get('image', '')
            if c['name'] == 'manager' and 'phorvex' in image and 'console' not in image:
                managers.append({'pod': p['metadata']['name'], 'image': image,
                                 'digest': c.get('imageID'), 'ready': c.get('ready', False)})
    current = managers[0] if len(managers) == 1 else {}
    return {'schema_version': 1, 'observed_at': now(), 'context': context,
            'namespaces': namespaces, 'operator_namespace': operator_namespace,
            'pins': {'image': current.get('image'), 'digest': current.get('digest'), 'source_sha': source_sha},
            'capabilities': {'cluster_read': not errors, 'operator_ready': bool(current.get('ready'))},
            'operator_candidates': managers, 'pods': pods, 'policies': policies, 'errors': errors}


def manifest_record(api, owner, path, producer, command, kind, subject):
    manifest_path = owner / 'evidence/manifest.yaml'
    manifest = load(manifest_path) if manifest_path.exists() else (
        {'schema_version': 1, 'fix_id': subject, 'artifacts': []} if kind == 'fix'
        else {'schema_version': 2, 'subject': {'kind': 'campaign', 'id': subject}, 'artifacts': []})
    rel = str(path.relative_to(owner))
    row = {'id': 'attack-' + hashlib.sha256(rel.encode()).hexdigest()[:16], 'path': rel,
           'bytes': path.stat().st_size, 'sha256': sha(path), 'producer': producer,
           'created_at': now(), 'command': command, 'evidence_class': 'ATTACK',
           'retention': 'git', 'positive_control_for': None, 'sensitivity': None}
    manifest['artifacts'] = [a for a in manifest.get('artifacts', []) if a.get('path') != rel] + [row]
    api['write_yaml'](manifest_path, manifest)


def load_plan(root, value):
    path = safe_file(root, value)
    if path.name != 'attack-plan.yaml':
        raise ValueError('select the active attack-plan.yaml')
    plan = load(path)
    owner, status, kind, executor = parent(root, plan['owner'])
    if path.parent != owner:
        raise ValueError('plan owner/path mismatch')
    return path, plan, owner, status, kind, executor


def plan_cases(api, args):
    root = api['ROOT']
    data, cases = catalogue(root)
    owner_rel = f'fixes/{args.fix}' if args.fix else f'campaigns/{args.campaign}/rounds/{args.round}'
    owner, status, kind, executor = parent(root, owner_rel)
    if args.by not in {executor, status.get('roles', {}).get('coordinator'), status.get('owner')}:
        raise ValueError('plan must be prepared by the assigned verifier/lead/coordinator')
    requested = list(args.case)
    if args.suite:
        if args.suite not in data['suites']:
            raise ValueError('unknown attack suite')
        requested += data['suites'][args.suite]
    if not requested:
        raise ValueError('choose explicit cases or a suite')
    ids = list(dict.fromkeys(resolve(data, cases, i) for i in requested))
    snapshot_path = Path(args.preflight).resolve()
    snapshot = load(snapshot_path)
    for key in ('context', 'namespaces', 'observed_at', 'pins', 'capabilities'):
        if not snapshot.get(key):
            raise ValueError(f'preflight missing {key}')
    baseline_only = all(cases[c]['claims'] == ['baseline'] for c in ids)
    pins = snapshot['pins']
    owner_pins = pinned(status, kind)
    if not baseline_only and any(owner_pins[k] and owner_pins[k] != pins.get(k) for k in owner_pins):
        raise ValueError('preflight differs from owner deployment; reconcile first')
    if args.permission != 'read-only' and not args.approval_ref:
        raise ValueError('mutating scope requires its existing authorization reference')
    criteria = None
    if getattr(args, 'criteria_file', None):
        criteria_path = safe_file(owner, args.criteria_file)
        criteria = load(criteria_path)
        for field in ('targets', 'success', 'abort', 'cleanup'):
            if not criteria.get(field):
                raise ValueError(f'criteria missing {field}')
        targets = criteria['targets']
        if not isinstance(targets, list) or any(
            not isinstance(t, dict) or t.get('namespace') not in snapshot['namespaces']
            or not t.get('workload') or t['workload'] == 'replace-me' for t in targets
        ):
            raise ValueError('criteria targets must name workloads inside the preflight namespaces')
        for field in ('success', 'abort', 'cleanup'):
            if str(criteria[field]).startswith('Replace with'):
                raise ValueError(f'criteria {field} is still a template')
        for field in ('duration_seconds', 'request_limit'):
            if not isinstance(criteria.get(field), int) or criteria[field] < 1:
                raise ValueError(f'criteria needs a positive {field}')
    procedures = {}
    for value in getattr(args, 'procedure_file', []):
        cid, separator, file = value.partition('=')
        if not separator or cid not in ids:
            raise ValueError('procedure override must name a selected case as ID=owner-relative-file')
        procedures[cid] = safe_file(owner, file)
    inputs = {}
    def retain_input(source):
        destination = owner / 'evidence/attacks/inputs' / (sha(source) + source.suffix)
        inputs[destination] = source.read_bytes()
        return {'path': str(destination.relative_to(owner)), 'sha256': sha(source)}
    prerequisites = []
    if snapshot.get('pin_evidence'):
        pin_file = safe_file(snapshot_path.parent, snapshot['pin_evidence'])
        if snapshot.get('pin_evidence_sha256') and sha(pin_file) != snapshot['pin_evidence_sha256']:
            raise ValueError('source pin evidence changed after preflight')
        prerequisites.append(retain_input(pin_file))
    elif not baseline_only:
        raise ValueError('preflight source pin needs retained pin_evidence')
    selected = []
    for cid in ids:
        case = dict(cases[cid]); blocked = []
        for requirement in case['requires']:
            value = snapshot['capabilities'].get(requirement)
            if requirement in {'cluster_read', 'operator_ready'} and value is True:
                continue
            if isinstance(value, dict) and value.get('available') is True and value.get('evidence'):
                prerequisites.append(retain_input(safe_file(snapshot_path.parent, value['evidence'])))
                continue
            blocked.append(f'capability unknown/absent: {requirement}')
        if PERMISSIONS[args.permission] < PERMISSIONS[case['permission']]:
            blocked.append('permission scope does not cover this case')
        if case['claims'] != ['baseline'] and not all(pins.get(k) for k in ('image', 'digest', 'source_sha')):
            blocked.append('observed image, digest and embedded source SHA required')
        if case['permission'] != 'read-only' and criteria is None:
            blocked.append('concrete target, window, request limit, success, abort and cleanup criteria required')
        if cid in procedures:
            case['run_procedure'] = retain_input(procedures[cid])
            case['readiness'] = 'guided'
        elif case['readiness'] == 'historical':
            blocked.append('historical case needs a reviewed concrete run procedure; not runnable as imported')
        case['blocked_by'] = blocked
        case['procedure_sha256'] = sha(root / 'attacks' / case['procedure'])
        selected.append(case)
    plan = {'schema_version': 1, 'owner': owner_rel, 'kind': kind, 'created_at': now(), 'prepared_by': args.by,
            'executor': executor, 'context': snapshot['context'], 'namespaces': snapshot['namespaces'],
            'operator_namespace': snapshot.get('operator_namespace', 'phorvex-system'), 'pins': pins,
            'permission': args.permission, 'approval_ref': args.approval_ref,
            'catalogue_sha256': sha(root / 'attacks/catalogue.yaml'), 'preflight_sha256': sha(snapshot_path),
            'criteria': criteria, 'prerequisite_evidence': prerequisites, 'cases': selected}
    path = owner / 'attack-plan.yaml'
    if path.exists() and not args.replace:
        raise ValueError('plan exists; use --replace to preserve history and create a new attempt')
    evidence = owner / 'evidence/attacks'
    subject = status['fix_id'] if kind == 'fix' else status['campaign_id']
    serialized = yaml.safe_dump(plan, sort_keys=False, allow_unicode=True)
    plan_hash = hashlib.sha256(serialized.encode()).hexdigest()
    frozen = evidence / f'plan-{plan_hash}.yaml'
    retained = evidence / f'preflight-{sha(snapshot_path)}.yaml'
    writes = {path: serialized.encode(), frozen: serialized.encode(),
              retained: snapshot_path.read_bytes(), **inputs}
    if path.exists():
        writes[evidence / f'plan-{sha(path)}.yaml'] = path.read_bytes()
    with api['workflow_transaction']([*writes, owner / 'evidence/manifest.yaml']):
        for target, content in writes.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            if target != path:
                manifest_record(api, owner, target, args.by, 'attacks plan: retain input', kind, subject)
    print(f'plan: {path.relative_to(root)}')
    for case in selected:
        print(f"{case['id']}: " + ('BLOCKED — ' + '; '.join(case['blocked_by']) if case['blocked_by'] else case['readiness']))
    return 0


def record(api, args):
    root = api['ROOT']
    path, plan, owner, status, kind, executor = load_plan(root, args.plan)
    if plan.get('executor') != executor:
        raise ValueError('assigned executor changed; replace the plan')
    _, _, integrity_errors = assess(root, path)
    if integrity_errors:
        raise ValueError('; '.join(integrity_errors))
    if args.by != executor or not executor or executor == 'unassigned':
        raise ValueError('only the assigned live verifier/campaign lead records execution')
    case = next((c for c in plan['cases'] if c['id'] == args.case), None)
    if not case:
        raise ValueError('case is not in the frozen plan')
    observation_path = Path(args.observation).resolve()
    observation = load(observation_path)
    if observation.get('case') != args.case or observation.get('result') not in RESULTS:
        raise ValueError('observation case/result mismatch')
    result = observation['result']
    if observation.get('defense_outcome') not in OUTCOMES:
        raise ValueError('declare defense_outcome separately from the test result')
    executed = result in {'PASS', 'FAIL'}
    if observation.get('pins') != plan['pins']:
        raise ValueError('observation pins differ from the planned deployment')
    if executed and case['blocked_by'] and case['permission'] != 'read-only':
        raise ValueError('case remains blocked; replace plan with verified prerequisites before execution')
    if executed and case['permission'] != 'read-only' and not plan.get('approval_ref'):
        raise ValueError('execution lacks scoped approval')
    if not executed and not observation.get('reason'):
        raise ValueError('non-execution disposition needs a concrete reason')
    if not executed and observation['defense_outcome'] != 'not_evaluated':
        raise ValueError('unexecuted cases cannot claim a defense outcome')
    stages = observation.get('stages', {})
    if executed and sha(root / 'attacks' / case['procedure']) != case['procedure_sha256']:
        raise ValueError('procedure changed after planning; replace the plan')
    if executed and case.get('run_procedure'):
        runbook = case['run_procedure']
        if sha(safe_file(owner, runbook['path'])) != runbook['sha256']:
            raise ValueError('run procedure changed after planning')
    if result == 'PASS':
        missing = [s for s in case['required_stages'] if stages.get(s) != 'PASS']
        if missing:
            raise ValueError(f'PASS lacks required stages: {missing}')
        if case['signal'] == 'detector' and observation.get('signal_source') != 'detector':
            raise ValueError('synthetic signal cannot pass a natural-detection case')
        if observation['defense_outcome'] != case['expected_defense']:
            raise ValueError('PASS defense outcome does not match the declared claim')
    if observation['defense_outcome'] == 'mitigated' and ('defense' not in case['claims'] or stages.get('attacker_goal') != 'PASS'):
        raise ValueError('integration/baseline evidence cannot claim attack mitigation')
    times = []
    for field in ('started_at', 'ended_at'):
        if not observation.get(field):
            raise ValueError(f'observation requires {field}')
        value = datetime.fromisoformat(str(observation[field]).replace('Z', '+00:00'))
        if value.tzinfo is None:
            raise ValueError('observation timestamps need timezone')
        times.append(value)
    if times[1] < times[0]:
        raise ValueError('observation window is reversed')
    if result == 'PASS' and case['permission'] != 'read-only':
        criteria = plan['criteria']
        if (times[1]-times[0]).total_seconds() > criteria['duration_seconds']:
            raise ValueError('run exceeded approved duration; record FAIL and cleanup')
        sent = observation.get('requests_sent')
        if not isinstance(sent, int) or sent < 0 or sent > criteria['request_limit']:
            raise ValueError('PASS requires requests_sent within the planned limit')
    findings = observation.get('findings', [])
    for finding in findings:
        safe_file(root, f'intake/{finding}/STATUS.yaml')
    artifacts = observation.get('artifacts', [])
    if not artifacts:
        raise ValueError('every disposition requires retained evidence')
    plan_hash = sha(path)
    run_dir = owner / 'evidence/attacks' / plan_hash / args.case
    if run_dir.exists():
        raise ValueError('case already recorded for this plan; replace the plan for a new attempt')
    # Validate all inputs before starting a multi-file write.
    sources = []
    for i, item in enumerate(artifacts):
        if not item.get('command'):
            raise ValueError('raw evidence requires an exact command')
        sources.append((safe_file(observation_path.parent, item.get('path', '')), item['command']))
    manifest_path = owner / 'evidence/manifest.yaml'
    with api['workflow_transaction']([manifest_path], [run_dir]):
        run_dir.mkdir(parents=True)
        retained = []
        subject = status['fix_id'] if kind == 'fix' else status['campaign_id']
        for i, (source, command) in enumerate(sources):
            target = run_dir / f'raw-{i}{source.suffix}'
            target.write_bytes(source.read_bytes())
            retained.append({'path': str(target.relative_to(owner)), 'sha256': sha(target), 'command': command})
            manifest_record(api, owner, target, args.by, command, kind, subject)
        observation.update({'executor': args.by, 'recorded_at': now(), 'plan_sha256': plan_hash,
                            'artifacts': retained})
        destination = run_dir / 'result.yaml'
        api['write_yaml'](destination, observation)
        manifest_record(api, owner, destination, args.by, 'attacks record', kind, subject)
    print(f'{args.case}: {result}; defense={observation["defense_outcome"]}; {destination.relative_to(root)}')
    return 0


def assess(root, plan_path):
    path, plan, owner, status, kind, executor = load_plan(root, str(plan_path.relative_to(root)))
    plan_hash = sha(path); rows = []; problems = []
    frozen = owner / 'evidence/attacks' / f'plan-{plan_hash}.yaml'
    if not frozen.exists() or sha(frozen) != plan_hash:
        problems.append('active plan changed without creating a retained plan')
    current_pins = pinned(status, kind)
    if any(current_pins[k] and current_pins[k] != plan['pins'].get(k) for k in current_pins):
        problems.append('owner deployment moved; replace plan and reverify')
    manifest = load(owner / 'evidence/manifest.yaml') or {}
    indexed = {a.get('path'): a.get('sha256') for a in manifest.get('artifacts', [])}
    for artifact in plan.get('prerequisite_evidence', []):
        try:
            if sha(safe_file(owner, artifact['path'])) != artifact['sha256'] or indexed.get(artifact['path']) != artifact['sha256']:
                problems.append('prerequisite evidence hash/index mismatch')
        except (ValueError, OSError):
            problems.append('missing prerequisite evidence')
    for case in plan['cases']:
        result_path = owner / 'evidence/attacks' / plan_hash / case['id'] / 'result.yaml'
        result = load(result_path) if result_path.exists() else {'result': 'NOT_RUN', 'defense_outcome': 'not_evaluated', 'stages': {}}
        if result_path.exists():
            if result.get('executor') != plan.get('executor'):
                problems.append(f'{case["id"]}: executor differs from the plan')
            if result.get('plan_sha256') != plan_hash or result.get('pins') != plan['pins']:
                problems.append(f'{case["id"]}: stale result/pins')
            artifacts = result.get('artifacts', []) + [{'path': str(result_path.relative_to(owner)), 'sha256': sha(result_path)}]
            for a in artifacts:
                try:
                    p = safe_file(owner, a['path'])
                    if sha(p) != a['sha256'] or indexed.get(a['path']) != a['sha256']:
                        problems.append(f'{case["id"]}: evidence hash/index mismatch')
                except (ValueError, OSError):
                    problems.append(f'{case["id"]}: missing retained artifact')
        rows.append({'case': case['id'], 'result': result['result'], 'defense_outcome': result['defense_outcome'],
                     'claims': case['claims'], 'permission': case['permission'], 'cleanup': result.get('stages', {}).get('cleanup', 'NOT_REQUIRED' if case['permission']=='read-only' else 'unknown')})
    return plan, rows, problems


def gate_errors(root, owner, *, closure=False):
    path = owner / 'attack-plan.yaml'
    if not path.exists():
        return []
    try:
        plan, rows, errors = assess(root, path)
        for row in rows:
            if row['result'] in {'NOT_RUN', 'BLOCKED'}:
                errors.append(f"attack {row['case']}: {row['result']}")
            if not closure and row['result'] == 'FAIL':
                errors.append(f"attack {row['case']}: FAIL")
            if row['result'] in {'PASS','FAIL'} and row['cleanup'] not in ({'PASS','NOT_REQUIRED'} if row['permission']=='read-only' else {'PASS'}):
                errors.append(f"attack {row['case']}: cleanup unresolved")
        if not closure and not any(r['result']=='PASS' and r['claims']!=['baseline'] for r in rows):
            errors.append('no passing non-baseline case; health/applicability alone cannot pass fix L3')
        return errors
    except (ValueError, OSError, KeyError, yaml.YAMLError) as exc:
        return [f'attack plan invalid: {exc}']


def report(api, args):
    root = api['ROOT']; path = safe_file(root, args.plan)
    plan, rows, problems = assess(root, path)
    lines = ['# Attack coverage', '', f"Owner: `{plan['owner']}` · source: `{plan['pins'].get('source_sha')}`", '',
             '| Case | Test result | Defense outcome | Claim |', '|---|---|---|---|']
    lines += [f"| {r['case']} | {r['result']} | {r['defense_outcome']} | {', '.join(r['claims'])} |" for r in rows]
    lines += ['', 'Test PASS is not automatically successful defense. NOT_APPLICABLE is excluded, not passed.']
    errors = gate_errors(root, path.parent, closure=plan['kind']=='campaign')
    lines += ['', 'Unresolved: ' + ('; '.join(errors) if errors else 'none')]
    output = path.parent / 'evidence/attacks' / sha(path) / 'coverage.md'
    output.parent.mkdir(parents=True, exist_ok=True)
    api['write_text'](output, '\n'.join(lines)+'\n')
    _, status, kind, _ = parent(root, plan['owner'])
    manifest_record(api, path.parent, output, 'attack-report', 'attacks report', kind,
                    status['fix_id'] if kind=='fix' else status['campaign_id'])
    print('\n'.join(lines)); print(f'coverage_artifact: {output.relative_to(root)}')
    return 1 if errors else 0


def validate_catalogue(root):
    if not (root/'attacks/catalogue.yaml').exists():
        return []
    errors=[]; data,cases=catalogue(root);seen=set()
    if len(cases)!=len(data['cases']):errors.append('duplicate attack IDs')
    for case in cases.values():
        if not re.fullmatch(r'[A-Z][A-Z0-9-]*',case['id']):errors.append('unsafe attack ID')
        for alias in [case['id']]+case['aliases']:
            if alias in seen:errors.append(f'duplicate alias {alias}')
            seen.add(alias)
        if case['permission'] not in PERMISSIONS:errors.append(f"{case['id']}: unknown permission")
        try:safe_file(root/'attacks',case['procedure'])
        except ValueError as exc:errors.append(str(exc))
        if case['expected_defense']=='mitigated' and ('defense' not in case['claims'] or 'attacker_goal' not in case['required_stages']):errors.append('mitigation case lacks goal oracle')
    for suite, ids in data['suites'].items():
        if set(ids)-set(cases):errors.append(f'{suite}: unknown cases')
    for redirect, ids in data.get('redirects',{}).items():
        if set(ids)-set(cases):errors.append(f'{redirect}: unknown redirect')
    return errors


def dispatch(args, api):
    root=api['ROOT']
    try:
        if args.attack_command in {'list','show'}:
            data,cases=catalogue(root)
            if args.attack_command=='show':
                case=cases[resolve(data,cases,args.case_id)]
                print(yaml.safe_dump(case,sort_keys=False),end='')
                print((root/'attacks'/case['procedure']).read_text())
            else:
                selected=data['suites'][args.suite] if args.suite else list(cases)
                for cid in selected:
                    c=cases[cid]
                    if not args.actuator or args.actuator in c['actuators']:
                        print(f"{cid:12} {c['readiness']:10} {','.join(c['claims']):16} {c['title']}")
            return 0
        if args.attack_command=='preflight':
            if args.source_sha and (not re.fullmatch(r'[a-f0-9]{7,40}',args.source_sha) or not args.pin_evidence or not Path(args.pin_evidence).is_file()):
                raise ValueError('source SHA requires retained observation evidence')
            snapshot=inspect_cluster(args.context,args.namespace,args.operator_namespace,args.source_sha)
            if args.pin_evidence:
                source = Path(args.pin_evidence)
                retained = Path(args.output).resolve().parent / ('pin-' + sha(source) + source.suffix)
                retained.parent.mkdir(parents=True, exist_ok=True)
                retained.write_bytes(source.read_bytes())
                snapshot['pin_evidence'] = retained.name
                snapshot['pin_evidence_sha256'] = sha(retained)
            api['write_yaml'](Path(args.output),snapshot)
            print(f'preflight: {args.output}; errors={len(snapshot["errors"])}')
            return 1 if snapshot['errors'] else 0
        with api['workflow_lock']():
            if args.attack_command=='plan':return plan_cases(api,args)
            if args.attack_command=='record':return record(api,args)
            if args.attack_command=='report':return report(api,args)
            if args.attack_command=='observe-health':
                path,plan,owner,status,kind,executor=load_plan(root,args.plan)
                if not any(c['id']=='P-HEALTH' for c in plan['cases']):raise ValueError('P-HEALTH not selected')
                snapshot=inspect_cluster(plan['context'],plan['namespaces'],plan['operator_namespace'],plan['pins'].get('source_sha'))
                import tempfile,argparse
                with tempfile.TemporaryDirectory(prefix='phorvex-health-') as temp:
                    temp=Path(temp);api['write_yaml'](temp/'preflight.yaml',snapshot)
                    passed=not snapshot['errors'] and snapshot['capabilities']['operator_ready'] and snapshot['pins']==plan['pins'] and bool(snapshot['pods']) and all(p['ready'] for p in snapshot['pods'])
                    observation={'case':'P-HEALTH','result':'PASS' if passed else 'FAIL','defense_outcome':'not_evaluated',
                         'signal_source':'none','pins':plan['pins'],'started_at':snapshot['observed_at'],'ended_at':now(),
                         'stages':{'fixture':'PASS','effect':'PASS' if passed else 'FAIL'},'reason':'ready at pinned deployment' if passed else 'readiness or deployment drift',
                         'findings':[],'artifacts':[{'path':'preflight.yaml','command':'kubectl GET preflight at explicit context'}]}
                    api['write_yaml'](temp/'observation.yaml',observation)
                    recorded = record(api,argparse.Namespace(plan=args.plan,case='P-HEALTH',observation=str(temp/'observation.yaml'),by=args.by))
                    return recorded if recorded else (0 if passed else 1)
        raise ValueError('unknown attack command')
    except (ValueError,OSError,KeyError,yaml.YAMLError) as exc:
        print(f'FAIL: {exc}')
        return 1


def register(sub,api):
    parser=sub.add_parser('attacks',help='select reusable tests for fix L3 or campaign rounds')
    commands=parser.add_subparsers(dest='attack_command',required=True)
    ls=commands.add_parser('list');ls.add_argument('--suite');ls.add_argument('--actuator')
    show=commands.add_parser('show');show.add_argument('case_id')
    pre=commands.add_parser('preflight');pre.add_argument('--context',required=True);pre.add_argument('--namespace',action='append',required=True)
    pre.add_argument('--operator-namespace',default='phorvex-system');pre.add_argument('--output',required=True)
    pre.add_argument('--source-sha');pre.add_argument('--pin-evidence')
    plan=commands.add_parser('plan');owner=plan.add_mutually_exclusive_group(required=True)
    owner.add_argument('--fix');owner.add_argument('--campaign');plan.add_argument('--round',default='round-1')
    plan.add_argument('--suite');plan.add_argument('--case',action='append',default=[]);plan.add_argument('--preflight',required=True)
    plan.add_argument('--by',required=True);plan.add_argument('--permission',choices=list(PERMISSIONS),default='read-only')
    plan.add_argument('--approval-ref');plan.add_argument('--replace',action='store_true')
    plan.add_argument('--criteria-file', help='owner-relative YAML with bounded acceptance criteria')
    plan.add_argument('--procedure-file',action='append',default=[],help='CASE=owner-relative concrete procedure, for historical cases')
    rec=commands.add_parser('record');rec.add_argument('--plan',required=True);rec.add_argument('--case',required=True)
    rec.add_argument('--observation',required=True);rec.add_argument('--by',required=True)
    rep=commands.add_parser('report');rep.add_argument('--plan',required=True)
    health=commands.add_parser('observe-health');health.add_argument('--plan',required=True);health.add_argument('--by',required=True)
    for p in (ls,show,pre,plan,rec,rep,health):p.set_defaults(func=lambda args:dispatch(args,api))
