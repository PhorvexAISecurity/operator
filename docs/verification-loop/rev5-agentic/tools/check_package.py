#!/usr/bin/env python3
"""Check bundled files, source hashes, JSON contracts and synthetic projections.

Uses the JSON Schema keyword subset present in this package; this is not a
full general-purpose schema validator, evidence verifier, or cluster test.
"""
import argparse
import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    'AGENTS.md','START-HERE.md','ARCHITECTURE.md','WORKFLOW.md','PROGRESS-FORMAT.md','TOOL-CONTRACTS.md','SOURCE-MAP.md','CODEX-ADAPTER.md','HANDOFF-CONTRACTS.md',
    'source/MANIFEST.json','source/rev5/HANDOFF-README.md','source/rev5/Phorvex-Verification-Loop-Architecture-Rev5.docx','source/rev5/architecture-docx-extracted.txt',
    'templates/campaign.json','templates/case.json','templates/milestones.json','templates/task.json','templates/return.json',
    'schemas/case.schema.json','schemas/task.schema.json','schemas/return.schema.json',
    'tools/progress.py','tools/check_package.py','tests/test_progress.py',
    'examples/generate.py','examples/README.md','examples/report/PROGRESS.md','examples/report/cases.json','examples/report/cases.csv',
] + ['prompts/'+role+'.md' for role in ('COMMON','ORCHESTRATOR','CLUSTER_ANALYST','LIBRARY_SELECTOR','CASE_BINDER','CHALLENGE_PLANNER','DEFENSE_PROPOSER','CRITIC','ACTUATOR_DESIGNER','EVIDENCE_AUDITOR')]
SCHEMA_KEYS = {'$schema','$id','$ref','$defs','title','description','default','examples','type','const','enum','required','properties','additionalProperties','items','minItems','maxItems','uniqueItems','minLength','maxLength','pattern','minimum','maximum','format','allOf','anyOf','oneOf','if','then','else','not','patternProperties'}


def load(path):
    def reject(value):
        raise ValueError('Non-finite JSON constant: '+value)
    return json.loads(Path(path).read_text(encoding='utf-8'),parse_constant=reject)


def schema_keywords(schema):
    if isinstance(schema,bool):
        return
    if not isinstance(schema,dict):
        raise ValueError('Schema must be an object or boolean')
    if set(schema)-SCHEMA_KEYS:
        raise ValueError('Unsupported schema keywords: '+', '.join(sorted(set(schema)-SCHEMA_KEYS)))
    for key in ('properties','patternProperties','$defs'):
        for child in schema.get(key,{}).values():
            schema_keywords(child)
    for key in ('items','additionalProperties','if','then','else','not'):
        if key in schema:
            schema_keywords(schema[key])
    for key in ('allOf','anyOf','oneOf'):
        for child in schema.get(key,[]):
            schema_keywords(child)


def validate_schema(value, schema, label='$', document=None):
    document = schema if document is None else document
    if schema is True:
        return
    if schema is False:
        raise ValueError(label+': schema rejects value')
    if '$ref' in schema:
        ref = schema['$ref']
        if not ref.startswith('#/'):
            raise ValueError('Only package-local JSON Pointer schema references supported')
        resolved = document
        for part in ref[2:].split('/'):
            resolved = resolved[part.replace('~1','/').replace('~0','~')]
        validate_schema(value,resolved,label,document)
    type_tests = {'object':isinstance(value,dict),'array':isinstance(value,list),'string':isinstance(value,str),'null':value is None,'boolean':type(value) is bool,'number':type(value) in (int,float) and math.isfinite(value),'integer':type(value) is int or (type(value) is float and math.isfinite(value) and value.is_integer())}
    if 'type' in schema:
        types = schema['type'] if isinstance(schema['type'],list) else [schema['type']]
        if not any(type_tests.get(t,False) for t in types):
            raise ValueError(label+': wrong type')
    if 'const' in schema and (value != schema['const'] or (type(value) is bool) != (type(schema['const']) is bool)):
        raise ValueError(label+': constant mismatch')
    if 'enum' in schema and not any(value == candidate and (type(value) is bool) == (type(candidate) is bool) for candidate in schema['enum']):
        raise ValueError(label+': outside enum')
    if isinstance(value,dict):
        missing = set(schema.get('required',[]))-value.keys()
        if missing:
            raise ValueError(label+': missing '+', '.join(sorted(missing)))
        properties = schema.get('properties',{})
        for key,item in value.items():
            matched = key in properties
            if matched:
                validate_schema(item,properties[key],label+'.'+key,document)
            for pattern,child in schema.get('patternProperties',{}).items():
                if re.search(pattern,key):
                    validate_schema(item,child,label+'.'+key,document)
                    matched = True
            if not matched:
                validate_schema(item,schema.get('additionalProperties',True),label+'.'+key,document)
    if isinstance(value,list):
        if len(value) < schema.get('minItems',0) or len(value) > schema.get('maxItems',float('inf')):
            raise ValueError(label+': invalid array length')
        if schema.get('uniqueItems') and len({json.dumps(x,sort_keys=True) for x in value}) != len(value):
            raise ValueError(label+': duplicate array items')
        for index,item in enumerate(value):
            validate_schema(item,schema.get('items',True),label+'['+str(index)+']',document)
    if isinstance(value,str):
        if len(value) < schema.get('minLength',0) or len(value) > schema.get('maxLength',float('inf')):
            raise ValueError(label+': invalid string length')
        if 'pattern' in schema and not re.search(schema['pattern'],value):
            raise ValueError(label+': pattern mismatch')
        if schema.get('format') == 'date-time':
            import datetime
            try:
                if datetime.datetime.fromisoformat(value.replace('Z','+00:00')).tzinfo is None:
                    raise ValueError()
            except ValueError:
                raise ValueError(label+': invalid timezone-aware date-time') from None
    if type(value) in (int,float):
        if not math.isfinite(value) or value < schema.get('minimum',-float('inf')) or value > schema.get('maximum',float('inf')):
            raise ValueError(label+': invalid number')
    for child in schema.get('allOf',[]):
        validate_schema(value,child,label,document)
    for keyword,count in [('anyOf',None),('oneOf',1)]:
        if keyword in schema:
            valid = 0
            for child in schema[keyword]:
                try:
                    validate_schema(value,child,label,document)
                    valid += 1
                except ValueError:
                    pass
            if (count is None and valid == 0) or (count is not None and valid != count):
                raise ValueError(label+': '+keyword+' mismatch')
    if 'not' in schema:
        try:
            validate_schema(value,schema['not'],label,document)
        except ValueError:
            pass
        else:
            raise ValueError(label+': forbidden value')
    if 'if' in schema:
        try:
            validate_schema(value,schema['if'],label,document)
            matches = True
        except ValueError:
            matches = False
        child = schema.get('then' if matches else 'else',True)
        validate_schema(value,child,label,document)


def within(root,path):
    resolved = (root/path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError('Path escapes package: '+str(path))
    return resolved


def check_source(root):
    manifest = load(root/'source/MANIFEST.json')
    if not re.fullmatch('[a-f0-9]{64}',manifest.get('source_package_sha256','')):
        raise ValueError('Invalid source archive digest metadata')
    entries = manifest['files']
    paths = set()
    for entry in entries:
        relative = entry['path']
        if relative in paths or not relative.startswith('source/rev5/'):
            raise ValueError('Duplicate/invalid source manifest path: '+relative)
        paths.add(relative)
        path = within(root,relative)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != entry['sha256']:
            raise ValueError('Source checksum mismatch: '+relative)
    actual_paths = {str(path.relative_to(root)) for path in (root/'source/rev5').rglob('*') if path.is_file()}
    if paths != actual_paths:
        raise ValueError('Source manifest coverage mismatch: '+str(sorted(paths ^ actual_paths)))
    return len(paths)


def check_links(root):
    checked = 0
    for path in root.rglob('*.md'):
        if 'source' in path.relative_to(root).parts:
            continue  # Original source is checksum-preserved, including its links.
        text = re.sub(r'```.*?```','',path.read_text(encoding='utf-8'),flags=re.S)
        for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)',text):
            target = target.strip().split(' ',1)[0].strip('<>')
            url = urlsplit(target)
            if not target or url.scheme or url.netloc or target.startswith('#'):
                continue
            candidate = (path.parent/unquote(url.path)).resolve()
            if not candidate.is_relative_to(root.resolve()) or not candidate.exists():
                raise ValueError('Broken/escaping relative Markdown link in '+str(path.relative_to(root))+': '+target)
            checked += 1
    return checked


def check(root=ROOT):
    root = Path(root)
    for path in REQUIRED:
        if not within(root,path).is_file() or not within(root,path).stat().st_size:
            raise ValueError('Missing/empty required package file: '+path)
    source_count = check_source(root)
    schemas = {}
    for name in ('case','task','return'):
        schemas[name] = load(root/('schemas/'+name+'.schema.json'))
        schema_keywords(schemas[name])
        validate_schema(load(root/('templates/'+name+'.json')),schemas[name],'templates/'+name+'.json')
    spec = importlib.util.spec_from_file_location('checked_progress',root/'tools/progress.py')
    progress = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(progress)
    template = load(root/'templates/case.json')
    progress.validate(template)
    if template['revision'] != 0 or template['outcome'] != 'PENDING' or progress.completion(template)[0] != 0:
        raise ValueError('Case template must start uncredited and pending')
    campaign = load(root/'templates/campaign.json')
    for key in ('case_parallelism','max_active_agents','max_parallel_experiments'):
        if type(campaign.get(key)) is not int or campaign[key] <= 0:
            raise ValueError('Invalid campaign capacity: '+key)
    if campaign['mode'] != 'PLAN':
        raise ValueError('Campaign template must default to PLAN')
    plan = load(root/'templates/milestones.json')
    if plan['phase1'] != [f'M{i:02}' for i in range(1,16)] or plan['full'] != [f'M{i:02}' for i in range(1,19)] or plan['actuator_branch'] != [f'E{i:02}' for i in range(1,7)]:
        raise ValueError('Unexpected Rev5 obligation plan')
    if set(plan['labels']) != set(plan['full']+plan['actuator_branch']):
        raise ValueError('Milestone labels incomplete')
    example = load(root/'examples/report/cases.json')
    accepted = total = 0
    for case in example['cases']:
        validate_schema(case,schemas['case'],'example/'+case['case_id'])
        progress.validate(case)
        if case.get('synthetic') is not True:
            raise ValueError('Example must be explicitly synthetic')
        def fake_refs(value,key=''):
            if isinstance(value,dict):
                for child,item in value.items():
                    fake_refs(item,child)
            elif isinstance(value,list):
                for item in value:
                    fake_refs(item,key)
            elif isinstance(value,str) and (key.endswith('_ref') or key.endswith('_refs') or key == 'url') and not value.startswith('synthetic://fake/'):
                raise ValueError('Example reference must be explicitly fake: '+key)
        fake_refs(case)
        k,n,_ = progress.completion(case)
        accepted += k
        total += n
    if example['summary']['accepted_obligations'] != accepted or example['summary']['required_obligations'] != total:
        raise ValueError('Synthetic report milestone totals inconsistent')
    with (root/'examples/report/cases.csv').open(encoding='utf-8',newline='') as file:
        rows = list(csv.DictReader(file))
    by_id = {row['case_id']:row for row in rows}
    if set(by_id) != {case['case_id'] for case in example['cases']} or len(rows) != len(example['cases']):
        raise ValueError('CSV case cohort inconsistent')
    md = (root/'examples/report/PROGRESS.md').read_text(encoding='utf-8')
    if 'Synthetic demonstration data' not in md or 'no cluster results' not in md:
        raise ValueError('Synthetic report label missing')
    for case in example['cases']:
        k,n,pct = progress.completion(case)
        row = by_id[case['case_id']]
        if (int(row['accepted']),int(row['required']),float(row['completion_percent'])) != (k,n,pct) or row['current_validation'] != case['current_validation'] or case['case_id'] not in md:
            raise ValueError('CSV/Markdown projection inconsistent: '+case['case_id'])
    return {'source_files_verified':source_count,'templates_checked':3,'synthetic_cases_checked':len(example['cases']),'relative_links_checked':check_links(root),'scope':'local package structure only; no cluster/harness acceptance'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    args = parser.parse_args()
    try:
        print(json.dumps({'status':'PASS',**check(args.root)},sort_keys=True))
    except (ValueError,KeyError,TypeError,OSError) as error:
        parser.exit(2,str(error)+'\n')


if __name__ == '__main__':
    main()
