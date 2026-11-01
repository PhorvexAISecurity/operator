"""Bounded, deterministic Markdown/TXT/DOCX requests. Never execute document code."""
import io
import json
import math
import re
import zipfile
from functools import lru_cache
from pathlib import Path
from xml.etree import ElementTree as ET


def stage_policy(value):
    ns = value.split('/')[0]
    if not re.search(r'(?:^|-)(?:stage|staging)(?:-|$)', ns):
        raise RequestError('Benchmark policy must be in a stage namespace; use /policies to see the configured allowlist.')

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
MAX_EXPERIMENTS = 5
EXTENSIONS = {'.md', '.markdown', '.txt', '.docx', '.json'}
POLICY = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
PARAMETER = re.compile(r'^P-[A-Z]{3}-[0-9]{3}$')
NUMBER = re.compile(r'^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$')


class RequestError(ValueError):
    pass


def document_text(filename, data):
    extension = Path(filename).suffix.lower()
    if extension not in EXTENSIONS:
        raise RequestError('Supported files: .md, .txt, .docx and study .json. Export older documents to .docx or UTF-8 .txt.')
    if not data or len(data) > MAX_FILE_BYTES:
        raise RequestError('The file must be nonempty and at most 2 MiB.')
    if extension == '.docx':
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                if len(entries) > 256 or sum(e.file_size for e in entries) > 4 * 1024 * 1024:
                    raise RequestError('The Word document expands beyond the allowed size.')
                if sum(e.filename == 'word/document.xml' for e in entries) != 1:
                    raise RequestError('The Word document must contain one word/document.xml.')
                xml = archive.read('word/document.xml')
            scan = xml.replace(b'\x00', b'').upper()
            if b'<!DOCTYPE' in scan or b'<!ENTITY' in scan:
                raise RequestError('XML declarations with custom entities are not supported.')
            root = ET.fromstring(xml)
            ns = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
            paragraphs = []
            for paragraph in root.iter(ns + 'p'):
                paragraphs.append(''.join(node.text or '' if node.tag == ns + 't' else '\n'
                                          for node in paragraph.iter() if node.tag in (ns + 't', ns + 'br')))
            text = '\n'.join(paragraphs)
        except (zipfile.BadZipFile, KeyError, RuntimeError, ET.ParseError, OSError, ValueError, NotImplementedError) as err:
            if isinstance(err, RequestError):
                raise
            raise RequestError('Unreadable .docx document; export a fresh Word file or UTF-8 .txt.') from err
    else:
        try:
            text = data.decode('utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
        except UnicodeError as err:
            raise RequestError('Text files must use UTF-8, or UTF-16 with a byte-order mark.') from err
    if len(text.encode('utf-8')) > (MAX_FILE_BYTES if extension == '.json' else MAX_TEXT_BYTES):
        raise RequestError('Extracted text exceeds 256 KiB.')
    if any(ord(ch) < 32 and ch not in '\n\r\t' for ch in text):
        raise RequestError('The document contains binary/control characters; send a text or .docx file.')
    return text.replace('\r\n', '\n').replace('\r', '\n')


@lru_cache(maxsize=1)
def knobs():
    path = Path(__file__).resolve().parents[1] / 'mathlab/registry/parameter_registry.json'
    return {item['param_id']: item for item in json.loads(path.read_text())['items']}


def validate_values(parameter, values):
    knob = knobs().get(parameter)
    if not knob or knob.get('control') != 'EXPERIMENT_KNOB' or 'REPLAY' not in knob.get('experiment_modes', []):
        raise RequestError('%s is not a supported registry replay knob.' % parameter)
    if not 1 <= len(values) <= 11:
        raise RequestError('%s needs 1 to 11 trial values.' % parameter)
    override = knob.get('replay_override') or {}
    domain, seen = override.get('domain') or {}, set()
    for value in values:
        if value == 'unset':
            if not override.get('unset_allowed'):
                raise RequestError('%s does not allow unset.' % parameter)
            number = 'unset'
        else:
            if not NUMBER.fullmatch(value) or not math.isfinite(float(value)):
                raise RequestError('%s values must be finite ASCII numbers.' % parameter)
            number = float(value)
            lo, hi = domain.get('min'), domain.get('max')
            if lo is not None and (number < lo or (number == lo and not domain.get('min_inclusive', True))):
                raise RequestError('%s value is below its allowed minimum (%s).' % (parameter, lo))
            if hi is not None and (number > hi or (number == hi and not domain.get('max_inclusive', True))):
                raise RequestError('%s value is above its allowed maximum (%s).' % (parameter, hi))
            if domain.get('integer') and number != int(number):
                raise RequestError('%s requires whole seconds.' % parameter)
        if number in seen:
            raise RequestError('%s repeats a trial value.' % parameter)
        seen.add(number)


def options(fields, policy, ticks):
    unknown = set(fields) - {'policy', 'ticks', 'sync'}
    if unknown:
        raise RequestError('Unknown option: %s.' % ', '.join(sorted(unknown)))
    chosen = fields.get('policy', policy)
    count = str(fields.get('ticks', ticks))
    sync = fields.get('sync', 'true').lower()
    if not POLICY.fullmatch(chosen):
        raise RequestError('policy must be a lowercase namespace/name.')
    stage_policy(chosen)
    if not re.fullmatch(r'[0-9]+', count) or not 1 <= int(count) <= 5000:
        raise RequestError('ticks must be a whole number from 1 to 5000.')
    if sync not in ('true', 'false'):
        raise RequestError('sync must be true or false.')
    return 'policy=%s ticks=%s%s' % (chosen, int(count), ' nosync' if sync == 'false' else '')


def command_spec(command, policy, ticks):
    words = command.split()
    if not words or words[0] not in ('/bench', '/param'):
        raise RequestError('Use /bench or /param commands only.')
    kind, rest, fields = words[0][1:], words[1:], {}
    def add(word):
        if word == 'nosync':
            key, value = 'sync', 'false'
        elif '=' in word:
            key, value = word.split('=', 1)
        else:
            return False
        if key not in ('policy', 'ticks', 'sync') or key == 'sync' and word != 'nosync':
            raise RequestError('Unknown command option. Use policy=, ticks= and nosync.')
        if key in fields:
            raise RequestError('Repeated command option: %s.' % key)
        fields[key] = value
        return True
    if kind == 'bench':
        while rest and (rest[0] == 'nosync' or '=' in rest[0]):
            add(rest.pop(0))
        prompt = ' '.join(rest)
        if len(prompt) < 10 or len(prompt) > 16000:
            raise RequestError('bench change must contain 10 to 16000 characters.')
        if any(w == 'nosync' or w.startswith(('policy=', 'ticks=')) for w in rest):
            raise RequestError('Place bench options before the change description.')
        return bench_spec(fields, policy, ticks, prompt)
    if not rest or not PARAMETER.fullmatch(rest[0]):
        raise RequestError('param needs a parameter ID such as P-FEA-006.')
    parameter, values = rest.pop(0), []
    for word in rest:
        if not add(word):
            values.append(word)
    validate_values(parameter, values)
    return {'kind': kind, 'text': parameter + ' ' + ' '.join(values) + ' ' + options(fields, policy, ticks)}


def heading(line):
    label = re.sub(r'^#{1,6}\s+', '', line).strip().lower()
    label = label.removeprefix('[').removesuffix(']').removesuffix(':').strip()
    return label if label in ('bench', 'endpoint') else 'param' if label in ('param', 'params', 'parameters') else None


def bench_spec(fields, policy, ticks, prompt):
    import endpoint_study
    prefix = options(fields, policy, ticks)
    request = endpoint_study.legacy_request(prompt, fields.get('policy', policy), int(fields.get('ticks', ticks)),
                                            fields.get('sync', 'true').lower() == 'true')
    if request is None:
        return {'kind': 'bench', 'text': prefix + ' ' + prompt}
    return {'kind': 'endpoint', 'text': json.dumps(endpoint_study.validate(request), ensure_ascii=False),
            'conversion': endpoint_study.legacy_conversion(prompt, request)}


def endpoint_section(section, policy, ticks):
    import endpoint_study
    fields = {}
    for line, text in section['lines']:
        match = re.fullmatch(r'([a-z][a-z0-9_.]*)\s*:\s*(.*)', text)
        if not match:
            raise RequestError('Line %d: endpoint needs one lowercase key: value per line.' % line)
        key, value = match.groups()
        if key in fields:
            raise RequestError('Line %d: repeated endpoint field %s.' % (line, key))
        fields[key] = value
    allowed = {'policy', 'ticks', 'sync', 'title', 'dataset'} | {'config.' + key for key in endpoint_study.CONSTANTS} | {'study.' + key for key in endpoint_study.STUDY_SETTINGS}
    if set(fields) - allowed:
        raise RequestError('Unknown endpoint fields: ' + ', '.join(sorted(set(fields) - allowed)))
    options({key: fields[key] for key in ('policy', 'ticks', 'sync') if key in fields}, policy, ticks)
    request = {'schema': endpoint_study.SCHEMA, 'title': fields.get('title', 'Paired V2/V3 endpoint study'),
               'policy': fields.get('policy', policy), 'ticks': int(fields.get('ticks', ticks)),
               'sync': fields.get('sync', 'false').lower() == 'true',
               'dataset': fields.get('dataset', 'recorded'), 'config': {}}
    for key, value in fields.items():
        if '.' not in key:
            continue
        if not NUMBER.fullmatch(value) or not math.isfinite(float(value)):
            raise RequestError('%s must be a finite ASCII number in seconds where applicable.' % key)
        group, name = key.split('.', 1)
        number = float(value)
        request.setdefault(group, {})[name] = int(number) if number.is_integer() else number
    try:
        request = endpoint_study.validate(request)
    except ValueError as error:
        raise RequestError('Endpoint validation: ' + str(error)) from error
    return {'kind': 'endpoint', 'text': json.dumps(request, ensure_ascii=False), 'line': section['line']}


def parse(text, policy='phorvex-staging-demo/demo-api-defense', ticks=500):
    if text.lstrip().startswith('{'):
        from study_schema import strict_json, validate
        try:
            request = strict_json(text)
            if request.get('schema') == 'phorvex-bench.endpoint-study.v1':
                import endpoint_study
                request = endpoint_study.validate(request)
                stage_policy(request['policy'])
                return [{'kind': 'endpoint', 'text': json.dumps(request, ensure_ascii=False), 'line': 1}]
            request = validate(request)
            stage_policy(request['policy'])
            if request.get('trace', {}).get('evidence') == 'recorded':
                raise RequestError('Inline uploaded reference traces are synthetic fixtures; recorded evidence requires stage installation.')
        except (ValueError, TypeError, KeyError, RecursionError) as err:
            raise RequestError('Study validation: %s' % err) from err
        return [{'kind': 'study', 'text': json.dumps(request, ensure_ascii=False), 'line': 1}]
    lines = [(n, line.strip()) for n, line in enumerate(text.splitlines(), 1)
             if line.strip() and not line.strip().startswith('```')]
    if not lines:
        raise RequestError('The document is empty.')
    tasks = []
    if any(line.startswith(('/bench ', '/param ')) for _, line in lines):
        for number, line in lines:
            if line.startswith('#'):
                continue
            try:
                task = command_spec(line, policy, ticks)
            except RequestError as err:
                raise RequestError('Line %d: %s Use sections for multiline changes.' % (number, err)) from err
            tasks.append({**task, 'line': number})
    else:
        sections, current = [], None
        for number, line in lines:
            kind = heading(line)
            if kind:
                current = {'kind': kind, 'line': number, 'lines': []}
                sections.append(current)
            elif current is not None and (line.startswith('#') or re.fullmatch(r'\[[A-Za-z_-]+\]', line)):
                raise RequestError('Line %d: unknown section heading; use [bench] and [params].' % number)
            elif current is None:
                if not line.startswith('#'):
                    raise RequestError('Line %d: expected [bench], [params], or a /bench or /param command.' % number)
            else:
                current['lines'].append((number, line))
        for section in sections:
            if section['kind'] == 'endpoint':
                tasks.append(endpoint_section(section, policy, ticks))
                continue
            fields, params, prompt = {}, [], None
            for number, line in section['lines']:
                if line.startswith('#'):
                    continue
                match = re.fullmatch(r'([A-Za-z0-9_-]+)\s*:\s*(.*)', line)
                if prompt is not None:
                    if match and match[1].lower() in ('policy', 'ticks', 'sync', 'change', 'prompt'):
                        raise RequestError('Line %d: put options before change; do not repeat change.' % number)
                    prompt.append(line)
                    continue
                if not match:
                    raise RequestError('Line %d: expected key: value. Use change: before a multiline brain change.' % number)
                key, value = match[1], match[2]
                if key.lower() in ('change', 'prompt') and section['kind'] == 'bench':
                    prompt = [] if value in ('', '|') else [value]
                elif PARAMETER.fullmatch(key) and section['kind'] == 'param':
                    if any(p[0] == key for p in params):
                        raise RequestError('Line %d: repeated parameter %s.' % (number, key))
                    params.append((key, re.split(r'[\s,]+', value.strip().strip('[]')), number))
                elif key.lower() in ('policy', 'ticks', 'sync'):
                    key = key.lower()
                    if key in fields:
                        raise RequestError('Line %d: repeated option %s.' % (number, key))
                    fields[key] = value
                else:
                    raise RequestError('Line %d: unknown field %s.' % (number, key))
            prefix = options(fields, policy, ticks)
            if section['kind'] == 'bench':
                change = ' '.join(prompt or [])
                if not 10 <= len(change) <= 16000:
                    raise RequestError('Line %d: bench needs change: and 10 to 16000 characters of description.' % section['line'])
                tasks.append({**bench_spec(fields, policy, ticks, change), 'line': section['line']})
            else:
                if not params:
                    raise RequestError('Line %d: params needs at least one parameter ID and trial values.' % section['line'])
                for parameter, values, number in params:
                    try:
                        validate_values(parameter, values)
                    except RequestError as err:
                        raise RequestError('Line %d: %s' % (number, err)) from err
                    tasks.append({'kind': 'param', 'text': parameter + ' ' + ' '.join(values) + ' ' + prefix, 'line': number})
    if not 1 <= len(tasks) <= MAX_EXPERIMENTS:
        raise RequestError('A file must contain 1 to %d experiments; empty or unknown sections are not executable.' % MAX_EXPERIMENTS)
    return tasks
