#!/usr/bin/env python3
"""Bounded, authenticated operator Live campaign; no generated code is executed."""
from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone

from exporter import COST_FILE, GATES_FILE, export_workbooks, typed_links, template_paths

APPLICATIONS = ('vllm', 'voice', 'litellm', 'crm')
VLLM = {'poison', 'kvcache', 'endpoint-rotate', 'endpoint-lease-revoke', 'guardrail-rotate',
        'guardrail-output-v2', 'request-drain', 'kv-migrate-invalidate', 'warm-swap', 'model-shard-replace'}
ROUTES = {
    ('voice', 'ai2-agent-memory-contamination'): '/api/voice/live/fire',
    ('voice', 'ai2-agent-excessive-agency'): '/api/voice/agency/live/fire',
    ('voice', 'ai2-system-prompt-leakage'): '/api/voice/output/live/fire',
    ('voice', 'voice-unauthenticated-media-admission'): '/api/voice/admission/live/fire',
    ('voice', 'ai2-mcp-tool-poisoning'): '/api/voice/mcp/live/fire',
    ('litellm', 'ai2-unbounded-consumption'): '/api/litellm/live/fire',
    ('litellm', 'ai2-query-extraction'): '/api/litellm/live/fire',
    ('litellm', 'ai2-sensitive-info-disclosure'): '/api/litellm/output/fire',
    ('litellm', 'ai2-system-prompt-leakage'): '/api/litellm/output/fire',
    ('crm', 'ai2-cross-record-refund'): '/api/crm/live/fire',
}
LOCAL_LOCK = threading.RLock()


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(512 * 1024), b''): digest.update(chunk)
    return digest.hexdigest()


def dump(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))
    os.replace(temp, path)


def append(path, value):
    with LOCAL_LOCK:
        with Path(path).open('a') as stream:
            stream.write(json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n')
            if Path(path).name in ('launch-intents.jsonl', 'accepted-launches.jsonl'):
                stream.flush(); os.fsync(stream.fileno())


def launch_body(case):
    ns, case_id, endpoint = case.get('namespace'), case.get('id'), case.get('endpoint')
    if ns not in APPLICATIONS:
        raise ValueError('Namespace is not in the benchmark allowlist')
    if case_id == 'foothold' and endpoint == '/api/workload/attack':
        return {'namespace': ns, 'action': 'foothold'}
    if ns == 'vllm' and case_id in VLLM and endpoint == '/api/vllm/attack':
        return {'action': case_id}
    if ROUTES.get((ns, case_id)) == endpoint:
        return {'scenario': case_id}
    raise ValueError('Catalogue ID and endpoint do not match the reviewed dispatcher')


def budget(case):
    if case['namespace'] == 'vllm':
        return {'request-drain': 270, 'endpoint-lease-revoke': 960, 'guardrail-rotate': 630,
                'guardrail-output-v2': 960}.get(case['id'], 150)
    return 600 if case['namespace'] == 'crm' else 960


def dependency_locks(case):
    """Serialize shared model/CRM producers as well as each app's target."""
    names = {case['namespace']}
    if case['namespace'] in ('voice', 'litellm', 'vllm'):
        names.add('shared-model-gateway')
    if case['namespace'] == 'crm' or case['namespace'] == 'voice' and case['id'] in (
        'ai2-agent-excessive-agency', 'ai2-mcp-tool-poisoning'):
        names.add('shared-crm')
    return sorted(names)


class TransportError(Exception): pass
class HTTPFailure(TransportError):
    def __init__(self, status, body):
        self.status, self.body = status, body
        super().__init__(f'Console HTTP {status}')


def error_details(error):
    """Protected diagnostic body, with authentication material removed."""
    def sanitize(value):
        if isinstance(value, dict):
            return {key: '[REDACTED]' if re.search(r'(?i)authorization|password|secret|api.?key|access.?token|credential', key) else sanitize(child)
                    for key, child in value.items()}
        if isinstance(value, list): return [sanitize(child) for child in value]
        if isinstance(value, str):
            value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [REDACTED]', value)
            value = re.sub(r'\bsk-[A-Za-z0-9_-]{8,}', '[REDACTED]', value)
            return re.sub(r'(?i)(\b(?:password|secret|api[-_]?key|access[-_]?token|credential)\s*[:=]\s*)\S+', r'\1[REDACTED]', value)
        return value
    details = {'error': str(error)}
    if isinstance(error, HTTPFailure): details.update(status=error.status, response=sanitize(error.body))
    return details


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A Console redirect must never carry the identity to another origin.
        return None


class Console:
    def __init__(self, out=None):
        self.url = os.environ.get('CONSOLE_URL', '').rstrip('/')
        self.token = os.environ.get('CONSOLE_TOKEN', '').strip()
        self.process = None
        self.owned_log = None
        self.out = Path(out) if out else None
        if not self.token:
            self.token = self.kubectl('-n', os.environ.get('KUBE_NAMESPACE', 'phorvex-system'), 'create', 'token',
                                      os.environ.get('CONSOLE_TOKEN_SERVICE_ACCOUNT', 'phorvex-phorvex-console-e2e'),
                                      '--audience=phorvex-console', '--duration=6h').strip()
            if not self.token:
                raise TransportError('Existing Console identity token could not be issued')
        if not self.url:
            self.start_forward()
        parsed = urllib.parse.urlparse(self.url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('CONSOLE_URL must be an HTTP(S) origin without credentials')
        if parsed.scheme == 'http' and parsed.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('Remote Console requires HTTPS')

    @staticmethod
    def kubectl(*arguments, timeout=30):
        result = subprocess.run(['kubectl', *arguments], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            # Never echo stderr containing environment, auth or request payload.
            raise TransportError('kubectl read/token request failed')
        return result.stdout

    def start_forward(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        # Ownership belongs to this exact process; never kill unrelated port forwards.
        log_path = self.out / 'raw' / 'port-forward.log' if self.out else Path('/tmp') / ('benchmark-forward-' + uuid.uuid4().hex + '.log')
        self.owned_log = log_path
        self.forward_stream = log_path.open('w')
        service = os.environ.get('CONSOLE_SERVICE', 'phorvex-console')
        if not service.replace('-', '').isalnum(): raise ValueError('Invalid Console service name')
        self.process = subprocess.Popen(['kubectl', '-n', os.environ.get('KUBE_NAMESPACE', 'phorvex-system'),
                                         'port-forward', '--address=127.0.0.1', 'service/' + service, f'{port}:80'],
                                        stdout=self.forward_stream, stderr=subprocess.STDOUT)
        end = time.monotonic() + 25
        while time.monotonic() < end:
            if self.process.poll() is not None: raise TransportError('Owned Console port-forward exited')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.25):
                    self.url = f'http://127.0.0.1:{port}'; return
            except OSError: time.sleep(.2)
        raise TransportError('Owned Console port-forward not ready')

    def open(self, path, method='GET', body=None, timeout=45):
        if not path.startswith('/api/') or path.startswith('//'):
            raise ValueError('Only reviewed Console API paths may be called')
        parsed = urllib.parse.urlsplit(path)
        q = urllib.parse.parse_qs(parsed.query)
        q['lens'] = ['operator']
        path = parsed.path + '?' + urllib.parse.urlencode(q, doseq=True)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json',
                                              'Accept': 'text/event-stream' if parsed.path == '/api/live' else 'application/json'})
        try:
            return urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout)
        except urllib.error.HTTPError as error:
            raw = error.read(1048576)
            try: payload = json.loads(raw)
            except ValueError: payload = {'error': 'Console returned non-JSON error; raw body not disclosed'}
            raise HTTPFailure(error.code, payload) from None
        except (OSError, TimeoutError, urllib.error.URLError):
            raise TransportError('Console transport failed; a POST may already have been accepted') from None

    def request(self, path, method='GET', body=None):
        # Explicitly no retry of mutation requests. Safe GET retries only.
        for attempt in range(3 if method == 'GET' else 1):
            try:
                with self.open(path, method, body) as response:
                    raw = response.read(32 * 1024 * 1024 + 1)
                    if len(raw) > 32 * 1024 * 1024: raise TransportError('Console JSON byte cap reached')
                    return json.loads(raw)
            except HTTPFailure:
                raise
            except (TransportError, ValueError):
                if method != 'GET' or attempt == 2: raise
                time.sleep(.5 * (attempt + 1))

    def close(self):
        if getattr(self, 'process', None):
            self.process.terminate()
            try: self.process.wait(timeout=8)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=3)
            self.forward_stream.close()
        if not getattr(self, 'out', None) and getattr(self, 'owned_log', None):
            self.owned_log.unlink(missing_ok=True)


def image_version(image):
    if not image: return None
    if '@sha256:' in image: return image.rsplit('@', 1)[-1]
    return image.rsplit(':', 1)[-1] if ':' in image.rsplit('/', 1)[-1] else None


def actual_versions(deployments, api):
    value = {'apiReported': api, 'authority': 'Separate actual Deployment container images', 'operator': None, 'console': None}
    for deployment in deployments:
        if deployment['name'] == 'phorvex-phorvex':
            manager = deployment['images'].get('manager') or next(iter(deployment['images'].values()), None)
            value['operatorImage'] = manager; value['operator'] = image_version(manager)
            if deployment['images'].get('console'):
                value['consoleImage'] = deployment['images']['console']; value['console'] = image_version(value['consoleImage'])
        elif 'console' in deployment['name']:
            console_image = deployment['images'].get('console') or next(iter(deployment['images'].values()), None)
            value['consoleImage'] = console_image; value['console'] = image_version(console_image)
    return value


def controller_pods(pods, replicasets, deployments):
    deployment_uids = {d['uid'] for d in deployments}
    replica_uids = {r['metadata']['uid'] for r in replicasets
                    if any(o.get('kind') == 'Deployment' and o.get('uid') in deployment_uids
                           for o in r['metadata'].get('ownerReferences', []))}
    return [pod for pod in pods if any(o.get('kind') == 'ReplicaSet' and o.get('uid') in replica_uids
                                      for o in pod['metadata'].get('ownerReferences', []))]


def readiness_error(pin):
    manager = [d for d in pin['deployments'] if d['name'] == 'phorvex-phorvex']
    console = [d for d in pin['deployments'] if 'console' in d['name'] or d['images'].get('console')]
    phoenix = [d for d in pin['deployments'] if d['name'] == 'operator-controller-manager']
    if not manager or not console or not phoenix:
        return 'Required manager, Console or Phoenix Deployment identity is absent'
    mandatory = {d['uid']: d for d in manager + console + phoenix}
    for deployment in mandatory.values():
        desired = deployment.get('desiredReplicas', 1)
        if desired < 1 or deployment['readyReplicas'] < desired or deployment.get('updatedReplicas', 0) < desired or deployment.get('observedGeneration', 0) < deployment.get('generation', 1):
            return 'Required controller Deployment has not completed rollout: ' + deployment['name']
        matching_pods = [pod for pod in pin['pods'] if pod.get('deploymentUID') == deployment['uid']]
        if not matching_pods:
            return 'Required controller Deployment has no retained owned Pod image evidence: ' + deployment['name']
    for pod in pin['pods']:
        if pod['namespace'] != 'phorvex-system' or pod.get('deploymentUID') not in mandatory: continue
        if pod['phase'] != 'Running' or not pod['containers'] or any(not c.get('ready') or not c.get('imageID') for c in pod['containers']):
            return 'Required controller Pod lacks ready immutable image evidence: ' + pod['name']
        expected = mandatory[pod['deploymentUID']]['images']
        if any(c['name'] in expected and c.get('specImage') != expected[c['name']] for c in pod['containers']):
            return 'Controller Pod still runs a different image from desired Deployment: ' + pod['name']
    return ''


def catalogue(console, applications=APPLICATIONS):
    api = console.request('/api/version')
    errors, deployed = [], []
    try:
        response = json.loads(console.kubectl('-n', 'phorvex-system', 'get', 'deployments', '-o', 'json'))
        deployed = [{'name': d['metadata']['name'], 'images': {c['name']: c['image'] for c in d['spec']['template']['spec']['containers']}}
                    for d in response.get('items', [])]
    except (TransportError, OSError, subprocess.SubprocessError, ValueError, KeyError):
        errors.append('Actual deployed component versions unavailable; API compile stamp retained separately')
    output = {'applications': [], 'version': actual_versions(deployed, api), 'errors': errors}
    for ns in applications:
        try:
            value = console.request('/api/workload/attacks?namespace=' + urllib.parse.quote(ns))
            if value.get('namespace') != ns:
                raise TransportError('Catalogue namespace identity mismatch')
            live = []
            for entry in value.get('live', []):
                item = {**entry, 'namespace': ns}
                blocked = {value.strip() for value in os.environ.get('BENCHMARK_BLOCKED_CASES', '').split(',') if value.strip()}
                if ns + ':' + str(entry.get('id', '')) in blocked:
                    item.update(benchmarkBlocked=True, benchmarkBlockReason=os.environ.get('BENCHMARK_BLOCK_REASON', 'Known producer/readback defect requires reconciliation before launch'))
                try: launch_body(item)
                except ValueError: item.update(armed=False, compatible=False, reason='No reviewed dispatcher for this namespace/ID/endpoint')
                live.append(item)
            output['applications'].append({'namespace': ns, 'live': live, 'stack': value.get('stack')})
        except (TransportError, ValueError) as error:
            output['applications'].append({'namespace': ns, 'live': [], 'error': str(error)})
            output['errors'].append(ns + ': ' + str(error))
    return output


def snapshot(console):
    result = {'time': utc(), 'apiVersion': console.request('/api/version'), 'source': os.environ.get('BENCHMARK_SOURCE_SHA', ''),
              'deployments': [], 'pods': [], 'namespaces': [], 'policies': [], 'errors': []}
    try:
        deployments = json.loads(console.kubectl('-n', 'phorvex-system', 'get', 'deployments', '-o', 'json'))
        for d in deployments.get('items', []):
            if not any(word in d['metadata']['name'] for word in ('phorvex', 'phoenix')) and d['metadata']['name'] != 'operator-controller-manager': continue
            result['deployments'].append({'name': d['metadata']['name'], 'uid': d['metadata']['uid'],
                                           'generation': d['metadata'].get('generation'), 'specSHA256': hashlib.sha256(json.dumps(d['spec'], sort_keys=True).encode()).hexdigest(),
                                           'images': {c['name']: c['image'] for c in d['spec']['template']['spec']['containers']},
                                           'readyReplicas': d.get('status', {}).get('readyReplicas', 0),
                                           'desiredReplicas': d['spec'].get('replicas', 1),
                                           'updatedReplicas': d.get('status', {}).get('updatedReplicas', 0),
                                           'observedGeneration': d.get('status', {}).get('observedGeneration', 0)})
        for ns in ('phorvex-system', *APPLICATIONS):
            pods = json.loads(console.kubectl('-n', ns, 'get', 'pods', '-o', 'json'))
            namespace = json.loads(console.kubectl('get', 'namespace', ns, '-o', 'json'))
            result['namespaces'].append({'name': ns, 'uid': namespace['metadata']['uid']})
            pod_items = pods.get('items', [])
            replica_owners = {}
            if ns == 'phorvex-system':
                replicasets = json.loads(console.kubectl('-n', ns, 'get', 'replicasets', '-o', 'json'))
                replica_owners = {r['metadata']['uid']: next((o.get('uid') for o in r['metadata'].get('ownerReferences', []) if o.get('kind') == 'Deployment'), None)
                                  for r in replicasets.get('items', [])}
                pod_items = controller_pods(pod_items, replicasets.get('items', []), result['deployments'])
            for pod in pod_items:
                spec_images = {c['name']: c['image'] for c in pod.get('spec', {}).get('containers', [])}
                result['pods'].append({'namespace': ns, 'name': pod['metadata']['name'], 'uid': pod['metadata']['uid'],
                                       'deploymentUID': next((replica_owners.get(o.get('uid')) for o in pod['metadata'].get('ownerReferences', []) if o.get('kind') == 'ReplicaSet'), None),
                                       'node': pod.get('spec', {}).get('nodeName'), 'phase': pod.get('status', {}).get('phase'),
                                       'containers': [{'name': c['name'], 'image': c.get('image'), 'specImage': spec_images.get(c['name']), 'imageID': c.get('imageID'),
                                                       'ready': c.get('ready'), 'restartCount': c.get('restartCount')} for c in pod.get('status', {}).get('containerStatuses', [])]})
            policies = json.loads(console.kubectl('-n', ns, 'get', 'phorvexpolicies', '-o', 'json'))
            for policy in policies.get('items', []):
                result['policies'].append({'namespace': ns, 'name': policy['metadata']['name'], 'uid': policy['metadata']['uid'],
                                           'generation': policy['metadata'].get('generation'), 'spec': policy['spec']})
    except (OSError, subprocess.SubprocessError, TransportError, ValueError, KeyError) as error:
        result['errors'].append('Deployment/configuration snapshot unavailable: ' + str(error))
    result['authority'] = 'Separate actual Deployment + Pod imageID, not Console compile stamp'
    result.update(actual_versions(result['deployments'], result['apiVersion']))
    return result


def drift(before, after):
    changes = []
    for key in ('apiVersion', 'deployments', 'namespaces', 'policies'):
        def stable(value):
            if key == 'deployments': return sorted(({k: v for k, v in d.items() if k not in ('readyReplicas', 'updatedReplicas', 'observedGeneration')} for d in value), key=lambda d: d['name'])
            return sorted(value, key=lambda d: (d.get('namespace', ''), d.get('name', ''))) if isinstance(value, list) else value
        if stable(before.get(key, [])) != stable(after.get(key, [])): changes.append(key)
    # Target Pod replacement can be the expected rotate effect; controller identity/restart/image changes cannot.
    for ns in ('phorvex-system',):
        one = [p for p in before.get('pods', []) if p['namespace'] == ns]
        two = [p for p in after.get('pods', []) if p['namespace'] == ns]
        if sorted(one, key=lambda p: p['uid']) != sorted(two, key=lambda p: p['uid']): changes.append('controllerPods')
    return changes


class Capture:
    def __init__(self, console, ns, out, event):
        self.console, self.ns, self.out, self.event = console, ns, Path(out), event
        self.ready, self.stop = threading.Event(), threading.Event()
        self.max_bytes = int(os.environ.get('BENCHMARK_CAPTURE_MAX_BYTES', str(256 * 1024 * 1024)))
        self.result = {'startedAt': utc(), 'bytes': 0, 'records': 0, 'fullTraceRecords': 0, 'gaps': []}
        self.response = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def gap(self, reason):
        self.result['gaps'].append({'time': utc(), 'reason': reason})
        self.event('warn', self.ns + ': capture gap: ' + reason)

    def run(self):
        try:
            self.response = self.console.open('/api/live?tenant=' + self.ns + '&namespace=' + self.ns + '&tail=1', timeout=60)
            if 'text/event-stream' not in self.response.headers.get('Content-Type', ''):
                raise TransportError('Console did not return SSE')
            data, kind = [], ''
            with (self.out / 'raw' / ('audit-' + self.ns + '.jsonl')).open('w') as records, \
                 (self.out / 'raw' / ('sse-' + self.ns + '.txt')).open('wb') as raw:
                while not self.stop.is_set():
                    line = self.response.readline(8 * 1024 * 1024 + 1)
                    if not line:
                        if not self.stop.is_set(): self.gap('Unexpected stream end; no silent reconnection')
                        break
                    self.result['bytes'] += len(line)
                    if self.result['bytes'] > self.max_bytes:
                        self.gap('Capture byte cap reached'); break
                    if len(line) > 8 * 1024 * 1024:
                        self.gap('SSE line limit reached'); break
                    raw.write(line)
                    if not self.ready.is_set(): self.result['readyAt'] = utc()
                    self.ready.set()
                    line = line.decode('utf-8').rstrip('\r\n')
                    if line.startswith('event:'): kind = line[6:].strip()
                    elif line.startswith('data:'): data.append(line[5:].lstrip())
                    elif not line:
                        if data:
                            try:
                                value = json.loads('\n'.join(data))
                                if kind and kind != 'message': self.gap('Server SSE notice: ' + json.dumps(value, ensure_ascii=False))
                                elif value.get('namespace') != self.ns or value.get('tenant') != self.ns: self.gap('Scoped stream returned another namespace/tenant')
                                else:
                                    records.write(json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n')
                                    records.flush(); self.result['records'] += 1
                                    if isinstance(value.get('decisionTrace'), dict): self.result['fullTraceRecords'] += 1
                            except (ValueError, UnicodeError, AttributeError): self.gap('SSE event parse failed')
                        data, kind = [], ''
        except (TransportError, OSError, ValueError) as error:
            if not self.stop.is_set(): self.gap(str(error))
        finally:
            self.result['finishedAt'] = utc()

    def close(self):
        self.stop.set()
        # Close the owned response. A quiet server read may only release after its 60s socket budget.
        if self.response:
            try:
                self.response.fp.raw._sock.shutdown(socket.SHUT_RDWR)
            except (AttributeError, OSError): pass
            try: self.response.close()
            except OSError: pass
        self.thread.join(timeout=5)
        if self.thread.is_alive(): self.gap('Capture did not finish before export deadline')


class Campaign:
    def __init__(self, request, out, console):
        self.request, self.out, self.console = request, Path(out), console
        self.cancelled = threading.Event()
        self.completed, self.cases, self.errors = 0, [], []
        self.locks = {key: threading.Lock() for key in (*APPLICATIONS, 'shared-model-gateway', 'shared-crm')}
        self.started = utc()
        self.deadline = time.monotonic() + min(14400, max(60, int(os.environ.get('BENCHMARK_MAX_SECONDS', '14400'))))
        self.total = 0
        self.version = {}
        self.captures = {}
        self.global_failure = ''

    def event(self, level, message):
        append(self.out / 'events.jsonl', {'time': utc(), 'level': level, 'message': message})

    def stopping(self):
        parent = os.environ.get('BENCHMARK_PARENT_PID')
        if parent:
            try: os.kill(int(parent), 0)
            except (OSError, ValueError): self.cancelled.set()
        return self.cancelled.is_set() or (self.out / 'cancel.flag').exists() or time.monotonic() >= self.deadline

    def progress(self, status='running'):
        dump(self.out / 'progress.json', {'status': status, 'total': self.total, 'completed': self.completed,
                                         'version': self.version, 'errors': self.errors})

    def store(self, case):
        with LOCAL_LOCK:
            self.cases.append(case); self.completed += 1
            append(self.out / 'cases.jsonl', case); self.progress()
        self.event('info' if case['status'] == 'completed' else 'warn', case['namespace'] + '/' + case['id'] + ': ' + case['status'])

    def exact_result(self, attack_id):
        value = self.console.request('/api/attack-results?includeObservations=true&limit=1&id=' + urllib.parse.quote(attack_id, safe=''))
        records = [r for r in value.get('attacks', []) if r.get('id') == attack_id]
        if len(records) > 1: raise TransportError('Multiple records for exact producer identity')
        return records[0] if records else None

    def execute(self, case):
        row = {**case, 'startedAt': utc()}
        if self.stopping():
            row.update(status='cancelled', reason='Campaign stopped before launch'); row['finishedAt'] = utc(); self.store(row); return
        if self.global_failure:
            row.update(status='blocked', reason=self.global_failure); row['finishedAt'] = utc(); self.store(row); return
        if case.get('benchmarkBlocked'):
            row.update(status='blocked', reason=case.get('benchmarkBlockReason') or 'Known producer/readback defect'); row['finishedAt'] = utc(); self.store(row); return
        if not case.get('compatible') or not case.get('armed'):
            row.update(status='blocked', reason=case.get('reason') or 'Catalogue not compatible/armed'); row['finishedAt'] = utc(); self.store(row); return
        capture = self.captures[case['namespace']]
        if not capture.ready.is_set() or capture.result['gaps']:
            row.update(status='blocked', reason='Original audit capture unavailable or incomplete before launch'); row['finishedAt'] = utc(); self.store(row); return
        acquired = []
        try:
            for name in dependency_locks(case):
                while not self.locks[name].acquire(timeout=.2):
                    if self.stopping():
                        row.update(status='cancelled', reason='Stopped while waiting for shared producer'); return
                acquired.append(self.locks[name])
            if self.stopping(): row.update(status='cancelled', reason='Stopped before launch'); return
            if self.global_failure:
                row.update(status='blocked', reason=self.global_failure); return
            if capture.result['gaps']:
                row.update(status='blocked', reason='Audit capture became incomplete while waiting for shared producer'); return
            body = launch_body(case)
            # Refresh arming immediately before firing; stateful prior defenses may retire an entry.
            advertised = self.console.request('/api/workload/attacks?namespace=' + case['namespace'])
            match = next((c for c in advertised.get('live', []) if c.get('id') == case['id'] and c.get('endpoint') == case['endpoint']), None)
            if not match or not match.get('armed') or not match.get('compatible'):
                row.update(status='blocked', reason=(match or {}).get('reason') or 'Live entry no longer armed'); return
            intent = {'time': utc(), 'namespace': case['namespace'], 'caseId': case['id'], 'endpoint': case['endpoint'], 'body': body}
            append(self.out / 'raw' / 'launch-intents.jsonl', intent)
            try:
                response = self.console.request(case['endpoint'], 'POST', body)
            except HTTPFailure as error:
                row.update(status='blocked' if error.status in (401, 403) else 'incomplete',
                           reason=str(error), launchError=error.body)
                if error.status not in (401, 403):
                    self.global_failure = 'Ambiguous producer POST; no further launches until reconciliation'
                return
            except (TransportError, ValueError):
                row.update(status='incomplete', reason='Ambiguous POST acceptance; not retried; reconcile original producer intent')
                self.global_failure = row['reason']; return
            row['launchResponse'] = response
            attack_id = response.get('attackId')
            if not isinstance(attack_id, str) or not attack_id:
                row.update(status='incomplete', reason='Producer response lacks exact record ID; launch not retried')
                self.global_failure = row['reason']; return
            row['attackRecordId'] = attack_id
            append(self.out / 'raw' / 'accepted-launches.jsonl', {**intent, 'attackRecordId': attack_id, 'response': response})
            self.event('info', case['namespace'] + '/' + case['id'] + ': following exact result ' + attack_id)
            # Cancellation prevents more launches but observes the already accepted record to its deadline.
            end = min(self.deadline + 960, time.monotonic() + budget(case))
            last = None
            while time.monotonic() < end:
                try:
                    result = self.exact_result(attack_id)
                    if result:
                        if result.get('namespace') != case['namespace']:
                            raise TransportError('Exact result namespace mismatch')
                        last = result
                        append(self.out / 'raw' / 'result-observations.jsonl', {'time': utc(), 'attackRecordId': attack_id, 'result': result})
                        if result.get('status') in ('done', 'partial'):
                            row.update(status='completed' if result['status'] == 'done' else 'incomplete', result=result,
                                       **{key: result.get(key) for key in ('outcome', 'outcomeClass', 'phorvexAction', 'actuated', 'evidenceKind')})
                            row.update(observedActuator=result.get('phorvexAction') or result.get('responseAction') or '',
                                       evidenceStatus='partial' if result['status'] == 'partial' or result.get('decisionAuditReadGap') else 'exact-decision' if typed_links(result) else 'unlinked-original-record',
                                       evidenceCounts={'exactResults': 1, 'decisionLinks': len(result.get('decisionTraceEvidence') or []),
                                                       'behavioralProbe': int(any(k.endswith('Probe') and isinstance(v, dict) for k, v in result.items()))})
                            if result['status'] == 'partial': row['reason'] = result.get('observationError') or 'Producer returned partial evidence'
                            return
                except (TransportError, ValueError) as error:
                    append(self.out / 'raw' / 'read-errors.jsonl', {'time': utc(), 'attackRecordId': attack_id, **error_details(error)})
                    if isinstance(error, HTTPFailure) and error.status in (400, 401, 403):
                        row.update(status='incomplete', reason='Exact result reader rejected request; accepted launch requires reconciliation', result=last)
                        self.global_failure = row['reason']; return
                time.sleep(float(os.environ.get('BENCHMARK_POLL_SECONDS', '3')))
            row.update(status='incomplete', reason='Exact record not terminal within producer-specific observation budget', result=last)
            self.global_failure = 'A producer may still be active after observation timeout; scheduling stopped'
        except (TransportError, ValueError) as error:
            row.update(status='blocked', reason=str(error))
        finally:
            for lock in reversed(acquired): lock.release()
            row['finishedAt'] = utc()
            self.store(row)

    def app_group(self, cases):
        for case in cases: self.execute(case)

    def run(self):
        self.event('info', 'Capturing deployed identities and current Live catalogue')
        before = snapshot(self.console)
        dump(self.out / 'raw' / 'snapshot-before.json', before)
        current = catalogue(self.console, self.request['applications'])
        dump(self.out / 'raw' / 'catalogue.json', current)
        self.version = before
        # Preserve all current entries; optional planner cases are an ordering hint, not a way to silently omit blocked rows.
        all_cases = [entry for app in current['applications'] for entry in app['live']]
        ordering = {(c.get('namespace'), c.get('id')): i for i, c in enumerate(self.request.get('cases', []))}
        all_cases.sort(key=lambda c: ordering.get((c['namespace'], c['id']), len(ordering)))
        self.total = len(all_cases)
        self.errors.extend(current.get('errors', []))
        if before['errors']:
            self.errors.extend(before['errors']); self.global_failure = 'Version/configuration identity could not be pinned before launch'
        self.global_failure = readiness_error(before) or self.global_failure
        if not before.get('operator') or not before.get('console') or before['operator'] != before['console'] or before['operator'] in ('latest', 'dev'):
            self.global_failure = 'Actual deployed manager/Console versions are missing, mutable or mismatched'
        preflight_error = self.global_failure
        if preflight_error:
            self.errors.append('Preflight rejected: ' + preflight_error)
            self.event('error', self.errors[-1])
        self.progress()
        for ns in self.request['applications']:
            capture = self.captures[ns] = Capture(self.console, ns, self.out, self.event)
            capture.thread.start()
        for capture in self.captures.values(): capture.ready.wait(timeout=20)
        self.event('info', 'Observation streams started; running ' + self.request['mode'] + ' catalogue with shared producer locks')
        if self.request['mode'] == 'serial':
            self.app_group(all_cases)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.request['applications'])) as pool:
                futures = [pool.submit(self.app_group, [c for c in all_cases if c['namespace'] == ns]) for ns in self.request['applications']]
                for future in futures: future.result()
        try: after = snapshot(self.console)
        except (TransportError, ValueError):
            after = {'apiVersion': {}, 'errors': ['Final deployed identity snapshot failed'], 'deployments': [], 'pods': [], 'namespaces': [], 'policies': []}
        dump(self.out / 'raw' / 'snapshot-after.json', after)
        changed = drift(before, after)
        if changed: self.errors.append('Deployment/configuration drift: ' + ', '.join(changed))
        self.errors.extend(after['errors'])
        if self.global_failure and self.global_failure != preflight_error:
            self.errors.append('Scheduling stopped: ' + self.global_failure)
        for capture in self.captures.values(): capture.close()
        gaps = [dict(namespace=ns, **gap) for ns, c in self.captures.items() for gap in c.result['gaps']]
        incomplete = bool(self.global_failure or self.errors or gaps or any(c['status'] == 'incomplete' for c in self.cases))
        status = 'cancelled' if self.stopping() else 'incomplete' if incomplete else 'completed'
        manifest = {'id': self.request['id'], 'status': status, 'mode': self.request['mode'], 'model': self.request.get('model'),
                    'startedAt': self.started, 'finishedAt': utc(), 'total': self.total, 'completed': self.completed,
                    'version': before, 'versionAfter': after, 'versionDrift': changed,
                    'preflight': {'passed': not preflight_error, 'error': preflight_error or None},
                    'capture': {ns: capture.result for ns, capture in self.captures.items()}, 'captureGaps': gaps,
                    'errors': self.errors, 'artifacts': [],
                    'limitations': ['Only original typed producer outcomes support their declared scopes.',
                                    'Realized CNorm/CFlow unavailable without compatible measurement definition and window.',
                                    'Shared model-gateway and CRM mutation locks can reduce parallelism.',
                                    'NOOP requires a recorded no-selection outcome. Missing audit is a coverage gap.']}
        manifest['reproduction'] = {'workerSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                    'exporterSHA256': hashlib.sha256(Path(__file__).with_name('exporter.py').read_bytes()).hexdigest(),
                                    'templateSHA256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in template_paths()},
                                    'requestedSource': os.environ.get('BENCHMARK_SOURCE_SHA', ''),
                                    'model': self.request.get('model'), 'policyPins': before['policies']}
        self.event('info', 'Exporting RAW templates from retained original decision traces')
        validation = export_workbooks(self.out, self.request, manifest)
        manifest['exportValidation'] = validation
        manifest['coverage'] = {'fullTraces': validation['uniqueTraces'], 'traceConflicts': len(validation['traceConflicts']),
                                'expectedCostFailures': validation['costChecksFailed'], 'realizedCostsAvailable': 0,
                                'realizedCostStatus': 'UNAVAILABLE', 'captureGapCount': len(gaps),
                                'decisionTraceCompleteness': 'UNVERIFIED; no independent completed-tick denominator captured',
                                'behavioralOutcomeBasis': 'Original per-case producer oracle only; no blanket acceptance'}
        if validation['traceConflicts'] or validation['costChecksFailed']:
            manifest['status'] = 'incomplete'; manifest['errors'].append('Exporter found conflicting identities or expected-cost discrepancies')
        manifest['artifacts'] = [{'name': COST_FILE, 'label': 'Expected vs measured costs'},
                                 {'name': GATES_FILE, 'label': 'Tick action gates'},
                                 {'name': 'evidence.zip', 'label': 'Original evidence and reproducibility'}]
        dump(self.out / 'manifest.json', manifest)
        self.progress(manifest['status'])
        self.event('info', 'Campaign ' + manifest['status'] + '; Excel artifacts retained')
        self.bundle()
        return manifest

    def bundle(self):
        hashes = {}
        with zipfile.ZipFile(self.out / 'evidence.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
            for path in sorted(self.out.rglob('*')):
                if not path.is_file() or path.is_symlink() or path.name.endswith('.tmp') or path.name in ('evidence.zip', 'cancel.flag') or any(part.startswith('.') for part in path.relative_to(self.out).parts): continue
                relative = str(path.relative_to(self.out))
                hashes[relative] = file_hash(path)
                bundle.write(path, relative)
            for path in [Path(__file__), Path(__file__).with_name('exporter.py'), Path(__file__).with_name('requirements.txt'), *template_paths()]:
                name = 'reproduction/' + ('templates/' if path.suffix == '.xlsx' else '') + path.name
                hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest(); bundle.write(path, name)
            bundle.writestr('SHA256SUMS', ''.join(value + '  ' + name + '\n' for name, value in hashes.items()))


def validate_request(value):
    if value.get('mode') not in ('serial', 'parallel'): raise ValueError('mode must be serial or parallel')
    apps = value.get('applications')
    if not isinstance(apps, list) or not apps or len(apps) != len(set(apps)) or any(a not in APPLICATIONS for a in apps):
        raise ValueError('applications must be unique allowlisted namespaces')
    if not isinstance(value.get('id'), str) or not value['id'] or len(value['id']) > 100: raise ValueError('Run identity is required')
    for case in value.get('cases', []):
        if not isinstance(case, dict) or case.get('namespace') not in apps: raise ValueError('Plan case namespace is outside the requested applications')
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--catalogue', action='store_true')
    parser.add_argument('--request', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--export-only', action='store_true', help='Rebuild both workbooks from retained evidence without network access')
    args = parser.parse_args()
    console, cluster_lock = None, None
    try:
        if args.catalogue:
            def finish_catalogue(*_):
                if console: console.close()
                sys.exit(143)
            signal.signal(signal.SIGTERM, finish_catalogue)
            signal.signal(signal.SIGINT, finish_catalogue)
            console = Console.__new__(Console); console.__init__()
            print(json.dumps(catalogue(console), ensure_ascii=False)); return 0
        if not args.request or not args.out: parser.error('--request and --out are required')
        request = validate_request(json.loads(args.request.read_text()))
        args.out.mkdir(parents=True, exist_ok=True); (args.out / 'raw').mkdir(exist_ok=True)
        if args.export_only:
            manifest = json.loads((args.out / 'manifest.json').read_text())
            print(json.dumps(export_workbooks(args.out, request, manifest))); return 0
        # A resumed process never repeats earlier POSTs. Manual reconciliation keeps old evidence intact.
        if (args.out / 'cases.jsonl').exists() or (args.out / 'raw' / 'launch-intents.jsonl').exists():
            raise ValueError('Run already contains launch evidence; automatic replay refused')
        cluster_lock = Path(os.environ.get('BENCHMARK_CLUSTER_LOCK', str(args.out.parent / '.campaign.lock'))).open('a')
        try: fcntl.flock(cluster_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('Another benchmark campaign holds the cluster mutation lock') from None
        dump(args.out / 'request.json', request)
        (args.out / 'cases.jsonl').touch()
        console = Console(args.out)
        campaign = Campaign(request, args.out, console)
        signal.signal(signal.SIGTERM, lambda *_: campaign.cancelled.set())
        signal.signal(signal.SIGINT, lambda *_: campaign.cancelled.set())
        manifest = campaign.run()
        print(json.dumps({'id': request['id'], 'status': manifest['status'], 'artifacts': manifest['artifacts']}))
        return 0
    except Exception as error:
        # Error strings here are sanitized; upstream raw records only go to protected artifacts.
        message = str(error) if isinstance(error, (ValueError, TransportError)) else 'Worker failed: ' + type(error).__name__
        if args.out:
            dump(args.out / 'progress.json', {'status': 'failed', 'errors': [message], 'total': 0, 'completed': 0})
            dump(args.out / 'manifest.json', {'status': 'failed', 'errors': [message], 'artifacts': [], 'finishedAt': utc()})
        print(json.dumps({'error': message}), file=sys.stderr); return 1
    finally:
        if console: console.close()
        if cluster_lock: cluster_lock.close()


if __name__ == '__main__': sys.exit(main())
