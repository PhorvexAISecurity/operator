#!/usr/bin/env python3
"""Render additive monitoring resources. Output contains a secret; keep private.

No credentials belong in Git. Prometheus verifies the dashboard's internal TLS CA.
"""
import argparse
import base64
import json
from pathlib import Path


def dashboard():
    ds = {'type': 'prometheus', 'uid': '${datasource}'}
    scope = 'run_id="$run_id",service="phorvex-benchmark"'
    panels = []
    def panel(title, expression, kind, x, y, w, h, description, legend=''):
        item = {'id': len(panels) + 1, 'type': kind, 'title': title,
                'description': description, 'datasource': ds,
                'gridPos': {'x': x, 'y': y, 'w': w, 'h': h},
                'targets': [{'refId': 'A', 'expr': expression, 'instant': True,
                             'format': 'table' if kind == 'table' else 'time_series',
                             'legendFormat': legend}],
                'fieldConfig': {'defaults': {'color': {'mode': 'palette-classic'}}, 'overrides': []}}
        if kind == 'stat':
            item['options'] = {'reduceOptions': {'calcs': ['lastNotNull'], 'fields': '', 'values': False},
                               'colorMode': 'value', 'graphMode': 'none', 'textMode': 'auto'}
        if kind == 'table':
            item['options'] = {'showHeader': True, 'cellHeight': 'sm'}
            item['transformations'] = [{'id': 'organize', 'options': {'excludeByName': {
                'Time': True, 'Value': expression.startswith('benchmark_case_info{'), '__name__': True, 'job': True, 'instance': True,
                'service': True, 'run_id': True}, 'renameByName': {
                    'application': 'Application', 'attack': 'Live attack', 'action': 'Recorded action',
                    'expected_action': 'Expected action',
                    'producer': 'Producer route', 'stack': 'Target stack',
                    'outcome': 'Original outcome', 'actuated': 'Producer actuation flag',
                    'evidence': 'Evidence scope', 'status': 'Case status',
                    'Value': 'Evidence items' if title == 'Evidence item counts' else 'Cases'}}}]
        if title == 'Campaign state': item['options']['textMode'] = 'name'
        panels.append(item)
    panel('Catalogue cases', f'max(benchmark_run_progress{{{scope},kind="total"}})', 'stat', 0, 0, 4, 4,
          'All catalogue/application combinations, including incompatible or blocked cases.')
    panel('Cases processed', f'max(benchmark_run_progress{{{scope},kind="completed"}})', 'stat', 4, 0, 4, 4,
          'Processed does not mean defended or executed. Inspect the original outcome below.')
    panel('Observed actuation', f'sum(benchmark_case_info{{{scope},actuated="true"}})', 'stat', 8, 0, 4, 4,
          'Producer reported actuation. This is not proof of mitigation.')
    panel('Blocked cases', f'sum(benchmark_case_info{{{scope},status="blocked"}})', 'stat', 12, 0, 4, 4,
          'Admission, compatibility, arming or identity prevented execution; never treated as a pass.')
    panel('Incomplete observations', f'sum(benchmark_case_info{{{scope},status="incomplete"}})', 'stat', 16, 0, 4, 4,
          'Capture/transport/observation gaps leave behavior unresolved.')
    panel('Campaign state', f'max by (state,mode) (benchmark_run_progress{{{scope},kind="total"}})', 'stat', 20, 0, 4, 4,
          'Completed means scheduling/export finished, not a blanket security verdict.', '{{state}} · {{mode}}')
    panel('Original outcomes by application', f'sum by(application,outcome) (benchmark_case_info{{{scope}}})',
          'table', 0, 4, 12, 8, 'Outcomes are retained verbatim from original producers, not inferred from selections.')
    panel('Recorded actions by application', f'sum by(application,action,actuated) (benchmark_case_info{{{scope}}})',
          'table', 12, 4, 12, 8, 'Recorded/selected actions remain distinct from actuation and mitigation.')
    panel('Live attacks: action, outcome and evidence', f'benchmark_case_info{{{scope}}}',
          'table', 0, 12, 24, 14, 'Same exact retained case records as Excel exports. Unknown is not NOOP. Use dashboard evidence.zip for record IDs, source UIDs, hashes and full gates.')
    panel('Evidence item counts', f'benchmark_case_evidence_total{{{scope}}}', 'table', 0, 26, 24, 8,
          'Counts alone do not prove effect; exact record scope and capture gaps are in the original evidence.')
    panel('Actual deployed versions and planner', 'benchmark_run_info{' + scope + '}', 'table', 0, 34, 24, 5,
          'Versions are from retained Deployment identity, not mutable Console compile stamps.')
    return {'uid': 'phorvex-benchmark', 'title': 'Phorvex — Benchmark: Attacks, Actions & Evidence',
            'schemaVersion': 39, 'version': 1, 'editable': True, 'tags': ['phorvex', 'benchmark'],
            'timezone': 'browser', 'refresh': '15s', 'time': {'from': 'now-6h', 'to': 'now'},
            'templating': {'list': [
                {'name': 'datasource', 'label': 'Prometheus', 'type': 'datasource', 'query': 'prometheus',
                 'current': {}, 'options': [], 'refresh': 1},
                {'name': 'run_id', 'label': 'Benchmark run', 'type': 'query', 'datasource': ds,
                 'definition': 'label_values(benchmark_run_progress{service="phorvex-benchmark"},run_id)',
                 'query': {'query': 'label_values(benchmark_run_progress{service="phorvex-benchmark"},run_id)', 'refId': 'run'},
                 'refresh': 1, 'multi': False, 'includeAll': False, 'sort': 2, 'options': [], 'current': {}}]},
            'panels': panels}


def resources(token, ca, proxy_url=None, proxy_authorization=None):
    namespace = 'monitoring'
    result = {'apiVersion': 'v1', 'kind': 'List', 'items': [
        {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
         'metadata': {'name': 'phorvex-benchmark-metrics', 'namespace': namespace},
         'data': {'token': base64.b64encode(token.encode()).decode(), 'ca.crt': base64.b64encode(ca).decode()}},
        {'apiVersion': 'monitoring.coreos.com/v1alpha1', 'kind': 'ScrapeConfig',
         'metadata': {'name': 'phorvex-benchmark', 'namespace': namespace, 'labels': {'release': 'kube-prom-stack'}},
         'spec': {'scheme': 'https', 'metricsPath': '/metrics', 'scrapeInterval': '15s', 'scrapeTimeout': '10s',
                  'staticConfigs': [{'targets': ['87.106.63.105:8444'], 'labels': {'service': 'phorvex-benchmark'}}],
                  'authorization': {'type': 'Bearer', 'credentials': {'name': 'phorvex-benchmark-metrics', 'key': 'token'}},
                  'tlsConfig': {'ca': {'secret': {'name': 'phorvex-benchmark-metrics', 'key': 'ca.crt'}},
                                'serverName': '87.106.63.105'}}},
        {'apiVersion': 'v1', 'kind': 'ConfigMap',
         'metadata': {'name': 'phorvex-benchmark-dashboard', 'namespace': namespace,
                      'labels': {'grafana_dashboard': '1'}},
         'data': {'phorvex-benchmark.json': json.dumps(dashboard(), ensure_ascii=False)}}]}
    if proxy_url:
        from urllib.parse import urlparse
        url = urlparse(proxy_url)
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
            raise ValueError('Proxy must be a verified HTTPS origin without URL credentials')
        if not proxy_authorization or not proxy_authorization.startswith('Basic ') or '\n' in proxy_authorization:
            raise ValueError('Private proxy authorization must be a complete Basic header')
        result['items'][0]['data']['proxy-authorization'] = base64.b64encode(proxy_authorization.encode()).decode()
        spec = result['items'][1]['spec']
        spec['proxyUrl'] = proxy_url
        spec['proxyConnectHeader'] = {'Proxy-Authorization': [{'name': 'phorvex-benchmark-metrics', 'key': 'proxy-authorization'}]}
        # Let each TLS hop verify its own identity against the combined CA pool.
        spec['tlsConfig'].pop('serverName', None)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--env', type=Path, required=True)
    p.add_argument('--ca', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--proxy-url', help='Optional existing verified HTTPS CONNECT proxy')
    p.add_argument('--proxy-authorization', type=Path, help='Private file with complete Basic header')
    p.add_argument('--proxy-ca', type=Path, help='Verified public proxy CA/certificate; never its private key')
    args = p.parse_args()
    values = dict(line.split('=', 1) for line in args.env.read_text().splitlines()
                  if line and not line.startswith('#') and '=' in line)
    token = values.get('METRICS_TOKEN', '')
    if len(token) < 24: p.error('METRICS_TOKEN must be provisioned')
    ca = args.ca.read_bytes()
    if b'BEGIN CERTIFICATE' not in ca: p.error('CA must be a PEM certificate')
    authorization = None
    if args.proxy_url:
        if not args.proxy_authorization or not args.proxy_ca: p.error('Proxy auth and verified CA are required')
        authorization = args.proxy_authorization.read_text().strip()
        proxy_ca = args.proxy_ca.read_bytes()
        if b'BEGIN CERTIFICATE' not in proxy_ca or b'PRIVATE KEY' in proxy_ca: p.error('Proxy CA must contain only public certificates')
        ca += b'\n' + proxy_ca
    elif args.proxy_authorization or args.proxy_ca: p.error('Proxy files require --proxy-url')
    import os
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(resources(token, ca, args.proxy_url, authorization), ensure_ascii=False, indent=2) + '\n')
    print('Private additive monitoring manifest written:', args.out)


if __name__ == '__main__': main()
