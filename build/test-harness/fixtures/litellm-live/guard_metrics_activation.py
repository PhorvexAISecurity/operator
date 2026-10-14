"""Fail closed on nonsecret activation evidence; never accesses Kubernetes.

V1 is explicitly the historical network-enforced branch. V2 is bearer auth;
valid auth proves protection with disabled CNI, while native vLLM remains a hard gate.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from render import canonical
from render_metrics import render, protection

ROOT = Path(__file__).resolve().parents[4]
NATIVE_QUERIES = {
    'vllm-up': 'up{job="vllm"}',
    'vllm-up10m': 'min_over_time(up{job="vllm"}[10m])',
    'vllm-native': 'vllm:request_success_total{namespace="vllm"}',
    'vllm-ReqRate': 'sum by (pod) (rate(http_requests_total{namespace="vllm"}[1m]))',
}


def checked_recent(value):
    try:
        when = datetime.fromisoformat(value.replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - when).total_seconds()
    except (AttributeError, TypeError, ValueError):
        raise ValueError('fresh owner evidence (at most 30 minutes) required') from None
    if not 0 <= age <= 1800:
        raise ValueError('fresh owner evidence (at most 30 minutes) required')


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def verify_network(base, network_config, network_proof):
    if not isinstance(network_config, dict) or not isinstance(network_proof, dict):
        raise ValueError('explicit network configuration and allowed/denied proof required')
    checked_recent(network_config['utc'])
    agent = next((c for c in network_config['containerArgs'] if c['name'] == 'aws-eks-nodeagent'), {})
    args = agent.get('args', [])
    if '--enable-network-policy=true' not in args or '--enable-network-policy=false' in args:
        raise ValueError('CNI network enforcement disabled: stop before exposing 4003')
    mode = next((e.get('value') for e in network_config.get('networkPolicyEnv', [])
                 if e.get('name') == 'NETWORK_POLICY_ENFORCING_MODE'), None)
    if mode != 'strict':
        raise ValueError('strict CNI startup enforcement required before exposing 4003')
    checked_recent(network_proof['utc'])
    if (network_proof.get('schema') != 'phorvex-litellm-network-enforcement-proof-v1' or
            network_proof.get('allowed') is not True or network_proof.get('denied') is not True or
            network_proof.get('prometheusPodLabels') != base['prometheusPodLabels'] or
            not network_proof.get('allowedPodUID') or not network_proof.get('deniedPodUID') or
            network_proof['allowedPodUID'] == network_proof['deniedPodUID'] or
            not re.fullmatch('[0-9a-f]{64}', network_proof.get('evidenceSHA256', ''))):
        raise ValueError('owned network allowed/denied witness required')


def verify_native(prometheus, *, authenticated=False):
    checked_recent(prometheus['utc'])
    names = NATIVE_QUERIES if authenticated else ('vllm-up', 'vllm-native', 'vllm-ReqRate')
    observed = {}
    for name in names:
        query = prometheus.get('queries', {}).get(name, {})
        if authenticated and query.get('query') != NATIVE_QUERIES[name]:
            raise ValueError('exact native vLLM source/bridge query required: ' + name)
        result = query.get('result', {})
        samples = result.get('data', {}).get('result', [])
        if result.get('status') != 'success' or not samples:
            raise ValueError('native vLLM source/bridge prerequisite unavailable: ' + name)
        observed[name] = set()
        for row in samples:
            try:
                value = float(row['value'][1])
            except (KeyError, IndexError, TypeError, ValueError):
                raise ValueError('native vLLM source/bridge prerequisite invalid: ' + name) from None
            if not math.isfinite(value) or value < 0 or (name in ('vllm-up', 'vllm-up10m') and value != 1):
                raise ValueError('native vLLM source/bridge prerequisite invalid: ' + name)
            if authenticated:
                pod = row.get('metric', {}).get('pod')
                if not pod or (name != 'vllm-ReqRate' and row['metric'].get('namespace') != 'vllm'):
                    raise ValueError('actual native vLLM serving-pod labels required: ' + name)
                checked_recent(datetime.fromtimestamp(float(row['value'][0]), timezone.utc).isoformat())
                observed[name].add(pod)
    if authenticated:
        pods = observed['vllm-up']
        if any(observed[name] != pods for name in NATIVE_QUERIES):
            raise ValueError('native vLLM query populations differ from current serving targets')
        targets = [target for target in prometheus.get('targets', [])
                   if target.get('labels', {}).get('job') == 'vllm']
        if (not targets or {target.get('labels', {}).get('pod') for target in targets} != pods or
                any(target.get('health') != 'up' or target.get('lastError') or
                    target.get('labels', {}).get('namespace') != 'vllm' for target in targets)):
            raise ValueError('healthy current native vLLM targets required')
        groups = [group for group in prometheus.get('bridgeRules', []) if group.get('name') == 'phorvex.physics.bridge']
        if len(groups) != 1:
            raise ValueError('existing healthy native vLLM bridge evidence required')
        bridge = next((rule for rule in groups[0].get('rules', []) if rule.get('name') == 'http_requests_total'), {})
        if (bridge.get('query') != 'sum by (namespace, pod, container, node) (vllm:request_success_total)' or
                bridge.get('health') != 'ok'):
            raise ValueError('existing healthy native vLLM bridge evidence required')
        checked_recent(bridge.get('lastEvaluation'))


def verify_artifacts(closure, inputs, artifacts):
    if artifacts is None:
        raise ValueError('reviewed candidate artifact files required')
    expected_names = {'gateway-metrics-source-configmap.json', 'metrics-service.json',
        'metrics-servicemonitor.json', 'metrics-networkpolicy.json', 'deployment-metrics-json-patch.json',
        'deployment-metrics-rollback-json-patch.json', 'previous-console-bindings.json'}
    expected_names.update(binding['configMapName'] + '.json' for binding in closure['profiles'])
    if set(closure.get('artifactsSHA256', {})) != expected_names:
        raise ValueError('complete reviewed artifact hashes required')
    objects = {}
    for name in expected_names:
        if Path(name).name != name:
            raise ValueError('invalid candidate artifact path')
        path = artifacts / name
        if not path.is_file() and artifacts.resolve() == (ROOT / 'deploy/monitoring/litellm-m5').resolve():
            path = ROOT / 'deploy/helm/phorvex-stack/files/litellm-m5' / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != closure['artifactsSHA256'][name]:
            raise ValueError('reviewed candidate artifact hash differs: ' + name)
        objects[name] = json.loads(path.read_text())
    def read(name):
        return json.loads((inputs / name).read_text())
    policies = [p for p in read('networkpolicies.json')
                if p.get('metadata', {}).get('name') != 'phorvex-litellm-gateway-metrics']
    auth = closure['metricsProtection']
    derived = render(read('deployment.json'), read('profiles.json'), policies,
        closure['baseline']['prometheusPodLabels'], read('output-policy.json'), enabled=True,
        preserve_unisolated_ingress=not policies, protection_mode=auth['mode'],
        metrics_secret_name=auth['secretName'], metrics_secret_key=auth['secretKey'])
    for key in ('metricsProtection', 'gatewaySourceSHA256', 'previousGatewaySourceSHA256',
                'gatewayImageByDigest', 'previousGatewayImageByDigest', 'profiles',
                'candidateTemplateSHA256', 'monitoringSpecsSHA256', 'networkAudit'):
        if closure.get(key) != derived['metrics-closure.json'].get(key):
            raise ValueError('reviewed candidate closure differs: ' + key)
    for name, value in derived.items():
        if name != 'metrics-closure.json' and value != objects[name]:
            raise ValueError('candidate template/projection/endpoint differs from reviewed baseline: ' + name)
    if objects['previous-console-bindings.json'] != closure['baseline']['previousConsoleBindings']:
        raise ValueError('preceding rollback bindings differ')
    return objects


def check(closure, inputs, runtime_receipt, network_config=None, network_proof=None, prometheus=None,
          *, auth_proof=None, secret_metadata=None, artifacts=None):
    schema = closure.get('schema')
    if schema == 'phorvex-litellm-metrics-candidate-v1':
        if closure.get('metricsProtection', {}).get('mode', 'networkEnforced') != 'networkEnforced':
            raise ValueError('legacy v1 closure requires explicit networkEnforced branch')
        mode = 'networkEnforced'
    elif schema == 'phorvex-litellm-metrics-candidate-v2':
        mode = closure.get('metricsProtection', {}).get('mode')
        if mode != 'bearerToken':
            raise ValueError('v2 closure requires explicit bearerToken protection')
        if closure.get('nativeDecision') != 'B' or closure.get('nativeVLLMPolicy') != 'hardGate':
            raise ValueError('reviewed default B native-vLLM hard gate required')
    else:
        raise ValueError('explicit reviewed metrics protection closure schema required')
    def read(name):
        return json.loads((inputs / name).read_text())
    d = read('deployment.json')
    base = closure['baseline']
    if d['metadata']['uid'] != base['deploymentUID'] or digest(d['spec']) != base['deploymentSpecSHA256']:
        raise ValueError('gateway UID/spec drift requires new review')
    source = read('gateway-source.json')
    if (source['metadata']['uid'] != base['sourceUID'] or source.get('immutable') is not True or
            set(source.get('data', {})) != {'gateway.py'} or source.get('binaryData') or
            hashlib.sha256(source['data']['gateway.py'].encode()).hexdigest() != closure['previousGatewaySourceSHA256']):
        raise ValueError('gateway source UID/bytes drift')
    service = read('service.json')
    if service['metadata']['uid'] != base['serviceUID'] or service['spec']['ports'][0]['targetPort'] != 4001:
        raise ValueError('serving Service drift')
    for prior in base['profiles']:
        p = next((p for p in read('profiles.json') if p['metadata']['name'] == prior['name']), None)
        if (p is None or p['metadata']['uid'] != prior['uid'] or p.get('immutable') is not True or
                set(p.get('data', {})) != {'profile.json'} or p.get('binaryData') or
                hashlib.sha256(p['data']['profile.json'].encode()).hexdigest() != prior['profileSHA256']):
            raise ValueError('retained profile UID/bytes drift')
    receipt_schema = 'phorvex-litellm-gateway-runtime-reuse-receipt-v2' if mode == 'bearerToken' else 'phorvex-litellm-gateway-runtime-reuse-receipt-v1'
    if (runtime_receipt.get('schema') != receipt_schema or
            runtime_receipt.get('result') != 'pass-local-and-published-image-protocol' or
            runtime_receipt.get('imageByDigest') != closure['gatewayImageByDigest'] or
            runtime_receipt.get('gatewaySourceSHA256') != closure['gatewaySourceSHA256'] or
            not re.fullmatch('[0-9a-f]{40}', runtime_receipt.get('sourceCommit', ''))):
        raise ValueError('actual published image/source proof required')
    if mode == 'bearerToken':
        contract = json.loads((ROOT / 'build/integrations/litellm-gateway-runtime/image-contract.json').read_text())
        auth = closure['metricsProtection']
        expected = protection('bearerToken', auth.get('secretName'), auth.get('secretKey'), contract['gatewaySourceSHA256'])
        if (auth != expected or closure['gatewaySourceSHA256'] != contract['gatewaySourceSHA256'] or
                closure['gatewayImageByDigest'] != contract['imageByDigest'] or
                runtime_receipt.get('mountedSourceCommit') != runtime_receipt['sourceCommit'] or
                runtime_receipt.get('publishedImageSourceCommit') != contract['publishedImageSourceCommit'] or
                runtime_receipt.get('publicationReceiptSHA256') != contract['publishedReceiptSHA256'] or
                runtime_receipt.get('previousMetricsSourceSHA256') != contract['previousMetricsSourceSHA256']):
            raise ValueError('exact authenticated source/runtime/publication proof required')
        if (source['metadata'].get('name') != base['sourceConfigMapName'] or
                digest(service['spec']) != base['serviceSpecSHA256'] or service['spec'].get('selector') != {'app': 'litellm'}):
            raise ValueError('baseline source/serving Service closure drift')
        clients = read('clients.json')
        if (clients['metadata'].get('uid') != base['clientsUID'] or clients['metadata'].get('name') != base['clientsConfigMapName'] or
                clients.get('immutable') is not True or set(clients.get('data', {})) != {'clients.json'} or clients.get('binaryData') or
                hashlib.sha256(clients['data']['clients.json'].encode()).hexdigest() != base['clientsSHA256']):
            raise ValueError('client inventory UID/bytes drift')
        for name, expected_hash in base['inputsSHA256'].items():
            if Path(name).name != name or hashlib.sha256((inputs / name).read_bytes()).hexdigest() != expected_hash:
                raise ValueError('fresh reviewed input hash differs: ' + name)
        verify_artifacts(closure, inputs, artifacts)
        if not isinstance(auth_proof, dict) or not isinstance(secret_metadata, dict):
            raise ValueError('fresh real auth witness and metadata-only Secret evidence required')
        checked_recent(auth_proof.get('utc'))
        checked_recent(secret_metadata.get('utc'))
        from provision_metrics_token import validate_metadata
        from verify_metrics_auth import validate_auth_proof
        validate_metadata(secret_metadata, closure)
        validate_auth_proof(auth_proof, closure, secret_metadata)
        # CNI status is recorded independently; auth does not claim enforcement.
        print('bearerToken metrics PROTECTION PASS; CNI enforcement is not inferred')
    else:
        verify_network(base, network_config, network_proof)
    output = read('output-policy.json')
    if output is not None and output != {'version': 2, 'revision': 0, 'entries': []}:
        raise ValueError('installed output policy must remain quiescent; never reset it')
    if prometheus is None:
        raise ValueError('fresh native vLLM source/bridge evidence required')
    verify_native(prometheus, authenticated=mode == 'bearerToken')
    print(mode + ' source/runtime/protection/native-source guards PASS; release and idle/journal gates still required')
    return {'protectionMode': mode, 'protection': 'pass', 'nativeVLLM': 'pass',
            'nativeDecision': 'B', 'releaseAndIdleJournalGates': 'still-required'}


def main():
    parser = argparse.ArgumentParser()
    for name in ('closure', 'inputs', 'runtime-receipt', 'prometheus'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('network-config', 'network-proof', 'auth-proof', 'secret-metadata'):
        parser.add_argument('--' + name, type=Path)
    a = parser.parse_args()
    read = lambda path: json.loads(path.read_text()) if path else None
    check(read(a.closure), a.inputs, read(a.runtime_receipt), read(a.network_config), read(a.network_proof),
          read(a.prometheus), auth_proof=read(a.auth_proof), secret_metadata=read(a.secret_metadata), artifacts=a.closure.parent)


if __name__ == '__main__':
    main()
