"""Fail closed on nonsecret M1b activation evidence; never accesses Kubernetes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from render import canonical


def checked_recent(value):
    when=datetime.fromisoformat(value.replace('Z','+00:00'))
    age=(datetime.now(timezone.utc)-when).total_seconds()
    if not 0<=age<=1800:raise ValueError('fresh owner evidence (at most 30 minutes) required')


def check(closure, inputs, runtime_receipt, network_config, network_proof, prometheus):
    def read(name):return json.loads((inputs/name).read_text())
    d=read('deployment.json');base=closure['baseline']
    if (d['metadata']['uid']!=base['deploymentUID'] or
            hashlib.sha256(canonical(d['spec']).encode()).hexdigest()!=base['deploymentSpecSHA256']):
        raise ValueError('gateway UID/spec drift requires new review')
    source=read('gateway-source.json')
    if (source['metadata']['uid']!=base['sourceUID'] or source.get('immutable') is not True or
            set(source.get('data',{}))!={'gateway.py'} or source.get('binaryData') or
            hashlib.sha256(source['data']['gateway.py'].encode()).hexdigest()!=closure['previousGatewaySourceSHA256']):
        raise ValueError('gateway source UID/bytes drift')
    service=read('service.json')
    if service['metadata']['uid']!=base['serviceUID'] or service['spec']['ports'][0]['targetPort']!=4001:
        raise ValueError('serving Service drift')
    for prior in base['profiles']:
        p=next((p for p in read('profiles.json') if p['metadata']['name']==prior['name']),None)
        if p is None or p['metadata']['uid']!=prior['uid'] or p.get('immutable') is not True or hashlib.sha256(p['data']['profile.json'].encode()).hexdigest()!=prior['profileSHA256']:
            raise ValueError('retained profile UID/bytes drift')
    if runtime_receipt.get('schema')!='phorvex-litellm-gateway-runtime-reuse-receipt-v1' or runtime_receipt.get('result')!='pass-local-and-published-image-protocol' or runtime_receipt.get('imageByDigest')!=closure['gatewayImageByDigest'] or runtime_receipt.get('gatewaySourceSHA256')!=closure['gatewaySourceSHA256'] or not re.fullmatch('[0-9a-f]{40}',runtime_receipt.get('sourceCommit','')):
        raise ValueError('actual published image/source proof required')
    checked_recent(network_config['utc'])
    agent=next((c for c in network_config['containerArgs'] if c['name']=='aws-eks-nodeagent'),{})
    args=agent.get('args',[])
    if '--enable-network-policy=true' not in args or '--enable-network-policy=false' in args:
        raise ValueError('CNI network enforcement disabled: stop before exposing 4003')
    # This is owner-produced evidence from a representative isolated data-plane
    # witness; actual gateway allow/deny controls are repeated after rollout.
    checked_recent(network_proof['utc'])
    if (network_proof.get('schema')!='phorvex-litellm-network-enforcement-proof-v1' or
            network_proof.get('allowed') is not True or network_proof.get('denied') is not True or
            network_proof.get('prometheusPodLabels')!=base['prometheusPodLabels'] or
            not network_proof.get('allowedPodUID') or not network_proof.get('deniedPodUID') or
            network_proof['allowedPodUID']==network_proof['deniedPodUID'] or not network_proof.get('evidenceSHA256')):
        raise ValueError('owned network allowed/denied witness required')
    checked_recent(prometheus['utc'])
    for name in ('vllm-up','vllm-native','vllm-ReqRate'):
        result=prometheus['queries'][name]['result']
        samples=result.get('data',{}).get('result',[])
        if result.get('status')!='success' or not samples:
            raise ValueError('native vLLM source/bridge prerequisite unavailable: '+name)
        for row in samples:
            value=float(row['value'][1])
            if not math.isfinite(value) or value<0 or (name=='vllm-up' and value!=1):
                raise ValueError('native vLLM source/bridge prerequisite invalid: '+name)
    output=read('output-policy.json')
    if output is not None and output!={'version':2,'revision':0,'entries':[]}:
        raise ValueError('installed output policy must remain quiescent; never reset it')
    print('M1b source/runtime/network/native-source guards PASS; release and idle/journal gates still required')


def main():
    parser=argparse.ArgumentParser()
    for name in ('closure','inputs','runtime-receipt','network-config','network-proof','prometheus'):
        parser.add_argument('--'+name,type=Path,required=True)
    a=parser.parse_args()
    read=lambda path:json.loads(path.read_text())
    check(read(a.closure),a.inputs,read(a.runtime_receipt),read(a.network_config),read(a.network_proof),read(a.prometheus))

if __name__=='__main__':main()
