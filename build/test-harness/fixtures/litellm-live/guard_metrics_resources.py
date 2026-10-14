"""Record or delete only M1b metrics objects via an off-gateway kubectl proxy.

DELETE uses API UID/resourceVersion preconditions, after exact spec/metadata
comparison. No credential or Secret endpoint is accepted. Immutable CMs stay.
"""
import argparse
import json
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

NAME='phorvex-litellm-gateway-metrics'
PATHS={
 'ServiceMonitor':f'/apis/monitoring.coreos.com/v1/namespaces/monitoring/servicemonitors/{NAME}',
 'Service':f'/api/v1/namespaces/litellm/services/{NAME}',
 'NetworkPolicy':f'/apis/networking.k8s.io/v1/namespaces/litellm/networkpolicies/{NAME}',
}


def authority(obj):
    m=obj['metadata']
    return {'uid':m['uid'],'spec':obj['spec'],'labels':m.get('labels',{}),
            'annotations':m.get('annotations',{}),'ownerReferences':m.get('ownerReferences',[])}


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('record','delete'))
    p.add_argument('--port',type=int,default=18081);p.add_argument('--receipt',type=Path,required=True)
    p.add_argument('--kind',choices=tuple(PATHS));a=p.parse_args()
    if not 1024<=a.port<=65535:raise ValueError('loopback proxy port required')
    base=f'http://127.0.0.1:{a.port}'
    opener=build_opener(ProxyHandler({}))
    def get(kind):
        with opener.open(base+PATHS[kind],timeout=10) as response:return json.load(response)
    if a.action=='record':
        # The lead first compares these objects with the merged rendered source.
        # Exclusive creation rejects collisions before the receipt is captured.
        receipt={kind:authority(get(kind)) for kind in PATHS}
        with a.receipt.open('x') as f:json.dump(receipt,f,sort_keys=True,indent=2);f.write('\n')
        print('recorded three metrics UID/spec authorities')
    else:
        if a.kind is None:raise ValueError('one explicit recorded kind required')
        current=get(a.kind);prior=json.loads(a.receipt.read_text())[a.kind]
        if authority(current)!=prior:raise ValueError('metrics UID/spec/owner drift: refusing deletion')
        body=json.dumps({'apiVersion':'v1','kind':'DeleteOptions','preconditions':{
            'uid':prior['uid'],'resourceVersion':current['metadata']['resourceVersion']}}).encode()
        request=Request(base+PATHS[a.kind],data=body,method='DELETE',headers={'Content-Type':'application/json'})
        with opener.open(request,timeout=10) as response:
            result=json.load(response)
            if result.get('status')=='Failure':raise ValueError('guarded deletion refused')
        print('deleted only recorded '+a.kind)

if __name__=='__main__':main()
