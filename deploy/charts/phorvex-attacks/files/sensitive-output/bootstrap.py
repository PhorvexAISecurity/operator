import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request

TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
HOST = os.environ["KUBERNETES_SERVICE_HOST"]
PORT = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
BASE = f"https://{HOST}:{PORT}/api/v1"
NAMESPACE = os.environ["POD_NAMESPACE"]
PODS = os.environ["FIXTURE_PODS"].split(",")
PROXY_SHA = os.environ["PROXY_SOURCE_SHA256"]
SUPPORT_SHA = os.environ["SUPPORT_SOURCE_SHA256"]
RULE_ID = "support-internal-audit-marker-v1"
context = ssl.create_default_context(cafile=CA_PATH)
token = open(TOKEN_PATH, encoding="ascii").read().strip()


def call(method, path, body=None, content_type="application/json"):
    raw = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(BASE + path, data=raw, method=method,
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": content_type})
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        return json.loads(response.read())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def provision(name):
    pod = None
    for _ in range(60):
        try:
            pod = call("GET", f"/namespaces/{NAMESPACE}/pods/{name}")
            if pod["metadata"].get("uid"):
                break
        except urllib.error.HTTPError:
            pass
        time.sleep(2)
    if not pod:
        raise RuntimeError("fixture Pod unavailable: " + name)
    uid = pod["metadata"]["uid"]
    rule = canonical({"version": 1, "ruleId": RULE_ID, "podUID": uid, "method": "POST",
                      "path": "/v1/support/case", "contentType": "application/json",
                      "fieldPath": ["diagnostics", "internalAuditMarker"], "maxResponseBytes": 65536})
    rule_sha = hashlib.sha256(rule.encode()).hexdigest()
    cm_name = "phorvex-output-policy-" + name
    annotations = {"phorvex.ai/output-policy-configmap": cm_name,
                   "phorvex.ai/output-policy-rule-sha256": rule_sha,
                   "phorvex.ai/output-proxy-source-sha256": PROXY_SHA,
                   "phorvex.ai/output-support-source-sha256": SUPPORT_SHA}
    call("PATCH", f"/namespaces/{NAMESPACE}/pods/{name}", {"metadata": {"annotations": annotations}},
         "application/merge-patch+json")
    initial = canonical({"version": 1, "ruleId": RULE_ID,
                         "configMapUID": "00000000-0000-0000-0000-000000000000",
                         "active": False, "revision": 0, "operationId": ""})
    body = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": cm_name, "namespace": NAMESPACE,
                         "labels": {"phorvex.ai/catalogue-fixture-profile": "sensitive-output"},
                         "ownerReferences": [{"apiVersion": "v1", "kind": "Pod", "name": name,
                                              "uid": uid, "controller": True, "blockOwnerDeletion": False}]},
            "data": {"rule.json": rule, "activation.json": initial}}
    try:
        cm = call("POST", f"/namespaces/{NAMESPACE}/configmaps", body)
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise
        cm = call("GET", f"/namespaces/{NAMESPACE}/configmaps/{cm_name}")
        owner = cm["metadata"].get("ownerReferences", [])
        if len(owner) != 1 or owner[0].get("uid") != uid or cm.get("data", {}).get("rule.json") != rule:
            raise RuntimeError("refusing foreign or stale output policy ConfigMap")
        return
    activation = canonical({"version": 1, "ruleId": RULE_ID, "configMapUID": cm["metadata"]["uid"],
                            "active": False, "revision": 0, "operationId": ""})
    body["metadata"]["resourceVersion"] = cm["metadata"]["resourceVersion"]
    body["data"]["activation.json"] = activation
    call("PUT", f"/namespaces/{NAMESPACE}/configmaps/{cm_name}", body)


for pod_name in PODS:
    provision(pod_name)
