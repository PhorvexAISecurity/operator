"""Idempotent, crash-safe bootstrap for the catalogue sensitive-output fixture.

For each fixed Pod (gfx-t0069{,-001,-002}) this provisions the Pod-owned
output-policy ConfigMap in the exact shape the console oracle validates
(internal/outputpolicy.ValidateConfigMap): a two-key rule.json + activation.json
ConfigMap controlled by the Pod, plus the Pod annotations that bind the rule and
the reviewed proxy/support source digests. The clean baseline is inactive
(revision 0, no operationId) so the run can later observe the vulnerable leak,
drive activation, and verify two-sided redaction.

The canonical rule.json / activation.json bytes are byte-for-byte identical to
Go's outputpolicy.RuleBytes / Activation.Bytes (both sort object keys), which is
what makes ValidateConfigMap/ParseActivation accept them.

Idempotency: re-running converges. A crash between creating the ConfigMap and
writing its final activation leaves the placeholder (zero-UID, inactive) that the
re-entry path repairs; a ConfigMap that is already active is never clobbered. The
Job's restarts and backoff are therefore safe.

The module has no import-time side effects (it only talks to the API server under
__main__), so its pure helpers are unit testable against the Go contract.
"""
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request

RULE_ID = "support-internal-audit-marker-v1"
ROUTE = "/v1/support/case"
ZERO_UID = "00000000-0000-0000-0000-000000000000"
PROFILE = "sensitive-output"
POD_CONFIGMAP_ANNOTATION = "phorvex.ai/output-policy-configmap"
POD_RULE_SHA_ANNOTATION = "phorvex.ai/output-policy-rule-sha256"
POD_PROXY_SHA_ANNOTATION = "phorvex.ai/output-proxy-source-sha256"
POD_SUPPORT_SHA_ANNOTATION = "phorvex.ai/output-support-source-sha256"

TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def rule_json(pod_uid):
    """Byte-for-byte equal to Go outputpolicy.RuleBytes(pod_uid)."""
    return canonical({"version": 1, "ruleId": RULE_ID, "podUID": pod_uid, "method": "POST",
                      "path": ROUTE, "contentType": "application/json",
                      "fieldPath": ["diagnostics", "internalAuditMarker"], "maxResponseBytes": 65536})


def rule_sha256(pod_uid):
    return hashlib.sha256(rule_json(pod_uid).encode("utf-8")).hexdigest()


def activation_json(config_map_uid, *, active=False, revision=0, operation_id=""):
    """Byte-for-byte equal to Go outputpolicy.Activation.Bytes(...)."""
    return canonical({"version": 1, "ruleId": RULE_ID, "configMapUID": config_map_uid,
                      "active": active, "revision": revision, "operationId": operation_id})


def configmap_body(cm_name, namespace, pod_name, pod_uid, rule, activation):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": cm_name, "namespace": namespace,
                         "labels": {"phorvex.ai/catalogue-fixture-profile": PROFILE,
                                    "phorvex.ai/cleanup-policy": "Delete"},
                         "ownerReferences": [{"apiVersion": "v1", "kind": "Pod", "name": pod_name,
                                              "uid": pod_uid, "controller": True,
                                              "blockOwnerDeletion": False}]},
            "data": {"rule.json": rule, "activation.json": activation}}


def _get_or_none(call, path):
    try:
        return call("GET", path)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def _owner_uid(cm):
    for owner in cm.get("metadata", {}).get("ownerReferences", []) or []:
        if owner.get("controller") and owner.get("kind") == "Pod":
            return owner.get("uid")
    return None


def provision(call, namespace, name, proxy_sha, support_sha, *, attempts=60, sleep=time.sleep):
    """Converge the Pod-owned output-policy ConfigMap for one fixed Pod."""
    uid = None
    for _ in range(attempts):
        pod = _get_or_none(call, "/namespaces/%s/pods/%s" % (namespace, name))
        if pod and pod.get("metadata", {}).get("uid"):
            uid = pod["metadata"]["uid"]
            break
        sleep(2)
    if not uid:
        raise RuntimeError("fixture Pod unavailable: " + name)

    rule = rule_json(uid)
    cm_name = "phorvex-output-policy-" + name
    annotations = {POD_CONFIGMAP_ANNOTATION: cm_name, POD_RULE_SHA_ANNOTATION: rule_sha256(uid),
                   POD_PROXY_SHA_ANNOTATION: proxy_sha, POD_SUPPORT_SHA_ANNOTATION: support_sha}
    # Merge patch is idempotent; re-applying the same annotations is a no-op.
    call("PATCH", "/namespaces/%s/pods/%s" % (namespace, name),
         {"metadata": {"annotations": annotations}}, "application/merge-patch+json")

    cm = _get_or_none(call, "/namespaces/%s/configmaps/%s" % (namespace, cm_name))
    if cm is None:
        # The ConfigMap UID is server-assigned, so create with a placeholder
        # activation and bind it to the real UID immediately below.
        placeholder = configmap_body(cm_name, namespace, name, uid, rule, activation_json(ZERO_UID))
        try:
            cm = call("POST", "/namespaces/%s/configmaps" % namespace, placeholder)
        except urllib.error.HTTPError as error:
            if error.code != 409:
                raise
            cm = call("GET", "/namespaces/%s/configmaps/%s" % (namespace, cm_name))

    if _owner_uid(cm) != uid or cm.get("data", {}).get("rule.json") != rule:
        raise RuntimeError("refusing foreign or stale output policy ConfigMap: " + cm_name)

    cm_uid = cm["metadata"]["uid"]
    desired = activation_json(cm_uid)
    current = cm.get("data", {}).get("activation.json")
    if current == desired:
        return  # already the clean inactive baseline

    parsed = None
    if isinstance(current, str) and current:
        try:
            parsed = json.loads(current)
        except (ValueError, json.JSONDecodeError):
            parsed = None
    if isinstance(parsed, dict) and (parsed.get("active") or parsed.get("revision") not in (0, None)):
        raise RuntimeError("refusing to reset an active sensitive-output policy: " + cm_name)

    final = configmap_body(cm_name, namespace, name, uid, rule, desired)
    final["metadata"]["resourceVersion"] = cm["metadata"]["resourceVersion"]
    call("PUT", "/namespaces/%s/configmaps/%s" % (namespace, cm_name), final)


def _api_call(base, token, context):
    def call(method, path, body=None, content_type="application/json"):
        raw = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(base + path, data=raw, method=method,
                                         headers={"Authorization": "Bearer " + token,
                                                  "Accept": "application/json",
                                                  "Content-Type": content_type})
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            return json.loads(response.read())
    return call


def main():
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    namespace = os.environ["POD_NAMESPACE"]
    pods = [pod for pod in os.environ["FIXTURE_PODS"].split(",") if pod]
    proxy_sha = os.environ["PROXY_SOURCE_SHA256"]
    support_sha = os.environ["SUPPORT_SOURCE_SHA256"]
    context = ssl.create_default_context(cafile=CA_PATH)
    with open(TOKEN_PATH, encoding="ascii") as handle:
        token = handle.read().strip()
    call = _api_call("https://%s:%s/api/v1" % (host, port), token, context)
    for name in pods:
        provision(call, namespace, name, proxy_sha, support_sha)


if __name__ == "__main__":
    main()
