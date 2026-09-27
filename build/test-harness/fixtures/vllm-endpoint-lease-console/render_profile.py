"""Render the reviewed, non-secret vLLM caller-lease console profile offline.

ADOPTION.json comes from the owner activation package after immutable source,
caller Secrets, policy, journal and public Service identities are known. This
tool does not contact a cluster or create credentials.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re


UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
CREATOR = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
MODEL = "Qwen/Qwen2.5-7B-Instruct-AWQ"
FIELDS = (
    "sourceConfigMapUID", "proxySourceSHA256", "proxyImage", "engineImage", "serviceUID",
    "policyConfigMapUID", "journalUID", "tenantSecretUID", "consoleSecretUID",
    "seedSHA256", "clientASHA256", "clientBSHA256", "clientAHMAC", "clientBHMAC",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read_object(path):
    raw = Path(path).read_bytes()
    if len(raw) > 16384:
        raise ValueError("adoption receipt exceeds bound")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate adoption key")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError("adoption receipt must be an object")
    if {"client-a", "client-b", "seed", "adminBearer", "adminToken"} & set(value):
        raise ValueError("adoption receipt must not contain credentials")
    return value


def profile(adoption, policy_uid, policy_generation, audit_source_identity):
    for name in FIELDS:
        if name not in adoption or type(adoption[name]) is not str:
            raise ValueError(f"missing non-secret adoption pin {name}")
    for name in ("sourceConfigMapUID", "serviceUID", "policyConfigMapUID", "journalUID",
                 "tenantSecretUID", "consoleSecretUID"):
        if not UID.fullmatch(adoption[name]):
            raise ValueError(f"invalid {name}")
    for name in ("proxySourceSHA256", "seedSHA256", "clientASHA256", "clientBSHA256",
                 "clientAHMAC", "clientBHMAC"):
        if not SHA.fullmatch(adoption[name]):
            raise ValueError(f"invalid {name}")
    if not IMAGE.fullmatch(adoption["proxyImage"]):
        raise ValueError("proxyImage requires reviewed immutable digest")
    if not IMAGE.fullmatch(adoption["engineImage"]):
        raise ValueError("engineImage requires independently reviewed immutable digest")
    if not UID.fullmatch(policy_uid) or policy_generation < 1 or not audit_source_identity or len(audit_source_identity) > 256:
        raise ValueError("policy or audit identity invalid")
    if adoption["clientAHMAC"] == adoption["clientBHMAC"] or adoption["clientASHA256"] == adoption["clientBSHA256"]:
        raise ValueError("A and B must be distinct")
    result = {
        "version": 1, "serviceName": "vllm", "serviceUID": adoption["serviceUID"],
        "policyName": "vllm-defense", "policyUID": policy_uid, "policyGeneration": policy_generation,
        "policyConfigMapUID": adoption["policyConfigMapUID"], "journalUID": adoption["journalUID"],
        "tenantSecretUID": adoption["tenantSecretUID"], "consoleSecretUID": adoption["consoleSecretUID"],
        "sourceConfigMapName": "guardrail-proxy", "sourceConfigMapUID": adoption["sourceConfigMapUID"],
        "proxySourceSHA256": adoption["proxySourceSHA256"], "proxyImage": adoption["proxyImage"],
        "approvedEngineImage": adoption["engineImage"],
        "seedSHA256": adoption["seedSHA256"], "clientASHA256": adoption["clientASHA256"],
        "clientBSHA256": adoption["clientBSHA256"], "clientAHMAC": adoption["clientAHMAC"],
        "clientBHMAC": adoption["clientBHMAC"], "eventCreator": CREATOR,
        "auditSourceIdentity": audit_source_identity, "modelId": MODEL, "maxRunSeconds": 900,
    }
    return result


def render(adoption, policy_uid, policy_generation, audit_source_identity):
    body = canonical(profile(adoption, policy_uid, policy_generation, audit_source_identity))
    digest = hashlib.sha256(body).hexdigest()
    name = "phorvex-catalogue-endpoint-lease-" + digest[:12]
    configmap = {
        "apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"name": name, "namespace": "phorvex-system"},
        "data": {"profile.json": body.decode()},
    }
    helm = {"phorvex": {"console": {"endpointLease": {
        "enabled": True, "configMapName": name, "profileSHA256": digest,
        "callerSecretName": "vllm-endpoint-lease-callers", "sourceConfigMapName": "guardrail-proxy",
    }}}}
    return body, configmap, helm


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("adoption", type=Path)
    parser.add_argument("--policy-uid", required=True)
    parser.add_argument("--policy-generation", required=True, type=int)
    parser.add_argument("--audit-source-identity", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    body, configmap, helm = render(read_object(args.adoption), args.policy_uid,
                                   args.policy_generation, args.audit_source_identity)
    args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
    (args.out / "profile.json").write_bytes(body)
    (args.out / "profile-configmap.json").write_bytes(canonical(configmap))
    (args.out / "helm-values.json").write_bytes(canonical(helm))
    print(configmap["metadata"]["name"])


if __name__ == "__main__":
    main()
