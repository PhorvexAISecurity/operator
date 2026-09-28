"""Offline preservation review of private before/after Kubernetes snapshots."""
import argparse
import json
from pathlib import Path

from policy import canonical, digest, require


def objects(snapshot):
    require(isinstance(snapshot, dict) and snapshot.get("kind") == "List" and isinstance(snapshot.get("items"), list))
    result = {}
    for obj in snapshot["items"]:
        meta = obj.get("metadata", {})
        key = (obj.get("kind"), meta.get("namespace"), meta.get("name"))
        require(key not in result and all(isinstance(part, str) and part for part in key))
        result[key] = obj
    return result


def verify_preservation(before, after):
    old, new = objects(before), objects(after)
    results = []
    for key, prior in old.items():
        kind, namespace, name = key
        protected = (kind == "Deployment" and namespace == "voice" and name == "voice-bot") or \
                    (kind in ("ConfigMap", "Secret") and namespace == "voice") or \
                    (kind == "ConfigMap" and namespace == "phorvex-system" and name.startswith("phorvex-voice-"))
        if not protected:
            continue
        require(key in new)
        current = new[key]
        require(current["metadata"].get("uid") == prior["metadata"].get("uid") and
                not current["metadata"].get("deletionTimestamp"))
        if kind != "Deployment":
            # Compare credential bytes locally without ever putting them in the
            # report. Rule and journal data must remain exactly byte-identical.
            for field in ("data", "binaryData", "immutable", "type"):
                require(current.get(field) == prior.get(field))
            require(current["metadata"].get("ownerReferences") == prior["metadata"].get("ownerReferences"))
            sha = digest(canonical({field: prior.get(field) for field in ("data", "binaryData", "immutable", "type")}))
        else:
            sha = ""
            require(current["spec"].get("strategy") == prior["spec"].get("strategy") and
                    current["spec"].get("replicas") == prior["spec"].get("replicas") and
                    current["spec"].get("selector") == prior["spec"].get("selector"))
        results.append({"kind": kind, "namespace": namespace, "name": name, "uid": prior["metadata"]["uid"],
                        "protectedBytesSHA256": sha, "preserved": True})
    require(any(item["kind"] == "Deployment" for item in results))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"version": 1, "checks": verify_preservation(json.loads(args.before.read_text()), json.loads(args.after.read_text())),
              "beforeSHA256": digest(args.before.read_bytes()), "afterSHA256": digest(args.after.read_bytes()),
              "claim": "listed protected Kubernetes identities/bytes only; no runtime or stored history success inferred"}
    import os
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
