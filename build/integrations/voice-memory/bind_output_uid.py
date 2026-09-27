"""Render the second-phase exact-UID patch for the new Voice output rule CM.

This tool reads a fresh API snapshot after bootstrap CM creation and writes a
private JSON Patch. It does not contact or mutate Kubernetes itself.
"""

import argparse
import json
import os
from pathlib import Path

from render_activation import bind_output_configmap_uid


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--created-cm-json", type=Path, required=True)
    parser.add_argument("--deployment-uid", required=True)
    parser.add_argument("--policy-uid", required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()
    patch = bind_output_configmap_uid(json.loads(args.created_cm_json.read_text()),
                                      args.deployment_uid, args.policy_uid)
    descriptor = os.open(args.out_json, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(json.dumps(patch, sort_keys=True, separators=(",", ":")).encode())
        stream.flush()
        os.fsync(stream.fileno())
    print("Rendered private output CM UID binding patch")


if __name__ == "__main__":
    main()
