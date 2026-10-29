#!/usr/bin/env python3
"""Prove a service image and its runnable binary carry one release identity."""

from __future__ import annotations

import argparse
import json
import re
import subprocess


ENTRYPOINTS = {
    "manager": "/manager",
    "brain": "/service",
    "sensor": "/service",
    "actuator": "/service",
    "console": "/app/console",
    "attacks": "/app/attacks",
}
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"[0-9A-Za-z.+-]+")


def run(*command: str) -> str:
    return subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE
    ).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--service", required=True, choices=ENTRYPOINTS)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if not SHA.fullmatch(args.git_sha):
        parser.error("--git-sha must be a 40-character lowercase hexadecimal SHA")
    if not VERSION.fullmatch(args.version):
        parser.error("--version is malformed")

    inspected = json.loads(run("docker", "image", "inspect", args.image))
    if len(inspected) != 1:
        raise SystemExit(f"expected one local image for {args.image}")
    image = inspected[0]
    labels = image.get("Config", {}).get("Labels") or {}
    expected_labels = {
        "org.opencontainers.image.revision": args.git_sha,
        "org.opencontainers.image.version": args.version,
    }
    for key, expected in expected_labels.items():
        if labels.get(key) != expected:
            raise SystemExit(
                f"{args.service} image label {key}={labels.get(key)!r}, want {expected!r}"
            )
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise SystemExit(
            f"{args.service} image platform is {image.get('Os')}/{image.get('Architecture')}, "
            "want linux/amd64"
        )
    if image.get("Config", {}).get("User") != "65532:65532":
        raise SystemExit(f"{args.service} image no longer runs as 65532:65532")

    output = run(
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        ENTRYPOINTS[args.service],
        args.image,
        "-version",
    )
    try:
        identity = json.loads(output)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"{args.service} binary returned malformed version JSON: {output!r}"
        ) from error
    expected_identity = {
        "service": args.service,
        "version": args.version,
        "gitSHA": args.git_sha,
    }
    if identity != expected_identity:
        raise SystemExit(
            f"{args.service} binary identity {identity!r}, want {expected_identity!r}"
        )
    print(
        json.dumps(
            {
                **expected_identity,
                "image": args.image,
                "imageID": image.get("Id"),
                "platform": "linux/amd64",
                "user": "65532:65532",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
