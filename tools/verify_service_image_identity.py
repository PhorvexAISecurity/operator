#!/usr/bin/env python3
"""Prove a service image and its runnable binary carry one release identity."""

from __future__ import annotations

import argparse
import json
import re
import subprocess


SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"[0-9A-Za-z.+-]+")
SERVICE = re.compile(r"[a-z][a-z0-9-]*")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def run(*command: str) -> str:
    return subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE
    ).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--expected-repository")
    parser.add_argument("--expected-tag")
    parser.add_argument("--expected-digest")
    args = parser.parse_args()
    if not SERVICE.fullmatch(args.service):
        parser.error("--service is malformed")
    if not args.entrypoint.startswith("/") or any(
        character.isspace() for character in args.entrypoint
    ):
        parser.error("--entrypoint must be an absolute path without whitespace")
    if not SHA.fullmatch(args.git_sha):
        parser.error("--git-sha must be a 40-character lowercase hexadecimal SHA")
    if not VERSION.fullmatch(args.version):
        parser.error("--version is malformed")
    remote = (
        args.expected_repository,
        args.expected_tag,
        args.expected_digest,
    )
    if any(remote) and not all(remote):
        parser.error(
            "--expected-repository, --expected-tag and --expected-digest are all required together"
        )
    if args.expected_digest and not DIGEST.fullmatch(args.expected_digest):
        parser.error("--expected-digest must be sha256:<64 lowercase hex>")

    inspected = json.loads(run("docker", "image", "inspect", args.image))
    if len(inspected) != 1:
        raise SystemExit(f"expected one local image for {args.image}")
    image = inspected[0]
    if all(remote):
        expected_tagged = f"{args.expected_repository}:{args.expected_tag}"
        expected_digest = f"{args.expected_repository}@{args.expected_digest}"
        if args.image != expected_tagged:
            raise SystemExit(
                f"inspected image {args.image!r}, want exact batch tag {expected_tagged!r}"
            )
        if expected_tagged not in (image.get("RepoTags") or []):
            raise SystemExit(
                f"{args.service} image is not tagged as expected {expected_tagged}"
            )
        if expected_digest not in (image.get("RepoDigests") or []):
            raise SystemExit(
                f"{args.service} image does not own pushed digest {expected_digest}"
            )
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
        args.entrypoint,
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
