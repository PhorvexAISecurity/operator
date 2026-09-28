"""Bind release tags to published immutable artifacts before one atomic values write."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
COMPONENTS = {"ci:phorvex-tag": "phorvex", "ci:console-tag": "phorvex-console"}


def docker_json(ref, field):
    result = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref,
                             "--format", "{{json ." + field + "}}"],
                            capture_output=True, timeout=60, check=True)
    if not result.stdout or len(result.stdout) > 1_000_000:
        raise ValueError("published image metadata absent or oversized")
    return json.loads(result.stdout)


def artifact(ref):
    descriptor = docker_json(ref, "Manifest")
    if not isinstance(descriptor, dict) or not DIGEST.fullmatch(descriptor.get("digest", "")):
        raise ValueError("published immutable manifest digest unavailable")
    # Fetch config through the resolved immutable descriptor, never the mutable tag
    # again. Official buildx JSON fields: https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/
    repo = ref.rsplit("@", 1)[0] if "@" in ref else ref.rsplit(":", 1)[0]
    config = docker_json(repo + "@" + descriptor["digest"], "Image")
    # buildx exposes a single-image config or a map by platform for an index.
    if isinstance(config, dict) and "linux/amd64" in config:
        config = config["linux/amd64"]
    if (not isinstance(config, dict) or config.get("architecture") != "amd64"
            or config.get("os") != "linux"):
        raise ValueError("published amd64 configuration unavailable")
    revision = config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision", "")
    if not HEX40.fullmatch(revision):
        raise ValueError("published build source unavailable")
    return descriptor["digest"], revision


def replace_marker(src, marker, key, value):
    pattern = re.compile(r'^(\s*' + re.escape(key) + r':\s*)"[^"]*"(\s*#\s*'
                         + re.escape(marker) + r'\s*)$', re.MULTILINE)
    src, count = pattern.subn(lambda m: m[1] + '"' + value + '"' + m[2], src)
    if count != 1:
        raise ValueError("release marker missing or duplicated: " + marker)
    return src


def update(src, version, registry, markers, source_mode, source_sha, release_from, digests, resolve=artifact):
    if not TAG.fullmatch(version) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?", registry):
        raise ValueError("release identity malformed")
    if not markers or len(set(markers)) != len(markers) or any(m not in COMPONENTS for m in markers):
        raise ValueError("release component selection invalid")
    if source_mode == "digest":
        if not HEX40.fullmatch(source_sha) or release_from:
            raise ValueError("built release source invalid")
    elif source_mode == "tag":
        if not TAG.fullmatch(release_from):
            raise ValueError("forced release source tag invalid")
    else:
        raise ValueError("release source mode invalid")
    authorities = {}
    # Validate every selected component before touching any values. The absent
    # component's prior digest/source/tag lines are preserved byte-for-byte.
    for marker in markers:
        repo = registry + "/" + COMPONENTS[marker]
        expected_digest = digests.get(marker, "")
        if source_mode == "digest":
            if not DIGEST.fullmatch(expected_digest):
                raise ValueError("successful build digest missing")
            expected_source = source_sha
        else:
            expected_digest, expected_source = resolve(repo + ":" + release_from)
        actual_digest, actual_source = resolve(repo + ":" + version)
        if actual_digest != expected_digest or actual_source != expected_source:
            raise ValueError("published tag differs from selected immutable build/source")
        authorities[marker] = (actual_digest, actual_source)
    for marker, (digest, revision) in authorities.items():
        stem = marker.removesuffix("-tag")
        src = replace_marker(src, marker, "tag", version)
        src = replace_marker(src, stem + "-digest", "releaseDigest", digest)
        src = replace_marker(src, stem + "-source", "releaseSourceSHA", revision)
    return src


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("values")
    parser.add_argument("markers", nargs="+")
    args = parser.parse_args()
    path = Path(args.values)
    raw = path.read_text()
    result = update(raw, os.environ["V"], os.environ["REG"], args.markers,
                    os.environ["SOURCE_MODE"], os.environ.get("SOURCE_SHA", ""),
                    os.environ.get("RELEASE_FROM", ""),
                    {"ci:phorvex-tag": os.environ.get("OPERATOR_DIGEST", ""),
                     "ci:console-tag": os.environ.get("CONSOLE_DIGEST", "")})
    if result == raw:
        raise ValueError("selected built release did not change values")
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(result)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()
