#!/usr/bin/env python3
"""Apply the pinned vLLM patch only to the exact reviewed 0.7.3 sources."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import sys
import tempfile


HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "manifest.json"
PATCH_PATH = HERE / "vllm-0.7.3-reset-ack.patch"
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def installed_root() -> Path:
    distribution = importlib.metadata.distribution("vllm")
    if distribution.version != "0.7.3":
        raise RuntimeError(f"vLLM version is {distribution.version!r}, expected '0.7.3'")
    return Path(distribution.locate_file(""))


def parse_patch(data: bytes) -> dict[str, list[tuple[int, int, int, int, list[bytes]]]]:
    lines = data.splitlines(keepends=True)
    result: dict[str, list[tuple[int, int, int, int, list[bytes]]]] = {}
    index = 0
    current: str | None = None
    while index < len(lines):
        line = lines[index]
        if line.startswith(b"+++ b/"):
            current = line[len(b"+++ b/"):].decode().strip()
            result[current] = []
            index += 1
            continue
        if line.startswith(b"@@ "):
            if current is None:
                raise RuntimeError("patch hunk appears before a target path")
            match = HUNK.match(line.decode())
            if not match:
                raise RuntimeError(f"invalid unified-diff hunk: {line!r}")
            old_start, old_count, new_start, new_count = (
                int(match.group(1)),
                int(match.group(2) or 1),
                int(match.group(3)),
                int(match.group(4) or 1),
            )
            index += 1
            body: list[bytes] = []
            while index < len(lines) and not lines[index].startswith((b"@@ ", b"diff --git ")):
                if lines[index].startswith((b" ", b"+", b"-", b"\\")):
                    body.append(lines[index])
                    index += 1
                    continue
                break
            result[current].append((old_start, old_count, new_start, new_count, body))
            continue
        index += 1
    return result


def apply_hunks(original: bytes, hunks: list[tuple[int, int, int, int, list[bytes]]]) -> bytes:
    source = original.splitlines(keepends=True)
    output: list[bytes] = []
    cursor = 0
    for old_start, old_count, _new_start, new_count, body in hunks:
        # Unified diff locates a zero-length insertion *after* old_start;
        # nonempty hunks use the usual one-based first source line.
        target = old_start if old_count == 0 else old_start - 1
        if target < cursor:
            raise RuntimeError("overlapping patch hunks")
        output.extend(source[cursor:target])
        cursor = target
        consumed = produced = 0
        for line in body:
            marker, payload = line[:1], line[1:]
            if marker == b"\\":
                continue
            if marker in (b" ", b"-"):
                if cursor >= len(source) or source[cursor] != payload:
                    raise RuntimeError(f"patch context mismatch at source line {cursor + 1}")
                cursor += 1
                consumed += 1
            if marker in (b" ", b"+"):
                output.append(payload)
                produced += 1
        if (consumed, produced) != (old_count, new_count):
            raise RuntimeError(
                f"patch hunk count mismatch: got {(consumed, produced)}, "
                f"expected {(old_count, new_count)}"
            )
    output.extend(source[cursor:])
    return b"".join(output)


def write_atomic(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        stream.write(data)
        temporary = Path(stream.name)
    temporary.chmod(path.stat().st_mode)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    roots = parser.add_mutually_exclusive_group(required=True)
    roots.add_argument("--source-root", type=Path)
    roots.add_argument("--installed", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()

    manifest = json.loads(MANIFEST_PATH.read_text())
    patch = PATCH_PATH.read_bytes()
    if digest(patch) != manifest["patch_sha256"]:
        raise RuntimeError("patch digest does not match manifest")
    root = installed_root() if args.installed else args.source_root.resolve()
    file_specs = manifest["files"]
    actual = {name: digest((root / name).read_bytes()) for name in file_specs}
    states = {
        name: "before" if value == file_specs[name]["before"] else
        "after" if value == file_specs[name]["after"] else "unknown"
        for name, value in actual.items()
    }
    if set(states.values()) == {"before"}:
        parsed = parse_patch(patch)
        if set(parsed) != set(file_specs):
            raise RuntimeError("patch targets do not exactly match the manifest")
        rendered = {
            name: apply_hunks((root / name).read_bytes(), parsed[name])
            for name in file_specs
        }
        for name, data in rendered.items():
            if digest(data) != file_specs[name]["after"]:
                raise RuntimeError(f"post-patch digest mismatch for {name}")
            compile(data, str(root / name), "exec")
        for name, data in rendered.items():
            write_atomic(root / name, data)
    elif set(states.values()) != {"after"}:
        detail = ", ".join(f"{name}={state}" for name, state in states.items())
        raise RuntimeError(f"refusing mixed or unreviewed vLLM sources: {detail}")

    final_hashes = {name: digest((root / name).read_bytes()) for name in file_specs}
    if any(final_hashes[name] != file_specs[name]["after"] for name in file_specs):
        raise RuntimeError("installed source verification failed")
    receipt = {
        "schema_version": 1,
        "patch_id": manifest["patch_id"],
        "upstream": manifest["upstream"],
        "base_image": manifest["base_image"],
        "python_cache_tag": sys.implementation.cache_tag,
        "files": final_hashes,
    }
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
