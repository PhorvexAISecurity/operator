#!/usr/bin/env python3
"""Run the pinned 192-attack live catalogue on isolated Phorvex lanes.

The runner is resumable. A case is complete only when its structured evidence
reports both ``verdict=DEFENDED`` and a clean postflight health gate.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_RUNNER = ROOT / "runner" / "phvx-attack.py"
DEFAULT_MANIFEST = ROOT / "catalog-192.txt"
DEFAULT_OUTPUT = ROOT / "run" / "catalog-192"
REQUIRED_SPEC_KEYS = {
    "name", "mode", "lane", "actuator", "family", "target",
    "oracle", "event", "defended", "expected",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in value)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.{threading.get_ident()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def load_specs(runner: Path) -> dict[str, dict[str, Any]]:
    specs_dir = runner.parent / "fires.d"
    specs: dict[str, dict[str, Any]] = {}
    for path in sorted(specs_dir.glob("*.json")):
        spec = read_json(path)
        if spec is None:
            raise RuntimeError(f"invalid JSON object: {path}")
        missing = REQUIRED_SPEC_KEYS - spec.keys()
        if missing:
            raise RuntimeError(f"{path.name}: missing keys {sorted(missing)}")
        if "arm" not in spec and "fixture" not in spec:
            raise RuntimeError(f"{path.name}: requires either arm or fixture")
        name = spec["name"]
        if not isinstance(name, str) or not name:
            raise RuntimeError(f"{path.name}: invalid name")
        if name in specs:
            raise RuntimeError(f"duplicate attack name: {name}")
        specs[name] = spec
    return specs


def load_manifest(path: Path, specs: dict[str, dict[str, Any]]) -> list[str]:
    names = [line.strip() for line in path.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if len(names) != 192 or len(set(names)) != 192:
        raise RuntimeError(f"{path}: expected 192 unique attacks, found {len(names)}/{len(set(names))}")
    unknown = sorted(set(names) - specs.keys())
    if unknown:
        raise RuntimeError(f"manifest names missing from fires.d: {unknown}")
    for name in names:
        spec = specs[name]
        if spec["mode"] != "lane" or spec["expected"] != "DEFENDED":
            raise RuntimeError(
                f"{name}: catalog-192 requires mode=lane and expected=DEFENDED; "
                f"found {spec['mode']!r}/{spec['expected']!r}"
            )
    return names


def defended(record: dict[str, Any] | None) -> bool:
    return bool(record and record.get("verdict") == "DEFENDED"
                and record.get("postflight_clean") is True)


def next_attempt(attempts_dir: Path, stem: str) -> int:
    return 1 + len(list(attempts_dir.glob(f"{stem}.attempt-*.json")))


def run_case(
    name: str,
    spec: dict[str, Any],
    runner: Path,
    output: Path,
    attempts: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    lane = spec["lane"]
    stem = safe_name(name)
    final_path = output / "evidence" / f"{stem}.json"
    current = read_json(final_path)
    if defended(current):
        return {"attack": name, "lane": lane, "status": "DEFENDED", "resumed": True}

    attempts_dir = output / "attempts"
    logs_dir = output / "logs"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    last: dict[str, Any] | None = current

    for _ in range(attempts):
        number = next_attempt(attempts_dir, stem)
        evidence = attempts_dir / f"{stem}.attempt-{number}.json"
        log_path = logs_dir / f"{stem}.attempt-{number}.log"
        command = [
            sys.executable, str(runner), "fire", name,
            "--lane", lane, "--evidence-out", str(evidence),
        ]
        environment = os.environ.copy()
        environment["PHVX_ATTACK_LOCK"] = f"/tmp/phvx-live-attack-{safe_name(lane)}.lock"
        started = utc_now()
        return_code: int | None = None
        error = ""
        with log_path.open("w") as log:
            log.write(f"started={started}\ncommand={json.dumps(command)}\n")
            log.flush()
            try:
                completed = subprocess.run(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env=environment,
                    timeout=timeout_seconds,
                    check=False,
                )
                return_code = completed.returncode
            except subprocess.TimeoutExpired:
                error = f"timeout after {timeout_seconds}s"
                log.write(f"\nBATCH ERROR: {error}\n")

        last = read_json(evidence) or {
            "attack": name,
            "generated_at": utc_now(),
            "verdict": "BATCH-ERROR",
            "postflight_clean": False,
            "reason": error or f"runner exited {return_code} without structured evidence",
        }
        last["batch"] = {
            "attempt": number,
            "lane": lane,
            "return_code": return_code,
            "started_at": started,
            "finished_at": utc_now(),
            "log": str(log_path),
        }
        atomic_json(evidence, last)
        if defended(last):
            atomic_json(final_path, last)
            return {"attack": name, "lane": lane, "status": "DEFENDED", "resumed": False}

    return {
        "attack": name,
        "lane": lane,
        "status": (last or {}).get("verdict", "BATCH-ERROR"),
        "reason": (last or {}).get("reason", "no evidence"),
        "resumed": False,
    }


def run_lane(
    lane: str,
    names: list[str],
    specs: dict[str, dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    results = []
    for name in names:
        result = run_case(
            name, specs[name], args.runner, args.output,
            args.attempts, args.timeout_seconds,
        )
        results.append(result)
        print(f"[{utc_now()}] {lane} {name}: {result['status']}", flush=True)
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, default=DEFAULT_RUNNER)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-workers", type=int, default=4,
                        help="parallel isolated lanes (default 4; farm CNI-safe ceiling)")
    parser.add_argument("--attempts", type=int, default=1,
                        help="attempts per unfinished attack in this invocation")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--only-lane", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.max_workers < 1 or args.max_workers > 4:
        parser.error("--max-workers must be between 1 and 4")
    if args.attempts < 1:
        parser.error("--attempts must be positive")
    return args


def main() -> int:
    args = parse_args()
    args.runner = args.runner.resolve()
    args.manifest = args.manifest.resolve()
    args.output = args.output.resolve()
    specs = load_specs(args.runner)
    names = load_manifest(args.manifest, specs)
    lanes: dict[str, list[str]] = {}
    allowed = set(args.only_lane)
    for name in names:
        lane = specs[name]["lane"]
        if allowed and lane not in allowed:
            continue
        lanes.setdefault(lane, []).append(name)

    plan = {
        "catalog": str(args.manifest),
        "runner": str(args.runner),
        "attacks": sum(map(len, lanes.values())),
        "lanes": {lane: len(items) for lane, items in sorted(lanes.items())},
        "max_workers": args.max_workers,
    }
    print(json.dumps(plan, indent=2, sort_keys=True), flush=True)
    if args.dry_run:
        return 0

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(args.max_workers, len(lanes))) as pool:
        futures = {
            pool.submit(run_lane, lane, items, specs, args): lane
            for lane, items in sorted(lanes.items())
        }
        for future in as_completed(futures):
            results.extend(future.result())

    results.sort(key=lambda row: row["attack"])
    counts: dict[str, int] = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    summary = {
        "generated_at": utc_now(),
        "strict_defended": sum(r["status"] == "DEFENDED" for r in results),
        "total": len(results),
        "counts": counts,
        "results": results,
    }
    atomic_json(args.output / "summary.json", summary)
    print(json.dumps({key: summary[key] for key in ("strict_defended", "total", "counts")},
                     indent=2, sort_keys=True))
    return 0 if summary["strict_defended"] == summary["total"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
