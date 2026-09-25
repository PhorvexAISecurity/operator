#!/usr/bin/env python3
"""Check or regenerate Go fixtures through the real guardrail public_state producer.

Run with the guardrail test Python environment. Installs deterministic classifier
stubs; never loads model weights or makes a network request.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build/test-harness/guardrail/guardrail_proxy.py"
FIXTURES = ROOT / "phorvex/internal/cataloguev1/testdata"
PRODUCER_SHA256 = "46c2b92106544f3015b49f3dade84acbbcf73ff98e19cfebc30b801c8076b18e"


def produce():
    # The module creates a FastAPI app at import; keep optional drain setup off.
    # No ASGI lifespan is entered, so the model loader is never started.
    os.environ["PHORVEX_DRAIN_V11"] = "0"
    os.environ["GUARDRAIL_INITIAL_VARIANT"] = "pgv2"
    os.environ["GUARDRAIL_MODE"] = "enforce"
    os.environ["GUARDRAIL_THRESHOLD_PGV1"] = "0.5"
    os.environ["GUARDRAIL_THRESHOLD_PGV2"] = "0.5"
    sys.path.insert(0, str(SOURCE.parent))
    import guardrail_proxy as proxy

    if Path(proxy.__file__).resolve() != SOURCE:
        raise RuntimeError("loaded a different guardrail producer")
    for mode, thresholds in (("enforce", {"pgv1": 0.0, "pgv2": 1.0}),
                             ("observe", {"pgv1": 0.25, "pgv2": 0.75})):
        config = proxy.GuardrailConfig(initial_variant="pgv2", mode=mode, thresholds=thresholds)
        runtime = proxy.GuardrailRuntime(config)
        for variant, revision in (("pgv1", "unknown"), ("pgv2", "fixture-revision-2")):
            runtime.install_classifier(variant, lambda text: [{"label": "LABEL_0", "score": 0.9}], revision)
        yield FIXTURES / f"guardrail_state_{mode}.json", (
            json.dumps(runtime.public_state(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()


def check_state(frozen, actual):
    # Python and package versions are genuine declarations from each runtime,
    # so their values may differ across otherwise compatible test environments.
    for state in (frozen, actual):
        runtime = state.pop("runtime")
        if set(runtime) != {"python", "packages"} or set(runtime["packages"]) != {
            "fastapi", "httpx", "torch", "transformers", "uvicorn"
        } or any(not isinstance(value, str) or not value.strip()
                 for value in [runtime["python"], *runtime["packages"].values()]):
            raise RuntimeError("producer runtime declaration differs")
    if frozen != actual:
        raise RuntimeError("producer structural or behavioral state differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="compare fixtures with producer output")
    action.add_argument("--write", action="store_true", help="regenerate fixtures")
    args = parser.parse_args()
    source_sha = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if source_sha != PRODUCER_SHA256:
        raise SystemExit("checked-in guardrail producer source changed")
    for path, raw in produce():
        if args.check:
            check_state(json.loads(path.read_bytes()), json.loads(raw))
        else:
            path.write_bytes(raw)
        print(json.dumps({"fixture": path.name, "result": "PASS" if args.check else "written",
                          "producerSHA256": source_sha,
                          "fixtureSHA256": hashlib.sha256(path.read_bytes()).hexdigest(),
                          "currentRuntime": json.loads(raw)["runtime"]}, sort_keys=True))


if __name__ == "__main__":
    main()
