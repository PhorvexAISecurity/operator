#!/usr/bin/env python3
"""Run Security Gain validation episodes for one attack scenario of the verification loop.

Every episode is a fresh one-case verification loop: a new private API server, new
credentials and a new brain decision from the same declared initial state. Arms are
interleaved in seeded random blocks so time-of-run drift cannot line up with one arm.
Nothing here touches a shared cluster.
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time

# The reviewed lease case keeps its defended path. In the token scenario the brain declines
# (rotate is excluded by the conformal cost gate), so "selected" would equal "baseline".
ARMS = {
    "lease": ("intervention", "baseline", "cf-rotate", "cf-endpoint-rotate"),
    "token": ("baseline", "cf-rotate", "cf-endpoint-rotate"),
    "combined": ("baseline", "selected", "cf-rotate", "cf-endpoint-rotate"),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--assets", required=True)
    ap.add_argument("--git-sha", required=True)
    ap.add_argument("--out", required=True, help="new or empty directory")
    ap.add_argument("--blocks", type=int, default=10)
    ap.add_argument("--hold", default="20s")
    ap.add_argument("--seed", type=int, default=20261012)
    ap.add_argument("--scenario", choices=sorted(ARMS), default="lease")
    ap.add_argument("--arms", help="comma-separated arms (default: the scenario's set)")
    a = ap.parse_args()
    arms_set = tuple(a.arms.split(",")) if a.arms else ARMS[a.scenario]
    os.makedirs(a.out, exist_ok=True)
    if os.listdir(a.out):
        sys.exit("output directory must be new or empty")
    rng = random.Random(a.seed)
    plan = []
    for block in range(1, a.blocks + 1):
        arms = list(arms_set)
        rng.shuffle(arms)
        plan += [(block, arm) for arm in arms]
    manifest = {"seed": a.seed, "blocks": a.blocks, "hold": a.hold, "git_sha": a.git_sha, "scenario": a.scenario,
                "arms": list(arms_set), "episodes": []}
    for i, (block, arm) in enumerate(plan, 1):
        name = "%03d-b%02d-%s" % (i, block, arm) if a.scenario == "lease" else "%03d-b%02d-%s-%s" % (i, block, a.scenario, arm)
        out = os.path.join(a.out, name)
        cmd = [a.binary, "-repo-root", a.repo_root, "-python", a.python, "-assets", a.assets,
               "-git-sha", a.git_sha, "-arm", arm, "-scenario", a.scenario, "-out", out, "-hold", a.hold]
        started = time.time()
        with open(os.path.join(a.out, name + ".log"), "w") as log:
            rc = subprocess.call(cmd, stdout=log, stderr=subprocess.STDOUT)
        verdict = None
        try:
            with open(os.path.join(out, "report.json")) as f:
                verdict = json.load(f).get("verdict")
        except (OSError, ValueError):
            pass
        manifest["episodes"].append({"order": i, "block": block, "scenario": a.scenario, "arm": arm, "dir": name, "exit_code": rc,
                                     "verdict": verdict, "wall_seconds": round(time.time() - started, 1)})
        print("%3d/%d %-20s rc=%d %s" % (i, len(plan), arm, rc, verdict), flush=True)
        with open(os.path.join(a.out, "study-manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    main()
