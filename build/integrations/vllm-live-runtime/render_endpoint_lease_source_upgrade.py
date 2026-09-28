"""Render a review-only retained-B profile from nonsecret original captures.

No API client or mutation. The current live source/Pods/Secrets remain subject
to the Console's normal snapshot checks; prior source UID is archival only.
"""
import argparse
import json
from pathlib import Path

import render_guardrail_profile as g
from endpoint_lease_source_upgrade import canonical, validate_upgrade

OLD_SOURCE = "c031693170c1d21d0a23405af255f83319efa240ce84d9c25d2436388528a3ff"
NEW_SOURCE = "322595a608b2384f2ed6994886416838fc4e1d1c45c9dadbf1c00f04a5f52691"


def render(old_raw, prior_cm, current_cm, journal_cm, source_cm):
    p = g.unique_json(old_raw)
    g.require(set(p) == g.LEASE_PROFILE_KEYS, "one upgrade from an original profile required")
    old = g.lease_policy_state(prior_cm, p["serviceUID"], p["proxySourceSHA256"],
                               p["policyConfigMapUID"], p["tenantSecretUID"])
    g.retained_lease_profile(old_raw, p["serviceUID"], p["sourceConfigMapUID"], p["proxySourceSHA256"],
                            p["policyUID"], p["policyGeneration"], p["policyConfigMapUID"], old,
                            {"image": p["proxyImage"]}, {"image": p["approvedEngineImage"]})
    sm = g.meta(source_cm, "ConfigMap", "guardrail-proxy", "vllm")
    data = source_cm.get("data", {})
    g.require(source_cm.get("immutable") is True and not source_cm.get("binaryData") and
              set(data) == set(g.LEASE_SOURCE_FILES) and all(isinstance(v, str) and 0 < len(v.encode()) <= 1 << 20
                                                          for v in data.values()), "current source closure differs")
    source_sha = g.digest(b"\0".join(data[k].encode() for k in g.LEASE_SOURCE_FILES))
    g.require(p["proxySourceSHA256"] == OLD_SOURCE and source_sha == NEW_SOURCE, "reviewed drain-only source pair differs")
    jm = g.meta(journal_cm, "ConfigMap", "phorvex-endpoint-lease-journal", "phorvex-system")
    g.require(jm["uid"] == p["journalUID"] and bool(jm.get("resourceVersion")) and
              set(journal_cm.get("data", {})) == {"receipts.json"} and not journal_cm.get("binaryData"),
              "protected journal UID/data differs")
    journal_raw = journal_cm["data"]["receipts.json"].encode()
    current = g.lease_policy_state(current_cm, p["serviceUID"], source_sha,
                                   p["policyConfigMapUID"], p["tenantSecretUID"])
    p["sourceConfigMapUID"], p["proxySourceSHA256"] = sm["uid"], source_sha
    prior_raw = prior_cm["data"]["state.json"].encode()
    p["sourceUpgrade"] = {"version": 1, "priorStateJSON": prior_raw.decode(),
                          "priorStateSHA256": g.digest(prior_raw), "priorJournalSHA256": g.digest(journal_raw),
                          "currentStateSHA256": g.digest(canonical(current)),
                          "priorSourceConfigMapUID": g.unique_json(old_raw)["sourceConfigMapUID"]}
    validate_upgrade(p, current, journal_raw)
    raw = canonical(p)
    g.require(len(raw) <= 8192, "upgraded profile exceeds bound")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("profile", "prior-policy", "current-policy", "journal", "source", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    def obj(path):
        return json.loads(g.read_regular_bounded(path, 6 << 20))
    raw = render(g.read_regular_bounded(args.profile, 8192), obj(args.prior_policy),
                 obj(args.current_policy), obj(args.journal), obj(args.source))
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"profileSHA256": g.digest(raw), "bytes": len(raw), "activation": "disabled-review-only"}))


if __name__ == "__main__":
    main()
