"""Validate a single immutable retained-B source-maintenance witness."""
import json

import render_guardrail_profile as g

WITNESS_KEYS = {"version", "priorStateJSON", "priorStateSHA256", "priorJournalSHA256",
                "currentStateSHA256", "priorSourceConfigMapUID"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def validate_upgrade(profile, current, journal_raw=None):
    w = profile.get("sourceUpgrade")
    g.require(isinstance(w, dict) and set(w) == WITNESS_KEYS and
              type(w["version"]) is int and w["version"] == 1 and
              isinstance(w["priorStateJSON"], str) and
              isinstance(w["priorSourceConfigMapUID"], str) and
              bool(g.UID.fullmatch(w["priorSourceConfigMapUID"])) and
              w["priorSourceConfigMapUID"] != profile["sourceConfigMapUID"],
              "source upgrade witness identity differs")
    for name in ("priorStateSHA256", "priorJournalSHA256", "currentStateSHA256"):
        g.require(isinstance(w[name], str) and bool(g.SHA.fullmatch(w[name])), "source upgrade digest invalid")
    raw = w["priorStateJSON"].encode()
    g.require(0 < len(raw) <= 16384 and g.digest(raw) == w["priorStateSHA256"], "prior state hash differs")
    prior = g.unique_json(raw)
    g.require(set(prior) == g.LEASE_POLICY_KEYS and type(prior["version"]) is int and prior["version"] == 1 and
              type(prior["revision"]) is int and prior["revision"] == 1 and
              prior["allowedClientHMACs"] == [profile["clientBHMAC"]] and
              prior["revokedClientHMACs"] == [profile["clientAHMAC"]] and
              prior["serviceUID"] == profile["serviceUID"] and prior["secretUID"] == profile["tenantSecretUID"] and
              prior["seedSHA256"] == profile["seedSHA256"] and
              isinstance(prior["proxySourceSHA256"], str) and bool(g.SHA.fullmatch(prior["proxySourceSHA256"])) and
              prior["proxySourceSHA256"] != profile["proxySourceSHA256"] and
              isinstance(prior["lastOperationID"], str) and bool(g.re.fullmatch(r"[0-9a-f]{32,64}", prior["lastOperationID"])),
              "prior completed A revocation differs")
    expected = dict(prior, revision=2, proxySourceSHA256=profile["proxySourceSHA256"])
    g.require(canonical(current) == canonical(expected) and
              g.digest(canonical(expected)) == w["currentStateSHA256"], "source upgrade changes more than revision/source")
    if journal_raw is not None:
        g.require(0 < len(journal_raw) <= 256 * 1024 and g.digest(journal_raw) == w["priorJournalSHA256"],
                  "protected journal bytes changed")
        journal = g.unique_json(journal_raw)
        g.require(set(journal) == {"receipts", "version"} and type(journal["version"]) is int and
                  journal["version"] == 1 and isinstance(journal["receipts"], list) and
                  len(journal["receipts"]) <= 256 and
                  all(isinstance(row, dict) and row.get("phase") in ("terminal-full", "aborted")
                      for row in journal["receipts"]), "protected journal unresolved/invalid")
        before = dict(prior, revision=0, lastOperationID="", revokedClientHMACs=[],
                      allowedClientHMACs=sorted([profile["clientAHMAC"], profile["clientBHMAC"]]))
        pins = {"phase": "terminal-full", "oldRevision": 0, "newRevision": 1,
                "oldStateSHA256": g.digest(canonical(before)), "newStateSHA256": w["priorStateSHA256"],
                "operationID": prior["lastOperationID"], "policyUID": profile["policyUID"],
                "policyConfigMapUID": profile["policyConfigMapUID"], "secretUID": profile["tenantSecretUID"],
                "serviceUID": profile["serviceUID"], "proxySourceSHA256": prior["proxySourceSHA256"],
                "seedSHA256": profile["seedSHA256"], "retainedClientHMAC": profile["clientBHMAC"],
                "revokedClientHMAC": profile["clientAHMAC"]}
        g.require(any(all(row.get(key) == value for key, value in pins.items())
                      for row in journal["receipts"]), "prior terminal A revocation absent")
    return prior
