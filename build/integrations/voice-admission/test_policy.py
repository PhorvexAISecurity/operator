import copy
import json
import unittest

from policy import Authority, PolicyUnavailable, canonical, load_profile
from test_runtime import fixture, TOKEN


class AuthorityTest(unittest.TestCase):
    def test_authoritative_cas_transition_is_sticky_and_refuses_replay(self):
        pins, _, obj = fixture()
        authority = Authority(pins, lambda: copy.deepcopy(obj))
        old, old_sha, _ = authority.read()
        rule = dict(old, revision=1, mode="require-twilio-signature", operationId="c" * 64)
        obj["data"]["rule.json"] = canonical(rule).decode()
        obj["metadata"]["resourceVersion"] = "11"
        self.assertEqual(authority.read()[0], rule)
        obj["data"]["rule.json"] = canonical(old).decode()
        obj["metadata"]["resourceVersion"] = "12"
        with self.assertRaises(PolicyUnavailable):
            authority.read()
        obj["data"]["rule.json"] = canonical(dict(rule, operationId="d" * 64)).decode()
        with self.assertRaises(PolicyUnavailable):
            authority.read()

    def test_wrong_owner_uid_duplicate_noncanonical_unknown_or_future_rules_fail_closed(self):
        pins, _, original = fixture()
        for change in ("uid", "owner", "deleting", "duplicate", "unknown", "noncanonical", "future", "boolrevision", "size"):
            obj = copy.deepcopy(original)
            raw = obj["data"]["rule.json"]
            if change == "uid":
                obj["metadata"]["uid"] = pins.wrapper_cm_uid
            elif change == "owner":
                obj["metadata"]["ownerReferences"][0]["uid"] = pins.wrapper_cm_uid
            elif change == "deleting":
                obj["metadata"]["deletionTimestamp"] = "now"
            elif change == "duplicate":
                obj["data"]["rule.json"] = raw[:-1] + ',"version":1}'
            elif change == "noncanonical":
                obj["data"]["rule.json"] = raw + "\n"
            elif change == "size":
                obj["data"]["rule.json"] = " " * 8193
            else:
                rule = json.loads(raw)
                if change == "unknown":
                    rule["extra"] = True
                else:
                    rule["revision"] = 2 if change == "future" else False
                obj["data"]["rule.json"] = canonical(rule).decode()
            with self.assertRaises(PolicyUnavailable, msg=change):
                Authority(pins, lambda: obj).read()

    def test_profile_token_url_and_removed_secret_uid_fail_closed(self):
        pins, original, _ = fixture()
        self.assertEqual(load_profile(canonical(original), pins, TOKEN), original)
        for change in ("token", "url", "secretuid", "unknown"):
            profile = dict(original)
            token = TOKEN
            if change == "token":
                token += "wrong"
            elif change == "url":
                profile["websocketSigningURLs"] = ["wss://untrusted/ws"]
            else:
                profile["twilioSecretUID" if change == "secretuid" else "extra"] = "unreviewed"
            with self.assertRaises(PolicyUnavailable):
                load_profile(canonical(profile), pins, token)
