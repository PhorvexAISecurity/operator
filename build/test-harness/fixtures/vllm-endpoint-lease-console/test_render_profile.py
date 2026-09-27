import unittest

from render_profile import canonical, profile, render


def fixture():
    uid = lambda n: f"{n * 8}-{n * 4}-4{n * 3}-8{n * 3}-{n * 12}"
    return {
        "sourceConfigMapUID": uid("1"), "proxySourceSHA256": "a" * 64,
        "proxyImage": "example/proxy@sha256:" + "b" * 64,
        "engineImage": "example/engine@sha256:" + "f" * 64,
        "serviceUID": uid("2"), "policyConfigMapUID": uid("3"), "journalUID": uid("4"),
        "tenantSecretUID": uid("5"), "consoleSecretUID": uid("6"),
        "seedSHA256": "c" * 64, "clientASHA256": "d" * 64, "clientBSHA256": "e" * 64,
        "clientAHMAC": "1" * 64, "clientBHMAC": "2" * 64,
    }


class RenderProfileTest(unittest.TestCase):
    def test_reviewed_nonsecret_profile_and_immutable_cm(self):
        adoption = fixture()
        body, cm, values = render(adoption, "77777777-7777-4777-8777-777777777777", 9, "reviewed-audit")
        self.assertEqual(body, canonical(profile(adoption, "77777777-7777-4777-8777-777777777777", 9, "reviewed-audit")))
        self.assertTrue(cm["immutable"])
        self.assertEqual(cm["metadata"]["namespace"], "phorvex-system")
        self.assertEqual(values["phorvex"]["console"]["endpointLease"]["sourceConfigMapName"], "guardrail-proxy")
        for forbidden in (b'"client-a"', b'"client-b"', b'"seed"', b"Bearer"):
            self.assertNotIn(forbidden, body)

    def test_missing_or_unreviewed_pins_refuse(self):
        adoption = fixture()
        del adoption["consoleSecretUID"]
        with self.assertRaises(ValueError):
            profile(adoption, "77777777-7777-4777-8777-777777777777", 9, "reviewed-audit")
        adoption = fixture()
        adoption["proxyImage"] = "example/proxy:latest"
        with self.assertRaises(ValueError):
            profile(adoption, "77777777-7777-4777-8777-777777777777", 9, "reviewed-audit")


if __name__ == "__main__":
    unittest.main()
