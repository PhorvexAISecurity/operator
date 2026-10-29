from pathlib import Path
import tarfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "deploy/charts/phorvex-common"
CHARTS = [
    ROOT / "deploy/charts/phorvex-actuator",
    ROOT / "deploy/charts/phorvex-attacks",
    ROOT / "deploy/charts/phorvex-brain",
    ROOT / "deploy/charts/phorvex-console",
    ROOT / "deploy/charts/phorvex-sensor",
    ROOT / "phorvex/charts/phorvex",
]


class AttackCatalogChartTests(unittest.TestCase):
    def test_defaults_are_off_and_staging_uses_the_fixed_fixture(self):
        defaults = [
            ROOT / "phorvex/charts/phorvex/values.yaml",
            ROOT / "deploy/charts/phorvex-console/values.yaml",
            ROOT / "deploy/charts/phorvex-attacks/values.yaml",
        ]
        for path in defaults:
            with self.subTest(path=path):
                values = yaml.safe_load(path.read_text())["phorvex"]
                self.assertEqual(values["console"]["attackCatalog"], {
                    "enabled": False,
                    "authorizationTenant": "",
                    "prometheusEvidence": {"enabled": False},
                })

        staging = yaml.safe_load((ROOT / "deploy/environments/staging/phorvex.yaml").read_text())["phorvex"]
        self.assertEqual(staging["console"]["attackCatalog"], {
            "enabled": True,
            "authorizationTenant": "phorvex-staging-demo",
            "prometheusEvidence": {"enabled": True},
        })
        self.assertTrue(staging["identityRotate"]["enabled"])
        self.assertEqual(staging["identityRotate"]["targetNamespace"], "console-identity-shared")
        self.assertEqual(staging["identityRotate"]["serviceAccountName"], "console-id-fixture")
        grants = yaml.safe_load(staging["console"]["auth"]["grants"]["data"])
        for subject in grants["subjects"]:
            self.assertEqual(subject["tenants"], ["phorvex-staging-demo"])

    def test_server_path_mount_and_permissions_are_fixed_in_source(self):
        deployment = (COMMON / "templates/_console.tpl").read_text()
        for exact in (
            "PHORVEX_CONSOLE_ATTACK_CATALOG_ENABLED",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE",
            "PHORVEX_CONSOLE_RUN_PROMETHEUS_EVIDENCE_ENABLED",
            "PHORVEX_CONSOLE_RUN_PROMETHEUS_ENVIRONMENT",
            "/etc/phorvex-attack-catalog/identity-profile.json",
            "attack-catalog-identity-fixture",
        ):
            self.assertIn(exact, deployment)
        rbac = (COMMON / "templates/_console-rbac.tpl").read_text()
        for exact in ("tokenreviews", "serviceaccounts/token", "configmaps", "attacks-identity-catalog"):
            self.assertIn(exact, rbac)
        self.assertNotIn('resources: ["secrets"]\n  verbs: ["get"]', rbac)

        config_map = (ROOT / "deploy/charts/phorvex-attacks/templates/attack-catalog-identity-configmap.yaml").read_text()
        self.assertIn('dig "console" "attackCatalog" "enabled" false', config_map)
        self.assertIn("identityRotate.profile", config_map)

    def test_every_dependent_chart_vendors_current_common_library(self):
        source_chart = yaml.safe_load((COMMON / "Chart.yaml").read_text())
        expected = {
            f"phorvex-common/{path.relative_to(COMMON)}": path.read_bytes()
            for path in COMMON.rglob("*")
            if path.is_file() and path.name != "Chart.yaml"
        }
        for chart in CHARTS:
            with self.subTest(chart=chart):
                dependency = next(
                    dep for dep in yaml.safe_load((chart / "Chart.yaml").read_text())["dependencies"]
                    if dep["name"] == "phorvex-common"
                )
                self.assertEqual(dependency["version"], source_chart["version"])
                package = chart / "charts" / f"phorvex-common-{source_chart['version']}.tgz"
                with tarfile.open(package) as archive:
                    actual = {
                        member.name: archive.extractfile(member).read()
                        for member in archive.getmembers()
                        if member.isfile()
                    }
                self.assertEqual(yaml.safe_load(actual.pop("phorvex-common/Chart.yaml")), source_chart)
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
