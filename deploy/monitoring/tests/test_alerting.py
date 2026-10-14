"""Light, offline A1 contracts; all credentials and process results are dummy."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


render = module("a1_render", "render-values.py")
provision = module("a1_provision", "provision-telegram-secret.py")
tool_checks = module("a1_tool_checks", "tests/check-tools.py")
DUMMY_TOKEN = "123456:" + "DUMMY_DATA_ONLY_" * 3
DUMMY_CHAT = "123456789"
DUMMY_ENV = f"TELEGRAM_BOT_TOKEN={DUMMY_TOKEN}\nTELEGRAM_CHAT_ID={DUMMY_CHAT}\n"


class ProvisionTests(unittest.TestCase):
    def test_literal_env_and_optional_approved_username(self):
        env = f"# dummy\nexport TELEGRAM_BOT_TOKEN='{DUMMY_TOKEN}'\nTELEGRAM_CHAT_ID=\"{DUMMY_CHAT}\"\nTELEGRAM_BOT_USERNAME=@phorvex_cluster_alerts_bot\n"
        self.assertEqual(provision.parse_env(env), (DUMMY_TOKEN, DUMMY_CHAT))

    def test_invalid_or_group_destination_rejected_without_echo(self):
        for chat in ["-100123456789", "0", "1;cat /tmp/dummy", "9223372036854775808", "$(echo dummy)"]:
            with self.subTest(chat=chat), self.assertRaises(provision.ProvisionError) as failure:
                provision.parse_env(DUMMY_ENV.replace(DUMMY_CHAT, chat))
            self.assertNotIn(DUMMY_TOKEN, str(failure.exception))
            self.assertNotIn(chat, str(failure.exception))

    def test_malformed_duplicate_missing_and_shell_data_rejected(self):
        cases = [DUMMY_ENV + "TELEGRAM_CHAT_ID=42\n", "TELEGRAM_CHAT_ID=42\n",
                 DUMMY_ENV.replace(DUMMY_TOKEN, "$(cat dummy)"), DUMMY_ENV + "OTHER=dummy\n",
                 DUMMY_ENV + "TELEGRAM_BOT_USERNAME=another_bot\n"]
        for env in cases:
            with self.subTest(env=env), self.assertRaises(provision.ProvisionError):
                provision.parse_env(env)

    def test_payload_contains_only_expected_secret_keys_no_annotations(self):
        payload = json.loads(provision.secret_payload(DUMMY_TOKEN, DUMMY_CHAT))
        self.assertEqual(payload["metadata"], {"name": "phorvex-telegram-alerts", "namespace": "monitoring"})
        self.assertEqual(set(payload["data"]), {"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"})
        self.assertEqual(base64.b64decode(payload["data"]["TELEGRAM_BOT_TOKEN"]).decode(), DUMMY_TOKEN)
        self.assertEqual(base64.b64decode(payload["data"]["TELEGRAM_CHAT_ID"]).decode(), DUMMY_CHAT)
        self.assertNotIn("stringData", payload)
        self.assertNotIn("annotations", payload["metadata"])

    def test_create_and_rotation_only_stdin_never_shell_or_client_apply(self):
        payload = provision.secret_payload(DUMMY_TOKEN, DUMMY_CHAT)
        for operation in ["create", "rotate"]:
            run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, DUMMY_TOKEN.encode(), DUMMY_CHAT.encode()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                provision.provision(operation, payload, runner=run)
            command = run.call_args.args[0]
            self.assertEqual(run.call_args.kwargs["input"], payload)
            self.assertFalse(run.call_args.kwargs.get("shell", False))
            self.assertEqual(command[:7], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "phorvex-gw", "kubectl"])
            self.assertNotIn(DUMMY_TOKEN, " ".join(command))
            self.assertNotIn(DUMMY_CHAT, " ".join(command))
            self.assertNotIn("--from-literal", " ".join(command))
            self.assertIn("--field-manager=phorvex-alerts-provisioner", command)
            if operation == "create":
                self.assertIn("create", command)
                self.assertNotIn("apply", command)
            else:
                self.assertIn("apply", command)
                self.assertIn("--server-side", command)
                self.assertIn("--field-manager=phorvex-alerts-provisioner", command)
            self.assertNotIn(DUMMY_TOKEN, output.getvalue())
            self.assertNotIn(DUMMY_CHAT, output.getvalue())

    def test_remote_failure_and_timeout_suppressed(self):
        runners = [mock.Mock(return_value=subprocess.CompletedProcess([], 1, DUMMY_TOKEN, DUMMY_CHAT)),
                   mock.Mock(side_effect=subprocess.TimeoutExpired("dummy", 60, output=DUMMY_TOKEN, stderr=DUMMY_CHAT)),
                   mock.Mock(side_effect=OSError(DUMMY_TOKEN))]
        for run in runners:
            with self.assertRaises(provision.ProvisionError) as failure:
                provision.provision("create", b"dummy", runner=run)
            self.assertNotIn(DUMMY_TOKEN, str(failure.exception))
            self.assertNotIn(DUMMY_CHAT, str(failure.exception))

    def test_invalid_operation_never_starts_process(self):
        run = mock.Mock()
        with self.assertRaises(provision.ProvisionError):
            provision.provision("apply", b"dummy", runner=run)
        run.assert_not_called()

    def test_no_execute_never_opens_credential_file_or_process(self):
        with mock.patch.object(provision, "read_private_env") as read, mock.patch.object(provision, "provision") as send:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(provision.cli(["create"]), 1)
            read.assert_not_called()
            send.assert_not_called()

    def test_read_only_dummy_regular_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dummy.env"
            path.write_text(DUMMY_ENV)
            path.chmod(0o600)
            self.assertEqual(provision.read_private_env(path), DUMMY_ENV)
            path.chmod(0o640)
            with self.assertRaises(provision.ProvisionError):
                provision.read_private_env(path)
            path.chmod(0o600)
            symlink = Path(directory) / "link"
            symlink.symlink_to(path)
            with self.assertRaises(provision.ProvisionError):
                provision.read_private_env(symlink)
            path.write_text("x" * (provision.MAX_FILE_BYTES + 1))
            with self.assertRaises(provision.ProvisionError):
                provision.read_private_env(path)
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(provision.ProvisionError):
                provision.read_private_env(fifo)

    def test_wrong_owner_rejected(self):
        info = mock.Mock(st_mode=0o100600, st_uid=os.geteuid() + 1, st_size=10)
        with mock.patch.object(provision.os, "open", return_value=99), mock.patch.object(provision.os, "fstat", return_value=info), mock.patch.object(provision.os, "close"):
            with self.assertRaises(provision.ProvisionError):
                provision.read_private_env(Path("dummy"))

    def test_cli_never_prints_unexpected_exception(self):
        output = io.StringIO()
        with mock.patch.object(provision, "read_private_env", side_effect=RuntimeError(DUMMY_TOKEN)), contextlib.redirect_stderr(output):
            self.assertEqual(provision.cli(["create", "--execute"]), 1)
        self.assertNotIn(DUMMY_TOKEN, output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_main_uses_only_approved_path_with_dummy_reader(self):
        with mock.patch.object(provision, "read_private_env", return_value=DUMMY_ENV) as read, mock.patch.object(provision, "provision") as send:
            self.assertEqual(provision.main(["create", "--execute"]), 0)
        read.assert_called_once_with(provision.APPROVED_ENV)
        send.assert_called_once_with("create", provision.secret_payload(DUMMY_TOKEN, DUMMY_CHAT))


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.overlay = render.load_yaml(ROOT / "kube-prom-stack/values-alerting.yaml")
        self.config = render.load_yaml(ROOT / "alertmanager-config.yaml")

    def test_overlay_matches_config_and_keeps_only_alertmanager(self):
        before = copy.deepcopy(self.overlay)
        self.assertEqual(render.render_values(self.overlay, self.config), self.overlay)
        self.assertEqual(self.overlay, before)
        self.assertEqual(set(self.overlay), {"alertmanager"})
        self.assertEqual(render.CHART_VERSION, "88.5.3")

    def test_generated_overlay_is_byte_stable(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(render.main([]), 0)
        self.assertEqual(output.getvalue(), (ROOT / "kube-prom-stack/values-alerting.yaml").read_text())

    def test_pinned_tool_version_accepts_stderr(self):
        result = subprocess.CompletedProcess([], 0, "", "amtool, version 0.34.0")
        with mock.patch.object(tool_checks.subprocess, "run", return_value=result):
            self.assertIn("0.34.0", tool_checks.tool_version("dummy-amtool"))

    def test_render_rejects_shared_release_keys_pvc_ingress_or_external_service(self):
        for patch in [lambda v: v.update(prometheus={}),
                      lambda v: v.update(defaultRules={}),
                      lambda v: v["alertmanager"]["alertmanagerSpec"].update(storage={}),
                      lambda v: v["alertmanager"]["ingress"].update(enabled=True),
                      lambda v: v["alertmanager"]["service"].update(type="LoadBalancer"),
                      lambda v: v["alertmanager"]["alertmanagerSpec"].update(replicas=3)]:
            values = copy.deepcopy(self.overlay)
            patch(values)
            with self.assertRaises(ValueError):
                render.render_values(values, self.config)

    def test_telegram_file_only_plain_bounded_message(self):
        telegram = self.config["receivers"][1]["telegram_configs"][0]
        self.assertEqual(telegram["parse_mode"], "")
        self.assertTrue(telegram["send_resolved"])
        self.assertNotIn("bot_token", telegram)
        self.assertNotIn("chat_id", telegram)
        for key in ["bot_token_file", "chat_id_file"]:
            self.assertTrue(telegram[key].startswith("/etc/alertmanager/secrets/phorvex-telegram-alerts/"))
        self.assertNotIn("Annotations", telegram["message"])
        self.assertIn("if lt $i 5", telegram["message"])
        self.assertIn('printf "%.80s"', telegram["message"])

    def test_grouping_and_scoped_inhibition_contract(self):
        route = self.config["route"]
        self.assertEqual(route["receiver"], "null")
        self.assertEqual(route["group_by"], ["phorvex_cluster", "alertname", "namespace"])
        self.assertEqual((route["group_wait"], route["group_interval"], route["repeat_interval"]), ("60s", "10m", "6h"))
        critical, coverage = self.config["inhibit_rules"]
        self.assertEqual(critical["equal"], ["phorvex_cluster", "namespace", "alertname"])
        self.assertIn('phorvex_cluster="dev"', critical["source_matchers"])
        self.assertEqual(coverage["equal"], ["phorvex_cluster", "namespace", "monitor"])
        self.assertIn('coverage="mathlab"', coverage["target_matchers"])

    def test_rule_ownership_scope_and_hold_times(self):
        rule = render.load_yaml(ROOT / "phorvex-runtime-health.rules.yaml")
        self.assertEqual(rule["kind"], "PrometheusRule")
        self.assertEqual(rule["metadata"]["name"], "phorvex-runtime-health")
        self.assertEqual(rule["metadata"]["namespace"], "monitoring")
        rules = rule["spec"]["groups"][0]["rules"]
        for item in rules:
            self.assertEqual(item["labels"]["phorvex_cluster"], "dev")
            self.assertIn(item["labels"]["severity"], ["warning", "critical"])
            self.assertNotRegex(item["expr"], r"nats|vllm|http_requests_total|http_request_duration|container_memory")
        pvc = [item for item in rules if item["alert"] == "PhorvexPrometheusPVCFreeSpaceLow"]
        self.assertEqual(len(pvc), 2)
        self.assertTrue(all(item["for"] == "10m" for item in pvc))
        self.assertEqual(next(item for item in rules if item["alert"] == "PhorvexDeploymentReplicasUnavailable")["for"], "5m")

    def test_rule_fixture_has_positive_negative_resolution_and_absence_cases(self):
        fixtures = render.load_yaml(ROOT / "tests/runtime-health.test.yaml")
        names = [case["name"] for case in fixtures["tests"]]
        for required in ["replica deficit", "replica recovery", "engine absent", "healthy engine missing store gauge", "PVC zero capacity", "store budget above threshold", "snapshot eviction", "snapshot write failure"]:
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
