#!/usr/bin/env python3
"""Pinned-tool integration checks. Run only in CI or already approved isolated AWS."""
import argparse
import base64
import copy
import datetime
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[1]


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def tool_version(tool):
    result = subprocess.run([tool, "--version"], check=True, capture_output=True, text=True)
    # Kingpin emits version information on stderr by default.
    return result.stdout + result.stderr


def check_helm(path):
    objects = [obj for obj in yaml.safe_load_all(path.read_text()) if obj]
    alertmanagers = [obj for obj in objects if obj["kind"] == "Alertmanager"]
    assert len(alertmanagers) == 1
    am = alertmanagers[0]
    assert am["spec"]["secrets"] == ["phorvex-telegram-alerts"]
    assert am["spec"]["replicas"] == 1
    assert "storage" not in am["spec"]
    assert "v0.34.0" in am["spec"]["image"]
    assert am["spec"]["resources"]["limits"]["memory"] == "256Mi"
    services = [obj for obj in objects if obj["kind"] == "Service" and obj["metadata"]["name"] == am["metadata"]["name"]]
    assert len(services) == 1 and services[0]["spec"].get("type", "ClusterIP") == "ClusterIP"
    assert not services[0]["spec"].get("externalIPs")
    native = yaml.safe_load((ROOT / "alertmanager-config.yaml").read_text())
    configs = [yaml.safe_load(base64.b64decode(obj["data"]["alertmanager.yaml"]))
               for obj in objects if obj["kind"] == "Secret" and "alertmanager.yaml" in obj.get("data", {})]
    assert len(configs) == 1 and configs[0] == native
    prometheus = next(obj for obj in objects if obj["kind"] == "Prometheus")
    assert prometheus["spec"]["alerting"]["alertmanagers"][0]["name"] == am["metadata"]["name"]
    assert not any(obj["kind"] == "PrometheusRule" and obj["metadata"]["name"] == "phorvex-runtime-health" for obj in objects)
    print("pinned Helm render: receiver, files, ephemeral CR, internal service and endpoint pass")


def check_templates(amtool, config, work):
    message = config["receivers"][1]["telegram_configs"][0]["message"]
    template_path = work / "telegram.tmpl"
    template_path.write_text('{{ define "a1.telegram" }}' + message + '{{ end }}')
    for status in ["firing", "resolved"]:
        alerts = [{"Status": status, "Labels": {"deployment": f"dummy<{i}>&" + "X" * 500,
                  "namespace": "dummy<&>", "severity": "warning"},
                  "Annotations": {"description": "NEVER_INCLUDE_DUMMY_ANNOTATION"}} for i in range(12)]
        data = {"Receiver": "milad-telegram", "Status": status, "Alerts": alerts,
                "CommonLabels": {"alertname": "dummy<&>", "namespace": "dummy<&>"}}
        data_path = work / "template-data.json"
        data_path.write_text(json.dumps(data))
        rendered = run(amtool, "template", "render", f"--template.glob={template_path}",
                       '--template.text={{ template "a1.telegram" . }}', "--template.type=text",
                       f"--template.data={data_path}")
        assert f"Phorvex dev: {status.upper()}" in rendered
        assert "dummy<&>" in rendered
        assert rendered.count("- " + status) == 5
        assert "dummy<4>&" in rendered and "dummy<5>&" not in rendered
        assert "NEVER_INCLUDE_DUMMY_ANNOTATION" not in rendered
        assert len(rendered) < 4096
    print("Telegram text templates: firing, resolved, < > &, five-object and length bounds pass")


def request(base, route, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + route, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=2) as response:
        content = response.read()
    return json.loads(content) if content else None


def check_inhibition(alertmanager, config, work):
    isolated = copy.deepcopy(config)
    # Actual routing and inhibition, with all receiver integrations removed.
    # No Telegram/API network traffic or message can result from these fixtures.
    isolated["receivers"] = [{"name": item["name"]} for item in config["receivers"]]
    path = work / "inhibition.yaml"
    path.write_text(yaml.safe_dump(isolated))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    command = [alertmanager, f"--config.file={path}", f"--storage.path={work / 'am-state'}",
               f"--web.listen-address=127.0.0.1:{port}", "--cluster.listen-address="]
    with (work / "alertmanager.log").open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    request(base, "/api/v2/status")
                    break
                except (OSError, urllib.error.URLError):
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError("isolated Alertmanager did not start")
                    time.sleep(0.1)
            common = {"phorvex_cluster": "dev", "namespace": "phorvex-system"}
            cases = {
                "critical": ({"alertname": "DummyPVC", "severity": "critical"}, False),
                "warning_same": ({"alertname": "DummyPVC", "severity": "warning"}, True),
                "warning_other_ns": ({"alertname": "DummyPVC", "severity": "warning", "namespace": "other"}, False),
                "warning_other_cluster": ({"alertname": "DummyPVC", "severity": "warning", "phorvex_cluster": "other"}, False),
                "warning_other_alert": ({"alertname": "DummyOther", "severity": "warning"}, False),
                "scrape_down": ({"alertname": "PhorvexEngineScrapeUnavailable", "severity": "critical", "monitor": "engine"}, False),
                "coverage_same": ({"alertname": "PhorvexMathLabStoreMetricsMissing", "severity": "warning", "monitor": "engine", "coverage": "mathlab"}, True),
                "coverage_other_monitor": ({"alertname": "PhorvexMathLabStoreMetricsMissing", "severity": "warning", "monitor": "other", "coverage": "mathlab"}, False),
            }
            end = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
            request(base, "/api/v2/alerts", [{"labels": {**common, **labels, "fixture": name}, "endsAt": end}
                                           for name, (labels, _) in cases.items()])
            deadline = time.monotonic() + 15
            while True:
                alerts = request(base, "/api/v2/alerts")
                observed = {item["labels"]["fixture"]: bool(item["status"]["inhibitedBy"]) for item in alerts}
                if observed == {name: expected for name, (_, expected) in cases.items()}:
                    break
                if time.monotonic() > deadline:
                    raise AssertionError(f"isolated inhibition mismatch: {observed}")
                time.sleep(0.1)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    print("actual Alertmanager inhibition: severity, namespace, cluster and coverage scope pass (null integrations)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--amtool", required=True)
    parser.add_argument("--promtool", required=True)
    parser.add_argument("--alertmanager", required=True)
    parser.add_argument("--helm-render", type=Path, required=True)
    args = parser.parse_args()
    assert "0.34.0" in tool_version(args.amtool)
    assert "3.14.0" in tool_version(args.promtool)
    check_helm(args.helm_render)
    config = yaml.safe_load((ROOT / "alertmanager-config.yaml").read_text())
    with tempfile.TemporaryDirectory(prefix="a1-checks-") as directory:
        work = Path(directory)
        dummy = copy.deepcopy(config)
        receiver = dummy["receivers"][1]["telegram_configs"][0]
        for key, value in [("bot_token_file", "123456:DUMMY_DATA_ONLY_DUMMY_DATA_ONLY"), ("chat_id_file", "123456789")]:
            path = work / key
            path.write_text(value)
            receiver[key] = str(path)
        cfg_path = work / "alertmanager.yaml"
        cfg_path.write_text(yaml.safe_dump(dummy))
        run(args.amtool, "check-config", str(cfg_path))
        for labels, expected in [(["phorvex_cluster=dev", "severity=warning", "alertname=Dummy"], "milad-telegram"),
                                 (["phorvex_cluster=dev", "severity=critical", "alertname=Dummy"], "milad-telegram"),
                                 (["phorvex_cluster=dev", "severity=info"], "null"),
                                 (["phorvex_cluster=other", "severity=critical"], "null"),
                                 (["severity=critical"], "null"),
                                 (["phorvex_cluster=dev", "severity=critical", "alertname=Watchdog"], "null"),
                                 (["phorvex_cluster=dev", "severity=warning", "alertname=InfoInhibitor"], "null")]:
            run(args.amtool, "config", "routes", "test", f"--config.file={cfg_path}", f"--verify.receivers={expected}", *labels)
        print("native config and actual amtool receiver routing pass")
        check_templates(args.amtool, config, work)
        rule = yaml.safe_load((ROOT / "phorvex-runtime-health.rules.yaml").read_text())
        (work / "rules.yaml").write_text(yaml.safe_dump(rule["spec"]))
        fixtures = yaml.safe_load((ROOT / "tests/runtime-health.test.yaml").read_text())
        fixture_path = work / "runtime-health.test.yaml"
        fixture_path.write_text(yaml.safe_dump(fixtures))
        run(args.promtool, "check", "rules", str(work / "rules.yaml"))
        run(args.promtool, "test", "rules", str(fixture_path))
        print(f"promtool syntax and all {len(fixtures['tests'])} rule scenarios pass")
        check_inhibition(args.alertmanager, config, work)


if __name__ == "__main__":
    main()
