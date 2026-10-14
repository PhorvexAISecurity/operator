#!/usr/bin/env python3
"""Render A1's nonsecret overlay or promtool rules, with no cluster access."""
import argparse
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parent
CHART_VERSION = "88.5.3"
HEADER = (
    "# Chart: prometheus-community/kube-prometheus-stack 88.5.3 (Alertmanager v0.34.0).\n"
    "# Standalone A1 overlay. Use --reuse-values only after Hami's retention release.\n"
    "# Refresh alertmanager.config with: python3 deploy/monitoring/render-values.py\n"
)


class ValuesDumper(yaml.SafeDumper):
    """Keep the embedded multiline Telegram template reviewable."""


def represent_string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


ValuesDumper.add_representer(str, represent_string)


def load_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def render_values(overlay, config):
    # Refuse widening the overlay into the shared release's other values.
    if not isinstance(overlay, dict) or set(overlay) != {"alertmanager"}:
        raise ValueError("A1 overlay must contain only alertmanager")
    am = overlay["alertmanager"]
    if set(am) != {"enabled", "config", "alertmanagerSpec", "service", "ingress"}:
        raise ValueError("unexpected Alertmanager overlay keys")
    if am["enabled"] is not True:
        raise ValueError("Alertmanager must be enabled in the opt-in overlay")
    spec = am["alertmanagerSpec"]
    if set(spec) != {"secrets", "replicas", "resources"}:
        raise ValueError("only secrets, replicas and resources belong in A1 spec")
    if spec["secrets"] != ["phorvex-telegram-alerts"] or spec["replicas"] != 1:
        raise ValueError("unexpected Secret mount or replica count")
    if am["service"] != {"enabled": True, "type": "ClusterIP", "externalIPs": [], "loadBalancerIP": ""}:
        raise ValueError("A1 service must be internal ClusterIP only")
    if am["ingress"] != {"enabled": False}:
        raise ValueError("A1 must not expose an ingress")
    if not isinstance(config, dict):
        raise ValueError("native Alertmanager config must be a mapping")
    # Never change callers' input; config is maintained separately and embedded here.
    return {"alertmanager": {**am, "config": config}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="fail if committed overlay differs from its config source")
    action.add_argument("--rules", action="store_true", help="emit the manual PrometheusRule's spec for promtool")
    args = parser.parse_args(argv)
    if args.rules:
        rule = load_yaml(ROOT / "phorvex-runtime-health.rules.yaml")
        if rule.get("kind") != "PrometheusRule":
            raise ValueError("expected a manual PrometheusRule")
        sys.stdout.write(yaml.safe_dump(rule["spec"], sort_keys=False))
        return 0
    path = ROOT / "kube-prom-stack/values-alerting.yaml"
    overlay = load_yaml(path)
    rendered = render_values(overlay, load_yaml(ROOT / "alertmanager-config.yaml"))
    if args.check:
        if overlay != rendered:
            print("A1 overlay config is stale; regenerate with render-values.py", file=sys.stderr)
            return 1
        print(f"A1 overlay matches native config; chart {CHART_VERSION}")
    else:
        sys.stdout.write(HEADER + yaml.dump(rendered, Dumper=ValuesDumper, sort_keys=False, width=1000))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, yaml.YAMLError):
        print("A1 render failed: invalid or unreadable local configuration", file=sys.stderr)
        raise SystemExit(1)
