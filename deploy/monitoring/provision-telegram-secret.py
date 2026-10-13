#!/usr/bin/env python3
"""Stage 2 only: transfer the approved local Telegram file to one Secret via stdin."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

APPROVED_ENV = Path.home() / ".config/phorvex-alerts/telegram-bot.env"
SECRET_NAME = "phorvex-telegram-alerts"
NAMESPACE = "monitoring"
MAX_FILE_BYTES = 4096


class ProvisionError(Exception):
    """Safe error categories; never include credentials or subprocess diagnostics."""


def read_private_env(path):
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
            raise ProvisionError("approved credential file must be an owned regular file with mode 0600")
        if info.st_size > MAX_FILE_BYTES:
            raise ProvisionError("approved credential file exceeds size bound")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            contents = stream.read(MAX_FILE_BYTES + 1)
        if len(contents) > MAX_FILE_BYTES:
            raise ProvisionError("approved credential file exceeds size bound")
        return contents.decode("utf-8")
    except (OSError, UnicodeError):
        raise ProvisionError("cannot read approved private credential file") from None
    finally:
        if fd is not None:
            os.close(fd)


def parse_env(contents):
    values = {}
    allowed = {"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_BOT_USERNAME"}
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in allowed or key in values:
            raise ProvisionError("credential file has an invalid or duplicate key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    token = values.get("TELEGRAM_BOT_TOKEN", "")
    chat = values.get("TELEGRAM_CHAT_ID", "")
    if not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,120}", token):
        raise ProvisionError("credential file has an invalid bot token")
    if not re.fullmatch(r"[1-9][0-9]{0,18}", chat) or int(chat) > 2**63 - 1:
        raise ProvisionError("credential file must contain a positive private chat ID")
    username = values.get("TELEGRAM_BOT_USERNAME")
    if username is not None and username.lstrip("@") != "phorvex_cluster_alerts_bot":
        raise ProvisionError("credential file names an unexpected bot")
    return token, chat


def secret_payload(token, chat):
    # Use data, not stringData: server-side apply tracks data reliably on rotation.
    return json.dumps({
        "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
        "metadata": {"name": SECRET_NAME, "namespace": NAMESPACE},
        "data": {
            "TELEGRAM_BOT_TOKEN": base64.b64encode(token.encode()).decode("ascii"),
            "TELEGRAM_CHAT_ID": base64.b64encode(chat.encode()).decode("ascii"),
        },
    }, separators=(",", ":")).encode()


def provision(operation, payload, runner=None):
    if operation == "create":
        kubectl = ["kubectl", "create", "--field-manager=phorvex-alerts-provisioner",
                   "-n", NAMESPACE, "-f", "-", "-o", "name"]
    elif operation == "rotate":
        kubectl = ["kubectl", "apply", "--server-side", "--field-manager=phorvex-alerts-provisioner",
                   "-n", NAMESPACE, "-f", "-", "-o", "name"]
    else:
        raise ProvisionError("invalid provisioning operation")
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "phorvex-gw", *kubectl]
    try:
        result = (runner or subprocess.run)(command, input=payload, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ProvisionError("Secret transfer failed; remote diagnostics suppressed") from None
    if result.returncode != 0:
        raise ProvisionError("Secret transfer failed; remote diagnostics suppressed")
    # Remote output/errors can echo submitted values. Never forward them.
    print(f"secret/{SECRET_NAME} {'created' if operation == 'create' else 'rotated'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["create", "rotate"])
    parser.add_argument("--execute", action="store_true", help="perform the approved stage-2 Secret write")
    args = parser.parse_args(argv)
    if not args.execute:
        raise ProvisionError("stage-2 provisioning requires explicit --execute")
    token, chat = parse_env(read_private_env(APPROVED_ENV))
    provision(args.operation, secret_payload(token, chat))
    return 0


def cli(argv=None):
    try:
        return main(argv)
    except ProvisionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        # No traceback or underlying parser/process exception can expose content.
        print("Secret provisioning failed; diagnostics suppressed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
