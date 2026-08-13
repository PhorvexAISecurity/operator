"""Telegram reporting for the End-to-End pipeline.

One message per run, edited in place as each stage finishes, so a channel watching many
CI runs gets a live progress board instead of eight messages per pull request. The final
edit carries the verdict, the check tally and the published report link.

Two rules this module holds to:

- **A notification failure is never a test failure.** Every call is wrapped; if Telegram is
  down, unreachable, or the token is wrong, the pipeline logs one line and carries on. The
  thing under test is Phorvex, not the messenger.
- **Absent credentials mean silence, not an error.** With no `TELEGRAM_BOT_TOKEN` /
  `TELEGRAM_CHAT_ID` the notifier is inert, so a developer's local run needs no setup.

Credentials come from the environment only — never from config.json, which is committed.
"""

import json
import os
import urllib.error
import urllib.request

API = "https://api.telegram.org"

# Stage titles mirror the [n/6] headings e2e.py prints, so the channel and the CI log read
# as the same run.
STAGES = [
    (0, "Preflight"),
    (1, "Baseline capture"),
    (2, "Fire"),
    (3, "Post-attack capture"),
    (4, "Ground truth"),
    (5, "Checks"),
    (6, "Report"),
]

ICON = {"ok": "✅", "fail": "❌", "warn": "⚠️", "skip": "⏭", "run": "⏳", "wait": "▫️"}


def _esc(s):
    """Escape for Telegram's HTML parse mode (the only three it requires)."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Notifier:
    """A live progress board in a Telegram channel. Inert without credentials."""

    def __init__(self, token=None, chat_id=None, enabled=True, log=print):
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
        self.enabled = bool(enabled and self.token and self.chat_id)
        self.log = log
        self.message_id = None
        self.header = ""
        self.footer = ""
        # stage index -> (status, detail); rendered in STAGES order regardless of arrival.
        self.state = {}
        self._broken = False   # set after the first transport failure; stops retry storms

    # ── transport ────────────────────────────────────────────────────────────
    def _call(self, method, payload, timeout=15):
        if not self.enabled or self._broken:
            return None
        req = urllib.request.Request(
            f"{API}/bot{self.token}/{method}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:200]
            # "message is not modified" is benign: two stages rendered to the same board.
            if "message is not modified" not in body:
                self.log(f"telegram: {method} → HTTP {e.code} {body}")
            return None
        except Exception as e:                       # network, DNS, TLS, timeout
            self._broken = True
            self.log(f"telegram: disabled — {type(e).__name__}: {e}")
            return None

    # ── board ────────────────────────────────────────────────────────────────
    def _render(self):
        lines = [self.header, ""]
        for idx, title in STAGES:
            status, detail = self.state.get(idx, ("wait", ""))
            row = f"{ICON.get(status, ICON['wait'])} <b>[{idx}/6]</b> {_esc(title)}"
            if detail:
                row += f" — <code>{_esc(detail)}</code>"
            lines.append(row)
        if self.footer:
            lines += ["", self.footer]
        return "\n".join(lines)

    def _flush(self):
        text = self._render()
        if self.message_id:
            self._call("editMessageText", {
                "chat_id": self.chat_id, "message_id": self.message_id,
                "text": text, "parse_mode": "HTML", "disable_web_page_preview": True,
            })
            return
        r = self._call("sendMessage", {
            "chat_id": self.chat_id, "text": text,
            "parse_mode": "HTML", "disable_web_page_preview": True,
        })
        if r and r.get("ok"):
            self.message_id = r["result"]["message_id"]

    # ── public API ───────────────────────────────────────────────────────────
    def start(self, mode, target, transport, ctx_lines=()):
        """Post the board with every stage pending. Safe to call when disabled."""
        if not self.enabled:
            return
        head = [f"🛡 <b>Phorvex E2E</b> · <code>{_esc(mode)}</code>"]
        if target:
            head.append(f"target: <code>{_esc(target)}</code>")
        head.append(f"transport: <code>{_esc(transport)}</code>")
        self.header = "\n".join(head + [_esc(l) for l in ctx_lines])
        self._flush()

    def stage(self, idx, status, detail=""):
        """Mark a stage and redraw. `status` is one of ICON's keys."""
        if not self.enabled:
            return
        self.state[idx] = (status, detail)
        self._flush()

    def running(self, idx, detail=""):
        self.stage(idx, "run", detail)

    def finish(self, verdict, tally, report_url=None, failures=(), extra=()):
        """Final edit: verdict, tally, the failing checks by id, and the report link.

        Failures are named rather than counted — "3 failed" sends someone to the report to
        find out which; the ids let them decide whether it matters before they click.
        """
        if not self.enabled:
            return
        icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(verdict, "❓")
        parts = [
            f"{icon} <b>{_esc(verdict)}</b> — "
            f"✔{tally.get('pass', 0)} ✘{tally.get('fail', 0)} "
            f"!{tally.get('warn', 0)} –{tally.get('skip', 0)}"
        ]
        if failures:
            shown = list(failures)[:8]
            line = "failed: " + ", ".join(f"<code>{_esc(f)}</code>" for f in shown)
            if len(failures) > len(shown):
                line += f" (+{len(failures) - len(shown)})"
            parts.append(line)
        parts += [_esc(e) for e in extra]
        if report_url:
            parts.append(f'📊 <a href="{_esc(report_url)}">full report</a>')
        self.footer = "\n".join(parts)
        self._flush()

    def alert(self, text):
        """A standalone message, for things that must not be buried in an edit —
        a transport error that killed the run before any stage reported."""
        if not self.enabled:
            return
        self._call("sendMessage", {
            "chat_id": self.chat_id, "text": text,
            "parse_mode": "HTML", "disable_web_page_preview": True,
        })
