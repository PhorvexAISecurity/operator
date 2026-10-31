"""Catalogue sensitive-output guardrail proxy (AML.T0069{,.001,.002}).

A self-contained, deterministic, non-secret CPU fixture that reproduces the
reviewed output-policy oracle the console drives through pods/proxy:

  * GET  /v1/output-policy/state  -> {ready, active, revision, operationId},
    read fresh from the Pod-owned output-policy ConfigMap mounted read-only at
    /policy (bootstrap.py provisions it; the actuator flips `active` on run).
  * GET  /healthz                 -> 200 once the policy state is readable, so
    the Pod only becomes Ready after its policy exists (explicit readiness).
  * POST /v1/support/case         -> a phorvex.support-case-response.v1 document.
      - caseId "CAT-001" carries the sensitive field diagnostics.internalAuditMarker.
        It LEAKS the synthetic marker while the policy is inactive (the vulnerable
        precondition) and is replaced by the exact redaction sentinel once active
        (the postcondition the console asserts two-sided).
      - any other caseId ("CAT-002" is the console's benign control) returns the
        fixed safe response with empty diagnostics and a deterministic modelReceipt.

The marker is a clearly-labelled synthetic token, never a credential. Nothing is
written to disk and the module has no import-time side effects so it is unit
testable; the HTTP server only starts under __main__.
"""
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

POLICY_DIR = Path(os.environ.get("OUTPUT_POLICY_DIR", "/policy"))
SCHEMA = "phorvex.support-case-response.v1"
MODEL_ID = "phorvex-catalogue-support-fixture"
MARKER = "SYNTHETIC-AUDIT-MARKER-7F3A9C2E-CATALOGUE-FIXTURE-NOT-A-CREDENTIAL"
REDACTED = "[REDACTED-BY-OUTPUT-POLICY]"
SENSITIVE_CASE = "CAT-001"
ACTIVATION_KEYS = {"active", "configMapUID", "operationId", "revision", "ruleId", "version"}
MAX_REQUEST_BYTES = 4096


def read_state(policy_dir=POLICY_DIR):
    """Return the proxy view of the mounted activation, fail-closed on any error.

    ready is False until a well-formed activation.json is present, so the Pod is
    not Ready before bootstrap provisions its policy ConfigMap.
    """
    try:
        value = json.loads((Path(policy_dir) / "activation.json").read_bytes())
        if not isinstance(value, dict) or set(value) != ACTIVATION_KEYS or \
                not isinstance(value["active"], bool) or not isinstance(value["revision"], int) or \
                isinstance(value["revision"], bool) or value["revision"] < 0 or \
                not isinstance(value["operationId"], str):
            raise ValueError("noncanonical activation")
        return {"ready": True, "active": value["active"],
                "revision": value["revision"], "operationId": value["operationId"]}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"ready": False, "active": False, "revision": 0, "operationId": ""}


def completion_id(case_id):
    return "cat-" + hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:24]


def support_case(case_id, active):
    """Build the exact six-key support response for the given case and policy state."""
    case_id = case_id if isinstance(case_id, str) and case_id else "UNKNOWN"
    response = {
        "schema": SCHEMA,
        "caseId": case_id,
        "status": "delivered",
        "answer": "Support case " + case_id + " delivered by the catalogue guardrail-output fixture.",
        "diagnostics": {},
        "modelReceipt": {"model": MODEL_ID, "completionId": completion_id(case_id)},
    }
    if case_id == SENSITIVE_CASE:
        # The sole sensitive field; the output policy redacts exactly this path.
        response["diagnostics"] = {"internalAuditMarker": REDACTED if active else MARKER}
    return response


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, code, value):
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            current = read_state()
            self._reply(200 if current["ready"] else 503,
                        {"status": "ok" if current["ready"] else "not-ready"})
        elif self.path == "/v1/output-policy/state":
            self._reply(200, read_state())
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/support/case":
            self._reply(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._reply(413, {"error": "request too large"})
            return
        body = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(body) if body else {}
            case_id = parsed.get("caseId") if isinstance(parsed, dict) else None
        except (ValueError, json.JSONDecodeError):
            case_id = None
        self._reply(200, support_case(case_id, read_state()["active"]))

    def log_message(self, *_):
        pass


def main():
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()


if __name__ == "__main__":
    main()
