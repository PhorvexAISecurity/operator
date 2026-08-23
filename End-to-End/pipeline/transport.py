"""How the pipeline reaches the system under test.

The console binds to localhost on the jump server, so almost every real run goes through
SSH. `local` exists for running the pipeline ON that server (or anywhere the console and
kubectl are directly reachable), and keeps the rest of the code transport-agnostic.

No secret is ever written to disk by this module, and the password is passed to sshpass
through an environment variable rather than argv, so it does not appear in `ps` output.
"""

import json
import os
import shlex
import subprocess
from pathlib import Path


class TransportError(RuntimeError):
    pass


def _password():
    """SSH password from the environment, then a 0600 file. Never from config.json."""
    env = os.environ.get("PHORVEX_SSH_PASSWORD")
    if env:
        return env
    secret = Path.home() / ".phorvex-e2e" / "secret"
    if secret.exists():
        return secret.read_text(encoding="utf-8").strip()
    raise TransportError(
        "no SSH password: set PHORVEX_SSH_PASSWORD or write it to ~/.phorvex-e2e/secret (chmod 600)"
    )


class Transport:
    """Environment overrides win over config.json.

    CI keeps the jump host in repository secrets rather than in a committed file, and a
    developer testing against a different cluster should not have to edit — and risk
    committing — config.json to do it.
    """

    def __init__(self, cfg):
        self.kind = os.environ.get("PHORVEX_TRANSPORT") or cfg.get("kind", "local")
        self.host = os.environ.get("PHORVEX_SSH_HOST") or cfg.get("host")
        self.user = os.environ.get("PHORVEX_SSH_USER") or cfg.get("user")
        self.port = int(os.environ.get("PHORVEX_SSH_PORT") or cfg.get("port", 22))
        self.connect_timeout = int(cfg.get("connect_timeout_sec", 10))
        if self.kind == "ssh":
            self._pw = _password()

    def describe(self):
        return "local shell" if self.kind == "local" else f"ssh {self.user}@{self.host}:{self.port}"

    def run(self, command, timeout=60):
        """Run a shell command on the system under test. Returns (rc, stdout, stderr).

        Never raises on a non-zero exit — a failing probe is data the checks need, not a
        crash. Only a transport-level failure (host unreachable) raises.
        """
        if self.kind == "local":
            argv, env = ["/bin/sh", "-c", command], None
        else:
            argv = [
                "sshpass", "-e", "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-o", f"ConnectTimeout={self.connect_timeout}",
                "-p", str(self.port), f"{self.user}@{self.host}", command,
            ]
            env = dict(os.environ, SSHPASS=self._pw)
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {timeout}s"
        except FileNotFoundError as e:
            raise TransportError(f"transport binary missing: {e}") from e
        return p.returncode, p.stdout, p.stderr


class Console:
    """Typed access to the Phorvex console API over whatever transport is configured."""

    def __init__(self, transport, cfg):
        self.t = transport
        self.base = cfg["base"].rstrip("/")
        self.lens = cfg.get("lens", "operator")

    def _curl(self, args, timeout):
        rc, out, err = self.t.run(args, timeout=timeout)
        if rc != 0 and not out:
            raise TransportError(f"console call failed (rc={rc}): {err.strip() or 'no output'}")
        return out

    def get_json(self, path, timeout=20):
        cmd = (
            f"curl -s -m {timeout - 2} -H {shlex.quote('X-Phorvex-Lens: ' + self.lens)} "
            f"{shlex.quote(self.base + path)}"
        )
        out = self._curl(cmd, timeout)
        try:
            return json.loads(out)
        except json.JSONDecodeError as e:
            raise TransportError(f"GET {path} did not return JSON: {out[:200]!r}") from e

    def post_json(self, path, body, timeout=40):
        cmd = (
            f"curl -s -m {timeout - 5} -X POST "
            f"-H 'Content-Type: application/json' "
            f"-H {shlex.quote('X-Phorvex-Lens: ' + self.lens)} "
            f"-d {shlex.quote(json.dumps(body))} {shlex.quote(self.base + path)}"
        )
        out = self._curl(cmd, timeout)
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"_raw": out}

    def stream_decisions(self, seconds, max_bytes):
        """Capture the audit SSE stream for a bounded window.

        The stream replays the audit file and then tails it, so a short window still
        yields the recent decision history. Bounded on BOTH time and bytes: an operator
        under heavy churn must not be able to hang the pipeline or exhaust memory.
        """
        cmd = (
            f"curl -sN -m {seconds} -H {shlex.quote('X-Phorvex-Lens: ' + self.lens)} "
            f"{shlex.quote(self.base + '/api/live?lens=' + self.lens)} | head -c {int(max_bytes)}"
        )
        # curl exits non-zero on its own -m timeout, which is the normal path here.
        _, out, _ = self.t.run(cmd, timeout=seconds + 20)
        records, malformed = [], 0
        for line in out.splitlines():
            if not line.startswith("data: "):
                continue
            try:
                records.append(json.loads(line[6:]))
            except json.JSONDecodeError:
                malformed += 1  # a truncated final line from `head -c` is expected
        return records, malformed


class Metrics:
    """The audit writer's own Prometheus endpoint.

    Some operator state never reaches the audit record — most importantly the global kill
    switch, which suppresses actuation while leaving `dryRun` false. Reading it here is how
    the pipeline tells a deliberate decision-only mirror apart from a broken actuator,
    instead of inferring it from an absence.
    """

    def __init__(self, transport, cfg):
        self.t = transport
        cfg = cfg or {}
        self.url = cfg.get("metrics_url")
        # The in-cluster operator publishes metrics on a container port with no Service and
        # no ingress, so there is no URL the jump host can curl. Rather than expose an
        # operator's internals to the internet just to read one gauge, go through the API
        # server's pod proxy — the same credentials kubectl already uses for ground truth.
        self.proxy = cfg.get("kubectl_pod_proxy")

    def describe(self):
        if self.proxy:
            p = self.proxy
            return f"kubectl proxy {p['namespace']}/{p['selector']}:{p['port']}{p.get('path', '/metrics')}"
        return self.url or "—"

    def scrape(self, timeout=15):
        if self.proxy:
            return self._scrape_proxy(timeout)
        if not self.url:
            return {}
        rc, out, _ = self.t.run(
            f"curl -s -m {timeout - 3} {shlex.quote(self.url)}", timeout=timeout)
        if rc != 0 and not out:
            return {}
        return self._parse(out)

    def _scrape_proxy(self, timeout):
        """Read the operator's own metrics through the API server's pod proxy.

        The pod name is resolved at scrape time rather than configured: the operator is
        recreated on every deploy, and a stale pod name would return an empty scrape that
        looks exactly like "the gauge is absent" — which is the one thing check A06 must
        never get wrong.
        """
        p = self.proxy
        ns, sel, port = p["namespace"], p["selector"], int(p["port"])
        path = p.get("path", "/metrics")
        cmd = (
            f"POD=$(kubectl -n {shlex.quote(ns)} get pod -l {shlex.quote(sel)} "
            f"--field-selector=status.phase=Running "
            f"-o jsonpath='{{.items[0].metadata.name}}') && "
            f"[ -n \"$POD\" ] && "
            f"kubectl get --raw \"/api/v1/namespaces/{ns}/pods/$POD:{port}/proxy{path}\""
        )
        rc, out, _ = self.t.run(cmd, timeout=timeout)
        if rc != 0 and not out:
            return {}
        return self._parse(out)

    @staticmethod
    def _parse(out):
        vals = {}
        for line in out.splitlines():
            if line.startswith("#") or " " not in line:
                continue
            name, _, val = line.rpartition(" ")
            try:
                vals[name.strip()] = float(val)
            except ValueError:
                continue
        return vals


class Cluster:
    """kubectl ground truth — deliberately independent of anything Phorvex reports."""

    def __init__(self, transport):
        self.t = transport

    def kubectl(self, args, timeout=25):
        rc, out, err = self.t.run("kubectl " + args, timeout=timeout)
        return rc, out.strip(), err.strip()

    def pod_uids(self, namespace, selector=None):
        sel = f"-l {shlex.quote(selector)} " if selector else ""
        rc, out, _ = self.kubectl(
            f"-n {shlex.quote(namespace)} get pod {sel}"
            "-o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.uid}|"
            "{.metadata.ownerReferences[0].kind}|{.status.phase}{\"\\n\"}{end}'"
        )
        pods = {}
        if rc != 0:
            return pods
        for line in out.strip("'").splitlines():
            f = line.strip().split("|")
            if len(f) >= 4 and f[0]:
                pods[f[0]] = {"uid": f[1], "owner": f[2], "phase": f[3]}
        return pods

    def controller_pods(self, namespace="phorvex-system"):
        """Health of the operator pods themselves. A crash-looping operator still lets the
        dashboard look alive, because a second operator keeps writing the audit.

        Completed CronJob/Job pods share the operator namespace but are not controllers;
        counting them makes every E2E run fail between the job completing and its TTL
        cleanup. Keep failed Jobs out for the same reason: their health belongs to the
        job-specific check, not the controller liveness invariant.
        """
        rc, out, _ = self.kubectl(
            f"-n {shlex.quote(namespace)} get pod "
            "-o jsonpath='{range .items[*]}{.metadata.name}|{.status.phase}|"
            "{.status.containerStatuses[0].restartCount}|"
            "{.metadata.ownerReferences[0].kind}{\"\\n\"}{end}'")
        pods = {}
        if rc != 0:
            return pods
        for line in out.strip("'").splitlines():
            f = line.strip().split("|")
            if len(f) >= 4 and f[0] and f[3] != "Job":
                pods[f[0]] = {"phase": f[1], "restarts": int(f[2]) if f[2].isdigit() else 0}
        return pods

    def pod_is_stateful(self, namespace, pod):
        """Mirror of ingest/kube.go:406 — StatefulSet-owned, or mounts a PVC, or a Job."""
        rc, out, _ = self.kubectl(
            f"-n {shlex.quote(namespace)} get pod {shlex.quote(pod)} "
            "-o jsonpath='{.metadata.ownerReferences[0].kind}|"
            "{range .spec.volumes[*]}{.persistentVolumeClaim.claimName}{\" \"}{end}'"
        )
        if rc != 0:
            return None
        owner, _, claims = out.strip("'").partition("|")
        return owner in ("StatefulSet", "Job") or bool(claims.strip())

    def quarantine_state(self, namespace, pod):
        """Read the real Phoenix quarantine effect: a deny-all policy selecting the pod."""
        policy = f"{namespace}-{pod}-policy"
        rc, pod_out, _ = self.kubectl(
            f"-n {shlex.quote(namespace)} get pod {shlex.quote(pod)} -o json")
        if rc != 0:
            return None
        rc, policy_out, _ = self.kubectl(
            f"-n {shlex.quote(namespace)} get networkpolicy {shlex.quote(policy)} -o json")
        if rc != 0:
            return {"active": False, "policy": policy,
                    "evidence": f"NetworkPolicy {policy} is missing"}
        try:
            pod_doc, policy_doc = json.loads(pod_out), json.loads(policy_out)
        except json.JSONDecodeError:
            return None

        label_key = "amtd.r6security.com/network-policy"
        pod_label = (pod_doc.get("metadata", {}).get("labels", {}) or {}).get(label_key, "")
        spec = policy_doc.get("spec", {}) or {}
        selector = ((spec.get("podSelector", {}) or {}).get("matchLabels", {}) or {}).get(label_key, "")
        policy_types = set(spec.get("policyTypes", []) or [])
        deny_all = not (spec.get("ingress") or []) and not (spec.get("egress") or [])
        active = (pod_label == policy and selector == policy and deny_all and
                  {"Ingress", "Egress"}.issubset(policy_types))
        return {
            "active": active,
            "policy": policy,
            "evidence": (f"podLabel={pod_label or '<missing>'}; selector={selector or '<missing>'}; "
                         f"denyAll={str(deny_all).lower()}; policyTypes={','.join(sorted(policy_types)) or '<missing>'}"),
        }

    def container_log(self, namespace, pod, since="3m", grep=None, tail=400):
        cmd = f"-n {shlex.quote(namespace)} logs {shlex.quote(pod)} --since={since} --tail={tail}"
        rc, out, _ = self.kubectl(cmd, timeout=35)
        if rc != 0:
            return ""
        if grep:
            return "\n".join(l for l in out.splitlines() if grep in l)
        return out
