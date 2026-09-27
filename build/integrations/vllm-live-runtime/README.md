# vLLM reset-ack live runtime candidate

This is a **review-only source package**, not a deployment. It joins the normal
`main` publication of the vLLM 0.7.3 reset-ack derivative to the observed
`vllm/vllm` Deployment, its `guardrail-proxy` ConfigMap, and Phorvex's existing
`secure-required` serving-control chart contract. The published image reference
is `753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:af3e5ce57d156c09533dde6bb7feab8f252ef3dbc3277b77c2baef4bd781897f`
from normal workflow run `36301573126`, source `39c5783157d0ee137fff25f39af58fab727887ff`.
The original publication receipt SHA-256 is
`34a9b06b5c5c81cf53ad2b6efdf9314766e0a198bbe1a812c12f850074e96643`.
The digest may be an OCI index; join the actual `linux/amd64` Pod image ID to
the published manifest after rollout. No currently running Pod is claimed to
use this image.

`render.py` accepts exact SHA-256-pinned original Kubernetes JSON, the immutable
published image reference, and names of pre-provisioned Secrets. It refuses
workload, source, port, LoRA flag, and dev-mode drift. It emits a private
candidate Deployment, ConfigMap, umbrella Helm values overlay, and a
non-secret Secret contract. It has no Kubernetes or registry client and does
not read Secret objects. Its output must be reviewed against a fresh source
capture before the normal workload owner installs it; the retained baseline
Deployment and proxy ConfigMap were observed on Sep 27 and may have changed.

The candidate keeps the public guardrail listener on HTTP port 8000 and the
same Service route. `dual_server.py` shares one classifier/runtime between that
listener and a private TLS listener on Pod port 8443. Public requests may reach
`/health`, `/v1/guardrail/state`, `GET /v1/models`, the two guarded completion
POSTs, and an explicit list of ordinary inference/tokenization routes in
`PUBLIC_MODEL`. The installed workload's known completion clients keep the
guardrail scoring path. Other listed routes retain the existing proxy's
unscored forwarding behavior; this package does not claim that the installed
model implements every listed route. The boundary replaces any public
Authorization header with the upstream vLLM API key only for listed model API
routes. It refuses
raw reset, runtime LoRA, guardrail reload, KV invalidate, and drain routes on
the public listener. The TLS listener requires a distinct admin bearer before
one exact control route reaches the existing proxy. For raw vLLM control routes
the boundary substitutes the upstream API key on the loopback hop; the named
guardrail routes retain the admin bearer. No control credential is placed in
Pod annotations or a public URL.

The renderer binds vLLM to `127.0.0.1:8001`, so an external Pod cannot bypass
the guardrail or reach vLLM's developer routes at PodIP:8001. Existing vLLM
`/health` probes become equivalent in-container loopback checks with their
periods and thresholds preserved. The guardrail still serves 8000 and retains
its startup/readiness probe. It advertises `phorvex.ai/lora-enabled=true`
because the captured args include `--enable-lora` and the container env has
`VLLM_ALLOW_RUNTIME_LORA_UPDATING=1`; this does **not** claim a loaded adapter
or a clean replacement source.

The normal deployment owner must provide **two private Secret objects** before
the candidate rollout:

| Namespace / Secret | Keys | Use |
| --- | --- | --- |
| `vllm/vllm-control` | `api-key`, `admin-bearer`, `tls.crt`, `tls.key` | Upstream vLLM key, distinct proxy admin bearer, Pod TLS certificate/key. |
| `phorvex-system/vllm-serving-admin` | `bearer`, `ca.crt` | The same admin bearer bytes and the issuing CA for the exact TLS listener. |

The admin bearer and upstream API key must be distinct 32–256 printable
non-space bytes. The certificate SAN must cover `vllm-admin.vllm.svc`; Phorvex
connects to exact Pod IP and verifies this name through its existing
`servingSecurity` binding. The sample binding is exact to policy
`vllm/vllm-defense` UID `5cef9d07-12ed-48a2-9f51-f8f45fb2442d` and the
Deployment's current `default` ServiceAccount. Re-read those identities before
rendering. Secret bytes must stay in the existing private Secret provisioning
path; no `stringData`, placeholder credential, or Secret dump belongs in Git.

The umbrella values overlay changes Phorvex serving-control mode from the
current explicit `legacy-plaintext` to `secure-required` and grants the manager
`get` only for `vllm-serving-admin`. It is a **global** serving-control mode.
A bounded read on Sep 27 inspected all 16 installed Pods in the eight namespaces
with active policies advertising serving actions; only the current
`vllm/vllm-77d4b5fc5f-xcpnt` Pod UID
`fdb92f85-c98d-40c8-83db-7881041b1f8b` declared a Phorvex model ID or
serving port. The private inventory receipt is
`live-workloads-20260926/vllm-live-runtime-candidate/serving-pods-v2-20260927T0728Z/RECEIPT.json`.
The other policy action lists are capabilities, not installed serving targets.
A future new declared target needs its own exact secure binding. Recheck the
inventory before applying the global chart change. Helm 3.16.4 rendered
the candidate overlay with the installed PodMonitor API capability, producing
the exact `phorvex-phorvex-serving-security` ConfigMap and name-scoped Secret
grant. The old `kv-session-v1` dispatching journal remains untouched and UNKNOWN;
the new Pod UID, if normal rollout creates one, is a separate operation domain.
The installed `prepareRecovery` source refuses a legacy-plaintext journal when
the current mode is `secure-required`; this package does not reconcile or
reinterpret that old attempt. A new reset still requires the separately
reviewed fresh-operation authority and current policy/Pod/source checks.

The external `vllm` Deployment/ConfigMap currently has no checked-in GitOps
owner. The normal workload owner must adopt and review the candidate; this
package must not be applied as an ad hoc patch. The intended rollout sequence
is: provision both Secrets and trusted CA; install the proxy ConfigMap and
candidate Deployment via the workload owner; verify the new Pod's actual
image/source and public inference plus the TLS/negative-auth route boundaries;
then install the exact operator binding through the normal Phorvex chart. A
control-path failure must refuse action, not fall back to plaintext. A later
authorized test may exercise one new reset and require the derivative's
`success:true|false` acknowledgement; this package performs no reset.

Offline checks (using the pinned local Python environment with FastAPI, HTTPX,
and Uvicorn installed):

```sh
/home/mehrdad/.local/share/phorvex-tools/m116-py311/bin/python -m unittest discover -s build/integrations/vllm-live-runtime -p 'test_*.py' -v
```

The real-app tests exercise the existing FastAPI proxy and lifespan, a local
upstream, public inference and control refusal, and both actual Uvicorn HTTP
and TLS listeners. They use synthetic in-process keys and a one-day localhost
test certificate. No model weights, live Pod, or cluster control were called.
