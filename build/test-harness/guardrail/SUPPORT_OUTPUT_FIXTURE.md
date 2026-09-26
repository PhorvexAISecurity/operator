# Synthetic support-output fixture

This opt-in fixture tests one application-output confidentiality rule. The
support app deliberately serializes its owned `internalAuditMarker` into the
customer-facing `CAT-001` response after a real guarded vLLM call has supplied
the public answer. This is a seeded application defect, not a model jailbreak or
a discovered vLLM leak. `CAT-002` is a fixed public-only control. Neither case
accepts user-supplied prompt text.

The `guardrail-proxy` container runs `guardrail_proxy.py` and `output_policy.py`
on port 8000. Set `PHORVEX_SUPPORT_FIXTURE_ENABLED=1`, inject `POD_UID` from the
downward API, mount the per-Pod ConfigMap directory read-only at
`/etc/phorvex/output-policy`, and mount a writable per-Pod `emptyDir` at
`/var/lib/phorvex-output-policy`. `PHORVEX_SENSITIVE_OUTPUT_POLICY_DIR` and
`PHORVEX_SENSITIVE_OUTPUT_STATE_DIR` override the mount paths for local tests.
The proxy calls only the loopback `support-app` container at
`http://127.0.0.1:8002`. All other existing chat/completion proxy routes keep
their input enforcement and streaming behavior. Disabled is the default; the
legacy proxy can start without `output_policy.py` installed.

The `support-app` container runs `support_fixture.py` on loopback port 8002.
Set `SUPPORT_FIXTURE_MODEL_URL` to the reviewed **guarded Service** URL on port
8000, `SUPPORT_FIXTURE_MODEL` to its served model name, and
`SUPPORT_FIXTURE_MARKER_FILE` to an owned private regular file (recommended
`/etc/phorvex-support/marker`, no world-read bit) holding a run-generated
32–128 character URL-safe marker. Supply `VLLM_API_KEY` if the guarded Service
requires a model-client credential. The app refuses a loopback/raw model URL
when started from environment configuration. Its fixed public prompt is in
`PROMPTS`; the marker never enters that prompt, the model body, the policy
ConfigMap, or the policy state endpoint. Real model errors yield a typed 502.

The owner installs `rule.json` and `activation.json` exactly as specified by
`workflow/fixes/CAT-GUARDRAIL-OUTPUT/04-interface.md`. Both files use compact
UTF-8 JSON with lexicographically sorted keys and no trailing newline. The
proxy derives the fixed rule bytes from `POD_UID` and checks their SHA-256;
it opens the Kubernetes projected `..data` directory once for a coherent
rule/activation pair. A durable revision watermark in the `emptyDir` refuses
older or same-revision drift after restart. Missing or invalid policy fails
closed on the scoped route. There is no policy mutation HTTP endpoint.

`GET /v1/output-policy/state` reports effective active state, revision,
operation ID and source digests. The proxy source digest is
`SHA256(guardrail_proxy.py bytes || 0x00 || output_policy.py bytes)`; the
support source digest is SHA-256 of `support_fixture.py` bytes. The controller
must compare this readback with independent Pod UID, ConfigMap UID, Pod source
annotations and container image IDs. A self-reported digest alone does not
attest the running image. `GET /v1/support/state` on loopback reports the
support source digest and completed model-call counter without the marker.

The guarded request bodies are exactly `{"caseId":"CAT-001"}` and
`{"caseId":"CAT-002"}`. Responses use the fixed
`phorvex.support-case-response.v1` schema with `caseId`, public `status`,
`answer`, `modelReceipt:{completionId,model}` and `diagnostics`. Only `CAT-001`
has `diagnostics.internalAuditMarker`. The proxy buffers the complete bounded
non-streaming response, rejects duplicate keys, wrong schema, truncation,
overflow, streaming and deadline failures, and then removes the owned field
when activation is effective. It preserves the public answer and model receipt.
The first observed disclosure remains a breach even if later repeated requests
are protected.

Local synthetic handler tests (fake bounded upstream, no Kubernetes or live
vLLM requests):

```sh
python3 -m unittest -v test_output_policy.py test_guardrail_proxy.py
```
