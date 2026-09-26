# Owned CPU support-output fixture package

This package renders one deterministic, separately owned Pod and Service in
`vllm`. It leaves the shared vLLM Deployment and Service untouched. The
support app obtains public wording from the **existing guarded vLLM Service**;
the CPU proxy serves only the fixed support and read-only state routes. Its
fixture startup uses `create_app(load_models=False)`, and the fixture-mode
catchall refuses ordinary chat and raw backend forwarding. The catalogue's
Say OK and arithmetic controls call the same pinned guarded Service directly.
The seeded CAT-001 diagnostic field is an application serializer defect, not
a model jailbreak or a found model leak. CAT-002 is the public-only control.

`plan.example.json` is deliberately incomplete and cannot render. Fill a
private plan with freshly reviewed cluster UID, existing guarded Service and
single ready model target UIDs/image ID, actual console service-account
creator, and **digest-pinned** proxy/support
Python images. The reviewed `Dockerfile` is a candidate for both containers:
it pins the Linux/amd64 Python 3.11 base by digest and installs exactly the
16 hash-locked FastAPI/httpx/Uvicorn runtime wheels, without app source. The
proxy image does not need a
second vLLM or classifier weights: this fixture's chat route is closed and
the existing guarded Service performs input filtering. No container performs
`pip install` at startup. The support app alone receives the model-client
credential when one is configured; neither container receives Kubernetes API credentials.
For a guarded Service that requires a model-client credential, include both
`modelAPIKeySecretName` and `modelAPIKeySecretKey` in the plan. The provisioner
checks the existing Secret key before any mutation and only the support app
receives it. Omit both fields for a reviewed guarded Service that accepts
ordinary requests without an API key; this omits the Secret reference and
`VLLM_API_KEY` environment variable. A single field is invalid.

To prepare the image build context, obtain the exact wheel files named in
`wheelhouse.sha256` into this directory's ignored `wheelhouse/`. A private
staging directory may be populated with `python3 -m pip download --no-deps
--only-binary=:all: --require-hashes -r requirements.lock -d wheelhouse` in
a separately reviewed networked environment. Verify the context before any
build:

```sh
python3 verify_wheelhouse.py requirements.lock wheelhouse.sha256 wheelhouse
```

The verifier rejects missing, extra, symlinked or changed wheels. The
Dockerfile repeats that verification, installs without an index or network,
checks dependency compatibility, and verifies the package versions/imports
both as root at build time and as UID 10001. Its final image contains no
fixture source; the Pod mounts the separate immutable three-file source
ConfigMap read-only. After separate review and authorization, build with
Linux/amd64 and no build network, run `verify_runtime.py requirements.lock`
in a read-only networkless container, publish to a unique fixture-only
repository, and put the resulting immutable image digest in both image fields
of the private plan. A tag or the base Python digest is not a valid fixture
image pin. This candidate has not been built or published.

Render and inspect a private package without Kubernetes access:

```sh
python3 render.py --plan /private/reviewed-plan.json --out-dir /private/guardrail-output-package
python3 provision.py --package /private/guardrail-output-package
python3 -m unittest -v test_fixture.py
```

The render step creates a new `0700` directory with `0600` files. It generates
a run marker unless `--marker-file` supplies a private run-owned marker. The
marker appears only in the private Secret manifest, not in the source
ConfigMap, Pod annotations, policy, package summary, or event metadata.
`provision.py` without `--execute` validates exact rendered bytes and current
source files and makes **zero API calls**. The source ConfigMap is immutable
and has exactly `guardrail_proxy.py`, `output_policy.py` and
`support_fixture.py`. `sourceSHA256` is SHA-256 of proxy source bytes, one NUL
byte, then output-policy source bytes; `supportSourceSHA256` hashes the support
source. A source edit requires a new package and review.

After separate rollout authorization, the explicit execution form is:

```sh
python3 provision.py --package /private/guardrail-output-package \
  --execute --kubeconfig /private/reviewed-kubeconfig \
  --context REVIEWED_CONTEXT --confirm-cluster-uid REVIEWED_KUBE_SYSTEM_UID
```

The provisioner checks the exact cluster, guarded Service UID, single ready
EndpointSlice target, real vLLM Pod UID/image ID, any configured model-client Secret key, and
console service account before any mutation. It refuses pre-existing fixture
object names. It then creates only the immutable source ConfigMap, private
marker Secret, and bare fixture Pod. The Pod's optional policy ConfigMap mount
is read-only and has no `subPath`; readiness stays false while policy is
absent. A marker-copy init container reads the projected Secret symlink and
writes a regular `0600` file into a Pod-local `emptyDir`, which the support
app opens with `O_NOFOLLOW`. The policy watermark uses another per-Pod
`emptyDir`, surviving container restarts.

Once Kubernetes assigns the Pod UID, the provisioner creates
`phorvex-output-policy-guardrail-output-fixture` with exact Pod controller
owner reference and canonical fixed rule bytes. Its initial activation is
temporarily invalid while the ConfigMap UID is unknown, so the proxy remains
closed. The provisioner re-reads the new ConfigMap UID and resourceVersion,
CAS-patches canonical inactive revision 0 with that UID, then CAS-patches the
Pod's UID-derived rule SHA annotation. It creates the dedicated fixture
Service, waits for both containers to become ready, and creates the dedicated
`guardrail-output-fixture` PhorvexPolicy last. That policy selects only the
fixture label and enables rotate, quarantine and output-policy activation;
normal feasibility, economics and NOOP remain in the decision path. Its
`reactiveOnly` trigger prevents a pre-baseline proactive move.

Successful provisioning writes private `runtime-pins.json` with the actual
fixture Pod/Service/source/policy ConfigMap/policy UIDs, both container image
IDs, rule SHA and source SHAs. Add these to
`build/test-harness/config.guardrail-output-response.yaml` together with fresh
manager, console and audit pins. The console independently checks source,
mount, creator, real model target and effective proxy readback before a
baseline request. This package alone establishes no disclosure or defended
outcome. If provisioning stops partway, retain exact object UIDs and
resourceVersions for review; it does not replace existing objects or delete
partial evidence automatically.

Cleanup after a completed, separately authorized run must check the protected
operation journal and policy activation first, then remove only objects whose
name and UID match `runtime-pins.json`: the dedicated policy, Service, Pod,
policy ConfigMap, marker Secret and source ConfigMap. A Pod UID replacement
invalidates its UID-bound policy rule and profile; render a new reviewed
package rather than reusing the old policy ConfigMap.
