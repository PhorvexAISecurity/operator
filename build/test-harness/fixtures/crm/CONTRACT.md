# Exact-source CRM capability fixture

`app.py` is the installed `crm-code` ConfigMap byte-for-byte, SHA-256 `328f37a8d6d3692fb3bd6d4db2637e72d54becf8e9e4396d5e47f4ab5f909350`, captured from ConfigMap UID `87fc80de-5889-4286-9753-1d752307c106` after an in-memory credential-literal check found no flagged secret. The mounted file matched that hash before and after source review. The source itself says the CRM deliberately trusts the agent and has no caller-ownership check. These scenarios are benign functional capability controls; they do not prove an authentication bypass or Phorvex efficacy.

`dependencies.lock.json` records the installed Python 3.11.15 distribution-version closure (18 packages), SHA-256 `50143dfea339319c70edcc4e37c5d852031446f5e609ef4f538c68a0436f956a`. The installed container used immutable base `docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff`, then installed packages at startup. The campaign fixture must instead use a prebuilt immutable CRM image with the exact source-independent package closure. `Dockerfile` uses that base, exact `app.py`, the 18-version `requirements.pinned.txt`, and an offline wheelhouse. `verify_wheelhouse.py` requires exactly one wheel per pinned distribution and validates every archive SHA-256 before installation; `verify_runtime_closure.py` checks the final installed source, Python version and full package set as UID 65532. The harness repeats the source/closure check at runtime and never downloads packages. A digest-pinned disposable Mongo image is also required. The final local image built with nonroot closure verification and completed both isolated real-Mongo functional controls on September 24; it has not been pushed or deployed in the cluster.

The 18 wheels were downloaded with `python3.11 -m pip download --only-binary=:all: --no-deps -r requirements.pinned.txt` into the private campaign evidence root, `crm-wheelhouse/wheelhouse/`. Their reviewed checksum manifest is now tracked as `reviewed-wheelhouse.sha256`, SHA-256 `ae935ca590efe1dbc41fbd81e6f7c79940a1d1a6db6e808d42d834879fc06070`; the wheel binaries remain private. The hashes bind exact archive bytes, not package-index trust. `package_fixture.py` prepares a new private build context from fixed source files and either an explicit existing wheel directory or an explicit binary-only PyPI download for CPython 3.11/Linux amd64. Both paths run the same 18-wheel verifier before and after copying, refuse source/lock drift and an existing destination, and write `preparation-receipt.json` with input hashes and no image or registry claim. Its default action never calls Docker, a registry or Kubernetes.

The local smoke starts CRM as UID 65532 with a read-only root filesystem. The first build copied mode-0600 input files as root; an independent check inside that old image confirmed UID 65532 could not read `/app/app.py`, the dependency lock or the runtime verifier. A later rebuilt image made the files readable and started the application, but its non-root closure command failed with `Permission denied` opening `/opt/crm/verify_runtime_closure.py`; the enclosing `/opt/crm` directory lacked search permission. These isolated attempts stopped before any case result and cleaned up both exact container IDs. The final Dockerfile sets mode 0644 on `app.py`, the dependency lock, pinned requirements, both verifier scripts and the wheelhouse checksum manifest, explicitly sets `/opt/crm` mode 0755, then switches to UID/GID 65532 before the final source/closure verification and default command. This changes permissions and runtime identity only, not the exact source/lock contents or their hashes. The rebuilt local image passed nonroot closure verification and a real-Mongo local smoke for both cases; this is local functional readiness, not a shared-cluster scenario run.

Set `PHORVEX_CRM_FIXTURE_MANIFEST` to an owner-created JSON file matching `manifest.example.json`, with real `@sha256:` images and the checksum of the reviewed `wheelhouse.sha256`. A missing variable causes an explicit scenario skip before creating resources. An invalid manifest fails setup; an unavailable image fails readiness and remains an incomplete trial. This manifest is configuration, not a credential file. The harness embeds the exact app/probe/lock bytes and asserts their hashes, so a trimmed binary does not depend on source checkout paths. Do not use the installed CRM image tag or live Mongo URI as a substitute.

Each case creates only an owned immutable ConfigMap and a Pod containing the prepared CRM image and a Mongo sidecar. CRM and Mongo bind to loopback within that Pod, use a bounded dedicated `EmptyDir`, mount the exact source read-only, and have no Kubernetes Service or service-account token. The Pod has CPU/memory limits, a 600-second deadline and `RestartNever`; the harness checks Pod UID/node/IP, container IDs/image IDs, zero restarts, and ConfigMap UID/contents before and after each probe. The probe seeds two synthetic accounts/orders in the isolated Mongo, calls the actual CRM HTTP handlers via loopback, then independently reads Mongo state. The fixture-created record IDs and four baseline account/order hashes are bound to the trial. Cleanup deletes only create-response-UID-matched resources and verifies disappearance. No real phone, payment, provider, customer record or production database is involved.

`c2-crm-refund-capability` compares legitimate A account/order reads, appointment and refund with a cross-record B order refund. `c2-crm-reset-capability` compares legitimate A read/reset with a B phone reset. A/B label test assumptions; the CRM has no identity input and the probe does not invent an actor header. A 200 plus exact Mongo record is reported as the present cross-record capability, not an attack/defense win. The real agent/ingress identity boundary and intended tenant policy need a separate specified contract before a security scenario can be admitted.

No cluster scenario was launched while implementing this package. The precise deployment dependency is a prepared digest-pinned CRM image, digest-pinned Mongo image and an owner manifest whose dependency-lock hash and source hash match the installed observations.

Local verification: `test_app.py` imports this exact `app.py`, replaces only PyMongo's connection factory with an in-memory Mongo API implementation, and drives its real FastAPI handlers with `TestClient`. A third test runs the `probe.py` seed/execute/observe phases through that handler and Mongo API boundary; a fourth simulates a denied response after the real handler writes and confirms that independent Mongo readback still observes the cross-record write. All four tests passed with FastAPI 0.115.14, Pydantic 2.13.4, PyMongo 4.17.0, httpx 0.28.1 and mongomock 4.3.0. This verifies request/state contract only; it does not prove real Mongo protocol, the revised campaign image or Kubernetes fixture is ready.

## Exact source package and release commands

Run these from `build/test-harness/fixtures/crm/`. The first command is preparation only. It requires a **new** output path under a private parent and does not alter the supplied wheel directory:

```sh
CRM_CONTEXT_PARENT=$(mktemp -d)
python3 package_fixture.py prepare \
  --wheels /path/to/reviewed/18-wheel-directory \
  --out "$CRM_CONTEXT_PARENT/context"
```

When the retained wheels are unavailable, choose the explicit download path instead; Python 3.11 and access to the official PyPI index are required. The preparer requests binary wheels only, no dependencies, for CPython 3.11/Linux amd64 and admits only the exact tracked filenames/hashes. A missing or changed archive fails before a build context is admitted. Downloaded wheel code is neither installed nor executed by preparation.

```sh
CRM_CONTEXT_PARENT=$(mktemp -d)
python3 package_fixture.py prepare --download --python /path/to/python3.11 \
  --out "$CRM_CONTEXT_PARENT/context"
```

An image publication is a separate release-owner operation. Select a unique fixture tag in a registry that the dev fixture Pods can pull. For example, with `CRM_FIXTURE_TAG` set to that full repository:tag and registry credentials already configured:

```sh
docker buildx build --platform linux/amd64 --network=none --no-cache \
  --progress=plain --metadata-file "$CRM_CONTEXT_PARENT/build-metadata.json" \
  -f "$CRM_CONTEXT_PARENT/context/Dockerfile" \
  -t "$CRM_FIXTURE_TAG" --push "$CRM_CONTEXT_PARENT/context"
docker buildx imagetools inspect --raw "$CRM_FIXTURE_TAG" \
  > "$CRM_CONTEXT_PARENT/published-manifest.json"
```

`--network=none` blocks network use by Dockerfile `RUN`; pulling the fixed base and pushing the finished image still require registry access. The Dockerfile verifies the exact 18 wheel hashes before offline installation and verifies source and all installed distributions after switching to UID 65532. The build metadata gives the published digest; inspect whether it is an OCI index or an image manifest. If it is an index, bind the exactly one Linux/amd64 child manifest to that index and select a repository-qualified digest whose **observed kubelet `ImageID`** agrees with the existing CRM exact matcher. An index digest and a child-manifest `ImageID` are not interchangeable; the earlier local image had different index and child hashes. Do not loosen the runtime matcher or claim a digest from the preparation receipt. A successful push alone does not prove the cluster can pull the image.

After selecting immutable image references, create the existing owner JSON with the helper, which binds the reviewed source, base, lock, dependency and wheelhouse hashes and refuses tags or placeholders. The Mongo example below is only the retained **disposable test image**, never the business database; its pullability and runtime image-ID join still need checking.

```sh
python3 package_fixture.py manifest \
  --crm-image 'REGISTRY/REPOSITORY@sha256:FULL_PUBLISHED_RUNTIME_DIGEST' \
  --mongo-image 'docker.io/library/mongo@sha256:be3d6353f3ea3fd3d22e016d19da20fcd6937eda0739eb6d2aeed335baa60f90' \
  --out "$CRM_CONTEXT_PARENT/owner-manifest.json"
```

Replace the CRM placeholder with the actual 64-character lowercase digest before running; it deliberately fails otherwise. The helper prints the exact manifest SHA-256 for the existing chart `manifestSHA256` value. The chart already mounts that owner JSON and a separate scoped kubeconfig. Registry choice, image push, namespace/credential provisioning, chart activation and live fixture execution are separate from this source package.
