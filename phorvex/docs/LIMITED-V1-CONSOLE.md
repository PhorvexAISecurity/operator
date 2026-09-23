# Limited v1 functional catalogue

The console keeps the existing scenario catalogue and adds six `limited-v1-*`
entries. Voice media, Voice replacement recovery, GPU request drain and the two
console boundary checks run as fixed server profiles. The guardrail entry uses
the existing correlated vLLM effect endpoint. Their results are functional or
effect observations; they are excluded from security efficacy scoring.

The fixed profiles are visible while disabled. A launch is refused until the
server profile is complete. The browser supplies only the profile ID. The
console resolves the target and tenant, writes private `job.json` and
`runtime.json` files, hashes both authorities, and self-executes the static
console binary. No browser command, URL, token, namespace or executable is
accepted.

Enable profiles with `phorvex.console.catalogueV1` in the Helm values. Keep
`enabled: false` until all selected profile prerequisites are present:

- Set `scopedToken.existingSecret` to an operator-provisioned Secret containing
  a short-lived bearer token under `scopedToken.key`. The chart mounts it with
  mode `0440`; the token value is never copied into a job, journal, result, API
  response or Git.
- Set the allowed and denied auth scopes and `expectedSubject`. The loopback URL
  must remain a fixed `http://127.0.0.1:<port>` origin. See
  `../internal/cataloguev1/AUTH-FIXTURE.md`.
- Enable Voice only after setting its exact namespace, Deployment, Service,
  container, port, PDB and transcript selector/container. The chart adds a
  Role in that namespace for read, port-forward/exec, EndpointSlice/PDB reads,
  and one `pods/eviction` create. It grants no direct Pod delete fallback.
- Enable GPU only with a reviewed fixture ConfigMap and exact fixture namespace.
  Set `gpu.runtimeSecret` to an operator-provisioned Secret containing only the
  pinned kubeconfig and fixture bearer under `kubeconfigKey` and
  `bearerTokenKey`, and set the exact `kubeContext`. The chart mounts the
  ConfigMap and Secret with mode `0440`; the fixture config's kubeconfig and
  bearer paths must point at those mounts. Their bytes are never emitted. The
  mounted config is checked against the fixed single scenario/arm and the
  server runtime before the harness starts. See
  `../internal/cataloguev1/GPU-FIXTURE.md`.

Every worker records intent before effects, uses one Linux execution lock, and
handles `SIGTERM` through bounded cleanup. A terminal functional pass requires
the matching job/result identities, one structurally valid benign metric,
verified cleanup, and matching oracle. A missing worker, malformed result,
lost persistence acknowledgement or cleanup uncertainty produces `partial`,
`inconclusive`, or `test-failed`; it cannot appear as a green functional pass.

The guardrail entry reports only a fresh exact-target effect observation. It
does not claim a bypass, policy improvement, jailbreak prevention, or generic
mitigation. The Voice entries do not claim a phone call, semantic response,
brain efficacy, unauthorized access, or seamless same-session recovery. The
GPU entry applies only to the dedicated owned ordinary-GPU fixture.
