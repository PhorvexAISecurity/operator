# V1 case-author fallback: owned credential reuse

The designated red-team worker terminated with a provider safety flag before
producing an artifact. This is a worker/tool failure, not an attack outcome. The
orchestrator did not retry that blocked task. For this bounded architecture
experiment it reused the existing, reviewed private fixture and authored the
case specification below; independent review must assess this fallback.

Both credentials are generated solely inside a disposable local experiment.
The unauthorized capability is future reuse of credential A after revocation;
the initial A access is an intentionally authorized baseline, not a recovered
real stolen secret. Credential B represents the continuing legitimate caller.

The executable `verification-loop` command already performs the baseline:
`clean-A`, `clean-B`, `attack-baseline-A`, `attack-baseline-B` must return 200,
the expected synthetic marker and request nonce, and increment the downstream
call counter exactly once. No external workload or arbitrary target is involved.

After ordinary selection and native dispatch, `A-after` and every A hold probe
must return exactly 401 with `unauthorized` and no downstream call increment.
B must retain successful downstream operations, including actual dispatch
overlap, within the declared two-second per-request ceiling.

Bounded defended-state variation supported by the existing runner: repeated A
requests with newly generated request nonces during the hold interval. This tests
that denial persists across request identities. It does not establish resistance
to other routes, restarts, token encodings or a different application protocol.

Potential later variations would need reviewed test adapters and fresh case
contracts; they are not executed or counted as coverage in this experiment.
The current driver tears down its state at command completion. A separate agent
cannot claim it re-attacked that destroyed defended environment. The V1 graph's
post-run re-attack step is therefore not implemented by the present tool.

Required negatives: withhold dispatch and observe continued A success despite
selection; remove authority after dispatch and observe 503/incomplete rather
than defense; clean/stale observation controls must not select revoke. These
are deliberately configured controls, not incidents requiring actuator repair.

The injected observation tests the response chain, not detector discovery.
No CVE claim, model exploit, new actuator or production claim is made.
