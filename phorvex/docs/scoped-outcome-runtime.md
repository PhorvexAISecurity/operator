# Scoped outcome runtime wiring

Qualified persistence outcomes remain unavailable unless the controller is
started with `--scoped-outcome-config=/absolute/private/startup.json`. The file
preregisters one synthetic session and one exact policy, workload, Pod and
replacement boundary. It does not enable discovery of other endpoints or
general external probes.

The configuration schema is `phorvex.scoped-outcome-startup.v1`:

```json
{
  "schemaVersion": "phorvex.scoped-outcome-startup.v1",
  "prepare": {
    "policy": {"namespace":"fixture","name":"policy","uid":"policy-uid","generation":1},
    "workload": {"namespace":"fixture","ownerKind":"Deployment","ownerName":"app","ownerUID":"deployment-uid"},
    "targetUID": "old-pod-uid",
    "targetName": "old-pod",
    "targetTerminationGraceSeconds": 30,
    "old": {"url":"https://session.fixture.svc/old","sessionID":"old-session","challenge":"old-challenge","targetUID":"old-pod-uid","workloadScopeSHA256":"64-lowercase-hex"},
    "replacement": {"url":"https://session.fixture.svc/replacement","sessionID":"replacement-session","challenge":"replacement-challenge","targetUID":"","workloadScopeSHA256":"64-lowercase-hex"}
  },
  "caFile": "/var/run/phorvex-scoped-outcome/ca.pem",
  "clientCertFile": "/var/run/phorvex-scoped-outcome/tls.crt",
  "clientKeyFile": "/var/run/phorvex-scoped-outcome/tls.key",
  "serverName": "session.fixture.svc",
  "evidenceDirectory": "/var/lib/phorvex/scoped-outcome",
  "evidenceMaxItems": 64,
  "evidenceMaxBytes": 4194304,
  "httpTimeout": "2s",
  "authorityTimeout": "2s"
}
```

The workload digest is the SHA-256 of the canonical JSON encoding of the four
`workload` fields. The config, certificate and key paths must be absolute. Both
timeouts are positive and at most five seconds. The evidence store is private
(`0700` directory, `0600` immutable files), non-evicting, and bounded by both
item and byte limits.

Startup verifies TLS 1.3 mutual authentication, the current policy UID and
generation, the Pod UID and grace period, its stable workload owner, and the
old synthetic session. Any configuration, authority, TLS, probe, or storage
failure leaves the producer disconnected and the existing
`no-qualified-live-label-producer` behavior intact. Only a coherent native
rotate receipt can consume the preregistration. Hybrid qualifies because its
rotate route is native; a Phoenix-only runtime refuses the observer.

Raw session responses and action receipts are written only to the private
evidence directory. They are never added to logs or decision audit notes. The
producer closes when the manager exits; shutdown cancels outstanding probes
before returning.
