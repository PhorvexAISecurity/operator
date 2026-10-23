# Mutual TLS between the services

The dispatcher calls the sensor, brain and actuator services over gRPC (ADR-0001).
With `phorvex.serviceTLS.enabled`, those calls run over mutual TLS:

- Every end presents a certificate that one service CA signed.
- The sensor, brain and actuator admit a client only when its certificate was
  issued for the dispatcher's identity, `<release>-dispatcher.<namespace>.svc`
  (`--grpc-tls-peer`). Another workload, even one holding a certificate from the
  same CA, is refused at the handshake.
- The dispatcher admits a server only when its certificate was issued for the
  Service name it dialed, such as `<release>-brain`.
- Both ends require TLS 1.3.

Off (the default), the calls are plaintext, as before. The in-process manager calls
no service and mounts nothing.

The console and the attacks service are not part of this: their boundary is the
console's HTTP API, authenticated per request (`attacks.md`). The console's audit
source has its own mutual TLS (`docs/CONSOLE-AUDIT-TRANSPORT.md`).

## The Secrets

Each end mounts its own Secret at `/etc/phorvex/grpc-tls`, holding `tls.crt`,
`tls.key` and `ca.crt`:

| Secret | End | Certificate |
|---|---|---|
| `<release>-dispatcher-grpc-tls` | the manager | client, `DNS:<release>-dispatcher.<namespace>.svc` |
| `<release>-brain-grpc-tls` | the brain | server, `DNS:<release>-brain` and its namespace forms |
| `<release>-sensor-grpc-tls` | the sensor | server, `DNS:<release>-sensor` and its namespace forms |
| `<release>-actuator-grpc-tls` | the actuator | server, `DNS:<release>-actuator` and its namespace forms |

`deploy/eks/provision-service-mtls.sh` writes them:

```sh
NAMESPACE=phorvex-staging RELEASE=staging bash deploy/eks/provision-service-mtls.sh
```

- **Idempotent.** It keeps the Secrets when all four are present, unexpired,
  bound to their identities and signed by one CA. Otherwise it issues a new CA
  and all four.
- **The CA key.** It never leaves the script's temporary directory.
- **Verification.** It verifies what it stored, not only what it built.

The charts mount the Secrets but never create them, like the audit transport's.

## Enabling

1. Run the script for the environment's namespace and release.
2. Deploy images that read the `--grpc-tls-*` flags: the manager, brain, sensor and
   actuator released with or after this document. An older image refuses the
   unknown flags and does not start.
3. Set `phorvex.serviceTLS.enabled: true` in the environment's `phorvex.yaml`.
   Every chart reads it, so the four ends switch in one sync.

The dispatcher refuses to start without each service it is configured for. A
handshake it cannot complete stops it the same way ("refusing to start without the
brain service"), and nothing actuates until it can.

## Rotating

Run the script with `FORCE_ROTATE=true`. Then:
- **The services** read their certificate, key and CA on every handshake.
- **The dispatcher** reads its certificate and key on every handshake, but its CA
  only when it starts. A new CA reaches it on a restart:

  ```sh
  kubectl -n <namespace> rollout restart deploy/<release>-phorvex
  ```

The script issues certificates for 397 days by default (`CERT_DAYS`).

## Checking

- **Startup.** Each service logs `mutualTLS=true` in its `... service ready` line.
- **Refusal.** A plaintext client is refused:

  ```sh
  kubectl -n <namespace> run grpc-probe --rm -i --restart=Never \
    --image=fullstorydev/grpcurl -- -plaintext <release>-brain:9090 list
  ```

- **Tests.** `phorvex/internal/servicetls` covers the handshake's refusals and
  rotation. `ServiceTLSTests` in `tools/test_service_charts.py` covers the charts
  and the script's names.
