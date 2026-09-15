# Adapter reload sources

Adapter reload is disabled unless the operator starts Phorvex with
`--lora-clean-sources-file`. The JSON file uses schema version 1 and maps an exact
namespace and adapter identity to one clean absolute path local to the serving
deployment:

```json
{"version":1,"sources":[{"namespace":"models","adapter":"support-v2","source":"/models/adapters/support-v2"}]}
```

The parser rejects unknown fields, duplicates, malformed identities, URLs,
relative or non-clean paths, control characters, oversized files, and more than
1024 entries. Configuration is copied at startup; changing a mounted ConfigMap
requires a manager restart. Pod annotations and rollback snapshots never grant
reload authority.

Approval of a path is not cryptographic proof that its contents are clean. The
serving deployment administrator must provision the referenced artifact through
an immutable, read-only mechanism and keep its meaning stable for the lifetime of
the manager process. When no exact mapping exists, a successful unload leaves the
base model serving and records that reload was omitted.
