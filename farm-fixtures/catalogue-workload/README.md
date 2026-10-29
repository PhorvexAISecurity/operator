# Catalogue workload fixture image

Build a deterministic, network-isolated local image from the repository root:

```sh
tools/build-catalogue-workload.sh phorvex/catalogue-workload:release-check
```

The reviewed release process may publish that local image later, then place the resulting
`REGISTRY/catalogue-workload@sha256:<64hex>` in
`phorvex.console.attackCatalog.familyFixtures.images.workload`. The image is a
non-root, bounded HTTP fixture and carries the exact `curl` executable required
by the network-edge adapter; it contains no credentials or cluster client.
