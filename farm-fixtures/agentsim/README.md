# Immutable agent-sim fixture

Build a network-isolated local image from the repository root so the Dockerfile,
platform, timestamps, provenance and SBOM inputs are fixed:

```sh
tools/build-agentsim.sh phorvex/agentsim:release-check
```

The reviewed release process may publish that local image later. Supply
the registry's resulting `REGISTRY/agent-sim@sha256:...` manifest reference to
`phorvex.console.attackCatalog.agentAction.image`. The chart rejects tags and
does not render this fixture until an immutable digest is supplied. Both build
stages are digest-pinned; the final runtime is non-root and contains only the
static fixture binary and CA data from distroless.
