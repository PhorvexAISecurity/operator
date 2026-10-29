# Immutable agent-sim fixture

Build from the repository root so the Dockerfile's inputs are fixed:

```sh
docker build -f farm-fixtures/agentsim/Dockerfile -t REGISTRY/agent-sim:build .
docker push REGISTRY/agent-sim:build
docker inspect --format='{{index .RepoDigests 0}}' REGISTRY/agent-sim:build
```

Supply the resulting `REGISTRY/agent-sim@sha256:...` to
`phorvex.console.attackCatalog.agentAction.image`. The chart rejects tags and
does not render this fixture until an immutable digest is supplied. Both build
stages are digest-pinned; the final runtime is non-root and contains only the
static fixture binary and CA data from distroless.
