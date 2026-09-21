# Phorvex operator (the deterministic "brain") image.
#
# IMPORTANT — build context must be the REPO ROOT, not phorvex/. Phorvex's go.mod
# has `replace github.com/r6security/phoenix => ../build/phoenix-extended`, so the
# Phoenix module must be present at that exact relative path inside the build. Build
# with:
#     docker build -f deploy/docker/operator.Dockerfile -t <img> .
#
# Go 1.26: both modules declare `go 1.26.1`, so the upstream Phoenix Dockerfile's
# golang:1.24 base is NOT sufficient here.
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Preserve only the revision pointer (the object database is excluded by
# .dockerignore) so the stripped binary still carries its exact source Git SHA.
COPY .git/HEAD /tmp/phorvex-git/HEAD
COPY .git/refs/heads/ /tmp/phorvex-git/refs/heads/

# The replace targets must exist before `go mod download` so the local modules
# resolve. Copy them first (Phoenix whole, since the operator imports its
# api/v1beta1 types).
COPY build/phoenix-extended/ build/phoenix-extended/
# `replace github.com/phorvex/metricvalidity => ../build/metricvalidity`: the
# shared, dependency-free definition of what makes a benchmark metric row a
# measurement. The console/report readers import it, so it must be in the context
# too — `go mod download` fails outright on a replace target that is not there,
# and a local `go build` in phorvex/ cannot detect that.
COPY build/metricvalidity/ build/metricvalidity/

# Cache dependency download on go.mod/go.sum alone.
COPY phorvex/go.mod phorvex/go.mod
COPY phorvex/go.sum phorvex/go.sum
WORKDIR /workspace/phorvex
RUN go mod download

# Now the operator source.
WORKDIR /workspace
COPY phorvex/ phorvex/
WORKDIR /workspace/phorvex

# PHORVEXSEC-83: fail the same build CI already runs if unfinished-work markers
# enter production paths, lose their Plane owner, or drift from the inventory.
RUN go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md

# Static, stripped manager binary. GOARCH left to BuildKit so the binary matches the
# image platform (amd64 on x86 EKS nodes, arm64 on Graviton).
RUN HEAD_VALUE="$(cat /tmp/phorvex-git/HEAD)" && \
    if case "$HEAD_VALUE" in "ref: "*) true;; *) false;; esac; then \
      REF_PATH="${HEAD_VALUE#ref: }"; \
      if [ -f "/tmp/phorvex-git/${REF_PATH}" ]; then GIT_SHA="$(cat "/tmp/phorvex-git/${REF_PATH}")"; else GIT_SHA="notAvailable"; fi; \
    else GIT_SHA="$HEAD_VALUE"; fi && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA=${GIT_SHA}" -a -o /manager ./cmd

# Administrative recovery is a separate, explicit invocation. The image entrypoint
# remains the manager; operators must override it to run this bounded CLI.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o /phorvex-recovery ./cmd/recovery

# Node-local read-only kubelet PodResources helper. The optional MIG agent runs this
# binary in a separate container from vendor GPU tooling.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o /phorvex-mig-allocation-helper ./cmd/mig-allocation-helper

# Independently authenticated one-shot synthetic completed-disclosure observer.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o /loss-observer ./cmd/loss-observer

# Independently authenticated one-shot synthetic current-inventory observer.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o /current-inventory-observer ./cmd/current-inventory-observer

# Distroless nonroot, matching the chart's runAsNonRoot + readOnlyRootFilesystem.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /manager .
COPY --from=builder /phorvex-recovery .
COPY --from=builder /phorvex-mig-allocation-helper .
COPY --from=builder /loss-observer .
COPY --from=builder /current-inventory-observer .
USER 65532:65532
ENTRYPOINT ["/manager"]
