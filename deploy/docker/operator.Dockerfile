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
ARG BUILD_JOBS=2
ENV GOMAXPROCS=${BUILD_JOBS} GOFLAGS=-p=${BUILD_JOBS}

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
# Shared libraries under libs/ are replace targets too.
COPY libs/logging/ libs/logging/

# Cache dependency download on go.mod/go.sum alone.
COPY phorvex/go.mod phorvex/go.mod
COPY phorvex/go.sum phorvex/go.sum
WORKDIR /workspace/phorvex
RUN --mount=type=cache,id=phvx-operator-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-operator-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked go mod download

# Now the operator source.
WORKDIR /workspace
COPY phorvex/ phorvex/
WORKDIR /workspace/phorvex

# PHORVEXSEC-83: fail the same build CI already runs if unfinished-work markers
# enter production paths, lose their Plane owner, or drift from the inventory.
RUN --mount=type=cache,id=phvx-operator-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-operator-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md

# Static, stripped manager binary. GOARCH left to BuildKit so the binary matches the
# image platform (amd64 on x86 EKS nodes, arm64 on Graviton).
RUN --mount=type=cache,id=phvx-operator-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-operator-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked HEAD_VALUE="$(cat /tmp/phorvex-git/HEAD)" && \
    if case "$HEAD_VALUE" in "ref: "*) true;; *) false;; esac; then \
      REF_PATH="${HEAD_VALUE#ref: }"; \
      if [ -f "/tmp/phorvex-git/${REF_PATH}" ]; then GIT_SHA="$(cat "/tmp/phorvex-git/${REF_PATH}")"; else GIT_SHA="notAvailable"; fi; \
    else GIT_SHA="$HEAD_VALUE"; fi && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA=${GIT_SHA}" -o /out/ ./cmd ./cmd/brain-replay && \
    mv /out/cmd /manager && mv /out/brain-replay /brain-replay

# Keep the four administrative/observer binaries' original plain ldflags.
RUN --mount=type=cache,id=phvx-operator-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-operator-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ \
      ./cmd/recovery ./cmd/mig-allocation-helper ./cmd/loss-observer ./cmd/current-inventory-observer && \
    mv /out/recovery /phorvex-recovery && \
    mv /out/mig-allocation-helper /phorvex-mig-allocation-helper && \
    mv /out/loss-observer /loss-observer && \
    mv /out/current-inventory-observer /current-inventory-observer

# Distroless nonroot, matching the chart's runAsNonRoot + readOnlyRootFilesystem.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /manager .
COPY --from=builder /phorvex-recovery .
COPY --from=builder /phorvex-mig-allocation-helper .
COPY --from=builder /loss-observer .
COPY --from=builder /current-inventory-observer .
COPY --from=builder /brain-replay .
USER 65532:65532
ENTRYPOINT ["/manager"]
