# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Phorvex operator (the deterministic "brain") image.
#
# IMPORTANT — build context must be the REPO ROOT, not phorvex/. Phorvex's go.mod
# has `replace github.com/r6security/phoenix => ../build/phoenix-extended`, so the
# Phoenix module must be present at that exact relative path inside the build. Build
# with:
#     docker build -f deploy/docker/operator.Dockerfile \
#       --build-arg GIT_SHA=<clean-reviewed-head> --build-arg RELEASE_VERSION=dev -t <img> .
#
# Go 1.26: both modules declare `go 1.26.1`, so the upstream Phoenix Dockerfile's
# golang:1.24 base is NOT sufficient here.
FROM docker.io/library/golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder
ARG TARGETOS
ARG TARGETARCH
ARG BUILD_JOBS=2
ARG GIT_SHA
ARG RELEASE_VERSION=dev
ENV GOMAXPROCS=${BUILD_JOBS} GOFLAGS=-p=${BUILD_JOBS}

WORKDIR /workspace

RUN [ "${#GIT_SHA}" -eq 40 ] && case "${GIT_SHA}" in *[!0-9a-f]*) false;; *) true;; esac || \
      { echo "GIT_SHA must be the exact 40-character lowercase Git SHA" >&2; exit 1; } && \
    case "${RELEASE_VERSION}" in ''|*[!0-9A-Za-z.+-]*) echo "RELEASE_VERSION is missing or malformed" >&2; exit 1;; esac

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
RUN --mount=type=cache,id=phvx-operator-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-operator-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA=${GIT_SHA} -X github.com/phorvex/phorvex/internal/buildinfo.linkedVersion=${RELEASE_VERSION}" \
      -o /out/ ./cmd ./cmd/brain-replay && \
    mv /out/cmd /manager && mv /out/brain-replay /brain-replay

# Keep the four administrative/observer binaries' original plain ldflags.
RUN --mount=type=cache,id=phvx-operator-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-operator-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ \
      ./cmd/recovery ./cmd/mig-allocation-helper ./cmd/loss-observer ./cmd/current-inventory-observer ./cmd/persistence-observer ./cmd/cost-budget-admin && \
    mv /out/recovery /phorvex-recovery && \
    mv /out/mig-allocation-helper /phorvex-mig-allocation-helper && \
    mv /out/loss-observer /loss-observer && \
    mv /out/current-inventory-observer /current-inventory-observer && \
    mv /out/persistence-observer /persistence-observer && \
    mv /out/cost-budget-admin /cost-budget-admin

# Distroless nonroot, matching the chart's runAsNonRoot + readOnlyRootFilesystem.
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG GIT_SHA
ARG RELEASE_VERSION=dev
WORKDIR /
COPY --from=builder /manager .
COPY --from=builder /phorvex-recovery .
COPY --from=builder /phorvex-mig-allocation-helper .
COPY --from=builder /loss-observer .
COPY --from=builder /current-inventory-observer .
COPY --from=builder /persistence-observer .
COPY --from=builder /cost-budget-admin .
COPY --from=builder /brain-replay .
LABEL org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${RELEASE_VERSION}"
USER 65532:65532
ENTRYPOINT ["/manager"]
