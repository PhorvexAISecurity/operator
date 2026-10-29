# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# One Phorvex service image (ADR-0001): brain, sensor or actuator, each its own
# image, version and chart. The manager and its administrative binaries stay in
# operator.Dockerfile.
#
# Build from the REPO ROOT, as operator.Dockerfile documents (the module's replace
# targets live outside phorvex/):
#     docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=brain \
#       --build-arg GIT_SHA=<clean-reviewed-head> --build-arg RELEASE_VERSION=dev -t <img> .
FROM docker.io/library/golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder
ARG TARGETOS
ARG TARGETARCH
ARG BUILD_JOBS=2
ARG SERVICE
ARG GIT_SHA
ARG RELEASE_VERSION=dev
ENV GOMAXPROCS=${BUILD_JOBS} GOFLAGS=-p=${BUILD_JOBS}

RUN case "${SERVICE}" in brain|sensor|actuator) ;; *) echo "SERVICE must be brain, sensor or actuator, got '${SERVICE}'" >&2; exit 1;; esac && \
    [ "${#GIT_SHA}" -eq 40 ] && case "${GIT_SHA}" in *[!0-9a-f]*) false;; *) true;; esac || \
      { echo "GIT_SHA must be the exact 40-character lowercase Git SHA" >&2; exit 1; } && \
    case "${RELEASE_VERSION}" in ''|*[!0-9A-Za-z.+-]*) echo "RELEASE_VERSION is missing or malformed" >&2; exit 1;; esac

WORKDIR /workspace

# The module's replace targets must exist before `go mod download`.
COPY build/phoenix-extended/ build/phoenix-extended/
COPY build/metricvalidity/ build/metricvalidity/
COPY libs/logging/ libs/logging/

COPY phorvex/go.mod phorvex/go.mod
COPY phorvex/go.sum phorvex/go.sum
WORKDIR /workspace/phorvex
RUN --mount=type=cache,id=phvx-service-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-service-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked go mod download

WORKDIR /workspace
COPY phorvex/ phorvex/
WORKDIR /workspace/phorvex

# PHORVEXSEC-83: the same unfinished-work gate as the operator image.
RUN --mount=type=cache,id=phvx-service-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-service-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md

RUN --mount=type=cache,id=phvx-service-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-service-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA=${GIT_SHA} -X github.com/phorvex/phorvex/internal/buildinfo.linkedVersion=${RELEASE_VERSION}" \
      -o /service ./cmd/${SERVICE}

# Distroless nonroot, matching the charts' runAsNonRoot + readOnlyRootFilesystem.
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG GIT_SHA
ARG RELEASE_VERSION=dev
WORKDIR /
COPY --from=builder /service /service
LABEL org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${RELEASE_VERSION}"
USER 65532:65532
ENTRYPOINT ["/service"]
