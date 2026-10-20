# One Phorvex service image (ADR-0001): brain, sensor or actuator, each its own
# image, version and chart. The manager and its administrative binaries stay in
# operator.Dockerfile.
#
# Build from the REPO ROOT, as operator.Dockerfile documents (the module's replace
# targets live outside phorvex/):
#     docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=brain -t <img> .
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG BUILD_JOBS=2
ARG SERVICE
ENV GOMAXPROCS=${BUILD_JOBS} GOFLAGS=-p=${BUILD_JOBS}

RUN case "${SERVICE}" in brain|sensor|actuator) ;; *) echo "SERVICE must be brain, sensor or actuator, got '${SERVICE}'" >&2; exit 1;; esac

WORKDIR /workspace

# Only the revision pointer, so the binary carries its exact source Git SHA.
COPY .git/HEAD /tmp/phorvex-git/HEAD
COPY .git/refs/heads/ /tmp/phorvex-git/refs/heads/

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

RUN --mount=type=cache,id=phvx-service-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-service-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked HEAD_VALUE="$(cat /tmp/phorvex-git/HEAD)" && \
    if case "$HEAD_VALUE" in "ref: "*) true;; *) false;; esac; then \
      REF_PATH="${HEAD_VALUE#ref: }"; \
      if [ -f "/tmp/phorvex-git/${REF_PATH}" ]; then GIT_SHA="$(cat "/tmp/phorvex-git/${REF_PATH}")"; else GIT_SHA="notAvailable"; fi; \
    else GIT_SHA="$HEAD_VALUE"; fi && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA=${GIT_SHA}" -o /service ./cmd/${SERVICE}

# Distroless nonroot, matching the charts' runAsNonRoot + readOnlyRootFilesystem.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /service /service
USER 65532:65532
ENTRYPOINT ["/service"]
