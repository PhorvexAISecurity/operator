# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Phorvex catalogue FIXTURE image: one minimal, non-root, reproducible image that
# bundles the three Go fixture binaries the serving-rate, serving-kv and datastore
# catalogue families need:
#   /ragstore-fixture     — datastore (rag-store) + serving-rate rate-target HTTP fixture
#   /cost-admission       — serving-rate rate-admission throttle proxy
#   /cost-load-detector   — serving-rate rate-detector
# The chart selects each by an explicit `command:`; the image is referenced ONLY by
# immutable digest through `render_catalogue_staging_values.py --phorvex-image`. It is
# published to its OWN immutable ECR repository and is NOT part of the locked
# eight-component staging-isolated-release batch, so the shared authority/consumer
# contract is untouched (see release/staging-phorvex-fixture.json).
#
# IMPORTANT — the build context is the REPO ROOT, exactly like operator.Dockerfile and
# service.Dockerfile: phorvex/go.mod `replace`s github.com/r6security/phoenix =>
# ../build/phoenix-extended, github.com/phorvex/metricvalidity => ../build/metricvalidity
# and phorvex.ai/libs/logging => ../libs/logging, so those modules must be present at
# their exact relative paths inside the build. Build with:
#     docker build -f deploy/docker/phorvex-fixture.Dockerfile \
#       --build-arg GIT_SHA=<clean-reviewed-head> --build-arg RELEASE_VERSION=<ver> \
#       --build-arg SOURCE_DATE_EPOCH=0 -t <img> .
#
# Go 1.26: both modules declare `go 1.26.1`, so the builder base matches the operator.
FROM docker.io/library/golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder
ARG TARGETOS
ARG TARGETARCH
ARG BUILD_JOBS=2
ARG GIT_SHA
ARG RELEASE_VERSION=dev
ARG SOURCE_DATE_EPOCH
ENV GOMAXPROCS=${BUILD_JOBS} GOFLAGS=-p=${BUILD_JOBS}

WORKDIR /workspace

RUN [ "${#GIT_SHA}" -eq 40 ] && case "${GIT_SHA}" in *[!0-9a-f]*) false;; *) true;; esac || \
      { echo "GIT_SHA must be the exact 40-character lowercase Git SHA" >&2; exit 1; } && \
    case "${RELEASE_VERSION}" in ''|*[!0-9A-Za-z.+-]*) echo "RELEASE_VERSION is missing or malformed" >&2; exit 1;; esac && \
    case "${SOURCE_DATE_EPOCH}" in ''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2; exit 1;; esac

# The replace targets must exist before `go mod download` so the local modules resolve.
COPY build/phoenix-extended/ build/phoenix-extended/
COPY build/metricvalidity/ build/metricvalidity/
COPY libs/logging/ libs/logging/

# Cache dependency download on go.mod/go.sum alone.
COPY phorvex/go.mod phorvex/go.mod
COPY phorvex/go.sum phorvex/go.sum
WORKDIR /workspace/phorvex
RUN --mount=type=cache,id=phvx-fixture-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-fixture-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked go mod download

# Now the fixture source (whole module, so the replace graph and internal packages resolve).
WORKDIR /workspace
COPY phorvex/ phorvex/
WORKDIR /workspace/phorvex

# PHORVEXSEC-83: the same unfinished-work gate the operator and service images run.
RUN --mount=type=cache,id=phvx-fixture-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-fixture-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md

# All three binaries in one reproducible, stripped, trimpathed build. GOARCH is left to
# BuildKit so the binaries match the image platform. `-buildid=` drops the only remaining
# non-deterministic linker field; `-trimpath` + CGO_ENABLED=0 + the pinned toolchain and
# go.sum make each binary byte-identical across clean builds.
RUN --mount=type=cache,id=phvx-fixture-gomod-${TARGETARCH},target=/go/pkg/mod,sharing=locked --mount=type=cache,id=phvx-fixture-gobuild-${TARGETARCH},target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -buildid= -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA=${GIT_SHA} -X github.com/phorvex/phorvex/internal/buildinfo.linkedVersion=${RELEASE_VERSION}" \
      -o /out/ ./cmd/ragstore-fixture ./cmd/cost-admission ./cmd/cost-load-detector

# Distroless static nonroot, matching the charts' runAsNonRoot + readOnlyRootFilesystem +
# drop-ALL-capabilities fixture pods. Three explicit file sources in one COPY (the same
# reproducible idiom as farm-fixtures/agentsim) => one deterministic application layer whose
# entry permissions and ownership are fixed at copy time, not read from the builder
# filesystem, and whose timestamps BuildKit rewrites to SOURCE_DATE_EPOCH.
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG GIT_SHA
ARG RELEASE_VERSION=dev
WORKDIR /
COPY --from=builder --chown=0:0 --chmod=0555 \
    /out/ragstore-fixture /out/cost-admission /out/cost-load-detector /
LABEL org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${RELEASE_VERSION}" \
      ai.phorvex.fixture.commands="/ragstore-fixture,/cost-admission,/cost-load-detector"
EXPOSE 8080
USER 65532:65532
# Benign default: every real consumer sets an explicit `command:`; the serving-kv
# config witness runs with replicas=0 and never executes this entrypoint.
ENTRYPOINT ["/ragstore-fixture"]
