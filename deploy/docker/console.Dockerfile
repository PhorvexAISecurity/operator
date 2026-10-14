# Phorvex Console (dashboard) image — a single binary that serves both the Next.js
# static SPA and the read-only /api over the Phorvex report/metrics/audit snapshots.
#
# Build context = REPO ROOT (same multi-module reason as the operator: the phorvex
# module's go.mod replaces Phoenix with ../build/phoenix-extended, and the report
# snapshots under build/test-harness/out-* are baked in as the dashboard's data).
#     docker build -f deploy/docker/console.Dockerfile -t <img> .

# ---- Stage 1: build the Next.js static export (output: "export" -> dashboard-web/out) ----
FROM node:20-bookworm-slim AS web
WORKDIR /web
COPY dashboard-web/package.json dashboard-web/package-lock.json ./
RUN npm ci
COPY dashboard-web/ ./
RUN npm run build      # emits ./out (static SPA)

# ---- Stage 2: build the Go console backend ----
FROM golang:1.26 AS gobuild
ARG TARGETOS
ARG TARGETARCH
WORKDIR /workspace
COPY build/phoenix-extended/ build/phoenix-extended/
# The console reads the harness metrics stream, so the phorvex module replaces
# github.com/phorvex/metricvalidity with ../build/metricvalidity — the shared,
# dependency-free measurement-validity contract. A replace target missing from
# the build context fails `go mod download` outright.
COPY build/metricvalidity/ build/metricvalidity/
COPY phorvex/go.mod phorvex/go.mod
COPY phorvex/go.sum phorvex/go.sum
WORKDIR /workspace/phorvex
RUN go mod download
WORKDIR /workspace
COPY phorvex/ phorvex/
WORKDIR /workspace/phorvex
# PHORVEXSEC-83: the console build shares the marker/ownership gate with the operator.
RUN go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md
# BuildStamp is what GET /api/version reports as the console's own version, and it is the
# ONLY way to tell which console build is serving — the operator's version is read from the
# live Deployment, but the console can only report what was compiled into it. Left unset it
# defaults to "dev", which made the deployed console report "dev" against operator "0.4.6"
# and tripped the End-to-End version-match check (P02) on every single run.
ARG CONSOLE_VERSION=dev
RUN : && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X github.com/phorvex/phorvex/internal/console.BuildStamp=${CONSOLE_VERSION}" \
      -a -o /console cmd/console/main.go

# The console's live-scan/ablation subsystems SHELL OUT to the phorvex operator binary at
# <root>/phorvex/bin/phorvex.exe (subsystems.go: c.PhorvexBin runs `phorvex --scan`). That
# binary was never built into this image, so GET /api/scan execed a missing file and the
# dashboard's Scan step reported 0 nodes / 0 pods on a full cluster (platform then falls back
# to generic-k8s). Build it from the SAME phorvex module — in-cluster it scans via the pod
# ServiceAccount, exactly like the running operator.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o /phorvex ./cmd

# ---- Stage 2c: the harness binary ----
# GET /api/catalog enumerates the full scenario catalogue by SHELLING OUT to this binary
# (evidence.go Catalog() runs `harness -config <cfg> -list`). Without it the handler returns
# {"items":null} and the per-app attack launcher can only offer the live attacks, never the
# scenario catalogue. The harness is its OWN Go module (github.com/r6security/phoenix-test-harness)
# with `replace github.com/r6security/phoenix => ../phoenix-extended` AND
# `replace github.com/phorvex/metricvalidity => ../metricvalidity`, so all three directories must
# sit side by side for those relative replaces to resolve.
FROM golang:1.26 AS harnessbuild
WORKDIR /workspace
COPY build/phoenix-extended/ build/phoenix-extended/
COPY build/metricvalidity/ build/metricvalidity/
COPY build/test-harness/ build/test-harness/
WORKDIR /workspace/build/test-harness
# CGO-free + static so it runs on the distroless/static final base next to the console binary.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /harness ./cmd/harness
# The synthetic NATS observer is a single read-only client. Build it from the
# same reviewed source into the existing console image; no runtime download or
# second image release is involved. Its Pod runs only this binary.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /nats-owned-observer ./cmd/nats-owned-observer

# ---- Stage 2b: kubectl ----
# internal/console/workload_attack.go fires a real attack by applying a SecurityEvent CR,
# and it does that by SHELLING OUT to kubectl (the console cannot reach pod IPs directly).
# Without the binary the endpoint fails with `exec: "kubectl": executable file not found`,
# which is why the in-cluster console could never fire an attack and the End-to-End suite
# had to drive a console running on the jump host instead.
#
# Pinned, and the checksum is verified: this binary is handed cluster-admin-shaped
# credentials at runtime, so a silently substituted download is not an acceptable risk.
FROM golang:1.26 AS kubectl
ARG TARGETARCH
ARG KUBECTL_VERSION=v1.31.4
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    curl -fsSLo /kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl"; \
    curl -fsSLo /kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl.sha256"; \
    echo "$(cat /kubectl.sha256)  /kubectl" | sha256sum -c -; \
    chmod +x /kubectl

# ---- Stage 3: assemble the data snapshot (kept separate so it's easy to swap) ----
# The console resolves data relative to -root: <root>/build/test-harness/out-* for the
# benchmark metrics, and <root>/phorvex/bin/console-audit.jsonl for the owner audit view.
FROM busybox:1.36 AS data
WORKDIR /data
COPY build/test-harness/ /data/build/test-harness/
# console-audit.jsonl is a GENERATED runtime trail, excluded by .gitignore, so it is absent
# from every clean checkout — a hard COPY of it made this image unbuildable in CI while
# still working on a developer machine that happened to have run the console locally.
# It is genuinely optional: newestAudit() in internal/console/server.go returns "" when the
# file is missing, and the owner audit view degrades rather than breaking.
#
# The trailing * makes it a glob, which resolves to nothing instead of failing when the
# file is absent — the same idiom as the familiar `COPY package.json package-lock.json* ./`.
# A COPY still fails when ALL of its sources resolve to nothing, so phorvex/go.mod rides
# along purely to guarantee one real match: it is always in the context (the gobuild stage
# builds from it) and .dockerignore excludes only phorvex/bin/*.exe, not it. Deleted again
# on the next line.
COPY phorvex/go.mod phorvex/bin/console-audit.jsonl* /data/phorvex/bin/
# Drop anything heavy/irrelevant the .dockerignore didn't catch, but KEEP three things the
# catalogue + scenario launcher need: the out-* metrics dirs, the per-target config*.yaml files
# (StartScenario runs `harness -config <cfg> ...`), and a bin/ dir for the harness binary the
# final stage drops in. `harness -list` itself short-circuits before it reads any config
# (cmd/harness/main.go), so enumeration needs only the binary — the configs are for launching.
RUN rm -f /data/phorvex/bin/go.mod && \
    cd /data/build/test-harness && \
    find . -maxdepth 1 -mindepth 1 ! -name 'out-*' ! -name 'config*.yaml' ! -name 'bin' \
        -exec rm -rf {} + || true && \
    mkdir -p /data/build/test-harness/bin

# ---- Final image ----
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=gobuild /console /app/console
COPY --from=web /web/out /app/web
COPY --from=data /data /data
# The harness binary lands at the exact path DefaultConfig() hardcodes:
# <root>/build/test-harness/bin/harness.exe. The .exe name is a historical dev artifact and is
# just a filename on Linux — the console execs it by that path, so it must match.
COPY --from=harnessbuild /harness /data/build/test-harness/bin/harness.exe
COPY --from=harnessbuild /nats-owned-observer /app/nats-owned-observer
# The phorvex operator binary lands at the exact path DefaultConfig() hardcodes for the
# console's live-scan subsystem: <root>/phorvex/bin/phorvex.exe. Without it the Scan step
# reports 0 nodes / 0 pods on a live cluster (missing-binary exec => empty result).
COPY --from=gobuild /phorvex /data/phorvex/bin/phorvex.exe
# Both are static and CGO-free, so distroless/static stays the right base.
COPY --from=kubectl /kubectl /usr/local/bin/kubectl
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/app/console"]
CMD ["-root=/data", "-web=/app/web", "-addr=:8090"]
