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
COPY phorvex/go.mod phorvex/go.mod
COPY phorvex/go.sum phorvex/go.sum
WORKDIR /workspace/phorvex
RUN go mod download
WORKDIR /workspace
COPY phorvex/ phorvex/
WORKDIR /workspace/phorvex
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o /console cmd/console/main.go

# ---- Stage 3: assemble the data snapshot (kept separate so it's easy to swap) ----
# The console resolves data relative to -root: <root>/build/test-harness/out-* for the
# benchmark metrics, and <root>/phorvex/bin/console-audit.jsonl for the owner audit view.
FROM busybox:1.36 AS data
WORKDIR /data
COPY build/test-harness/ /data/build/test-harness/
COPY phorvex/bin/console-audit.jsonl /data/phorvex/bin/console-audit.jsonl
# Drop anything heavy/irrelevant the .dockerignore didn't catch (keep only out-* + audit).
RUN cd /data/build/test-harness && \
    find . -maxdepth 1 -mindepth 1 ! -name 'out-*' -exec rm -rf {} + || true

# ---- Final image ----
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=gobuild /console /app/console
COPY --from=web /web/out /app/web
COPY --from=data /data /data
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/app/console"]
CMD ["-root=/data", "-web=/app/web", "-addr=:8090"]
