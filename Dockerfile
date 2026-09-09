FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o mirage \
    ./cmd/mirage

FROM debian:bookworm-slim AS runner
RUN groupadd --system mirage && \
    useradd --system \
    --gid mirage \
    --no-create-home \
    --shell /usr/sbin/nologin \
    mirage
WORKDIR /app
COPY --from=builder /app/mirage /usr/local/bin/mirage
COPY --from=builder /app/config /app/config
RUN chown mirage /usr/local/bin/mirage && chown -R mirage /app/config
# /app/data is where the fleet_queue volume mounts (see docker-compose.yml).
# Docker only copies this ownership into a *new* named volume on first
# creation -- it won't retroactively fix an existing volume, but it stops a
# fresh deploy from ever hitting the mirage-user-can't-write-to-root-owned-
# mountpoint bug that a stale production volume already hit once.
RUN mkdir -p /app/data && chown mirage /app/data
USER mirage
EXPOSE 22 2222
ENTRYPOINT ["/usr/local/bin/mirage"]
