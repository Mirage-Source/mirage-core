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
USER mirage
EXPOSE 22 2222
ENTRYPOINT ["/usr/local/bin/mirage"]
