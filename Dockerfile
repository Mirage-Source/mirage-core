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
RUN mkdir -p /app/config
WORKDIR /app
COPY --from=builder /app/mirage /usr/local/bin/mirage
RUN chown mirage /usr/local/bin/mirage
USER mirage
EXPOSE 22 2222
ENTRYPOINT ["/usr/local/bin/mirage"]
