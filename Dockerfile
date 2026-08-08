# syntax=docker/dockerfile:1

# ---- Stage 1: Build Go Backend -------------------------------------------
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o anchor main.go

# ---- Stage 2: Final minimal image -----------------------------------------
# syft/grype/grant run in-process via their Go libraries (see pkg/scanner) -
# no CLI binaries to install, so this only needs CA certs (registry/DB TLS)
# and tzdata.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/anchor ./anchor

ENV PORT=8080 \
    DATA_DIR=/data \
    HOME=/data

RUN mkdir -p /data \
  && chgrp -R 0 /app /data \
  && chmod -R g=u /app /data

EXPOSE 8080
USER 1001:0

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["wget", "-qO-", "http://127.0.0.1:8080/healthz"]

CMD ["/app/anchor"]
